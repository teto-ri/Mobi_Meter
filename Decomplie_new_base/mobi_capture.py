import sys
import traceback
from websockets.sync.server import serve
from scapy.all import sniff, IP, TCP, Raw, get_if_addr, get_if_list, conf, AsyncSniffer
from functools import lru_cache
import subprocess
import threading
import queue
import time
import brotli
import collections
import logging

packet_queue = queue.Queue()

# 로깅 레벨을 DEBUG로 변경하여 더 자세한 정보 출력
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("capture.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)

# 로거 인스턴스 생성
logger = logging.getLogger(__name__)
my_ip = get_if_addr(conf.iface)

# WebSocket
ws = None
ws_lock = threading.Lock()  # 웹 소켓 동기화용 락 추가
sniffer = None
PORT = 16000

# Constants
PACKET_START = b"\x3a\x04\x00\x00\x00\x00\x00\x00"
PACKET_END = b"\x04\x00\x00\x00\x00\x00\x00\x00"

INVALID_DAMAGE = 4294967295  # Invalid damage value, used to filter out invalid entries

# Data Types
DATA_TYPE_DOT = 67
DATA_TYPE_DAMAGE = 1283
DATA_TYPE_SKILL = 1432

EXCEPTED_DATA_TYPES = [DATA_TYPE_DAMAGE, DATA_TYPE_SKILL]

FLAG_BITS = (
    (0, "crit_flag", 0x01),
    (0, "unguarded_flag", 0x04),
    (0, "break_flag", 0x08),
    (0, "first_hit_flag", 0x40),
    (0, "default_attack_flag", 0x80),
    (1, "multi_attack_flag", 0x01),
    (1, "power_flag", 0x02),
    (1, "fast_flag", 0x04),
    (1, "dot_flag", 0x08),
    (3, "add_hit_flag", 0x08),
    (3, "bleed_flag", 0x10),
    (3, "fire_flag", 0x40),
    (3, "holy_flag", 0x80),
    (4, "ice_flag", 0x01),
    (4, "electric_flag", 0x02),
    (4, "poison_flag", 0x04),
    (4, "mind_flag", 0x08),
    (4, "not_dot_flag", 0x10),
)

# 유저 ID별 큐를 저장하는 딕셔너리
user_skill_queues = {}
SKILL_TIMEOUT_SEC = 10  # 10초 후 스킬명 만료


def beautify_hex(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        ascii_bytes = "".join((chr(b) if 32 <= b < 127 else ".") for b in chunk)
        lines.append(f"{i:08X}  {hex_bytes:<{width*3}}  |{ascii_bytes}|")
    return "\n".join(lines)


def find_pattern(data: bytes, pattern: bytes) -> list:
    return [i for i in range(len(data)) if data[i : i + len(pattern)] == pattern]


def find_patterns(data: bytes, data_types: list) -> list:
    """여러 데이터 타입의 패턴을 모두 찾기 - 개선된 버전"""
    all_indices = []
    for data_type in data_types:
        pattern = data_type.to_bytes(4, byteorder="little")
        indices = find_pattern(data, pattern)

        # 각 패턴이 유효한 데이터 블록의 시작인지 검증
        valid_indices = []
        for idx in indices:
            # 최소 헤더 크기(9바이트) 확인
            if idx + 9 > len(data):
                continue

            try:
                # 데이터 길이 읽기 시도
                data_len = int.from_bytes(data[idx + 4 : idx + 8], byteorder="little")

                # 합리적인 데이터 길이인지 확인 (1 ~ 65536 바이트)
                if 1 <= data_len <= 65536:
                    total_needed = idx + 9 + data_len - 1
                    # 완전한 블록이 있는 경우만 유효한 인덱스로 간주
                    if total_needed <= len(data):
                        valid_indices.append(idx)

            except Exception:
                continue

        all_indices.extend(valid_indices)

    return sorted(all_indices)


def is_dot_or_elemental_skill(skill_name: str) -> bool:
    """DOT 또는 원소 지속 효과 스킬인지 판단"""
    if not skill_name:
        return False

    # DOT/원소 관련 키워드들
    dot_keywords = [
        "Elemental_Common_Hit",  # 원소 지속 효과
        "_Bleed",  # 출혈
        "_Poison",  # 독
        "_Soul",  # 소울
        "_Fire",  # 화염
        "_Ice",  # 빙결
        "_Electric",  # 전기
        "_Holy",  # 신성
        "DOT_",  # DOT 접두사
        "_DOT",  # DOT 접미사
        "Continuous",  # 지속 효과
        "Persistent",  # 지속 효과
    ]

    skill_upper = skill_name.upper()
    for keyword in dot_keywords:
        if keyword.upper() in skill_upper:
            return True

    return False

# 유저 ID와 스킬명을 인자로 받아 시퀀스 번호와 시간 정보와 함께 큐에 추가하는 함수
def add_skill_with_sequence(
    user_id: str, skill_name: str, seq_num: int, packet_time: float
):
    """새로운 스킬명을 유저별 큐에 시퀀스 번호, 시간 정보와 함께 추가"""
    global user_skill_queues
    if not skill_name:
        return

    # 해당 유저의 큐가 없으면 새로 생성
    if user_id not in user_skill_queues:
        user_skill_queues[user_id] = collections.deque(maxlen=50)

    skill_queue = user_skill_queues[user_id]

    # 중복 체크: 같은 seq_num과 packet_time을 가진 스킬이 이미 있는지 확인
    for existing_skill in skill_queue:
        if (
            existing_skill["seq"] == seq_num
            and abs(existing_skill["packet_time"] - packet_time) < 0.001
        ):  # 시간 오차 0.001초 허용
            logger.debug(
                f"[{user_id}] Duplicate skill ignored: '{skill_name}' (seq: {seq_num}, time: {packet_time:.3f})"
            )
            return

    skill_info = {
        "name": skill_name,
        "seq": seq_num,
        "packet_time": packet_time,
        "used_count": 0,  # 사용 횟수 (여러 Idle에 대응)
    }
    skill_queue.append(skill_info)
    logger.debug(
        f"[{user_id}] Added skill '{skill_name}' with seq {seq_num} at time {packet_time:.3f}, queue size: {len(skill_queue)}"
    )


# 유저 ID와 데미지 시퀀스, 시간 정보를 받아 해당 시퀀스보다 앞선 가장 최근 스킬명을 반환하는 함수
def get_skill_for_damage(
    user_id: str, damage_seq: int, damage_time: float
) -> str or None:
    """데미지 시퀀스보다 앞선 가장 최근 스킬명을 유저별 큐에서 반환"""
    global user_skill_queues
    current_time = time.time()

    # 해당 유저의 큐가 없으면 None 반환
    if user_id not in user_skill_queues:
        logger.debug(f"[{user_id}] No skill queue found for damage.")
        return None

    skill_queue = user_skill_queues[user_id]

    # 만료된 스킬명들 제거
    while (
        skill_queue
        and (current_time - skill_queue[0]["packet_time"]) > SKILL_TIMEOUT_SEC
    ):
        expired_skill = skill_queue.popleft()
        logger.debug(
            f"[{user_id}] Expired skill removed: '{expired_skill['name']}' (seq: {expired_skill['seq']})"
        )

    # 데미지 시퀀스보다 앞서고 시간적으로도 앞선 스킬 중 가장 최근 것 찾기
    best_match = None
    TOLERANCE_SEC = 0.05  # 50ms 허용 오차
    for skill_info in reversed(skill_queue):  # 최신부터 검색
        # 시퀀스 번호가 데미지보다 작거나 같고, 시간도 (허용 오차 내에서) 앞서야 함
        if (
            skill_info["seq"] <= damage_seq
            and skill_info["packet_time"] <= damage_time + TOLERANCE_SEC
        ):  # <-- 이 부분 수정
            best_match = skill_info
            break

    if best_match:
        best_match["used_count"] += 1
        logger.debug(
            f"[{user_id}] Matched skill '{best_match['name']}' (seq: {best_match['seq']}) for damage (seq: {damage_seq}), used count: {best_match['used_count']}"
        )
        return best_match["name"]

    logger.debug(f"[{user_id}] No valid skill found for damage (seq: {damage_seq})")
    return None


def parse_skill_name(content: bytes):
    """1432 타입에서 스킬명만 추출"""
    try:
        skill_name_len, content = (
            int.from_bytes(content[:4], byteorder="little"),
            content[4:],
        )
        skill_name_bytes, content = (content[:skill_name_len], content[skill_name_len:])

        skill_name = skill_name_bytes.replace(b"\x00", b"").decode(
            "utf-8", errors="replace"
        )
        import re

        skill_name = re.sub(r"[^\x20-\x7E]", "", skill_name)

        # 공백 정리
        skill_name = skill_name.strip()
        return skill_name
    except Exception as e:
        logger.warning(f"skill parsing error: {e}")
    return None


# 스킬명에서 플래그를 추출하는 함수
@lru_cache(maxsize=256)
def extract_flags(flags: bytes) -> dict:
    result = {}
    for index, name, mask in FLAG_BITS:
        result[name] = int((flags[index] & mask) != 0) if index < len(flags) else 0
    return result


# 데미지 정보를 파싱하는 함수
def parse_damage(content: bytes):
    used_by, content = (content[:4].hex(), content[8:])
    target, content = (content[:4].hex(), content[4:])
    t, content = (int.from_bytes(content[:4], byteorder="little"), content[4:])
    skill_name_len, content = (
        int.from_bytes(content[:4], byteorder="little"),
        content[4:],
    )
    skill_name_bytes, content = (content[:skill_name_len], content[skill_name_len:])
    damage, content = (int.from_bytes(content[:4], byteorder="little"), content[4:])
    if damage == INVALID_DAMAGE:
        return None  # Invalid damage, skip this entry
    unknown, content = (content[:12], content[12:])
    flags, content = (content[:6], content[6:])
    skill_id, content = (content[:4].hex(), content[4:])

    skill_name = skill_name_bytes.replace(b"\x00", b"").decode(
        "utf-8", errors="replace"
    )
    flag_values = extract_flags(flags)

    base_info = {
        "timestamp": round(time.time() * 1000),
        "used_by": used_by,
        "target": target,
        "skill_name": skill_name,
        "flags": flag_values,
        "skill_id": skill_id,
        "damage": damage,
    }
    return {**base_info, **flag_values}

# 데이터 파싱 함수
def parse_data(raw_data: bytes, seq_num, packet_time):
    results = []
    indices = find_patterns(raw_data, EXCEPTED_DATA_TYPES)

    if len(indices) > 0:
        logger.debug(
            f"Found {len(indices)} patterns in {len(raw_data)} bytes: {indices}"
        )

    # --------------------------------------------------------------------------
    # ## Pass 1: 스킬(1432) 정보 먼저 처리 ##
    # 데이터 블록 전체를 스캔하여 스킬 정보를 먼저 큐에 모두 등록
    # --------------------------------------------------------------------------
    for start in sorted(indices):
        try:
            # 데이터 타입 확인
            data_type = int.from_bytes(raw_data[start : start + 4], byteorder="little")

            # 스킬 타입이 아니면 이번 루프에서는 건너뜀
            if data_type != DATA_TYPE_SKILL:
                continue

            # 기본 정보 추출 (길이, 인코딩 타입 등)
            data_len = int.from_bytes(
                raw_data[start + 4 : start + 8], byteorder="little"
            )
            if data_len <= 0 or start + 9 + data_len > len(raw_data):
                continue

            encode_type = raw_data[start + 8]
            payload = raw_data[start + 9 : start + 9 + data_len]

            # 압축 해제
            if encode_type == 1:
                payload = brotli.decompress(payload)

            # 스킬 정보 파싱 및 큐에 추가
            user_id = payload[:4].hex()
            skill_name = parse_skill_name(payload[24:])
            if skill_name and not is_dot_or_elemental_skill(skill_name):
                add_skill_with_sequence(user_id, skill_name, seq_num, packet_time)

        except Exception as e:
            logger.warning(
                f"[PASS 1: SKILL] Error processing block at offset {start}: {e}"
            )
            continue

    # --------------------------------------------------------------------------
    # ## Pass 2: 데미지(1283) 정보 처리 ##
    # 이제 모든 스킬이 큐에 등록된 상태에서 데미지 정보를 처리
    # --------------------------------------------------------------------------
    for start in sorted(indices):
        try:
            # 데이터 타입 확인
            data_type = int.from_bytes(raw_data[start : start + 4], byteorder="little")

            # 데미지 타입이 아니면 이번 루프에서는 건너뜁니다.
            if data_type != DATA_TYPE_DAMAGE:
                continue

            # 기본 정보 추출 (길이, 인코딩 타입 등)
            data_len = int.from_bytes(
                raw_data[start + 4 : start + 8], byteorder="little"
            )
            if data_len <= 0 or start + 9 + data_len > len(raw_data):
                continue

            encode_type = raw_data[start + 8]
            payload = raw_data[start + 9 : start + 9 + data_len]

            # 압축 해제
            if encode_type == 1:
                payload = brotli.decompress(payload)

            # 데미지 정보 파싱
            damage = parse_damage(payload)
            if damage:
                # 'Idle' 스킬명 처리
                if damage.get("skill_name") == "Idle":
                    user_id = damage["used_by"]
                    # 이 시점에는 Pass 1에서 스킬을 이미 등록했으므로 안전하게 검색 가능
                    matched_skill = get_skill_for_damage(user_id, seq_num, packet_time)
                    if matched_skill:
                        damage["skill_name"] = matched_skill
                        logger.info(
                            f"[{user_id}] Replaced 'Idle' with '{matched_skill}'"
                        )

                # 빈 스킬명 처리 (DOT 등)
                elif damage.get("skill_name") == "":
                    flag_values = damage.get("flags", {})
                    prefix = "DOT" if flag_values.get("dot_flag") else "UNKNOWN"
                    suffix_parts = []
                    element_flags = [
                        ("ice_flag", "ICE"),
                        ("fire_flag", "FIRE"),
                        ("electric_flag", "ELECTRIC"),
                        ("holy_flag", "HOLY"),
                        ("bleed_flag", "BLEED"),
                        ("poison_flag", "POISON"),
                        ("mind_flag", "MIND"),
                    ]
                    for flag, name in element_flags:
                        if flag_values.get(flag):
                            suffix_parts.append(name)
                    damage["skill_name"] = f"{prefix}_{'_'.join(suffix_parts)}"

                results.append(damage)

        except Exception as e:
            logger.warning(
                f"[PASS 2: DAMAGE] Error processing block at offset {start}: {e}"
            )
            continue

    return results


def format_log(damage_data):
    ordered_keys = [
        "timestamp",
        "used_by",
        "target",
        "skill_name",
        "skill_id",
        "damage",
        "crit_flag",
        "add_hit_flag",
        "unguarded_flag",
        "break_flag",
        "first_hit_flag",
        "default_attack_flag",
        "multi_attack_flag",
        "power_flag",
        "fast_flag",
        "dot_flag",
        "ice_flag",
        "fire_flag",
        "electric_flag",
        "holy_flag",
        "bleed_flag",
        "poison_flag",
        "mind_flag",
    ]
    full_data = {
        "timestamp": damage_data.get("timestamp", 0),
        **{k: damage_data.get(k, "") for k in ordered_keys if k != "timestamp"},
    }
    return "|".join(str(full_data.get(k, "")) for k in ordered_keys)


def processor():
    global ws
    buffer = b""
    consecutive_errors = 0
    max_consecutive_errors = 5
    last_error_time = 0
    expected_next_seq = None

    while True:
        try:
            seq, payload, packet_time, flags = packet_queue.get(timeout=1)
        except queue.Empty:
            continue

        if flags & 0x01:  # FIN flag
            logger.info(
                "FIN flag detected, clearing buffer and resetting sequence tracking"
            )
            buffer = b""
            consecutive_errors = 0
            expected_next_seq = None
            continue

        if expected_next_seq is not None and seq != expected_next_seq:
            logger.warning(
                f"Sequence mismatch! Expected: {expected_next_seq}, Got: {seq}. Continuing without reset."
            )
            # buffer = b''

        expected_next_seq = seq + len(payload)

        buffer += payload

        if len(buffer) > 2 * 1024 * 1024:  # 2MB
            logger.warning(f"Buffer too large ({len(buffer)} bytes), clearing old data")
            start_idx = buffer.rfind(PACKET_START, -1024 * 1024)
            buffer = buffer[start_idx:] if start_idx > 0 else buffer[-512 * 1024 :]
            expected_next_seq = None  # Reset sequence tracking

        while True:
            start_idx = buffer.find(PACKET_START)
            if start_idx == -1:
                buffer = buffer[max(0, len(buffer) - (len(PACKET_START) - 1)) :]
                break

            end_idx = buffer.find(PACKET_END, start_idx + len(PACKET_START))
            if end_idx == -1:
                buffer = buffer[start_idx:]
                break

            complete_data = buffer[start_idx : end_idx + len(PACKET_END)]

            min_size = len(PACKET_START) + len(PACKET_END)
            if len(complete_data) < min_size:
                logger.warning(f"Complete data too small: {len(complete_data)} bytes")
                buffer = buffer[end_idx + len(PACKET_END) :]
                continue

            try:
                damages = parse_data(complete_data, seq, packet_time)

                if damages:
                    consecutive_errors = 0
                    for dmg_data in damages:
                        if dmg_data:
                            log_content = format_log(dmg_data)
                            if log_content and ws:
                                try:
                                    ws.send(log_content)
                                except Exception as e:
                                    logger.error(f"WebSocket send error: {e}")
                                    with ws_lock:
                                        ws = None
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                tb_lines = traceback.format_exception(
                    exc_type, exc_value, exc_traceback
                )
                logger.error(f"Error processing packet data: {e}\n{''.join(tb_lines)}")
                consecutive_errors += 1

                if consecutive_errors >= max_consecutive_errors:
                    logger.warning(f"Too many errors, clearing buffer.")
                    buffer = b""
                    expected_next_seq = None
                    break

            # 처리한 부분 버퍼에서 제거
            buffer = buffer[end_idx + len(PACKET_END) :]


def packet_callback(packet):
    if TCP in packet and Raw in packet:
        if packet[TCP].sport == PORT:
            seq = packet[TCP].seq
            payload = bytes(packet[Raw].load)
            packet_queue.put((seq, payload, time.time(), packet[TCP].flags))


if __name__ == "__main__":

    def wsserve(websocket):
        global ws, sniffer
        logger.info("WebSocket client connected.")
        with ws_lock:
            if ws:
                try:
                    ws.close()
                except Exception:
                    pass
            ws = websocket

            if sniffer and sniffer.running:
                sniffer.stop()

            # sniffer를 새로 시작하여 최신 filter와 callback을 보장
            sniffer = AsyncSniffer(
                filter=f"tcp and src port {PORT}", prn=packet_callback, store=False
            )
            sniffer.start()
            logger.info(
                f"Started packet capture on {conf.iface or 'default'} for port {PORT}"
            )

        try:
            for message in websocket:  # 클라이언트로부터 메시지를 기다리며 연결 유지
                logger.info(f"Received message: {message}")  # 필요한 경우 메시지 처리
        except Exception as e:
            logger.info(f"WebSocket client disconnected: {e}")
        finally:
            with ws_lock:
                if ws == websocket:
                    ws = None
            # WebSocket 연결이 끊어져도 스니퍼는 계속 동작
            logger.info("Client connection closed.")

    # 프로세서 스레드 시작
    pktprocess = threading.Thread(target=processor, daemon=True)
    pktprocess.start()

    # 웹소켓 서버 시작
    with serve(wsserve, "0.0.0.0", 8000) as server:
        logger.info("WebSocket server started on ws://0.0.0.0:8000")
        server.serve_forever()
