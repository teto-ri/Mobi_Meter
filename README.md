# 마비노기 모바일 데미지 미터기 분석 및 개선

## 소개

본 프로젝트는 커뮤니티에서 공개된 원본 데미지 로그 분석기(https://github.com/MabinogiMeter/MDM/releases/tag/v1.0.0), (https://github.com/pblyat/MabinogiTools/tree/main/DamageMeter) 를 기반으로

비공식 WebSocket 로그 데이터를 프록시 중계로 확장해, 편리하게 분석 가능한 인터페이스를 추가한 확장 프로젝트입니다.

## 목적

본 프로젝트는 비공식 로그 뷰어의 정보를 시각적으로 표현하기 위한 도구로,

직접적인 패킷 분석을 수행하지 않으며 비공식 패킷 분석기의 WebSocket 로그 데이터를 동일 네트워크 상의 디바이스에서 시각화하는 것에 초점을 두었습니다.

해당 데이터는 공개된 도구에 의해 노출되는 수준이며, 게임 플레이에 영향을 주거나 데이터 변조, 유출을 전혀 포함하지 않습니다.

또한, 개인 연구 및 UI 실험 목적으로 진행되었음을 밝힙니다.

## 기능

원본 툴은 소스가 비공개이며 localhost에서만 데이터를 확인 가능했으나, 

본 프로젝트를 이용해서 VM이나 포트미러링이 가능한 기기에서 MDM패킷 분석기를 실행하고

이를 같은 네트워크 안의 모바일/웹에서 필요한 실시간 전투 데이터를 시각화해, 유저별 기여도, 자동화 패턴, 스킬 사용 주기 등을 분석할 수 있습니다.



## 테스트 방법

필자는 윈도우의 기본 가상시스템인 Hyper-V를 이용하여 구동했습니다.

1. 윈도우10 VM 설치 및 실행 참조 링크 (https://blog.naver.com/yujuit/223237345171)

2. 윈도우 환경의 VM 세팅이 끝났다면, 호스트의 패킷이 분석기에 들어오는지 확인합니다.
   
   2-1. VMware일경우, 브릿지 모드로 실행하면 됩니다.
   
   2-2. Hyper-V의 경우 호스트PC -> VM 안으로 패킷을 전달하도록 수동 설정이 필요합니다.

      먼저 Hyper-V 관리자 -> 가상 스위치 관리자 -> 새 가상 네트워크 스위치 -> 외부, 만들기로 네트워크 스위치를 만들어줍니다.
   
      다음, 호스트 PC에서 Powershell 에서 다음과 같은 명령어를 수행해주세요.
   
      ### 1. 가상 스위치에 분석용 포트 추가
      Add-VMNetworkAdapter -VMName "<VM이름>" -Name "Monitor" -SwitchName "<가상 스위치 이름>"
      
      ### 2. Monitor 어댑터를 미러링 대상(Destination)으로 설정
      Set-VMNetworkAdapter -VMName "<VM이름>" -Name "Monitor" -PortMirroring Destination
      
      ### 3. 외부 포트를 미러링 원본(Source)으로 설정
      $ExtPortFeature = Get-VMSystemSwitchExtensionPortFeature -FeatureName "Ethernet Switch Port Security Settings"
      $ExtPortFeature.SettingData.MonitorMode = 2
      Add-VMSwitchExtensionPortFeature -ExternalPort -SwitchName "<가상 스위치 이름>" -VMSwitchExtensionFeature $ExtPortFeature
      
      ### 4. Microsoft NDIS Capture 확장 활성화
      Enable-VMSwitchExtension -VMSwitchName "<가상 스위치 이름>" -Name "Microsoft NDIS Capture"

5. VM에 패킷 캡처용 winPcap(https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe) 또는 nPcap(https://npcap.com/dist/npcap-1.82.exe)을 설치합니다.
6. run.bat을 실행합니다.


## 비공식 패킷 분석기 구조

>  본 내용은 직접 패킷을 해석하거나 변조하지 않았으며, 공개된 분석기를 디컴파일해 이해한 동작 구조입니다.  
>  패킷 수집 및 해석은 일부 게임에서 이용 약관 또는 관련 법에 저촉될 수 있으므로 주의가 필요합니다.

---

### 🔄 데이터 처리 절차 (구조 이해 요약)

- **1. TCP 패킷 수신**
  - `Scapy` 라이브러리를 이용해 로컬 네트워크의 TCP 패킷을 수신
  - 마비노기.exe의 서버 통신 포트 번호 `16000`만 감지하여 필터링

- **2. 세그먼트 조립**
  - TCP는 데이터를 여러 조각(세그먼트)으로 나눠 보내므로, 순서대로 정렬하고 중복 제거
  - 일부 조각이 누락된 경우엔 다음 수신 때까지 대기
  - 완전한 데이터 블록이 모이면 다음 단계로 진행

- **3. 패킷 필터링**
  - 헤더가 유효하지 않거나 의미 없는 데이터 (`\x00...`, 특정 매직넘버 등)는 제외
  - 내부에 `0x03050000`(데미지 타입 시그니처) 포함 여부를 기준으로 유효성 확인

- **4. 압축 해제**
  - 내부 데이터가 `Brotli`로 압축된 경우 자동으로 해제
  - 압축 알고리즘 종류의 경우 'Brute Force'로 해제됨.
  - 이후 바이너리 형식의 상세 정보 추출

- **5. 전투 정보 추출**
  - 다음과 같은 구조로 순차적으로 추출:
    - **공격자 ID (8바이트)**: 누가 공격했는지
    - **피격자 ID (8바이트)**: 누가 맞았는지
    - **스킬 이름 길이 (4바이트)** → **스킬 이름 (가변 길이)**: 사용된 기술 이름
    - **데미지 수치 (4바이트)**: 실제 피해량 (특정 값이면 무효)
    - **부가 정보 (12바이트)**: 사용되지 않지만 그대로 저장됨
    - **속성 플래그 (20바이트)**: 크리티컬, 속성(불/얼음/전기 등), 연타 등 효과 정보
    - **스킬 ID (8바이트)**: 고유 기술 ID

- **6. 정보 후처리**
  - 스킬명이 없는 경우 `DOT_FIRE`, `DOT_ICE` 등 속성 기반 이름을 자동 생성
  - 플래그는 각 바이트 비트를 읽어 True/False로 변환
    - 예: `crit_flag=True`, `fire_flag=False`, `multi_attack_flag=True` 등

- **7. 로그 변환 및 전송**
  - 추출한 정보를 `|` 구분자로 나열해 문자열로 만듦
  - WebSocket으로 외부 클라이언트(시각화 도구)로 실시간 전송

---

패킷 내부의 전투 관련 데이터는 보통 다음 순서로 구성되어 있습니다:

```
[스킬 이름 (유니코드)] + [데미지 (4바이트 정수)]
```

- **스킬 이름**은 UTF-16LE 형식 (한 글자당 2바이트)으로 저장됨
- **데미지**는 4바이트 리틀엔디언 정수로 저장됨

---

### 분석기 예시

#### 원시 데이터 (16진수)

```
41 00 72 00 62 00 61 00 6c 00 69 00 73 00 74 00 
5f 00 47 00 75 00 73 00 74 00 69 00 6e 00 67 00 
42 00 6f 00 6c 00 74 00 5f 00 30 00 31 00 
e1 09 00 00
```

#### 구성 해석

| 항목         | 내용                                                              |
|--------------|-------------------------------------------------------------------|
| 스킬 이름    | `Arbalist_GustingBolt_01` (총 44바이트, UTF-16LE로 인코딩됨)        |
| 데미지 값    | `e1 09 00 00` → 0x09E1 (리틀엔디언) = **2529**                      |

#### 최종 해석 결과

```json
{
  "skill_name": "Arbalist_GustingBolt_01",
  "damage": 2529
}
```

---

### 참고

- UTF-16LE은 문자를 2바이트씩 표현하기 때문에, A(0x41)는 `41 00`으로 저장됩니다.
- 데미지는 항상 4바이트이며, 리틀엔디언 방식이므로 **뒤에서부터 읽습니다**:
  - `e1 09 00 00` → `0x000009e1` = 2529

---

### ✅ 분석기 출력 형식

분석기는 전투 데이터 하나를 다음과 같이 `|` 구분자로 구분된 문자열 형태로 출력합니다:

```
timestamp | used_by | target | skill_name | skill_id | damage | crit_flag | addhit_flag | unguarded_flag | break_flag | first_hit_flag | default_attack_flag | multi_attack_flag | power_flag | fast_flag | dot_flag | ice_flag | fire_flag | electric_flag | holy_flag | bleed_flag | poison_flag | mind_flag
```

총 23개의 항목이 하나의 문자열로 이어져 있습니다.

---

### 실제 출력 예시

아래는 분석기가 출력하는 예시 로그입니다:

```
1717821123456|fa1a32c41b9d4e5f|dd4b21e94e8a6a33|Arbalist_GustingBolt_01|0011223344556677|2529|1|0|0|0|0|1|0|0|1|0|0|1|0|0|0|0|0
```

#### 항목별 의미

| 항목 이름               | 예시 값                      | 설명 |
|------------------------|------------------------------|------|
| timestamp              | 1717821123456                | 로그 생성 시각 (ms 단위, epoch 기준) |
| used_by                | fa1a32c41b9d4e5f             | 공격자(캐릭터)의 ID (8바이트 hex) |
| target                 | dd4b21e94e8a6a33             | 피격 대상의 ID (8바이트 hex) |
| skill_name             | Arbalist_GustingBolt_01      | 사용한 스킬 이름 |
| skill_id               | 0011223344556677             | 스킬의 고유 식별자 |
| damage                 | 2529                         | 데미지 수치 |
| crit_flag              | 1                            | 크리티컬 여부 (1=Yes, 0=No) |
| addhit_flag            | 0                            | 추가 타격 여부 |
| unguarded_flag         | 0                            | 방어 무시 여부 |
| break_flag             | 0                            | 가드 브레이크 여부 |
| first_hit_flag         | 0                            | 선공 여부 |
| default_attack_flag    | 1                            | 일반 공격 여부 |
| multi_attack_flag      | 0                            | 멀티 타격 여부 |
| power_flag             | 0                            | 강타 여부 |
| fast_flag              | 1                            | 고속기 여부 |
| dot_flag               | 0                            | 도트 데미지 여부 |
| ice_flag               | 0                            | 빙결 속성 여부 |
| fire_flag              | 1                            | 화염 속성 여부 |
| electric_flag          | 0                            | 전격 속성 여부 |
| holy_flag              | 0                            | 성속성 여부 |
| bleed_flag             | 0                            | 출혈 여부 |
| poison_flag            | 0                            | 중독 여부 |
| mind_flag              | 0                            | 정신 공격 여부 |

---


### 주의
- 단순 분석 도구라도 **게임사 정책에 따라 제재**될 수 있으며, 본 코드는 **학습 목적의 구조 분석 참고용**입니다.


  
