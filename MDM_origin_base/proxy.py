import websocket
import threading
import asyncio
import websockets

clients = set()
loop = asyncio.new_event_loop()

async def send_to_clients(message):
    for client in list(clients):
        try:
            await client.send(message)
        except:
            clients.discard(client)

def on_message(ws, message):
    asyncio.run_coroutine_threadsafe(send_to_clients(message), loop)

def on_error(ws, error):
    pass  # 에러 로그 생략

def on_close(ws, close_status_code, close_msg):
    print("[패킷 분석기] 연결 종료")

def on_open(ws):
    print("[패킷 분석기] 연결됨")

async def websocket_server():
    async def handler(websocket):
        print("[웹 클라이언트] 연결됨:", websocket.remote_address)
        clients.add(websocket)
        try:
            async for _ in websocket:
                pass
        finally:
            print("[웹 클라이언트] 연결 종료:", websocket.remote_address)
            clients.discard(websocket)

    async with websockets.serve(handler, "0.0.0.0", 9000):
        await asyncio.Future()

def start_ws_server():
    asyncio.set_event_loop(loop)
    loop.run_until_complete(websocket_server())
    loop.run_forever()

if __name__ == "__main__":
    threading.Thread(target=start_ws_server, daemon=True).start()

    headers = {"User-Agent": "Mozilla/5.0"}
    ws = websocket.WebSocketApp(
        "ws://localhost:8000",
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        header=headers
    )
    ws.run_forever()