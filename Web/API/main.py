import util

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from typing import List
from pydantic import BaseModel
import subprocess
import sys
import json

app = FastAPI()

# 解決瀏覽器跨域 (CORS) 問題
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 開發時允許所有來源
    allow_credentials=True,
    allow_methods=["*"],  # 包含 POST, OPTIONS 等方法
    allow_headers=["*"],
)

# 儲存所有已連線的 B (前端接收端)
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        # 將訊息廣播給所有 B 端
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

# 定義 A 傳送過來的資料格式
class CommandPayload(BaseModel):
    log: str
    log_type: str

# 1. A 透過這個 API 發送資料
@app.post("/api/pentest/send_log")
async def receive_from_a(payload: CommandPayload):
    print(f"log type: {payload.log_type}, log: {payload.log}")
    
    # 💡 關鍵：使用 json.dumps() 確保轉成雙引號的合法 JSON 字串
    log_data = json.dumps({
        "log": payload.log,
        "log_type": payload.log_type
    })
    
    # 2. 透過 WebSocket 轉發/推播給 B
    await manager.broadcast(log_data)
    
    return {"status": 200, "message": "已成功送達並轉發"}

# B (接收端) 的 WebSocket 路由
@app.websocket("/ws/receive_b")
async def websocket_b(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # 保持連線等待廣播
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/api/pentest/get_devices_list")
def get_devices_list():
    try:
        # 取得基礎資料夾並轉換為絕對路徑
        folder = util.get_folder() # 假設這是你原本取得基準路徑的方法
        devices_folder = (folder / ".." / ".." / "Firmware" / "Firmware_tool" / "firmware-analysis-plus" / "fw_bin").resolve()
        
        # 檢查資料夾是否存在
        if not devices_folder.exists() or not devices_folder.is_dir():
            return {
                "status": 404,
                "files_name": []
            }
        
        # 讀取該資料夾下的所有檔案名稱
        file_names = [file.name for file in devices_folder.iterdir() if file.is_file()]
        
        return {
            "status": 200,
            "files_name": file_names
        }
    except Exception as e:
        print(f"[!] 讀取裝置清單失敗: {e}")
        return {
            "status": 500,
            "files_name": []
        }

# 記錄背景執行的程序，方便之後想要關閉它
running_process = None

@app.post("/api/pentest/start_pentest")
def start_pentest():
    global running_process

    # 檢查是否已經在跑了
    if running_process is not None and running_process.poll() is None:
        return {
            "status": 400,
            "message": "滲透測試已經在執行中了！"
        }

    try:
        # 💡 關鍵修正：
        # 1. 用 sys.executable 自動帶入當前正在跑 FastAPI 的那個 Python 路徑（絕對不會抓錯環境）
        # 2. 用 Popen 而不是 run，讓它在「背景」非同步執行，才不會卡住 API 請求
        running_process = subprocess.Popen([sys.executable, "../test_terminal.py"])

        return {
            "status": 200,
            "message": "Start Pentest.",
            "pid": running_process.pid
        }
    except Exception as e:
        return {
            "status": 500,
            "message": str(e)
        }