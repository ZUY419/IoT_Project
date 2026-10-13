import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import List, Optional

import API.util as util
from anyio import to_thread
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# 設定 CORS 允許跨域連線
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

web_service_process = None
pentest_process = None


class ConnectionManager:

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(
            f"[WebSocket] 新接收端已連線，當前連線數: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(
                f"[WebSocket] 接收端已斷開，當前連線數: {len(self.active_connections)}"
            )

    async def broadcast(self, message: str):
        disconnected_clients = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                print(f"[WebSocket Error] 發送訊息失敗: {e}")
                disconnected_clients.append(connection)

        for dead_conn in disconnected_clients:
            self.disconnect(dead_conn)


manager = ConnectionManager()


class CommandPayload(BaseModel):
    log: str
    log_type: str


class StartPentestPayload(BaseModel):
    device_name: Optional[str] = None


def _check_web_service_ready(url: str, timeout_sec: int = 30) -> bool:
    start_time = time.time()
    while time.time() - start_time < timeout_sec:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "HealthCheck"}
            )
            with urllib.request.urlopen(req, timeout=2) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(1)
    return False


def _build_run_command(script_path: Path, args: List[str] = None) -> List[str]:
    """一律以背景模式執行 run.sh，不再開啟任何 GUI 終端機視窗。

    原本會依 DISPLAY/WAYLAND_DISPLAY 偵測並用 gnome-terminal / xterm / konsole
    把 run.sh 包進一個彈出式終端機裡執行；由於所有日誌都已透過 send_log API
    廣播到網頁，那個視窗其實是多餘的，故改為直接背景執行。
    """
    return ["bash", str(script_path)] + (args if args else [])


def _sync_get_devices_list():
    folder = util.get_folder()
    devices_folder = (
        folder.parent.parent
        / "Firmware"
        / "Firmware_tool"
        / "firmware-analysis-plus"
        / "fw_bin"
    ).resolve()

    if not devices_folder.exists() or not devices_folder.is_dir():
        print(f"[!] 找不到韌體資料夾: {devices_folder}")
        return {"status": 404, "files_name": []}

    file_names = [
        file.stem for file in devices_folder.iterdir() if file.is_file()
    ]
    return {"status": 200, "files_name": file_names}


def _sync_start_pentest(device_name: Optional[str]):
    global web_service_process

    if web_service_process is not None and web_service_process.poll() is None:
        return {"status": 400, "message": "測試服務已經在執行中了！"}

    current_folder = util.get_folder()
    project_root = current_folder.parent.parent
    print(project_root)

    run_sh_path = (project_root / "run.sh").resolve()

    if not run_sh_path.exists():
        return {"status": 404, "message": f"找不到 run.sh 腳本: {run_sh_path}"}

    env_vars = os.environ.copy()

    try:
        run_args = [device_name] if device_name else []
        run_cmd = _build_run_command(run_sh_path, run_args)

        # 背景行程的輸出導向 log 檔，既不跳視窗，也不會污染 API server 的 console。
        # 若完全不需要輸出，可把 stdout/stderr 改成 subprocess.DEVNULL。
        log_path = (project_root / "pentest_run.log").resolve()
        log_file = open(log_path, "a", encoding="utf-8")

        # start_new_session=True 建立獨立 Process Group，
        # 這樣後續可用 os.killpg 一次清空 run.sh 及其子行程，且不會波及 openWeb.sh
        web_service_process = subprocess.Popen(
            run_cmd,
            cwd=str(project_root),
            env=env_vars,
            start_new_session=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

        return {
            "status": 200,
            "message": "已於背景成功啟動環境，將於服務就緒後自動開啟相關視窗！",
            "pid": web_service_process.pid,
        }
    except Exception as e:
        return {"status": 500, "message": f"啟動失敗: {str(e)}"}


def _sync_stop_pentest():
    global web_service_process, pentest_process

    # 1. 關閉 pentest_process 及其子行程 (若有使用)
    if pentest_process is not None and pentest_process.poll() is None:
        try:
            os.killpg(os.getpgid(pentest_process.pid), signal.SIGTERM)
            pentest_process.wait(timeout=2)
        except Exception:
            try:
                os.killpg(os.getpgid(pentest_process.pid), signal.SIGKILL)
            except Exception:
                pass
        pentest_process = None

    # 2. 關閉 web_service_process (run.sh) 及其子行程
    if web_service_process is not None and web_service_process.poll() is None:
        try:
            os.killpg(os.getpgid(web_service_process.pid), signal.SIGTERM)
            web_service_process.wait(timeout=2)
        except Exception:
            try:
                os.killpg(os.getpgid(web_service_process.pid), signal.SIGKILL)
            except Exception:
                pass
        web_service_process = None

    # 3. 備用方案：只精準匹配 run.sh 的行程，保護 openWeb.sh 不受影響
    try:
        subprocess.run(
            ["pkill", "-9", "-f", r"(^|/)run\.sh(\s|$)"], check=False
        )
        print("[*] 已針對 run.sh 發送強制清理訊號 (已排除 openWeb.sh)")
    except Exception as e:
        print(f"[!] 清理 run.sh 時發生例外: {e}")

    return {
        "status": 200,
        "message": "已成功關閉 run.sh 相關行程，openWeb.sh 依然保持運行！",
    }


def _sync_restart_ai():
    current_folder = util.get_folder()
    project_root = current_folder.parent.parent

    # restartAI.sh 位於 run.sh 同層的 Docker/ 資料夾內
    restart_sh_path = (project_root / "Docker" / "restartAI.sh").resolve()

    if not restart_sh_path.exists():
        return {
            "status": 404,
            "message": f"找不到 restartAI.sh 腳本: {restart_sh_path}",
        }

    env_vars = os.environ.copy()

    try:
        # 背景執行，不跳終端機；輸出導向 restart_ai.log。
        # cwd 設在 Docker/ 目錄，確保腳本內的 docker compose 等相對路徑能正確解析。
        log_path = (project_root / "restart_ai.log").resolve()
        log_file = open(log_path, "a", encoding="utf-8")

        subprocess.Popen(
            ["bash", str(restart_sh_path)],
            cwd=str(restart_sh_path.parent),
            env=env_vars,
            start_new_session=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

        return {
            "status": 200,
            "message": "已於背景送出 AI 重新啟動指令 (restartAI.sh)！",
        }
    except Exception as e:
        return {"status": 500, "message": f"重新啟動失敗: {str(e)}"}


@app.post("/api/pentest/send_log")
async def receive_from_a(payload: CommandPayload):
    log_data = json.dumps({"log": payload.log, "log_type": payload.log_type})
    await manager.broadcast(log_data)
    return {"status": 200, "message": "Log 已成功廣播"}


@app.websocket("/ws/receive_b")
async def websocket_b(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@app.post("/api/pentest/get_devices_list")
async def get_devices_list():
    try:
        return await to_thread.run_sync(_sync_get_devices_list)
    except Exception as e:
        return {"status": 500, "files_name": [], "error": str(e)}


@app.post("/api/pentest/start_pentest")
async def start_pentest(payload: StartPentestPayload = None):
    try:
        device_name = payload.device_name if payload else None
        return await to_thread.run_sync(_sync_start_pentest, device_name)
    except Exception as e:
        return {"status": 500, "message": str(e)}


@app.post("/api/pentest/stop_pentest")
async def stop_pentest():
    try:
        return await to_thread.run_sync(_sync_stop_pentest)
    except Exception as e:
        return {"status": 500, "message": str(e)}


@app.post("/api/pentest/restart_ai")
async def restart_ai():
    try:
        return await to_thread.run_sync(_sync_restart_ai)
    except Exception as e:
        return {"status": 500, "message": str(e)}