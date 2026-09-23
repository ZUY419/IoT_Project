import util

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

app = FastAPI()

# 解決瀏覽器跨域 (CORS) 問題
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 開發時允許所有來源
    allow_credentials=True,
    allow_methods=["*"],  # 包含 POST, OPTIONS 等方法
    allow_headers=["*"],
)

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

@app.post("/api/pentest/start_pentest")
def start_pentest():
    return {
        "status": 200,
        "message": "Start Pentest."  # 順便修正了一個小拼字筆誤
    }