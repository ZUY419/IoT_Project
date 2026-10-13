# Docker/ai/langchain/config/config.py
import os
from pathlib import Path
from dotenv import load_dotenv

try:
    from langchain_ollama import OllamaLLM
except ImportError:
    OllamaLLM = None

try:
    from ollama import Client
except ImportError:
    Client = None

load_dotenv()


# =============================================================================
# 1. 統一全域設定 (模型與環境變數)
# =============================================================================
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:14b")

DEFAULT_MODEL = OLLAMA_MODEL
REASONING_MODEL = os.getenv("REASONING_MODEL", OLLAMA_MODEL)
GENERATION_MODEL = os.getenv("GENERATION_MODEL", OLLAMA_MODEL)
PARSING_MODEL = os.getenv("PARSING_MODEL", OLLAMA_MODEL)

# =============================================================================
# [NEW] 🎯 目標與沙盒設定 (Target & Workspace Configuration)
# =============================================================================
# 這裡從 .yml 變數讀取目標 IP，如果沒設定，預設為 D-Link 靶機的 192.168.0.1
TARGET_IP = os.getenv("PENTEST_TARGET", os.getenv("TARGET_IP", "192.168.0.1"))

# 設定工作沙盒路徑 (當前目錄下的 workspace 資料夾)
WORKSPACE_DIR = Path.cwd() / "workspace"

# 【自動初始化沙盒】只要 config.py 被載入，自動確保 workspace 資料夾存在，防止工具噴 FileNotFoundError
try:
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
except Exception as e:
    print(f"[Config Warning] 無法建立工作沙盒目錄: {e}")

# =============================================================================
# 2. 提供給未來如果想用 LangChain 模組的初始化
# =============================================================================
llm = (
    OllamaLLM(model=OLLAMA_MODEL, base_url=OLLAMA_HOST)
    if OllamaLLM is not None
    else None
)

# =============================================================================
# 3. 提供給我們目前 main.py 原生感知模組使用的 Client
# =============================================================================
def get_ollama_client():
    """
    初始化並回傳 Ollama 客戶端實例
    """
    if Client is None:
        print("[Config] Ollama SDK 未安裝；Stage 1 可在無 LLM 模式下執行。")
        return None
    try:
        client = Client(host=OLLAMA_HOST)
        return client
    except Exception as e:
        print(f"[Config Error] 無法初始化 Ollama 客戶端: {e}")
        return None

ollama_client = get_ollama_client()
