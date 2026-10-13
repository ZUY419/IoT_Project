# Docker/ai/langchain/ai/ollama.py

import json
import os
from pathlib import Path
import re
import sys
from dotenv import load_dotenv

# ⚠️【明確載入 ai/langchain/.env】本檔在 ai/langchain/ai/ 底下，往上一層才是 langchain 根目錄。
#    不加這行的話，OLLAMA_TIMEOUT / OLLAMA_HOST 等要看別的模組有沒有先載 .env，容易「改了沒反應」。
#    這裡直接鎖定 langchain 的 .env，讓 OLLAMA_TIMEOUT 這顆旋鈕一定吃得到。
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# LangChain Imports (支援原生 LangChain Community / LangChain Core 鏈與提示詞模版)
try:
    from langchain_community.chat_models import ChatOllama
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import JsonOutputParser
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    ChatOllama = None
    ChatPromptTemplate = None
    JsonOutputParser = None

from config.logging import log_info

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import util

# 從全域中央設定 config/config.py 載入統一的 ollama_client, llm 與模型/連線設定
try:
    from config.config import (
        ollama_client,
        llm,
        OLLAMA_HOST,
        OLLAMA_MODEL,
        DEFAULT_MODEL,
        REASONING_MODEL,
        GENERATION_MODEL,
        PARSING_MODEL,
    )
except ImportError:
    try:
        from ollama import Client
    except ImportError:
        Client = None

    load_dotenv()
    OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    DEFAULT_MODEL = OLLAMA_MODEL
    REASONING_MODEL = os.getenv("REASONING_MODEL", OLLAMA_MODEL)
    GENERATION_MODEL = os.getenv("GENERATION_MODEL", OLLAMA_MODEL)
    PARSING_MODEL = os.getenv("PARSING_MODEL", OLLAMA_MODEL)
    llm = None

    def get_ollama_client():
        if Client is None:
            log_info.warn("Ollama SDK 未安裝；系統將嘗試使用模擬/預設模式運作。")
            return None
        try:
            client = Client(host=OLLAMA_HOST)
            log_info.info(f"Ollama Client 初始化成功 (Host: {OLLAMA_HOST})")
            return client
        except Exception as e:
            log_info.error(f"無法初始化 Ollama 客戶端 ({OLLAMA_HOST}): {e}")
            return None

    ollama_client = get_ollama_client()


# =============================================================================
# ⚠️【Ollama 呼叫逾時】這是「卡在某一筆 CVE 永遠不回」的根治設定。
# 症狀：qwen2.5-coder:7b 被連續操很多次後，偶爾某次呼叫卡死不回；
#       若 HTTP 連線沒設逾時，Python 就無限等 → 整條 Stage 4 凍住。
# 作法：
#   - LangChain ChatOllama（path 1，你實際走的路）→ 加 timeout
#   - 原生 Ollama Client（path 2 備援）→ 另建一個帶 timeout 的 client 來呼叫
# 數字建議略小於 generation.py 的 LLM_CALL_TIMEOUT(預設 90s)，
# 讓底層 socket 先乾淨中斷、拋例外被接住，而不是等到應用層才硬跳。
# 可用環境變數 OLLAMA_TIMEOUT 調整。
# =============================================================================
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "80"))

# 另建一個「帶逾時」的原生 client 給 path 2 用
# （config/config.py 提供的 ollama_client 可能沒設 timeout，這裡不去動它，另開一個安全的）。
_timeout_client = None
try:
    from ollama import Client as _OllamaClientCls
    _timeout_client = _OllamaClientCls(host=OLLAMA_HOST, timeout=OLLAMA_TIMEOUT)
    log_info.info(f"🕒 Ollama 逾時客戶端就緒 (timeout={OLLAMA_TIMEOUT}s @ {OLLAMA_HOST})")
except Exception as _e:
    log_info.warn(f"⚠️ 無法建立帶逾時的 Ollama 客戶端，path 2 將沿用既有 ollama_client：{_e}")


def create_langchain_chat_model(model_name: str, temperature: float = 0.0, timeout: float = None):
    """
    建立 LangChain ChatOllama 物件 (針對 Qwen2.5-Coder 優化 sampling 參數)
    ⚠️ 加上 timeout，避免某次 chain.invoke() 卡住不回導致整條流程凍住。
    timeout=None 時用全域 OLLAMA_TIMEOUT；某些重任務（如改寫 PoC）可傳入較大的值。
    """
    if not LANGCHAIN_AVAILABLE or ChatOllama is None:
        return None
    eff_timeout = timeout if timeout else OLLAMA_TIMEOUT
    try:
        return ChatOllama(
            base_url=OLLAMA_HOST,
            model=model_name,
            temperature=temperature,
            top_p=0.95,
            format="json",
            timeout=eff_timeout,   # ⚠️ 單次呼叫逾時（秒）
        )
    except TypeError:
        # 某些 langchain_community 版本的 ChatOllama 不收 timeout 參數，
        # 退回不帶 timeout 的建法（此時仍有 generation.py 的應用層逾時保護）。
        log_info.warn("⚠️ 此版本 ChatOllama 不支援 timeout 參數，改用應用層逾時保護。")
        return ChatOllama(
            base_url=OLLAMA_HOST,
            model=model_name,
            temperature=temperature,
            top_p=0.95,
            format="json",
        )
    except Exception as e:
        log_info.error(f"無法建立 LangChain ChatOllama 模型 ({model_name}): {e}")
        return None


def call_ollama_json(
    system_prompt: str,
    user_content: str,
    response_schema: dict,
    model_name: str = None,
    timeout: float = None,
) -> dict:
    """
    Qwen2.5-Coder / Ollama 相容的高可靠度 JSON 結構化呼叫函式
    優先使用由 config/config.py 提供之 ollama_client 呼叫
    timeout=None 時用全域 OLLAMA_TIMEOUT；傳入值則本次呼叫套用該逾時（給重任務用）。
    """
    target_model = model_name or DEFAULT_MODEL
    eff_timeout = timeout if timeout else OLLAMA_TIMEOUT
    log_info.AI_prompt(
        f"[Model: {target_model}] System Prompt:\n{system_prompt[:250]}...\nUser Content:\n{user_content[:350]}..."
    )

    # 1. 嘗試使用 LangChain ChatOllama + LCEL 鏈執行
    if LANGCHAIN_AVAILABLE:
        try:
            lc_llm = create_langchain_chat_model(target_model, timeout=eff_timeout)
            if lc_llm:
                prompt_template = ChatPromptTemplate.from_messages([
                    ("system", "{system_prompt}"),
                    ("user", "{user_content}"),
                ])
                chain = prompt_template | lc_llm | JsonOutputParser()
                parsed_res = chain.invoke({
                    "system_prompt": system_prompt,
                    "user_content": user_content,
                })

                if isinstance(parsed_res, dict):
                    log_info.info(
                        f"🔗 [LangChain Chain] ({target_model}) 成功透過 LangChain LCEL 鏈取得解析回應！"
                    )
                    log_info.AI_response(
                        json.dumps(parsed_res, ensure_ascii=False)
                    )
                    return parsed_res
        except Exception as lce:
            log_info.warn(
                f"⚠️ [LangChain LCEL 呼叫跳過]: {lce}，切換至 Ollama 原生客戶端處理。"
            )

    # 2. Ollama 原生 Client 備用回退方案
    #    若本次要求的逾時跟全域不同（如改寫 PoC 給更長時間），就臨時建一個帶該逾時的 client。
    native_client = _timeout_client or ollama_client
    if eff_timeout != OLLAMA_TIMEOUT:
        try:
            from ollama import Client as _C
            native_client = _C(host=OLLAMA_HOST, timeout=eff_timeout)
        except Exception:
            pass  # 建不出來就沿用既有 client（仍有 generation.py 應用層逾時保護）
    if native_client is None:
        log_info.error(f"Ollama Client 未就緒 ({OLLAMA_HOST})，無法呼叫 LLM。")
        return {}

    try:
        response = native_client.chat(
            model=target_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            format=response_schema,
            options={"temperature": 0.0, "top_p": 0.95},
        )

        raw_content = response.message["content"].strip()
        log_info.AI_response(raw_content)

        cleaned_json = re.sub(
            r"^```(?:json)?\s*", "", raw_content, flags=re.MULTILINE
        )
        cleaned_json = re.sub(r"\s*```$", "", cleaned_json, flags=re.MULTILINE)

        parsed = json.loads(cleaned_json)
        if not isinstance(parsed, dict):
            log_info.error(f"LLM 回應解析非字典型態: {type(parsed)}")
            return {}

        return parsed

    except json.JSONDecodeError as e:
        log_info.error(
            f"LLM 回應 JSON 解析失敗: {e}，原始輸出: {raw_content[:200]}"
        )
        return {}
    except Exception as e:
        err_str = str(e)
        if "not found" in err_str.lower() and target_model != DEFAULT_MODEL:
            log_info.warn(
                f"⚠️ 模型 `{target_model}` 未找到，自動退回預設模型 `{DEFAULT_MODEL}` 重新嘗試..."
            )
            return call_ollama_json(
                system_prompt,
                user_content,
                response_schema,
                model_name=DEFAULT_MODEL,
            )

        log_info.error(
            f"呼叫 Ollama 模型 ({target_model} @ {OLLAMA_HOST}) 發生例外: {e}"
        )
        return {}