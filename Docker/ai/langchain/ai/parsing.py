# Docker/ai/langchain/ai/parsing.py
# ----------------------------------------------------------------------------
# SOP 版 Parsing：把工具亂 log 解析成結構化欄位。
# 關鍵防呆（程式端，不靠 7B 自律）：若 raw log 本身就是錯誤/失敗訊息，
# 直接回空結構，不送給 7B —— 這擋掉「連線失敗卻還腦補 vendor: D-Link」那類幻覺。
# ----------------------------------------------------------------------------

import json

from ai.ollama import call_ollama_json, PARSING_MODEL
from ai.prompt import PARSING_SYSTEM_PROMPT
from config.logging import log_info
from tool_config import PARSING_RESPONSE_SCHEMA

# raw log 開頭或內容出現這些，判定為失敗，直接回空、不送 7B
_HARD_FAIL_MARKERS = [
    "❌", "（錯誤", "（執行發生例外", "失敗",
    "connection reset", "connection refused", "timed out",
    "could not resolve", "no route to host", "未安裝",
]


def _empty_result(reason: str, status: str = "failed") -> dict:
    return {
        "summary": reason,
        "extracted_facts": {
            "vendor": "",
            "device_type": "",
            "discovered_endpoints": [],
            "cves": [],
        },
        "new_evidence_found": False,
        "status": status,
    }


def parse_tool_output(tool_name: str, argument: dict, raw_output: str) -> dict:
    raw_output = raw_output or ""
    log_info.info(f"🔍 [Parsing] 解析 `{tool_name}` 輸出 (長度 {len(raw_output)})...")

    low = raw_output.lower()

    # ---- 程式端硬防呆：失敗訊息直接回空，不給 7B 機會腦補 ----
    if any(m.lower() in low for m in _HARD_FAIL_MARKERS):
        log_info.info("   ↳ 偵測到失敗/錯誤訊息，直接回空結構（不送 LLM）。")
        return _empty_result(raw_output.strip()[:200] or "工具執行失敗")

    # 系統提示類（Nmap 攔截、防重複等）也不需 LLM
    if "系統提示" in raw_output or "防重複" in raw_output:
        return _empty_result(raw_output.strip()[:200], status="notice")

    # ---- 其餘才送 7B 做語意提煉 ----
    chunk = raw_output[:3000]
    user_payload = (
        f"【執行的工具】: {tool_name}\n"
        f"【工具參數】: {json.dumps(argument, ensure_ascii=False)}\n"
        f"【原始輸出 Log】:\n{chunk}\n\n"
        f"請提煉 3-5 句安全摘要、提取結構化特徵 (extracted_facts)，並標註是否發現新證據。"
    )

    try:
        resp = call_ollama_json(PARSING_SYSTEM_PROMPT, user_payload, PARSING_RESPONSE_SCHEMA, model_name=PARSING_MODEL)
    except Exception as e:
        log_info.warn(f"⚠️ [Parsing] LLM 解析例外: {e}")
        return _empty_result(f"解析例外，原始輸出前 200 字: {raw_output[:200]}", status="partial")

    if not resp or not isinstance(resp, dict) or "summary" not in resp:
        short = raw_output[:300] + "..." if len(raw_output) > 300 else raw_output
        return {
            "summary": f"工具 {tool_name} 執行完成。部分輸出：{short}",
            "extracted_facts": resp.get("extracted_facts", {}) if isinstance(resp, dict) else {},
            "new_evidence_found": len(raw_output) > 200,
            "status": "success",
        }

    log_info.info(f"📝 [Parsing] {resp.get('summary', '')[:80]} | 新證據: {resp.get('new_evidence_found')}")
    return resp
