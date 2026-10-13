# Docker/ai/langchain/ai/generation.py
# ----------------------------------------------------------------------------
# SOP 版 Generation：唯一工作是「讀一個 CVE 的描述與 PoC，產生 N 條可直接執行的
# Linux 驗證指令」。這是 7B 做得還行的局部任務（有明確輸入輸出），不涉及流程決策。
# ----------------------------------------------------------------------------

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from ai.ollama import call_ollama_json, GENERATION_MODEL
from config.logging import log_info
from tool_config import POC_CMDS_SCHEMA, POC_FILE_SCHEMA


# =============================================================================
# ⚠️【單次 LLM 呼叫逾時保護】
# 症狀：qwen2.5-coder:7b 被連續操很多次後，偶爾某一次呼叫「卡住不回」，
#       而 ollama 呼叫若沒逾時，Python 就無限等 → 整條 Stage 4 凍在那一筆 CVE。
# 作法：把每一次 call_ollama_json 丟到背景執行緒，最多等 LLM_CALL_TIMEOUT 秒；
#       超時就放棄這一次（丟 TimeoutError 給呼叫端 → 走保底 / 跳過），換下一步。
#       卡住的那條執行緒設為 daemon，隨主程式自然收掉，不擋流程。
# 注意：這是「應用層」的保護。要讓底層 HTTP socket 也真的中斷，最乾淨的做法是
#       在 ai/ollama.py 建 ollama.Client 時加 timeout（見本次說明）。兩者並用最保險。
# =============================================================================
LLM_CALL_TIMEOUT = float(os.getenv("LLM_CALL_TIMEOUT", "90"))
# ⚠️【改寫 PoC 專屬逾時】改寫 PoC 要吐一整個可執行檔，是最重的任務，常比一般指令生成久很多。
#    給它獨立且較長的逾時，不必把全域 LLM_CALL_TIMEOUT/OLLAMA_TIMEOUT 一起調大。
#    可用環境變數 POC_ADAPT_TIMEOUT 調整（預設 180 秒）。
POC_ADAPT_TIMEOUT = float(os.getenv("POC_ADAPT_TIMEOUT", "180"))
_LLM_EXECUTOR = ThreadPoolExecutor(max_workers=4)


def _call_llm_json_guarded(guard_timeout: float = None, **kwargs):
    """呼叫 call_ollama_json，最多等 guard_timeout 秒（預設 LLM_CALL_TIMEOUT）。
    超時丟 FutureTimeout，由各函式自行處理（保底或跳過）。
    kwargs 裡可帶 timeout=，一路傳到 call_ollama_json 設定底層 socket 逾時。"""
    gt = guard_timeout if guard_timeout else LLM_CALL_TIMEOUT
    future = _LLM_EXECUTOR.submit(call_ollama_json, **kwargs)
    return future.result(timeout=gt)


POC_SYSTEM_PROMPT = """You are a penetration testing PoC command generator powered by Qwen2.5-Coder.
Given ONE CVE (its ID, description and any PoC hints), produce concrete Linux shell commands that
attempt to VERIFY whether the target is vulnerable.

STRICT RULES:
1. Output ONLY a JSON object: {"commands": ["cmd1", "cmd2", ...]}.
2. Every command must be a single-line, directly-runnable Linux shell command (curl, wget, nc, etc.).
3. Commands MUST target the given TARGET_IP. Never use example.com or placeholder IPs.
4. Prefer safe verification over destructive actions: use curl/wget to probe endpoints,
   send the PoC request, and let the caller inspect the response.
5. Produce DIFFERENT approaches across the commands (different endpoints, methods, payloads),
   not the same command repeated.
6. If the CVE cannot be meaningfully tested with a shell command, still output your best-effort
   probing commands (e.g. curl the service banner) rather than refusing.
7. No markdown, no commentary, JSON only.
"""


def _fallback_cmds(cve: dict, target_ip: str, n: int) -> list:
    """7B 失敗時的保底指令：至少對目標做基本探測，確保 Stage 4 有東西可跑。"""
    cid = cve.get("cve_id") or cve.get("cveID") or "CVE"
    base = [
        f"curl -i -s http://{target_ip}/",
        f"curl -i -s -X POST http://{target_ip}/",
        f"curl -s -A 'PoC-{cid}' http://{target_ip}/",
        f"curl -i -s http://{target_ip}/cgi-bin/",
        f"curl -i -s http://{target_ip}/HNAP1/",
    ]
    return base[:n]


def _sanitize_cmd(c, target_ip: str):
    """清洗單條指令：換掉 placeholder、擋外部網址與破壞性指令。
    合格回傳清洗後字串；不合格回 None。"""
    if not isinstance(c, str) or not c.strip():
        return None
    c = c.strip()
    c = c.replace("example.com", target_ip).replace("TARGET_IP", target_ip)
    c = c.replace("<target>", target_ip).replace("{target}", target_ip)
    # 指令裡若出現 http(s) 但完全沒提到 target_ip，視為亂填，丟棄
    if ("http://" in c or "https://" in c) and target_ip not in c:
        return None
    # 擋掉明顯破壞性指令
    if re.search(r"\brm\s+-rf\b|\bmkfs\b|\b:\(\)\{", c):
        return None
    return c


def generate_poc_cmds(cve: dict, target_ip: str, n: int = 5, context: str = "") -> list:
    """讓 7B 針對單一 CVE 產生 n 條驗證指令；失敗則回退到保底探測指令。
    context：偵察階段得到的真實端點/裝置資訊，讓 7B 打對位置而非亂猜。"""
    cve_id = cve.get("cve_id") or cve.get("cveID") or "UNKNOWN"

    poc_hint = ""
    poc_list = cve.get("PoC", [])
    if isinstance(poc_list, list) and poc_list:
        # 只取前 2 筆、各截 800 字，避免 context 爆掉
        poc_hint = "\n".join(str(p)[:800] for p in poc_list[:2])

    context_block = ""
    if context:
        context_block = (
            f"\nRECON CONTEXT (real endpoints/services discovered on THIS target — "
            f"PREFER these over guessing generic paths like /status or /api):\n{context[:1800]}\n"
        )

    user_payload = (
        f"TARGET_IP: {target_ip}\n"
        f"CVE_ID: {cve_id}\n"
        f"CVSS: {cve.get('score') or cve.get('cvss') or 'N/A'}\n"
        f"DESCRIPTION:\n{str(cve.get('description', ''))[:1500]}\n"
        f"{context_block}\n"
        f"POC_HINTS (may be empty):\n{poc_hint[:1500]}\n\n"
        f"Produce exactly {n} DIFFERENT verification commands as JSON {{\"commands\": [...]}}. "
        f"When relevant, target the real endpoints listed in RECON CONTEXT."
    )

    try:
        resp = _call_llm_json_guarded(
            system_prompt=POC_SYSTEM_PROMPT,
            user_content=user_payload,
            response_schema=POC_CMDS_SCHEMA,
            model_name=GENERATION_MODEL,
        )
    except FutureTimeout:
        log_info.warn(
            f"⏱️ [Generation] {cve_id} 產生指令超過 {LLM_CALL_TIMEOUT}s 未回應（LLM 疑似卡住），"
            f"放棄本次、改用保底指令並繼續下一步。"
        )
        return _fallback_cmds(cve, target_ip, n)
    except Exception as e:
        log_info.warn(f"⚠️ [Generation] {cve_id} 產生指令例外: {e}，改用保底指令。")
        return _fallback_cmds(cve, target_ip, n)

    cmds = []
    if isinstance(resp, dict):
        raw_cmds = resp.get("commands", [])
        if isinstance(raw_cmds, list):
            for c in raw_cmds:
                if isinstance(c, str) and c.strip():
                    cmds.append(c.strip())

    # 安全網：強制每條指令都指向 target_ip，過濾掉 7B 亂填的外部網址
    safe_cmds = []
    for c in cmds:
        # 把常見 placeholder 換成真 target
        c = c.replace("example.com", target_ip).replace("TARGET_IP", target_ip)
        c = c.replace("<target>", target_ip).replace("{target}", target_ip)
        # 指令裡若出現 http(s) 但完全沒提到 target_ip，視為亂填，丟棄
        if ("http://" in c or "https://" in c) and target_ip not in c:
            continue
        # 擋掉明顯破壞性指令
        if re.search(r"\brm\s+-rf\b|\bmkfs\b|\b:\(\)\{", c):
            continue
        safe_cmds.append(c)

    if not safe_cmds:
        log_info.warn(f"⚠️ [Generation] {cve_id} 未產出有效指令，改用保底指令。")
        return _fallback_cmds(cve, target_ip, n)

    # 不足 n 條就補保底
    if len(safe_cmds) < n:
        for fb in _fallback_cmds(cve, target_ip, n):
            if fb not in safe_cmds:
                safe_cmds.append(fb)
            if len(safe_cmds) >= n:
                break

    return safe_cmds[:n]


# =============================================================================
# PoC 優先驗證：若 CVE 自帶 PoC 程式碼，交給 qwen2.5-coder 改寫成可執行檔
# =============================================================================

def extract_poc_scripts(cve: dict) -> list:
    """從 CVE 取出「真的是程式碼」的 PoC（排除純網址）。
    share_memory 裡的 cve['PoC'] 是字串 list，有些是腳本內容、有些只是 URL。
    這裡只留下看起來像程式碼的（排除以 http 開頭的純連結）。"""
    out = []
    for p in cve.get("PoC", []) or []:
        if not isinstance(p, str):
            continue
        s = p.strip()
        if not s:
            continue
        # 純網址（整段就是一個連結）→ 不算可執行 PoC
        if s.lower().startswith(("http://", "https://")) and "\n" not in s and len(s.split()) <= 1:
            continue
        # 太短（像一句話）也略過
        if len(s) < 30:
            continue
        out.append(s)
    return out


ADAPT_POC_SYSTEM_PROMPT = """You are Qwen2.5-Coder acting as an exploit adaptation engineer in an
isolated penetration-testing lab. You are given a raw public PoC for a CVE and the TARGET_IP of the
lab device. Rewrite the PoC into ONE self-contained, directly-runnable file that targets TARGET_IP.

STRICT RULES:
1. Output ONLY a JSON object: {"language": "python|bash", "filename": "poc_xxx.py", "content": "<full file>", "run_cmd": "python3 poc_xxx.py"}.
2. Replace every hard-coded target host/IP/placeholder in the original PoC with the given TARGET_IP.
3. Keep it self-contained: only use the Python standard library (socket, urllib, http.client, struct...) or basic shell tools (curl/wget). Do NOT require pip packages that may be missing.
4. The file must PRINT clear evidence to stdout so the caller can judge success (e.g. the server response, a leaked string, 'VULNERABLE' / 'NOT VULNERABLE').
5. Do NOT perform destructive actions (no rm, no flooding, no fork bombs). Verification/probing only.
6. If the PoC is a DoS/crash exploit, do NOT actually crash the target — instead just send a single probe and report what came back.
7. No markdown, no commentary, JSON only.
"""


def adapt_poc_to_file(cve: dict, target_ip: str, raw_poc: str, context: str = "") -> dict:
    """讓 qwen2.5-coder 把一段原始 PoC 改寫成可執行檔（換成靶機 IP、補成完整檔）。
    context：偵察到的真實端點/裝置資訊，協助改寫時打對位置。
    回傳 {"language","filename","content","run_cmd"}；失敗回 None。"""
    cve_id = cve.get("cve_id") or cve.get("cveID") or "CVE"

    context_block = f"\nRECON CONTEXT (real endpoints/services on this target):\n{context[:1500]}\n" if context else ""

    user_payload = (
        f"TARGET_IP: {target_ip}\n"
        f"CVE_ID: {cve_id}\n"
        f"DESCRIPTION:\n{str(cve.get('description',''))[:1000]}\n"
        f"{context_block}\n"
        f"RAW POC (adapt this):\n{raw_poc[:4000]}\n\n"
        f"Rewrite into ONE runnable file targeting {target_ip}. JSON only."
    )

    try:
        resp = _call_llm_json_guarded(
            guard_timeout=POC_ADAPT_TIMEOUT + 10,   # 應用層守門，略大於 socket 逾時
            timeout=POC_ADAPT_TIMEOUT,              # 傳到底層 → socket 也給這麼久
            system_prompt=ADAPT_POC_SYSTEM_PROMPT,
            user_content=user_payload,
            response_schema=POC_FILE_SCHEMA,
            model_name=GENERATION_MODEL,
        )
    except FutureTimeout:
        log_info.warn(
            f"⏱️ [PoC 改寫] {cve_id} 超過 {POC_ADAPT_TIMEOUT}s 未回應（LLM 疑似卡住），放棄本段 PoC、繼續。"
        )
        return None
    except Exception as e:
        log_info.warn(f"⚠️ [PoC 改寫] {cve_id} 例外: {e}")
        return None

    if not isinstance(resp, dict):
        return None

    language = (resp.get("language") or "").lower().strip()
    filename = (resp.get("filename") or "").strip()
    content = resp.get("content") or ""
    run_cmd = (resp.get("run_cmd") or "").strip()

    if not content or not filename:
        log_info.warn(f"⚠️ [PoC 改寫] {cve_id} 產出不完整，略過。")
        return None

    # 安全檢查：擋掉明顯破壞性內容
    if re.search(r"\brm\s+-rf\b|\bmkfs\b|\b:\(\)\{|\bshutil\.rmtree\b", content):
        log_info.warn(f"⚠️ [PoC 改寫] {cve_id} 內容含破壞性指令，拒絕執行。")
        return None

    # 補 run_cmd（若 LLM 沒給）
    if not run_cmd:
        if language == "python" or filename.endswith(".py"):
            run_cmd = f"python3 {filename}"
        else:
            run_cmd = f"bash {filename}"

    return {"language": language, "filename": filename, "content": content, "run_cmd": run_cmd}


# =============================================================================
# 🔁【回饋迴圈 Feedback Loop】
# 舊做法：一次盲生 5 條指令照跑，LLM 看不到前一條打出去的結果 → 一直亂猜。
# 新做法：生 1 條 → 跑 → 把「指令 + 真實回應」當歷史餵回去 → LLM 看了回應再生下一條。
#         這讓 7B「吸收剛剛看到的東西」，用上一步的真實回應修正下一步（in-context 成長）。
#   - 若某次回應已證明有漏洞 → LLM 回 done=true（呼叫端命中後本來就會停）。
#   - 若 LLM 判斷沒東西可試了 → done=true，呼叫端據此提早停，不浪費剩餘次數。
# 本函式「永遠」回一個可跑的 dict（LLM 失敗/逾時就給保底探測），讓 main 迴圈很乾淨。
# =============================================================================

POC_FEEDBACK_SYSTEM_PROMPT = """You are a penetration testing assistant powered by Qwen2.5-Coder,
running an ITERATIVE verification loop for ONE CVE on an ISOLATED lab device.
You are given the CVE, the TARGET_IP, recon context, and the HISTORY of commands already tried
together with the server's ACTUAL responses. Decide the SINGLE next shell command that best
advances verifying whether the target is vulnerable, LEARNING from what the responses revealed.

STRICT RULES:
1. Output ONLY a JSON object: {"command": "<one shell command>", "done": false, "reason": "<short>"}.
2. "command": ONE single-line, directly-runnable Linux command (curl/wget/nc...) targeting TARGET_IP.
   Never use example.com or placeholder hosts.
3. LEARN FROM HISTORY: if a path already returned 404 / "not found", do NOT repeat it — pivot to a
   different path, method, header or payload suggested by what you actually saw (links, forms,
   error strings, Server header, SOAP actions).
4. If a PREVIOUS RESPONSE already PROVES the vulnerability (leaked credentials/config, SQL error,
   auth bypass, device settings dump), set "done": true and return a minimal command that confirms it.
5. If you have exhausted sensible options and nothing indicates vulnerability, set "done": true and
   return one harmless final probe, explaining in "reason" that no further test is meaningful.
6. PREFER real endpoints from RECON CONTEXT over guessing generic paths like /status or /api.
7. No markdown, no commentary. JSON only.
"""

# 單條「下一步指令」的 JSON schema（給原生 Ollama format= 用；LangChain 路徑走 JSON 解析）
POC_NEXT_SCHEMA = {
    "type": "object",
    "properties": {
        "command": {"type": "string"},
        "done": {"type": "boolean"},
        "reason": {"type": "string"},
    },
    "required": ["command"],
}


def _format_history(history, max_items: int = 6, resp_cap: int = 500) -> str:
    """把已試過的 (指令, 回應) 整理成文字，只留最近 max_items 筆、每筆回應截 resp_cap 字。"""
    if not history:
        return "(none yet — this is the first attempt)"
    recent = history[-max_items:]
    lines = []
    for i, h in enumerate(recent, 1):
        cmd = str(h.get("cmd", ""))[:200]
        resp = str(h.get("response", ""))
        resp = re.sub(r"\s+", " ", resp).strip()[:resp_cap]
        lines.append(f"[{i}] CMD: {cmd}\n    RESP: {resp or '(empty)'}")
    return "\n".join(lines)


def generate_next_poc_cmd(cve: dict, target_ip: str, context: str = "", history=None) -> dict:
    """回饋迴圈核心：根據『CVE + 真實端點上下文 + 已試過的指令與回應』決定下一條指令。
    永遠回傳 {"command","done","reason"}（LLM 失敗/逾時/亂填時給保底探測），
    讓 main 的驗證迴圈不需處理 None。"""
    history = history or []
    cve_id = cve.get("cve_id") or cve.get("cveID") or "UNKNOWN"

    def _fallback(reason: str) -> dict:
        probe = _fallback_cmds(cve, target_ip, 5)[len(history) % 5]
        return {"command": probe, "done": False, "reason": reason}

    poc_hint = ""
    poc_list = cve.get("PoC", [])
    if isinstance(poc_list, list) and poc_list:
        poc_hint = "\n".join(str(p)[:600] for p in poc_list[:2])

    context_block = ""
    if context:
        context_block = (
            f"\nRECON CONTEXT (real endpoints/services on THIS target — PREFER these):\n{context[:1600]}\n"
        )

    user_payload = (
        f"TARGET_IP: {target_ip}\n"
        f"CVE_ID: {cve_id}\n"
        f"CVSS: {cve.get('score') or cve.get('cvss') or 'N/A'}\n"
        f"DESCRIPTION:\n{str(cve.get('description',''))[:1200]}\n"
        f"{context_block}\n"
        f"POC_HINTS (may be empty):\n{poc_hint[:1000]}\n\n"
        f"HISTORY (commands already tried and the server's ACTUAL responses):\n"
        f"{_format_history(history)}\n\n"
        f"Decide the SINGLE next command. Learn from the responses above. JSON only."
    )

    try:
        resp = _call_llm_json_guarded(
            system_prompt=POC_FEEDBACK_SYSTEM_PROMPT,
            user_content=user_payload,
            response_schema=POC_NEXT_SCHEMA,
            model_name=GENERATION_MODEL,
        )
    except FutureTimeout:
        log_info.warn(
            f"⏱️ [回饋迴圈] {cve_id} 第 {len(history)+1} 步超過 {LLM_CALL_TIMEOUT}s 未回應，改用保底探測並繼續。"
        )
        return _fallback("LLM 逾時，改用保底探測")
    except Exception as e:
        log_info.warn(f"⚠️ [回饋迴圈] {cve_id} 第 {len(history)+1} 步例外: {e}，改用保底探測。")
        return _fallback(f"LLM 例外: {e}")

    if not isinstance(resp, dict):
        return _fallback("LLM 回應格式異常")

    cmd = _sanitize_cmd(resp.get("command", ""), target_ip)
    if not cmd:
        return _fallback("LLM 未產出有效指令")

    return {
        "command": cmd,
        "done": bool(resp.get("done", False)),
        "reason": str(resp.get("reason", ""))[:200],
    }