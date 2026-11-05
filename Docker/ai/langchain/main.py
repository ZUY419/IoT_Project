# Docker/ai/langchain/main.py
# ============================================================================
# PentestGPT v2 — SOP 固定流程版 (Deterministic SOP Edition)
# ----------------------------------------------------------------------------
# 設計原則：流程決策全部由程式碼的 for 迴圈控制，7B 模型只在三個「局部翻譯」
# 任務被呼叫，碰不到任何流程決策，藉此消除小模型亂跳、鬼打牆、幻覺收工的問題。
#
#   7B 的三個（且唯一的）工作：
#     1. parse_tool_output()  —— 把工具亂 log 解析成結構化欄位
#     2. generate_poc_cmds()  —— 讀 CVE 描述/PoC，產生驗證指令
#     3. report 階段的文字潤飾（在 report.py）
#
#   六階段 SOP（依「實際執行順序」編號，全部窮舉，不問 AI 要不要做）：
#     Stage 1  資產偵察    nmap（已是 SOP）                              [stage1_recon]
#     Stage 2  Web 列舉    對每個「內部」端點各分析一次，外部網址自動跳過   [stage3_web_enum]
#     Stage 3  裝置指紋    主動探測 HNAP/UPnP/標頭，抽真實裝置資訊         [_fingerprint_device]
#     Stage 4  漏洞檢索    對每個已知 service 各打一次 RAG（查無則 NVD 備援）[stage2_vuln_search]
#     Stage 5  漏洞驗證    每個 CVE 產 N 次 payload 逐一執行，硬條件判定成敗 [stage4_verify]
#     Stage 6  產生報告    彙整成 Markdown + JSON                         [stage5_report]
#
#   ⚠️ 函式名稱中的數字（stage2_/stage3_/stage4_）是「開發期的歷史命名」，
#      與上面的執行順序編號不同，這是刻意保留的（避免大改函式名）。
#      對外顯示（log / 網頁）一律用上面的「執行順序」編號。
# ============================================================================

import json
import os
import re
from dotenv import load_dotenv

import util
from config.config import TARGET_IP
from config.logging import log_info
from tools import PentestToolbox, _looks_like_device_model
from ai.parsing import parse_tool_output
from ai.generation import (
    generate_poc_cmds,
    generate_next_poc_cmd,
    extract_poc_scripts,
    adapt_poc_to_file,
    classify_cve,
    make_exec_nonce,
)
import report as report_mod

load_dotenv()

# ---- 可調參數（可用環境變數覆寫）----
POC_ATTEMPTS_PER_CVE = int(os.getenv("POC_ATTEMPTS_PER_CVE", "5"))   # 每個 CVE 驗證幾次
CVSS_MIN = float(os.getenv("CVSS_MIN", "0.0"))                        # 報告收錄的 CVSS 下限（0 = 全收）
MAX_ENDPOINTS = int(os.getenv("MAX_ENDPOINTS", "15"))                 # Web 端點最多分析幾個，避免爆量
# 回應節錄長度：寫進 share_memory / 報告的 HTTP/HTML 回應保留幾個字元。
# 預設放大到 4000（約一整頁內容），讓資料「夠完整」；仍保留上限，避免整頁 HTML
# 把 share_memory.json 撐爆。要幾乎不截斷可在 .env 設很大的值（例如 100000）。
RESP_EXCERPT_LEN = int(os.getenv("RESP_EXCERPT_LEN", "4000"))

# 「驗證成功」的程式硬條件：回應中出現以下任一關鍵字，視為可能命中。
# ⚠️【收緊】只保留「正常網頁不會出現」的強特徵，避免假陽性。
#   拿掉了 password / admin / passwd / <script> / alert( —— 這些在任何登入頁都會出現，
#   會把「抓到一個普通網頁」誤判成「漏洞命中」（你遇過的 Juniper 假陽性就是這樣來的）。
SUCCESS_KEYWORDS = [
    "root:x:0:0",            # /etc/passwd 真的被讀出來
    "uid=0(root)", "gid=0(", # id 命令回顯 → 命令執行成功
    # ⚠️【重大修正】拿掉 "/bin/sh:" 與 "/bin/bash" ——
    #   這兩個會撞到工具缺失的錯誤訊息 "/bin/sh: 1: wget: not found"，
    #   導致「工具沒裝」被誤判成「漏洞命中」。
    "sh-4.$", "sh-5.$",      # bash 互動 shell prompt（真的拿到 shell 才會有）
    "you have an error in your sql syntax",  # SQL 報錯（完整句）
    "mysql_fetch", "ora-01756",              # DB 錯誤特徵
    # ⚠️【重大修正：移除 HNAP 特徵字】原本這裡放了
    #   getdevicesettingsresponse / purenetworks.com/hnap1 / <firmwareversion> / <modelname>，
    #   但那段 XML 是這台路由器「本來就會回」的東西（就是 HNAP 未授權洩漏本身），
    #   不是「某個 CVE 被攻破」的證據。回饋迴圈只要順手 curl 了 /HNAP1/，
    #   就會讓『當下正在驗的任何 CVE』被誤判成功（你看到的 CVE-2023-43197 假陽性）。
    #   HNAP 洩漏已由指紋階段單獨記成 disclosure_findings 並寫進報告，
    #   所以這裡拿掉完全不會漏掉那個發現，只是不再冤枉掛到別的 CVE 上。
    #   本清單只保留「CVE-agnostic 的真實攻破證據」：讀到 passwd、命令回顯、SQL 報錯、真 shell。
]

# 明確代表「失敗/無效」的回應特徵。
# ⚠️【新增】工具缺失、shell 執行錯誤、空輸出 → 一律判失敗，絕不算命中。
FAILURE_MARKERS = [
    "❌", "失敗", "connection reset", "connection refused",
    "timed out", "timeout", "could not resolve", "no route to host",
    "（錯誤", "（執行發生例外", "404 not found",
    "not found", "command not found", "no such file",   # 工具缺失（wget/nc/host not found）
    "/bin/sh:",                                          # shell 執行層錯誤
    "指令執行成功，但無文字輸出",                          # 空輸出不算命中
    # ⚠️【A：認證／session 失敗特徵，根治假陽性】
    #   例如靶機回 "FAILNO SESSION uid=0(root)..." 時——前半是靶機說「沒 session、請求被拒」，
    #   後半的 uid=0 往往是本機容器自己的 id 漏出來的（見 tools.py B1）。
    #   FAILURE_MARKERS 會「先判」，命中就直接判失敗，贏過後面的 root 關鍵字。
    #   這裡只收「成功的命令執行輸出絕不會出現」的認證拒絕字串，保守不誤殺：
    #   刻意不收 access denied / unauthorized / forbidden（可能出現在合法檔案列舉輸出中）。
    "no session", "failno session", "session expired", "invalid session",
    "session timeout", "need login", "please login", "login required", "not logged in",
]

# ⚠️【新增】DoS 類漏洞的描述特徵。偵測到就「跳過不實際攻擊」，只在報告記錄，
# 避免把靶機服務打崩導致後續測試無法進行（這也是真實滲透測試對待 DoS 的專業作法）。
DOS_KEYWORDS = [
    "denial of service", "denial-of-service", "(dos)", " dos ",
    "crash", "buffer overflow", "out-of-memory", "out of memory",
    "exhaust", "resource exhaustion", "infinite loop", "reboot",
    "拒絕服務", "崩潰", "耗盡",
]


def _is_dos_cve(cve: dict) -> bool:
    """用 CVE 描述關鍵字判斷是否為 DoS 類（程式判斷，不靠 7B）。"""
    desc = (cve.get("description") or "").lower()
    return any(k in desc for k in DOS_KEYWORDS)


_VENDOR_PREFIX_RE = re.compile(
    r"(?i)^(d[-\s]?link|tp[-\s]?link|netgear|cisco|zyxel|huawei|tenda|asus|linksys|ubiquiti|mikrotik)\s+")


def _nvd_family_keyword(model_query: str) -> str:
    """把型號變體正規化成『NVD 查得到的家族名』。
    例：DIR-601B1 / DIR601B1 / DIR 601B1 / D-Link DIR-601B1 / DIR601 / DIR 601 → 一律 DIR-601。
    作法：去廠商前綴 → 去硬體版號後綴(B1/A1…) → 分隔符統一成連字號(DIR601/DIR 601 → DIR-601)。
    NVD 的描述用的是連字號型號(DIR-601)，所以統一成這個形式命中率最高。"""
    s = _VENDOR_PREFIX_RE.sub("", (model_query or "").strip())
    s = re.sub(r"(?i)[\s_-]*[A-Z]\d{1,2}$", "", s).strip()   # 去硬體版號後綴 B1/A1…
    s = s.replace(" ", "-")                                   # DIR 601 → DIR-601
    s = re.sub(r"([A-Za-z])(\d)", r"\1-\2", s)                # DIR601 → DIR-601
    s = re.sub(r"-+", "-", s).strip("-")
    return s


# 預設帳密清單檔（與 main.py 同目錄）。登入環節逐組「直接全試」。
DEFAULT_CREDS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "default_creds.json")


def _load_default_creds() -> list:
    """載入 default_creds.json 的 credentials 清單；讀不到回空清單。"""
    try:
        with open(DEFAULT_CREDS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        creds = data.get("credentials", [])
        return [c for c in creds if isinstance(c, dict) and ("user" in c and "pass" in c)]
    except FileNotFoundError:
        log_info.warn(f"⚠️ 找不到帳密清單 {DEFAULT_CREDS_FILE}，略過自動登入。")
        return []
    except Exception as e:
        log_info.warn(f"⚠️ 讀取帳密清單失敗：{e}，略過自動登入。")
        return []


class PentestSOP:

    def __init__(self, reset_memory: bool = True):
        self.target_ip = TARGET_IP
        # 目前這顆 CVE 的「執行回顯驗證碼」marker（可執行類漏洞用）；
        # 回應若出現它＝指令真的在靶機上執行了（最強命中條件，非 LLM 自稱）。
        self._active_nonce = None
        self.net_tools = PentestToolbox(self.target_ip)
        self.mem = util.LangChainPentestMemory(target_ip=self.target_ip, reset=reset_memory)
        self.sm = util.get_share_memory()
        self._ensure_sm_keys()
        log_info.info("✨ [SOP] Share Memory 初始化完成。")

    # ------------------------------------------------------------------
    def _ensure_sm_keys(self):
        self.sm = util.get_share_memory()
        self.sm.setdefault("ports", {"TCP": [], "UDP": []})
        self.sm.setdefault("web_footprints", {})
        self.sm.setdefault("analyzed_urls", [])
        self.sm.setdefault("searched_rag_queries", [])
        self.sm.setdefault("cves", [])
        self.sm.setdefault("exploit_attempts", [])   # 每個 CVE 的驗證紀錄都存這
        util.update_share_memory(self.sm)

    def _reload(self):
        self.sm = util.get_share_memory()

    def _save(self):
        util.update_share_memory(self.sm)
        log_info.share_memory(self.sm)

    @staticmethod
    def _clean_service_query(service: str, version: str) -> str:
        """把 service/version 清成乾淨查詢字串：剝掉括號雜質與 port 描述。"""
        raw = f"{service} {version}".strip()
        raw = re.sub(r"\([^)]*\)", " ", raw)                       # 去括號內容
        raw = re.sub(r"(?i)\bport\b.*", " ", raw)                  # 去 port 描述
        raw = re.sub(r"(?i)service detection performed.*", " ", raw)  # 去 nmap 雜訊
        raw = re.sub(r"\s+", " ", raw).strip()
        return raw

    def _is_internal_url(self, url: str) -> bool:
        """只接受指向 target IP（或相對路徑）的端點，外部網址一律跳過。"""
        u = (url or "").strip()
        if not u:
            return False
        if u.startswith("http://") or u.startswith("https://"):
            return self.target_ip in u
        return True  # 相對路徑視為內部

    # ==================================================================
    # Stage 1（執行順序）：資產偵察 — nmap SOP  [def stage1_recon]
    # ==================================================================
    def stage1_recon(self):
        log_info.info("═══ Stage 1：資產偵察 (nmap SOP) ═══")
        self.net_tools.nmap_scan_tcp()
        self.net_tools.nmap_scan_udp()
        self._reload()

        ports = self.sm.get("ports", {})
        tcp_n = len(ports.get("TCP", []))
        udp_n = len(ports.get("UDP", []))
        log_info.info(f"✅ Stage 1 完成：TCP {tcp_n} 埠 / UDP {udp_n} 埠")

    # ==================================================================
    # Stage 4（執行順序）：漏洞檢索 — 對每個已知 service 窮舉 RAG，查無則 NVD 備援  [def stage2_vuln_search]
    # ==================================================================
    @staticmethod
    def _is_real_version(version: str) -> bool:
        """判斷版本欄位是不是『真的有版本資訊』。
        排除 unknown、空值、nmap 的雜訊字串（Service detection performed...）。"""
        v = (version or "").strip().lower()
        if not v or v == "unknown":
            return False
        if "service detection performed" in v or "please report" in v:
            return False
        return True

    @staticmethod
    def _model_query_variants(model: str, vendor_short: str = "") -> list:
        """從指紋型號展開多組查詢變體，提高 CVE 檢索命中率。
        重點場景：HNAP 回報硬體版號（如 DIR-601B1），但 CVE 以市場型號收錄（DIR-601L / DIR-601）。
        作法：
          1. 原字串（DIR-601B1）
          2. 去掉『硬體版號後綴』(結尾的 字母+數字，如 B1/A1/C1；L/K 這種市場字尾不動) → 家族名 DIR-601
             —— DIR-601 是 DIR-601L 的子字串，NVD/RAG 查 DIR-601 就能撈到 DIR-601L 的 CVE。
          3. 分隔符變體（DIR601 / DIR 601）
          4. 加廠商前綴（D-Link DIR-601 / D-Link DIR-601B1）
        回傳保序去重後的變體清單。"""
        m = (model or "").strip()
        if not m:
            return []
        variants = [m]
        # 去硬體版號後綴：結尾的「(rev) 字母+1~2位數字」，如 B1/A1/C1/ rev B1。
        # 只動『字母緊接數字』的尾巴；DIR-868L 這種單一字母市場字尾（後面沒數字）不會被誤砍。
        base = re.sub(r"(?i)[\s_-]*(rev\.?\s*)?[A-Z]\d{1,2}$", "", m).strip()
        if base and base.lower() != m.lower():
            variants.append(base)

        # 對 原字串 與 家族名 都做分隔符變體
        expanded = []
        for v in variants:
            expanded.append(v)
            if "-" in v:
                expanded.append(v.replace("-", ""))    # DIR601
                expanded.append(v.replace("-", " "))    # DIR 601

        # 加廠商前綴（放最後，當補充）
        vs = (vendor_short or "").strip()
        if vs:
            for v in list(dict.fromkeys([m, base])):
                if v and vs.lower() not in v.lower():
                    expanded.append(f"{vs} {v}")

        # 保序去重，濾掉太短的
        out = []
        for v in expanded:
            v = (v or "").strip()
            if len(v) >= 4 and v.lower() not in [x.lower() for x in out]:
                out.append(v)
        return out

    def _build_stage2_targets(self) -> list:
        """只挑『真實服務』當檢索目標：
          1. 有明確版本號的 port 服務（例如 dnsmasq 2.41、MiniUPnP 1.4）
          2. Web 分析挖到的廠商與 server 軟體（例如 D-Link、lighttpd 1.4.28）
        跳過 http unknown / dhcps / netbios-ns 這種只有服務類型、沒有產品的髒查詢。"""
        targets = []

        def _add(q):
            q = (q or "").strip()
            if q and q.lower() not in [t.lower() for t in targets]:
                targets.append(q)

        # 1. port 服務：只取有真實版本號的，查詢字串用「版本字串」本身（已含產品名，如 dnsmasq 2.41）
        for proto in ("TCP", "UDP"):
            for p in self.sm.get("ports", {}).get(proto, []):
                version = p.get("version", "")
                if self._is_real_version(version):
                    _add(self._clean_service_query("", version))

        # 2. Web 分析成果：廠商名 + server 標頭軟體（這些正是本地 RAG 庫有資料的）
        wf = self.sm.get("web_footprints", {})
        vendor = (wf.get("iot_vendor", {}) or {}).get("name", "")
        vendor_short = ""
        if vendor and vendor.lower() not in ("unknown", "unknown vendor"):
            # 取廠商名的第一個詞即可（D-LINK SYSTEMS, INC. → D-Link）
            vendor_short = vendor.split(",")[0].split()[0] if vendor.split() else vendor
            _add(vendor_short)

        server = wf.get("server", "")
        if server and server.lower() != "unknown":
            # lighttpd/1.4.28 → lighttpd 1.4.28
            _add(server.replace("/", " ").strip())

        # 3. 裝置指紋階段抽出的真實型號 —— 展開多組變體（去硬體版號後綴 / 分隔符 / 加廠商）
        #    例如 DIR-601B1 → DIR-601B1, DIR-601, DIR601, DIR 601, D-Link DIR-601 …
        #    家族名 DIR-601 可橋接到以 DIR-601L 收錄的 CVE（子字串命中）。
        model = wf.get("device_model", "")
        if model and model.lower() != "unknown":
            for v in self._model_query_variants(model, vendor_short):
                _add(v)

        # 4. 使用者手動指定的型號（指紋抓不到的，例如 HNAP 只回 DIR-601B1 但你知道實機是 DIR-601L）。
        #    在 ai/langchain/.env 設 EXTRA_MODELS=DIR-601L（可逗號/分號分隔多個），
        #    這些會原樣加入檢索目標 → NVD 會直接用該型號字串查（DIR-601L 不會被當硬體版號砍掉）。
        extra_models = os.getenv("EXTRA_MODELS", "").strip()
        if extra_models:
            for em in re.split(r"[;,]", extra_models):
                em = em.strip()
                if em:
                    _add(em)
                    for v in self._model_query_variants(em, vendor_short):
                        _add(v)

        return targets

    def stage2_vuln_search(self):
        log_info.info("═══ Stage 4：漏洞檢索 (只查真實服務) ═══")
        self._reload()

        targets = self._build_stage2_targets()
        if not targets:
            log_info.warn("⚠️ [漏洞檢索] 沒有任何可查的真實服務（都是 unknown 或純服務類型）。")
            return

        log_info.info(f"🎯 [漏洞檢索] 本次檢索目標（已過濾髒查詢）: {targets}")

        NVD_CAP_PER_QUERY = int(os.getenv("NVD_CAP_PER_QUERY", "10"))
        # 🔀 RAG 開關：在 ai/langchain/.env 設 USE_RAG=0（或 false/no/off）即可關閉 RAG，本階段只走 NVD。
        USE_RAG = os.getenv("USE_RAG", "1").strip().lower() not in ("0", "false", "no", "off")
        if not USE_RAG:
            log_info.info("⏸️ [漏洞檢索] RAG 已關閉 (USE_RAG=0)，本階段只使用 NVD 線上檢索。")
        nvd_done = set()   # 已查過的 NVD 關鍵字 → 去重，避免同一家族查很多次（也減少 NVD 限流）

        for q in targets:
            self._reload()
            before = len(self.sm.get("cves", []))   # 先量，RAG+NVD 的新增才算得準

            if USE_RAG:
                log_info.info(f"🔎 [漏洞檢索] RAG 檢索: {q}")
                self.net_tools.rag_search_cve(q)
                self._reload()

            is_model = _looks_like_device_model(q)

            # 【NVD 升為主要來源，不再只是 RAG 的備援】每個目標都查 NVD：
            #   - 裝置型號 → 正規化成家族名(DIR-601)，用關鍵字查
            #   - 元件 → 直接用原查詢(含版本，如 dnsmasq 2.41)查
            #   純廠商詞(如 D-Link，無版本又非型號)會被 nvd_search_cve 內部的版本守衛擋掉，不會灌爆。
            #   同一關鍵字本階段只查一次(去重)，減少重複與 NVD 限流。
            nvd_kw = _nvd_family_keyword(q) if is_model else q

            if nvd_kw and nvd_kw.lower() not in nvd_done:
                nvd_done.add(nvd_kw.lower())
                reason = "裝置型號→家族名查 NVD" if is_model else "元件→NVD 查詢"
                log_info.info(f"   ↳ {reason}：`{q}` → NVD 關鍵字 `{nvd_kw}`")
                nvd_before = len(self.sm.get("cves", []))
                self.net_tools.nvd_search_cve(nvd_kw)
                self._reload()

                # ⚠️ NVD 上限：單一關鍵字最多保留 NVD_CAP_PER_QUERY 筆，避免泛詞灌爆
                cves = self.sm.get("cves", [])
                added = len(cves) - nvd_before
                if added > NVD_CAP_PER_QUERY:
                    self.sm["cves"] = cves[:nvd_before] + cves[nvd_before:nvd_before + NVD_CAP_PER_QUERY]
                    util.update_share_memory(self.sm)
                    log_info.warn(
                        f"   ⚠️ NVD 回傳 {added} 筆過多，已截斷為前 {NVD_CAP_PER_QUERY} 筆"
                        f"（可用環境變數 NVD_CAP_PER_QUERY 調整）。"
                    )
                    self._reload()
            elif nvd_kw:
                log_info.info(f"   ↳ NVD 關鍵字 `{nvd_kw}` 本階段已查過，略過重複查詢。")

            after = len(self.sm.get("cves", []))
            log_info.info(f"   ↳ 累計 CVE: {after} 筆 (本次新增 {after - before})")

        log_info.info(f"✅ [漏洞檢索] 完成：共檢索出 {len(self.sm.get('cves', []))} 筆 CVE")

    # ==================================================================
    # Stage 2（執行順序）：Web 端點列舉 — 窮舉內部端點，外部自動跳過  [def stage3_web_enum]
    # ==================================================================
    def stage3_web_enum(self):
        log_info.info("═══ Stage 2：Web 列舉 (窮舉內部端點) ═══")

        # 先分析首頁，挖出端點
        self.net_tools.analyze_web_page(f"http://{self.target_ip}")
        self._reload()

        processed = set(self.sm.get("analyzed_urls", []))
        rounds = 0
        while rounds < MAX_ENDPOINTS:
            rounds += 1
            self._reload()
            wf = self.sm.get("web_footprints", {})
            pages = wf.get("web_pages_for_deeper_investigation", [])

            # 找出下一個「內部、尚未分析」的端點
            next_url = None
            for item in pages:
                u = item.get("url") if isinstance(item, dict) else str(item)
                u = (u or "").strip()
                if not u:
                    continue
                if u.startswith("http://") or u.startswith("https://"):
                    full = u
                else:
                    full = f"http://{self.target_ip}/{u.lstrip('/')}"

                if not self._is_internal_url(full):
                    continue
                if full in processed:
                    continue
                next_url = full
                break

            if not next_url:
                break

            log_info.info(f"🌐 [Stage 2] 分析端點: {next_url}")
            self.net_tools.analyze_web_page(next_url)
            processed.add(next_url)

        log_info.info(f"✅ Stage 2 完成：共分析 {len(processed)} 個 Web 端點")

    # ==================================================================
    # Stage 5（執行順序）：漏洞驗證 — 每個 CVE 產 N 次 payload 逐一執行  [def stage4_verify]
    # ==================================================================
    def _judge_success(self, response: str) -> bool:
        """程式硬條件判定。
        ①最強：執行回顯 nonce 出現＝指令真的在靶機執行（勝過一切，連失敗字串也不翻盤，
          因為我們注入的隨機碼被回顯，本身就是鐵證）。
        ②其次：失敗特徵命中 → 判失敗。
        ③最後：成功關鍵字命中 → 判成功。"""
        text = response or ""
        if self._active_nonce and self._active_nonce in text:
            return True
        low = text.lower()
        if any(m.lower() in low for m in FAILURE_MARKERS):
            return False
        return any(k.lower() in low for k in SUCCESS_KEYWORDS)

    def _success_evidence(self, response: str) -> dict:
        """命中後抽出「為什麼算成功」的客觀證據，供報告說明用。
        回傳 {"keywords": [實際命中的成功特徵...], "snippet": 該特徵在回應中前後的原文片段}。
        注意：這裡回報的是「程式硬條件」實際比對到的字串，屬可稽核的鐵證，
        不是 LLM 自稱成功。judged_success 為 False 時回空 dict。"""
        text = response or ""
        low = text.lower()
        # ① 最強證據：執行回顯 nonce 出現（我們注入的隨機碼被原封回顯＝真的執行）
        if self._active_nonce and self._active_nonce in text:
            pos = text.find(self._active_nonce)
            start = max(0, pos - 120)
            end = min(len(text), pos + len(self._active_nonce) + 120)
            snippet = text[start:end].replace("\n", " ").strip()
            if start > 0:
                snippet = "…" + snippet
            if end < len(text):
                snippet = snippet + "…"
            return {"keywords": ["<exec-nonce>"], "snippet": snippet}
        # ② 失敗特徵優先（與 _judge_success 一致）→ 不算命中，無證據
        if any(m.lower() in low for m in FAILURE_MARKERS):
            return {}
        hits = [k for k in SUCCESS_KEYWORDS if k.lower() in low]
        if not hits:
            return {}
        # 取第一個命中特徵在原文中的位置，擷取前後各 120 字當佐證片段
        pos = low.find(hits[0].lower())
        start = max(0, pos - 120)
        end = min(len(text), pos + len(hits[0]) + 120)
        snippet = text[start:end].replace("\n", " ").strip()
        if start > 0:
            snippet = "…" + snippet
        if end < len(text):
            snippet = snippet + "…"
        return {"keywords": hits, "snippet": snippet}

    def _run_poc_file(self, cve_id: str, poc_file: dict) -> dict:
        """把 coder 改寫好的 PoC 寫成檔案並執行，回傳一筆 attempt 紀錄。"""
        import os as _os
        # PoC 檔也放進本台設備專屬資料夾 workspace/data/<設備名稱>/poc_tmp/
        poc_dir = str(util.get_device_data_dir() / "poc_tmp")
        _os.makedirs(poc_dir, exist_ok=True)

        filename = poc_file.get("filename") or f"poc_{cve_id}.py"
        # 防目錄穿越：只取檔名
        filename = _os.path.basename(filename)
        filepath = _os.path.join(poc_dir, filename)
        content = poc_file.get("content", "")
        run_cmd = poc_file.get("run_cmd") or f"python3 {filename}"

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            return {"cmd": f"(寫入 PoC 檔失敗: {e})", "response_excerpt": "", "judged_success": False, "is_poc": True}

        # run_cmd 裡的檔名換成完整路徑
        full_cmd = run_cmd.replace(filename, filepath)
        log_info.info(f"   🧬 [PoC 執行] {cve_id} → {run_cmd}")
        resp = self.net_tools.execute_cli(full_cmd)
        ok = self._judge_success(resp)
        evidence = self._success_evidence(resp) if ok else {}

        return {
            "cmd": run_cmd,
            "poc_filename": filename,
            "poc_content": content[:2000],
            "response_excerpt": (resp or "")[:RESP_EXCERPT_LEN],
            "judged_success": ok,
            "is_poc": True,
            "evidence_keywords": evidence.get("keywords", []),
            "evidence_snippet": evidence.get("snippet", ""),
        }

    # 標準、跨廠牌的裝置發現協定（不假設任何特定廠商）。
    # 這些是通用協定：任何 IoT 設備若支援，主動探測即可抽出真實裝置資訊。
    # 格式：(id, 說明, 路徑, 是否為「未授權本不該外洩」的敏感端點)
    STANDARD_DISCOVERY = [
        ("http-root",      "HTTP 根頁面 (Server 標頭 / 標題)",        "/",                       False),
        ("hnap",           "HNAP 裝置管理協定 (/HNAP1/)",              "/HNAP1/",                 True),
        ("upnp-rootdesc",  "UPnP 裝置描述 (rootDesc.xml)",            "/rootDesc.xml",           True),
        ("upnp-gatedesc",  "UPnP 裝置描述 (gatedesc.xml)",            "/gatedesc.xml",           True),
        ("upnp-devdesc",   "UPnP 裝置描述 (DeviceDescription.xml)",   "/DeviceDescription.xml",  True),
    ]

    @staticmethod
    def _extract_fingerprint(text: str) -> dict:
        """從回應抽出真實的 vendor / model / firmware / server / title。
        同時支援 HNAP 與 UPnP 的 XML 標籤，以及 HTTP Server 標頭——皆為標準格式。"""
        out = {}
        pats = {
            "vendor":   [r"<VendorName>([^<]+)</VendorName>", r"<manufacturer>([^<]+)</manufacturer>"],
            "model":    [r"<ModelName>([^<]+)</ModelName>", r"<modelName>([^<]+)</modelName>",
                         r"<ModelDescription>([^<]+)</ModelDescription>", r"<friendlyName>([^<]+)</friendlyName>"],
            "firmware": [r"<FirmwareVersion>([^<]+)</FirmwareVersion>", r"<modelNumber>([^<]+)</modelNumber>"],
            "server":   [r"(?im)^Server:\s*(.+)$"],
            "title":    [r"(?i)<title>([^<]+)</title>"],
        }
        for key, plist in pats.items():
            for p in plist:
                m = re.search(p, text or "")
                if m:
                    out[key] = m.group(1).strip()
                    break
        return out

    def _fingerprint_device(self):
        """主動探測標準裝置發現協定（HNAP / UPnP / HTTP 標頭），
        從回應抽出真實的 vendor/model/firmware（程式在執行過程中獲取，非寫死、非 LLM 猜測）。
        這些是跨廠牌標準協定，對任何 IoT 設備一體適用，不假設廠商。
        若標準協定在『未授權』狀態回傳裝置資訊，一併記為資訊洩漏 finding。"""
        log_info.info("═══ Stage 3：裝置指紋 (主動探測標準發現協定 HNAP/UPnP/標頭) ═══")
        self._reload()

        collected = {}      # 彙整出的真實裝置資訊
        findings = []

        for pid, desc, path, sensitive in self.STANDARD_DISCOVERY:
            cmd = f"curl -s -i http://{self.target_ip}{path}"
            resp = self.net_tools.execute_cli(cmd)
            if not resp:
                continue
            # 404 / 連線失敗就跳過
            low = resp.lower()
            if "404 not found" in low or self._judge_fail_only(resp):
                continue

            info = self._extract_fingerprint(resp)
            if info:
                for k, v in info.items():
                    collected.setdefault(k, v)
                log_info.info(f"   📡 {pid}: 抽出 {info}")

            # HNAP 回應會列出支援的 SOAP 動作（真實攻擊面）→ 抽出動作名存起來
            if pid == "hnap":
                acts = re.findall(r"/HNAP1/([A-Za-z0-9_]+)\s*<", resp)
                if acts:
                    collected.setdefault("_hnap_actions", list(dict.fromkeys(acts)))

            # 敏感端點在未授權下回了裝置資訊（vendor/model/firmware）→ 資訊洩漏
            leaked = sensitive and any(k in info for k in ("vendor", "model", "firmware"))
            if leaked:
                log_info.info(f"   ✅ [資訊洩漏] {path} 未授權即回傳裝置資訊")
                findings.append({
                    "cve_id": f"INFO-DISCLOSURE {path}",
                    "cvss": "N/A",
                    "description": f"{desc}：未授權即可取得裝置資訊 "
                                   f"(vendor={info.get('vendor','')}, model={info.get('model','')}, "
                                   f"firmware={info.get('firmware','')})。",
                    "method": "standard-protocol-probe",
                    "attempts": [{
                        "n": 1, "cmd": cmd,
                        "response_excerpt": (resp or "")[:RESP_EXCERPT_LEN],
                        "judged_success": True, "is_poc": False,
                    }],
                    "success": True,
                    "success_cmd": cmd,
                })

        # 把程式實際抽出的真實裝置資訊寫回 web_footprints（覆蓋 Stage 2 Web 列舉的 LLM 猜測）
        if collected:
            self._reload()
            wf = self.sm.setdefault("web_footprints", {})
            if collected.get("vendor"):
                wf.setdefault("iot_vendor", {})["name"] = collected["vendor"]
            if collected.get("model"):
                wf["device_model"] = collected["model"]
            if collected.get("firmware"):
                wf["firmware_version"] = collected["firmware"]
            if collected.get("server"):
                wf["server"] = collected["server"]
            if collected.get("_hnap_actions"):
                wf["hnap_actions"] = collected["_hnap_actions"]
            wf["fingerprint_source"] = "standard-protocol-probe"
            self.sm["device_fingerprint"] = collected
            self.sm["disclosure_findings"] = findings
            self._save()
            log_info.info(f"🧾 [裝置指紋] 程式抽出真實裝置資訊: {collected}")
        else:
            self._reload()
            self.sm["disclosure_findings"] = findings
            self._save()
            log_info.info("   ↳ 標準協定未回傳可用裝置資訊（可能為未知/未支援的設備）。")

        return findings

    def _judge_fail_only(self, response: str) -> bool:
        """只判斷是否命中『失敗特徵』（連線失敗、404 等），用於指紋探測略過無效回應。"""
        low = (response or "").lower()
        return any(m.lower() in low for m in FAILURE_MARKERS)

    def _build_target_context(self) -> str:
        """彙整偵察階段得到的「真實」端點/裝置資訊，餵給 LLM 當產指令/改 PoC 的上下文，
        讓它打對位置（真實端點、表單、HNAP 動作），而非亂猜 /status、/api。"""
        self._reload()
        wf = self.sm.get("web_footprints", {})
        lines = []

        # 裝置資訊
        fp = self.sm.get("device_fingerprint", {})
        if fp:
            lines.append(f"Device: vendor={fp.get('vendor','')}, model={fp.get('model','')}, "
                         f"firmware={fp.get('firmware','')}, server={fp.get('server','')}")

        # 已實測「確認存在(非 404)」的端點——這是最可信的攻擊面情報
        live = self.sm.get("live_endpoints", [])
        if live:
            live_urls = [x.get("url") for x in live if isinstance(x, dict) and x.get("url")]
            if live_urls:
                lines.append("Confirmed-live endpoints (verified HTTP 200, NOT 404): "
                             + ", ".join(live_urls[:20]))

        # 已確認 404 的端點——明確告訴 LLM 別再打這些
        dead = self.sm.get("dead_endpoints", [])
        if dead:
            dead_urls = [x.get("url") for x in dead if isinstance(x, dict) and x.get("url")]
            if dead_urls:
                lines.append("Known-dead endpoints (404, do NOT target): " + ", ".join(dead_urls[:15]))

        # 已分析/發現的 Web 端點
        urls = self.sm.get("analyzed_urls", [])
        if urls:
            lines.append("Discovered URLs: " + ", ".join(urls[:10]))

        invest = wf.get("web_pages_for_deeper_investigation", [])
        paths = []
        for item in invest:
            u = item.get("url") if isinstance(item, dict) else str(item)
            if u:
                paths.append(u.strip())
        if paths:
            lines.append("Candidate endpoints: " + ", ".join(paths[:15]))

        # 表單(含欄位名)——命令注入/認證類很需要
        forms = wf.get("forms", [])
        for f in forms[:5]:
            if isinstance(f, dict):
                inputs = ",".join(i.get("name", "") for i in f.get("inputs", []) if isinstance(i, dict))
                lines.append(f"Form: action={f.get('action','')} method={f.get('method','')} fields=[{inputs}]")

        # HNAP 動作(攻擊面)
        actions = wf.get("hnap_actions", [])
        if actions:
            lines.append("HNAP SOAP actions: " + ", ".join(actions[:15]))

        # 開放埠
        ports = self.sm.get("ports", {})
        port_list = []
        for proto in ("TCP", "UDP"):
            for p in ports.get(proto, []):
                port_list.append(f"{p.get('port')}/{proto}({p.get('service','')})")
        if port_list:
            lines.append("Open ports: " + ", ".join(port_list))

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 🔐 登入環節（由流程控制）：讀 default_creds.json → 逐組登入 → 存 session
    #    session 狀態與流程都由程式管；7B 只在「程式抽不出登入表單」時被叫去看 HTML。
    # ------------------------------------------------------------------
    def _llm_login_form(self, html: str) -> dict:
        """7B 後備：程式抽不出登入表單時，請 7B 從 HTML 找出表單欄位。
        回傳 {action_url, method, user_field, pass_field}。失敗回 {}。"""
        try:
            from ai.ollama import call_ollama_json
        except Exception:
            return {}
        schema = {
            "type": "object",
            "properties": {
                "action_url": {"type": "string"},
                "method": {"type": "string"},
                "user_field": {"type": "string"},
                "pass_field": {"type": "string"},
            },
            "required": ["pass_field"],
        }
        sys_p = ("You extract the LOGIN form from router/IoT admin HTML. "
                 "Return ONLY JSON {action_url, method(GET/POST), user_field, pass_field} "
                 "with the exact input 'name' attributes. If there is no login form, return empty strings. JSON only.")
        try:
            return call_ollama_json(sys_p, f"HTML:\n{html}", schema) or {}
        except Exception as e:
            log_info.warn(f"🔐 7B 解析登入表單呼叫失敗：{e}")
            return {}

    def _login_stage(self):
        """流程控制的登入：成功則把 cookie 設給 net_tools（後續驗證指令自動帶上）。"""
        creds = _load_default_creds()
        if not creds:
            log_info.info("🔐 無帳密清單，略過自動登入，改以未登入方式驗證。")
            return

        # 從已分析/確認存在的端點挑「像登入頁」的當優先候選
        login_urls = []
        for u in self.sm.get("analyzed_urls", []):
            if isinstance(u, str) and re.search(r"login|signin|auth", u, re.IGNORECASE):
                login_urls.append(u)
        for x in self.sm.get("live_endpoints", []) or []:
            if isinstance(x, dict):
                u, t = x.get("url", ""), str(x.get("title", ""))
                if re.search(r"login|signin|auth", u + " " + t, re.IGNORECASE) and u not in login_urls:
                    login_urls.append(u)

        log_info.info(f"🔐 [登入] 讀入 {len(creds)} 組預設帳密，開始嘗試登入取得 session…")
        result = self.net_tools.attempt_login(
            creds, login_urls=login_urls, llm_form_extractor=self._llm_login_form
        )

        if result.get("success"):
            self.net_tools.set_auth_cookie(result["cookie"])
            self.sm["auth_session"] = {
                "logged_in": True,
                "user": result.get("user"),
                "used_url": result.get("used_url"),
                "cookie_preview": (result.get("cookie") or "")[:60],
                "tried": result.get("tried"),
            }
            self._save()
            log_info.info(f"🔐 [登入] 成功（試了 {result.get('tried')} 組）→ 後續驗證將帶此 session。")
        else:
            self.sm["auth_session"] = {"logged_in": False, "tried": result.get("tried", 0),
                                       "reason": result.get("reason", "")}
            self._save()
            log_info.warn(f"🔐 [登入] 未取得 session（{result.get('reason')}）。"
                          f"需認證的 CVE 可能因此無法驗證，將以未登入方式繼續。")

    def stage4_verify(self):
        log_info.info("═══ Stage 5：漏洞驗證 (每個 CVE 試 {} 次) ═══".format(POC_ATTEMPTS_PER_CVE))
        self._reload()

        # 🔐【自動登入：目前停用】登入環節與機制都保留（_login_stage / tools.py），但預設不跑，
        #    改以「未登入」方式驗證。之後若有 CVE 指出該裝置有「弱登入/認證繞過」類漏洞再啟用——
        #    取消下面這行註解即可恢復（成功後 execute_cli 會自動把 cookie 帶進每條 curl）。
        # self._login_stage()

        attempts_log = []

        # 併入裝置指紋階段發現的「標準協定未授權資訊洩漏」findings
        attempts_log.extend(self.sm.get("disclosure_findings", []))

        # 組出「真實端點上下文」，稍後餵給 LLM，讓它打對位置而非亂猜
        target_context = self._build_target_context()
        # （登入停用期間 auth_session 不會是 logged_in，這段 AUTH 提示自動不會觸發；
        #   日後重啟登入時會自動恢復提示 7B 沿用 session。）
        if self.sm.get("auth_session", {}).get("logged_in"):
            target_context = ((target_context or "") +
                              "\nAUTH: an authenticated session is active; the runner auto-attaches the "
                              "login cookie to every curl. Target authenticated/admin endpoints; do NOT add cookies yourself.")
        if target_context:
            log_info.info(f"🧭 [上下文] 提供給 LLM 的真實端點資訊:\n{target_context}")

        all_cves = [c for c in self.sm.get("cves", []) if isinstance(c, dict)]

        # 🚫【DoS 不進驗證清單】DoS 類會打崩靶機、本來就不實際驗證，
        #    直接從「要用的 CVE 清單」切掉，只留在報告當「已識別、未驗證」。
        dos_cves = [c for c in all_cves if _is_dos_cve(c)]
        cves = [c for c in all_cves if not _is_dos_cve(c)]

        # 把 DoS 從 share_memory 的「要用的 CVE 清單」移除 → 網頁/計數看到的就是乾淨的待驗證清單
        self.sm["cves"] = cves
        self._save()

        # DoS 仍寫進報告（已識別、未驗證），但不佔驗證進度、不進迴圈
        for c in dos_cves:
            cid = c.get("cve_id") or c.get("cveID") or "UNKNOWN"
            try:
                sc = float(c.get("score") or c.get("cvss") or 0)
            except (ValueError, TypeError):
                sc = 0.0
            attempts_log.append({
                "cve_id": cid, "cvss": sc, "description": c.get("description", ""),
                "attempts": [], "success": False, "success_cmd": None,
                "skipped_dos": True,   # 報告端據此寫「已識別、未驗證(DoS)」
            })
        if dos_cves:
            log_info.info(f"🚫 已排除 {len(dos_cves)} 筆 DoS 類 CVE，不納入驗證清單（仍列入報告）。")

        total_cves = len(cves)
        if not cves:
            log_info.warn("⚠️ Stage 5：扣除 DoS 後沒有可驗證的 CVE，但已併入裝置指紋階段的洩漏發現。")

        for idx, cve in enumerate(cves, 1):
            cve_id = cve.get("cve_id") or cve.get("cveID") or "UNKNOWN"

            # ⚡ 即時回報子進度：目前測到第 idx / 共 total_cves 個 CVE（網頁即時更新計數）
            log_info.cve_progress(idx, total_cves, cve_id, status="testing")

            # CVSS 門檻過濾（CVSS_MIN=0 時全收）
            try:
                score = float(cve.get("score") or cve.get("cvss") or 0)
            except (ValueError, TypeError):
                score = 0.0
            if CVSS_MIN > 0 and score and score < CVSS_MIN:
                log_info.info(f"   ↳ {cve_id} CVSS {score} < {CVSS_MIN}，略過驗證。")
                continue

            # 🎯 分類漏洞 + 產生「執行回顯驗證碼」（可執行類漏洞用）：
            #    vuln_class 決定回饋迴圈給 7B 哪組 payload 模板；
            #    nonce marker 設給 self，_judge_success 一旦在回應看到它＝真的執行了。
            vuln_class = classify_cve(cve)
            nonce_marker, nonce_echo = make_exec_nonce()
            self._active_nonce = nonce_marker

            log_info.info(f"🎯 [Stage 5] 驗證 {cve_id} (CVSS {score or 'N/A'}, 類型={vuln_class})")

            cve_record = {
                "cve_id": cve_id,
                "cvss": score,
                "description": cve.get("description", ""),
                "vuln_class": vuln_class,
                "attempts": [],
                "success": False,
                "success_cmd": None,
                "method": None,   # "poc" = 用現成 PoC；"llm" = LLM 產生指令
            }

            # ============================================================
            # ① 有 PoC → 交給 coder 改寫成可執行檔再跑（你要的優先路徑）
            # ============================================================
            poc_scripts = extract_poc_scripts(cve)
            attempt_n = 0

            if poc_scripts:
                log_info.info(f"   📜 {cve_id} 自帶 {len(poc_scripts)} 段 PoC，優先用 PoC 驗證。")
                cve_record["method"] = "poc"
                # 每段 PoC 最多試一個改寫檔（避免太多），試到成功為止
                for raw_poc in poc_scripts[:POC_ATTEMPTS_PER_CVE]:
                    attempt_n += 1
                    poc_file = adapt_poc_to_file(cve, self.target_ip, raw_poc, context=target_context)
                    if not poc_file:
                        cve_record["attempts"].append({
                            "n": attempt_n, "cmd": "(coder 改寫 PoC 失敗)",
                            "response_excerpt": "", "judged_success": False, "is_poc": True,
                        })
                        continue
                    rec = self._run_poc_file(cve_id, poc_file)
                    rec["n"] = attempt_n
                    cve_record["attempts"].append(rec)
                    if rec.get("judged_success"):
                        cve_record["success"] = True
                        cve_record["success_cmd"] = rec.get("cmd")
                        cve_record["success_evidence"] = rec.get("evidence_keywords", [])
                        cve_record["success_snippet"] = rec.get("evidence_snippet", "")
                        log_info.info(f"   ✅ {cve_id} PoC 驗證命中成功條件！")
                        break

            # ============================================================
            # ② 沒 PoC（或 PoC 全失敗）→ 回饋迴圈：生 1 條 → 跑 → 餵回應 → 再生下一條
            #    LLM 看得到前一步的真實回應，用它修正下一步（取代舊的盲生 5 條）。
            # ============================================================
            if not cve_record["success"] and not poc_scripts:
                cve_record["method"] = "llm"
                history = []   # [{"cmd":..., "response":...}]，餵回給 LLM 當記憶
                for step in range(1, POC_ATTEMPTS_PER_CVE + 1):
                    nxt = generate_next_poc_cmd(
                        cve, self.target_ip, context=target_context, history=history,
                        vuln_class=vuln_class, nonce_echo=nonce_echo,
                    )
                    cmd = nxt.get("command")
                    if not cmd:
                        break
                    attempt_n += 1
                    reason = nxt.get("reason", "")
                    log_info.info(
                        f"   ↳ 第 {attempt_n} 步 (回饋迴圈): {cmd[:80]}"
                        + (f"  〔理由: {reason[:40]}〕" if reason else "")
                    )
                    resp = self.net_tools.execute_cli(cmd)
                    ok = self._judge_success(resp)
                    evidence = self._success_evidence(resp) if ok else {}
                    cve_record["attempts"].append({
                        "n": attempt_n, "cmd": cmd,
                        "response_excerpt": (resp or "")[:RESP_EXCERPT_LEN],
                        "judged_success": ok, "is_poc": False,
                        "reason": reason,
                        "evidence_keywords": evidence.get("keywords", []),
                        "evidence_snippet": evidence.get("snippet", ""),
                    })
                    # 把這一步的真實回應餵回歷史，下一步 LLM 就看得到
                    history.append({"cmd": cmd, "response": (resp or "")[:RESP_EXCERPT_LEN]})

                    if ok:
                        cve_record["success"] = True
                        cve_record["success_cmd"] = cmd
                        cve_record["success_evidence"] = evidence.get("keywords", [])
                        cve_record["success_snippet"] = evidence.get("snippet", "")
                        log_info.info(f"   ✅ {cve_id} 第 {attempt_n} 步命中成功條件！")
                        break
                    # LLM 判斷已無可試 → 提早停，不浪費剩餘次數
                    if nxt.get("done"):
                        log_info.info(
                            f"   🧭 {cve_id} LLM 判斷無更多可試"
                            + (f"（{reason[:40]}）" if reason else "")
                            + "，提早結束本 CVE。"
                        )
                        break

            if not cve_record["success"]:
                log_info.info(f"   ❌ {cve_id} 經 {len(cve_record['attempts'])} 次嘗試未命中，記錄為 attempted。")

            attempts_log.append(cve_record)
            self._active_nonce = None   # 本顆 CVE 結束，清掉驗證碼避免殘留誤判

        # ⚡ 全部 CVE 測完：回報子進度收尾（網頁計數跳到 N/N 完成）
        if total_cves:
            log_info.cve_progress(total_cves, total_cves, None, status="done")

        self._reload()
        self.sm["exploit_attempts"] = attempts_log
        self._save()
        succ = sum(1 for a in attempts_log if a["success"])
        log_info.info(f"✅ Stage 5 完成：{len(attempts_log)} 個 CVE，成功 {succ}、未果 {len(attempts_log) - succ}")

    # ==================================================================
    # Stage 6（執行順序）：產生 Markdown + JSON 報告  [def stage5_report]
    # ==================================================================
    def stage5_report(self):
        log_info.info("═══ Stage 6：產生 Markdown 報告 ═══")
        self._reload()
        path = report_mod.generate_markdown_report(self.sm, self.target_ip)
        log_info.info(f"✅ Stage 6 完成：報告已輸出 → {path}")
        return path

    # ==================================================================
    # 執行順序（依資料依賴排；編號即網頁進度列顯示的 1~6）
    STAGES = [
        ("資產偵察",  "stage1_recon"),
        ("Web 列舉",  "stage3_web_enum"),
        ("裝置指紋",  "_fingerprint_device"),
        ("漏洞檢索",  "stage2_vuln_search"),
        ("漏洞驗證",  "stage4_verify"),
        ("產生報告",  "stage5_report"),
    ]

    def run(self):
        log_info.info("🚀 PentestGPT v2 (SOP 固定流程版) 啟動！")
        # ⚠️【順序】Web 分析 → 裝置指紋(標準協定主動探測) → 漏洞檢索。
        #    指紋階段用標準協定抽出真實 vendor/model/firmware，再驅動漏洞檢索；
        #    每進一個階段先 log_info.stage() 回報進度，網頁據此畫進度列。
        total = len(self.STAGES)
        path = None
        for idx, (name, method) in enumerate(self.STAGES, 1):
            log_info.stage(idx, total, name)
            result = getattr(self, method)()
            if method == "stage5_report":
                path = result
        log_info.info("🏁 全流程結束。")
        # 回報完成：網頁據此跳通知並自動載入最終報告
        report_file = os.path.basename(path) if path else None
        log_info.done(device=util.get_device_name(), report_file=report_file)
        return path


if __name__ == "__main__":
    PentestSOP().run()