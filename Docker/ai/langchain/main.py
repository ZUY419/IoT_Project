# Docker/ai/langchain/main.py

import json
import os
import re
import time
from dotenv import load_dotenv

import util
from config.config import TARGET_IP
from config.logging import log_info
from tools import PentestToolbox
from ai.generation import (
    generate_next_poc_cmd,
    extract_poc_scripts,
    adapt_poc_to_file,
    classify_cve,
    make_exec_nonce,
    REPORT_ONLY_CLASSES,
)
import report as report_mod

load_dotenv()

# ---- 可調參數（可用環境變數覆寫）----
POC_ATTEMPTS_PER_CVE = int(os.getenv("POC_ATTEMPTS_PER_CVE", "5"))    # 每個 CVE 驗證幾次
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
    "sh-4.$", "sh-5.$",      # bash 互動 shell prompt（真的拿到 shell 才會有）
    "you have an error in your sql syntax",  # SQL 報錯（完整句）
    "mysql_fetch", "ora-01756",              # DB 錯誤特徵
]

# 明確代表「失敗/無效」的回應特徵。
FAILURE_MARKERS = [
    "❌", "失敗", "connection reset", "connection refused",
    "timed out", "timeout", "could not resolve", "no route to host",
    "（錯誤", "（執行發生例外", "404 not found",
    "not found", "command not found", "no such file",   # 工具缺失（wget/nc/host not found）
    "/bin/sh:",                                          # shell 執行層錯誤
    "指令執行成功，但無文字輸出",                          # 空輸出不算命中
    "no session", "failno session", "session expired", "invalid session",
    "session timeout", "need login", "please login", "login required", "not logged in",
]

# =============================================================================
# ⏱️【盲注時間差判定】
# 有些指令注入是「盲注」：指令會在靶機執行，但輸出不回顯到 HTTP 回應（例如 Netgear
# boardData*.php 的 CVE-2016-1555——回應只回表單頁，看不到 id/echo 的結果）。此時
# nonce / uid=0 這種「看回顯」的判定永遠不會中。
# 解法：注入 `sleep N`，量「這條指令實際花多久」。若耗時 ≥ N*0.7 秒，代表 sleep 真的在
# 靶機上被執行 → 盲注命中。耗時來源有二，任一達標即可：
#   (a) 執行端實測（time.perf_counter 包住 execute_cli，最可靠，不靠 LLM 加參數）
#   (b) 指令自帶 curl -w 'OOB_SECONDS=%{time_total}' 印在回應裡的秒數（generation.py 的 T3 模板）
# =============================================================================
_SLEEP_PROBE_RE = re.compile(r"\bsleep\s+(\d+)")
_OOB_SECONDS_RE = re.compile(r"OOB_SECONDS=([0-9.]+)")
# 小於這個秒數的 sleep 不採信（和網路抖動分不開）；可用環境變數調。
BLIND_SLEEP_MIN = float(os.getenv("BLIND_SLEEP_MIN", "3"))

def _judge_blind_timing(command: str, elapsed: float = None, response: str = "") -> bool:
    """盲注時間差判定：指令若注入了 sleep N，且（執行端實測耗時 或 回應裡的 OOB_SECONDS）
    ≥ N*0.7 秒，代表 sleep 真的在靶機執行 → 判盲注命中。都沒達標回 False。
    command 沒有 sleep、或 sleep 秒數太短時直接回 False，不會誤判一般指令。"""
    m = _SLEEP_PROBE_RE.search(command or "")
    if not m:
        return False
    want = int(m.group(1))
    if want < BLIND_SLEEP_MIN:
        return False
    threshold = want * 0.7
    # (a) 執行端實測耗時（最可靠）
    if elapsed is not None and elapsed >= threshold:
        return True
    # (b) curl -w 印在回應裡的 OOB_SECONDS=秒數
    mo = _OOB_SECONDS_RE.search(response or "")
    if mo:
        try:
            if float(mo.group(1)) >= threshold:
                return True
        except ValueError:
            pass
    return False

# =============================================================================
# ♻️【同注入點去重】
# 問題：CVE-2016-1555 / CVE-2017-18805 / CVE-2017-18806 都是「Netgear 指令注入」，
# 且 agent 對它們都用同一條 boardDataWW.php + macAddress payload。只要該 sink 可注入，
# 三筆都會因同一個 sleep 延遲而「命中」——但實際只證明了【一個】注入點。若全記成獨立
# 利用，報告會灌水。
# 解法：為每次成功算出「注入點簽章」= 正規化端點 + 漏洞類別。同一簽章只算一次獨立命中，
# 其餘標成 affected-by-version（受影響、未獨立驗證），並指回標準歸屬 CVE。
#   - boardData*.php（WW/NA/102/103/JP）是同一個洞 → 正規化成同一 key。
#   - 該 sink 的標準歸屬＝CVE-2016-1555（有公開 PoC、未授權、描述明確點名此端點）。
# =============================================================================
_BOARDDATA_RE = re.compile(r"/boardData\w*\.php", re.IGNORECASE)
_URLPATH_RE = re.compile(r"""https?://[^/\s'"]+(/[^\s'"?]*)""")

# 已知注入點的標準歸屬 CVE：此 sink 命中時，獨立利用一律歸給這個 CVE。
_CANONICAL_CVE_FOR_SIG = {
    "cmd_injection@/boardData*.php": "CVE-2016-1555",
}

def _injection_signature(command: str, vuln_class: str = "") -> str:
    """從成功指令抽出『注入點簽章』＝正規化端點路徑 + 漏洞類別。
    同一簽章代表打的是同一個洞（所有 boardData*.php 命令注入歸為一個）。
    抽不出端點時回空字串（代表無法判定，不做去重）。"""
    if not command:
        return ""
    if _BOARDDATA_RE.search(command):           # boardData 家族一律收斂成同一 key
        path = "/boardData*.php"
    else:
        m = _URLPATH_RE.search(command)
        if not m:
            return ""
        path = m.group(1).rstrip("/") or "/"
    return f"{vuln_class or 'generic'}@{path}"

# 避免把靶機服務打崩導致後續測試無法進行。
DOS_KEYWORDS = [
    "denial of service", "denial-of-service", "(dos)", " dos ",
    "crash", "buffer overflow", "out-of-memory", "out of memory",
    "exhaust", "resource exhaustion", "infinite loop", "reboot",
    "拒絕服務", "崩潰", "耗盡",
]

def _is_dos_cve(cve: dict) -> bool:
    """
    用 CVE 描述關鍵字判斷是否為 DoS 類 (程式碼判斷)。
    """
    desc = (cve.get("description") or "").lower()
    return any(k in desc for k in DOS_KEYWORDS)

# 預設帳密清單檔（與 main.py 同目錄）。登入環節逐組「直接全試」。
DEFAULT_CREDS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "default_creds.json")

def _load_default_creds() -> list:
    """
    載入 default_creds.json 的 credentials 清單；
    讀不到回空清單。
    """
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
        """初始化滲透測試 SOP：綁定目標 IP、建立工具箱與記憶體，並確保 share_memory 必要鍵存在。
        reset_memory=True 會清掉上一輪的 share_memory（換一台設備重新開跑時用）。"""
        self.target_ip = TARGET_IP
        # 目前這顆 CVE 的「執行回顯驗證碼」marker（可執行類漏洞用）；
        # 回應若出現它 = 指令真的在靶機上執行了（最強命中條件，非 LLM 自稱）。
        self._active_nonce = None
        self.net_tools = PentestToolbox(self.target_ip)
        self.mem = util.LangChainPentestMemory(target_ip=self.target_ip, reset=reset_memory)
        self.sm = util.get_share_memory()
        self._ensure_sm_keys()
        log_info.info("✨ [SOP] Share Memory 初始化完成。")

    # ------------------------------------------------------------------
    def _ensure_sm_keys(self):
        """確保 share_memory 內各階段會用到的鍵都存在（缺的給預設空值），避免後續 KeyError。"""
        self.sm = util.get_share_memory()
        self.sm.setdefault("ports", {"TCP": [], "UDP": []})
        self.sm.setdefault("web_footprints", {})
        self.sm.setdefault("analyzed_urls", [])
        self.sm.setdefault("searched_rag_queries", [])
        self.sm.setdefault("cves", [])
        self.sm.setdefault("exploit_attempts", [])   # 每個 CVE 的驗證紀錄都存這
        util.update_share_memory(self.sm)

    def _reload(self):
        """從磁碟重新載入 share_memory 到 self.sm（工具會直接改磁碟，讀之前先同步最新狀態）。"""
        self.sm = util.get_share_memory()

    def _save(self):
        """把目前 self.sm 寫回磁碟，並同步記一份到 log。"""
        util.update_share_memory(self.sm)
        log_info.share_memory(self.sm)

    @staticmethod
    def _clean_service_query(service: str, version: str) -> str:
        """
        把 service/version 清成乾淨查詢字串：剝掉括號雜質與 port 描述。
        """
        raw = f"{service} {version}".strip()
        raw = re.sub(r"\([^)]*\)", " ", raw)                          # 去括號內容
        raw = re.sub(r"(?i)\bport\b.*", " ", raw)                     # 去 port 描述
        raw = re.sub(r"(?i)service detection performed.*", " ", raw)  # 去 nmap 雜訊
        raw = re.sub(r"\s+", " ", raw).strip()
        return raw

    def _is_internal_url(self, url: str) -> bool:
        """
        只接受指向 target IP（或相對路徑）的端點，外部網址一律跳過。
        """
        u = (url or "").strip()
        if not u:
            return False
        if u.startswith("http://") or u.startswith("https://"):
            return self.target_ip in u
        return True  # 相對路徑視為內部

    def stage1_recon(self):
        """
        [ State 1 ] 資產偵查 ( nmap SOP )：做 UDP 跟 TCP 的 Port 偵查
        """
        log_info.info("═══ Stage 1：資產偵察 (nmap SOP) ═══")
        self.net_tools.nmap_scan_tcp()
        self.net_tools.nmap_scan_udp()
        self._reload()

        ports = self.sm.get("ports", {})
        tcp_n = len(ports.get("TCP", []))
        udp_n = len(ports.get("UDP", []))
        log_info.info(f"✅ Stage 1 完成：TCP {tcp_n} 埠 / UDP {udp_n} 埠")

    def stage2_web_enum(self):
        """
        [ State 2 ] 網頁列舉
        """
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

    def _fingerprint_device(self):
        """
        [ 裝置指紋蒐集 ] 主動探測標準裝置發現協定 ( HNAP / UPnP / HTTP 標頭 )，
        並從中抽取出真實的 vendor / model / firmware ( 藉由程式碼進行，而非 LLM )。
        如果抽取失敗，將資訊標記為 finding。
        另外併入自製通用辨識器 ( identify_device )，做廣度補強。
        """
        log_info.info("═══ 裝置指紋 ( 主動探測標準發現協定 HNAP / UPnP / 標頭 ) ═══")
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
                # ℹ️ HNAP 本就是「裝置管理/發現」協定，回傳 vendor/model/firmware 屬其設計用途，
                #    不應算成一筆「成功的漏洞」。故 HNAP 只保留為『資訊性紀錄』(info_only)，
                #    success=False → 不計入 Stage 5 成功數；其餘敏感端點(如 UPnP)維持原樣算洩漏。
                is_info_only = (pid == "hnap")
                if is_info_only:
                    log_info.info(f"   ℹ️ [資訊性] {path} 回傳裝置資訊（HNAP 協定設計行為，不計入成功）")
                else:
                    log_info.info(f"   ✅ [資訊洩漏] {path} 未授權即回傳裝置資訊")
                findings.append({
                    "cve_id": f"INFO-DISCLOSURE {path}",
                    "cvss": "N/A",
                    "description": f"{desc}：未授權即可取得裝置資訊 "
                                   f"(vendor={info.get('vendor','')}, model={info.get('model','')}, "
                                   f"firmware={info.get('firmware','')})。"
                                   + ("（HNAP 為裝置發現協定之設計行為，列為資訊性、不計入成功。）"
                                      if is_info_only else ""),
                    "method": "standard-protocol-probe",
                    "attempts": [{
                        "n": 1, "cmd": cmd,
                        "response_excerpt": (resp or "")[:RESP_EXCERPT_LEN],
                        "judged_success": not is_info_only, "is_poc": False,
                    }],
                    "success": not is_info_only,
                    "success_cmd": None if is_info_only else cmd,
                    "info_only": is_info_only,
                })

        # =============================================================
        # 📡【廣度指紋補強】標準協定探測（深度）跑完後，再跑自製通用辨識器
        #    （HTTP 爬首頁跳轉/子框架/.php 設定腳本 + CSS logo OCR + UPnP/SSDP）。
        #    用 setdefault 只補 standard-probe「沒抽到」的欄位——HNAP/UPnP XML 的
        #    高可信結果優先，不會被覆蓋。identify_device 內部也會把結果 setdefault
        #    進 web_footprints，standalone 呼叫同樣有效。
        # =============================================================
        try:
            dev = self.net_tools.identify_device()
        except Exception as e:
            dev = {}
            log_info.warn(f"⚠️ [裝置指紋] identify_device 例外：{e}")
        if dev:
            for k in ("vendor", "model", "firmware", "server"):
                if dev.get(k):
                    collected.setdefault(k, dev[k])     # 只補 standard-probe 沒有的
            if dev.get("hw_version"):
                collected.setdefault("hw_version", dev["hw_version"])
            if dev.get("clues"):
                collected.setdefault("clues", dev["clues"])
            log_info.info(
                f"   📡 [廣度指紋補強] identify_device 貢獻："
                f"vendor={dev.get('vendor') or '—'}, model={dev.get('model') or '—'}, "
                f"firmware={dev.get('firmware') or '—'}, hw={dev.get('hw_version') or '—'}"
            )

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
            if collected.get("hw_version"):
                wf["hardware_version"] = collected["hw_version"]
            if collected.get("server"):
                wf["server"] = collected["server"]
            if collected.get("_hnap_actions"):
                wf["hnap_actions"] = collected["_hnap_actions"]
            wf["fingerprint_source"] = "standard-protocol-probe + identify_device"
            self.sm["device_fingerprint"] = collected
            self.sm["disclosure_findings"] = findings
            self._save()
            log_info.info(f"🧾 [裝置指紋] 程式抽出真實裝置資訊: {collected}")
        else:
            self._reload()
            self.sm["disclosure_findings"] = findings
            self._save()
            log_info.info("   ↳ 標準協定未回傳可用裝置資訊（可能為未知/未支援的設備）。")

        # 🎯【已知 IoT 攻擊面主動探測】把 boardData*.php / recreate.php 這類沒連結、Stage 2
        #    爬不到、但正是 CVE sink 的端點主動探一輪，存在的記進 live_endpoints 當攻擊面情報。
        self._probe_known_attack_endpoints()

        return findings

    def _probe_known_attack_endpoints(self):
        """主動探測已知 IoT 攻擊面端點（boardData*.php / recreate.php 等）。
        這些真實 sink 多半沒有連結、Stage 2 爬不到，但正是 CVE 的注入/存取點。
        逐一 curl，存在（非 404、非連線失敗、非逾時）就記進 share_memory['live_endpoints']，
        讓 Stage 4 的 _build_target_context 把它們當攻擊面情報餵給 LLM。"""
        self._reload()
        existing = {x.get("url") for x in self.sm.get("live_endpoints", [])
                    if isinstance(x, dict)}

        new_recs = []
        found = []
        for path in self.KNOWN_ATTACK_ENDPOINTS:
            url = f"http://{self.target_ip}{path}"
            if url in existing:
                continue
            resp = self.net_tools.execute_cli(f"curl -s -i -m 10 http://{self.target_ip}{path}")
            low = (resp or "").lower()
            # 連線失敗 / 404 / 逾時 → 視為不存在，跳過
            if not resp or "404 not found" in low or self._judge_fail_only(resp):
                continue
            m = re.search(r"http/\d\.\d\s+(\d+)", low)
            status = m.group(1) if m else "200"
            new_recs.append({
                "url": url, "status": status, "title": "",
                "note": "known-attack-surface probe（主動探測命中的 CVE sink）",
            })
            found.append(f"{path}({status})")

        if new_recs:
            # execute_cli 期間 share_memory 可能被改，收尾前重讀再合併，避免覆蓋
            self._reload()
            live = self.sm.get("live_endpoints", [])
            if not isinstance(live, list):
                live = []
            have = {x.get("url") for x in live if isinstance(x, dict)}
            for rec in new_recs:
                if rec["url"] not in have:
                    live.append(rec)
            self.sm["live_endpoints"] = live
            self._save()
            log_info.info(f"🎯 [已知攻擊面] 主動探測命中: {', '.join(found)}（已記入攻擊面情報）")
        else:
            log_info.info("   ↳ 已知攻擊面端點主動探測：無額外命中。")

    @staticmethod
    def _is_real_version(version: str) -> bool:
        """
        判斷版本欄位是不是『真的有版本資訊』。
        排除 unknown、空值、nmap 的雜訊字串（Service detection performed...）。
        """
        v = (version or "").strip().lower()
        if not v or v == "unknown":
            return False
        if "service detection performed" in v or "please report" in v:
            return False
        return True

    @staticmethod
    def _model_query_variants(model: str, vendor_short: str = "") -> list:
        """
        從指紋型號展開多組查詢變體，提高 CVE 檢索命中率。
        重點場景：HNAP 回報硬體版號（如 DIR-601B1），但 CVE 以市場型號收錄（DIR-601L / DIR-601）。
        作法：
          1. 原字串（DIR-601B1）
          2. 去掉『硬體版號後綴』(結尾的 字母+數字，如 B1/A1/C1；L/K 這種市場字尾不動) → 家族名 DIR-601
             —— DIR-601 是 DIR-601L 的子字串，NVD/RAG 查 DIR-601 就能撈到 DIR-601L 的 CVE。
          3. 分隔符變體（DIR601 / DIR 601）
          4. 加廠商前綴（D-Link DIR-601 / D-Link DIR-601B1）
        回傳保序去重後的變體清單。
        """
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

    def _build_stage4_targets(self) -> list:
        """
        只挑『真實服務』當檢索目標：
          1. 有明確版本號的 port 服務（例如 dnsmasq 2.41、MiniUPnP 1.4）
          2. Web 分析挖到的廠商與 server 軟體（例如 D-Link、lighttpd 1.4.28）
        跳過 http unknown / dhcps / netbios-ns 這種只有服務類型、沒有產品的髒查詢。
        """
        targets = []

        def _add(q):
            """把查詢字串去空白後加進 targets；空字串或已存在的（大小寫不分）直接跳過。"""
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

        # 3b. identify_device 抓到的多候選型號（例如 WNAP210 / WNAP320）也一起展開檢索
        for m in (self.sm.get("device_identify", {}) or {}).get("models_all", []):
            if m and m.lower() != "unknown":
                for v in self._model_query_variants(m, vendor_short):
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

    def stage3_vuln_search(self):
        """[ Stage 4 執行順序 ] 漏洞檢索：對每個真實服務 / 廠商 / 型號查 NVD 線上 API。
        （RAG 目前停用，只用 NVD；要恢復「RAG 優先、查無則 NVD 備援」見下方註解。）
        NVD 工具本身會把命中的 CVE 寫進 share_memory['cves']，這裡只負責決定『查哪些目標』，
        並以 share_memory['cves'] 筆數的增量判斷某個目標有沒有新命中。"""
        log_info.info("═══ Stage 4：漏洞檢索 (目前僅用 NVD) ═══")
        self._reload()

        targets = self._build_stage4_targets()
        if not targets:
            log_info.warn("⚠️ Stage 4：沒有可檢索的目標（無真實版本號服務 / 廠商 / 型號），略過。")
            return

        log_info.info(f"🔍 [Stage 4] 檢索目標共 {len(targets)} 個：{targets}")

        for i, q in enumerate(targets, 1):
            log_info.info(f"🔎 [Stage 4] ({i}/{len(targets)}) 檢索：{q}")

            # 查詢前的 CVE 數 → 用增量判斷這個目標有沒有新命中
            self._reload()
            before = len(self.sm.get("cves", []))

            # 🔕【RAG 目前停用】只用 NVD。要恢復「RAG 優先、查無則 NVD 備援」，
            #    取消下面這段註解即可（rag_search_cve 會把命中的 CVE 寫進 share_memory['cves']）：
            # self.net_tools.rag_search_cve(q)
            # self._reload()
            # if len(self.sm.get("cves", [])) > before:
            #     log_info.info(f"   ✅ RAG 命中：{q}。")
            #     continue

            # NVD 線上查詢（無版本號的泛詞會在 nvd_search_cve 內自動跳過）
            self.net_tools.nvd_search_cve(q)

            self._reload()
            after = len(self.sm.get("cves", []))
            if after > before:
                log_info.info(f"   ✅ NVD 命中：{q} 新增 {after - before} 筆 CVE。")
            else:
                log_info.info(f"   ❌ {q} NVD 無結果。")

        # 🧹 相關性過濾：剔除與本機軟體棧無關的 CVE（NVD 關鍵字搜尋常撈到 Windows/HP/SunOS/
        #    印表機等完全不相干的歷史 CVE，會把報告風險分佈灌爆、嚴重影響可信度）。
        self._filter_irrelevant_cves()

        self._reload()
        total = len(self.sm.get("cves", []))
        log_info.info(f"✅ Stage 4 完成：share_memory 累積 {total} 筆 CVE（已過濾不相關）。")

    # 服務/協定泛詞：太常見，當關鍵詞會把一堆不相干 CVE 也留下，故排除。
    _GENERIC_SVC_TERMS = {
        "http", "https", "www", "domain", "dns", "upnp", "ssdp", "ssl", "tls",
        "tcp", "udp", "unknown", "service",
    }

    def _build_relevance_terms(self) -> set:
        """從裝置指紋 + 開放埠組出『相關產品/服務關鍵詞』集合，用來判斷一筆 CVE 是否真的
        跟本機軟體棧有關。包含：
          - 產品名（lighttpd / dnsmasq / miniupnp / d-link / dir-601 變體…）
          - 實際開放的服務/協定名（tftp / snmp / netbios / dhcp…；排除 http 等過泛詞）
        全部小寫；純數字（版本號）與長度 < 3 的字串捨棄，避免誤命中。"""
        terms = set()

        def _add_words(s):
            for tok in re.split(r"[\s/(),_]+", (s or "").lower()):
                tok = tok.strip(" .-?")
                if len(tok) >= 3 and not re.fullmatch(r"[\d.]+", tok):
                    terms.add(tok)

        wf = self.sm.get("web_footprints", {})
        fp = self.sm.get("device_fingerprint", {})

        # server 標頭（lighttpd/1.4.28 → lighttpd）、廠商（D-Link）
        _add_words(wf.get("server", "")); _add_words(fp.get("server", ""))
        _add_words((wf.get("iot_vendor", {}) or {}).get("name", "")); _add_words(fp.get("vendor", ""))

        # 型號（DIR-601B1 → 展開家族/分隔符變體，橋接 DIR-601 / DIR601 等寫法）
        def _add_model(s):
            # 型號詞必須『含數字或長度 >= 5』，否則像 'dir' 會誤命中 directory/jetDirect/direct…
            for tok in re.split(r"[\s/(),_]+", (s or "").lower()):
                tok = tok.strip(" .-?")
                if not tok or re.fullmatch(r"[\d.]+", tok):
                    continue
                if re.search(r"\d", tok) or len(tok) >= 5:
                    terms.add(tok)

        model_sources = [wf.get("device_model", ""), fp.get("model", "")]
        model_sources += (self.sm.get("device_identify", {}) or {}).get("models_all", [])
        for m in model_sources:
            if m and m.lower() != "unknown":
                for v in self._model_query_variants(m):
                    _add_model(v)

        # 開放埠：真實版本字串（常含產品名 dnsmasq/MiniUPnP）+ 夠特定的服務名（排除 http 等泛詞）
        for proto in ("TCP", "UDP"):
            for p in self.sm.get("ports", {}).get(proto, []):
                ver = p.get("version", "")
                if self._is_real_version(ver):          # 跳過 nmap 的雜訊版本字串
                    _add_words(ver)
                svc = (p.get("service", "") or "").lower().strip(" ?").split("-")[0]
                if len(svc) >= 3 and svc not in self._GENERIC_SVC_TERMS:
                    terms.add(svc)                      # tftp / snmp / netbios / dhcps…

        if "d-link" in terms:
            terms.add("dlink")
        if "dlink" in terms:
            terms.add("d-link")

        noise = {"unknown", "service", "detection", "performed", "please", "report",
                 "incorrect", "results", "wireless", "router", "home", "inc", "systems",
                 "nmap", "submit", "org", "the", "and", "for", "version"} | self._GENERIC_SVC_TERMS
        return {t for t in terms if t not in noise}

    def _filter_irrelevant_cves(self):
        """把與本機軟體棧無關的 CVE 從待驗證清單移到 excluded_cves（不刪除、保留可稽核）。
        判準：CVE 的（描述 + 產品 + 編號 + CPE）需命中至少一個相關關鍵詞；全都沒命中＝視為
        NVD 關鍵字誤撈（Windows/HP/SunOS/印表機/其他裝置…），排除、不列入驗證與報告。
        若指紋沒抽到任何可用關鍵詞則略過過濾（全數保留），以免把全部誤殺。"""
        self._reload()
        terms = self._build_relevance_terms()
        if not terms:
            log_info.warn("⚠️ [相關性過濾] 指紋未提供可用關鍵詞，略過過濾（全數保留）。")
            return

        cves = [c for c in self.sm.get("cves", []) if isinstance(c, dict)]
        kept, dropped = [], []
        for c in cves:
            cpe = c.get("cpe", "")
            cpe_s = " ".join(cpe) if isinstance(cpe, list) else str(cpe)
            blob = " ".join([
                str(c.get("description", "")),
                str(c.get("product", "")),
                str(c.get("cve_id") or c.get("cveID") or ""),
                cpe_s,
            ]).lower()
            if any(t in blob for t in terms):
                kept.append(c)
            else:
                dropped.append(c)

        if dropped:
            self.sm["cves"] = kept
            self.sm["excluded_cves"] = (self.sm.get("excluded_cves", []) or []) + [
                {"cve_id": d.get("cve_id") or d.get("cveID"),
                 "reason": "irrelevant-product",
                 "description": (d.get("description", "") or "")[:200]}
                for d in dropped
            ]
            self._save()
            log_info.info(
                f"🧹 [相關性過濾] 保留 {len(kept)} 筆、排除 {len(dropped)} 筆與軟體棧無關的 CVE。"
            )
            log_info.info(f"   ↳ 相關關鍵詞：{', '.join(sorted(terms))}")
        else:
            log_info.info(f"🧹 [相關性過濾] {len(kept)} 筆全部相關，無排除。")

    def _judge_success(self, response: str, command: str = None, elapsed: float = None) -> bool:
        """程式硬條件判定。
        ①最強：執行回顯 nonce 出現＝指令真的在靶機執行（勝過一切，連失敗字串也不翻盤，
          因為我們注入的隨機碼被回顯，本身就是鐵證）。
        ①'盲注時間差：注入 sleep N 且實際耗時達標＝指令真的執行（輸出不回顯的盲注也抓得到）。
          與 nonce 同屬「鐵證」，優先於失敗字串——因為延遲本身就是執行的證明。
        ②其次：失敗特徵命中 → 判失敗。
        ③最後：成功關鍵字命中 → 判成功。
        command / elapsed：呼叫端把「這條指令」與「實測耗時」傳進來，供盲注時間差判定用；
        不傳（如舊呼叫）則時間差規則自動略過，行為與原本相同（向下相容）。"""
        text = response or ""
        if self._active_nonce and self._active_nonce in text:
            return True
        if _judge_blind_timing(command, elapsed, text):
            return True
        low = text.lower()
        if any(m.lower() in low for m in FAILURE_MARKERS):
            return False
        return any(k.lower() in low for k in SUCCESS_KEYWORDS)

    def _success_evidence(self, response: str, command: str = None, elapsed: float = None) -> dict:
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
        # ①' 盲注時間差證據：注入 sleep N 且耗時達標＝指令確實執行（盲注 RCE）
        if _judge_blind_timing(command, elapsed, text):
            m = _SLEEP_PROBE_RE.search(command or "")
            want = m.group(1) if m else "?"
            if elapsed is not None:
                got = f"{elapsed:.1f} 秒（執行端實測）"
            else:
                mo = _OOB_SECONDS_RE.search(text)
                got = f"{mo.group(1)} 秒（curl -w 回報）" if mo else "≥ 門檻"
            return {
                "keywords": ["<blind-timing>"],
                "snippet": f"注入 sleep {want} 秒後，回應耗時 {got} → 指令確實在靶機執行"
                           f"（盲注 RCE，時間差證明；輸出不回顯故無法用關鍵字判定）。",
            }
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
        _t0 = time.perf_counter()
        resp = self.net_tools.execute_cli(full_cmd)
        elapsed = time.perf_counter() - _t0
        ok = self._judge_success(resp, command=full_cmd, elapsed=elapsed)
        evidence = self._success_evidence(resp, command=full_cmd, elapsed=elapsed) if ok else {}

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

    # 已知 IoT 攻擊面端點：這些真實 sink 多半沒有連結、Stage 2 web 列舉爬不到，但正是
    # CVE 的注入/存取點。裝置指紋階段會主動 curl 一輪，存在的記進 live_endpoints，讓
    # Stage 4 的 _build_target_context 餵給 LLM——命令注入才打得到真 sink 而非亂猜 config.php。
    KNOWN_ATTACK_ENDPOINTS = [
        "/boardDataWW.php", "/boardData102.php", "/boardData103.php",
        "/boardDataJP.php", "/boardDataNA.php",   # Netgear ProSAFE 命令注入 sink
        "/recreate.php",                          # Netgear 存取控制 / 認證繞過
        "/BackupConfig.php",                      # 設定備份洩漏
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
        """
        7B 後備：程式抽不出登入表單時，請 7B 從 HTML 找出表單欄位。
        回傳 {action_url, method, user_field, pass_field}。失敗回 {}。
        """
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
        """[ Stage 5 執行順序 ] 漏洞驗證：逐一拿 share_memory['cves'] 的 CVE 做實測。
        有自帶 PoC → 交 coder 改寫成可執行檔跑；沒 PoC → 回饋迴圈由 LLM 逐步產指令
        （看得到上一步真實回應再修正下一步）。以『執行回顯 nonce / 成功關鍵字』做程式硬條件判定，
        DoS 類只列報告不實跑。結果寫進 share_memory['exploit_attempts']。"""
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

        # 🚫【DoS 不進驗證清單】DoS 類會打崩靶機、本來就不實際驗證，只留在報告當「已識別、未驗證」。
        # 📋【report-only 不進驗證清單】csrf / buffer_overflow / misconfiguration 用現有判定條件
        #    (nonce / root:x:0:0 / uid=0…) 本來就驗不出來，比照 DoS 只列報告、不進迴圈，
        #    避免 Stage 5 成功率被必然未果的類別拉低。
        dos_cves = [c for c in all_cves if _is_dos_cve(c)]
        rest = [c for c in all_cves if not _is_dos_cve(c)]

        report_only_cves = []
        cves = []
        for c in rest:
            if classify_cve(c) in REPORT_ONLY_CLASSES:
                report_only_cves.append(c)
            else:
                cves.append(c)

        # 把 DoS / report-only 從 share_memory 的「要用的 CVE 清單」移除
        # → 網頁/計數看到的就是乾淨的待驗證清單
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

        # report-only 類別寫進報告（已識別、不自動驗證），同樣不佔驗證進度、不進迴圈
        for c in report_only_cves:
            cid = c.get("cve_id") or c.get("cveID") or "UNKNOWN"
            try:
                sc = float(c.get("score") or c.get("cvss") or 0)
            except (ValueError, TypeError):
                sc = 0.0
            attempts_log.append({
                "cve_id": cid, "cvss": sc, "description": c.get("description", ""),
                "vuln_class": classify_cve(c),
                "attempts": [], "success": False, "success_cmd": None,
                "report_only": True,   # 報告端據此寫「已識別、不自動驗證(csrf/溢位/設定不當)」
            })
        if report_only_cves:
            log_info.info(
                f"📋 已將 {len(report_only_cves)} 筆 report-only 類 CVE"
                f"(csrf/buffer_overflow/misconfiguration)列報告、不自動驗證。"
            )

        total_cves = len(cves)
        if not cves:
            log_info.warn("⚠️ Stage 5：扣除 DoS / report-only 後沒有可驗證的 CVE，但已併入裝置指紋階段的洩漏發現。")

        # ♻️【去重狀態】confirmed_signatures: 注入點簽章 → 第一個獨立命中的 CVE。
        #    cve_ids_in_scope: 這輪實際會驗證的 CVE 集合（標準歸屬 CVE 不在其中時退回「第一個命中」當歸屬）。
        confirmed_signatures = {}
        cve_ids_in_scope = {(c.get("cve_id") or c.get("cveID")) for c in cves}

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
                    _t0 = time.perf_counter()
                    resp = self.net_tools.execute_cli(cmd)
                    elapsed = time.perf_counter() - _t0
                    ok = self._judge_success(resp, command=cmd, elapsed=elapsed)
                    evidence = self._success_evidence(resp, command=cmd, elapsed=elapsed) if ok else {}
                    cve_record["attempts"].append({
                        "n": attempt_n, "cmd": cmd,
                        "response_excerpt": (resp or "")[:RESP_EXCERPT_LEN],
                        "judged_success": ok, "is_poc": False,
                        "reason": reason,
                        "elapsed_sec": round(elapsed, 2),
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

            # ============================================================
            # ♻️ 同注入點去重：命中後算注入點簽章，若該 sink 已有歸屬（標準歸屬 CVE，
            #    或這輪第一個命中它的 CVE）且不是自己 → 標成 affected-by-version，
            #    不計為獨立利用，避免同族 CVE 借同一 sink 灌水。
            # ============================================================
            if cve_record["success"]:
                sig = _injection_signature(cve_record.get("success_cmd", ""), vuln_class)
                canonical = _CANONICAL_CVE_FOR_SIG.get(sig)
                if canonical and canonical not in cve_ids_in_scope:
                    canonical = None   # 標準歸屬 CVE 這輪沒驗到 → 退回「第一個命中」當歸屬
                owner = canonical or confirmed_signatures.get(sig)
                if sig and owner and owner != cve_id:
                    # 這條命中其實是別人(owner)的 sink → 去重
                    cve_record["success"] = False
                    cve_record["affected_by_version"] = True
                    cve_record["duplicate_of"] = owner
                    cve_record["dedup_note"] = (
                        f"與 {owner} 為同一注入點（{sig}）。本次時間差命中的實為該 sink，"
                        f"非本 CVE 獨立驗證；列為『受影響(版本範圍內)、未獨立驗證』。"
                    )
                    log_info.info(
                        f"   ♻️ {cve_id} 與 {owner} 同注入點（{sig}）→ 去重，標為 affected-by-version（不計獨立命中）。"
                    )
                elif sig:
                    # 該 sink 的獨立命中（標準歸屬本尊，或無標準歸屬時的第一個）
                    confirmed_signatures.setdefault(sig, cve_id)
                    cve_record["independent"] = True

            if not cve_record["success"] and not cve_record.get("duplicate_of"):
                log_info.info(f"   ❌ {cve_id} 經 {len(cve_record['attempts'])} 次嘗試未命中，記錄為 attempted。")

            attempts_log.append(cve_record)
            self._active_nonce = None   # 本顆 CVE 結束，清掉驗證碼避免殘留誤判

        # ⚡ 全部 CVE 測完：回報子進度收尾（網頁計數跳到 N/N 完成）
        if total_cves:
            log_info.cve_progress(total_cves, total_cves, None, status="done")

        self._reload()
        self.sm["exploit_attempts"] = attempts_log
        self._save()
        succ = sum(1 for a in attempts_log if a.get("success"))
        dup = sum(1 for a in attempts_log if a.get("duplicate_of"))
        other = len(attempts_log) - succ - dup
        log_info.info(
            f"✅ Stage 5 完成：{len(attempts_log)} 個 CVE，"
            f"獨立成功 {succ}、同注入點去重 {dup}、其餘未果/未驗證 {other}"
        )

    def stage5_report(self):
        """[ Stage 6 執行順序 ] 彙整 share_memory 產生 Markdown 報告，回傳報告檔路徑。"""
        log_info.info("═══ Stage 6：產生 Markdown 報告 ═══")
        self._reload()
        path = report_mod.generate_markdown_report(self.sm, self.target_ip)
        log_info.info(f"✅ Stage 6 完成：報告已輸出 → {path}")
        return path

    # ==================================================================
    # 執行順序（依資料依賴排；編號即網頁進度列顯示的 1~6）
    STAGES = [
        ("資產偵察",  "stage1_recon"),
        ("Web 列舉",  "stage2_web_enum"),
        ("裝置指紋",  "_fingerprint_device"),
        ("漏洞檢索",  "stage3_vuln_search"),
        ("漏洞驗證",  "stage4_verify"),
        ("產生報告",  "stage5_report"),
    ]

    def run(self):
        """依 STAGES 的順序跑完整條 SOP（偵察 → Web 列舉 → 指紋 → 漏洞檢索 → 驗證 → 報告），
        每進一階段先回報進度列，結束時回傳報告檔路徑。"""
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