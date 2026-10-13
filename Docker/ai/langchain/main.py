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
#   五階段 SOP（全部窮舉，不問 AI 要不要做）：
#     Stage 1  偵察        nmap（已是 SOP）
#     Stage 2  漏洞檢索    對每個已知 service 各打一次 RAG（查無則 NVD 備援）
#     Stage 3  Web 列舉    對每個「內部」端點各分析一次，外部網址自動跳過
#     Stage 4  漏洞驗證    每個 CVE 產 5 次 payload 逐一執行，硬條件判定成敗
#     Stage 5  產生報告    彙整成 Markdown
# ============================================================================

import json
import os
import re
from dotenv import load_dotenv

import util
from config.config import TARGET_IP
from config.logging import log_info
from tools import PentestToolbox
from ai.parsing import parse_tool_output
from ai.generation import (
    generate_poc_cmds,
    generate_next_poc_cmd,
    extract_poc_scripts,
    adapt_poc_to_file,
)
import report as report_mod

load_dotenv()

# ---- 可調參數（可用環境變數覆寫）----
POC_ATTEMPTS_PER_CVE = int(os.getenv("POC_ATTEMPTS_PER_CVE", "5"))   # 每個 CVE 驗證幾次
CVSS_MIN = float(os.getenv("CVSS_MIN", "0.0"))                        # 報告收錄的 CVSS 下限（0 = 全收）
MAX_ENDPOINTS = int(os.getenv("MAX_ENDPOINTS", "15"))                 # Web 端點最多分析幾個，避免爆量

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


class PentestSOP:

    def __init__(self, reset_memory: bool = True):
        self.target_ip = TARGET_IP
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
    # Stage 1：偵察（nmap SOP）
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
    # Stage 2：漏洞檢索（對每個已知 service 窮舉 RAG，查無則 NVD 備援）
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
        if vendor and vendor.lower() not in ("unknown", "unknown vendor"):
            # 取廠商名的第一個詞即可（D-LINK SYSTEMS, INC. → D-Link）
            vendor_short = vendor.split(",")[0].split()[0] if vendor.split() else vendor
            _add(vendor_short)

        server = wf.get("server", "")
        if server and server.lower() != "unknown":
            # lighttpd/1.4.28 → lighttpd 1.4.28
            _add(server.replace("/", " ").strip())

        # 3. 裝置指紋階段抽出的真實型號（例如 DIR-601B1）——最精準的檢索目標
        model = wf.get("device_model", "")
        if model and model.lower() != "unknown":
            _add(model)

        return targets

    def stage2_vuln_search(self):
        log_info.info("═══ [漏洞檢索] 只查真實服務 ═══")
        self._reload()

        targets = self._build_stage2_targets()
        if not targets:
            log_info.warn("⚠️ [漏洞檢索] 沒有任何可查的真實服務（都是 unknown 或純服務類型）。")
            return

        log_info.info(f"🎯 [漏洞檢索] 本次檢索目標（已過濾髒查詢）: {targets}")

        NVD_CAP_PER_QUERY = int(os.getenv("NVD_CAP_PER_QUERY", "10"))

        for q in targets:
            log_info.info(f"🔎 [漏洞檢索] RAG 檢索: {q}")
            raw = self.net_tools.rag_search_cve(q)

            # RAG 查無 → NVD 線上備援
            self._reload()
            before = len(self.sm.get("cves", []))
            if "未找到" in raw or "資料庫中未找到" in raw:
                log_info.info(f"   ↳ RAG 無結果，改用 NVD 線上備援查詢: {q}")
                self.net_tools.nvd_search_cve(q)
                self._reload()

                # ⚠️ NVD 備援上限：單一查詢最多保留 NVD_CAP_PER_QUERY 筆，
                #    避免像 'http' 這種泛詞一次灌進數百筆不相干 CVE。
                cves = self.sm.get("cves", [])
                added = len(cves) - before
                if added > NVD_CAP_PER_QUERY:
                    self.sm["cves"] = cves[:before] + cves[before:before + NVD_CAP_PER_QUERY]
                    util.update_share_memory(self.sm)
                    log_info.warn(
                        f"   ⚠️ NVD 回傳 {added} 筆過多，已截斷為前 {NVD_CAP_PER_QUERY} 筆"
                        f"（可用環境變數 NVD_CAP_PER_QUERY 調整）。"
                    )
                    self._reload()

            after = len(self.sm.get("cves", []))
            log_info.info(f"   ↳ 累計 CVE: {after} 筆 (本次新增 {after - before})")

        log_info.info(f"✅ [漏洞檢索] 完成：共檢索出 {len(self.sm.get('cves', []))} 筆 CVE")

    # ==================================================================
    # Stage 3：Web 端點列舉（窮舉內部端點，外部自動跳過）
    # ==================================================================
    def stage3_web_enum(self):
        log_info.info("═══ [Web 列舉] 窮舉內部端點 ═══")

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

            log_info.info(f"🌐 [Stage 3] 分析端點: {next_url}")
            self.net_tools.analyze_web_page(next_url)
            processed.add(next_url)

        log_info.info(f"✅ Stage 3 完成：共分析 {len(processed)} 個 Web 端點")

    # ==================================================================
    # Stage 4：漏洞驗證（每個 CVE 產 5 次 payload 逐一執行）
    # ==================================================================
    def _judge_success(self, response: str) -> bool:
        """程式硬條件判定：先看有沒有失敗特徵，再看有沒有成功關鍵字。"""
        low = (response or "").lower()
        if any(m.lower() in low for m in FAILURE_MARKERS):
            return False
        return any(k.lower() in low for k in SUCCESS_KEYWORDS)

    def _run_poc_file(self, cve_id: str, poc_file: dict) -> dict:
        """把 coder 改寫好的 PoC 寫成檔案並執行，回傳一筆 attempt 紀錄。"""
        import os as _os
        poc_dir = _os.path.join(_os.getcwd(), "poc_tmp")
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

        return {
            "cmd": run_cmd,
            "poc_filename": filename,
            "poc_content": content[:2000],
            "response_excerpt": (resp or "")[:500],
            "judged_success": ok,
            "is_poc": True,
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
        log_info.info("═══ [裝置指紋] 主動探測標準發現協定 (HNAP/UPnP/標頭) ═══")
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
                        "response_excerpt": (resp or "")[:500],
                        "judged_success": True, "is_poc": False,
                    }],
                    "success": True,
                    "success_cmd": cmd,
                })

        # 把程式實際抽出的真實裝置資訊寫回 web_footprints（覆蓋 Stage 3 的 LLM 猜測）
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

    def stage4_verify(self):
        log_info.info("═══ Stage 4：漏洞驗證 (每個 CVE 試 {} 次) ═══".format(POC_ATTEMPTS_PER_CVE))
        self._reload()

        attempts_log = []

        # 併入裝置指紋階段發現的「標準協定未授權資訊洩漏」findings
        attempts_log.extend(self.sm.get("disclosure_findings", []))

        # 組出「真實端點上下文」，稍後餵給 LLM，讓它打對位置而非亂猜
        target_context = self._build_target_context()
        if target_context:
            log_info.info(f"🧭 [上下文] 提供給 LLM 的真實端點資訊:\n{target_context}")

        cves = self.sm.get("cves", [])
        if not cves:
            log_info.warn("⚠️ Stage 4：沒有 CVE，但已併入裝置指紋階段的洩漏發現。")

        for cve in cves:
            if not isinstance(cve, dict):
                continue
            cve_id = cve.get("cve_id") or cve.get("cveID") or "UNKNOWN"

            # CVSS 門檻過濾（CVSS_MIN=0 時全收）
            try:
                score = float(cve.get("score") or cve.get("cvss") or 0)
            except (ValueError, TypeError):
                score = 0.0
            if CVSS_MIN > 0 and score and score < CVSS_MIN:
                log_info.info(f"   ↳ {cve_id} CVSS {score} < {CVSS_MIN}，略過驗證。")
                continue

            # ⚠️【DoS 跳過】偵測到 DoS 類漏洞不實際攻擊，只記錄，避免打崩靶機。
            if _is_dos_cve(cve):
                log_info.info(f"   ⏭️ {cve_id} 判定為 DoS 類漏洞，為保護靶機不實際驗證，僅記錄。")
                attempts_log.append({
                    "cve_id": cve_id,
                    "cvss": score,
                    "description": cve.get("description", ""),
                    "attempts": [],
                    "success": False,
                    "success_cmd": None,
                    "skipped_dos": True,   # 報告端據此寫「偵測到但未驗證(DoS)」
                })
                continue

            log_info.info(f"🎯 [Stage 4] 驗證 {cve_id} (CVSS {score or 'N/A'})")

            cve_record = {
                "cve_id": cve_id,
                "cvss": score,
                "description": cve.get("description", ""),
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
                        cve, self.target_ip, context=target_context, history=history
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
                    cve_record["attempts"].append({
                        "n": attempt_n, "cmd": cmd,
                        "response_excerpt": (resp or "")[:500],
                        "judged_success": ok, "is_poc": False,
                        "reason": reason,
                    })
                    # 把這一步的真實回應餵回歷史，下一步 LLM 就看得到
                    history.append({"cmd": cmd, "response": (resp or "")[:800]})

                    if ok:
                        cve_record["success"] = True
                        cve_record["success_cmd"] = cmd
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

        self._reload()
        self.sm["exploit_attempts"] = attempts_log
        self._save()
        succ = sum(1 for a in attempts_log if a["success"])
        log_info.info(f"✅ Stage 4 完成：{len(attempts_log)} 個 CVE，成功 {succ}、未果 {len(attempts_log) - succ}")

    # ==================================================================
    # Stage 5：產生 Markdown 報告
    # ==================================================================
    def stage5_report(self):
        log_info.info("═══ Stage 5：產生 Markdown 報告 ═══")
        self._reload()
        path = report_mod.generate_markdown_report(self.sm, self.target_ip)
        log_info.info(f"✅ Stage 5 完成：報告已輸出 → {path}")
        return path

    # ==================================================================
    def run(self):
        log_info.info("🚀 PentestGPT v2 (SOP 固定流程版) 啟動！")
        self.stage1_recon()
        # ⚠️【順序】Web 分析 → 裝置指紋(標準協定主動探測) → 漏洞檢索。
        #    指紋階段用標準協定抽出真實 vendor/model/firmware，再驅動漏洞檢索；
        #    這一步不假設任何廠牌，對未知設備一體適用。
        self.stage3_web_enum()
        self._fingerprint_device()
        self.stage2_vuln_search()
        self.stage4_verify()
        path = self.stage5_report()
        log_info.info("🏁 全流程結束。")
        return path


if __name__ == "__main__":
    PentestSOP().run()