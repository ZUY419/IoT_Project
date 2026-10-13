# Docker/ai/langchain/tools.py
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request
from urllib.parse import urljoin, urlparse
import requests
from dotenv import load_dotenv
from config.logging import log_info
import util

# ⚠️【關鍵】載入與本檔同目錄的 .env（即 ai/langchain/.env）。
# 若少了這行，下面的 os.getenv(...) 只會讀系統環境(compose env 區塊已移除 → 空的)，
# 一律吃預設值——你把 .env 的 RAG_SERVICE_TIMEOUT 改成 600 也完全沒用，訊息永遠顯示 60。
# 必須在下面任何 os.getenv 之前就載入。
load_dotenv(Path(__file__).resolve().parent / ".env")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

TOOL_PACKAGE_MAP = {
    "dirb": "dirb",
    "gobuster": "gobuster",
    "dig": "dnsutils",
    "nslookup": "dnsutils",
    "nmap": "nmap",
    "hydra": "hydra",
    "nc": "netcat-openbsd",
    "netcat": "netcat-openbsd",
    "curl": "curl",
    "nikto": "nikto",
}

# ⚠️【修正重點】RAG 是獨立的 Docker 容器，不能用本地 import 存取其程式碼或資料庫，
# 必須透過網路呼叫其 Flask API (RAG/server.py 暴露的 /search endpoint)。
# RAG_SERVICE_URL 預設值假設 docker-compose 中 RAG 容器的 service name 叫 "rag"，
# 若你的 docker-compose.yml 裡服務名稱不同，請設定環境變數 RAG_SERVICE_URL 覆寫，
# 例如: RAG_SERVICE_URL=http://my-rag-service:8000/search
RAG_SERVICE_URL = os.getenv("RAG_SERVICE_URL", "http://rag:8000/search")
RAG_SERVICE_TIMEOUT = int(os.getenv("RAG_SERVICE_TIMEOUT", "60"))


# =====================================================================
# 查詢字串清洗 —— RAG 與 NVD 的需求相反：
#   RAG(語意向量搜尋)：版本號是雜訊，只留產品名 → 'dnsmasq 2.41' 送 'dnsmasq'
#   NVD(關鍵字+版本)：需要版本號 → 'dnsmasq 2.41' 拆成 product=dnsmasq, version=2.41
# 這是「RAG 查了帶版本號就查無結果」的根治：log 顯示送出 'dnsmasq 2.41' 代表沒做這步。
# =====================================================================
_NMAP_SERVICE_PREFIXES = {
    "domain", "http", "https", "upnp", "dhcps", "dhcp", "tftp", "tftp?",
    "netbios-ns", "netbios", "ssh", "telnet", "ftp", "smtp", "dns", "snmp",
}


def _clean_query_for_search(raw: str) -> str:
    """送進 NVD / RAG 前先清洗：去掉 'unknown'、拆括號但保留內容。
      'MiniUPnP (1.4)' -> 'MiniUPnP 1.4'，'dhcps (unknown)' -> 'dhcps'
    """
    q = raw or ""
    q = re.sub(r"(?i)\bunknown\b", " ", q)
    q = q.replace("(", " ").replace(")", " ")
    q = re.sub(r"\s+", " ", q).strip()
    return q


def _strip_version_for_rag(q: str) -> str:
    """RAG 語意搜尋用：去掉『開頭服務前綴』與『結尾版本號』，只留產品名。
      'MiniUPnP 1.4' -> 'MiniUPnP'，'dnsmasq 2.41' -> 'dnsmasq'，
      'domain dnsmasq 2.41' -> 'dnsmasq'，'D-Link' -> 'D-Link'
    """
    q = (q or "").strip()
    # 先剝掉開頭的服務類型前綴（domain/http/upnp...），至少保留一個詞
    tokens = q.split()
    while tokens and tokens[0].lower().rstrip("?") in _NMAP_SERVICE_PREFIXES:
        if len(tokens) == 1:
            break
        tokens.pop(0)
    q = " ".join(tokens)
    # 再砍掉結尾版本號
    q = re.sub(r"\s+v?\d[\d.]*\s*$", "", q).strip()
    return q


def _split_product_version(query: str):
    """把查詢拆成 (product_name, version) 供 NVD 用。先剝掉服務類型前綴再用版本特徵切。
      'domain dnsmasq 2.41' -> ('dnsmasq','2.41')，'upnp MiniUPnP 1.4' -> ('MiniUPnP','1.4')，
      'lighttpd' -> ('lighttpd','')
    """
    q = (query or "").strip()
    tokens = q.split()
    while tokens and tokens[0].lower().rstrip("?") in _NMAP_SERVICE_PREFIXES:
        if len(tokens) == 1:
            break
        tokens.pop(0)
    q = " ".join(tokens)
    m = re.search(r"^(.*?)\s+(v?\d[\d.]*)\s*$", q)
    if m:
        product_name = m.group(1).strip()
        target_version = m.group(2).strip()
    else:
        product_name = q.strip()
        target_version = ""
    if not product_name:
        product_name = q or query
        target_version = ""
    return product_name, target_version


def ensure_python_package(pkg_name: str, import_name: str = None) -> bool:
    """檢查 Python 套件是否已安裝（僅檢查，不再自動 pip 安裝）。
    套件應在 Dockerfile build 階段裝好；缺失時回 False 並印出明確訊息，
    由呼叫處記錄為失敗，而非 runtime 嘗試安裝（既慢又常失敗）。"""
    import importlib

    try:
        importlib.import_module(import_name or pkg_name)
        return True
    except ImportError:
        log_info.error(
            f"❌ 缺少 Python 套件 `{pkg_name}`（import 名稱: {import_name or pkg_name}）。"
            f"請在 ai/langchain/Dockerfile 的 pip install 清單補上後 rebuild。"
        )
        return False


class PentestToolbox:

    def __init__(self, target_ip: str):
        self.target_ip = target_ip

    @staticmethod
    def ensure_tool_installed(cmd_name) -> bool:
        """檢查 CLI 工具是否存在（僅檢查，不再自動 apt-get 安裝）。
        工具應在 Dockerfile build 階段裝好；缺失時回 False 並印出明確訊息，
        由呼叫處記錄為失敗。shutil.which 只查 PATH，毫秒級、幾乎零成本。"""
        if isinstance(cmd_name, list):
            cmd_name = cmd_name if cmd_name else ""
        elif not isinstance(cmd_name, str):
            cmd_name = str(cmd_name)

        if not cmd_name or shutil.which(cmd_name) is not None:
            return True

        package_name = TOOL_PACKAGE_MAP.get(cmd_name, cmd_name)
        log_info.error(
            f"❌ 系統缺少工具 `{cmd_name}`（對應套件 `{package_name}`）。"
            f"請在 ai/langchain/Dockerfile 的 apt-get install 清單補上後 rebuild。"
        )
        return False

    def nmap_scan_tcp(self, sensitive_ports: set = None) -> list:
        """SOP 第一階段：TCP 全埠快速探測與非敏感埠深度版本偵測"""
        log_info.tool("nmap_scan_tcp")

        if sensitive_ports is None or not isinstance(sensitive_ports, set):
            sensitive_ports = {"80", "443", "8080", "8443"}

        TCP_ports = []

        try:
            log_info.info(f"正在對目標 {self.target_ip} 執行全 TCP 埠 (1-65535) 快速探測...")
            command = [
                "nmap", "-sT", "-p-", "--max-rate", "1000",
                "--host-timeout", "120s", self.target_ip
            ]

            result = subprocess.run(command, capture_output=True, text=True, check=False)
            matches = re.findall(r"(\d+)/tcp\s+([a-zA-Z|]+)\s+([^\n]*)", result.stdout)

            open_ports = []
            for port_str, state, info in matches:
                port_str = str(port_str)
                if state == "open":
                    open_ports.append((port_str, info))

            for port_str, info in open_ports:
                info_clean = info.strip()
                parts = info_clean.split() if info_clean else []

                if isinstance(parts, list) and parts:
                    service_name = ", ".join(parts)
                else:
                    service_name = "http" if port_str in sensitive_ports else "unknown"

                if port_str in sensitive_ports:
                    log_info.info(f"發現敏感 TCP 埠 {port_str} (狀態: open)，已略過自動版本偵測以防當機。")
                    TCP_ports.append({"port": port_str, "service": service_name, "version": "unknown"})
                    continue

                log_info.info(f"正在對非敏感 TCP 埠 {port_str} 進行深度版本偵測...")
                deep_command = [
                    "nmap", "-sT", "-p", port_str, "-sV",
                    "--version-intensity", "5", self.target_ip
                ]

                deep_result = subprocess.run(deep_command, capture_output=True, text=True, check=False)
                deep_match = re.search(rf"{port_str}/tcp\s+open\s+([^\s]+)\s*([^\n]*)", deep_result.stdout)

                if deep_match:
                    service = deep_match.group(1)
                    version_raw = deep_match.group(2).strip()
                    if not version_raw or "service unrecognized" in version_raw.lower():
                        version = "unknown"
                    else:
                        version = version_raw
                else:
                    service = service_name
                    version = "unknown"

                TCP_ports.append({"port": port_str, "service": service, "version": version})
                log_info.info(f"TCP Port {port_str} Open | Service: {service} | Version: {version}")

        except Exception as e:
            log_info.error(f"TCP Port Scan Error: {e}")

        share_memory = util.get_share_memory()
        if "ports" not in share_memory or not isinstance(share_memory["ports"], dict):
            share_memory["ports"] = {"TCP": [], "UDP": []}

        if "TCP" not in share_memory["ports"] or not isinstance(share_memory["ports"]["TCP"], list):
            share_memory["ports"]["TCP"] = []

        for tcp in TCP_ports:
            existing = next((p for p in share_memory["ports"]["TCP"] if p.get("port") == tcp["port"]), None)
            if existing:
                existing["service"] = tcp["service"]
                existing["version"] = tcp["version"]
            else:
                share_memory["ports"]["TCP"].append(tcp)

        util.update_share_memory(share_memory)
        log_info.share_memory(share_memory)
        return TCP_ports

    def nmap_scan_udp(self, sensitive_ports: set = None) -> list:
        """SOP 第一階段：UDP 埠探測 (支援快取機制)"""
        log_info.tool("nmap_scan_udp")

        cached_udp = util.get_udp_cache()
        if cached_udp:
            log_info.info("⚡ [快取命中] 檢測到 data/UDP.json 已有 UDP 掃描紀錄，自動跳過 Nmap 掃描並載入快取！")
            share_memory = util.get_share_memory()
            if "ports" not in share_memory or not isinstance(share_memory["ports"], dict):
                share_memory["ports"] = {"TCP": [], "UDP": []}

            share_memory["ports"]["UDP"] = cached_udp
            util.update_share_memory(share_memory)
            log_info.share_memory(share_memory)
            return cached_udp

        if sensitive_ports is None or not isinstance(sensitive_ports, set):
            sensitive_ports = {"53", "123", "161", "1900"}

        UDP_ports = []

        try:
            log_info.info(f"正在對目標 {self.target_ip} 執行 UDP 埠快速探測...")
            command = [
                "nmap", "-sU", "--top-ports", "100", "--max-rate", "1000",
                "--host-timeout", "120s", self.target_ip
            ]

            result = subprocess.run(command, capture_output=True, text=True, check=False)
            matches = re.findall(r"(\d+)/udp\s+([a-zA-Z|]+)\s+([^\n]*)", result.stdout)

            open_ports = []
            for port_str, state, info in matches:
                port_str = str(port_str)
                if "open" in state:
                    open_ports.append((port_str, info))

            for port_str, info in open_ports:
                info_clean = info.strip()
                parts = info_clean.split() if info_clean else []

                if isinstance(parts, list) and parts:
                    service_name = ", ".join(parts)
                else:
                    service_name = "dns" if port_str == "53" else "unknown"

                if port_str in sensitive_ports:
                    log_info.info(f"發現敏感 UDP 埠 {port_str}，已略過詳細版本探測以防當機。")
                    UDP_ports.append({"port": port_str, "service": service_name, "version": "unknown"})
                    continue

                log_info.info(f"正在對非敏感 UDP 埠 {port_str} 進行深度版本探測...")
                deep_command = [
                    "nmap", "-sU", "-p", port_str, "-sV",
                    "--version-intensity", "5", self.target_ip
                ]

                deep_result = subprocess.run(deep_command, capture_output=True, text=True, check=False)
                deep_match = re.search(rf"{port_str}/udp\s+(?:open|open\|filtered)\s+([^\s]+)\s*([^\n]*)", deep_result.stdout)

                if deep_match:
                    service = deep_match.group(1)
                    version_raw = deep_match.group(2).strip()
                    if not version_raw or "service unrecognized" in version_raw.lower():
                        version = "unknown"
                    else:
                        version = version_raw
                else:
                    service = service_name
                    version = "unknown"

                UDP_ports.append({"port": port_str, "service": service, "version": version})
                log_info.info(f"UDP Port {port_str} Open | Service: {service} | Version: {version}")

        except Exception as e:
            log_info.error(f"UDP Port Scan Error: {e}")

        util.update_udp_cache(UDP_ports)

        share_memory = util.get_share_memory()
        if "ports" not in share_memory or not isinstance(share_memory["ports"], dict):
            share_memory["ports"] = {"TCP": [], "UDP": []}

        share_memory["ports"]["UDP"] = UDP_ports
        util.update_share_memory(share_memory)
        log_info.share_memory(share_memory)

        return UDP_ports

    def analyze_web_page(self, url: str = None) -> str:
        """深度分析目標 Web 頁面 HTML，自動識別 IoT 廠商、設備類型、關鍵頁面與腳本功能"""
        log_info.tool("analyze_web_page")

        if not url or not isinstance(url, str) or not url.strip():
            url = f"http://{self.target_ip}"

        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            if url.startswith("/"):
                url = f"http://{self.target_ip}{url}"
            else:
                url = f"http://{self.target_ip}/{url}"

        share_memory = util.get_share_memory()
        if "analyzed_urls" not in share_memory or not isinstance(share_memory["analyzed_urls"], list):
            share_memory["analyzed_urls"] = []

        if url not in share_memory["analyzed_urls"]:
            share_memory["analyzed_urls"].append(url)
            util.update_share_memory(share_memory)

        if not ensure_python_package("beautifulsoup4", "bs4"):
            return "（錯誤：容器內未安裝 beautifulsoup4，請在 ai/langchain/Dockerfile 的 pip install 補上後 rebuild。此次分析未執行。）"

        from bs4 import BeautifulSoup

        log_info.info(f"正在抓取並分析 Web 頁面內容: {url} ...")

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                html_content = response.read().decode("utf-8", errors="ignore")
                headers = dict(response.info())

                soup = BeautifulSoup(html_content, "html.parser")
                title = soup.title.string.strip() if (soup.title and soup.title.string) else "無標題"

                # =============================================================
                # 🟢【確認存在的端點情報】能走到這裡代表 urlopen 沒拋 4xx/5xx，
                #    也就是這個網址「實測確認存在(非 404)」。記成情報，之後貼給 AI 當依據。
                # =============================================================
                status_code = getattr(response, "status", None) or 200
                _live_rec = {
                    "url": url,
                    "status": status_code,
                    "title": title,
                    "server": headers.get("Server", "Unknown"),
                    "content_type": headers.get("Content-Type", ""),
                    "snippet": re.sub(r"\s+", " ", html_content[:300]).strip(),
                }
                _sm_live = util.get_share_memory()
                _live = _sm_live.get("live_endpoints", [])
                if not isinstance(_live, list):
                    _live = []
                if not any(isinstance(x, dict) and x.get("url") == url for x in _live):
                    _live.append(_live_rec)
                    _sm_live["live_endpoints"] = _live
                    util.update_share_memory(_sm_live)
                    log_info.info(f"   🟢 [確認存在] {url} (HTTP {status_code})")

                forms = []
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "GET").upper()
                    inputs = []
                    for inp in form.find_all(["input", "button", "select", "textarea"]):
                        inp_name = inp.get("name") or inp.get("id")
                        inp_type = inp.get("type", "text")
                        if inp_name:
                            inputs.append({"name": inp_name, "type": inp_type})
                    forms.append({"action": action, "method": method, "inputs": inputs})

                script_sources = [s.get("src") for s in soup.find_all("script") if s.get("src")]
                inline_scripts = "\n".join([s.text for s in soup.find_all("script") if s.text])

                links = [a["href"].strip() for a in soup.find_all("a", href=True)]

                # =============================================================
                # 【端點探勘：挖整頁(含內嵌 JS)】
                # IoT 管理介面的真實端點大多藏在 JavaScript 裡（.cgi / SOAP / 設定 .xml），
                # 不在 <a href>。只靠 <a> 會抓不到東西。這裡用兩條正則掃整個 HTML（含內嵌 JS）：
                #   1) 帶副檔名的端點字串：xxx.cgi / xxx.php / GetDeviceSettings.xml ...
                #   2) 以 '/' 開頭的絕對路徑字串：'/getcfg.php' '/HNAP1/' ...
                # 全是「程式」抽取，不經過 7B，不會被竄改。
                # =============================================================
                blob = html_content + "\n" + inline_scripts
                ext_pages = re.findall(
                    r"""['"]([^'"\s<>]+?\.(?:html?|php|cgi|asp|aspx|jsp|xml|do|json|js))(?:\?[^'"]*)?['"]""",
                    blob, flags=re.IGNORECASE,
                )
                abs_paths = re.findall(r"""['"](/[A-Za-z0-9_\-./]{1,100})['"]""", blob)
                raw_found_pages = ext_pages + abs_paths

                # 保序去重後給 LLM 看（僅供語意分析參考；實際要爬的清單由下方程式解析決定）
                candidate_pages = list(dict.fromkeys(links + raw_found_pages))[:20]

                # =============================================================
                # 📋【情報彙整】把目前為止「實測確認存在(非 404)」與「確認 404」的端點
                #    整理成文字，貼進 prompt 當作 AI 分析的事實依據（跨頁累積的情報）。
                # =============================================================
                _sm_intel = util.get_share_memory()
                _live_all = _sm_intel.get("live_endpoints", []) or []
                _dead_all = _sm_intel.get("dead_endpoints", []) or []
                live_intel = "\n".join(
                    f"  - {x.get('url')} (HTTP {x.get('status')}, title={str(x.get('title',''))[:40]})"
                    for x in _live_all[-25:] if isinstance(x, dict)
                ) or "  (目前尚無確認存在的端點)"
                dead_intel = ", ".join(
                    x.get("url", "") for x in _dead_all[-25:] if isinstance(x, dict)
                ) or "(無)"

                prompt_input = (
                    f"【Web 頁面分析任務】\n"
                    f"目標 URL: {url}\n"
                    f"頁面 Title: {title}\n"
                    f"Server 標頭: {headers.get('Server', 'Unknown')}\n"
                    f"發現表單: {json.dumps(forms, ensure_ascii=False)}\n"
                    f"發現網頁/腳本連結: {candidate_pages}\n"
                    f"引用的外連腳本: {script_sources}\n"
                    f"【已實測確認存在(非 404)的端點情報】(這些是真的回應成功的網址，請以此為事實依據):\n{live_intel}\n"
                    f"【已實測確認不存在(404)的端點】(請勿再建議或推測這些):\n  {dead_intel}\n"
                    f"內嵌 JavaScript 摘要 (前 1000 字): {inline_scripts[:1000]}\n"
                    f"HTML 前 1500 字內容:\n{html_content[:1500]}\n\n"
                    f"請分析以上數據，識別出：\n"
                    f"1. IoT 廠商名稱 (iot_vendor) 與背景說明\n"
                    f"2. 設備種類 (device_type，如 Wireless Router, IP Camera, Gateway)\n"
                    # ⚠️【修正：不再給具體範例檔名】原本這裡寫「如 login_real.htm, wizard_default.htm」，
                    #   7B 會把這兩個範例當成『真的發現的頁面』照抄回來（你看到的假網址就是這樣來的）。
                    #   實際要爬的端點一律由程式從上面『發現網頁/腳本連結』裡挑，不要自己發明檔名。
                    f"3. 可深入調查的網頁頁面 (web_pages_for_deeper_investigation)："
                    f"【只能從上面『發現網頁/腳本連結』清單裡挑，嚴禁自行發明或補上任何未列出的檔名】\n"
                    f"4. 額外備註 (additional_notes，描述 JS 函數的用途與編碼)"
                )

                iot_analysis = {}
                try:
                    from ai.ollama import call_ollama_json
                    from tool_config import IOT_WEB_ANALYSIS_SCHEMA

                    system_web_prompt = (
                        "你是一名資深 IoT 設備 Web 安全分析專家。"
                        "請分析傳入的 HTML、標題與 JavaScript 原始碼，精確識別出設備廠商 (iot_vendor)、設備類型 (device_type)、"
                        "值得深入調查的網頁 URL (web_pages_for_deeper_investigation)，以及腳本功能與額外備註 (additional_notes)。"
                        "輸出格式必須嚴格符合 JSON Schema。"
                        "【嚴格禁令】若無法從 HTML 內容中明確判讀廠商或設備類型，"
                        "請誠實填入 'Unknown'，絕不可以憑空捏造或猜測具體品牌名稱。"
                    )

                    iot_analysis = call_ollama_json(system_web_prompt, prompt_input, IOT_WEB_ANALYSIS_SCHEMA)
                except Exception as le:
                    log_info.warn(f"⚠️ LLM 網頁分析例外，執行啟發式備用解析: {le}")

                if not iot_analysis or not isinstance(iot_analysis, dict) or "iot_vendor" not in iot_analysis:
                    vendor_name = "Unknown Vendor"
                    content_lower = html_content.lower() + " " + title.lower()
                    if "d-link" in content_lower:
                        vendor_name = "D-Link"
                    elif "netgear" in content_lower:
                        vendor_name = "Netgear"
                    elif "tp-link" in content_lower:
                        vendor_name = "TP-Link"
                    elif "cisco" in content_lower:
                        vendor_name = "Cisco"

                    dev_cat = "Networking Device"
                    if "router" in content_lower:
                        dev_cat = "Wireless Router"
                    elif "camera" in content_lower:
                        dev_cat = "IP Camera"

                    investigate_pages = [{"url": p, "description": "自動探測發現的潛在端點"} for p in candidate_pages[:5]]

                    iot_analysis = {
                        "iot_vendor": {"name": vendor_name, "description": f"{vendor_name} 網路通訊設備製造商"},
                        "device_type": {"category": dev_cat, "description": f"由 {vendor_name} 生產的 {dev_cat} 網頁管理介面"},
                        "web_pages_for_deeper_investigation": investigate_pages,
                        "additional_notes": {
                            "script_functionality": "含前端認證、重定向或 XML 設定腳本",
                            "charset": headers.get("Content-Type", "UTF-8")
                        }
                    }

                # =============================================================
                # ⚠️【端點清單由「程式」決定，不信任 LLM 複述的 URL】
                # 問題：7B 會把原始相對連結 'EULA.html' 幻覺成 '/EULA.html'（擅自加斜線），
                #       破壞相對路徑資訊 → urljoin 再怎麼對也會解析成根目錄 → 404。
                # 原則：URL 是「事實」，要由程式忠實抽取（a[href]、表單 action、正則），
                #       各自以「當前頁 url」為基準用 urljoin 解析。LLM 只負責語意（廠商/類型/備註），
                #       它的 URL 不採用，只拿它的『描述』去標註程式抽到的真實連結。
                # 相對路徑規則（與 IoT 無關，是 HTML 標準）：
                #   'EULA.html'       → http://IP/info/EULA.html   (相對同目錄)
                #   '/IndexHome.html' → http://IP/IndexHome.html   (根相對，前面有 /)
                #   'http://other/'   → 跨主機，直接丟棄
                # =============================================================
                base_host = urlparse(url).netloc

                def _is_crawlable(abs_url: str) -> bool:
                    if not abs_url.startswith(("http://", "https://")):
                        return False
                    if urlparse(abs_url).netloc != base_host:   # 跨主機（如 shareport.local）丟棄
                        return False
                    path_low = abs_url.lower().split("?")[0].split("#")[0]
                    # 排除靜態資源，只留值得爬的頁面/腳本端點
                    if path_low.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
                                          ".ico", ".svg", ".woff", ".woff2", ".ttf", ".map")):
                        return False
                    return True

                # 程式忠實抽出的原始連結（可信來源）：a[href] + 正則掃到的頁面 + 表單 action
                raw_link_strings = list(links) + list(raw_found_pages)
                for f in forms:
                    act = (f.get("action") or "").strip()
                    if act:
                        raw_link_strings.append(act)

                program_resolved = []
                seen_abs = set()
                for rl in raw_link_strings:
                    rl = (rl or "").strip()
                    if not rl or rl.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                        continue
                    abs_url = urljoin(url, rl).split("#")[0]   # base = 當前正在分析的頁面
                    if not _is_crawlable(abs_url) or abs_url in seen_abs:
                        continue
                    seen_abs.add(abs_url)
                    if rl != abs_url:
                        log_info.info(f"   🔗 [相對網址解析] 以 {url} 為基準：'{rl}' → {abs_url}")
                    program_resolved.append(abs_url)

                # LLM 的 URL 不採用（會幻覺），只把它的「描述」依解析後網址比對、貼到真實連結上
                llm_desc_by_url = {}
                for item in (iot_analysis.get("web_pages_for_deeper_investigation") or []):
                    if isinstance(item, dict):
                        lu = urljoin(url, (item.get("url") or "").strip()).split("#")[0]
                        if lu:
                            llm_desc_by_url[lu] = item.get("description", "")

                resolved_invest = [
                    {"url": au, "description": llm_desc_by_url.get(au, "程式自連結抽取發現的端點")}
                    for au in program_resolved
                ]
                iot_analysis["web_pages_for_deeper_investigation"] = resolved_invest

                web_info = {
                    "target_url": url,
                    "title": title,
                    "server": headers.get("Server", "Unknown"),
                    "iot_vendor": iot_analysis.get("iot_vendor", {}),
                    "device_type": iot_analysis.get("device_type", {}),
                    "web_pages_for_deeper_investigation": iot_analysis.get("web_pages_for_deeper_investigation", []),
                    "additional_notes": iot_analysis.get("additional_notes", {}),
                    "forms": forms,
                    "discovered_endpoints": [p.get("url") if isinstance(p, dict) else str(p) for p in iot_analysis.get("web_pages_for_deeper_investigation", [])]
                }

                share_memory = util.get_share_memory()
                share_memory["web_footprints"] = web_info
                util.update_share_memory(share_memory)
                log_info.share_memory(share_memory)

                pages_summary = ""
                for p in iot_analysis.get("web_pages_for_deeper_investigation", []):
                    if isinstance(p, dict):
                        pages_summary += f"\n  - 網頁 `{p.get('url')}`: {p.get('description')}"

                vendor_obj = iot_analysis.get("iot_vendor", {})
                device_obj = iot_analysis.get("device_type", {})
                notes_obj = iot_analysis.get("additional_notes", {})

                return (
                    f"✅ [IoT Web 分析成功] ({url}):\n"
                    f"【IoT 廠商】: {vendor_obj.get('name', 'Unknown')} ({vendor_obj.get('description', '')})\n"
                    f"【設備類型】: {device_obj.get('category', 'Unknown')} ({device_obj.get('description', '')})\n"
                    f"【可深入調查的網頁】: {pages_summary if pages_summary else '無特殊頁面'}\n"
                    f"【額外備註 / JS 功能】: {notes_obj.get('script_functionality', '無')}\n"
                    f"（結構化數據已寫入 share_memory 的 web_footprints 區塊！）"
                )

        except Exception as e:
            # 🔴 記錄「確認不存在(404)」的端點，當作反向情報貼給 AI（叫它別再建議這些）
            code = getattr(e, "code", None)
            if code == 404:
                _sm_dead = util.get_share_memory()
                _dead = _sm_dead.get("dead_endpoints", [])
                if not isinstance(_dead, list):
                    _dead = []
                if url not in [d.get("url") for d in _dead if isinstance(d, dict)]:
                    _dead.append({"url": url, "status": 404})
                    _sm_dead["dead_endpoints"] = _dead
                    util.update_share_memory(_sm_dead)
                    log_info.info(f"   🔴 [確認 404] {url}（已記入反向情報）")
            err_msg = f"❌ 分析網頁 {url} 失敗: {e}"
            log_info.error(err_msg)
            return err_msg

    def rag_search_cve(self, query: str = "") -> str:
        """⚠️【修正重點】RAG 向量搜尋：透過 HTTP 呼叫獨立 RAG 容器的 Flask API，
        而非本地 import RAG_search.py（因為 RAG 在不同容器，跨容器無法用檔案系統
        或 Python import 存取，只能透過網路呼叫其暴露的 /search endpoint）。
        """
        log_info.tool("rag_search_cve")
        raw_query = query.strip() if isinstance(query, str) else str(query)
        if not raw_query:
            return "（提示：請提供搜尋關鍵字，例如 'dnsmasq 2.41'）"

        # ⚠️ RAG 語意搜尋前清洗：去 unknown/括號，並【去掉版本號】——
        #    版本號對向量搜尋是雜訊，帶著 'dnsmasq 2.41' 查會查不到；只送 'dnsmasq' 才命中。
        query = _strip_version_for_rag(_clean_query_for_search(raw_query))
        if not query:
            return f"（RAG 查詢 `{raw_query}` 清洗後為空，略過。）"
        if query != raw_query:
            log_info.info(f"🧹 [RAG 查詢清洗] `{raw_query}` -> `{query}`（已去版本號）")
        log_info.info(f"🔎 [RAG 查詢字串] 實際送出: `{query}`")

        share_memory = util.get_share_memory()

        if "searched_rag_queries" not in share_memory or not isinstance(share_memory["searched_rag_queries"], list):
            share_memory["searched_rag_queries"] = []

        if query.lower() in [q.lower() for q in share_memory["searched_rag_queries"]]:
            log_info.warn(f"⚠️ [防無窮迴圈機制] 攔截重複的 RAG 查詢 `{query}`")
            existing_cves = share_memory.get("cves", [])
            return (
                f"⚡ [防重複檢索機制觸發] 系統檢測到你已經於先前對 `{query}` 執行過 RAG 漏洞檢索！\n"
                f"相關 CVE 及其完整 PoC 內容已存於 share_memory['cves'] (目前共 {len(existing_cves)} 筆)。\n"
                "🛑 【硬性要求】：請勿重複檢索，請直接發起 Web 頁面分析 (analyze_web_page) 或進行 PoC 指令驗證 (execute_cli)。"
            )

        log_info.info(f"🌐 正在透過 HTTP 向 RAG 容器 ({RAG_SERVICE_URL}) 發送查詢請求: `{query}` ...")

        try:
            resp = requests.post(
                RAG_SERVICE_URL,
                json={"query": query},
                timeout=RAG_SERVICE_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            err = (
                f"❌ [RAG Container 連線失敗]: 無法連線至 {RAG_SERVICE_URL}。"
                f"請確認 RAG 容器是否已啟動，且與本容器在同一個 docker network 下"
                f"（檢查 docker-compose.yml 的 service name 與 RAG_SERVICE_URL 環境變數是否一致）。原始錯誤: {e}"
            )
            log_info.error(err)
            return err
        except requests.exceptions.Timeout:
            err = f"❌ [RAG Container 逾時]: 查詢 `{query}` 超過 {RAG_SERVICE_TIMEOUT} 秒未回應。"
            log_info.error(err)
            return err
        except Exception as e:
            err = f"❌ [RAG Container 請求失敗]: {e}"
            log_info.error(err)
            return err

        if resp.status_code != 200:
            err = f"❌ [RAG Container 回應異常]: HTTP {resp.status_code} - {resp.text[:300]}"
            log_info.error(err)
            return err

        try:
            data = resp.json()
        except Exception as e:
            err = f"❌ [RAG Container 回應解析失敗]: {e}，原始回應: {resp.text[:300]}"
            log_info.error(err)
            return err

        if "error" in data:
            err = f"❌ [RAG Container 執行錯誤]: {data['error']}"
            log_info.error(err)
            return err

        results = data.get("result", [])
        if not isinstance(results, list):
            log_info.warn(f"⚠️ [RAG Container 回應格式異常] result 非 list 型態: {type(results)}")
            results = []

        try:
            share_memory["searched_rag_queries"].append(query)

            if "cves" not in share_memory or not isinstance(share_memory["cves"], list):
                share_memory["cves"] = []

            existing_ids = {item.get("cve_id") or item.get("cveID") for item in share_memory["cves"] if isinstance(item, dict)}
            new_cve_count = 0
            for item in results:
                if not isinstance(item, dict):
                    continue
                c_id = item.get("cve_id") or item.get("cveID")
                if c_id and c_id not in existing_ids:
                    share_memory["cves"].append(item)
                    existing_ids.add(c_id)
                    new_cve_count += 1

            if "task_tree" in share_memory and isinstance(share_memory["task_tree"], dict):
                try:
                    from ai.task_tree import PentestTaskTree, TaskStatus, TaskType
                    tree = PentestTaskTree.from_dict(share_memory["task_tree"])
                    parent_node_id = tree.root_ids[0] if len(tree.root_ids) > 0 else None

                    sub_node = tree.add_task(
                        title=f"RAG 漏洞檢索與 PoC 提取: {query}",
                        parent_id=parent_node_id,
                        task_type=TaskType.VULN_SCAN,
                        description=f"對 {query} 進行向量搜尋並直接提取完整 PoC 腳本"
                    )

                    tree.update_task_status(
                        node_id=sub_node.node_id,
                        status=TaskStatus.COMPLETED,
                        result=f"找到 {len(results)} 筆匹配 CVE 完整資料 (新增 {new_cve_count} 筆)"
                    )

                    share_memory["task_tree"] = tree.to_dict()
                except Exception as te:
                    log_info.error(f"❌ [Task Tree 同步失敗]: {te}")

            util.update_share_memory(share_memory)
            log_info.share_memory(share_memory)

            if not results:
                return f"（RAG 搜尋結果：資料庫中未找到與 `{query}` 相關的 CVE 漏洞。此查詢已紀錄，請勿重複搜尋。）"

            return json.dumps(results, indent=2, ensure_ascii=False)

        except Exception as e:
            err = f"❌ [RAG 結果處理失敗]: {e}"
            log_info.error(err)
            return err

    def nvd_search_cve(self, query: str = "") -> str:
        """線上 NVD API 查詢工具"""
        log_info.tool("nvd_search_cve")
        query = query.strip() if isinstance(query, str) else str(query)
        if not query:
            return "（提示：請提供搜尋關鍵字，例如 'dnsmasq 2.41'）"

        # ⚠️ NVD 需要版本號：先清洗，再拆服務前綴/產品/版本
        raw_query = query
        query = _clean_query_for_search(query)
        if query != raw_query:
            log_info.info(f"🧹 [NVD 查詢清洗] `{raw_query}` -> `{query}`")

        product_name, target_version = _split_product_version(query)

        # version 拆不出 → 跳過 NVD（只用產品名會撈到海量不相關結果）
        if not target_version:
            log_info.info(f"⏭️ [NVD 跳過] 查詢 `{query}` 無明確版本號（product='{product_name}'），跳過以免撈到大量不相關結果。")
            return f"（NVD 跳過：`{query}` 無明確版本號，未查詢。）"

        try:
            from get_nvd import convert_to_markdown, get_vulnerability_data
        except ImportError:
            try:
                from ai.langchain.get_nvd import convert_to_markdown, get_vulnerability_data
            except ImportError:
                return "（錯誤：無法載入 get_nvd 模組）"

        try:
            log_info.info(f"🌐 透過 NVD 線上 API 查詢 -> {product_name} ({target_version})...")
            vuln_results = get_vulnerability_data(product_name, target_version)

            if vuln_results:
                share_memory = util.get_share_memory()
                if "cves" not in share_memory or not isinstance(share_memory["cves"], list):
                    share_memory["cves"] = []

                existing_ids = {item.get("cveID") or item.get("cve_id") for item in share_memory["cves"] if isinstance(item, dict)}

                for item in vuln_results:
                    cve_id = item.get("cveID") or item.get("cve_id")
                    if cve_id and cve_id not in existing_ids:
                        cvss_data = item.get("cvss", {})
                        score = cvss_data.get("score", "N/A") if isinstance(cvss_data, dict) else item.get("score", "N/A")
                        severity = cvss_data.get("severity", "UNKNOWN") if isinstance(cvss_data, dict) else item.get("severity", "UNKNOWN")

                        share_memory["cves"].append({
                            "cve_id": cve_id,
                            "service": product_name,
                            "version": target_version,
                            "score": str(score),
                            "severity": str(severity),
                            "description": item.get("description", ""),
                            "source": "NVD API"
                        })
                        existing_ids.add(cve_id)

                util.update_share_memory(share_memory)
                log_info.share_memory(share_memory)

            return convert_to_markdown(vuln_results, product_name, target_version)

        except Exception as e:
            err = f"❌ [NVD Search 失敗]: {e}"
            log_info.error(err)
            return err

    def execute_cli(self, command, timeout: int = 120) -> str:
        """執行 Linux CLI 滲透指令。執行前檢查工具是否存在（不自動安裝）。"""
        log_info.tool(command)

        if isinstance(command, list):
            command = " ".join(str(x) for x in command)
        elif not isinstance(command, str):
            command = str(command)

        clean_cmd = command.strip()
        parts = clean_cmd.split()
        main_binary = parts[0] if parts else ""

        share_memory = util.get_share_memory()
        if "executed_commands" not in share_memory or not isinstance(share_memory["executed_commands"], list):
            share_memory["executed_commands"] = []

        if clean_cmd and clean_cmd not in share_memory["executed_commands"]:
            share_memory["executed_commands"].append(clean_cmd)
            util.update_share_memory(share_memory)

        if main_binary and main_binary in TOOL_PACKAGE_MAP:
            installed = PentestToolbox.ensure_tool_installed(main_binary)
            if not installed:
                return f"（錯誤：系統缺乏工具 `{main_binary}`，請在 Dockerfile 的 apt-get install 清單補上後 rebuild。此次指令未執行。）"

        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            output = stdout if stdout else stderr

            return output if output else "（指令執行成功，但無文字輸出）"

        except subprocess.TimeoutExpired:
            log_info.warn(f"指令 `{command}` 執行超過 {timeout} 秒超時")
            return f"（錯誤：指令 `{command}` 執行超過 {timeout} 秒超時）"
        except Exception as e:
            log_info.error(f"執行發生例外: {e}")
            return f"（執行發生例外: {e}）"