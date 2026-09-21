import subprocess
import time
import re
import get_nvd
import os
from pathlib import Path
import json
import sys

from config.logging import log_info
import util

class PentestToolbox:
    def __init__(self, target_ip, db_client=None):
        """
        初始化工具箱
        :param target_ip: 要攻擊或掃描的目標 IoT 設備 IP
        :param db_client: MongoDB 的連線實例（選填，之後 main.py 傳進來）
        """
        self.target_ip = target_ip
        self.db = db_client
        self.mapped_cves = []       # 共享記憶體：儲存經 NVD 查詢並篩選後的結構化 CVE 漏洞清單

    # ---------------------------------------------------------------------------------------------------------------------------- #

    def nmap_scan_tcp(self) -> dict:
        """
        執行全埠 (1-65535) TCP 掃描。
        針對 IoT 設備優化：
        1. 自動略過已知敏感或易當機的埠（如 80, 443）。
        2. 對發現的非敏感開放埠進行深度版本探測 (-sV)。
        3. 統一規格：version 若無法辨識則保持空字串 ""。
        """
        log_info.tool("nmap_scan_tcp")

        scan_results = {}

        # 🛡️ Anti-Crash：定義容易當機、需要特別小心處理的敏感埠
        sensitive_ports = {"80", "443", "8080", "8443"}

        try:
            log_info.info(f"正在對目標 {self.target_ip} 執行全 TCP 埠 (1-65535) 快速探測...")
            
            # 第一階段：快速全埠掃描
            command = [
                "nmap",
                "-sT",
                "-p-",
                "--max-rate", "1000",
                "--host-timeout", "120s",
                self.target_ip,
            ]
            
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            stdout = result.stdout
            
            matches = re.findall(r'(\d+)/tcp\s+([a-zA-Z|]+)\s+([^\n]*)', stdout)
            
            open_ports = []
            for port_str, state, info in matches:
                port_str = str(port_str)
                if state == "open":
                    open_ports.append((port_str, info))

            # 第二階段：針對發現的開放埠進行分類處理
            for port_str, info in open_ports:
                
                # 處理敏感埠 (略過詳細版本偵測)
                if port_str in sensitive_ports:
                    log_info.info(f"發現敏感埠 {port_str} (狀態: open)，已略過自動版本偵測以防當機。")
                    scan_results[port_str] = {
                        "name": info.strip().split()[0] if info.strip() else "http",
                        "version": "unknown"
                    }
                    continue

                # 💡 非敏感埠：執行深度版本掃描 (-sV)
                log_info.info(f"正在對非敏感埠 {port_str} 進行深度版本偵測...")
                deep_command = [
                    "nmap",
                    "-sT",
                    "-p", port_str,
                    "-sV",
                    "--version-intensity", "5",  # 適度的版本探測強度
                    self.target_ip,
                ]
                
                deep_result = subprocess.run(deep_command, capture_output=True, text=True, check=False)
                deep_match = re.search(rf'{port_str}/tcp\s+open\s+([^\s]+)\s*([^\n]*)', deep_result.stdout)
                
                if deep_match:
                    service = deep_match.group(1)
                    version_raw = deep_match.group(2).strip()
                    # 如果 version 是 unknown 或者是空白，就轉成空字串
                    version = version_raw if version_raw and "service unrecognized despite returning data" not in version_raw.lower() else "unknown"
                else:
                    parts = info.strip().split(maxsplit=1) if info.strip() else []
                    service = parts[0] if len(parts) > 0 else "unknown"
                    version_raw = parts[1] if len(parts) > 1 else ""
                    version = version_raw if version_raw not in version_raw.lower() else "unknown"

                # 統一寫入格式
                scan_results[port_str] = {
                    "name": service,
                    "version": version
                }
                log_info.info(f"Port {port_str} Open | Service: {service} | Version: {version or 'unknown'}")

        except Exception as e:
            log_info.error(f"All Port Scan Error: {e}")

        return scan_results
    
    def nmap_scan_udp(self, port=None) -> dict:
        """
        逐個 Port 進行 UDP 掃描與版本探測，
        並回傳以 port 為 key 的巢狀字典格式。
        """
        log_info.tool("nmap_scan_udp")

        # 🛡️ 超強防呆處理
        if port is None:
            port_list = ["53", "67", "69", "161", "1900", "5000", "5351"]
        elif isinstance(port, str):
            port_list = [p.strip() for p in port.replace("U:", "").split(",") if p.strip()]
        elif isinstance(port, (list, tuple)):
            port_list = [str(p).replace("U:", "").strip() for p in port if str(p).strip()]
        else:
            log_info.warn(f"收到無效的 port 型態，即將使用預設清單。")
            port_list = ["53", "67", "69", "161", "1900", "5000", "5351"]
            
        folder = Path(util.get_current_folder_path())
        # 快取必須按目標隔離，避免把上一台設備的 UDP 服務誤套到目前目標。
        safe_target = re.sub(r"[^A-Za-z0-9_.-]", "_", str(self.target_ip))
        json_path = folder / "data" / "nmap" / f"udp-{safe_target}.json"
        
        # 讀取現有快取（如果檔案不存在或格式不對則給空字典）
        udp_data = {}
        if json_path.exists():
            try:
                udp_data = util.read_json(json_path) or {}
            except Exception:
                udp_data = {}

        print("UDP Data (現有快取):")
        util.pretty_print_json(udp_data)

        # 濾掉已經存在快取中的 Port
        ports_to_scan = [p for p in port_list if p not in udp_data]
        
        # 💡 先把舊的快取資料載入 scan_results，確保回傳時包含全部歷史資料
        scan_results = udp_data.copy()
        print(f"port: {ports_to_scan}")
        for p in ports_to_scan:
            try:
                log_info.info(f"Scanning UDP Port: {p}")
                command = [
                    "nmap",
                    "-sU",
                    "-p", p,
                    "-sV",
                    "--max-rate", "30",
                    "--max-retries", "1",
                    self.target_ip,
                ]
                
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                
                stdout = result.stdout
                stderr = result.stderr
                
                if stderr.strip():
                    log_info.error(f"Port {p}: {stderr.strip()}")
                
                # 🔍 解析 Nmap 輸出
                match = re.search(rf'{p}/udp\s+([a-zA-Z|]+)\s*([^\n]*)', stdout)
                
                if match:
                    state = match.group(1)
                    if "closed" in state:
                        continue

                    extra = match.group(2).strip()
                    
                    parts = extra.split(maxsplit=1) if extra else []
                    service = parts[0] if len(parts) > 0 else "unknown"
                    version = parts[1] if len(parts) > 1 else "unknown"
                    
                    scan_results[str(p)] = {
                        "name": service,
                        "version": version
                    }
                    log_info.info(f"Port {p} Status: {state} | Service: {service} {version}")
                else:
                    scan_results[str(p)] = {
                        "state": "closed/filtered",
                        "name": "unknown",
                        "version": ""
                    }
                    log_info.info(f"Port {p} 無明確回應 (closed/filtered)")

            except subprocess.TimeoutExpired:
                log_info.error(f"Port {p} Scan Timeout (Longer than 12 Sec), Skip~")
                scan_results[str(p)] = {
                    "state": "timeout/filtered",
                    "name": "unknown",
                    "version": ""
                }
            except Exception as e:
                print(f"Port {p} has Error when Scanning: {str(e)}")
                scan_results[str(p)] = {
                    "state": "error",
                    "name": "unknown",
                    "version": ""
                }

        # 💾 自動將最新的完整結果寫回本機快取
        # 確保資料夾存在
        json_path.parent.mkdir(parents=True, exist_ok=True)
        util.write_json(json_path, scan_results)
        log_info.info(f"Scaning Result is Updated and Stored to {json_path}")

        return scan_results

    def run_nikto(self):
        """Nikto 網頁伺服器版本與潛在漏洞掃描，並自動提煉 Server Banner"""
        log_info.tool(f"run_nikto")
        log_info.info(f"target: {self.target_ip}")

        # 💡 修正 -Pause 語法，並加入 -Tuning b (僅掃描 Banner/版本) 與 -maxtime
        command = [
            "nikto",
            "-h", f"http://{self.target_ip}",
            "-Pause", "1",        # 每次請求間隔 1 秒，保護輕量級 Web Server
            "-Tuning", "b",       # 僅進行 Software Version 識別，大幅減少 Request 數量
            "-maxtime", "60s"     # 限制 Nikto 內部最大執行時間 60 秒
        ]

        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=120
            )
            raw_log = result.stdout
            if result.stderr:
                raw_log += f"\n[Stderr]\n{result.stderr}"

            # 💡 使用正則表達式自動抓取 Nikto 輸出的 Server Banner
            # 匹配範例: "+ Server: lighttpd/1.4.28" 或 "+ Server: Apache/2.4.41"
            banner_match = re.search(
                r"\+\s*Server:\s*([a-zA-Z0-9\-_]+)/([\d\.]+)", raw_log
            )

            extracted_info = ""
            if banner_match:
                product = banner_match.group(1)  # 例如: lighttpd
                version = banner_match.group(2)  # 例如: 1.4.28
                extracted_info = f"\n\n[系統自動解析] 偵測到服務 Banner: Product='{product}', Version='{version}'"
                extracted_info += f"\n建議執行的 NVD 查詢指令: python3 get_nvd.py {product} {version}"

            return raw_log + extracted_info

        except subprocess.TimeoutExpired:
            return "[!] Nikto 掃描因超過時間限制結束，返回部分擷取日誌。"
        except Exception as e:
            return f"[Nikto Error] {str(e)}"

    def run_whatweb(self):
        log_info.tool(f"run_whatweb")
        log_info.info(f"target: {self.target_ip}")

        command = ["whatweb", "-v", f"http://{self.target_ip}"]
        
        try:
            # 2. 執行指令，設定 60 秒逾時保護
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=60
            )
            
            # 檢查是否有正常的輸出
            if result.returncode != 0 and not result.stdout:
                log_info.warn(f"[WhatWeb] 執行發生錯誤或無回應，Return Code: {result.returncode}")
                return {"error": f"whatweb failed with code {result.returncode}", "stderr": result.stderr}

            output_data = result.stdout
            log_info.info(f"[WhatWeb] 探測完畢，成功獲取 {len(output_data)} 字元的情報。")
            
            # 💡 3. 自動清洗 ANSI 顏色碼並萃取 Title (Vendor)
            ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
            clean_text = ansi_escape.sub('', output_data)
            
            title_match = re.search(r"Title\s*:\s*(.+)", clean_text)
            extracted_vendor = title_match.group(1).strip() if title_match else "Unknown"
            
            log_info.info(f"[WhatWeb] 成功萃取目標品牌/標題: {extracted_vendor}")

            # 4. 回傳包含結構化欄位與原始日誌的字典
            return extracted_vendor

        except subprocess.TimeoutExpired:
            log_info.error("[Toolbox 錯誤] WhatWeb 執行逾時（超過 60 秒）")
            return {"error": "whatweb timeout"}
        except Exception as e:
            log_info.error(f"[Toolbox 錯誤] 執行 WhatWeb 時發生未預期的例外: {str(e)}")
            return {"error": str(e)}

    def search_rag_poc(self, query: str) -> str:
        log_info.tool(f"search_rag_poc")
        log_info.info(f"query: {query}")

        try:
            # 透過 docker exec 執行你剛寫好的 RAG 程式
            docker_cmd = [
                "docker", "exec", "-i", "RAG", 
                "python3", "RAG_search.py", query
            ]
            
            result = subprocess.run(
                docker_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return f"RAG Error: {result.stderr.strip()}"
        except Exception as e:
            return f"Failed to execute RAG container: {str(e)}"

    # ---------------------------------------------------------------------------------------------------------------------------- #

    def run_curl(self, path: str = "/", port: int = 80, headers: dict = None, timeout: int = 90) -> dict:
        """
        動態 curl 探測工具：支援自訂 Port、自訂 Header（如 Host Header Injection 攻擊）
        """
        log_info.tool("run_curl")

        # 💡 修改點：將 port 納入 URL 組合中（如果非標準 80/443 埠，curl 會自動帶上）
        # 若你的服務是 HTTPS，也可以在這裡動態切換 http:// 或 https://
        target_url = f"http://{self.target_ip}:{port}{path}"
        
        # 基礎 curl 指令：包含靜默模式、抓取 Header、超時控制
        command = ["curl", "-s", "-i", "--connect-timeout", str(timeout)]

        # 如果 AI 帶了自訂 Headers（例如 Host Header 注入）
        if headers:
            for key, value in headers.items():
                command.extend(["-H", f"{key}: {value}"])

        command.append(target_url)

        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 2)
            raw_output = result.stdout

            # 簡單切分 Header 與 Body 方便分析
            parts = raw_output.split("\r\n\r\n", 1) if "\r\n\r\n" in raw_output else raw_output.split("\n\n", 1)
            response_headers = parts[0]
            response_body = parts[1] if len(parts) > 1 else ""

            # 提取 HTTP 狀態碼
            status_code = "Unknown"
            for line in response_headers.splitlines():
                if line.startswith("HTTP/"):
                    status_code = line.split(" ")[1]
                    break

            return {
                "status": "success",
                "status_code": status_code,
                "headers": response_headers,
                "body_snippet": response_body[:300], # 截取前 300 字避免 Token 爆炸
                "is_sql_error": "sql syntax" in response_body.lower() or "mysql" in response_body.lower()
            }

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": "Curl request timed out."}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def run_nvd_lookup(self, protocol, port, raw_service, raw_version):
        """
        NVD 漏洞自動批次查詢工具
        """
        log_info.tool(f"run_nvd_lookup")
        log_info.info(f"service: {raw_service or 'unknown'}, version: {raw_version or 'unknown'}")
        
        # 1. 智慧分離產品名與版號
        if raw_version and " " in raw_version and not "windows" in raw_version.lower():
            parts = raw_version.split()
            service_name = parts[0]
            version = parts[1]
        else:
            service_name = raw_service
            # 若 raw_version 存在，用正規表達式抓出合法的版號格式
            if raw_version:
                match = re.search(r'(\d+(\.\d+)+[a-zA-Z0-9-]*)', raw_version)
                version = match.group(1) if match else raw_version
            else:
                version = "unknown"

        # 2. 安全取得目標資訊與檢查是否已查詢過
        if hasattr(self, 'shared_memory') and self.shared_memory:
            target_info = self.shared_memory.get("discovered_services", {}).get(protocol, {}).get(port, {})
            if target_info.get("nvd_searched", False):
                return f"⚠️ [System Notification] The NVD query for {protocol.upper()} Port {port} ({service_name}) has already been completed!", []

        # 3. 確保 Toolbox 與共用記憶體的 CVE 清單是同一份
        if hasattr(self, 'shared_memory') and self.shared_memory:
            if "mapped_cves" not in self.shared_memory:
                self.shared_memory["mapped_cves"] = []
            self.mapped_cves = self.shared_memory["mapped_cves"]

        if not service_name or not version:
            return "### [NVD 查詢結果]\n目前沒有任何已發現的服務資產，無法進行 NVD 查詢。", []
        
        product_name = service_name
        target_version = version
        
        if not product_name or target_version.lower() == "unknown" or not target_version.strip():
            return f"### [NVD 查詢略過]\n服務 {product_name} 的版本為未知或空值 ({target_version})，不進行 NVD 查詢。", []
            
        print(f"[Toolbox] 發現未查詢資產 -> {product_name} ({target_version}) 正在連線 NVD...")
        
        all_reports = []
        newly_added_cves = []  # 收集這次呼叫新增加的 CVE 清單

        try:
            vulnerability_list = get_nvd.get_vulnerability_data(product_name, target_version)
            
            output = []
            output.append(f"## 🔍 NVD 漏洞查詢結果: {product_name} ({target_version})")
            
            if not vulnerability_list:
                output.append(f"- 在 NVD 中未發現任何與此版本直接相符的已知 CVE 漏洞。\n")
                all_reports.append("\n".join(output))
            else:
                output.append(f"系統已自動過濾版本不符的雜訊，以下為該產品目前版本確實受影響的漏洞 (共 {len(vulnerability_list)} 個)：\n")
                
                vulnerability_list.sort(key=lambda x: x.get("cvss", {}).get("score", 0.0) or 0.0, reverse=True)

                for idx, item in enumerate(vulnerability_list[:3], start=1):
                    cve_id = item.get("cveID")
                    cvss_info = item.get("cvss", {})
                    score = cvss_info.get("score", 0.0) or 0.0
                    severity = cvss_info.get("severity", "UNKNOWN")
                    cwes = item.get("cwe", [])
                    desc = item.get("description", "無詳細描述。")

                    cve_obj = {
                        "cve_id": cve_id,
                        "service": product_name,
                        "version": target_version,
                        "port": str(port),
                        # "severity": severity,
                        "score": score,
                        # "cvss": score,
                        # "cwes": cwes,
                        # "description": desc,
                        # "summary": desc[:100] + "..." if len(desc) > 100 else desc,
                        "status": "untested"
                    }

                    # 去重並寫入，同時記錄到本次新增清單
                    if not any(e.get("cve_id") == cve_id and str(e.get("port")) == str(port) for e in self.mapped_cves):
                        self.mapped_cves.append(cve_obj)
                        newly_added_cves.append(cve_obj)  # 👈 收集起來
                        log_info.info(f"New CVE Found: {cve_id}")

                    clean_desc = desc.replace("\n", " ")
                    short_desc = (clean_desc[:100] + "...") if len(clean_desc) > 100 else clean_desc
                    cwe_str = f" [CWE: {', '.join(cwes)}]" if cwes else ""
                    
                    output.append(f"- {cve_id} (Score: {score} {severity}){cwe_str}: {short_desc}")

                output.append("")
                all_reports.append("\n".join(output))
                
        except Exception as e:
            all_reports.append(f"### ❌ [NVD 查詢錯誤] 查詢 {product_name} ({target_version}) 時發生異常: {str(e)}")    

        if not all_reports:
            return "### [NVD 查詢結果]\n所有已知服務皆已完成過 NVD 歷史查詢，且目前無新資產資訊。", []
            
        report_str = "\n\n---\n\n".join(all_reports)
        return report_str, newly_added_cves  # 👈 同時回傳字串與本次的 CVE 清單
            
    def run_dirbuster(self):
        """目錄爆破工具"""
        log_info.tool(f"run_dirbuster")
        log_info.info(f"target: {self.target_ip}")

        raw_log = "假設這是 dirb 噴出來的純文字 Log..."
        return raw_log

    def run_exploit_dlink(self):
        """針對 D-Link 模擬韌體的特定 Exploit 攻擊"""
        log_info.tool(f"run_exploit_dlink")
        log_info.info(f"target: {self.target_ip}")

        raw_log = "漏洞利用成功！取得管理者 Shell Log..."
        return raw_log

    def get_local_cve_details(slef, cve_id):
        log_info.tool("get_local_cve_details")
        log_info.info(f"CVE ID: {cve_id}")

        try:
            # 透過 docker exec 執行你剛寫好的 RAG 程式
            docker_cmd = [
                "docker", "exec", "-i", "RAG", 
                "python3", "RAG_search_cve.py", cve_id
            ]
            
            result = subprocess.run(
                docker_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return f"RAG Error: {result.stderr.strip()}"
        except Exception as e:
            return f"Failed to execute RAG container: {str(e)}"

# ─────────────── (測試用) ───────────────
# if __name__ == "__main__":
#     # 在這裡把你的韌體 IP 傳進去
#    my_firmware_ip = "192.168.0.1"
    
#     # 建立工具箱實體
#    toolbox = PentestToolbox(target_ip=my_firmware_ip)
    
#     # 測試執行 Nmap 看看能不能掃到 D-Link 韌體
#    test_result = toolbox.run_RAG_search("Dlink")
    
#    print("\n--- Nmap 掃描 D-Link 韌體的 Raw Log 如下 ---")
#    print(test_result)
