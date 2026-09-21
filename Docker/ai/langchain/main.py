from dataclasses import dataclass, field
import json
import time
import re
import argparse

from tools import PentestToolbox
import util

from config.config import get_ollama_client, OLLAMA_MODEL, TARGET_IP
from config.logging import log_info

from ai_agent.update_memory import _update_stage1_memory, _update_stage2_memory, _update_stage3_memory
from ai_agent.parsing import ai_parsing_module, ai_parsing_stage2, ai_parsing_stage3
from ai_agent.tool_config import TOOL_DESCRIPTION
from ai_agent.task_tree import TaskTree
from ai_agent.call_ollama import _call_ollama_and_parse_json, ask_ollama

folder = util.get_folder()
share_memory_file = folder / "data" / "share memory" / "share memory.json"

# =============================================================================
# 核心資料結構與編排器
# =============================================================================

@dataclass
class IoTStageResult:
    """簡化版：記錄每一動工具執行的結果，最後用來存 MongoDB 與生報告"""
    state: str
    action_name: str       # 例如: "RUN_NMAP", "RUN_NIKTO"
    status: str = "completed" # "completed" 或 "error"
    raw_log: str = ""      # 該工具跑出來的純文字 Log
    summary: str = ""      # AI 對這段 Log 的分析總結 (JSON 裡的描述)

class IoTPipelineOrchestrator:
    def __init__(self, target_ip, toolbox, task_tree):
        self.target_ip = target_ip
        self.toolbox = toolbox
        self.task_tree = task_tree
        self.stage_results = []
        self.current_state = "stage1_recon"

        # update_memory.py 定義的是可重用函式，這裡明確綁定到實例，
        # 避免原本 self._update_* 不存在而在第一輪直接失敗。
        self._update_stage1_memory = lambda result: _update_stage1_memory(self, result)
        self._update_stage2_memory = lambda result: _update_stage2_memory(self, result)
        self._update_stage3_memory = lambda result: _update_stage3_memory(self, result)

        # ==========================================
        # 🧠 跨階段共享記憶體 (結構化白板)
        # ==========================================
        self.shared_memory = {
            "target IP": target_ip,
            "vendor": "",
            "discovered_services": {}, # 格式: {"80": "lighttpd 1.4.28", "53": "dnsmasq 2.41"}
            "mapped_cves": [],  # 格式: [{"cve": "CVE-2017-14491", "service": "dnsmasq", "cvss": 9.8}]
            "tried_exploits": [],      # 格式: [{"cve": "CVE-2017-14491", "status": "FAILED", "reason": "Connection reset"}]
            "recon_completed": False,
            "tool_history": []
        }
        
        util.print_and_write_share_momery(self.shared_memory)

    def run_pipeline(self):
        log_info.info(f"Start Pentesting Pipe Line")

        state1_first = True
        state2_first = True
        state3_first = True

        current_log = {}
    
        max_turns = 200
        turn = 0
        
        while turn < max_turns:
            turn += 1
            log_info.info(f"輪數 {turn}，當前為 {self.current_state} 狀態")
            
            # 1. ⚡️ 動態組裝「跨階段記憶上下文」送入 AI
            prior_context = self._build_context()
            
            # 2. 根據當前狀態派發給 AI 解析 Log
            if self.current_state == "stage1_recon":
                if state1_first:
                    # self.shared_memory = util.get_state_data()
                    # util.print_and_write_share_momery(self.shared_memory)
                    # current_log = "Within the established 'State 1' workflow, Nmap is used to identify specific TCP and UDP ports. Subsequently, the port information obtained via Nmap is utilized to conduct further reconnaissance on the IoT device's web interface using Nikto and WhatWeb. Finally, the identified services and their corresponding versions are used to query the NVD for relevant CVEs (skipping any instances where either the service or the version is 'Unknown'). Please determine the next course of action based on the data stored in shared memory."
                    current_log = self.run_state_1()
                    state1_first = False
                perception_result = ai_parsing_module(current_log, prior_context, orchestrator=self)
                self._update_stage1_memory(perception_result)
                
            elif self.current_state == "stage2_cve_mapping":
                # if "CVE-" not in current_log and "Vulnerabilities" not in current_log:
                #     log_info.info("  └─ 🔄 [自動補償] 當前 Log 未含 CVE 資料，立即呼叫 RUN_NVD_LOOKUP 實體工具...")
                #     current_log = self._execute_tool("RUN_NVD_LOOKUP")
                perception_result = ai_parsing_stage2(current_log, prior_context)
                self._update_stage2_memory(perception_result)
                
            elif self.current_state == "stage3_exploit":
                perception_result = ai_parsing_stage3(current_log, prior_context)
                self._update_stage3_memory(perception_result)

            # 3. 🧠 根據『更新後的記憶』讓 TaskTree 決策狀態轉移
            next_state = self.task_tree.update_from_perception(self.current_state, perception_result)
            
            # 取得 AI 建議的下一步行動
            # 1. 取得建議步驟清單，若沒有則給預設值
            steps = perception_result.get("recommended_next_steps", [])

            # 2. 如果清單有內容，就拿第一個；如果清單是空的，就給 "NONE"
            recommended_action = steps[0] if len(steps) > 0 else {"name": "NONE", "arguments": {}}

            # 💡【新增】擷取並印出 AI 的思考原因 (Reason)
            if isinstance(perception_result, dict):
                # 1. 抓取階段狀態的 Reason (例如 is_recon_completed 的理由)
                stage_status = perception_result.get("stage1_status", {}) # 如果是 stage2/stage3 可以依此類推
                if isinstance(stage_status, dict):
                    stage_reason = stage_status.get("reason", "")
                    if stage_reason:
                        log_info.info(f"  └─ 💡 [階段評估原因] {stage_reason}")

                # 2. 抓取下一步行動的 Reason
                next_steps_reason = perception_result.get("recommended_next_steps_reason", "")
                if next_steps_reason:
                    log_info.info(f"  └─ 🎯 [決策行動原因] {next_steps_reason}")
            
            # 記錄本次決策
            self.stage_results.append(IoTStageResult(
                state=self.current_state,
                action_name=recommended_action,
                raw_log=current_log,
                summary=perception_result.get("analysis_summary", "") 
            ))
            
            # 判斷是否結束
            if recommended_action == "FINISH_ALL" or next_state == "COMPLETED":
                log_info.info("[+] 任務樹回報：目標已成功拿下或已無可行路徑，終止 Pipeline。")
                break

            # 4. 🔀 狀態轉移 (在執行下一個工具前，確定當前階段)
            if next_state != self.current_state:
                log_info.info(f"[狀態轉移] {self.current_state} ➔ ➔ ➔ {next_state}")
                self.current_state = next_state

            # 5. 🛠️ 執行工具（下一個工具會拿到下一輪需要的 Log）
            log_info.info(f"[🛠️ 執行行動] 當前階段: {self.current_state} -> 準備執行工具: {recommended_action}")
            execution_result = self._execute_tool(recommended_action)
            
            # 🛡️【防呆修正】確保 execution_result 永遠是字串，避免 Tuple 串接錯誤
            if isinstance(execution_result, tuple):
                # 如果不小心拿到 tuple，通常第一個元素是 log 字串
                execution_result = str(execution_result[0])
            elif not isinstance(execution_result, str):
                execution_result = str(execution_result)

            log_info.info("================ [工具執行回傳結果] ================")
            log_info.info(execution_result[:500] + ("..." if len(execution_result) > 500 else ""))
            log_info.info("==================================================")
            
            # 將本次執行的結果交給下一輪
            current_log = execution_result

    def _execute_tool(self, action_name: str) -> str:
        if isinstance(action_name, str):
            action = action_name
            arguments = {}
        else:
            action = action_name.get("name", "NONE")
            arguments = action_name.get("arguments", {})

        self.shared_memory = util.read_json(share_memory_file)
        self.shared_memory["tool_history"].append(action_name)

        log = ""

        if action == "nmap_scan_udp":
            target_ip = arguments.get("target_ip", "")
            ports = arguments.get("port", "")
            if ports:
                log = self.toolbox.nmap_scan_udp(port=ports)
            else:
                log = self.toolbox.nmap_scan_udp()

            return log

        elif action == "nmap_scan_tcp":
            log = self.toolbox.nmap_scan_tcp()

            return log

        elif action == "run_nikto":
            log = self.toolbox.run_nikto()
            return log

        elif action == "run_whatweb":
            log = self.toolbox.run_whatweb()
            return log

        elif action == "run_nvd_lookup":
            protocol = arguments.get("protocol", "").lower()
            port = str(arguments.get("port"))
                
            raw_service = arguments.get("service_name", "")
            raw_version = arguments.get("version", "")

            # 💡 依照新的參數順序傳入：protocol, port, raw_service, raw_version
            log, cves = self.toolbox.run_nvd_lookup(protocol, port, raw_service, raw_version)

            # 4. 成功執行後，安全更新共用記憶體狀態
            if hasattr(self, 'shared_memory') and self.shared_memory:
                if "discovered_services" not in self.shared_memory:
                    self.shared_memory["discovered_services"] = {}
                if protocol not in self.shared_memory["discovered_services"]:
                    self.shared_memory["discovered_services"][protocol] = {}
                if port not in self.shared_memory["discovered_services"][protocol]:
                    self.shared_memory["discovered_services"][protocol][port] = {}
                    
                self.shared_memory["discovered_services"][protocol][port]["nvd_searched"] = True
                for cve in cves:
                    self.shared_memory["mapped_cves"].append(cve)
                util.print_and_write_share_momery(self.shared_memory)

            if not log:
                log = "The NVD tool cannot find CVE data."

            return log
        
        elif action == "search_rag_poc":
            query = arguments.get("query", "")
            if not query:
                return "Error: Unable to retrieve query keyword (query)"

            if not self.shared_memory.get("rag_search"):
                self.shared_memory["rag_search"] = []

            self.shared_memory["rag_search"].append(query)
            
            if "mapped_cves" not in self.shared_memory:
                self.shared_memory["mapped_cves"] = []

            raw_log = self.toolbox.search_rag_poc(query)
            
            try:
                cve_list = json.loads(raw_log) if isinstance(raw_log, str) else raw_log
                
                if isinstance(cve_list, list):
                    added = 0
                    for cve in cve_list:
                        # 兼容 id 與 cve_id 兩種命名
                        cve_id = cve.get("id") or cve.get("cve_id")
                        
                        if cve_id:
                            cve["cve_id"] = cve_id
                            
                            # 🛡️ 雙向去重檢查（同時比對 cve_id 與 id，避免與 NVD 重複）
                            is_duplicate = any(
                                item.get("cve_id") == cve_id or item.get("id") == cve_id 
                                for item in self.shared_memory["mapped_cves"]
                            )
                            
                            if not is_duplicate:
                                self.shared_memory["mapped_cves"].append(cve)
                                added += 1
                                
                    log = f"Successfully retrieved and integrated {added} new vulnerability information."
                else:
                    log = str(raw_log)

                util.print_and_write_share_momery(self.shared_memory)

                return log
                    
            except Exception as e:
                log = f"Parsing result failed: {str(e)}"
                log_info.info(f"[SEARCH RAG POC ERROR] {log}")

        elif action == "get_local_cve_details":
            log = self.toolbox.get_local_cve_details("CVE-2025-1000")
            return log

        elif action == "NONE":
            util.print_and_write_share_momery(self.shared_memory)

            return "No tools available, forced transition to the next stage."
        
        else:
            log_info.info("ℹ️ [Tool Executor] 當前無須執行實體工具，跳過工具呼叫，直接進入下一輪決策。")
            return "No tool executed."

        log_info.info("[+] ⏳ 啟動 IoT 設備冷卻保護，等待 3 秒鐘讓網路連線池復原...")

        time.sleep(3)
        return log
    
    def _get_tool_history(self) -> list:
        """從 stage_results 中萃取出所有使用過的工具名稱"""
        return [res.action_name for res in self.stage_results if res.action_name and res.action_name != "NONE"]

    def _build_context(self) -> str:
        """
        將『結構化記憶體』與『已使用工具歷史』轉換為易讀的 Markdown 文字
        """
        context_lines = ["=== SYSTEM SHARED MEMORY (PAST KNOWLEDGE) ==="]
        
        # 1. 注入已確定的服務與版本資訊
        context_lines.append("[Discovered Services & Versions]:")
        context_lines.append("[Discovered Services & Versions]:")
        has_services = False
        
        if self.shared_memory.get("discovered_services"):
            # 外層迴圈：遍歷 tcp / udp
            for proto, ports_dict in self.shared_memory["discovered_services"].items():
                if isinstance(ports_dict, dict) and ports_dict:
                    # 內層迴圈：遍歷每個 Port
                    for port, info in ports_dict.items():
                        has_services = True
                        service_name = info.get('name', 'Unknown')
                        service_version = info.get('version', 'Unknown')
                        context_lines.append(
                            f"  - Port {port}/{proto}: {service_name} "
                            f"(Version: {service_version})"
                        )
                        
        if not has_services:
            context_lines.append("  - No verified services yet.")
            
        # 2. 注入工具使用歷史（對應你的規則 10：ANTI-REPETITION）
        tool_history = self._get_tool_history()
        context_lines.append("\n[Recently Executed Tools / History]:")
        if tool_history:
            # 這裡可以運用前面提過的技巧，只取最近 3 個避免 Prompt 太長，或全數列出
            recent_tools = tool_history[-3:]
            context_lines.append(f"  - Recently used: {recent_tools}")
        else:
            context_lines.append("  - No tools executed yet.")

        # 3. 注入 Stage 2 比對出的 CVE 成果
        if self.shared_memory["mapped_cves"]:
            context_lines.append("\n[Mapped Known Vulnerabilities (CVEs)]:")
            for cve in self.shared_memory["mapped_cves"]:
                context_lines.append(
                    f"  - {cve['cve_id']} on {cve['service']} "
                    f"(CVSS: {cve['score']}) -> {cve.get('description', '')}"
                )

        # 4. 注入失敗的嘗試防呆
        if self.shared_memory["tried_exploits"]:
            context_lines.append("\n[🚨 Warning: Previously Failed Exploits - DO NOT RETRY THESE]:")
            for fail in self.shared_memory["tried_exploits"]:
                context_lines.append(f"  - Exploit {fail['cve']} FAILED. Reason: {fail['reason']}")

        return "\n".join(context_lines)

    def _save_to_db_and_report(self):
        """最後整合資料庫與生報告的邏輯"""
        # 可以在這裡寫寫入 MongoDB 的 Code
        pass
    
    def run_state_1(self):
        log_info.info("State 1 -> Start!")
        log_info.info("Fix Process: Scan TCP and UDP, Run Nitkto and Whatweb, Run NVD to get CVEs")

        # --- TCP & UDP --- #
        tcp_results = self._execute_tool({"name": "nmap_scan_tcp", "arguments": {}})
        udp_results = self._execute_tool({"name": "nmap_scan_udp", "arguments": {}})

        self.shared_memory["discovered_services"]["tcp"] = tcp_results
        self.shared_memory["discovered_services"]["udp"] = udp_results

        util.print_and_write_share_momery(self.shared_memory)

        # --- Nikto ------- #
        isWebOpen = any(port in tcp_results for port in ["80", "443", "8080", "8443"])
        if isWebOpen:
            log_info.info("Web is Open -> Run Nikto...")
            log = self._execute_tool({"name": "run_nikto", "arguments": {}})
            log_info.info("Nikto Log:")
            print(log)
            
            # 1. 動態擷取 Nikto 掃描的實際目標埠號
            port_match = re.search(r"Target Port:\s+(\d+)", log)
            target_port = port_match.group(1) if port_match else "80"
            
            # 2. 即時解析 Nikto 抓到的 Banner 並同步至共用記憶體
            banner_match = re.search(r"\+\s*Server:\s*([^\r\n]+)", log)
            if banner_match:
                server_full = banner_match.group(1).strip() # 例如抓到 "WebServer" 或 "lighttpd/1.4.28"
                
                # 進一步拆解名稱與版本
                if "/" in server_full:
                    product, version = server_full.split("/", 1)
                else:
                    product = server_full
                    version = ""  # 如果沒有版號，就設為空字串，符合我們的統一規格！
                
                # 同步更新共用記憶體
                self.shared_memory["discovered_services"]["tcp"][target_port] = {
                    "name": product,
                    "version": version
                }
                log_info.info(f"Port {target_port} 已順利更新為產品: '{product}', 版本: '{version or '無'}'")
            
            util.print_and_write_share_momery(self.shared_memory)

        # --- WharWeb ----- #
        if self.shared_memory["discovered_services"]["tcp"].get("80", ""):
            vendor = self._execute_tool({"name": "run_whatweb", "arguments": {}})
            if vendor:
                self.shared_memory["vendor"] = vendor
            util.print_and_write_share_momery(self.shared_memory)

        # --- NVD --------- #
        tcp_services = self.shared_memory.get("discovered_services", {}).get("tcp", {})
        for port, data in tcp_services.items():
            service_name = data.get("name")
            version = data.get("version")

            parameters = {
                "name": "run_nvd_lookup",
                "arguments": {
                    "protocol": "tcp",
                    "port": f"{port}",
                    "service_name": f"{service_name}",
                    "version": f"{version}"
                }
            }

            self._execute_tool(parameters)

        # 🛡️ 批次處理 UDP 服務的 NVD 查詢（自動過濾 unknown 版本，避免白跑）
        udp_services = self.shared_memory.get("discovered_services", {}).get("udp", {})
        for port, data in udp_services.items():
            service_name = data.get("name")
            version = data.get("version")

            parameters = {
                "name": "run_nvd_lookup",
                "arguments": {
                    "protocol": "udp",
                    "port": f"{port}",
                    "service_name": f"{service_name}",
                    "version": f"{version}"
                }
            }

            self._execute_tool(parameters)
        return "Within the established 'State 1' workflow, Nmap is used to identify specific TCP and UDP ports. Subsequently, the port information obtained via Nmap is utilized to conduct further reconnaissance on the IoT device's web interface using Nikto and WhatWeb. Finally, the identified services and their corresponding versions are used to query the NVD for relevant CVEs (skipping any instances where either the service or the version is 'Unknown'). Please determine the next course of action based on the data stored in shared memory."

if __name__ == "__main__":
    log_info.info("Agent AI Start Pentest")
    
    # 1. 設定目標 IP (可以寫死或從環境變數拿)
    TARGET_IP = "192.168.0.1" 
    
    # 2. 實體化雙手（工具箱）與記憶（任務樹）
    toolbox = PentestToolbox(target_ip=TARGET_IP)
    task_tree = TaskTree()  
    
    # 3. 將控制權交給流水線編排器
    orchestrator = IoTPipelineOrchestrator(
        target_ip=TARGET_IP, 
        toolbox=toolbox, 
        task_tree=task_tree
    )
    
    # 4. 🚀 啟動全自動智慧滲透流水線
    orchestrator.run_pipeline()
    
    # orchestrator._execute_tool({'name': 'get_local_cve_details', 'arguments': {'protocol': 'udp', 'port': '53', 'service_name': 'domain', 'version': 'Unbound'}})
    
    log_info.info("Agent AI Pentest Finish")