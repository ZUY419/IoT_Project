import json
import time
import re
from tools import PentestToolbox
from config import get_ollama_client, OLLAMA_MODEL, TARGET_IP
from task_tree import TaskTree  
import logging
from dataclasses import dataclass, field
from prompt import get_stage1_system_prompt, get_stage2_system_prompt, get_stage3_system_prompt
import util
from tool_config import TOOL_DESCRIPTION

ollama_client = get_ollama_client()
logger = logging.getLogger(__name__)

# =============================================================================
# 模組們
# =============================================================================

import json

def ai_parsing_module(raw_log, prior_context="", orchestrator=None):
    """【Stage 1: 感知模組】分析最新 Nmap/掃描日誌，回傳標準化 JSON"""
    print("\n[感知模組 Stage 1] 正在叫 Qwen2.5-Coder 分析最新日誌...")
    
    # 💡 確保安全處理 Dictionary 或 String 格式的 raw_log
    if isinstance(raw_log, (dict, list)):
        formatted_log_str = json.dumps(raw_log, indent=2, ensure_ascii=False)
    else:
        formatted_log_str = str(raw_log)
        
        # 保留原本對傳統 Nmap 文字 Log 的過濾與美化邏輯
        if "PORT STATE SERVICE" in formatted_log_str or "/tcp" in formatted_log_str:
            cleaned_lines = []
            for line in formatted_log_str.split('\n'):
                if "/tcp" in line or "/udp" in line or "PORT" in line:
                    cleaned_lines.append(line.strip())
            if len(cleaned_lines) > 1:
                formatted_log_str = "\n".join(cleaned_lines)
    
    system_prompt = get_stage1_system_prompt(orchestrator)
    user_content = f"""{prior_context}

=== NEW EXECUTED RAW LOG TO ANALYZE ===
{formatted_log_str}"""
    
    return _call_ollama_and_parse_json(system_prompt, user_content, "Stage 1")


def ai_parsing_stage2(raw_log: str, prior_context: str = "") -> dict:
    """
    【Stage 2: 推理模組】
    解析預先排序好的 CVE 報告，進行目標選擇與 RAG 檢索語句生成。
    """
    print("\n[🧠 推理模組 Stage 2] 正在分析 CVE 報告並鎖定利用目標 (PentestGPT Mode)...")
    
    # 1. 載入獨立管理之 System Prompt
    system_prompt = get_stage2_system_prompt()
    
    # 2. 組裝 User Content
    user_content = f"""{prior_context}

=== NVD SEARCHED CVE REPORT TO EVALUATE ===
{raw_log}"""

    # 3. 呼叫 LLM 進行推理並解析 JSON
    parsed_result = _call_ollama_and_parse_json(system_prompt, user_content, "Stage 2 Reasoning")
    
    # 4. 終端機日誌列印
    if parsed_result and parsed_result.get("status") == "success":
        stage2_info = parsed_result.get("stage2_status", {})
        target_cve = stage2_info.get("selected_target_cve", "None")
        reason = stage2_info.get("reason", "No reason provided.")
        rag_query = stage2_info.get("rag_search_query", "None")
        
        print(f"  └─ 🎯 [推理決策] 鎖定目標 CVE: \033[91m{target_cve}\033[0m")
        print(f"  └─ 💡 [決策邏輯]: {reason}")
        print(f"  └─ 🔍 [RAG 檢索指令]: {rag_query}")
    else:
        print("  └─ ⚠️ [推理失敗] 無法產出有效決策，請檢查 LLM 輸出內容。")

    return parsed_result

def ai_parsing_stage3(raw_log, prior_context=""):
    """【Stage 3: 決策生成模組 (Generation)】根據推理結果，生成或決定攻擊 Payload 執行方案"""
    print("\n[生成模組 Stage 3] 正在規劃具體攻擊 Payload 與利用鏈步驟...")
    
    # 這裡如果你有定義 get_stage3_system_prompt，請改用它
    # 目前先用 stage2 或通用範本墊底以防報錯
    try:
        from prompt import get_stage3_system_prompt
        system_prompt = get_stage3_system_prompt()
    except ImportError:
        print("[!] 警告: 未在 prompt.py 找到 get_stage3_system_prompt，暫時借用 Stage 2 模版")
        system_prompt = get_stage2_system_prompt()

    user_content = f"""{prior_context}

=== LAST EXPLOIT EXECUTION RESULT ===
{raw_log}"""
    
    return _call_ollama_and_parse_json(system_prompt, user_content, "Stage 3")

# =============================================================================
# 通用 LLM 呼叫與 JSON 清洗輔助函式
# =============================================================================

def _call_ollama_and_parse_json(system_prompt, user_content, stage_name="LLM"):
    """發送請求給 Ollama，並利用 Regex 強制清洗出合法的 Python dict"""
    raw_reply = ""
    try:
        response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            tools=TOOL_DESCRIPTION,
            options={'temperature': 0.0}
        )
        raw_reply = response['message']['content'].strip()
        
        # 剝離 Markdown Code Block (```json ... ```)
        clean_text = re.sub(r'```json|```', '', raw_reply).strip()
        
        # 擷取 JSON 區塊 { ... }
        match = re.search(r'\{.*\}', clean_text, re.DOTALL)
        clean_json_text = match.group(0) if match else clean_text
        
        # 修復數字 Key 沒有加雙引號的狀況
        clean_json_text = re.sub(r'([{,]\s*)(\d+)(\s*:) ', r'\1"\2"\3 ', clean_json_text)
        
        result = json.loads(clean_json_text)
        return result
        
    except Exception as e:
        print(f"[!] {stage_name} 模組發生未知錯誤: {e}")
        print(f"原始回傳：\n{raw_reply}\n--------------------")
        return {"status": "error", "reason": str(e), "recommended_next_steps": ["NONE"]}

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

        # ==========================================
        # 🧠 跨階段共享記憶體 (結構化白板)
        # ==========================================
        self.shared_memory = {
            "vendor": "",
            "discovered_services": {
                "tcp": {},
                "udp": {}
            }, # 格式: {"80": "lighttpd 1.4.28", "53": "dnsmasq 2.41"}
            "mapped_cves": self.toolbox.mapped_cves,  # 格式: [{"cve": "CVE-2017-14491", "service": "dnsmasq", "cvss": 9.8}]
            "tried_exploits": [],      # 格式: [{"cve": "CVE-2017-14491", "status": "FAILED", "reason": "Connection reset"}]
            "recon_completed": False
        }

    def run_pipeline(self):
        print(f"\n[*] ─── 啟動門戶：IoT 非線性動態流水線 ───")

        current_log = {"tcp": {}, "udp": {}}
        
        # 1. 執行初始資安偵察：掃描 TCP 與 UDP 埠口
        print("[*] 執行初始資安偵察：掃描 TCP 與 UDP 埠口...")
        tcp_results = toolbox.nmap_scan_tcp()
        current_log["tcp"] = tcp_results
        current_log["udp"] = toolbox.nmap_scan_udp()

        self.shared_memory["discovered_services"] = current_log

        # 💡 智慧型自動觸發：如果 TCP 掃描發現了網頁埠 (80, 443 等)，自動執行 Nikto 抓取 Banner
        web_ports_open = any(port in tcp_results for port in ["80", "443", "8080", "8443"])
        if web_ports_open:
            print("\n[+] ⚡️ [自動補償/智慧探針] 偵測到網頁服務埠開放，自動啟動 Nikto 安全探針...")
            log = toolbox.run_nikto()

            print("-" * 80 + " Nikto")
            print(log)
            print("-" * 80)
            
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
                print(f"[+] [記憶體即時同步] Port {target_port} 已順利更新為產品: '{product}', 版本: '{version or '無'}'")
            
            # 💡 3. 【關鍵修正】把更新後的共用記憶體或 Nikto 日誌指定給 current_log
            # 這樣進入 while 迴圈的第一輪決策時，AI 才能讀到最新的 Port 80 狀態！
            current_log["tcp"] = self.shared_memory["discovered_services"]["tcp"]
            print("-" * 80 + " Share Memory")
            util.pretty_print_json(self.shared_memory)
            print("-" * 80)

        if self.shared_memory["discovered_services"]["tcp"].get("80", ""):
            print("-" * 80 + " WhatWeb")
            vendor = toolbox.run_whatweb()
            if vendor:
                self.shared_memory["vendor"] = vendor
            print("-" * 80 + " Share Memory")
            util.pretty_print_json(self.shared_memory)
            print("-" * 80)

        max_turns = 5
        turn = 0
        
        while turn < max_turns:
            turn += 1
            print(f"\n[第 {turn} 輪決策] 當前系統狀態: {self.current_state}")
            
            # 1. ⚡️ 動態組裝「跨階段記憶上下文」送入 AI
            prior_context = self._build_context()
            
            # 2. 根據當前狀態派發給 AI 解析 Log
            if self.current_state == "stage1_recon":
                perception_result = ai_parsing_module(current_log, prior_context, orchestrator=self)
                self._update_stage1_memory(perception_result)
                
            elif self.current_state == "stage2_cve_mapping":
                if "CVE-" not in current_log and "Vulnerabilities" not in current_log:
                    print("  └─ 🔄 [自動補償] 當前 Log 未含 CVE 資料，立即呼叫 RUN_NVD_LOOKUP 實體工具...")
                    current_log = self._execute_tool("RUN_NVD_LOOKUP")
                perception_result = ai_parsing_stage2(current_log, prior_context)
                self._update_stage2_memory(perception_result)
                
            elif self.current_state == "stage3_exploit":
                perception_result = ai_parsing_stage3(current_log, prior_context)
                self._update_stage3_memory(perception_result)

            # 3. 🧠 根據『更新後的記憶』讓 TaskTree 決策狀態轉移
            next_state = self.task_tree.update_from_perception(self.current_state, perception_result)
            
            # 取得 AI 建議的下一步行動
            recommended_action = perception_result.get("recommended_next_steps", ["NONE"])[0]
            
            # 記錄本次決策
            self.stage_results.append(IoTStageResult(
                state=self.current_state,
                action_name=recommended_action,
                raw_log=current_log,
                summary=perception_result.get("analysis_summary", "") 
            ))
            
            # 判斷是否結束
            if recommended_action == "FINISH_ALL" or next_state == "COMPLETED":
                print("[+] 任務樹回報：目標已成功拿下或已無可行路徑，終止 Pipeline。")
                break

            # 4. 🔀 狀態轉移 (在執行下一個工具前，確定當前階段)
            if next_state != self.current_state:
                print(f"[狀態轉移] {self.current_state} ➔ ➔ ➔ {next_state}")
                self.current_state = next_state

            # 5. 🛠️ 執行工具（下一個工具會拿到下一輪需要的 Log）
            print(f"[🛠️ 執行行動] 當前階段: {self.current_state} -> 準備執行工具: {recommended_action}")
            execution_result = self._execute_tool(recommended_action)
            
            print("\n================ [工具執行回傳結果] ================")
            print(execution_result[:500] + ("..." if len(execution_result) > 500 else ""))
            print("==================================================\n")
            
            # 將本次執行的結果交給下一輪
            current_log = execution_result
            util.pretty_print_json(self.shared_memory)

    def _execute_tool(self, action_name: str) -> str:
        print(f"\n觸發工具 (原始輸入): {action_name}")
        action = action_name.get("name")
        arguments = action_name.get("arguments", {})  # 💡 確保安全取得 arguments 字典

        log = ""

        if action == "nmap_scan_udp":
            target_ip = arguments.get("target_ip", "")
            ports = arguments.get("port", "")
            log = toolbox.nmap_scan_udp(target_ip=target_ip, ports=ports)

        elif action == "run_nvd_lookup":
            protocol = arguments.get("protocol")
            port = str(arguments.get("port"))
            raw_service = arguments.get("service_name", "")
            raw_version = arguments.get("version", "")

            # 2. 智慧分離產品名與版號
            # 如果 version 裡面包含了空格（例如 "dnsmasq 2.41"），通常第一個字是產品，後面是版號
            if " " in raw_version and not "windows" in raw_version.lower():
                parts = raw_version.split()
                service_name = parts[0]  # 例如 "dnsmasq"
                if service_name == "":
                    service_name = raw_service
                version = parts[1]       # 例如 "2.41"
            else:
                service_name = raw_service
                # 用 regex 把版本號（如 2.41, 1.4.28）從 raw_version 中獨立抓出來
                match = re.search(r'(\d+(\.\d+)+[a-zA-Z0-9-]*)', raw_version)
                version = match.group(1) if match else raw_version

            # 3. 防呆與查詢
            target_info = self.shared_memory.get("discovered_services", {}).get(protocol, {}).get(port, {})

            if target_info.get("nvd_searched", False):
                log = f"⚠️ [系統提示] {protocol.upper()} Port {port} ({service_name}) 已經完成過 NVD 查詢！"
            else:
                # 呼叫工具
                log = self.toolbox.run_nvd_lookup(service_name, version, port)
                
                # 🛡️ 安全地更新狀態（如果 target_info 存在就直接改它的屬性）
                if target_info:
                    target_info["nvd_searched"] = True
                else:
                    # 如果記憶體結構剛好缺這層，保險起見動態建立並標記
                    if "discovered_services" not in self.shared_memory:
                        self.shared_memory["discovered_services"] = {}
                    if protocol not in self.shared_memory["discovered_services"]:
                        self.shared_memory["discovered_services"][protocol] = {}
                    if port not in self.shared_memory["discovered_services"][protocol]:
                        self.shared_memory["discovered_services"][protocol][port] = {}
                        
                    self.shared_memory["discovered_services"][protocol][port]["nvd_searched"] = True

            print("-" * 80 + " Share Memory")
            util.pretty_print_json(self.shared_memory)
            print("-" * 80)

            # # 1. 取得現有的 CVE 清單
            # current_cves = self.shared_memory.get("mapped_cves", [])

            # # 2. 假設 log 是 toolbox 回傳的結構化清單 (List[dict])
            # # 如果你的 toolbox 回傳的是 Markdown 字串，請先用 regex 提取 CVE ID
            # if isinstance(log, list):
            #     new_cves = log
            # else:
            #     # 簡易處理：若 log 是字串，嘗試從中提取 CVE ID (如果是純字串列表)
            #     import re
            #     found_ids = re.findall(r'(CVE-\d{4}-\d{4,7})', log)
            #     new_cves = [{"cve_id": cid} for cid in found_ids]

            # # 3. 去重邏輯：只加入不在 current_cves 中的項目
            # added_count = 0
            # for new_item in new_cves:
            #     # 統一取出 ID 進行比對
            #     new_id = new_item.get("cve_id") or new_item.get("cveID")
                
            #     # 檢查是否已存在
            #     is_duplicate = any(
            #         (c.get("cve_id") == new_id or c.get("cveID") == new_id) 
            #         for c in current_cves
            #     )
                
            #     if not is_duplicate:
            #         current_cves.append(new_item)
            #         added_count += 1

            # # 4. 更新回 shared_memory
            # self.shared_memory["mapped_cves"] = current_cves
            # print(f"[🛡️ 記憶體管理] 成功過濾重複，本次新增 {added_count} 個 CVE 到 mapped_cves。")

            return log
        
        elif action == "search_rag_poc":
            print("[🔍 實體工具呼叫] 正在向 RAG 資料庫檢索相關漏洞...")
            
            # 💡 直接從 arguments 取得關鍵字
            query = arguments.get("query_keyword", "")
            
            if not query:
                return "Error: 無法取得查詢關鍵字 (query_keyword)"

            # 更新記憶體中的查詢紀錄
            self.shared_memory["rag_query"] = query
            if "mapped_cves" not in self.shared_memory:
                self.shared_memory["mapped_cves"] = []

            # 執行工具
            raw_log = self.toolbox.search_rag_poc(query)
            
            try:
                # 解析並更新 CVE 清單
                cve_list = json.loads(raw_log) if isinstance(raw_log, str) else raw_log
                if isinstance(cve_list, list):
                    added = 0
                    for cve in cve_list:
                        cve_id = cve.get("id") or cve.get("cve_id")
                        if cve_id and not any(item.get("id") == cve_id for item in self.shared_memory["mapped_cves"]):
                            self.shared_memory["mapped_cves"].append(cve)
                            added += 1
                    log = f"成功查詢並整合 {added} 個新漏洞資料。"
                else:
                    log = str(raw_log)
            except Exception as e:
                log = f"解析結果失敗: {str(e)}"
                print(f"[SEARCH RAG POC ERROR] {log}")
            
            return log
        
        else:
            print("ℹ️ [Tool Executor] 當前無須執行實體工具，跳過工具呼叫，直接進入下一輪決策。")
            return "No tool executed."

        print("[+] ⏳ 啟動 IoT 設備冷卻保護，等待 3 秒鐘讓網路連線池復原...")

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

    def _update_stage1_memory(self, perception_result: dict):
        """解析 Stage 1 的 JSON，更新服務與版本記憶（純資產盤點，不涉及 CVE/NVD）"""
        services = perception_result.get("services", {})
        open_ports = perception_result.get("open_ports", [])
        
        # 1. 初始化或取得現有的巢狀結構
        if "discovered_services" not in self.shared_memory:
            self.shared_memory["discovered_services"] = {
                "tcp": {},
                "udp": {}
            }
        
        all_service = self.shared_memory["discovered_services"]

        # 2. 優先處理服務與版本建檔 (支援 "53/tcp" 或純數字)
        for port_protocol, info in services.items():
            if "/" in port_protocol:
                port, protocol = port_protocol.split("/", 1)
            else:
                port = port_protocol
                protocol = "tcp"  # 預設協定防呆

            # 確保該 protocol 分類存在
            if protocol not in all_service:
                all_service[protocol] = {}

            # 取得目前舊資料 (如果有的話) 以便做增量保護
            current_node = all_service[protocol].get(port, {})
            
            service_name = info.get("service", info.get("name", "unknown"))
            service_version = info.get("version", "unknown")

            # 增量覆蓋：只在拿到「非 unknown」且「非 -」的新資訊時覆蓋舊資訊
            final_name = service_name if service_name not in ["unknown", "-"] else current_node.get("name", "unknown")
            final_version = service_version if service_version not in ["unknown", "-"] else current_node.get("version", "unknown")

            all_service[protocol][port] = {
                "name": final_name,
                "version": final_version
            }

        # 3. 確保所有 open_ports 也有基本建檔 (防呆：避免漏掉沒有詳細 service 資訊的 port)
        for p in open_ports:
            p_str = str(p)
            # 預設檢查 tcp，若沒有則補上基本未知節點
            if p_str not in all_service["tcp"] and p_str not in all_service["udp"]:
                all_service["tcp"][p_str] = {
                    "name": "unknown",
                    "version": "unknown"
                }

        self.shared_memory["discovered_services"] = all_service

        # 4. 同步到 TaskTree 的 scanned_ports！
        if hasattr(self, "task_tree"):
            flattened_scanned_ports = {
                "tcp": {},
                "udp": {}
            }
            
            # 遍歷 tcp / udp 外層
            for proto, ports_dict in self.shared_memory["discovered_services"].items():
                # 確保內層 key 存在
                if proto not in flattened_scanned_ports:
                    flattened_scanned_ports[proto] = {}
                    
                # 遍歷內層的 port 與對應的 service 資訊
                for port, info in ports_dict.items():
                    flattened_scanned_ports[proto][port] = {
                        "service": info.get("name", "unknown"),
                        "version": info.get("version", "unknown")
                    }
                    
            self.task_tree.scanned_ports = flattened_scanned_ports

    def _update_stage2_memory(self, perception_result: dict):
        """解析 Stage 2 的 JSON，更新漏洞評估與目標選擇記憶"""
        if not isinstance(perception_result, dict):
            return
        
        stage2_info = perception_result.get("stage2_status", {})
    
        # 1. 保存/更新比對出的 CVE 清單
        matched = stage2_info.get("matched_cves", [])
        if matched:
            self.shared_memory["mapped_cves"] = matched
        
        #2. 存入 Stage 2 最終精選的「當前焦點 CVE」與「推理決策」
        if "selected_target_cve" in stage2_info:
            self.shared_memory["current_target_cve"] = stage2_info.get("selected_target_cve")
            self.shared_memory["target_reasoning"] = stage2_info.get("reason", "")
            self.shared_memory["rag_query"] = stage2_info.get("rag_search_query", "")

    def _update_stage3_memory(self, perception_result: dict):
        """解析 Stage 3 的 JSON，如果 Exploit 失敗，記錄失敗原因"""
        # 假設 Stage 3 回傳攻擊狀態
        exploit_status = perception_result.get("exploit_status", {})
        if exploit_status.get("result") == "FAILED":
            self.shared_memory["tried_exploits"].append({
                "cve": exploit_status.get("targeted_cve"),
                "reason": exploit_status.get("error_message", "Unknown execution error")
            })

    def _save_to_db_and_report(self):
        """最後整合資料庫與生報告的邏輯"""
        # 可以在這裡寫寫入 MongoDB 的 Code
        pass
    
if __name__ == "__main__":
    print("[*] 正在初始化 ai_agent 主程式 ...")
    
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

    # orchestrator._execute_tool({'name': 'run_nvd_lookup', 'arguments': {'protocol': 'tcp', 'port': '53', 'service_name': 'domain', 'version': 'dnsmasq 2.41'}})
    
    print("\n[+] 主程式安全退出。")