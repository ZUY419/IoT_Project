import json
from datetime import datetime

class TaskTree:
    def __init__(self):
        self.target = None
        self.status = "initialized"
        self.created_at = datetime.now().isoformat()
        self.stage2_decision_made = False
        
        # 1. 階段閘門管理
        self.stages = {
            "stage1_recon": "todo",          # 資產與服務偵察
            "stage2_cve_mapping": "todo",    # NVD 漏洞查詢與戰術思考
            "stage3_exploit": "todo",        # 漏洞利用
            #"stage4_report": "todo"          # 報告生成
        }
        
        self.scanned_ports = {} 
        self.global_vectors = []
        self.latest_recommended_steps = []

    def update_from_perception(self, current_stage: str, perception_json: dict) -> str:
        self.target = perception_json.get("target", self.target)
        self.latest_recommended_steps = perception_json.get("recommended_next_steps", [])
        
        new_ports = perception_json.get("open_ports", [])
        services_map = perception_json.get("services", {})
        vectors = perception_json.get("potential_attack_vectors", [])
        
        for v in vectors:
            if v not in self.global_vectors:
                self.global_vectors.append(v)

        for port in new_ports:
            port_str = str(port)
            ai_port_info = services_map.get(port_str, {})
            
            if isinstance(ai_port_info, str):
                ai_service, ai_version = ai_port_info, "unknown"
            else:
                ai_service = ai_port_info.get("service", "unknown")
                ai_version = ai_port_info.get("version", "unknown")

            if port_str not in self.scanned_ports:
                self.scanned_ports[port_str] = {
                    "service": ai_service,
                    "version": ai_version,
                    "nvd_searched": False,  
                    "is_exploited": False,
                    "discovered_at": datetime.now().isoformat()
                }
            else:
                current_node = self.scanned_ports[port_str]
                if ai_service != "unknown":
                    current_node["service"] = ai_service
                if current_node.get("version", "unknown") == "unknown" and ai_version != "unknown":
                    current_node["version"] = ai_version

        # 1. 評估閘門狀態
        self._auto_eval_stage_status(current_stage, perception_json)

        # 2. 狀態切換
        next_stage = current_stage
        
        if current_stage == "stage1_recon" and self.stages.get("stage1_recon") == "completed":
            print("\n[+ TaskTree Gate] ⚙️【Stage 1 完工】資產偵察全數完成，推進至 Stage 2 (CVE Mapping & NVD 查詢)")
            self.stages["stage2_cve_mapping"] = "running"
            next_stage = "stage2_cve_mapping"
            
        elif current_stage == "stage2_cve_mapping" and self.stages.get("stage2_cve_mapping") == "completed":
            print("\n[+ TaskTree Gate] ⚙️【Stage 2 完工】CVE 對照與戰術選定完成，推進至 Stage 3 (Exploit)")
            self.stages["stage3_exploit"] = "running"
            next_stage = "stage3_exploit"
            
        return next_stage

    def _auto_eval_stage_status(self, current_stage: str, perception_json: dict):
        # --- Stage 1: 純資產偵察 ---
        if current_stage == "stage1_recon":
            has_ports = len(self.scanned_ports) > 0
            
            all_ports_identified = (
                has_ports and 
                all(
                    info.get("service", "unknown") != "unknown" and 
                    info.get("version", "unknown") != "unknown"
                    for info in self.scanned_ports.values()
                )
            )
            
            # 1. 檢查 AI 是否在 stage1_status 中宣告完成 (例如 is_recon_completed == True)
            stage1_meta = perception_json.get("stage1_status", {})
            ai_meta_completed = False
            if isinstance(stage1_meta, dict):
                ai_meta_completed = stage1_meta.get("is_recon_completed", False) or stage1_meta.get("completed", False)

            # 2. 檢查 recommended_next_steps 是否包含 NONE / FINISH
            steps = perception_json.get("recommended_next_steps", [])
            ai_said_finish = False
            for step in steps:
                # 處理 step 是 dict 或 str 的兩種情況
                action_name = ""
                if isinstance(step, dict):
                    action_name = str(step.get("name", "")).upper()
                else:
                    action_name = str(step).upper()
                    
                if action_name in ["NONE", "FINISH", "STOP", "NO_TOOL", "NEXT_STAGE"]:
                    ai_said_finish = True
                    break

            # 只要滿足任一條件（全部識別、AI屬性宣告完成、或行動給NONE），就允許通關！
            if all_ports_identified or ai_said_finish or ai_meta_completed:
                self.stages["stage1_recon"] = "completed"
        
        # --- Stage 2: CVE Mapping & 戰術評估 ---
        elif current_stage == "stage2_cve_mapping":
            # 1. 檢查 AI 是否已選定目標 CVE (例如 selected_target_cve / recommended_target)
            selected_cve = perception_json.get("selected_target_cve") or perception_json.get("recommended_target")
            
            # 2. 檢查 recommended_next_steps 是否為 NONE 或包含轉向 Exploit 的動作
            steps = perception_json.get("recommended_next_steps", [])
            ai_said_finish = False
            for step in steps:
                action_name = str(step.get("name", "")) if isinstance(step, dict) else str(step)
                if action_name.upper() in ["NONE", "FINISH", "STOP", "NO_TOOL", "NEXT_STAGE", "EXPLOIT"]:
                    ai_said_finish = True
                    break

            # 3. 檢查 AI 是否在 stage2_status 中宣告完成
            stage2_meta = perception_json.get("stage2_status", {})
            ai_meta_completed = False
            if isinstance(stage2_meta, dict):
                ai_meta_completed = stage2_meta.get("is_cve_completed", False) or stage2_meta.get("completed", False)

            # 只要 AI 選定了目標 CVE，或者行動給 NONE/EXPLOIT，就允許進入 Stage 3！
            if selected_cve or ai_said_finish or ai_meta_completed:
                self.stages["stage2_cve_mapping"] = "completed"
