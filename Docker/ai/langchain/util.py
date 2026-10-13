# Docker/ai/langchain/util.py
import json
import os
from pathlib import Path
from typing import Any, Dict, List

def get_current_folder_path() -> Path:
    return Path(__file__).resolve().parent

def read_json(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def write_json(path: Path, data: dict) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        print(f"[❌ 檔案寫入失敗] 路徑 {path} 異常: {e}")
        return False

folder = get_current_folder_path()
share_memory_file = folder / "data" / "share memory" / "share memory.json"
udp_cache_file = folder / "data" / "UDP.json"

def update_share_memory(data: dict):
    write_json(share_memory_file, data)

def get_share_memory() -> dict:
    return read_json(share_memory_file)

def init_share_memory(target_ip: str = "192.168.0.1", force_reset: bool = True) -> dict:
    """
    一開始初始化 / 重置 Share Memory 的結構化基礎狀態
    """
    initial_data = {
        "device_information": {
            "device_type": "IoT Device",
            "target_ip": target_ip,
        },
        "ports": {"TCP": [], "UDP": []},
        "web_footprints": {},
        "searched_rag_queries": [],
        "analyzed_urls": [],
        "executed_commands": [],
        "cves": [],
        "tool_history": [],
        "current_observation": "滲透測試任務啟動。",
    }
    if force_reset or not get_share_memory():
        update_share_memory(initial_data)
        return initial_data
    return get_share_memory()

def get_udp_cache() -> list:
    data = read_json(udp_cache_file)
    if isinstance(data, dict) and "UDP" in data and isinstance(data["UDP"], list):
        return data["UDP"]
    return []

def update_udp_cache(udp_list: list):
    write_json(udp_cache_file, {"UDP": udp_list})

# =====================================================================
# LangChain State & Memory Subsystem (Pentest Memory Wrapper)
# =====================================================================

class LangChainPentestMemory:
    """
    符合 LangChain 記憶體介面規範的滲透測試狀態記憶體管理器 (State Store)。
    封裝 share_memory.json，維護資產、漏洞、工具歷史與 PTT Task Tree 的全域持久化狀態。
    """

    def __init__(self, target_ip: str = "192.168.0.1", reset: bool = True):
        self.target_ip = target_ip
        self.memory_path = share_memory_file
        self.reset_memory(reset=reset)

    def reset_memory(self, reset: bool = True) -> dict:
        return init_share_memory(target_ip=self.target_ip, force_reset=reset)

    def _ensure_init(self):
        init_share_memory(target_ip=self.target_ip, force_reset=False)

    def load_memory_variables(self, inputs: Dict[str, Any] = None) -> Dict[str, Any]:
        """LangChain 標準 BaseMemory 介面：載入當前記憶體狀態變數"""
        data = get_share_memory()
        return {
            "share_memory": data,
            "ports": data.get("ports", {}),
            "web_footprints": data.get("web_footprints", {}),
            "searched_rag_queries": data.get("searched_rag_queries", []),
            "analyzed_urls": data.get("analyzed_urls", []),
            "executed_commands": data.get("executed_commands", []),
            "cves": data.get("cves", []),
            "tool_history": data.get("tool_history", []),
            "current_observation": data.get("current_observation", ""),
        }

    def save_context(self, inputs: Dict[str, Any], outputs: Dict[str, Any]):
        """LangChain 標準 BaseMemory 介面：寫入並更新最新互動上下文"""
        data = get_share_memory()
        if "tool_history" not in data:
            data["tool_history"] = []

        history_entry = {
            "decided_task": inputs.get("decided_task", ""),
            "tool": inputs.get("tool", {}),
            "parsed_summary": outputs.get("summary", ""),
            "extracted_facts": outputs.get("extracted_facts", {}),
            "new_evidence_found": outputs.get("new_evidence_found", False),
        }
        data["tool_history"].append(history_entry)
        data["current_observation"] = f"【上輪執行任務】: {inputs.get('decided_task', '')}\n【提煉摘要】: {outputs.get('summary', '')}"

        update_share_memory(data)

    def clear(self):
        """清空記憶體重置為初始狀態"""
        self.reset_memory(reset=True)
