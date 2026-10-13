# Docker/ai/langchain/ai/task_tree.py
from enum import Enum
import json
from typing import Any, Dict, List, Optional
import uuid

class TaskStatus(str, Enum):
    TO_DO = "to_do"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PRUNED = "pruned"  # TDA / EGATS: 自動動態剪枝 (Task Difficulty Index 超限)

class TaskType(str, Enum):
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    REPORT = "report"

def _clean_str_id(val: Any) -> Optional[str]:
    """清洗並收斂變數，確保 ID 必為單一字串，徹底防止 list 類型導致 dict unhashable 錯誤"""
    if val is None:
        return None
    if isinstance(val, list):
        return _clean_str_id(val[0]) if len(val) > 0 else None
    return str(val)

class TaskNode:

    def __init__(
        self,
        node_id: str,
        title: str,
        parent_id: Optional[str] = None,
        task_type: TaskType = TaskType.RECON,
        status: TaskStatus = TaskStatus.TO_DO,
        description: str = "",
        result: str = "",
        attempts_count: int = 0,
        tdi_score: float = 0.0,
        evidence_ids: Optional[List[str]] = None,
    ):
        self.node_id = _clean_str_id(node_id) or str(uuid.uuid4())[:8]
        self.title = str(title)
        self.parent_id = _clean_str_id(parent_id)
        self.task_type = (
            task_type if isinstance(task_type, TaskType) else TaskType(task_type)
        )
        self.status = (
            status if isinstance(status, TaskStatus) else TaskStatus(status)
        )
        self.description = str(description) if description else ""
        self.result = str(result) if result else ""
        self.children_ids: List[str] = []
        
        # PentestGPT v2 TDA & EGATS 欄位
        self.attempts_count = int(attempts_count)
        self.tdi_score = float(tdi_score)  # Task Difficulty Index (0.0 ~ 1.0)
        self.evidence_ids = evidence_ids if isinstance(evidence_ids, list) else []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "title": self.title,
            "parent_id": self.parent_id,
            "task_type": self.task_type.value,
            "status": self.status.value,
            "description": self.description,
            "result": self.result,
            "children_ids": self.children_ids,
            "attempts_count": self.attempts_count,
            "tdi_score": self.tdi_score,
            "evidence_ids": self.evidence_ids,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskNode":
        node = cls(
            node_id=data.get("node_id", str(uuid.uuid4())[:8]),
            title=data.get("title", ""),
            parent_id=data.get("parent_id"),
            task_type=TaskType(data.get("task_type", "recon")),
            status=TaskStatus(data.get("status", "to_do")),
            description=data.get("description", ""),
            result=data.get("result", ""),
            attempts_count=data.get("attempts_count", 0),
            tdi_score=data.get("tdi_score", 0.0),
            evidence_ids=data.get("evidence_ids", []),
        )
        raw_children = data.get("children_ids", [])
        if isinstance(raw_children, list):
            node.children_ids = [_clean_str_id(c) for c in raw_children if _clean_str_id(c)]
        return node

class PentestTaskTree:

    def __init__(self, target_ip: str = ""):
        self.target_ip = target_ip
        self.nodes: Dict[str, TaskNode] = {}
        self.root_ids: List[str] = []
        self._init_default_tree()

    def _init_default_tree(self):
        target_str = f" ({self.target_ip})" if self.target_ip else ""

        node_recon = self.add_task(
            title=f"1. 資產偵察與服務列舉{target_str}",
            task_type=TaskType.RECON,
            description="探測 TCP/UDP 開放埠與 Web 介面結構",
        )

        node_vuln = self.add_task(
            title="2. 漏洞檢索與評估",
            task_type=TaskType.VULN_SCAN,
            description="對已知服務進行 RAG / NVD CVE 與 PoC 查驗",
        )

        node_exploit = self.add_task(
            title="3. 漏洞利用與驗證",
            task_type=TaskType.EXPLOIT,
            description="執行針對性 Payload 或 CLI 命令驗證安全風險",
        )

    def add_task(
        self,
        title: str,
        parent_id: Optional[Any] = None,
        task_type: TaskType = TaskType.RECON,
        description: str = "",
        node_id: Optional[Any] = None,
    ) -> TaskNode:
        clean_node_id = _clean_str_id(node_id) or str(uuid.uuid4())[:8]
        clean_parent_id = _clean_str_id(parent_id)

        node = TaskNode(
            node_id=clean_node_id,
            title=title,
            parent_id=clean_parent_id,
            task_type=task_type,
            status=TaskStatus.TO_DO,
            description=description,
        )

        self.nodes[clean_node_id] = node

        if clean_parent_id and clean_parent_id in self.nodes:
            if clean_node_id not in self.nodes[clean_parent_id].children_ids:
                self.nodes[clean_parent_id].children_ids.append(clean_node_id)
        else:
            if clean_node_id not in self.root_ids:
                self.root_ids.append(clean_node_id)

        return node

    def find_or_add_subtask(self, decided_task: str, stage: int = 1) -> TaskNode:
        """根據 Reasoning 模組的 decided_task 自動在 TaskTree 中搜尋或建立相應的子任務節點"""
        clean_title = decided_task.strip()
        # 尋找是否已有相似或包含標題的節點
        for nid, node in self.nodes.items():
            if node.title.lower() == clean_title.lower() or \
               (len(clean_title) > 6 and clean_title.lower() in node.title.lower()) or \
               (len(node.title) > 6 and node.title.lower() in clean_title.lower()):
                return node

        # 根據階段決定父節點
        parent_id = None
        if stage == 1 and len(self.root_ids) > 0:
            parent_id = self.root_ids[0]
        elif stage == 2 and len(self.root_ids) > 1:
            parent_id = self.root_ids[1]
        elif stage >= 3 and len(self.root_ids) > 2:
            parent_id = self.root_ids[2]
        elif self.root_ids:
            parent_id = self.root_ids[0]

        task_type = TaskType.RECON if stage == 1 else (TaskType.VULN_SCAN if stage == 2 else TaskType.EXPLOIT)
        new_node = self.add_task(title=clean_title, parent_id=parent_id, task_type=task_type)
        return new_node

    def record_attempt(self, node_id: Any, success: bool = True, new_evidence_found: bool = False) -> TaskStatus:
        """
        PentestGPT v2 TDA (Task Difficulty Assessment) 核心機制:
        記錄節點執行嘗試次數與新證據產出。若連續嘗試 >= 2 次且未有新證據產出，自動判定該攻擊路徑無效並進行剪枝 (Pruning)。
        """
        clean_id = _clean_str_id(node_id)
        if not clean_id or clean_id not in self.nodes:
            return TaskStatus.TO_DO

        node = self.nodes[clean_id]
        node.attempts_count += 1

        if new_evidence_found:
            node.tdi_score = max(0.0, node.tdi_score - 0.3)
            if success:
                node.status = TaskStatus.COMPLETED
        else:
            node.tdi_score = min(1.0, node.tdi_score + 0.5)
            # 若嘗試 >= 2 次且沒有產出新證據 -> TDA 自動剪枝
            if node.attempts_count >= 2:
                node.status = TaskStatus.PRUNED
                node.result = f"TDA 動態剪枝: 連續 {node.attempts_count} 次嘗試無新證據 (TDI={node.tdi_score:.2f})"
            elif not success:
                node.status = TaskStatus.FAILED

        return node.status

    def update_task_status(
        self,
        node_id: Any,
        status: TaskStatus,
        result: str = "",
        description: Optional[str] = None,
    ) -> bool:
        clean_id = _clean_str_id(node_id)
        if not clean_id or clean_id not in self.nodes:
            return False

        node = self.nodes[clean_id]
        node.status = (
            status if isinstance(status, TaskStatus) else TaskStatus(status)
        )
        if result:
            node.result = str(result)
        if description is not None:
            node.description = str(description)

        return True

    def render_tree(self) -> str:
        """將 Task Tree 轉為純文字樹狀圖 (含 TDA 剪枝與嘗試統計)"""
        lines = ["=== 【Pentesting Task Tree - EGATS & TDA 樹狀圖】 ==="]

        def _render_node(node_id_val: Any, prefix: str = "", is_last: bool = True):
            clean_id = _clean_str_id(node_id_val)
            if not clean_id:
                return
            node = self.nodes.get(clean_id)
            if not node:
                return

            status_text = {
                TaskStatus.TO_DO: "[To-Do]",
                TaskStatus.IN_PROGRESS: "[In-Progress]",
                TaskStatus.COMPLETED: "[Completed]",
                TaskStatus.FAILED: "[Failed]",
                TaskStatus.PRUNED: "[Pruned / 剪枝避開]",
            }.get(node.status, "[Unknown]")

            branch = "└── " if is_last else "├── "
            attempts_info = f" (嘗試: {node.attempts_count}次, TDI: {node.tdi_score:.1f})" if node.attempts_count > 0 else ""
            line = (
                f"{prefix}{branch}{status_text} (ID: {node.node_id}) {node.title}{attempts_info}"
            )

            if node.result:
                short_res = (
                    node.result[:50] + "..."
                    if len(node.result) > 50
                    else node.result
                )
                line += f" -> 結果: {short_res}"

            lines.append(line)

            child_prefix = prefix + ("    " if is_last else "│   ")
            child_count = len(node.children_ids)
            for idx, child_id in enumerate(node.children_ids):
                _render_node(child_id, child_prefix, idx == child_count - 1)

        root_count = len(self.root_ids)
        for idx, root_id in enumerate(self.root_ids):
            _render_node(root_id, "", idx == root_count - 1)

        return "\n".join(lines)

    def get_egats_candidate_branches(self) -> Dict[str, List[str]]:
        """回傳 EGATS 候選分支視圖，明確標註可執行候選與已剪枝/已完成分支"""
        active_candidates = []
        completed_branches = []
        pruned_branches = []

        for nid, node in self.nodes.items():
            if node.status == TaskStatus.TO_DO:
                active_candidates.append(f"[{node.node_id}] {node.title}")
            elif node.status == TaskStatus.COMPLETED:
                completed_branches.append(f"[{node.node_id}] {node.title}")
            elif node.status in [TaskStatus.PRUNED, TaskStatus.FAILED]:
                pruned_branches.append(f"[{node.node_id}] {node.title} (原因: {node.result})")

        return {
            "active_candidates": active_candidates,
            "completed_branches": completed_branches,
            "pruned_branches": pruned_branches,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "nodes": {nid: node.to_dict() for nid, node in self.nodes.items()},
            "root_ids": [_clean_str_id(r) for r in self.root_ids if _clean_str_id(r)],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PentestTaskTree":
        tree = cls.__new__(cls)
        tree.target_ip = data.get("target_ip", "")
        tree.nodes = {}
        for nid, ndata in data.get("nodes", {}).items():
            clean_nid = _clean_str_id(nid)
            if clean_nid and isinstance(ndata, dict):
                tree.nodes[clean_nid] = TaskNode.from_dict(ndata)
        raw_roots = data.get("root_ids", [])
        if isinstance(raw_roots, list):
            tree.root_ids = [_clean_str_id(r) for r in raw_roots if _clean_str_id(r)]
        else:
            tree.root_ids = []
        return tree
