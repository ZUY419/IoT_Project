# Docker/ai/langchain/ai/__init__.py
"""
PentestGPT v2 — SOP 固定流程版 AI 模組套件
SOP 版不再使用 ReasoningModule / GenerationModule / ParsingModule 這些 class，
流程決策改由 main.py 的固定 for 迴圈控制，7B 只被呼叫做三個局部函式任務：
    - parse_tool_output : 解析工具輸出
    - generate_poc_cmds : 針對單一 CVE 產生驗證指令
    - call_ollama_json  : 底層 LLM JSON 呼叫
"""

from ai.prompt import (
    PARSING_SYSTEM_PROMPT,
    GENERATION_SYSTEM_PROMPT,
    REASONING_SYSTEM_PROMPT,
)
from ai.ollama import call_ollama_json
from ai.parsing import parse_tool_output
from ai.generation import generate_poc_cmds

# task_tree 在 SOP 版非必要，但保留 import 以防其他舊檔引用；若該檔不存在或不需要可自行移除。
try:
    from ai.task_tree import PentestTaskTree, TaskNode, TaskStatus, TaskType  # noqa: F401
    _HAS_TASK_TREE = True
except Exception:
    _HAS_TASK_TREE = False

__all__ = [
    "PARSING_SYSTEM_PROMPT",
    "GENERATION_SYSTEM_PROMPT",
    "REASONING_SYSTEM_PROMPT",
    "call_ollama_json",
    "parse_tool_output",
    "generate_poc_cmds",
]

if _HAS_TASK_TREE:
    __all__ += ["PentestTaskTree", "TaskNode", "TaskStatus", "TaskType"]