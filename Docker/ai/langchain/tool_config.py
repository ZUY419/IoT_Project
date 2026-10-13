# Docker/ai/langchain/tool_config.py

import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from config.logging import log_info

# =====================================================================
# 1. Pydantic 結構化 Schemas (LangChain & Pydantic Standard)
# =====================================================================

class ReasoningResponse(BaseModel):
    thought: str = Field(description="隊長分析全局 PTT 與 Share Memory 的思考過程")
    decided_task: str = Field(description="決定的下一個高階子任務描述")
    stage_completed: bool = Field(default=False, description="當前階段任務是否已全部完成")

class ToolCallArgument(BaseModel):
    cmd: Optional[str] = Field(default="", description="Linux CLI 指令")
    url: Optional[str] = Field(default="", description="目標網址")
    query: Optional[str] = Field(default="", description="搜尋關鍵字")

class ToolCall(BaseModel):
    tool_name: str = Field(description="工具名稱: analyze_web_page, rag_search_cve, nvd_search_cve, execute_cli")
    argument: ToolCallArgument = Field(default_factory=ToolCallArgument, description="工具調用參數")

class GenerationResponse(BaseModel):
    thought: str = Field(description="將子任務轉換為工具/指令的思考推導 (CoT)")
    tool: ToolCall = Field(description="具體工具與參數物件")

class ParsingResponse(BaseModel):
    summary: str = Field(description="從原始 Log 提煉出的 3-5 句精準安全摘要")
    extracted_facts: Dict[str, Any] = Field(default_factory=dict, description="從 Log 提取的結構化資訊 (如 ports, cves, urls)")
    new_evidence_found: bool = Field(default=False, description="本次執行是否發現新的資產、端點或漏洞情報 (供 TDA 剪枝判斷)")
    status: str = Field(default="success", description="執行結果狀態 (success / failed / partial)")

class IoTVendorInfo(BaseModel):
    name: str = Field(description="IoT 設備廠商名稱，例如 D-Link, Netgear")
    description: str = Field(description="廠商背景與說明")

class IoTDeviceCategory(BaseModel):
    category: str = Field(description="設備種類，例如 Wireless Router, IP Camera")
    description: str = Field(description="設備類型的用途說明")

class WebPageInvestigation(BaseModel):
    url: str = Field(description="頁面檔名或 URL，例如 login_real.htm, wizard_default.htm")
    description: str = Field(description="該頁面的用途、轉向機制與潛在攻擊面說明")

class AdditionalNotes(BaseModel):
    script_functionality: Optional[str] = Field(default="", description="頁面中 JavaScript 函數用途 (如 get_login_info, get_settings_xml)")
    charset: Optional[str] = Field(default="UTF-8", description="網頁字元集編碼，如 UTF-8")

class IoTWebAnalysisResponse(BaseModel):
    iot_vendor: IoTVendorInfo
    device_type: IoTDeviceCategory
    web_pages_for_deeper_investigation: List[WebPageInvestigation]
    additional_notes: Optional[AdditionalNotes] = None

# 相容舊版 Dict Schema，供原本 call_ollama_json 呼叫使用
REASONING_RESPONSE_SCHEMA = ReasoningResponse.model_json_schema()
GENERATION_RESPONSE_SCHEMA = GenerationResponse.model_json_schema()
PARSING_RESPONSE_SCHEMA = ParsingResponse.model_json_schema()
IOT_WEB_ANALYSIS_SCHEMA = IoTWebAnalysisResponse.model_json_schema()

# =====================================================================
# 2. LangChain 工具調用分發器 (LangChain Tool Dispatcher)
# =====================================================================

def dispatch_tool(toolbox_instance, tool_name: str, arguments: dict) -> str:
    tool_name = tool_name.strip() if tool_name else ""

    if not tool_name:
        return "（提示：LLM 未指定任何工具名稱）"

    # 使用 Pydantic 模型進行輸入參數驗證，防止類型錯亂
    if isinstance(arguments, dict):
        try:
            validated_arg = ToolCallArgument(**arguments)
        except Exception:
            validated_arg = ToolCallArgument(cmd=str(arguments))
    else:
        validated_arg = ToolCallArgument(cmd=str(arguments))

    if tool_name == "analyze_web_page":
        log_info.info("🛠️ [LangChain Dispatcher] 觸發 analyze_web_page...")
        target_url = validated_arg.url or validated_arg.cmd or ""
        return toolbox_instance.analyze_web_page(target_url)

    elif tool_name == "rag_search_cve":
        log_info.info("🛠️ [LangChain Dispatcher] 觸發 rag_search_cve...")
        target_query = validated_arg.query or validated_arg.cmd or ""
        return toolbox_instance.rag_search_cve(target_query)

    elif tool_name == "nvd_search_cve":
        log_info.info("🛠️ [LangChain Dispatcher] 觸發 nvd_search_cve...")
        target_query = validated_arg.query or validated_arg.cmd or ""
        return toolbox_instance.nvd_search_cve(target_query)

    elif tool_name in ["execute_cli", "command"]:
        cmd_str = validated_arg.cmd or ""
        if not cmd_str:
            return "（提示：未提供具體的 CLI 指令）"
        return toolbox_instance.execute_cli(cmd_str)

    elif tool_name == "nmap_scan_tcp":
        log_info.info("🛠️ [LangChain Dispatcher] 觸發 nmap_scan_tcp...")
        tcp_results = toolbox_instance.nmap_scan_tcp()
        return f"（TCP 掃描完成，已獲取 {len(tcp_results)} 個開放埠，結果已更新至 Share Memory）"

    elif tool_name == "nmap_scan_udp":
        log_info.info("🛠️ [LangChain Dispatcher] 觸發 nmap_scan_udp...")
        udp_results = toolbox_instance.nmap_scan_udp()
        return f"（UDP 掃描完成，已獲取 {len(udp_results)} 個開放埠，結果已更新至 Share Memory）"

    else:
        log_info.warn(f"⚠️ [LangChain Dispatcher] 未知的工具名稱: {tool_name}，嘗試回退至 CLI 命令執行...")
        cmd_str = validated_arg.cmd or str(arguments)
        if cmd_str:
            return toolbox_instance.execute_cli(cmd_str)
        return f"（錯誤：無法識別的工具名稱 `{tool_name}`）"

# =====================================================================
# 3. LangChain Structured Tools 封裝工廠
# =====================================================================

def get_langchain_tools(toolbox_instance) -> List[Any]:
    """
    將 PentestToolbox 方法轉換為 LangChain 官方 StructuredTool 物件
    """
    try:
        from langchain_core.tools import StructuredTool

        tools = [
            StructuredTool.from_function(
                func=toolbox_instance.analyze_web_page,
                name="analyze_web_page",
                description="分析 Web 頁面 HTML、表單欄位、隱藏敏感 URL 與 IoT 資產類型",
            ),
            StructuredTool.from_function(
                func=toolbox_instance.rag_search_cve,
                name="rag_search_cve",
                description="本地 FAISS 向量資料庫檢索 CVE 與 PoC 腳本",
            ),
            StructuredTool.from_function(
                func=toolbox_instance.nvd_search_cve,
                name="nvd_search_cve",
                description="線上 NVD API 查詢最新 CVE 與 CVSS 評分",
            ),
            StructuredTool.from_function(
                func=toolbox_instance.execute_cli,
                name="execute_cli",
                description="執行具體 Linux CLI 滲透測試指令與 PoC 驗證腳本",
            ),
        ]
        return tools
    except ImportError:
        log_info.warn("langchain_core 未安裝，跳過 StructuredTool 封裝")
        return []

from pydantic import BaseModel, Field
from typing import List


# Stage 4：LLM 產生「多條單行驗證指令」用（沒 PoC 時的 fallback）
class PoCCommandsResponse(BaseModel):
    commands: List[str] = Field(default_factory=list, description="針對單一 CVE 的數條驗證指令")


POC_CMDS_SCHEMA = PoCCommandsResponse.model_json_schema()


# Stage 4：有 PoC 時，coder 把 PoC 改寫成「一個可執行檔」用
class PoCFileResponse(BaseModel):
    language: str = Field("", description="python 或 bash")
    filename: str = Field("", description="輸出檔名，例如 poc_CVE-2024-3661.py")
    content: str = Field("", description="完整可執行的檔案內容")
    run_cmd: str = Field("", description="執行指令，例如 python3 poc_xxx.py")


POC_FILE_SCHEMA = PoCFileResponse.model_json_schema()