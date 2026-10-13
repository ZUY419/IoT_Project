# AGENTS.md — Agent AI 滲透測試專案開發與執行規範 (Universal Guidelines)

> 本規範依據 **iT 邦幫忙 5 大 Agent 指南體系** 與 **PentestGPT (USENIX Security '24 / PentestGPT v2)** 最佳實踐制定。

---

## 1. 專案基本資訊 (Project Context)

- **專案名稱**：Autonomous Agent AI for Automated IoT Penetration Testing
- **目標**：利用 Agent AI 對 IoT 韌體 (QEMU / FAP 模擬環境) 進行全自動化滲透測試並產出安全報告。
- **技術棧 (Tech Stack)**：
  - **語言與環境**：Python 3.12, Ubuntu 20.04 (FAP / QEMU) + Windows (Ollama GPU)
  - **LLM 框架**：LangChain (LangChain Core, LangChain Community, Pydantic, ChatOllama)
  - **三模組 Agent 架構**：Reasoning Module (隊長戰略) + Generation Module (CoT 命令生成) + Parsing Module (日誌壓縮提煉)
  - **核心檢索與向量庫**：FAISS, Nomic Embed (`nomic-embed-text-rag-v1`), Ollama (`qwen2.5:7b`, `qwen2.5-coder:7b`, `qwen2.5:3b`)

---

## 2. 程式碼風格與架構規範 (Code Style & Standards)

- **Pydantic 強型別驗證**：所有工具輸入/輸出結構必須經由 Pydantic `BaseModel` 定義，嚴禁傳入未驗證的裸 List 或 Dict，防止 `unhashable type: 'list'` 錯誤。
- **LangChain 解耦鏈設計**：
  - Reasoning、Generation 與 Parsing 模組必須維護獨立的 LLM Session / Prompt Context，避免 Context Loss (上下文喪失)。
  - 使用 LangChain `ChatPromptTemplate` 與 `StructuredTool` 規範輸入與輸出契約。
- **例外處理與日誌**：所有外部系統呼叫與 LLM 解析必須包裹於 `try-except` 中，使用 `config.logging.log_info` 記錄標籤化 Log。

---

## 3. 安全規範 (Security & Guardrails)

- **無窮迴圈與重複指令防護 (Overseer Guard)**：
  - 嚴禁對已標記為 `[Completed]` 或 `[Pruned]` 的 PTT 任務重複下達命令。
  - 嚴禁對已執行的關鍵字重複發起 `rag_search_cve` 檢索。
- **平滑降級 (Hard Fallback)**：當檢測到 LLM 嘗試重複呼叫時，系統自動將指令轉譯降級為 Web 頁面結構分析 (`analyze_web_page`) 或 CLI 命令驗證 (`execute_cli`)。

---

## 4. 測試與驗證要求 (Testing Rules)

- **TDA (Task Difficulty Assessment) 反饋**：
  - 每輪工具執行後，Parsing Module 必須判斷 `new_evidence_found` (是否發現新情報)。
  - 若連續嘗試 3 次且 TDI 評估缺乏新證據，自動進行 **`[Pruned]` (動態剪枝)**，強制 Agent 轉向其他潛在攻擊分支。

---

## 5. 特殊規則 (Special Rules)

- **無人干預自動化 (Fully Autonomous)**：Agent 必須能獨立完成 Recon ➔ Exploit ➔ Web Analysis ➔ Verification 循環。
- **機密維護**：不硬編碼 API 金鑰，統一經由 `.env` 或系統環境變數讀取。
