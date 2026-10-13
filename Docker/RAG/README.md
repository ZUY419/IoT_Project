# IoT_Project RAG 搜尋系統

本專案針對 CVE 2024 ~ 2026 年之資料進行清洗與 PoC 爬蟲，並透過 RAG 技術提供關鍵字與 CVE 編號查詢功能。

## 主要工具

- **RAG_search.py**：輸入漏洞描述或關鍵字，輸出相關 CVE 資訊（Description, Reason, PoC）及清單。
  - *範例*：`python3 RAG_search.py "D-Link, dnsmasq 2.41"`
- **RAG_search_cve.py**：輸入 CVE 編號，輸出該漏洞詳細資訊（Description, PoC）。
  - *範例*：`python3 RAG_search_cve.py CVE-2025-1000`

---

## ⚠️ 重要：下載 Vector_DB 資料庫
由於向量資料庫檔案較大（超過 GitHub 上傳限制），請先至下方連結下載 `Vector_DB` 資料夾，並放回專案根目錄下（確保路徑包含 `Vector_DB/cve.index` 與 `Vector_DB/embeddings.npy`），方可正常執行 RAG 搜尋：

👉 [Google 雲端硬碟下載 Vector_DB](https://drive.google.com/drive/folders/15jkDfx1Cg43Z-3262kBIPVSDURchCBhM?dmr=1&ec=wgc-drive-%5Bmodule%5D-goto)

## ⚠️ 重要：下載 Embedding 模型
請至下方連結下載本 RAG 系統所使用的 ollama Embedding 模型：

👉 [Google 雲端硬碟下載 ollama Embedding 模型](https://drive.google.com/drive/folders/1ae-qn3c_W4ZzJn2M3HGlgZpjF_R1CX3z?dmr=1&ec=wgc-drive-%5Bmodule%5D-goto)
