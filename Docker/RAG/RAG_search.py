import faiss
import numpy as np
import pickle
import ollama
import json
import sys
import re
from pathlib import Path
import textwrap
import os

# --- Configuration ---
# 請確認這些路徑與你的實際目錄結構一致
BASE_DIR = Path(__file__).resolve().parent
VECTOR_DIR = BASE_DIR / "Vector_DB"
CVES_DIR = BASE_DIR / "Data" / "Normalization CVES"
INDEX_PATH = VECTOR_DIR / "cve.index"
METADATA_PATH = VECTOR_DIR / "metadata.pkl"
EMBEDDING_MODEL = "nomic-embed-text-rag-v1"
AI_FILTER_MODEL = "qwen2.5:3b"

max_ignore = 5
max_match = 5

ollama_host = os.getenv("OLLAMA_HOST", "http://RAG-ollama:11434")
client = ollama.Client(host=ollama_host)

def format_text(text, indent_size=4):
    """自動處理多行文字、換行並進行縮排，讓終端機輸出整齊"""
    if isinstance(text, list):
        text = " ".join(text)
    elif not isinstance(text, str):
        text = str(text)
    
    # 清理不必要的換行並合併
    clean_text = text.replace("\n", " ").strip()
    # 自動折行
    return textwrap.indent(clean_text, " " * indent_size)

def load_system():
    """載入 FAISS index 與 metadata"""
    if not INDEX_PATH.exists() or not METADATA_PATH.exists():
        print(f"[!] Error: Index files not found at {VECTOR_DIR}")
        sys.exit(1)
        
    print(f"[+] Loading system files...")
    index = faiss.read_index(str(INDEX_PATH))
    with open(METADATA_PATH, "rb") as f:
        metadata = pickle.load(f)
    print("[+] System loaded successfully.")
    return index, metadata

def analyze_single_cve(query, cve_data):
    """使用 AI 分析 CVE 相關性，強制輸出 JSON"""
    prompt = f"""
    You are a cybersecurity expert.
    User Query: "{query}"
    
    Vulnerability Data:
    {json.dumps(cve_data, indent=2, ensure_ascii=False)}
    
    Task:
    1. Determine if this CVE is relevant to the user query.
    2. Output your answer STRICTLY as a JSON object:
       {{
           "relevant": true,
           "reason": "Why it matches"
       }}
       or
       {{
           "relevant": false,
           "reason": "Why it does not match"
       }}
    3. Do not include any text outside the JSON.
    """
    
    try:
        response = client.chat(model=AI_FILTER_MODEL, messages=[
            {'role': 'system', 'content': 'You are a helpful assistant that outputs only valid JSON.'},
            {'role': 'user', 'content': prompt},
        ])
        
        content = response['message']['content']
        # 嘗試從回應中提取 JSON
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
        else:
            return {"relevant": False, "reason": "Failed to parse JSON output from AI."}
            
    except Exception as e:
        return {"relevant": False, "reason": f"AI error: {str(e)}"}

def search_and_analyze(query, index, metadata, max_ignore=5, max_matches=5):
    """執行向量搜尋與逐筆分析"""
    # 1. Embedding
    try:
        query_emb = client.embed(model=EMBEDDING_MODEL, input=[query])["embeddings"][0]
        query_emb = np.array([query_emb], dtype="float32")
        faiss.normalize_L2(query_emb)
    except Exception as e:
        print(f"[!] Embedding error: {e}")
        return

    top_k = max_ignore * max_matches

    # 2. Search
    distances, indices = index.search(query_emb, top_k)
    
    print(f"\n{'='*60}\n--- Processing Search Results (Top {top_k}) ---\n{'='*60}")
    
    # 3. Process results
    match_cve = []
    ignore_time = {"time": 0, "status": "[IGNORED]"}

    for i in range(top_k):
        # 1. 判斷停止原因
        stop_reason = None
        if ignore_time["time"] >= max_ignore:
            stop_reason = "Reason: Status is IGNORED for five times !"
        elif len(match_cve) >= max_matches:
            stop_reason = "Reason: Already match five CVE !"

        # 2. 如果需要停止，執行統一的輸出與 break
        if stop_reason:
            print(f"\n{'='*60}\n--- Finish for Analysising ---\n{'='*60}")
            print(stop_reason)
            # 使用 ' '.join(match_cve) 可以更漂亮地印出清單，不需寫 for 迴圈
            if match_cve:
                print(f"CVE ID list: {', '.join(match_cve)}")
            else:
                print("No CVEs found for your query.")
            break

        idx = indices[0][i]
        score = distances[0][i]
        cve_id = metadata[idx]["cveID"]
        
        found_files = list(CVES_DIR.rglob(f"*{cve_id}*.json"))
        if found_files:
            with open(found_files[0], "r", encoding="utf-8") as f:
                data = json.load(f)
                
                # 取得描述並確保它是字串
                raw_desc = data.get("descriptions", "No description provided.")
                cve_info = {
                    "cveID": cve_id,
                    "description": raw_desc
                }

                print(f"\n{'-'*30}")
                print(f"Analysis {cve_id} (Score: {score:.4f})")
                print(f"{'-'*30}", end=" ", flush=True)
                
                # AI 分析
                result = analyze_single_cve(query, cve_info)
                
                # 視覺化輸出
                status = "[MATCHED]" if result.get("relevant") else "[IGNORED]"
                print(f"{status}", end=" ")
                if status == "[MATCHED]":
                    match_cve.append(cve_id)
                    ignore_time["time"] = 0
                    print(f"Matching Time = {len(match_cve)}")
                else:
                    ignore_time["time"] += 1
                    print(f"Ignore Time = {ignore_time['time']}", flush=True)

                ignore_time["status"] = status
                print(f"Reason:")
                print(format_text(result.get("reason", "No reason provided.")))
                print(f"Description:")
                print(format_text(raw_desc))
                print("PoC:")
                PoC = data.get("PoC")
                if PoC:
                    for p in PoC:
                        print(format_text(p))
                else:
                    print(format_text("No PoC !"))
        else:
            print(f"\n[!] {cve_id} -> [File not found]")

if __name__ == "__main__":
    index, metadata = load_system()
    
    print("[+] System Ready. Type 'exit' to quit.")
    while True:
        query = input("\nEnter search query: ").strip()
        if query.lower() == 'exit':
            break
        if not query:
            continue
            
        search_and_analyze(query, index, metadata)
