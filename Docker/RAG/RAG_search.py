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
import argparse
from datetime import datetime

# --- Configuration ---
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

def load_system():
    """載入 FAISS index 與 metadata"""
    if not INDEX_PATH.exists() or not METADATA_PATH.exists():
        print(f"[!] Error: Index files not found at {VECTOR_DIR}")
        sys.exit(1)
        
    index = faiss.read_index(str(INDEX_PATH))
    with open(METADATA_PATH, "rb") as f:
        metadata = pickle.load(f)
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
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
        else:
            return {"relevant": False, "reason": "Failed to parse JSON output from AI."}
            
    except Exception as e:
        return {"relevant": False, "reason": f"AI error: {str(e)}"}

def search_and_analyze(query, index, metadata, max_ignore=5, max_matches=5):
    """執行向量搜尋與逐筆分析，並回傳完整的 JSON 陣列"""
    # 1. Embedding
    try:
        query_emb = client.embed(model=EMBEDDING_MODEL, input=[query])["embeddings"][0]
        query_emb = np.array([query_emb], dtype="float32")
        faiss.normalize_L2(query_emb)
    except Exception as e:
        print(f"[!] Embedding error: {e}")
        return []

    top_k = max_ignore * max_matches

    # 2. Search
    distances, indices = index.search(query_emb, top_k)
    
    # 3. Process results
    match_cve = []
    ignore_time = {"time": 0, "status": "[IGNORED]"}

    for i in range(top_k):
        # 判斷停止原因
        if ignore_time["time"] >= max_ignore or len(match_cve) >= max_match:
            break

        idx = indices[0][i]
        cve_id = metadata[idx]["cveID"]
        
        found_files = list(CVES_DIR.rglob(f"*{cve_id}*.json"))
        if found_files:
            with open(found_files[0], "r", encoding="utf-8") as f:
                data = json.load(f)
                
                raw_desc = data.get("descriptions", "No description provided.")
                if isinstance(raw_desc, list):
                    raw_desc = " ".join(raw_desc)

                cve_info = {
                    "cveID": cve_id,
                    "description": raw_desc
                }
                
                # AI 分析
                result = analyze_single_cve(query, cve_info)
                
                if result.get("relevant"):
                    # 提取 CWEs
                    cwes = []
                    for problem in data.get("problemTypes", []):
                        desc_dict = problem.get("descriptions", {})
                        if isinstance(desc_dict, dict):
                            cwe_id_val = desc_dict.get("cweID")
                            if cwe_id_val:
                                cwes.append(cwe_id_val)

                    # 從 metrics 提取 CVSS、Score、Severity
                    base_score = ""
                    severity = ""
                    metrics_list = data.get("metrics", [])
                    
                    for item in metrics_list:
                        if isinstance(item, dict):
                            if "baseScore" in item:
                                base_score = item.get("baseScore", "")
                                severity = item.get("baseSeverity", "")
                                break

                    poc_list = data.get("PoC", [])
                    pocs = []
                    for poc in poc_list:
                        poc_content = poc.get("poc", "")
                        if poc_content:
                            pocs.append(poc_content)

                    match_cve.append(
                        {
                            "cve_id": cve_id,
                            "service": "",
                            "version": "",
                            "port": "",
                            "severity": severity,
                            "score": base_score,
                            "cvss": base_score,
                            "cwes": cwes,
                            "description": raw_desc,
                            "PoC": pocs,
                        }
                    )
                    ignore_time["time"] = 0
                else:
                    ignore_time["time"] += 1

    return match_cve

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("query", type=str, help="Search query")
    args = parser.parse_args()

    index, metadata = load_system()

    # 執行搜尋並取得 Python 串列 (List of dicts)
    results = search_and_analyze(args.query, index, metadata)

    # 轉成合法的標準 JSON 字串並輸出
    output_json = json.dumps(results, indent=4, ensure_ascii=False)
    print(output_json)