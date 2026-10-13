import os
import json
import pickle
import numpy as np
import faiss
import ollama
from pathlib import Path
from tqdm import tqdm
from dotenv import load_dotenv

# 1. 環境設定
load_dotenv()

# =====================================================
# 路徑與設定
# =====================================================
BASE_DIR = Path(__file__).resolve().parent
CVES_DIR = BASE_DIR / "Data" / "Normalization CVES"  # 確保這是你正規化後的資料夾名稱
VECTOR_DIR = BASE_DIR / "Vector_DB" / "v2"

# 自動建立必要目錄
VECTOR_DIR.mkdir(parents=True, exist_ok=True)

INDEX_PATH = VECTOR_DIR / "cve.index"
METADATA_PATH = VECTOR_DIR / "metadata.pkl"
EMBEDDING_PATH = VECTOR_DIR / "embeddings.npy"
MODEL_INFO_PATH = VECTOR_DIR / "model_info.json"
CHECKPOINT_PATH = VECTOR_DIR / "checkpoint.pkl"

MODEL_NAME = "nomic-embed-text-rag-v1"
BATCH_SIZE = 32

# =====================================================
# 文字轉換邏輯
# =====================================================
def cve_to_text(doc):
    """將正規化後的 JSON 物件轉為 Embedding 用的純文字"""
    # 處理描述
    desc = "\n".join([d for d in doc.get("descriptions", []) if isinstance(d, str)])
    
    # 處理廠商與產品
    vendors = ", ".join(doc.get("vendors", []))
    products = ", ".join(doc.get("products", []))
    
    # 處理 CWE
    cwes = []
    for item in doc.get("problemTypes", []):
        if isinstance(item, dict) and "descriptions" in item:
            cwes.append(item["descriptions"].get("description", ""))
    
    # 處理版本與 CPE
    versions = []
    cpes = []
    for affected in doc.get("affected", []):
        cpes.extend(affected.get("cpes", []))
        for v in affected.get("versions", []):
            if isinstance(v, dict):
                if v.get("version"): versions.append(v["version"])
                if v.get("lessThanOrEqual"): versions.append(f"<= {v['lessThanOrEqual']}")
    
    # 處理 Metrics
    scores = [str(m.get("baseScore", "")) for m in doc.get("metrics", []) if isinstance(m, dict) and "baseScore" in m]
    severity = [m.get("baseSeverity", "") for m in doc.get("metrics", []) if isinstance(m, dict) and "baseSeverity" in m]

    return f"""
CVE ID: {doc.get('cveID', '')}
Description: {desc}
Vendor: {vendors}
Product: {products}
Affected Version: {", ".join(versions)}
CPE: {", ".join(cpes)}
CWE: {", ".join(cwes)}
CVSS Score: {", ".join(scores)}
Severity: {", ".join(severity)}
Tags: {", ".join(doc.get('tags', []))}
""".strip()

# =====================================================
# 主邏輯
# =====================================================
def run_pipeline():
    # 1. 檢查 Checkpoint
    if CHECKPOINT_PATH.exists():
        print("[+] 讀取斷點檔案...")
        with open(CHECKPOINT_PATH, "rb") as f:
            cp = pickle.load(f)
            embeddings = cp["embeddings"]
            metadata = cp["metadata"]
            processed = set(cp["processed"])
        print(f"[+] 恢復進度：已處理 {len(processed)} 筆")
    else:
        embeddings = []
        metadata = []
        processed = set()

    # 2. 取得所有檔案
    all_files = list(CVES_DIR.rglob("*.json"))
    print(f"[+] 找到 {len(all_files)} 個 JSON 檔案")

    texts_batch, docs_batch = [], []
    
    pbar = tqdm(total=len(all_files), desc="Embedding", unit="file")
    
    # 若已有進度，先更新進度條
    pbar.update(len(processed))

    for file_path in all_files:
        # 跳過已處理
        if file_path.name in processed:
            continue
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            
            cve_id = doc.get("cveID")
            if not cve_id: continue

            # 轉換為文字並放入 batch
            texts_batch.append(cve_to_text(doc))
            docs_batch.append({"cveID": cve_id, "file_name": file_path.name})

            # 批次處理
            if len(texts_batch) >= BATCH_SIZE:
                vectors = ollama.embed(model=MODEL_NAME, input=texts_batch)["embeddings"]
                embeddings.extend(vectors)
                
                for d in docs_batch:
                    metadata.append({"cveID": d["cveID"]})
                    processed.add(d["file_name"])
                
                # 存檔 Checkpoint
                with open(CHECKPOINT_PATH, "wb") as f:
                    pickle.dump({"embeddings": embeddings, "metadata": metadata, "processed": list(processed)}, f)
                
                texts_batch, docs_batch = [], []
                pbar.update(BATCH_SIZE)
        
        except Exception as e:
            print(f"\n[!] 處理檔案 {file_path.name} 失敗: {e}")
            continue

    # 3. 處理最後剩餘 (Last Batch)
    if texts_batch:
        vectors = ollama.embed(model=MODEL_NAME, input=texts_batch)["embeddings"]
        embeddings.extend(vectors)
        for d in docs_batch:
            metadata.append({"cveID": d["cveID"]})
            processed.add(d["file_name"])
    
    pbar.close()

    # 4. 建立 FAISS Index
    print("[+] 建立 FAISS 索引...")
    emb_array = np.array(embeddings, dtype="float32")
    faiss.normalize_L2(emb_array)
    
    index = faiss.IndexFlatIP(emb_array.shape[1])
    index.add(emb_array)
    
    # 5. 儲存成品
    faiss.write_index(index, str(INDEX_PATH))
    np.save(EMBEDDING_PATH, emb_array)
    with open(METADATA_PATH, "wb") as f: pickle.dump(metadata, f)
    
    # 刪除檢查點
    if CHECKPOINT_PATH.exists():
        os.remove(CHECKPOINT_PATH)
        
    print(f"\n[+] 完成！共處理 {len(metadata)} 筆資料。")

if __name__ == "__main__":
    run_pipeline()