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

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

# --- Configuration ---
BASE_DIR = Path(__file__).resolve().parent

VECTOR_SUBDIR = os.getenv("VECTOR_SUBDIR", "")
VECTOR_DIR = (BASE_DIR / "Vector_DB" / VECTOR_SUBDIR) if VECTOR_SUBDIR else (BASE_DIR / "Vector_DB")
CVES_DIR = BASE_DIR / "Data" / "Normalization CVES"
INDEX_PATH = VECTOR_DIR / "cve.index"
METADATA_PATH = VECTOR_DIR / "metadata.pkl"
EMBEDDING_MODEL = "nomic-embed-text-rag-v1"
AI_FILTER_MODEL = "qwen2.5:7b"

# =====================================================================
# ⚠️【架構改變：LLM re-ranking，由 LLM 當守門員，不再用分數硬切】
# 舊版用 SCORE_THRESHOLD 做硬性 break，導致 dnsmasq(最高分僅 0.54)連 LLM
# 都沒機會判斷就被擋掉。新版：
#   - 分數只負責「排序 + 取 top-K 候選」
#   - LLM(qwen2.5:7b)逐一判斷候選是否真的相關 ← 真正的守門員
#   - HARD_FLOOR 只是極低的安全地板，擋掉幾乎零相似的雜訊，預設 0.0(全交給 LLM)
# =====================================================================

# 從 FAISS 取幾筆候選交給 LLM 判斷。
# ⚠️ 因為停止條件改成「連續 N 筆不相關才停」(不再限制收錄數量)，
#    這裡要夠大，才不會在還沒遇到連續不相關前就把候選用完。預設 200。
TOP_K_CANDIDATES = int(os.getenv("RAG_TOP_K", "200"))
# ⚠️ MAX_MATCH = 0 代表「不限收錄數量」(一直收，直到連續不相關才停)。
#    若想限制上限，設成正整數即可。
MAX_MATCH = int(os.getenv("RAG_MAX_MATCH", "0"))
# 連續幾筆被 LLM 判為不相關就停止。FAISS 已按相似度排序，連續 N 筆不相關
# 代表後面只會更不像，故可安全停止。你要求的「連續 5 筆不相關就停」。
MAX_CONSECUTIVE_IGNORE = int(os.getenv("RAG_MAX_IGNORE", "5"))
# 安全地板：相似度低於此值直接不送 LLM。預設 0.0 = 全部候選都讓 LLM 判。
HARD_FLOOR = float(os.getenv("RAG_HARD_FLOOR", "0.0"))

# Ollama host
ollama_host = os.getenv("OLLAMA_HOST", "http://192.168.131.1:11434")
client = ollama.Client(host=ollama_host)


# =====================================================================
# 第一道閘：輸入清洗與垃圾擋除（擋 IP / 純數字 / 無產品名）
# =====================================================================
_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$")


def sanitize_query(raw_query: str) -> str:
    if not isinstance(raw_query, str):
        raw_query = str(raw_query)
    q = raw_query.strip()
    q = re.sub(r"\([^)]*\)", " ", q)
    q = re.sub(r"(?i)\bport\b\s*\d+\s*/\s*(tcp|udp)", " ", q)
    q = re.sub(r"\b\d+\s*/\s*(tcp|udp)\b", " ", q, flags=re.IGNORECASE)
    q = re.sub(r"\s+", " ", q).strip()
    return q


def is_meaningful_query(query: str) -> bool:
    if not query:
        return False
    if _IP_PATTERN.match(query.strip()):
        return False
    if not re.search(r"[A-Za-z]", query):
        return False
    if len(query.replace(" ", "")) < 3:
        return False
    return True


def load_system():
    if not INDEX_PATH.exists() or not METADATA_PATH.exists():
        print(f"[!] Error: Index files not found at {VECTOR_DIR}")
        print(f"[!] 請先執行 create_embedding.py 建立 cve.index 與 metadata.pkl，或確認 VECTOR_SUBDIR 設定")
        sys.exit(1)
    index = faiss.read_index(str(INDEX_PATH))
    with open(METADATA_PATH, "rb") as f:
        metadata = pickle.load(f)
    return index, metadata


def analyze_single_cve(query, cve_data):
    """LLM 判斷這筆 CVE 是否真的跟查詢的產品相關（這是真正的守門員）。"""
    prompt = f"""
    You are a strict cybersecurity CVE matching expert.
    User is looking for vulnerabilities of this specific product/service: "{query}"

    Candidate Vulnerability Data:
    {json.dumps(cve_data, indent=2, ensure_ascii=False)}

    Task:
    Decide if this CVE is TRULY about the SAME product/software named in the query.
    STRICT RULES:
    - The product name in the query MUST actually appear in or clearly match the CVE description or product field.
    - Do NOT mark relevant just because both are "network devices" or "routers" in general.
    - If the query is an IP address, a port number, or has no clear product name, answer relevant=false.
    - When in doubt, answer relevant=false.

    Output STRICTLY as a JSON object, nothing else:
        {{"relevant": true, "reason": "exact product/version match found"}}
        or
        {{"relevant": false, "reason": "why it does not match"}}
    """
    try:
        response = client.chat(model=AI_FILTER_MODEL, messages=[
            {'role': 'system', 'content': 'You are a strict assistant that outputs only valid JSON and errs on the side of relevant=false.'},
            {'role': 'user', 'content': prompt},
        ])
        content = response['message']['content']
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
        return {"relevant": False, "reason": "Failed to parse JSON output from AI."}
    except Exception as e:
        return {"relevant": False, "reason": f"AI error: {str(e)}"}


def search_and_analyze(query, index, metadata, **kwargs):
    """向量搜尋取候選 → 交給 LLM 逐筆判斷相關性（LLM re-ranking）。"""
    # ---- 第一道閘：清洗 + 擋垃圾 ----
    original_query = query
    query = sanitize_query(query)
    if not is_meaningful_query(query):
        print(f"[RAG] 查詢 {original_query!r} 清洗後為 {query!r}，判定為無意義輸入，直接回空。")
        return []
    if query != original_query:
        print(f"[RAG] 查詢已清洗: {original_query!r} -> {query!r}")

    # ---- Embedding ----
    try:
        query_emb = client.embed(model=EMBEDDING_MODEL, input=[query])["embeddings"][0]
        query_emb = np.array([query_emb], dtype="float32")
        faiss.normalize_L2(query_emb)
    except Exception as e:
        print(f"[!] Embedding error: {e}")
        raise RuntimeError(
            f"RAG 容器無法連線至 Ollama ({ollama_host}) 進行 embedding，請確認 OLLAMA_HOST 與 Ollama 狀態。原始錯誤: {e}"
        )

    # ---- 向量搜尋取 top-K 候選 ----
    distances, indices = index.search(query_emb, TOP_K_CANDIDATES)

    match_cve = []
    consecutive_ignore = 0

    for i in range(TOP_K_CANDIDATES):
        # MAX_MATCH > 0 才限制收錄數量；= 0 代表不限（一直收到連續不相關為止）
        if MAX_MATCH > 0 and len(match_cve) >= MAX_MATCH:
            break
        if consecutive_ignore >= MAX_CONSECUTIVE_IGNORE:
            print(f"[RAG] 連續 {MAX_CONSECUTIVE_IGNORE} 筆被 LLM 判為不相關，停止檢索。")
            break

        score = float(distances[0][i])

        # 安全地板（預設 0，等於不擋；只有設了才會擋掉極低相似度的）
        if score < HARD_FLOOR:
            print(f"[RAG] 第 {i+1} 筆相似度 {score:.4f} < 安全地板 {HARD_FLOOR}，停止。")
            break

        idx = indices[0][i]
        cve_id = metadata[idx]["cveID"]

        found_files = list(CVES_DIR.rglob(f"*{cve_id}*.json"))
        if not found_files:
            continue

        with open(found_files[0], "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_desc = data.get("descriptions", "No description provided.")
        if isinstance(raw_desc, list):
            raw_desc = " ".join(raw_desc)

        # 把產品/廠商也給 LLM 看，判斷更準
        products = data.get("products", [])
        vendors = data.get("vendors", [])
        cve_info = {
            "cveID": cve_id,
            "vendors": vendors,
            "products": products,
            "description": raw_desc,
        }

        # ---- LLM 守門員 ----
        result = analyze_single_cve(query, cve_info)
        print(f"[RAG]   候選 {cve_id} (相似度 {score:.4f}) → LLM 判定: "
              f"{'相關 ✓' if result.get('relevant') else '不相關'} ({result.get('reason','')[:40]})")

        if result.get("relevant"):
            cwes = []
            for problem in data.get("problemTypes", []):
                desc_dict = problem.get("descriptions", {})
                if isinstance(desc_dict, dict) and desc_dict.get("cweID"):
                    cwes.append(desc_dict["cweID"])

            base_score, severity = "", ""
            for item in data.get("metrics", []):
                if isinstance(item, dict) and "baseScore" in item:
                    base_score = item.get("baseScore", "")
                    severity = item.get("baseSeverity", "")
                    break

            pocs = []
            for poc in data.get("PoC", []):
                if isinstance(poc, dict) and poc.get("poc"):
                    pocs.append(poc["poc"])
                elif isinstance(poc, str):
                    pocs.append(poc)

            match_cve.append({
                "cve_id": cve_id,
                "service": query,
                "version": "",
                "port": "",
                "severity": severity,
                "score": base_score,
                "cvss": base_score,
                "similarity": round(score, 4),
                "cwes": cwes,
                "description": raw_desc,
                "PoC": pocs,
            })
            consecutive_ignore = 0
        else:
            consecutive_ignore += 1

    print(f"[RAG] 查詢 {query!r} 完成，LLM 判定相關的 CVE 共 {len(match_cve)} 筆。")
    return match_cve


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("query", type=str, help="Search query")
    args = parser.parse_args()
    index, metadata = load_system()
    results = search_and_analyze(args.query, index, metadata)
    print(json.dumps(results, indent=4, ensure_ascii=False))