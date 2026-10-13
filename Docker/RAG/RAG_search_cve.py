import json
import re
from pathlib import Path
import textwrap
import sys

# --- Configuration ---
BASE_DIR = Path(__file__).resolve().parent
CVES_DIR = BASE_DIR / "Data" / "Normalization CVES"

def format_text(text, indent_size=4):
    if isinstance(text, list):
        text = " ".join(text)
    elif not isinstance(text, str):
        text = str(text)
    clean_text = text.replace("\n", " ").strip()
    return textwrap.indent(clean_text, " " * indent_size)

def lookup_cve_single(cve_id):
    """
    單次查詢一個指定的 CVE 編號
    """
    cve_id = cve_id.strip().upper()
    
    # 驗證是否符合 CVE 格式
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
        return {"cve_id": cve_id, "error": "無效的 CVE 編號格式 (應為 CVE-YYYY-XXXX)"}
    
    cve_data = {
        "cve_id": cve_id,
        "description": "No description provided.",
        "PoC": []
    }
    
    # 解析 CVE 結構以定位檔案路徑 (例如 CVE-2025-1000 -> 2025 / 1xxx / CVE-2025-1000.json)
    parts = cve_id.split("-")
    if len(parts) == 3:
        year = parts[1]
        seq_str = parts[2]
        bucket = (seq_str[:-3] + "xxx") if len(seq_str) >= 3 else "0xxx"
        target_path = CVES_DIR / year / bucket / f"{cve_id}.json"
    else:
        target_path = None
    
    if target_path and target_path.exists():
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # 抓取描述
            raw_desc = data.get("descriptions", "No description provided.")
            if isinstance(raw_desc, list):
                raw_desc = " ".join([d.get("value", str(d)) if isinstance(d, dict) else str(d) for d in raw_desc])
            cve_data["description"] = raw_desc
            
            # 抓取 PoC
            raw_poc = data.get("PoC")
            if raw_poc:
                if isinstance(raw_poc, list):
                    cve_data["PoC"].extend(raw_poc)
                else:
                    cve_data["PoC"].append(str(raw_poc))
        except Exception as e:
            cve_data["error"] = f"解析 JSON 檔案時發生錯誤: {str(e)}"
    else:
        cve_data["error"] = f"找不到對應的 CVE 檔案: {cve_id}"
        
    # 以 JSON 字串形式回傳單一結果
    return json.dumps(cve_data, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    # 透過命令列帶入單一 CVE 進行查詢 (例如: python3 RAG_search_cve.py CVE-2017-14492)
    if len(sys.argv) > 1:
        target_cve = sys.argv[1]
        print(lookup_cve_single(target_cve))
    else:
        print(json.dumps({"error": "請提供欲查詢的單一 CVE 編號"}))