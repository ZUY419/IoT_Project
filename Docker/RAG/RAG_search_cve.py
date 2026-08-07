import json
import re
from pathlib import Path
import textwrap

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

def lookup_cves(query):
    cve_regex = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
    cve_matches = cve_regex.findall(query)
    
    if not cve_matches:
        print("[!] 輸入中未偵測到有效的 CVE 編號格式 (例如 CVE-YYYY-XXXX)。")
        return False
        
    unique_cves = list(set([c.upper() for c in cve_matches]))
    print(f"\n[+] 偵測到 CVE 編號: {', '.join(unique_cves)}")
    
    for cve_id in unique_cves:
        print(f"\n{'-'*40}\nTarget CVE: {cve_id}\n{'-'*40}")
        
        # 解析 CVE 結構以直接定位檔案路徑 (例如 CVE-2025-1000 -> 2025 / 1xxx / CVE-2025-1000.json)
        parts = cve_id.split("-")
        if len(parts) == 3:
            year = parts[1]
            seq_str = parts[2]
            # 將後三位改為 xxx 形成分桶名稱 (例如 1000 -> 1xxx, 12345 -> 12xxx)
            bucket = (seq_str[:-3] + "xxx") if len(seq_str) >= 3 else "0xxx"
            target_path = CVES_DIR / year / bucket / f"{cve_id}.json"
        else:
            target_path = None
        
        if target_path and target_path.exists():
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            raw_desc = data.get("descriptions", "No description provided.")
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
            print(f"[!] 找不到對應的 CVE 檔案: {cve_id}")
    return True

if __name__ == "__main__":
    print("[+] CVE Direct Lookup Tool Ready. Type 'exit' to quit.")
    while True:
        query = input("\nEnter CVE ID (e.g., cve-2025-1000): ").strip()
        if query.lower() == 'exit':
            break
        if not query:
            continue
        lookup_cves(query)