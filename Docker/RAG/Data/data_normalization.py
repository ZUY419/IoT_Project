from pathlib import Path
import json
from tqdm import tqdm
import re
from urllib.parse import urlparse
from typing import List, Dict, Optional
import os
from dotenv import load_dotenv
import requests

# =========================
# Path 設定
# =========================
folder_path = Path(__file__).resolve().parent / "CVES"
log_folder = folder_path.parent / "Error Logs"
output_folder = folder_path.parent / "Normalization CVES"

env_path = folder_path / ".env"

# 載入 .env 檔案
load_dotenv(dotenv_path=env_path)

# 透過 os.getenv 取得變數
api_key = os.getenv("API_KEY")

log_folder.mkdir(parents=True, exist_ok=True)
output_folder.mkdir(parents=True, exist_ok=True)

error_files_path = log_folder / "error_files.txt"
error_logs_path = log_folder / "error_logs.txt"
poc_path = log_folder / "poc.txt"

for file in [error_files_path, error_logs_path, poc_path]:
    with open(file, "w", encoding="utf-8") as f:
        f.write("")

# =========================
# 允許抓取的特定網站白名單與 URL 檢查機制
# =========================
ALLOWED_POC_DOMAINS = {
    "github.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "exploit-db.com",
    "packetstormsecurity.com",
    "gitlab.com"
}

URL_CACHE = {}

# def check_url_is_alive(url: str) -> bool:
#     """檢查網址是否存活（排除 404 或失效連結）"""
#     if url in URL_CACHE:
#         return URL_CACHE[url]

#     headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
#     try:
#         # 先嘗試 HEAD 請求（速度最快）
#         response = requests.head(url, headers=headers, timeout=4, allow_redirects=True)
#         if response.status_code < 400:
#             URL_CACHE[url] = True
#             return True
        
#         # 如果伺服器不支援 HEAD，改用 GET 輕量請求
#         response = requests.get(url, headers=headers, timeout=4, stream=True)
#         is_alive = response.status_code < 400
#         URL_CACHE[url] = is_alive
#         return is_alive
#     except Exception:
#         # 逾時或連線失敗均視為無效網址
#         URL_CACHE[url] = False
#         return False

# =========================
# Global Collection
# =========================
error_files = []
error_log_list = ["cveID", "descriptions", "metrics", "problemTypes", "tags", "solutions", "vendors", "products", "affected"]
rejected_count = 0
files = list(folder_path.rglob("*.json"))

# =========================
# Process CVE JSON
# =========================
for file in tqdm(files, desc="Normalizing CVE", unit="file"):
    try:
        with open(file, "r", encoding="utf-8") as f:
            data = json.load(f)

        cveMetadata = data.get("cveMetadata") or {}
        if cveMetadata.get("state") == "REJECTED":
            rejected_count += 1
            continue

        output_dict = {"cveID": cveMetadata.get("cveId", "")}
        file_vendors, file_products = set(), set()
        affected_list = []

        containers = data.get("containers") or {}
        cna = containers.get("cna") or {}

        if cna:
            output_dict["descriptions"] = [d.get("value", "") for d in (cna.get("descriptions") or [])]
            output_dict["metrics"] = [val for m in (cna.get("metrics") or []) for val in m.values() if any(k.lower().startswith("cvss") for k in m.keys())]
            output_dict["problemTypes"] = [{"descriptions": {"cweID": d.get("cweId", ""), "description": d.get("description", "")}} for pt in (cna.get("problemTypes") or []) for d in (pt.get("descriptions") or [])]
            output_dict["tags"] = [t for ref in (cna.get("references") or []) for t in (ref.get("tags") or [])]
            output_dict["solutions"] = [s.get("value", "") for s in (cna.get("solutions") or [])]

            # Affected
            for affected in (cna.get("affected") or []):
                v, p = affected.get("vendor", ""), affected.get("product", "")
                if v: file_vendors.add(v)
                if p: file_products.add(p)
                affected_list.append({"vendor": v, "product": p, "cpes": affected.get("cpes") or [], "versions": affected.get("versions") or []})

            # Filtered PoC: 僅限白名單網域 且 檢查不是 404（存活）才放入 PoC 清單
            filtered_poc_urls = []
            for ref in (cna.get("references") or []):
                url = ref.get("url")
                if not url:
                    continue
                
                parsed = urlparse(url.lower())
                domain = parsed.netloc.replace("www.", "")
                
                # 1. 檢查是否符合特定網站白名單
                is_allowed_domain = any(allowed in domain for allowed in ALLOWED_POC_DOMAINS)
                
                if is_allowed_domain:
                    filtered_poc_urls.append(url)
            
            output_dict["PoC"] = filtered_poc_urls

        # ADP
        for adp in (containers.get("adp") or []):
            for affected in (adp.get("affected") or []):
                v, p = affected.get("vendor", ""), affected.get("product", "")
                if v: file_vendors.add(v)
                if p: file_products.add(p)
                affected_list.append({"vendor": v, "product": p, "cpes": affected.get("cpes") or [], "versions": affected.get("versions") or []})

        # 合併集合 (使用 set 去除重複值)
        final_vendors = set(file_vendors)
        final_products = set(file_products)

        # 更新字典 (確保轉回 list)
        output_dict.update({
            "vendors": sorted(list(final_vendors)), 
            "products": sorted(list(final_products)), 
            "affected": affected_list
        })

        output_file = output_folder / file.relative_to(folder_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(output_dict, f, ensure_ascii=False, indent=4)

        empty_fields = [f for f in error_log_list if not output_dict.get(f)]
        if empty_fields:
            with open(error_logs_path, "a", encoding="utf-8") as f:
                f.write(f"{file.name} = {empty_fields}\n")

    except Exception as e:
        error_files.append(f"---- {file} ----\nerror = {e}\n\n")

if error_files:
    with open(error_files_path, "w", encoding="utf-8") as f:
        f.writelines(error_files)

print(f"\n{'='*10} Normalization Summary {'='*10}")
print(f"Total files : {len(files)}")
print(f"Rejected    : {rejected_count}")
print(f"Errors      : {len(error_files)}")