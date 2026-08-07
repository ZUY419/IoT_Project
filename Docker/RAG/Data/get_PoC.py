import json
import time
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from pathlib import Path

folder_path = Path(__file__).resolve().parent
output_path = folder_path / "PoC_content.txt"
CVE_files = folder_path / "Normalization CVES"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

SECTION_KEYWORDS = {
    "poc": [
        "proof of concept", "poc", "proof", "exploit", 
        "reproduction", "steps to reproduce", "example request", "payload"
    ]
}

def classify_heading(text):
    text = text.lower().strip()
    for v in SECTION_KEYWORDS["poc"]:
        if v in text:
            return "poc"
    return None

def extract_poc_section(soup):
    poc_text = ""
    current = False
    for element in soup.find_all(["h1", "h2", "h3", "h4", "p", "pre", "li"]):
        text = element.get_text("\n", strip=True)
        if not text:
            continue
        if element.name in ["h1", "h2", "h3", "h4"]:
            if classify_heading(text):
                current = True
                continue
            else:
                current = False
        if current:
            poc_text += text + "\n"
    return poc_text.strip()

def parse_advisory(session, url):
    max_retries = 3
    backoff_factor = 2  

    # 1. 🔑 支援 Exploit-DB 網址，直接轉為下載原始攻擊腳本
    if "exploit-db.com/exploits/" in url:
        parts = url.rstrip("/").split("/")
        if parts[-1].isdigit():
            exploit_id = parts[-1]
            download_url = f"https://www.exploit-db.com/download/{exploit_id}"
            for attempt in range(max_retries):
                try:
                    res = session.get(download_url, headers=HEADERS, timeout=30)
                    if res.status_code == 429:
                        time.sleep(backoff_factor ** (attempt + 1))
                        continue
                    res.raise_for_status()
                    return {
                        "url": url,
                        "title": f"Exploit-DB Exploit #{exploit_id}",
                        "poc": res.text.strip()
                    }
                except requests.exceptions.RequestException:
                    if attempt == max_retries - 1:
                        break
                    time.sleep(2)

    # 一般網頁的重試請求邏輯
    for attempt in range(max_retries):
        try:
            response = session.get(url, headers=HEADERS, timeout=30)
            
            if response.status_code == 429:
                sleep_time = backoff_factor ** (attempt + 1)
                tqdm.write(f"[!] 遇到 429 限制 ({url})，正在進行第 {attempt + 1} 次重試，等待 {sleep_time} 秒...")
                time.sleep(sleep_time)
                continue

            response.raise_for_status()
            break
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                return {"error": str(e)}
            time.sleep(2)
    else:
        return {"error": "429 Too Many Requests: 重試次數耗盡"}

    # 2. 支援 .patch、.diff 或 .driff 檔案直接當作 PoC 收錄
    if url.endswith(".patch") or url.endswith(".diff") or url.endswith(".driff"):
        return {
            "url": url,
            "title": "GitHub Commit Patch / Diff",
            "poc": response.text.strip()
        }

    # 3. 一般 HTML 網頁解析
    soup = BeautifulSoup(response.text, "html.parser")
    for tag in soup(["script", "style", "svg", "nav", "footer", "header"]):
        tag.decompose()

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    poc_content = extract_poc_section(soup)

    return {
        "url": url,
        "title": title,
        "poc": poc_content
    }

if __name__ == "__main__":
    files = list(CVE_files.rglob("*.json"))

    with requests.Session() as session:
        for file in tqdm(files, desc="Normalizing CVE", unit="file"):
            try:
                with open(file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                urls = data.get("PoC", [])
                references = data.get("references", [])
                
                if not urls and not references:
                    continue

                poc_list = []
                references_list = []
                has_updated = False

                for item in urls:
                    if isinstance(item, dict):
                        if item.get("poc"):
                            poc_list.append(item)
                        else:
                            if "url" in item:
                                references_list.append(item["url"])
                        continue

                    if type(item) is not str:
                        continue
                    if not (item.startswith("http://") or item.startswith("https://")):
                        continue

                    url = item
                    tqdm.write(f"[*] 正在檢查網址: {url}")
                    result = parse_advisory(session, url)

                    if "error" in result:
                        err_msg = result["error"]
                        if "404" in err_msg:
                            tqdm.write(f"[!] 發現 404 錯誤，已自動刪除此網址: {url}")
                        else:
                            tqdm.write(f"[!] 請求失敗 ({err_msg})，已自動刪除此網址: {url}")
                        has_updated = True
                        continue

                    if result.get("poc"):
                        tqdm.write("[+] 發現明確的 PoC 內容（或 Exploit-DB/Patch），收錄至 PoC 欄位！")
                        poc_list.append(result)
                        has_updated = True
                    else:
                        tqdm.write("[-] 無明確 PoC 標題或內容，歸類至 references 欄位。")
                        references_list.append(url)
                        has_updated = True

                    time.sleep(1.5)

                for ref_url in references:
                    if isinstance(ref_url, str) and (ref_url.startswith("http://") or ref_url.startswith("https://")):
                        if ref_url not in references_list and ref_url not in [p.get("url") for p in poc_list]:
                            references_list.append(ref_url)

                data["PoC"] = poc_list
                data["references"] = references_list

                if has_updated:
                    with open(file, "w", encoding="utf-8") as f:
                        f.write(json.dumps(data, indent=4, ensure_ascii=False))

            except Exception as e:
                tqdm.write(f"---- {file} ----\nerror = {e}\n\n")
        
    print(f"\n[*] 處理完成！所有 JSON 檔案已更新分類。")