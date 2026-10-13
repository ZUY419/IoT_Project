# Docker/ai/langchain/get_nvd.py
import urllib.request
import urllib.parse
import json
import ssl

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_vulnerability_data(product_name: str, target_version: str = "") -> list:
    """
    透過 NVD API v2 線上查詢特定產品與版本的 CVE 漏洞資料。
    安全處理 list/dict 解析，避免 'list indices must be integers or slices, not str' 錯誤。
    """
    query_str = f"{product_name} {target_version}".strip()
    encoded_query = urllib.parse.quote(query_str)
    url = f"{NVD_API_URL}?keywordSearch={encoded_query}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PentestAgent/2.0"
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    results = []

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            if response.status != 200:
                print(f"[!] NVD API 回應異常狀態碼: {response.status}")
                return []
            
            raw_data = response.read().decode("utf-8", errors="ignore")
            data = json.loads(raw_data)

        if not isinstance(data, dict):
            print("[!] NVD 回傳資料格式非 dict 物件")
            return []

        vulnerabilities = data.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            print(f"[!] NVD vulnerabilities 欄位非 list 類型: {type(vulnerabilities)}")
            return []

        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            
            cve_obj = item.get("cve", {})
            if not isinstance(cve_obj, dict):
                continue

            cve_id = cve_obj.get("id", "N/A")

            # 提煉描述
            descriptions = cve_obj.get("descriptions", [])
            cve_desc = "No description available."
            if isinstance(descriptions, list):
                for desc in descriptions:
                    if isinstance(desc, dict) and desc.get("lang") == "en":
                        cve_desc = desc.get("value", cve_desc)
                        break
                    elif isinstance(desc, dict) and "value" in desc:
                        cve_desc = desc.get("value", cve_desc)

            # 提煉 CVSS 分數與 Severity
            metrics = cve_obj.get("metrics", {})
            score = "N/A"
            severity = "UNKNOWN"

            if isinstance(metrics, dict):
                metric_keys = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
                for key in metric_keys:
                    metric_list = metrics.get(key, [])
                    if isinstance(metric_list, list) and len(metric_list) > 0:
                        m_item = metric_list[0]
                        if isinstance(m_item, dict):
                            cvss_data = m_item.get("cvssData", {})
                            if isinstance(cvss_data, dict):
                                score = cvss_data.get("baseScore", score)
                                severity = cvss_data.get("baseSeverity", m_item.get("baseSeverity", severity))
                                break

            results.append({
                "cveID": cve_id,
                "cve_id": cve_id,
                "description": cve_desc,
                "score": str(score),
                "severity": str(severity),
                "cvss": {"score": str(score), "severity": str(severity)}
            })

    except Exception as e:
        print(f"[!] NVD 網路請求或解析失敗: {e}")
        return []

    return results

def convert_to_markdown(vuln_results: list, product_name: str, target_version: str) -> str:
    """將漏洞查詢結果格式化為 Markdown 摘要表格與列表"""
    if not vuln_results or not isinstance(vuln_results, list):
        return f"（NVD 查詢結果：線上 NVD 資料庫中未找到與 `{product_name} {target_version}` 相關的已知漏洞。）"

    lines = [f"### 🌐 NVD 線上漏洞檢索結果 ({product_name} {target_version})"]
    lines.append(f"共找到 {len(vuln_results)} 筆匹配的 CVE 漏洞：\n")

    for idx, item in enumerate(vuln_results[:10], 1):
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID") or item.get("cve_id", "N/A")
        score = item.get("score", "N/A")
        severity = item.get("severity", "UNKNOWN")
        desc = item.get("description", "")
        if len(desc) > 150:
            desc = desc[:150] + "..."

        lines.append(f"{idx}. **{cve_id}** [CVSS {score} - {severity}]")
        lines.append(f"   - **描述**: {desc}")

    return "\n".join(lines)
