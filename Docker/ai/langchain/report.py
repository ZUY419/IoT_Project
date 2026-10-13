# Docker/ai/langchain/report.py
# ----------------------------------------------------------------------------
# Stage 5：把 share_memory 彙整成 Markdown 滲透測試報告。
# 每個 CVE 一節：成功 → 怎麼成功、哪條 payload；失敗 → 試過哪些、為何判定失敗。
# 報告主體由程式組裝（不靠 7B，保證資料真實），只在「總結段」可選擇讓 7B 潤飾。
# ----------------------------------------------------------------------------

import json
import os
from datetime import datetime
from pathlib import Path

from config.logging import log_info
import util

# Markdown 報告放在本台設備專屬資料夾 workspace/data/<設備名稱>/reports/（可用 REPORT_DIR 覆寫）
REPORT_DIR = Path(os.getenv("REPORT_DIR", util.get_device_data_dir() / "reports"))

# JSON 報告放在「集中、扁平」的資料夾：workspace/reports/（可用 JSON_REPORT_DIR 覆寫）。
# 檔名已含設備名稱（{firmware}_{時間戳}.json），網頁只要列這一個資料夾即可，
# 不必再進到各設備子資料夾用設備名稱去找。
JSON_REPORT_DIR = Path(os.getenv("JSON_REPORT_DIR", util.WORKSPACE_DIR / "reports"))


def _fmt_ports(sm: dict) -> str:
    lines = ["| Protocol | Port | Service | Version |", "|---|---|---|---|"]
    ports = sm.get("ports", {})
    any_row = False
    for proto in ("TCP", "UDP"):
        for p in ports.get(proto, []):
            any_row = True
            lines.append(f"| {proto} | {p.get('port','')} | {p.get('service','')} | {p.get('version','')} |")
    if not any_row:
        return "_（未發現開放埠）_"
    return "\n".join(lines)


def _fmt_web(sm: dict) -> str:
    wf = sm.get("web_footprints", {})
    analyzed = sm.get("analyzed_urls", [])
    if not analyzed and not wf:
        return "_（未進行 Web 端點分析或無結果）_"

    out = []
    vendor = wf.get("iot_vendor", {})
    device = wf.get("device_type", {})
    if vendor:
        out.append(f"- **廠商判定**：{vendor.get('name', 'Unknown')}")
    if device:
        out.append(f"- **設備類型**：{device.get('category', 'Unknown')}")
    if analyzed:
        out.append(f"- **已分析端點（{len(analyzed)}）**：")
        for u in analyzed:
            out.append(f"  - `{u}`")
    return "\n".join(out) if out else "_（無 Web 資訊）_"


def _fmt_cve_section(sm: dict) -> str:
    attempts = sm.get("exploit_attempts", [])
    if not attempts:
        return "_（Stage 4 未驗證任何 CVE —— 可能是 RAG/NVD 未檢索到對應 CVE）_"

    blocks = []
    for rec in attempts:
        cve_id = rec.get("cve_id", "UNKNOWN")
        cvss = rec.get("cvss", "N/A")
        success = rec.get("success", False)
        skipped_dos = rec.get("skipped_dos", False)

        if skipped_dos:
            status_badge = "⏭️ 已識別，為保護靶機未實際驗證 (Identified, not exploited — DoS risk)"
        elif success:
            status_badge = "✅ 驗證命中成功條件"
        else:
            status_badge = "❌ 多次嘗試未果 (Attempted / Not Exploitable)"

        b = [f"### {cve_id}", "", f"- **CVSS**：{cvss}", f"- **驗證結果**：{status_badge}"]

        # 驗證方式：用現成 PoC 改寫，還是 LLM 自行產生指令
        method = rec.get("method")
        if method == "poc":
            b.append("- **驗證方式**：採用資料庫收錄之 PoC，由 qwen2.5-coder 改寫為可執行程式後驗證")
        elif method == "llm":
            b.append("- **驗證方式**：資料庫無 PoC，由 qwen2.5-coder 自行產生探測指令嘗試")

        desc = (rec.get("description") or "").strip()
        if desc:
            b.append(f"- **漏洞描述**：{desc[:400]}")

        if skipped_dos:
            b.append("")
            b.append(f"> **說明**：此 CVE 為阻斷服務 (DoS) 類漏洞。實際驗證將導致目標服務崩潰，"
                     f"影響後續測試並可能損害設備，故依滲透測試慣例僅標記為「已識別」，不進行實際利用。"
                     f"建議由人員在受控環境中另行評估。")
            blocks.append("\n".join(b))
            continue

        if success and rec.get("success_cmd"):
            b.append("")
            b.append("**成功的驗證指令（payload）：**")
            b.append("```bash")
            b.append(rec["success_cmd"])
            b.append("```")
            # 若成功是靠 PoC 檔，附上 coder 改寫後的程式碼（報告的有力佐證）
            succ_att = next((a for a in rec.get("attempts", [])
                             if a.get("judged_success") and a.get("is_poc") and a.get("poc_content")), None)
            if succ_att:
                b.append("")
                b.append(f"**成功的 PoC 程式（{succ_att.get('poc_filename','poc')}，由 qwen2.5-coder 改寫）：**")
                b.append("```python")
                b.append(succ_att.get("poc_content", ""))
                b.append("```")

        # 所有嘗試紀錄（成功與失敗都列，供佐證）
        atts = rec.get("attempts", [])
        if atts:
            b.append("")
            b.append(f"**嘗試紀錄（共 {len(atts)} 次）：**")
            b.append("")
            b.append("| # | 指令 | 判定 | 回應節錄 |")
            b.append("|---|---|---|---|")
            for a in atts:
                cmd = (a.get("cmd", "") or "").replace("|", "\\|")[:80]
                judged = "命中" if a.get("judged_success") else "未命中"
                exc = (a.get("response_excerpt", "") or "").replace("|", "\\|").replace("\n", " ")[:80]
                b.append(f"| {a.get('n','')} | `{cmd}` | {judged} | {exc} |")

        if not success:
            b.append("")
            b.append(f"> **結論**：Agent 已透過上述 {len(atts)} 種方式對 {cve_id} 進行自動化驗證嘗試，"
                     f"但回應均未命中預設的成功特徵（關鍵字/狀態碼），"
                     f"故判定此 CVE 在當前靶機上**未能成功利用**，列為 Attempted。")

        blocks.append("\n".join(b))

    return "\n\n---\n\n".join(blocks)


def generate_markdown_report(sm: dict, target_ip: str) -> str:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    JSON_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    device = util.get_device_name()
    # 檔名格式：{firmware}_{YYYYMMDD_HHMMSS}.{ext}
    path = REPORT_DIR / f"{device}_{ts}.md"           # .md 在設備資料夾
    json_path = JSON_REPORT_DIR / f"{device}_{ts}.json"  # .json 在集中扁平資料夾

    attempts = sm.get("exploit_attempts", [])
    total_cve = len(attempts)

    # ---- 驗證結果細分類 ----
    def _is_disclosure(r):
        cid = str(r.get("cve_id", "")).upper()
        return bool(r.get("disclosure")) or cid.startswith("INFO-DISCLOSURE")

    hit_cnt        = sum(1 for a in attempts if a.get("success"))
    disclosure_hit = sum(1 for a in attempts if a.get("success") and _is_disclosure(a))
    cve_hit        = hit_cnt - disclosure_hit
    dos_cnt        = sum(1 for a in attempts if a.get("skipped_dos"))
    attempted_cnt  = sum(1 for a in attempts if not a.get("success") and not a.get("skipped_dos"))
    att_poc = sum(1 for a in attempts
                  if not a.get("success") and not a.get("skipped_dos") and a.get("method") == "poc")
    att_llm = sum(1 for a in attempts
                  if not a.get("success") and not a.get("skipped_dos") and a.get("method") == "llm")
    att_other = attempted_cnt - att_poc - att_llm

    open_ports = sum(len(sm.get('ports', {}).get(p, [])) for p in ('TCP', 'UDP'))

    md = f"""# 滲透測試報告 — {target_ip}

> 本報告由 PentestGPT v2 (SOP 固定流程版) 自動產生
> 產生時間：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
> 執行模型：qwen2.5-coder:7b（僅用於指令生成與解析，流程決策由固定 SOP 控制）
> 設備資料夾：workspace/data/{util.get_device_name()}/

---

## 一、執行摘要

### 1-1 掃描與檢索統計

| 項目 | 數量 |
|---|---|
| 開放埠 (TCP+UDP) | {open_ports} |
| 已分析 Web 端點 | {len(sm.get('analyzed_urls', []))} |
| 檢索出的 CVE | {len(sm.get('cves', []))} |
| 進入驗證的項目（CVE + 資訊洩漏發現） | {total_cve} |

### 1-2 漏洞驗證結果分類

| 驗證結果 | 數量 | 說明 |
|---|---|---|
| ✅ 驗證命中 | {hit_cnt} | 其中：資訊洩漏 {disclosure_hit}、CVE 驗證 {cve_hit} |
| ⏭️ DoS 主動略過 | {dos_cnt} | 偵測為阻斷服務類，為保護靶機不實際驗證 |
| ❌ Attempted 未果 | {attempted_cnt} | 其中：PoC 改寫 {att_poc}、LLM 探測 {att_llm}{f"、其他 {att_other}" if att_other else ""} |
| **合計** | **{total_cve}** | |

> 說明：「驗證命中」以程式硬條件判定（非 LLM 自稱）；「DoS 主動略過」是刻意不攻擊以保護靶機，非驗證失敗；
> 「Attempted」代表已實際嘗試但未重現。分母包含資訊洩漏發現，故與「檢索出的 CVE」不一定相等。

---

## 二、資產偵察結果（Stage 1）

{_fmt_ports(sm)}

---

## 三、Web 端點分析（Stage 3）

{_fmt_web(sm)}

---

## 四、漏洞驗證詳情（Stage 4）

{_fmt_cve_section(sm)}

---

## 五、附註

- 本報告之「驗證命中」係以程式硬條件（回應關鍵字 / HTTP 狀態碼）判定，非由語言模型自行宣稱，以確保結論可信。
- 標記為 **Attempted / Not Exploitable** 的 CVE，代表 Agent 已實際嘗試但未能在當前靶機環境重現，屬有效的滲透測試結論。
- 完整原始資料保存於 `share_memory.json`。
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(md)

    # =====================================================================
    # 另存一份結構化 JSON，方便網頁直接讀取顯示（與 .md 同名、同資料夾）
    # =====================================================================
    def _result_of(r):
        if r.get("skipped_dos"):
            return "dos_skipped"
        if r.get("success"):
            return "hit"
        return "attempted"

    findings = []
    for r in attempts:
        findings.append({
            "id": r.get("cve_id", "UNKNOWN"),
            "cvss": r.get("cvss", "N/A"),
            "result": _result_of(r),              # hit / dos_skipped / attempted
            "is_disclosure": _is_disclosure(r),
            "method": r.get("method"),            # poc / llm / None
            "description": (r.get("description") or "").strip(),
            "success_cmd": r.get("success_cmd"),
            "attempts": [
                {
                    "n": a.get("n"),
                    "cmd": a.get("cmd", ""),
                    "judged_success": bool(a.get("judged_success")),
                    "is_poc": bool(a.get("is_poc")),
                    "response_excerpt": (a.get("response_excerpt") or "")[:500],
                }
                for a in r.get("attempts", [])
            ],
        })

    report_data = {
        "device": device,
        "target_ip": target_ip,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "model": "qwen2.5-coder:7b",
        "summary": {
            "open_ports": open_ports,
            "analyzed_web_endpoints": len(sm.get("analyzed_urls", [])),
            "retrieved_cves": len(sm.get("cves", [])),
            "verified_items": total_cve,
            "classification": {
                "hit": {"total": hit_cnt, "disclosure": disclosure_hit, "cve": cve_hit},
                "dos_skipped": dos_cnt,
                "attempted": {"total": attempted_cnt, "poc": att_poc, "llm": att_llm, "other": att_other},
            },
        },
        "ports": sm.get("ports", {"TCP": [], "UDP": []}),
        "web": {
            "vendor": sm.get("web_footprints", {}).get("iot_vendor", {}),
            "device_type": sm.get("web_footprints", {}).get("device_type", {}),
            "analyzed_urls": sm.get("analyzed_urls", []),
        },
        "findings": findings,
        "report_md_file": path.name,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)

    log_info.info(f"📄 報告已寫入: {path}")
    log_info.info(f"🧾 JSON 報告已寫入: {json_path}")
    return str(path)