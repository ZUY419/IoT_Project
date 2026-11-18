# Docker/ai/langchain/report.py
# ----------------------------------------------------------------------------
# Stage 6（執行順序）：把 share_memory 彙整成正式格式的 Markdown 滲透測試報告。
# 報告主體由程式組裝（不靠 7B，保證資料真實），只在「總結段」可選擇讓 7B 潤飾。
# 正式報告結構：封面資訊 → 執行摘要（風險分級 + 一覽表）→ 範圍與方法 →
#               資產偵察 → 詳細發現（依嚴重度分組排序）→ 修補建議彙整 → 附註/免責。
# ----------------------------------------------------------------------------

import os
from datetime import datetime
from pathlib import Path

from config.logging import log_info
from config.config import GENERATION_MODEL   # 實際用來產指令/改 PoC 的模型（報告動態顯示，不再寫死）
import util

# Markdown 報告放在本台設備專屬資料夾 workspace/data/<設備名稱>/reports/（可用 REPORT_DIR 覆寫）
REPORT_DIR = Path(os.getenv("REPORT_DIR", util.get_device_data_dir() / "reports"))

# 另存一份 .md 到「集中、扁平」資料夾：workspace/reports/（可用 JSON_REPORT_DIR 覆寫，沿用舊環境變數名）。
# ⚠️ 網頁的 API(_sync_get_report) 就是來這個扁平資料夾 glob "*.md" 抓最新報告，
#    所以 .md 一定要寫到這裡，網頁才看得到（否則資料夾只有舊 .json → 網頁永遠「尚無報告」）。
FLAT_REPORT_DIR = Path(os.getenv("JSON_REPORT_DIR", util.WORKSPACE_DIR / "reports"))

# Markdown 嘗試紀錄表格內，單筆回應節錄最多顯示幾字（避免整頁 HTML blob 把表格撐爆）。
RESP_EXCERPT_MD = int(os.getenv("RESP_EXCERPT_MD", "300"))

# =============================================================================
# 「為什麼判定成功」的特徵對照表。
# key = main.py SUCCESS_KEYWORDS 的硬條件字串（小寫比對）；value = 它在回應中出現
# 代表什麼、證明了哪一類利用成立。報告用這張表把「程式比對到的字串」翻成人看得懂的
# 結論，讓每一筆「成功」都有可稽核的理由，而非 LLM 自稱。
# =============================================================================
SUCCESS_EVIDENCE_MEANING = {
    "<exec-nonce>": "回應中原封出現我方注入的『執行回顯驗證碼』→ 指令**真的在靶機上被執行**"
                    "（且非伺服器原樣反射，因驗證碼需經 shell 串接才會還原）→ 證明**遠端命令執行／注入**成立。"
                    "此為最強證據，近乎零假陽性。",
    "root:x:0:0": "回應中出現 /etc/passwd 的 root 帳號列（`root:x:0:0`）→ 成功讀出系統檔案，"
                  "證明**任意檔案讀取／路徑穿越**成立。",
    "uid=0(root)": "回應中出現 `uid=0(root)` → `id` 指令以 root 身分回顯，"
                   "證明**遠端命令執行 (RCE)** 成立，且取得最高權限。",
    "gid=0(": "回應中出現 `gid=0(` → `id` 指令群組回顯，證明**遠端命令執行**成立。",
    "sh-4.$": "回應中出現 Bash 互動提示字元（`sh-4.x$`）→ 已取得遠端互動式 shell。",
    "sh-5.$": "回應中出現 Bash 互動提示字元（`sh-5.x$`）→ 已取得遠端互動式 shell。",
    "you have an error in your sql syntax":
        "資料庫回報 SQL 語法錯誤 → 輸入未經過濾被帶入查詢，證明**SQL 注入**成立。",
    "mysql_fetch": "回應洩漏 MySQL 函式錯誤特徵 → 資料庫錯誤外洩，屬 **SQL 注入／錯誤型資訊洩漏**。",
    "ora-01756": "回應含 Oracle 錯誤碼 `ORA-01756` → 資料庫錯誤外洩，屬 **SQL 注入**。",
}

# 各漏洞類別的通用修補建議（CVE 類漏洞一律先「升級韌體」，再附類別專屬強化）。
_REMEDIATION = {
    "cmd_injection": "對所有會進入系統指令的參數做嚴格白名單驗證與跳脫，避免把使用者輸入拼接進 shell；"
                     "能以 API/函式庫取代呼叫外部命令者優先改寫。",
    "path_traversal": "對檔案路徑參數先正規化再限制在白名單目錄內，拒絕 `../`、URL 編碼變體等穿越序列。",
    "sqli": "改用參數化查詢 / prepared statement，對輸入做型別與白名單驗證，關閉詳細 SQL 錯誤回顯。",
    "xss": "對輸出做情境式編碼（HTML / JS / URL），導入 Content-Security-Policy。",
    "auth_bypass": "為所有管理/設定端點強制身分驗證與授權檢查，移除未授權即可達的路徑與後門頁面。",
    "info_disclosure": "移除未授權可取得的設定/狀態端點，敏感資料加密儲存並加上存取控制。",
    "csrf": "為所有會改變狀態的請求加入不可預測的 anti-CSRF token，並驗證 Origin / Referer 標頭。",
    "buffer_overflow": "對輸入與 HTTP 標頭長度做嚴格邊界檢查、改用安全字串函式；務必升級至修補版韌體。",
    "misconfiguration": "收斂過寬的預設存取控制、關閉非必要服務、補齊安全標頭，依最小權限原則重新設定。",
}
_REMEDIATION_DEFAULT = "升級韌體至廠商發佈的修補版本；在修補前，將管理介面限制為僅限內網/受信任來源存取。"


def _severity(cvss):
    """把 CVSS 分數轉成 (排序權重, 中英標籤, 色塊)。數值無法解析 → 未評分。"""
    try:
        s = float(cvss)
    except (TypeError, ValueError):
        return (0, "未評分 Unrated", "⚪")
    if s >= 9.0:
        return (4, "嚴重 Critical", "🔴")
    if s >= 7.0:
        return (3, "高 High", "🟠")
    if s >= 4.0:
        return (2, "中 Medium", "🟡")
    if s > 0:
        return (1, "低 Low", "🟢")
    return (0, "未評分 Unrated", "⚪")


def _status_short(rec) -> str:
    """一覽表用的短狀態。"""
    if rec.get("success"):
        return "✅ 已確認"
    if rec.get("skipped_dos"):
        return "⏭️ DoS 未驗"
    if rec.get("report_only"):
        return "⏭️ 未自動驗證"
    return "❌ 未重現"


def _remediation(rec) -> str:
    """依漏洞類別給修補建議：一律先列升級韌體，再附類別專屬強化。"""
    lines = [f"- {_REMEDIATION_DEFAULT}"]
    vc = rec.get("vuln_class")
    if vc and vc in _REMEDIATION:
        lines.append(f"- {_REMEDIATION[vc]}")
    return "\n".join(lines)


def _explain_evidence(keywords) -> list:
    """把 main.py 記錄下的命中特徵字串，翻成報告用的「為什麼成功」說明列。
    對照不到的字串也原樣列出（至少說明比對到了什麼），確保不漏證據。"""
    lines = []
    for kw in (keywords or []):
        meaning = SUCCESS_EVIDENCE_MEANING.get(str(kw).lower())
        if meaning:
            lines.append(f"- {meaning}")
        else:
            lines.append(f"- 回應中比對到成功特徵字串 `{kw}`。")
    return lines


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
    model = wf.get("device_model", "")
    fw = wf.get("firmware_version", "")
    if vendor:
        out.append(f"- **廠商判定**：{vendor.get('name', 'Unknown')}")
    if model:
        out.append(f"- **裝置型號**：{model}")
    if fw:
        out.append(f"- **韌體版本**：{fw}")
    if device:
        out.append(f"- **設備類型**：{device.get('category', 'Unknown')}")
    if analyzed:
        out.append(f"- **已分析端點（{len(analyzed)}）**：")
        for u in analyzed:
            out.append(f"  - `{u}`")
    return "\n".join(out) if out else "_（無 Web 資訊）_"


def _severity_breakdown_table(attempts: list) -> str:
    """依風險等級統計：各等級的項目數與其中已確認數。"""
    buckets = {4: [0, 0], 3: [0, 0], 2: [0, 0], 1: [0, 0], 0: [0, 0]}  # rank -> [total, confirmed]
    for r in attempts:
        rank = _severity(r.get("cvss"))[0]
        buckets[rank][0] += 1
        if r.get("success"):
            buckets[rank][1] += 1
    labels = {4: "🔴 嚴重 Critical", 3: "🟠 高 High", 2: "🟡 中 Medium",
              1: "🟢 低 Low", 0: "⚪ 未評分 Unrated"}
    rows = ["| 風險等級 | 項目數 | 其中已確認 |", "|---|---|---|"]
    for rank in (4, 3, 2, 1, 0):
        total, conf = buckets[rank]
        if total:
            rows.append(f"| {labels[rank]} | {total} | {conf} |")
    return "\n".join(rows)


def _findings_summary_table(attempts: list) -> str:
    """發現一覽表：每個 CVE 一列，依嚴重度由高到低排序。"""
    rows = ["| CVE | 風險等級 | CVSS | 類別 | 狀態 |", "|---|---|---|---|---|"]
    for r in sorted(attempts, key=lambda x: (-_severity(x.get("cvss"))[0], str(x.get("cve_id", "")))):
        _, sev, badge = _severity(r.get("cvss"))
        vc = r.get("vuln_class") or "—"
        rows.append(
            f"| {r.get('cve_id','?')} | {badge} {sev} | {r.get('cvss','N/A')} | {vc} | {_status_short(r)} |"
        )
    return "\n".join(rows)


def _fmt_finding_detail(rec: dict) -> str:
    """單筆發現的正式格式：資訊表 + 描述 + 證據/PoC + 嘗試紀錄 + 修補建議。"""
    cve_id = rec.get("cve_id", "UNKNOWN")
    cvss = rec.get("cvss", "N/A")
    _, sev_label, badge = _severity(cvss)
    success = rec.get("success", False)
    skipped_dos = rec.get("skipped_dos", False)
    report_only = rec.get("report_only", False)

    if success:
        status = "✅ 已確認（Confirmed）"
    elif skipped_dos:
        status = "⏭️ 已識別，未驗證（DoS — 為保護靶機不實測）"
    elif report_only:
        status = "⏭️ 已識別，未自動驗證（此類別無法以單機探測可靠判定）"
    else:
        status = "❌ 已嘗試，未重現（Attempted / Not Exploitable）"

    b = [f"#### {badge} {cve_id}", ""]

    # 資訊表
    b.append("| 項目 | 內容 |")
    b.append("|---|---|")
    b.append(f"| 風險等級 | {sev_label}（CVSS {cvss}） |")
    b.append(f"| 驗證狀態 | {status} |")
    vc = rec.get("vuln_class")
    if vc:
        b.append(f"| 漏洞類別 | {vc} |")
    method = rec.get("method")
    if method == "poc":
        b.append(f"| 驗證方式 | 資料庫 PoC 經 {GENERATION_MODEL} 改寫後執行 |")
    elif method == "llm":
        b.append(f"| 驗證方式 | {GENERATION_MODEL} 自動產生探測指令 |")
    b.append("")

    desc = (rec.get("description") or "").strip()
    if desc:
        b.append("**漏洞描述**")
        b.append("")
        b.append(desc)
        b.append("")

    # DoS / report-only 的額外說明
    if skipped_dos:
        b.append("> **說明**：此 CVE 屬阻斷服務（DoS）類，實際驗證會導致目標服務崩潰、影響後續測試，"
                 "依滲透測試慣例僅標記為「已識別」，不進行利用，建議由人員於受控環境另行評估。")
        b.append("")
    elif report_only:
        b.append("> **說明**：此類別（CSRF／緩衝區溢位／設定不當）無法以單機自動探測可靠重現"
                 "（例如 CSRF 需受害者已登入的瀏覽器加上跨站觸發），故僅依 CVE 情報列為「已識別」，"
                 "建議改以人工審查確認。")
        b.append("")

    # 成功證據（程式硬條件，非 LLM 自稱）
    if success:
        ev_kws = rec.get("success_evidence", [])
        ev_snip = (rec.get("success_snippet") or "").strip()
        b.append("**驗證證據（程式硬條件比對，非 LLM 自稱）**")
        b.append("")
        expl = _explain_evidence(ev_kws)
        b.extend(expl if expl else ["- 回應命中預設成功硬條件，詳見下方節錄。"])
        b.append("")
        if ev_snip:
            b.append("關鍵證據片段：")
            b.append("```")
            b.append(ev_snip)
            b.append("```")
            b.append("")
        if rec.get("success_cmd"):
            b.append("成功 payload：")
            b.append("```bash")
            b.append(rec["success_cmd"])
            b.append("```")
            b.append("")
            succ_att = next((a for a in rec.get("attempts", [])
                             if a.get("judged_success") and a.get("is_poc") and a.get("poc_content")), None)
            if succ_att:
                b.append(f"成功 PoC（{succ_att.get('poc_filename','poc')}，由 {GENERATION_MODEL} 改寫）：")
                b.append("```python")
                b.append(succ_att.get("poc_content", ""))
                b.append("```")
                b.append("")

    # 嘗試紀錄（純 markdown 表格；回應截斷以利閱讀。不用 <details> 原始 HTML，
    # 因為網頁 markdown 渲染器會把 < 跳脫掉，<details> 會變成純文字顯示。）
    atts = rec.get("attempts", [])
    if atts:
        b.append(f"**驗證嘗試紀錄（共 {len(atts)} 次）：**")
        b.append("")
        b.append("| # | 指令 | 判定 | 回應節錄 |")
        b.append("|---|---|---|---|")
        for a in atts:
            cmd = (a.get("cmd", "") or "").replace("|", "\\|").replace("\n", " ")
            judged = "命中" if a.get("judged_success") else "未命中"
            exc = (a.get("response_excerpt", "") or "").replace("|", "\\|").replace("\n", " ")
            if len(exc) > RESP_EXCERPT_MD:
                exc = exc[:RESP_EXCERPT_MD] + "…（內容過長已截斷）"
            b.append(f"| {a.get('n','')} | `{cmd}` | {judged} | {exc} |")
        b.append("")

    # 修補建議
    b.append("**修補建議**")
    b.append("")
    b.append(_remediation(rec))

    return "\n".join(b)


def _fmt_detailed_findings(sm: dict) -> str:
    """詳細發現：分三組（已確認 / 已嘗試未重現 / 已識別未自動驗證），各組內依嚴重度排序。"""
    attempts = sm.get("exploit_attempts", [])
    if not attempts:
        return "_（Stage 5 未驗證任何項目 —— 可能是 RAG/NVD 未檢索到對應 CVE）_"

    def _sev_key(r):
        return (-_severity(r.get("cvss"))[0], str(r.get("cve_id", "")))

    confirmed = sorted([r for r in attempts if r.get("success")], key=_sev_key)
    attempted = sorted([r for r in attempts
                        if not r.get("success") and not r.get("skipped_dos") and not r.get("report_only")],
                       key=_sev_key)
    not_verified = sorted([r for r in attempts
                           if r.get("skipped_dos") or r.get("report_only")], key=_sev_key)

    parts = []

    parts.append(f"### 4-1 已確認漏洞（Confirmed）— {len(confirmed)} 項")
    parts.append("")
    if confirmed:
        parts.append("\n\n".join(_fmt_finding_detail(r) for r in confirmed))
    else:
        parts.append("_本次自動化驗證未確認任何漏洞。_")

    parts.append("")
    parts.append(f"### 4-2 已嘗試但未重現（Attempted）— {len(attempted)} 項")
    parts.append("")
    if attempted:
        parts.append("\n\n".join(_fmt_finding_detail(r) for r in attempted))
    else:
        parts.append("_無。_")

    parts.append("")
    parts.append(f"### 4-3 已識別、未自動驗證（DoS／設計上無法自動驗證）— {len(not_verified)} 項")
    parts.append("")
    if not_verified:
        parts.append("\n\n".join(_fmt_finding_detail(r) for r in not_verified))
    else:
        parts.append("_無。_")

    return "\n".join(parts)


def generate_markdown_report(sm: dict, target_ip: str) -> str:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    FLAT_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    device = util.get_device_name()
    path = REPORT_DIR / f"{device}_{ts}.md"               # .md 在設備子資料夾
    flat_md_path = FLAT_REPORT_DIR / f"{device}_{ts}.md"  # .md 副本在扁平資料夾（網頁 API 來這裡抓）

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
    report_only_cnt = sum(1 for a in attempts if a.get("report_only") and not a.get("success"))
    attempted_cnt  = sum(1 for a in attempts
                         if not a.get("success") and not a.get("skipped_dos") and not a.get("report_only"))
    att_poc = sum(1 for a in attempts
                  if not a.get("success") and not a.get("skipped_dos") and not a.get("report_only")
                  and a.get("method") == "poc")
    att_llm = sum(1 for a in attempts
                  if not a.get("success") and not a.get("skipped_dos") and not a.get("report_only")
                  and a.get("method") == "llm")
    att_other = attempted_cnt - att_poc - att_llm

    open_ports = sum(len(sm.get('ports', {}).get(p, [])) for p in ('TCP', 'UDP'))

    # ---- 風險結論（供執行摘要開頭）----
    if cve_hit > 0 or disclosure_hit > 0:
        posture = ("⚠️ **本次評估在隔離測試環境中成功驗證了至少一項漏洞**，"
                   "目標存在可被實際利用的安全風險，應優先處理「已確認」項目。")
    else:
        posture = ("本次自動化評估未能在目標上重現可利用漏洞；惟仍識別出多項已知 CVE（詳見下表），"
                   "未重現不代表目標絕對安全，建議就高風險項目進行人工複驗。")

    md = f"""# 滲透測試報告（Penetration Test Report）

**目標系統**：{target_ip}
**受測設備**：{device}
**報告日期**：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**測試性質**：自動化黑箱測試（隔離實驗環境）
**產生工具**：PentestGPT v2（SOP 固定流程版）／指令生成模型 {GENERATION_MODEL}
**機密等級**：機密（Confidential）— 僅限授權人員閱讀

> 本報告由自動化流程產生。流程決策由固定 SOP 控制，語言模型僅用於指令生成與解析；
> 所有「已確認」結論均以程式硬條件比對（回應關鍵字／狀態碼）判定，非語言模型自我宣稱。

---

## 一、執行摘要（Executive Summary）

{posture}

### 1-1 風險等級分佈

{_severity_breakdown_table(attempts)}

### 1-2 測試與檢索統計

| 項目 | 數量 |
|---|---|
| 開放埠 (TCP+UDP) | {open_ports} |
| 已分析 Web 端點 | {len(sm.get('analyzed_urls', []))} |
| 檢索出的 CVE | {len(sm.get('cves', []))} |
| 進入驗證的項目（CVE + 資訊洩漏發現） | {total_cve} |

### 1-3 驗證結果分類

| 驗證結果 | 數量 | 說明 |
|---|---|---|
| ✅ 已確認（Confirmed） | {hit_cnt} | 其中：資訊洩漏 {disclosure_hit}、CVE 驗證 {cve_hit} |
| ❌ 已嘗試未重現（Attempted） | {attempted_cnt} | 其中：PoC 改寫 {att_poc}、LLM 探測 {att_llm}{f"、其他 {att_other}" if att_other else ""} |
| ⏭️ DoS 主動略過 | {dos_cnt} | 偵測為阻斷服務類，為保護靶機不實際驗證 |
| ⏭️ 已識別未自動驗證 | {report_only_cnt} | CSRF／緩衝區溢位／設定不當等，單機探測無法可靠判定 |
| **合計** | **{total_cve}** | |

> 「已確認」以程式硬條件判定；「DoS 主動略過」與「已識別未自動驗證」是刻意不自動利用，非驗證失敗；
> 「Attempted」代表已實際嘗試但未重現。分母含資訊洩漏發現，故與「檢索出的 CVE」不一定相等。

---

## 二、測試範圍與方法（Scope & Methodology）

- **範圍**：單一目標主機 `{target_ip}`（{device}），於隔離實驗環境進行，未涉及其他系統。
- **方法**：固定 SOP 六階段 —— 資產偵察（nmap）→ Web 端點列舉 → 裝置指紋（HNAP/UPnP/主動探測）
  → 漏洞檢索（RAG／NVD）→ 漏洞驗證（PoC 改寫／LLM 回饋迴圈）→ 報告產生。
- **判定原則**：僅當回應出現預設成功特徵（執行回顯驗證碼、`root:x:0:0`、`uid=0(root)`、SQL 錯誤等）
  才判為「已確認」，確保結論可重現、可稽核。
- **限制**：自動化黑箱測試對 CSRF、緩衝區溢位、設定不當等類別無法可靠自動驗證（列為「已識別」）；
  DoS 類為保護靶機不實測。此類項目建議輔以人工審查。

---

## 三、資產偵察結果（Stage 1 / Stage 2）

### 3-1 開放埠與服務

{_fmt_ports(sm)}

### 3-2 Web 端點與裝置指紋

{_fmt_web(sm)}

---

## 四、發現一覽（Findings at a Glance）

{_findings_summary_table(attempts) if attempts else "_（無驗證項目）_"}

---

## 五、詳細發現（Detailed Findings）

{_fmt_detailed_findings(sm)}

---

## 六、修補建議彙整（Remediation Summary）

1. **優先升級韌體**：上述多數 CVE 已有廠商修補版本，升級至修補版是最直接有效的處置。
2. **收斂攻擊面**：於修補前，將管理介面（HTTP/HTTPS/SNMP 等）限制為僅限內網或受信任來源存取。
3. **強化輸入處理**：對會進入系統指令、檔案路徑、資料庫查詢的參數一律做白名單驗證與跳脫。
4. **補強認證與防偽**：管理端點強制身分驗證，狀態變更請求加入 anti-CSRF token。
5. **人工複驗**：對標記為「已識別、未自動驗證」與高風險「未重現」的項目，建議由人員手動確認。

---

## 七、附註與免責（Notes & Disclaimer）

- 本報告之「已確認」係以程式硬條件（回應關鍵字／HTTP 狀態碼）判定，非由語言模型自行宣稱，以確保結論可信。
- 標記為 **Attempted / Not Exploitable** 的 CVE，代表 Agent 已實際嘗試但未能在當前靶機環境重現，不代表該漏洞絕對不存在。
- 本測試於隔離實驗環境執行，僅供研究與防禦用途；實機評估請在取得授權後進行。
- 完整原始資料（含未截斷之回應）保存於 `share_memory.json`。
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(md)

    # 另存一份 .md 到扁平資料夾，讓網頁 API 直接抓最新一份（無須進各設備子資料夾）。
    # 這一步是網頁能顯示報告的關鍵：API 就是來這裡 glob "*.md"。
    try:
        with open(flat_md_path, "w", encoding="utf-8") as f:
            f.write(md)
    except Exception as e:
        log_info.warn(f"⚠️ 扁平資料夾 .md 副本寫入失敗（不影響主報告）: {e}")

    log_info.info(f"📄 報告已寫入: {path}")
    log_info.info(f"📄 報告副本（扁平，給網頁）: {flat_md_path}")
    return str(path)