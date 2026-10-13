"use strict";

// ===== 全域狀態管理 =====
const state = {
    started_device: "",
    current_tab: "",
    current_tool: "",
    log_history: "",
    ai_history: "",
    iot_log_history: "",          // IoT 模擬日誌歷史
    share_memory_data: null,
    tool_history_logs: [],
    stage: null,                  // {index,total,name} 目前階段
    done: false,                  // 流程是否已完成
    last_report_file: ""          // 最近一份報告檔名
};

// 效能設定
const CONFIG = {
    MAX_LOG_ENTRIES: 300,        // Terminal / AI / IoT 訊息最大保留數
    RECONNECT_INTERVAL: 3000,   // WebSocket 重連間隔 (ms)
    BOTTOM_THRESHOLD: 60         // 判定為「處於最底部」的容許像素範圍 (px)
};

let wsB = null;
let reconnectTimer = null;

// 動態伺服器位址設定 (自動匹配 Host，避免硬編碼 localhost)
const HOSTNAME = window.location.hostname || "localhost";
const API_BASE_URL = `http://${HOSTNAME}:8000`;
const WS_BASE_URL = `ws://${HOSTNAME}:8000`;

// ===== 智慧滾動輔助函式 =====

/**
 * 檢查指定的捲動容器目前是否處於（或接近）最底部
 * @param {HTMLElement} container 
 * @param {number} threshold 判定閾值（預設 60px）
 * @returns {boolean}
 */
function isScrolledNearBottom(container, threshold = CONFIG.BOTTOM_THRESHOLD) {
    if (!container) return false;
    const distanceToBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
    return distanceToBottom <= threshold;
}

/**
 * 將指定容器順暢滾動至最底部
 * @param {string} containerId 
 */
function scrollToBottom(containerId) {
    requestAnimationFrame(() => {
        const container = document.getElementById(containerId);
        if (container) {
            container.scrollTop = container.scrollHeight;
        }
    });
}

/**
 * 修剪過多的舊 DOM 節點以增進效能
 */
function pruneContainerChildren(container, maxCount) {
    while (container.children.length > maxCount) {
        container.removeChild(container.firstChild);
    }
}

function escapeHtml(text) {
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ===== 階段進度列 / 通知 =====

// 依 state.stage 更新頂部進度列（跨分頁持續顯示）
function updateStageBar() {
    const bar = document.getElementById("stage_bar");
    if (!bar) return;
    const st = state.stage;
    if (!st || !st.total) { bar.style.display = "none"; return; }
    bar.style.display = "flex";

    const total = st.total, cur = st.index;
    let steps = "";
    for (let i = 1; i <= total; i++) {
        let cls = "stage_step";
        if (state.done || i < cur) cls += " stage_done";
        else if (i === cur) cls += " stage_current";
        steps += `<div class="${cls}"><span class="stage_num">${i}</span></div>`;
        if (i < total) steps += `<div class="stage_line ${(state.done || i < cur) ? 'stage_line_done' : ''}"></div>`;
    }
    const label = state.done
        ? `✅ 已完成（共 ${total} 階段）`
        : `階段 ${cur}/${total}：${escapeHtml(st.name || "")}`;
    bar.innerHTML = `<div class="stage_steps">${steps}</div><div class="stage_label">${label}</div>`;
}

// 浮動通知
function showToast(msg, ms = 6000) {
    const root = document.getElementById("toast_root");
    if (!root) return;
    const el = document.createElement("div");
    el.className = "toast";
    el.innerHTML = escapeHtml(msg);
    root.appendChild(el);
    requestAnimationFrame(() => el.classList.add("show"));
    setTimeout(() => {
        el.classList.remove("show");
        setTimeout(() => el.remove(), 300);
    }, ms);
}

// 在「最終報告」分頁按鈕上加紅點，提示有新報告
function markReportReady() {
    const btn = document.querySelector(`.switch_show_button[value='Final Report']`);
    if (btn && !btn.querySelector(".ready_dot")) {
        const dot = document.createElement("span");
        dot.className = "ready_dot";
        btn.appendChild(dot);
    }
}
function clearReportReady() {
    const dot = document.querySelector(".switch_show_button[value='Final Report'] .ready_dot");
    if (dot) dot.remove();
}

// 清空上一輪測試在網頁上留下的所有顯示資料（不影響 started_device）
function clearAllData() {
    state.log_history = "";
    state.ai_history = "";
    state.iot_log_history = "";
    state.share_memory_data = null;
    state.tool_history_logs = [];
    state.current_tool = "";
    state.stage = null;
    state.done = false;
    state.last_report_file = "";
    clearReportReady();
    updateStageBar();
    // 重新渲染目前分頁，讓畫面上的舊內容一併清空
    const activeBtn = document.querySelector(".switch_show_button.action");
    if (activeBtn) switch_button_state(activeBtn);
}

// ===== 1. 分頁切換與 UI 渲染 =====
async function switch_button_state(clickedButton) {
    if (!clickedButton) return;

    const buttonValue = clickedButton.value;
    state.current_tab = buttonValue;

    // 按鈕高亮切換
    const allButtons = document.querySelectorAll(".switch_show_button");
    allButtons.forEach(btn => {
        const isSelected = (btn === clickedButton);
        btn.classList.toggle("action", isSelected);
        btn.style.fontSize = isSelected ? "22px" : "";
    });

    const info_show_block = document.querySelector(".info_show_block");
    const info_title_name = document.querySelector(".info_title_name");
    const info_title_data = document.querySelector(".info_title_data");
    const pentest_state = document.querySelector(".pentest_state");

    if (!info_show_block) return;

    // 清空顯示區塊與標題
    info_show_block.innerHTML = "";
    if (info_title_name) info_title_name.textContent = "";
    if (info_title_data) info_title_data.textContent = "";
    if (pentest_state) pentest_state.textContent = "";

    // 分頁渲染邏輯 (切換分頁時預設拉到底部)
    switch (buttonValue) {
        case "Shared Memory":
            if (info_title_name) info_title_name.textContent = "當前共享記憶體的資料";
            render_share_memory();
            break;

        case "Tool History":
            if (info_title_name) info_title_name.textContent = "當前使用過的工具";
            render_tool_history();
            break;

        case "AI Interaction":
            if (info_title_name) info_title_name.textContent = "與 AI 的對話紀錄";
            info_show_block.innerHTML = `<div class="ai_show_block" id="ai_container">${state.ai_history}</div>`;
            scrollToBottom("ai_container");
            break;

        case "Final Report":
            if (info_title_name) info_title_name.textContent = "最終滲透測試報告";
            if (info_title_data) {
                info_title_data.textContent = state.started_device !== ""
                    ? state.started_device : "（顯示最新一份報告）";
            }
            if (pentest_state) {
                pentest_state.innerHTML = `<button class="terminal_restart_btn" onclick="render_final_report()">重新整理</button>`;
            }
            clearReportReady();
            render_final_report();
            break;

        case "Terminal":
            if (info_title_name) info_title_name.textContent = "當前工具";
            if (info_title_data) {
                info_title_data.textContent = state.current_tool !== "" 
                    ? state.current_tool 
                    : "尚未開啟設備或是尚未使用到任何工具";
            }
            // 在標題列右側放置「重新開始」按鈕 (僅 Terminal 分頁顯示)
            if (pentest_state) {
                pentest_state.innerHTML = `<button class="terminal_restart_btn" onclick="restart_ai(this)">重新開始</button>`;
            }
            info_show_block.innerHTML = `<div class="terminal_show_block" id="terminal_container">${state.log_history}</div>`;
            scrollToBottom("terminal_container");
            break;

        case "IoT Log":
            if (info_title_name) info_title_name.textContent = "模擬 IoT 日誌";
            if (info_title_data) {
                info_title_data.textContent = state.started_device !== ""
                    ? state.started_device
                    : "尚未開啟任何設備";
            }
            info_show_block.innerHTML = state.iot_log_history !== ""
                ? `<div class="iot_log_block" id="iot_log_container">${state.iot_log_history}</div>`
                : `<div class="iot_log_block" id="iot_log_container"><div class="memory_empty_notice">尚未收到模擬 IoT 日誌...</div></div>`;
            scrollToBottom("iot_log_container");
            break;

        case "IoT Devices":
            if (info_title_name) info_title_name.textContent = "當前設備:";
            if (info_title_data) {
                info_title_data.textContent = state.started_device !== "" ? state.started_device : "尚未選擇設備";
            }
            await render_iot_devices(info_show_block);
            break;

        default:
            console.warn(`[UI] 未知的分頁標籤: ${buttonValue}`);
            break;
    }
}

// 渲染 IoT 設備選單
async function render_iot_devices(container) {
    const devices_name = await get_devices_name();
    if (devices_name && devices_name.length > 0) {
        const devicesHTML = devices_name.map(file_name => {
            const isStarted = (file_name === state.started_device);
            return `
                <div class="device_selection_block" id="dev_${escapeHtml(file_name)}">
                    <p class="device_name">${escapeHtml(file_name)}</p>
                    <div class="device_btn_group">
                        <button class="device_button start_btn ${isStarted ? 'active' : ''}" 
                                id="start_${escapeHtml(file_name)}" 
                                onclick="start_device('${escapeHtml(file_name)}')" 
                                ${isStarted ? 'disabled' : ''}>
                            ${isStarted ? 'Running' : 'Start'}
                        </button>
                        <button class="device_button stop_btn" 
                                id="stop_${escapeHtml(file_name)}" 
                                onclick="stop_device('${escapeHtml(file_name)}')" 
                                ${!isStarted ? 'disabled' : ''}>
                            Stop
                        </button>
                    </div>
                </div>
            `;
        }).join("");
        container.innerHTML = devicesHTML;
    } else {
        container.innerHTML = `<p class="device_name" style="color: #f87171; padding: 10px;">找不到任何 IoT 設備檔案</p>`;
    }
}

// ===== 2. 滲透測試設備控制 (Start / Stop) =====
async function start_device(deviceName) {
    if (state.started_device === "") {
        state.started_device = deviceName;

        // 新一輪測試：先清掉上一輪留在網頁的所有資料（log / AI / IoT 日誌 / 共享記憶體 / 進度）
        clearAllData();

        const info_title_data = document.querySelector(".info_title_data");
        if (info_title_data) info_title_data.textContent = deviceName;

        await start_pentest(deviceName);

        const currentBtn = document.querySelector(`.switch_show_button[value='IoT Devices']`);
        if (currentBtn) switch_button_state(currentBtn);
    } else if (state.started_device !== deviceName) {
        alert(`目前已有設備 [${state.started_device}] 正在執行中，請先停止它！`);
    }
}

async function stop_device(deviceName) {
    if (state.started_device === deviceName) {
        if (confirm(`確定要停止設備 [${deviceName}] 的滲透測試嗎？`)) {
            await stop_pentest();
            state.started_device = "";

            const info_title_data = document.querySelector(".info_title_data");
            if (info_title_data) info_title_data.textContent = "尚未選擇設備";

            const currentBtn = document.querySelector(`.switch_show_button[value='IoT Devices']`);
            if (currentBtn) switch_button_state(currentBtn);
        }
    }
}

// ===== 3. WebSocket 即時通訊接收器（含 Smart Auto-Scroll） =====
function initReceiver() {
    if (wsB && (wsB.readyState === WebSocket.OPEN || wsB.readyState === WebSocket.CONNECTING)) return;

    if (reconnectTimer) clearTimeout(reconnectTimer);

    wsB = new WebSocket(`${WS_BASE_URL}/ws/receive_b`);

    wsB.onopen = function() {
        console.log("[WebSocket] 成功連線至即時日誌接收通道");
    };

    wsB.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            const log_type = (data.log_type || "").toUpperCase();

            // 分流 1：AI 對話訊息
            if (log_type === "AI_PROMPT" || log_type === "AI_RESPONSE") {
                const isPrompt = log_type === "AI_PROMPT";
                const roleClass = isPrompt ? "ai_msg_prompt" : "ai_msg_response";
                const roleLabel = isPrompt ? "PROMPT / User" : "AI RESPONSE";

                const newAiHTML = `
                    <div class="ai_message_card ${roleClass}">
                        <div class="ai_msg_header">${roleLabel}</div>
                        <div class="ai_msg_body">${escapeHtml(data.log)}</div>
                    </div>
                `;
                state.ai_history += newAiHTML;

                if (state.current_tab === "AI Interaction") {
                    const aiContainer = document.getElementById("ai_container");
                    if (aiContainer) {
                        // 插入新數據前判斷是否在底部
                        const isAtBottom = isScrolledNearBottom(aiContainer);

                        aiContainer.insertAdjacentHTML('beforeend', newAiHTML);
                        pruneContainerChildren(aiContainer, CONFIG.MAX_LOG_ENTRIES);

                        // 只有當原本就在底部時才自動滾動
                        if (isAtBottom) {
                            scrollToBottom("ai_container");
                        }
                    }
                }

            // 分流 2：共享記憶體更新
            } else if (log_type === "SHARE_MEMORY") {
                state.share_memory_data = data.log;

                if (state.current_tab === "Shared Memory") {
                    render_share_memory();
                }

            // 分流 2.1：階段進度 (agent 每進一階段送一次)
            } else if (log_type === "STAGE") {
                try {
                    const st = (typeof data.log === "string") ? JSON.parse(data.log) : data.log;
                    state.stage = st;        // {index,total,name}
                    state.done = false;
                    updateStageBar();
                } catch (e) { console.warn("STAGE 解析失敗", e); }

            // 分流 2.2：流程完成 (agent 跑完送一次) → 通知 + 自動載入報告
            } else if (log_type === "DONE") {
                try {
                    const info = (typeof data.log === "string") ? JSON.parse(data.log) : data.log;
                    state.done = true;
                    state.last_report_file = info.report_file || "";
                    updateStageBar();
                    markReportReady();
                    showToast("✅ 滲透測試完成！報告已產生，可至「最終報告」檢視。");
                    // 若正停在最終報告分頁，直接刷新載入最新；否則標記紅點提示
                    if (state.current_tab === "Final Report") {
                        render_final_report();
                    }
                } catch (e) { console.warn("DONE 解析失敗", e); }

            // 分流 2.5：IoT 模擬日誌 (由 openfirmware.py 以 IOT_LOG 型別送入)
            } else if (log_type === "IOT_LOG") {
                const rowHTML = buildIotLogRowHTML(data.log);
                state.iot_log_history += rowHTML;

                if (state.current_tab === "IoT Log") {
                    const iotContainer = document.getElementById("iot_log_container");
                    if (iotContainer) {
                        // 若容器內還是「空日誌」提示，先清掉再插入第一筆
                        const emptyNotice = iotContainer.querySelector(".memory_empty_notice");
                        if (emptyNotice) iotContainer.innerHTML = "";

                        const isAtBottom = isScrolledNearBottom(iotContainer);
                        iotContainer.insertAdjacentHTML('beforeend', rowHTML);
                        pruneContainerChildren(iotContainer, CONFIG.MAX_LOG_ENTRIES);
                        if (isAtBottom) scrollToBottom("iot_log_container");
                    }
                }

            // 分流 3：一般 Terminal Log (INFO, TOOL, WARN, ERROR 等)
            } else {
                if (log_type === "TOOL") {
                    state.current_tool = data.log;

                    const info_title_data = document.querySelector(".info_title_data");
                    // 修正：原本誤用未定義的 current_tool，應讀取 state.current_tool
                    if (info_title_data && state.current_tab === "Terminal") {
                        info_title_data.textContent = state.current_tool;
                    }

                    state.tool_history_logs.push(data);
                    
                    if (state.current_tab === "Tool History") {
                        render_tool_history();
                    }
                }

                const newTerminalLogHTML = `
                    <div class="log_${log_type}_section">
                        <span class="log_type_${log_type}">${log_type}</span> 
                        <span class="log_content_${log_type}">${escapeHtml(data.log)}</span>
                    </div>
                `;
                state.log_history += newTerminalLogHTML;

                if (state.current_tab === "Terminal") {
                    const termContainer = document.getElementById("terminal_container");
                    if (termContainer) {
                        // 插入新 Log 前先檢測使用者位置
                        const isAtBottom = isScrolledNearBottom(termContainer);

                        termContainer.insertAdjacentHTML('beforeend', newTerminalLogHTML);
                        pruneContainerChildren(termContainer, CONFIG.MAX_LOG_ENTRIES);

                        // 若原本就在最底下，才跟著自動滑動
                        if (isAtBottom) {
                            scrollToBottom("terminal_container");
                        }
                    }
                }
            }
        } catch (e) {
            console.error("解析 WebSocket 廣播資料失敗:", e);
        }
    };

    wsB.onclose = function() {
        console.warn(`[WebSocket] 連線中斷，${CONFIG.RECONNECT_INTERVAL / 1000} 秒後自動重連...`);
        reconnectTimer = setTimeout(() => {
            initReceiver();
        }, CONFIG.RECONNECT_INTERVAL);
    };

    wsB.onerror = function(err) {
        console.error("[WebSocket 錯誤]", err);
    };
}

// ===== 4. 工具歷史紀錄 (Tool History) 渲染器 =====
function render_tool_history() {
    const info_show_block = document.querySelector(".info_show_block");
    if (!info_show_block) return;

    if (state.tool_history_logs.length === 0) {
        info_show_block.innerHTML = `<p style="color: #FFF8F0; opacity: 0.7; padding: 20px; text-align: center;">尚未收到工具執行紀錄...</p>`;
        return;
    }

    let html = `<div style="display: flex; flex-direction: column; gap: 10px; height: 100%; overflow-y: auto;">`;
    state.tool_history_logs.forEach((item, index) => {
        html += `
            <div class="tool_card">
                <div class="tool_card_header">
                    <div class="tool_title_group">
                        <span class="tool_badge">Tool #${index + 1}</span>
                        <span class="tool_name">${escapeHtml(item.log_type)}</span>
                    </div>
                </div>
                <div class="tool_card_body">
                    <div class="tool_argument">${escapeHtml(item.log)}</div>
                </div>
            </div>
        `;
    });
    html += `</div>`;

    info_show_block.innerHTML = html;
}

// ===== 4.5. IoT 模擬日誌：單筆渲染 =====
function buildIotLogRowHTML(rawLog) {
    let entry;
    try {
        entry = (typeof rawLog === "string") ? JSON.parse(rawLog) : rawLog;
    } catch (e) {
        entry = { label: "Nothing", message: String(rawLog), timestamp: "" };
    }

    const rawLabel = (entry.label || "Nothing").toUpperCase();
    const map = {
        "ERROR":   { cls: "ERROR",   text: "ERROR" },
        "WARING":  { cls: "WARN",    text: "WARN" },   // 對應 Python 端的拼字
        "WARNING": { cls: "WARN",    text: "WARN" },
        "NETWORK": { cls: "NETWORK", text: "NETWORK" },
        "NOTHING": { cls: "INFO",    text: "INFO" }
    };
    const meta = map[rawLabel] || { cls: "INFO", text: rawLabel };

    const time = entry.timestamp ? escapeHtml(entry.timestamp) : "";
    const msgRaw = entry.message != null ? String(entry.message) : "";

    // Network 若是網址，渲染成可點擊連結，方便直接開啟模擬 IoT 介面
    let msgHtml;
    if (meta.cls === "NETWORK" && /^https?:\/\//i.test(msgRaw.trim())) {
        const safeUrl = escapeHtml(msgRaw.trim());
        msgHtml = `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer" class="iot_log_link">${safeUrl}</a>`;
    } else {
        msgHtml = escapeHtml(msgRaw);
    }

    return `
        <div class="iot_log_row">
            ${time ? `<span class="iot_log_time">${time}</span>` : ""}
            <span class="iot_log_label iot_log_label_${meta.cls}">${meta.text}</span>
            <span class="iot_log_msg iot_log_msg_${meta.cls}">${msgHtml}</span>
        </div>
    `;
}

// ===== 5. 通用型共享記憶體 (Shared Memory) 動態渲染器 =====
function render_share_memory() {
    const info_show_block = document.querySelector(".info_show_block");
    if (!info_show_block) return;

    const rawData = state.share_memory_data;
    if (!rawData || (typeof rawData === "string" && rawData.trim() === "")) {
        info_show_block.innerHTML = `<div class="memory_empty_notice">尚未收到共享記憶體更新資料...</div>`;
        return;
    }

    let parsedData;
    try {
        parsedData = (typeof rawData === "string") ? JSON.parse(rawData) : rawData;
    } catch (e) {
        info_show_block.innerHTML = `<div class="memory_show_block">${escapeHtml(String(rawData))}</div>`;
        return;
    }

    let html = `<div class="memory_dashboard">`;
    html += renderGenericJson(parsedData, 0);

    html += `
        <details class="raw_json_details">
            <summary>📄 檢視原始 JSON 資料 (Raw JSON)</summary>
            <div class="memory_show_block">${escapeHtml(JSON.stringify(parsedData, null, 2))}</div>
        </details>
    `;
    html += `</div>`;

    info_show_block.innerHTML = html;
}

// 遞迴解析任意 JSON 物件/陣列結構
function renderGenericJson(data, level = 0) {
    if (data === null || data === undefined) {
        return `<span class="val_null">null</span>`;
    }

    if (typeof data !== "object") {
        return `<span class="val_primitive">${escapeHtml(String(data))}</span>`;
    }

    // 陣列處理
    if (Array.isArray(data)) {
        if (data.length === 0) return `<div class="val_empty">[ 空清單 ]</div>`;

        const isArrayOfObjects = data.every(item => typeof item === "object" && item !== null && !Array.isArray(item));

        if (isArrayOfObjects) {
            const allKeys = Array.from(new Set(data.flatMap(item => Object.keys(item))));

            let tableHtml = `<div class="table_responsive"><table class="mem_table"><thead><tr>`;
            allKeys.forEach(k => {
                tableHtml += `<th>${escapeHtml(formatKeyName(k))}</th>`;
            });
            tableHtml += `</tr></thead><tbody>`;

            data.forEach(item => {
                tableHtml += `<tr>`;
                allKeys.forEach(k => {
                    const val = item[k];
                    tableHtml += `<td>${val !== undefined ? renderGenericJson(val, level + 1) : '<span class="val_null">-</span>'}</td>`;
                });
                tableHtml += `</tr>`;
            });

            tableHtml += `</tbody></table></div>`;
            return tableHtml;
        } else {
            let listHtml = `<div class="generic_array_group">`;
            data.forEach(item => {
                listHtml += `<div class="array_tag_item">${renderGenericJson(item, level + 1)}</div>`;
            });
            listHtml += `</div>`;
            return listHtml;
        }
    }

    // 物件處理
    const entries = Object.entries(data);
    if (entries.length === 0) return `<div class="val_empty">{ 空物件 }</div>`;

    const primitives = entries.filter(([_, v]) => typeof v !== "object" || v === null);
    const complex = entries.filter(([_, v]) => typeof v === "object" && v !== null);

    let objHtml = "";

    if (primitives.length > 0) {
        const gridContent = primitives.map(([k, v]) => `
            <div class="mem_info_item">
                <span class="mem_label">${escapeHtml(formatKeyName(k))}:</span>
                <span class="mem_val">${escapeHtml(String(v))}</span>
            </div>
        `).join("");

        if (level === 0) {
            objHtml += `
                <div class="mem_card">
                    <div class="mem_card_title">📌 基本屬性 (Properties)</div>
                    <div class="mem_info_grid">${gridContent}</div>
                </div>
            `;
        } else {
            objHtml += `<div class="mem_info_grid" style="margin-bottom: 10px;">${gridContent}</div>`;
        }
    }

    complex.forEach(([k, v]) => {
        const title = formatKeyName(k);
        objHtml += `
            <div class="mem_card">
                <div class="mem_card_title">📂 ${escapeHtml(title)}</div>
                <div class="mem_card_body">
                    ${renderGenericJson(v, level + 1)}
                </div>
            </div>
        `;
    });

    return objHtml;
}

// 格式化 Key 名稱 (例：device_information -> Device Information)
function formatKeyName(key) {
    return String(key)
        .replace(/([a-z])([A-Z])/g, '$1 $2')
        .replace(/[_-]+/g, ' ')
        .replace(/\b\w/g, l => l.toUpperCase());
}

// ===== 5.5 最終報告 (Final Report) 渲染器 =====
const RPT_RESULT = {
    hit:         { label: "驗證命中", cls: "rpt_hit" },
    dos_skipped: { label: "DoS 略過", cls: "rpt_dos" },
    attempted:   { label: "未果",    cls: "rpt_att" }
};

async function render_final_report() {
    const info_show_block = document.querySelector(".info_show_block");
    if (!info_show_block) return;
    info_show_block.innerHTML = `<div class="memory_empty_notice">正在載入最新報告...</div>`;

    let res;
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/get_report`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ device_name: state.started_device || null })
        });
        res = await response.json();
    } catch (e) {
        info_show_block.innerHTML = `<div class="memory_empty_notice">無法連線 API 取得報告：${escapeHtml(String(e))}</div>`;
        return;
    }

    if (!res || res.status !== 200 || !res.report) {
        info_show_block.innerHTML = `<div class="memory_empty_notice">${escapeHtml((res && res.message) || "尚無報告，請先完成一次滲透測試。")}</div>`;
        return;
    }
    info_show_block.innerHTML = buildReportHTML(res.report, res.file);
}

function buildReportHTML(d, fileName) {
    const s = d.summary || {}, c = s.classification || {};
    const hit = c.hit || { total: 0 }, att = c.attempted || { total: 0 }, dos = c.dos_skipped || 0;
    const totalV = s.verified_items || 0;
    const tot = Math.max(totalV, (hit.total || 0) + dos + (att.total || 0), 1);

    const card = (n, l) => `<div class="rpt_card"><div class="rpt_card_n">${n == null ? 0 : n}</div><div class="rpt_card_l">${escapeHtml(l)}</div></div>`;
    const seg = (cls, v) => v ? `<div class="${cls}" style="width:${(v / tot * 100)}%" title="${v}">${(v / tot * 100) > 8 ? v : ""}</div>` : "";
    const leg = (cls, txt) => `<span class="rpt_leg"><i class="rpt_dot ${cls}"></i>${escapeHtml(txt)}</span>`;

    let html = `<div class="rpt_dashboard">`;

    // 中繼資訊
    html += `<div class="rpt_meta">
        <span>設備：<b>${escapeHtml(d.device)}</b></span>
        <span>目標：<b>${escapeHtml(d.target_ip)}</b></span>
        <span>產生時間：<b>${escapeHtml(d.generated_at)}</b></span>
        <span>模型：<b>${escapeHtml(d.model)}</b></span>
        ${fileName ? `<span>檔案：<b>${escapeHtml(fileName)}</b></span>` : ""}
    </div>`;

    // 摘要卡片
    html += `<div class="rpt_cards">
        ${card(s.open_ports, "開放埠 (TCP+UDP)")}
        ${card(s.analyzed_web_endpoints, "已分析 Web 端點")}
        ${card(s.retrieved_cves, "檢索出的 CVE")}
        ${card(totalV, "進入驗證的項目")}
    </div>`;

    // 驗證結果分類
    html += `<div class="mem_card"><div class="mem_card_title">📊 驗證結果分類</div>
        <div class="rpt_bar">
            ${seg("rpt_seg_hit", hit.total || 0)}
            ${seg("rpt_seg_dos", dos)}
            ${seg("rpt_seg_att", att.total || 0)}
        </div>
        <div class="rpt_legend">
            ${leg("rpt_seg_hit", `✅ 驗證命中 ${hit.total || 0}（資訊洩漏 ${hit.disclosure || 0} / CVE ${hit.cve || 0}）`)}
            ${leg("rpt_seg_dos", `⏭️ DoS 主動略過 ${dos}`)}
            ${leg("rpt_seg_att", `❌ Attempted ${att.total || 0}（PoC ${att.poc || 0} / LLM ${att.llm || 0}${att.other ? " / 其他 " + att.other : ""}）`)}
        </div>
    </div>`;

    // 資產偵察（埠）
    html += `<div class="mem_card"><div class="mem_card_title">🔌 資產偵察（開放埠）</div>${portsTableHTML(d.ports || {})}</div>`;

    // Web 資訊
    const web = d.web || {}, v = web.vendor || {}, dt = web.device_type || {}, urls = web.analyzed_urls || [];
    html += `<div class="mem_card"><div class="mem_card_title">🌐 Web 端點分析</div>
        <div class="rpt_kv">廠商：<b>${escapeHtml(v.name || "Unknown")}</b>　|　設備類型：<b>${escapeHtml(dt.category || "Unknown")}</b></div>
        ${urls.length ? `<div class="generic_array_group">${urls.map(u => `<div class="array_tag_item">${escapeHtml(u)}</div>`).join("")}</div>` : `<div class="val_empty">（無 Web 端點）</div>`}
    </div>`;

    // Findings
    const findings = d.findings || [];
    html += `<div class="mem_card"><div class="mem_card_title">🛡️ 漏洞驗證詳情（${findings.length} 筆）</div>`;
    if (findings.length) {
        html += findings.map(buildFindingHTML).join("");
    } else {
        html += `<div class="val_empty">（無驗證項目）</div>`;
    }
    html += `</div>`;

    html += `</div>`;
    return html;
}

function portsTableHTML(ports) {
    const rows = [];
    ["TCP", "UDP"].forEach(proto => {
        (ports[proto] || []).forEach(p => {
            rows.push(`<tr><td>${proto}</td><td>${escapeHtml(p.port)}</td><td>${escapeHtml(p.service || "")}</td><td>${escapeHtml(p.version || "")}</td></tr>`);
        });
    });
    if (!rows.length) return `<div class="val_empty">（無開放埠資料）</div>`;
    return `<div class="table_responsive"><table class="mem_table"><thead><tr><th>協定</th><th>Port</th><th>服務</th><th>版本</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

function buildFindingHTML(f) {
    const r = RPT_RESULT[f.result] || RPT_RESULT.attempted;
    const atts = f.attempts || [];
    let tags = "";
    if (f.cvss && f.cvss !== "N/A") tags += `<span class="rpt_tag">CVSS ${escapeHtml(f.cvss)}</span>`;
    if (f.is_disclosure) tags += `<span class="rpt_tag">資訊洩漏</span>`;
    if (f.method) tags += `<span class="rpt_tag">${f.method === "poc" ? "PoC 改寫" : "LLM 探測"}</span>`;

    let body = "";
    if (f.description) body += `<div class="rpt_kv"><b>描述：</b>${escapeHtml(f.description)}</div>`;
    if (f.success_cmd) body += `<div class="rpt_kv"><b>成功指令：</b></div><div class="tool_argument">${escapeHtml(f.success_cmd)}</div>`;
    if (atts.length) {
        body += `<div class="table_responsive" style="margin-top:8px"><table class="mem_table"><thead><tr><th>#</th><th>指令</th><th>判定</th><th>回應節錄</th></tr></thead><tbody>`;
        body += atts.map(a => `<tr>
            <td>${escapeHtml(a.n)}</td>
            <td style="font-family:'Fira Code',monospace;word-break:break-all">${escapeHtml(a.cmd)}</td>
            <td>${a.judged_success ? '<span class="rpt_ok">命中</span>' : '<span class="rpt_no">未命中</span>'}</td>
            <td style="word-break:break-all">${escapeHtml(a.response_excerpt)}</td>
        </tr>`).join("");
        body += `</tbody></table></div>`;
    }

    return `<details class="rpt_finding">
        <summary>
            <span class="rpt_pill ${r.cls}">${r.label}</span>
            <span class="rpt_fid">${escapeHtml(f.id)}</span>
            ${tags}
            <span class="rpt_grow"></span>
            <span class="rpt_count">${atts.length} 次嘗試 ▾</span>
        </summary>
        <div class="rpt_finding_body">${body}</div>
    </details>`;
}

// ===== 6. 輔助 API 呼叫 =====
async function get_devices_name() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/get_devices_list`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (response.ok) {
            const data = await response.json();
            return data.files_name || [];
        } else {
            return [];
        }
    } catch (error) {
        console.error("取得裝置清單失敗:", error);
        return [];
    }
}

async function start_pentest(deviceName) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/start_pentest`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ device_name: deviceName })
        });

        if (response.ok) {
            console.log(`[Pentest] 成功啟動裝置 [${deviceName}]！`);
        } else {
            const errData = await response.json();
            alert(`啟動失敗: ${errData.message || response.statusText}`);
        }
    } catch (error) {
        console.error("無法啟動測試:", error);
    }
}

async function stop_pentest() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/stop_pentest`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (response.ok) {
            const data = await response.json();
            console.log(`[Pentest] ${data.message}`);
        } else {
            console.error("發送停止請求失敗");
        }
    } catch (error) {
        console.error("無法發送停止滲透測試請求:", error);
    }
}

// 重新啟動 AI (呼叫 Docker/restartAI.sh)
async function restart_ai(btn) {
    if (!confirm("確定要重新啟動 AI (restartAI.sh) 嗎？")) return;

    const original = btn ? btn.textContent : "";
    if (btn) {
        btn.disabled = true;
        btn.textContent = "重啟中...";
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/restart_ai`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        const data = await response.json().catch(() => ({}));

        if (response.ok && data.status === 200) {
            console.log(`[Restart AI] ${data.message || "已送出重啟指令"}`);
            // 重新啟動：清掉上一輪在網頁留下的所有資料（保留目前設備）
            clearAllData();
            showToast("🔄 已重新啟動，網頁資料已清空。");
        } else {
            alert(`重新啟動失敗: ${data.message || response.statusText}`);
        }
    } catch (error) {
        console.error("無法發送重新啟動請求:", error);
        alert("無法發送重新啟動請求，請確認 API 伺服器是否正在運行。");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = original;
        }
    }
}

function pentest_button_init() {
    const firstButton = document.querySelector(".switch_show_button");
    if (firstButton) {
        switch_button_state(firstButton);
    }
}

// 頁面初始化與卸載事件
window.addEventListener("DOMContentLoaded", () => {
    initReceiver();
    pentest_button_init();
});

window.addEventListener("beforeunload", () => {
    if (wsB) {
        wsB.onclose = null; // 避免離開頁面時觸發重連機制
        wsB.close();
    }
});