// 記錄目前正在執行的設備名稱
var started_device = "";
var current_tab = "";

// 顯示按鈕切換
async function switch_button_state(clickedButton) {
    const buttonValue = clickedButton.value;

    const AllButton = document.querySelectorAll(".switch_show_button");
    AllButton.forEach(btn => {
        if (btn !== clickedButton) {
            btn.style.backgroundColor = "";
            btn.style.color = "";
            btn.style.fontSize = "";
        } else {
            btn.style.backgroundColor = "#8C5A3C";
            btn.style.color = "#FFF8F0";
            btn.style.fontSize = "35px";
        }
    });

    const info_show_block = document.querySelector(".info_show_block");
    const info_title_name = document.querySelector(".info_title_name");
    const info_title_data = document.querySelector(".info_title_data");
    const pentest_state = document.querySelector(".pentest_state");
    info_show_block.innerHTML = "";
    info_title_name.textContent = "";
    info_title_data.textContent = "";
    pentest_state.textContent = "";
    current_tab = buttonValue;
   
    if (buttonValue === "Shared Memory") {
        info_title_name.textContent = "當前共享記憶體的資料";
        info_show_block.innerHTML = `<p>共享記憶體內容...</p>`;

    } else if (buttonValue === "Tool History") {
        info_title_name.textContent = "當前使用過的工具";
        info_show_block.innerHTML = `<p>工具歷史紀錄...</p>`;

    } else if (buttonValue === "AI Interaction") {
        info_title_name.textContent = "與 AI 的對話紀錄";
        info_show_block.innerHTML = `<p>AI 互動視窗...</p>`;

    } else if (buttonValue === "Terminal") {
        info_title_name.textContent = "當前工具:";
        info_show_block.innerHTML = log_history;

    } else if (buttonValue === "IoT Devices") {
        const devices_name = await get_devices_name();
        if (devices_name && devices_name.length > 0) {
            devices_name.forEach(file_name => {
                // 💡 核心檢查：判斷這台設備是否為正在執行的設備
                const isStarted = (file_name === started_device);
                const btnText = isStarted ? "Started" : "Start";
                const btnColor = isStarted ? "color: #092328;" : "";

                info_show_block.innerHTML += `
                    <div class="device_selection_block" id="${file_name}">
                        <p class="device_name">${file_name}</p>
                        <button class="device_button" id="${file_name}" style="${btnColor}" onclick="start_device(this)">${btnText}</button>
                    </div>
                `;
            });
        } else {
            info_show_block.innerHTML = `<p class="device_name">找不到任何 IoT 設備檔案</p>`;
        }

        
        if (info_title_name) info_title_name.textContent = "當前設備:";
        
        if (info_title_data) {
            if (started_device !== "") {
                info_title_data.textContent = started_device;
            } else {
                info_title_data.textContent = "尚未選擇設備";
            }
        }
    }
}

async function start_device(clickedButton) {
    if (started_device === "") {
        const deviceName = clickedButton.id; 
        
        clickedButton.textContent = "Started";
        clickedButton.style.color = "#092328";

        started_device = deviceName;

        const info_title_data = document.querySelector(".info_title_data");
        if (info_title_data) info_title_data.textContent = deviceName;
        initReceiver();
        await start_pentest();
    } else if (started_device !== clickedButton.id) {
        alert(`目前已有設備 [${started_device}] 正在執行中，請先停止它！`);
    }
}

let pentestWs = null;
var log_history = "";

// 初始化並連線 WebSocket 的函式
function initReceiver() {

    const wsB = new WebSocket("ws://localhost:8000/ws/receive_b");

    wsB.onopen = function() {
        console.log("B 成功連線到即時接收通道");
    };

    wsB.onmessage = function(event) {
    // 1. 解析後端傳過來的 JSON 資料
    const data = JSON.parse(event.data);
    // console.log("B 收到來自 API 轉發的資料：", data);

    const logContainer = document.querySelector(".info_show_block");
    if (logContainer) {

        // 3. 渲染到畫面上
        log_history += `
            <div class="log_${data.log_type}_section">
                <span class="log_type_${data.log_type}">${data.log_type}</span> 
                <span class="log_content_${data.log_type}">${data.log}</span>
            </div>
        `;

        if (current_tab === "Terminal") {
            logContainer.innerHTML = log_history;
        }
        
        // 4. 讓終端機自動捲動到最底部
        // logContainer.scrollTop = logContainer.scrollHeight;
    }
};

    wsB.onclose = function() {
        console.log("接收通道已斷開");
    };
}

// 取得裝置清單的 API 函式
async function get_devices_name() {
    try {
        const response = await fetch("http://localhost:8000/api/pentest/get_devices_list", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            }
        });

        if (response.ok) {
            // 透過 .json() 解析後端回傳的 JSON 物件
            const data = await response.json();
            return data.files_name; // 回傳檔名陣列
        } else {
            console.error("伺服器回應錯誤狀態碼:", response.status);
            return [];
        }
    } catch (error) {
        console.error("API 連線發生錯誤:", error);
        return [];
    }
}

// 頁面初始化
window.addEventListener("DOMContentLoaded", () => {
    pentest_button_init();
});

function pentest_button_init() {
    // 抓取第一顆按鈕
    const firstButton = document.querySelector(".switch_show_button");
   
    if (firstButton) {
        switch_button_state(firstButton);
        current_tab = firstButton.value;
    }
}

async function start_pentest() {
    const response = await fetch("http://localhost:8000/api/pentest/start_pentest", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        }
    });

    const status = response.status;

    if (status == 200) {
        log.console("Start Pentest Success!");
    }
}