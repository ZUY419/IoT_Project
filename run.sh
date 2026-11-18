#!/bin/bash
# ================= 設定區 =================
firmware="$1"
MAX_RETRIES=60
RETRY_INTERVAL=3
# =========================================

if [ -z "$firmware" ]; then
    echo "[-] 錯誤: 未提供韌體名稱參數！用法: $0 <firmware_name>"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$SCRIPT_DIR"

echo "[+] ======= 啟動原生非 Docker 自動化滲透測試環境 ======="
echo "[+] 選擇韌體標籤: ${firmware}"

# 1. 清理舊行程與殘留容器
echo "[+] 1. 清理背景殘留行程..."
pkill -f openfirmware.py 2>/dev/null
pkill -f sentMQTT.py 2>/dev/null
pkill -f startPentest.sh 2>/dev/null
sleep 1
cd Docker && docker compose down && cd ..

# 2. 生成配置
python3 ./Firmware/modifyToolConfig.py

# 交接檔：openfirmware.py 會把 FAP 解析到的靶機 IP 寫進這裡
IP_FILE="$SCRIPT_DIR/Firmware/Firmware_logs/${firmware}_target_ip"
rm -f "$IP_FILE"

# 3. 啟動 FAP 初始化韌體（丟背景，記下 PID）
echo "[+] 啟動 FAP 初始化韌體與虛擬網路..."
python3 ./Firmware/openfirmware.py "$firmware" &
FAP_PID=$!
echo "[+] openfirmware.py 已啟動 (PID=${FAP_PID})"

# 4a. 等待 openfirmware.py 從 FAP 輸出解析出靶機 IP
echo "[+] 等待 FAP 解析靶機 IP..."
attempt=0
TARGET_IP=""
while [ -z "$TARGET_IP" ]; do
    if ! kill -0 "$FAP_PID" 2>/dev/null; then
        echo "[-] openfirmware.py 已結束且未取得 IP，韌體可能開機失敗。"
        exit 1
    fi
    if [ -s "$IP_FILE" ]; then
        TARGET_IP="$(tr -d '[:space:]' < "$IP_FILE")"
        break
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$MAX_RETRIES" ]; then
        echo "[-] 逾時: 尚未取得靶機 IP，但 FAP 保持運行以供除錯 (PID=${FAP_PID})。"
        echo "[-] run.sh 停止後續等待；請自行檢查 FAP 開機狀態。"
        exit 0
    fi
    echo "[-] 尚未取得靶機 IP... (${attempt}/${MAX_RETRIES})"
    sleep "$RETRY_INTERVAL"
done
echo "[+] 取得靶機 IP: ${TARGET_IP}"

# 4b. 等待該 IP 的 web 服務就緒（逾時不關 FAP）
echo "[+] 等待 http://${TARGET_IP} web 服務就緒..."
attempt=0
web_ready=0
until curl -s --connect-timeout 2 "http://${TARGET_IP}" > /dev/null; do
    if ! kill -0 "$FAP_PID" 2>/dev/null; then
        echo "[-] FAP 已結束，web 未就緒。"
        exit 1
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$MAX_RETRIES" ]; then
        echo "[-] 逾時: ${TARGET_IP} web 仍未就緒，但 FAP 保持運行以供除錯 (PID=${FAP_PID})。"
        break
    fi
    echo "[-] 靶機初始化中，網頁尚未就緒... (${attempt}/${MAX_RETRIES})"
    sleep "$RETRY_INTERVAL"
done

if curl -s --connect-timeout 2 "http://${TARGET_IP}" > /dev/null; then
    web_ready=1
    echo "[+] 偵測到 ${TARGET_IP} 網頁服務已上線！靶機準備就緒！"
fi
sleep 2

# 5. 建立綁定 br0 的 Docker 外部網路
docker network create -d bridge -o com.docker.network.bridge.name=br0 iot_bridge 2>/dev/null

# 設定 DEVICE_NAME 與 TARGET_IP 到 .env
ENV_FILE="$SCRIPT_DIR/Docker/ai/langchain/.env"
if [ -f "$ENV_FILE" ]; then
    if grep -q '^DEVICE_NAME=' "$ENV_FILE"; then
        sed -i "s|^DEVICE_NAME=.*|DEVICE_NAME=${firmware}|" "$ENV_FILE"
    else
        echo "DEVICE_NAME=${firmware}" >> "$ENV_FILE"
    fi
    if grep -q '^TARGET_IP=' "$ENV_FILE"; then
        sed -i "s|^TARGET_IP=.*|TARGET_IP=${TARGET_IP}|" "$ENV_FILE"
    else
        echo "TARGET_IP=${TARGET_IP}" >> "$ENV_FILE"
    fi
    echo "[+] 已設定 DEVICE_NAME=${firmware}, TARGET_IP=${TARGET_IP}"
else
    echo "[-] 警告: 找不到 $ENV_FILE。"
fi

# 6. 啟動 Docker（web 未就緒時仍保留 FAP，交由你決定是否續跑）
if [ "$web_ready" -eq 1 ]; then
    echo "[+] 正在啟動專案 Docker 容器..."
    cd Docker
    docker compose up -d
    cd ..
    echo "[+] ======= 所有服務已依序啟動！ ======="
else
    echo "[-] web 未就緒，略過 Docker 啟動；FAP 仍在背景運行 (PID=${FAP_PID})。"
fi

wait