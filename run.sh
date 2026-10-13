#!/bin/bash
# ================= 設定區 =================
firmware=$1
TARGET_IP="192.168.0.1"
MAX_RETRIES=60
# =========================================

if [ -z "$firmware" ]; then
    echo "[-] 錯誤: 未提供韌體名稱參數！用法: $0 <firmware_name>"
    exit 1
fi

# 獲取腳本所在目錄的絕對路徑
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

# 切換到該目錄
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

# 3. 啟動 FAP 初始化韌體（丟背景）
echo "[+] 啟動 FAP 初始化韌體與虛擬網路..."
python3 ./Firmware/openfirmware.py "${firmware[fwnum]}" &

TARGET_IP="192.168.0.1"
echo "[+] 正在監聽 QEMU 靶機虛擬作業系統開機狀態 (HTTP Port 80)..."

# 循環探測 192.168.0.1 的 80 埠口
while ! curl -s --connect-timeout 2 http://${TARGET_IP} > /dev/null; do
    echo "[-] 靶機作業系統初始化中，網頁尚未就緒..."
    sleep 3
done

echo "[+] 偵測到 192.168.0.1 網頁服務已成功上線！靶機 100% 準備就緒！"
sleep 2

# 5. 自動建立綁定 br0 的 Docker 外部網路
docker network create -d bridge -o com.docker.network.bridge.name=br0 iot_bridge 2>/dev/null

# ================= 新增：設定本次設備名稱 =================
# ai_agent 容器只讀 ai/langchain/.env（load_dotenv），讀不到這裡的 shell 變數，
# 所以要在 docker compose up 之前，把本次韌體名稱寫進 .env 的 DEVICE_NAME。
# 這樣容器就會把資料存到 workspace/data/<韌體名稱>/，每台設備互不污染。
ENV_FILE="$SCRIPT_DIR/Docker/ai/langchain/.env"
if [ -f "$ENV_FILE" ]; then
    if grep -q '^DEVICE_NAME=' "$ENV_FILE"; then
        sed -i "s|^DEVICE_NAME=.*|DEVICE_NAME=${firmware}|" "$ENV_FILE"
    else
        echo "DEVICE_NAME=${firmware}" >> "$ENV_FILE"
    fi
    echo "[+] 已設定 DEVICE_NAME=${firmware}（資料將存到 workspace/data/${firmware}/）"
else
    echo "[-] 警告: 找不到 $ENV_FILE，DEVICE_NAME 未設定，資料會落到預設資料夾。"
fi
# =========================================================

# 6. 正式啟動 Docker 大軍
echo "[+] 正在啟動專案 Docker 容器..."
cd Docker
docker compose up -d
cd ..

echo "[+] ======= 所有服務已成功一鍵全自動依序啟動！ ======="
wait