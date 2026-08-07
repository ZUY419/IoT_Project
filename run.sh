#!/bin/bash
firmware=("iot_dir880l_110b01" "dir601_revB_FW_201")
fwnum=1

# 1. 清理舊行程與殘留容器
pkill -f python
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

# 6. 正式啟動 Docker 大軍
echo "[+] 正在啟動專案 Docker 容器..."
cd Docker
docker compose up -d
cd ..

# 7. 確認 MQTT Broker 就緒
echo "[+] 正在確認 MQTT Broker (Port 1883) 是否完全就緒..."
sleep 3 

# 8. 最後才放行 AI Agent 與 MQTT 傳送腳本
echo "[+] 所有基礎建設就緒，啟動 sentMQTT..."
python3 ./Firmware/sentMQTT.py "${firmware[fwnum]}" &

echo "[+] ======= 所有服務已成功一鍵全自動依序啟動！ ======="
wait
