#!/bin/bash

# 0. 設定 (修正陣列語法)
firmware=("iot_dir880l_110b01" "dir601_revB_FW_201")
cd /app

# 1. 啟動資料庫
service postgresql start

# 2. 安裝轉發工具
if ! command -v socat &> /dev/null; then
    apt-get update && apt-get install -y socat > /dev/null
fi

# 3. 初始化工具 (維持原邏輯)
cd ./Tool/sasquatch
bash build.sh
cd ..
cd ..
wait

python3 modifyToolConfig.py
wait

# 6. 啟動 MQTT 數據傳送 (讓 Node-RED 有東西看)
python3 sentMQTT.py "${firmware[0]}" &
python3 openfirmware.py "${firmware[0]}" > ./fap_log/fap_output.log 2>&1 &
# python3 openfirmware.py "${firmware[1]}" 

# 5. 自動尋找 IP 並打通主機連線
while true; do
    TARGET_IP=$(grep -oP '(?<=Interface: br0, IP: )\d+\.\d+\.\d+\.\d+' /app/fap_log/fap_output.log)
    if [ ! -z "$TARGET_IP" ]; then
        echo "===================================================="
        echo "[+ ] 偵測到韌體 IP: $TARGET_IP"
        # 建立隧道，方便你從外部電腦存取
        socat TCP-LISTEN:80,fork,reuseaddr TCP:$TARGET_IP:80 &
        echo "[OK] 隧道已打通！請從你的電腦瀏覽: http://[樹莓派IP]:8080"
        echo "===================================================="
        break
    fi
    sleep 3
done

# 7. 讓容器保持活著，讓你手動測試
echo "[*] 系統已就緒。手動測試結束後，請使用 docker compose stop 關閉。"
wait