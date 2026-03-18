#!/bin/bash

# 1. 定義路徑 (請確認資料夾名稱與此一致)
yml_files=("./MQTT/mqtt-broker.yml" "./mongoDB/mongo-db.yml" "./Node_RED/node-red.yml")

# 取得本機 IP，如果抓不到就用 localhost
IP_ADDR=$(hostname -I | awk '{print $1}')
BASE_IP=${IP_ADDR:-"127.0.0.1"}

echo "============================================"
echo "      🐳 IoT 系統整合啟動工具"
echo "============================================"

# 核心：建立虛擬橋樑
docker network create iot-network 2>/dev/null

for file in "${yml_files[@]}"; do
    if [ -f "$file" ]; then
        echo "🚀 啟動服務: $file"
        # 啟動容器
        docker compose -f "$file" up -d > /dev/null 2>&1

        # 修正判斷條件，使其匹配上面的定義
        if [[ "$file" == *"mqtt-broker.yml" ]]; then
            echo -e "✅ \033[32mMQTT Broker 已就緒\033[0m"
        elif [[ "$file" == *"mongo-db.yml" ]]; then
            echo -e "✅ \033[32mMongoDB 已就緒\033[0m"
        elif [[ "$file" == *"node-red.yml" ]]; then
            echo -e "✅ \033[32mNode-RED 已就緒\033[0m"
            # 💡 這裡會輸出網址
            echo -e "🔗 編輯器網址: \033[36mhttp://$BASE_IP:1880\033[0m"
        fi
        echo "--------------------------------------------"
    else
        echo -e "⚠️  找不到檔案: $file (請檢查路徑是否正確)"
    fi
done

echo "🎉 所有容器狀態："
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
