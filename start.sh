#!/bin/bash
# 這是執行於 VirtualBox 主機端的環境清理與啟動腳本

echo "[*] 正在執行外部大掃除..."
# 1. 安全停止並移除舊容器，不會觸發 137 錯誤
docker compose down --remove-orphans

# 2. 清理無效的網路與暫存鏡像 (釋放空間)
docker system prune -f
docker container prune -f
docker network prune -f

# 3. 清理 root 權限產生的韌體殘留 (避免 OSError 28)
sudo rm -rf ./scratch/*

# 4. 強制解除所有異常掛載的 loop 裝置 (針對 DIR-880L 模擬失敗)
sudo losetup -D

echo "[*] 正在建構並啟動韌體模擬環境..."
docker compose up --build