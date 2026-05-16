import paho.mqtt.client as mqtt
import time
import os
import sys

# 1. 檢查參數
if len(sys.argv) < 2:
    print("使用說明: python3 sentMQTT.py <韌體名稱>")
    sys.exit(1)

FIRMWARE_NAME = sys.argv[1]
# BROKER_ADDRESS = "MQTT-respberryPi"
BROKER_ADDRESS = "172.19.0.1"
TOPIC = "QEMU_Log"
# 這是 FAP 持續寫入的原始日誌路徑 [cite: 1032, 1035]
LOGS_PATH = "./fap_log/fap_output.log"

# 2. 定義 MQTT 回呼函數 (使用 VERSION2)
def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print(f"[*] 成功連線至 Broker: {BROKER_ADDRESS}")
    else:
        print(f"[!] 連線失敗，原因代碼: {reason_code}")

def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    print(f"[!] 與 Broker 斷開連線 (代碼: {reason_code})，正在嘗試重新連線...")

# 3. 初始化 MQTT 客戶端
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_disconnect = on_disconnect
client.reconnect_delay_set(min_delay=1, max_delay=30) # 自動遞增重連等待時間

# 4. 建立連線並啟動背景循環
try:
    client.connect(BROKER_ADDRESS, 1883, keepalive=60)
    client.loop_start() # 在背景處理心跳與自動重連
except Exception as e:
    print(f"[!] 初始連線發生錯誤: {e}")
    # 這裡不退出，讓後續邏輯繼續嘗試或報錯

print(f"[*] 正在監控並定期清空: {LOGS_PATH}")

# 5. 主迴圈：監控檔案並發送
try:
    while True:
        if os.path.exists(LOGS_PATH):
            try:
                # 以「讀寫」模式開啟，避免讀取時 QEMU 無法寫入 [cite: 1041-1042]
                with open(LOGS_PATH, "r+", encoding="utf-8") as file:
                    lines = file.readlines()
                    
                    if lines:
                        # 批量發送：將所有行合併為一個訊息，降低網路開銷 [cite: 1048-1051]
                        # 加上韌體名稱標記，方便 Node-RED 分辨來源
                        payload = f"[{FIRMWARE_NAME}] \n" + "".join(lines)
                        
                        # 發送至 MQTT (QOS 1 確保至少送達一次)
                        info = client.publish(TOPIC, payload.strip(), qos=1)
                        info.wait_for_publish() # 確保資料已送出
                        
                        # 重要：發送完畢後立刻清空檔案 [cite: 1054-1055]
                        file.seek(0)      # 回到檔案開頭
                        file.truncate()   # 刪除內容
                        print(f"[{time.strftime('%H:%M:%S')}] 已發送批量日誌並清空檔案")
                
            except Exception as e:
                print(f"[!] 處理日誌檔案時發生錯誤: {e}")
        
        # 每隔 5 秒檢查一次 [cite: 1063]
        time.sleep(5)

except KeyboardInterrupt:
    print("\n[*] 使用者停止監控")
finally:
    client.loop_stop()
    client.disconnect()
    print("[*] 已安全關閉 MQTT 連線")