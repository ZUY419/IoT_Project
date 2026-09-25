import time
import requests

url = "http://localhost:8000/api/pentest/send_log"  # 你的 API 網址

class log_info:
    """
    level = 0(info), 1(warn), 2(error)
    """
    level = 0

    # 內部輔助方法：統一處理 API 發送與例外狀況
    @staticmethod
    def _send(log_content, log_type):
        payload = {
            "log": str(log_content),
            "log_type": log_type
        }
        try:
            # 🚀 實際發送 POST API 請求
            response = requests.post(url, json=payload, timeout=2)
            if response.status_code != 200:
                print(f"[API WARN] 伺服器回應狀態碼: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"[API ERROR] 無法連線到伺服器 ({url})，請確認 FastAPI 是否正在執行。")
        except Exception as e:
            print(f"[API ERROR] 發送日誌失敗: {e}")

    def info(log):
        if log_info.level >= 0:
            print(f"[INFO    ] {log}")
            log_info._send(log, "INFO")

    def tool(tool_name):
        if log_info.level <= 0:
            print("")
            print(f"[TOOL    ] {tool_name}")
            log_info._send(tool_name, "TOOL")

    def warn(log):
        if log_info.level <= 1:
            print(f"[WARN    ] {log}")
            log_info._send(log, "WARN")

    def error(log):
        if log_info.level <= 2:
            print(f"[ERROR   ] {log}")
            log_info._send(log, "ERROR")

    def AI_prompt(prompt):
        if log_info.level <= 0:
            print(f"[PROMPT  ] {prompt}")
            log_info._send(prompt, "AI_PROMPT")

    def AI_response(response):
        if log_info.level <= 0:
            print(f"[RESPONSE] {response}")
            log_info._send(response, "AI_RESPONSE")

# 測試迴圈
while True:
    log_info.info("Start Pentest!")
    log_info.tool("run_nmap_udp")
    log_info.warn("Port Cannot scan!")
    log_info.error("Argument Keyword Error!")
    log_info.AI_prompt("What is Pentest?")
    log_info.AI_response("I don't know what you say.")

    time.sleep(1)