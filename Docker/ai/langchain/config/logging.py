# Docker/ai/langchain/config/logging.py
import os
import json
import requests

import util  # ⚠️【修正重點】恢復 import，供 share_memory() 實際持久化使用

# 從環境變數讀取 FastAPI 端點，預設指向 /api/pentest/send_log
FASTAPI_LOG_URL = "http://172.17.0.1:8000/api/pentest/send_log"
ENABLE_FASTAPI_LOGGING = True


class log_info:
    level = 0

    @staticmethod
    def _send_to_fastapi(log_type: str, log_content: str):
        """
        將 Log 以 JSON 格式傳送給 FastAPI 端點 (/api/pentest/send_log)
        Payload 結構嚴格對應 CommandPayload (包含 log 與 log_type)
        """
        if not ENABLE_FASTAPI_LOGGING or not FASTAPI_LOG_URL:
            return

        payload = {
            "log": str(log_content),
            "log_type": str(log_type)
        }

        try:
            requests.post(FASTAPI_LOG_URL, json=payload, timeout=2.0)
        except Exception:
            pass

    @staticmethod
    def info(log):
        if log_info.level >= 0:
            print(f"[INFO    ] {log}")
            log_info._send_to_fastapi("info", log)

    @staticmethod
    def tool(tool):
        if log_info.level <= 0:
            print(f"[TOOL    ] {tool}")
            log_info._send_to_fastapi("tool", tool)

    @staticmethod
    def AI_prompt(prompt):
        if log_info.level <= 0:
            print(f"[PROMPT  ] {prompt}")
            log_info._send_to_fastapi("ai_prompt", prompt)

    @staticmethod
    def AI_response(response):
        if log_info.level <= 0:
            print(f"[RESPONSE] {response}")
            log_info._send_to_fastapi("ai_response", response)

    @staticmethod
    def warn(log):
        if log_info.level <= 1:
            print(f"[WARN    ] {log}")
            log_info._send_to_fastapi("warn", log)

    @staticmethod
    def error(log):
        if log_info.level <= 2:
            print(f"[ERROR   ] {log}")
            log_info._send_to_fastapi("error", log)

    @staticmethod
    def share_memory(data):
        """⚠️【根因修正】這裡原本把 util.update_share_memory(data) 註解掉了，
        導致呼叫端誤以為呼叫此方法就等於已經持久化，實際上只是送去前端顯示用的 log。
        三個工具函式 (nmap_scan_tcp / nmap_scan_udp / analyze_web_page) 完全依賴此方法
        來保存 ports 與 web_footprints，這個 bug 導致它們的結果從未真正寫回磁碟。
        """
        util.update_share_memory(data)
        log_info._send_to_fastapi("share_memory", json.dumps(data, ensure_ascii=False))