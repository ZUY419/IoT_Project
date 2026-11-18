import os
import sys
import re
import time
import json
import shutil
import select
import subprocess
import pty
from pathlib import Path

import requests

# ============================================================
# 日誌廣播設定
# ============================================================
FASTAPI_LOG_URL = os.environ.get(
    "FASTAPI_LOG_URL", "http://localhost:8000/api/pentest/send_log"
)
ENABLE_FASTAPI_LOGGING = True

READ_TIMEOUT = 2     # 單次 select 等待（秒）；沒輸出就回去再等，不關閉


class iot_log:
    """韌體模擬日誌廣播器。"""

    @staticmethod
    def _send(entry: dict):
        if not ENABLE_FASTAPI_LOGGING or not FASTAPI_LOG_URL:
            return
        payload = {
            "log": json.dumps(entry, ensure_ascii=False),
            "log_type": "IOT_LOG",
        }
        try:
            requests.post(FASTAPI_LOG_URL, json=payload, timeout=2.0)
        except Exception:
            pass


def delete_folder(folder_path):
    if os.path.exists(folder_path):
        try:
            shutil.rmtree(folder_path)
            print(f"[OK] Successfully deleted folder: {folder_path}")
        except Exception as e:
            print(f"[ER] Unsuccessfully deleted folder: {e}")
    else:
        print(f"[WR] Folder does not exist. Skipping deletion: {folder_path}")


def write_to_file(file_path, content, label, firmware):
    """以追加模式寫入 JSONL 格式，保護樹莓派 SD 卡。"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    content = f"{content}"
    entry = {
        "firmware": firmware,
        "label": label,
        "message": content.strip(),
    }
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    iot_log._send(entry)


def info_output(info, firmware):
    upper_info = info.upper()
    if "WARN" in upper_info:
        print(f"[WR]  {info}")
        write_to_file(f"Firmware_logs/{firmware}_logs.jsonl", info, "Waring", firmware)
        return
    elif "ERROR" in upper_info:
        print(f"[ER] {info}")
        write_to_file(f"Firmware_logs/{firmware}_logs.jsonl", info, "Error", firmware)
        return

    if "[+]" in upper_info:
        display_info = info.replace("[+]", "").strip()
        print(f"[OK] {display_info}")
        write_to_file(f"Firmware_logs/{firmware}_logs.jsonl", info, "Nothing", firmware)
    else:
        print(f"   {info}")
        write_to_file(f"Firmware_logs/{firmware}_logs.jsonl", info, "Nothing", firmware)
    return


def _resolve_fw_file(fap_path: str, firmware: str):
    """在 fw_bin/ 裡找出該韌體檔，副檔名不限 (.bin/.tar/.zip...)。"""
    fw_dir = Path(fap_path) / "fw_bin"
    exact = fw_dir / firmware
    if exact.is_file():
        return f"./fw_bin/{exact.name}"
    if fw_dir.is_dir():
        for f in fw_dir.iterdir():
            if f.is_file() and f.stem == firmware:
                return f"./fw_bin/{f.name}"
    return None


def _pick_target_ip(ips):
    """過濾掉不可能是靶機的位址。"""
    bad = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
    out = []
    for ip in ips:
        if ip in bad or ip.startswith("127.") or ip.endswith(".255"):
            continue
        out.append(ip)
    return out


def samulating_fw_logic(firmware):
    current_dir = Path(__file__).resolve().parent
    fap_path = "./Firmware_tool/firmware-analysis-plus"
    print(f"[+] Current Path: {current_dir}")
    os.chdir(current_dir)

    fw_arg = _resolve_fw_file(fap_path, firmware)
    if fw_arg is None:
        info_output(f"ERROR: 在 fw_bin/ 找不到韌體 '{firmware}' (任何副檔名)", firmware)
        return

    enter_sent = False
    url_matched = False
    webIsOpen = False
    match_url = []

    # 交接檔：供 run.sh 讀取靶機 IP
    ip_file = f"Firmware_logs/{firmware}_target_ip"
    os.makedirs("Firmware_logs", exist_ok=True)
    if os.path.exists(ip_file):
        os.remove(ip_file)

    # 1. 初始化環境
    print(f"\n[+] Initializing FAP for {firmware}...")
    subprocess.run("python3 reset.py", shell=True, cwd=fap_path)
    subprocess.run("python3 shutdown.py", shell=True, cwd=fap_path)
    with open(f"Firmware_logs/{firmware}_logs.jsonl", "w", encoding="utf-8") as f:
        f.write("")

    # 2. 啟動指令
    fap_cmd = f"stdbuf -oL python3 -u fap.py -q ./qemu-builds/2.5.0/ {fw_arg}"
    print(f"\n[+] Start simulating firmware: {firmware} ({fw_arg})")
    print("-" * 40)

    # 3. 使用 PTY 啟動 (不使用 text 模式，避免崩潰韌體吐出的二進位造成 UnicodeDecodeError)
    master, slave = pty.openpty()
    process = subprocess.Popen(
        fap_cmd,
        shell=True,
        cwd=fap_path,
        stdin=slave, stdout=slave, stderr=slave,
        close_fds=True,
    )
    os.close(slave)

    # 4. 讀取迴圈：只要 FAP(QEMU) 還活著就一直讀 bytes，逐行以 errors="replace" 解碼
    buf = b""
    try:
        while process.poll() is None:
            rlist, _, _ = select.select([master], [], [], READ_TIMEOUT)
            if master not in rlist:
                continue  # 這段時間沒輸出，保持運行不關閉
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break

            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                # 關鍵：errors="replace"，壞位元組換成 � 而非中斷
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                info_output(line, firmware)
                upper = line.upper()

                # 偵測網路 IP → 寫交接檔
                if not url_matched and "NETWORK" in upper:
                    ips = _pick_target_ip(
                        re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", line)
                    )
                    for ip in ips:
                        url = f"http://{ip}"
                        match_url.append(url)
                        print(f"[TR] Target URL ({url}) is matched!")
                        write_to_file(f"Firmware_logs/{firmware}_logs.jsonl",
                                      url, "Network", firmware)
                    if ips:
                        with open(ip_file, "w", encoding="utf-8") as f:
                            f.write(ips[0])
                        print(f"[OK] 已寫入靶機 IP 到 {ip_file}: {ips[0]}")
                        url_matched = True

                # 偵測 All set 並按 Enter
                elif "ALL SET" in upper and not enter_sent:
                    time.sleep(2)
                    os.write(master, b"\n")
                    print("[OK] Auto-sent Enter key via PTY.")
                    enter_sent = True

                # 偵測 web 服務 (僅記錄)
                elif url_matched and not webIsOpen:
                    for url in match_url:
                        try:
                            r = requests.get(url, timeout=0.5, allow_redirects=True)
                            if r.status_code < 400:
                                print(f"[NK] Web Service Ready: {url}")
                                webIsOpen = True
                                break
                        except requests.RequestException:
                            pass
    except (OSError, BrokenPipeError):
        pass

    process.wait()  # 一直等到 QEMU 自己結束（或手動 Ctrl-C）
    print("-" * 40)
    print(f"[+] Simulation for {firmware} has finished.")


def main():
    if len(sys.argv) < 2:
        print("用法: python3 openfirmware.py <firmware_name>")
        sys.exit(1)
    firmware = sys.argv[1]
    print(f"openfirmware get firmware: {firmware}")
    samulating_fw_logic(firmware)


if __name__ == "__main__":
    main()