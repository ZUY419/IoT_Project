import os

# 設定要抓取的目標資料夾
TARGET_DIRS = ["."]

# 要排除的資料夾名稱集合 (Set)
EXCLUDE_DIRS = {"__pycache__", ".git", "venv", ".idea", ".vscode", "temp", "exploitdb"}

TARGET_EXTENSIONS = (".js", ".html", ".css", ".py", ".env", ".yml")

# 💡 允許讀取的隱藏檔（其他以 . 開頭的檔案仍會被跳過）
ALLOWED_DOTFILES = {".env", ".env.example", ".env.local"}

# 💡 是否遮蔽 .env 的值（True = 只顯示變數名稱，避免金鑰外洩）
MASK_ENV_VALUES = True

OUTPUT_FILE = "README.md"


def is_env_file(filename):
    """判斷是否為 .env 類型的檔案"""
    return filename.startswith(".env") or filename.endswith(".env")


def should_include(filename):
    """判斷檔案是否要被寫入 README"""
    if filename in ALLOWED_DOTFILES:
        return True
    return filename.endswith(TARGET_EXTENSIONS) and not filename.startswith(".")


def get_language_tag(filename):
    """根據副檔名判定 Markdown 程式碼區塊的語法標註"""
    if filename.endswith(".py"):
        return "python"
    elif filename.endswith(".js"):
        return "javascript"
    elif filename.endswith(".html"):
        return "html"
    elif filename.endswith(".css"):
        return "css"
    elif filename.endswith(".yml"):
        return "yaml"
    elif is_env_file(filename):
        return "bash"
    elif filename.endswith(".sh"):
        return "bash"
    elif filename.endswith(".txt"):
        return "text"
    return ""


def mask_env(content):
    """將 .env 內容的值遮蔽，只保留變數名稱與註解"""
    lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            lines.append(f"{key}=********")
        else:
            lines.append(line)
    return "\n".join(lines)


def generate_readme():
    with open(OUTPUT_FILE, "w", encoding="utf-8") as outfile:
        outfile.write("更新後的專案程式碼\n")
        outfile.write("# AI Agent 模組程式碼與架構說明\n\n")
        outfile.write(
            "本檔案由 `update_readme.py` 自動生成，僅彙整 `AI Agent` 目錄內之核心程式碼。\n\n"
        )

        for target_dir in TARGET_DIRS:
            if not os.path.exists(target_dir):
                print(f"[!] 找不到目錄: {target_dir}，請確認目錄名稱。")
                continue

            outfile.write(f"## 📁 資料夾: `{target_dir}/` \n\n")

            for root, dirs, files in os.walk(target_dir):
                # 原地修改 dirs，跳過包含在 EXCLUDE_DIRS 中的子資料夾
                dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

                for file in sorted(files):
                    if not should_include(file):
                        continue

                    file_path = os.path.join(root, file)

                    if "update_readme.py" in file_path:
                        continue

                    lang = get_language_tag(file)

                    outfile.write(f"### 📄 `{file_path}`\n\n")
                    outfile.write(f"```{lang}\n")
                    try:
                        with open(file_path, "r", encoding="utf-8") as infile:
                            content = infile.read()
                            if MASK_ENV_VALUES and is_env_file(file):
                                content = mask_env(content)
                            outfile.write(content)
                    except Exception as e:
                        outfile.write(f"# 無法讀取檔案內容: {e}\n")
                    outfile.write("\n```\n\n")

    print(f"[OK] 已成功將 AI Agent 程式碼打包寫入 {OUTPUT_FILE}！")


if __name__ == "__main__":
    generate_readme()