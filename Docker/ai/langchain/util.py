import json
from datetime import datetime
import os
import re

def pretty_print_json(data, indent=4):
    """
    將 Python 字典（dict）或字串格式化為高可讀性的 JSON 輸出
    """
    if isinstance(data, str):
        try:
            # 如果傳進來的是 JSON 字串，先轉成 dict
            data = json.loads(data)
        except json.JSONDecodeError:
            # 如果不是合法的 JSON 字串，就直接印出原本的文字
            print(data)
            return

    # 自訂序列化處理（例如遇到時間物件時轉成字串）
    def default_serializer(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    # 進行 json.dumps 格式化
    formatted_str = json.dumps(
        data, 
        indent=indent, 
        ensure_ascii=False,  # 確保中文不會被跳脫成 Unicode 碼
        sort_keys=False,     # 是否按 Key 字母排序（通常保持 False 比較符合邏輯順序）
        default=default_serializer
    )
    
    print(formatted_str)

def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def get_current_folder_path():
    """
    取得目前腳本所在的絕對資料夾路徑
    """
    # 適用於一般 .py 執行檔或腳本
    return os.path.dirname(os.path.abspath(__file__))

def clean_version(version_str):
    if not version_str:
        return ""
    # 如果版本字串裡包含了軟體名稱或多餘符號，可以用正規表達式抓出純數字與小數點（例如 "2.41" 或 "1.4.28"）
    # 或是單純把常見的前綴、斜線取代掉
    cleaned = version_str.replace("/", " ")
    
    # 嘗試用 Regex 抓出類似 x.y.z 的版號
    match = re.search(r'(\d+(\.\d+)+[a-zA-Z0-9-]*)', cleaned)
    if match:
        return match.group(1)
    
    return version_str.strip()

def remove_version(text):
    if not text:
        return ""
    
    # 1. 這裡用你原本抓版本號的 Regex 邏輯
    # 它會抓出類似 2.41, 1.4.28, v1.0-beta 等版本號格式
    version_pattern = r'(\d+(\.\d+)+[a-zA-Z0-9-]*)'
    
    # 2. 用 re.sub 把符合版本號的片段替換成空字串 ""
    cleaned_text = re.sub(version_pattern, '', text)
    
    # 3. 清理多餘的空白字元與結尾符號
    cleaned_text = cleaned_text.strip()
    
    return cleaned_text