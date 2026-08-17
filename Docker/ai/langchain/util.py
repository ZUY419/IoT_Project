import json
from datetime import datetime

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