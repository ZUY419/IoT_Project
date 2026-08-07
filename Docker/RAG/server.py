from flask import Flask, request, jsonify
from RAG_search import search_and_analyze  

app = Flask(__name__)

@app.route('/search', methods=['POST'])
def search():
    data = request.get_json() or {}
    query = data.get('query', '')
    print(f"[RAG Server] 收到檢索請求: {query}")
    
    try:
        # 帶入 3 個必填參數 (index 與 metadata 需為 RAG 初始化載入好的全域變數)
        # 後面兩個 max_ignore=5, max_matches=5 會自動採用預設值
        result_log = search_and_analyze(query, global_index, global_metadata)
        
        return jsonify({"result": result_log})
    except Exception as e:
        print(f"[RAG Server 錯誤] {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # 監聽 0.0.0.0:8000 讓其他容器連得進來
    app.run(host='0.0.0.0', port=8000)
