from flask import Flask, request, jsonify
from RAG_search import search_and_analyze, load_system

app = Flask(__name__)

# ⚠️【根因修正】原本的 /search route 直接使用 global_index 與 global_metadata，
# 但整份檔案從未初始化這兩個變數，導致每次請求都 NameError。這裡在啟動時
# 明確呼叫 load_system() 存成全域變數，啟動失敗則讓容器啟動失敗（而非把錯誤
# 隱藏到每次請求）。
global_index = None
global_metadata = None


def init_rag_system():
    global global_index, global_metadata
    print("[RAG Server] 正在載入 FAISS 向量資料庫與 Metadata...")
    global_index, global_metadata = load_system()
    print("[RAG Server] ✅ FAISS 向量資料庫與 Metadata 載入完成！")


@app.route('/search', methods=['POST'])
def search():
    if global_index is None or global_metadata is None:
        return jsonify({"error": "RAG 向量資料庫尚未成功載入，請檢查容器啟動日誌"}), 503

    data = request.get_json() or {}
    query = data.get('query', '')
    if not query:
        return jsonify({"error": "請提供 query 參數"}), 400

    print(f"[RAG Server] 收到檢索請求: {query}")

    try:
        result_log = search_and_analyze(query, global_index, global_metadata)
        return jsonify({"result": result_log})
    except Exception as e:
        # RAG_search 現在會在 embedding 連不到 Ollama 時 raise，這裡回明確 500，
        # 讓 ai_agent 端能分辨「連線問題」與「查無資料」。
        print(f"[RAG Server 錯誤] {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    """健康檢查 endpoint，供 docker-compose healthcheck 確認 FAISS 是否已載入完成。"""
    ready = global_index is not None and global_metadata is not None
    return jsonify({"status": "ready" if ready else "loading"}), (200 if ready else 503)


if __name__ == '__main__':
    init_rag_system()
    app.run(host='0.0.0.0', port=8000)
