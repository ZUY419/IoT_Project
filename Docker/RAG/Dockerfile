FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# 1. 安裝編譯工具與 FAISS 所需的底層 C++ 函式庫 (libgomp1)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        curl \
        git \
        libgomp1 && \
    rm -rf /var/lib/apt/lists/*

# 2. 複製並安裝 Python 套件
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# 3. 複製 RAG 資料夾內的所有程式碼與檔案
COPY . .

# 4. 預設直接執行同學的 Python 腳本
# (如果同學的主程式檔名不是 RAG_search.py，請將下方替換成他的實際檔名，例如 main.py)
CMD ["tail", "-f", "/dev/null"]