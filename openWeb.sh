cd ./Web

# 開啟 HTML (Linux 請使用 xdg-open)
xdg-open index.html

# 在背景啟動 FastAPI 後端
uvicorn API.main:app --host 0.0.0.0 --port 8000 --reload &

cd ..
