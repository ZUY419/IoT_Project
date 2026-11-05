#!/usr/bin/env bash
# openWeb.sh  用法: ./openWeb.sh [start|stop|restart]
set -e

PROJECT_DIR="/home/todoroki/IoT_Project-main"   # 依實際調整
PID_FILE="/tmp/openweb_uvicorn.pid"
PORT=8000

start() {
    # 網路設定(免密碼,已由 sudoers 放行)
    sudo "$PROJECT_DIR/networkSetUp.sh"

    # 前端
    ( cd "$PROJECT_DIR/Web" && xdg-open index.html ) || true

    # 後端:背景啟動並記下 PID
    ( cd "$PROJECT_DIR/Web" && \
      uvicorn API.main:app --host 0.0.0.0 --port "$PORT" --reload ) &
    echo $! > "$PID_FILE"
    echo "[openWeb] started, uvicorn pid $(cat $PID_FILE)"
}

stop() {
    echo "[openWeb] stopping..."
    # 關掉所有佔用該 port 的程序(含 --reload 的子進程)
    PIDS=$(sudo lsof -t -i:"$PORT" 2>/dev/null || true)
    if [ -n "$PIDS" ]; then
        sudo kill $PIDS 2>/dev/null || true
        sleep 1
        # 還activo的話強制關
        PIDS=$(sudo lsof -t -i:"$PORT" 2>/dev/null || true)
        [ -n "$PIDS" ] && sudo kill -9 $PIDS 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
    echo "[openWeb] stopped."
}

case "${1:-start}" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    *) echo "用法: $0 [start|stop|restart]"; exit 1 ;;
esac