FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

# 安裝套件：新增了 rinetd 用於流量轉發
RUN apt-get update && apt-get install -y --no-install-recommends \
    rinetd \
    uml-utilities \
    bridge-utils \
    socat \
    iptables \
    build-essential zlib1g-dev liblzma-dev liblzo2-dev \
    python3 python3-pip python3-dev \
    binwalk squashfs-tools \
    file \
    qemu-system-arm qemu-system-mips qemu-system-x86 \
    qemu-utils \
    kpartx \
    busybox-static \
    net-tools \
    iputils-ping \
    lsb-release \
    postgresql sudo locales iproute2 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# 語系設定
RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

# Python 套件安裝
RUN python3 -m pip install --no-cache-dir \
    requests paho-mqtt pexpect psycopg2-binary psutil python-magic

WORKDIR /app

# 複製專案
COPY ./Simulator .

# 修正 FAP 啟動參數以適應 SD 卡驅動 (針對特定 ARM 韌體)
RUN FAP_PY="./Tool/firmware-analysis-plus/fap.py" && \
    if [ -f "$FAP_PY" ]; then \
    sed -i 's/virtio-blk-device,drive=rootfs/-drive if=sd,file={0},format=raw/g' "$FAP_PY" && \
    sed -i 's/root=\/dev\/vda1/root=\/dev\/mmcblk0p1/g' "$FAP_PY"; \
    fi

# 建立 rinetd 設定檔：將容器 80 埠轉發至韌體 IP [cite: 70]
RUN echo "0.0.0.0 80 192.168.0.1 80" > /etc/rinetd.conf

# 賦予執行權限
RUN chmod +x ./run.sh

# 改用啟動腳本模式
CMD ["sh", "-c", "rinetd -c /etc/rinetd.conf && bash ./run.sh"]