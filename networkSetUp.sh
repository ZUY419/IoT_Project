#!/usr/bin/env bash
# networkSetUp.sh
# 掛上 TFTP conntrack helper,讓 Docker container 能正常收 TFTP data 回包。
# 由啟動腳本以 sudo 呼叫;搭配 sudoers.d/tftp-helper 可免密碼。
set -e

# 載入模組(已載入時 modprobe 本來就是 no-op,安全)
/usr/sbin/modprobe nf_conntrack_tftp
/usr/sbin/modprobe nf_nat_tftp

# iptables 規則:-C 先檢查,不存在才新增,避免重跑疊加
/usr/sbin/iptables -t raw -C OUTPUT     -p udp --dport 69 -j CT --helper tftp 2>/dev/null \
  || /usr/sbin/iptables -t raw -A OUTPUT     -p udp --dport 69 -j CT --helper tftp
/usr/sbin/iptables -t raw -C PREROUTING -p udp --dport 69 -j CT --helper tftp 2>/dev/null \
  || /usr/sbin/iptables -t raw -A PREROUTING -p udp --dport 69 -j CT --helper tftp

echo "[networkSetUp] TFTP helper ready."