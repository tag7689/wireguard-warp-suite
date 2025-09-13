#!/bin/bash
# VPS 網絡性能優化腳本

# BBR 擁塞控制 (提升速度)
echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf

# UDP 緩衝區調整 (提升 WireGuard 性能)
echo 'net.core.rmem_default = 262144' >> /etc/sysctl.conf
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_default = 262144' >> /etc/sysctl.conf  
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf

# Shadowsocks TCP 優化
echo 'net.ipv4.tcp_fastopen = 3' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_slow_start_after_idle = 0' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_notsent_lowat = 16384' >> /etc/sysctl.conf

# 應用設置
sysctl -p

echo "✅ 網絡性能優化完成"
echo "BBR 狀態: $(cat /proc/sys/net/ipv4/tcp_congestion_control)"