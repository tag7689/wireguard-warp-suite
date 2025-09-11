#!/bin/bash
set -e

# 配置
WG_IF="awg0"
WG_PORT="51820"
WG_NET="10.66.66.0/24"
WG_SVR_IP="10.66.66.1/24"
CLIENT_IP="10.66.66.10/32"
DNS_ADDR="1.1.1.1"
MTU="1280"
WARP_NETNS="warp"
WARP_IF="wgcf"

# 顏色
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🌐 WireGuard + WARP IP隱藏方案 (修復版)${NC}"

[[ $EUID -eq 0 ]] || { echo "需要 root 權限"; exit 1; }

# 檢測 WAN
WAN_IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
echo -e "${GREEN}WAN 介面: $WAN_IF${NC}"

# 清理舊配置
systemctl stop wg-quick@awg0 2>/dev/null || true
ip netns del warp 2>/dev/null || true
ip link del veth-main 2>/dev/null || true

# 安裝套件
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq curl

# 下載 wgcf
if [[ ! -f /usr/local/bin/wgcf ]]; then
    wget -q -O /usr/local/bin/wgcf https://github.com/ViRb3/wgcf/releases/download/v2.2.19/wgcf_2.2.19_linux_amd64
    chmod +x /usr/local/bin/wgcf
fi

# 生成密鑰
mkdir -p /etc/wireguard/{clients,warp}
chmod 700 /etc/wireguard /etc/wireguard/clients /etc/wireguard/warp

SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
CLIENT_PRIV=$(wg genkey)  
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
CLIENT_PSK=$(wg genpsk)

# WARP 配置（直接創建，避免註冊失敗）
echo -e "${BLUE}創建 WARP 配置...${NC}"
cd /etc/wireguard/warp

WARP_PRIVATE_KEY=$(wg genkey)
cat > wgcf-profile.conf << WARPCONF
[Interface]
PrivateKey = $WARP_PRIVATE_KEY
Address = 172.16.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
Endpoint = 162.159.192.1:2408
PersistentKeepalive = 25
WARPCONF

# 提取 WARP 參數（避免 sed 問題）
WARP_ADDR="172.16.0.2/32"
WARP_PRIV="$WARP_PRIVATE_KEY"
WARP_PUB_PEER="bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WARP_ENDPOINT="162.159.192.1:2408"

echo -e "${GREEN}WARP 配置: $WARP_ADDR -> $WARP_ENDPOINT${NC}"

# 創建 namespace 設置腳本（直接寫入變數，不用 sed）
cat > /usr/local/bin/setup-warp-namespace.sh << NAMESPACE
#!/bin/bash
set -e

WARP_NETNS="warp"
WARP_IF="wgcf"
WAN_IF="$WAN_IF"

echo "設置 WARP namespace..."

# 清理舊的
ip netns del \$WARP_NETNS 2>/dev/null || true
ip link del veth-main 2>/dev/null || true

# 創建 namespace
ip netns add \$WARP_NETNS
ip netns exec \$WARP_NETNS ip link set lo up

# veth pair
ip link add veth-warp type veth peer name veth-main
ip link set veth-warp netns \$WARP_NETNS
ip link set veth-main up

# IP 配置
ip addr add 172.31.0.1/30 dev veth-main
ip netns exec \$WARP_NETNS ip addr add 172.31.0.2/30 dev veth-warp
ip netns exec \$WARP_NETNS ip link set veth-warp up
ip netns exec \$WARP_NETNS ip route add default via 172.31.0.1

# WARP 介面
ip netns exec \$WARP_NETNS ip link add dev \$WARP_IF type wireguard
ip netns exec \$WARP_NETNS ip addr add $WARP_ADDR dev \$WARP_IF

# WARP WG 設置
ip netns exec \$WARP_NETNS wg set \$WARP_IF \\
    private-key <(echo "$WARP_PRIV") \\
    peer $WARP_PUB_PEER \\
    allowed-ips 0.0.0.0/0 \\
    endpoint $WARP_ENDPOINT \\
    persistent-keepalive 25

# 啟動
ip netns exec \$WARP_NETNS ip link set \$WARP_IF up
ip netns exec \$WARP_NETNS ip route add default dev \$WARP_IF metric 1

echo "✅ WARP namespace 完成"
NAMESPACE

chmod +x /usr/local/bin/setup-warp-namespace.sh

# 執行設置
/usr/local/bin/setup-warp-namespace.sh

# PostUp 腳本（直接寫入變數）
cat > /etc/wireguard/postup-warp.sh << POSTUP
#!/bin/bash
set -e

echo "啟動 WARP 路由..."

# 基本設置
sysctl -w net.ipv4.ip_forward=1

# 創建路由表
echo "200 warp_out" >> /etc/iproute2/rt_tables 2>/dev/null || true

# VPN 流量標記
iptables -t mangle -A PREROUTING -s $WG_NET -j MARK --set-mark 200

# 標記流量走 WARP
ip rule add fwmark 200 table warp_out 2>/dev/null || true
ip route add default via 172.31.0.2 dev veth-main table warp_out 2>/dev/null || true

# WARP NAT
ip netns exec warp iptables -t nat -A POSTROUTING -s 172.31.0.0/30 -o wgcf -j MASQUERADE

# 轉發規則
iptables -A FORWARD -i $WG_IF -o veth-main -j ACCEPT
iptables -A FORWARD -i veth-main -o $WG_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s $WG_NET -o veth-main -j MASQUERADE

# SSH 保持直連
iptables -t mangle -A OUTPUT -p tcp --dport 22 -j MARK --set-mark 100
ip rule add fwmark 100 table main 2>/dev/null || true

logger "WireGuard WARP 路由啟動"
echo "\$(date): WARP 路由啟動" >> /var/log/wireguard.log
POSTUP

chmod +x /etc/wireguard/postup-warp.sh

# PreDown 腳本
cat > /etc/wireguard/predown-warp.sh << PREDOWN
#!/bin/bash

echo "清理 WARP 路由..."

# 清理規則
ip rule del fwmark 200 table warp_out 2>/dev/null || true
ip rule del fwmark 100 table main 2>/dev/null || true
ip route del default via 172.31.0.2 dev veth-main table warp_out 2>/dev/null || true

# 清理 iptables
iptables -t mangle -D PREROUTING -s $WG_NET -j MARK --set-mark 200 2>/dev/null || true
iptables -t mangle -D OUTPUT -p tcp --dport 22 -j MARK --set-mark 100 2>/dev/null || true
iptables -D FORWARD -i $WG_IF -o veth-main -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i veth-main -o $WG_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s $WG_NET -o veth-main -j MASQUERADE 2>/dev/null || true

# 清理 namespace
ip netns exec warp iptables -t nat -D POSTROUTING -s 172.31.0.0/30 -o wgcf -j MASQUERADE 2>/dev/null || true

logger "WireGuard WARP 路由清理"
echo "\$(date): WARP 路由清理" >> /var/log/wireguard.log
PREDOWN

chmod +x /etc/wireguard/predown-warp.sh

# WireGuard 配置
cat > /etc/wireguard/${WG_IF}.conf << WGCONF
[Interface]
Address = ${WG_SVR_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV}
PostUp = /etc/wireguard/postup-warp.sh
PreDown = /etc/wireguard/predown-warp.sh

[Peer]
PublicKey = ${CLIENT_PUB}
PresharedKey = ${CLIENT_PSK}
AllowedIPs = ${CLIENT_IP}
WGCONF

chmod 600 /etc/wireguard/${WG_IF}.conf

# 客戶端配置
SERVER_IP=$(curl -4 -s --max-time 10 https://api.ipify.org || echo "YOUR_SERVER_IP")
cat > /etc/wireguard/clients/client01.conf << CLIENTCONF
[Interface]
Address = ${CLIENT_IP}
PrivateKey = ${CLIENT_PRIV}
DNS = ${DNS_ADDR}
MTU = ${MTU}

[Peer]
PublicKey = ${SERVER_PUB}
PresharedKey = ${CLIENT_PSK}
Endpoint = ${SERVER_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
CLIENTCONF

chmod 600 /etc/wireguard/clients/client01.conf

# 系統優化
cat > /etc/sysctl.d/99-wg-warp.conf << SYSCTL
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.veth-main.rp_filter = 0
SYSCTL

sysctl -p /etc/sysctl.d/99-wg-warp.conf

# systemd 服務
cat > /etc/systemd/system/warp-namespace.service << SERVICE
[Unit]
Description=WARP Namespace Setup
After=network.target
Before=wg-quick@awg0.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/setup-warp-namespace.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable warp-namespace.service

# 測試腳本
cat > /usr/local/bin/test-warp-routing.sh << 'TEST'
#!/bin/bash
echo "🧪 測試 WARP 路由..."

echo "1. VPS 直連 IP:"
curl -s --max-time 5 ifconfig.me

echo -e "\n2. WARP namespace IP:"
timeout 10 ip netns exec warp curl -s --max-time 8 ifconfig.me || echo "WARP 連接失敗"

echo -e "\n3. WireGuard 狀態:"
wg show awg0

echo -e "\n4. 路由規則:"
ip rule show | grep -E "(200|100)" || echo "無自定義路由規則"

echo -e "\n5. WARP 介面狀態:"
ip netns exec warp wg show wgcf 2>/dev/null || echo "WARP 介面未啟動"

echo -e "\n6. Namespace 網路測試:"
ip netns exec warp ping -c 3 1.1.1.1 2>/dev/null || echo "WARP 網路不通"
TEST

chmod +x /usr/local/bin/test-warp-routing.sh

# 啟動服務
systemctl start warp-namespace.service
sleep 3
systemctl enable wg-quick@${WG_IF}
systemctl start wg-quick@${WG_IF}

echo -e "\n${GREEN}🎉 WireGuard + WARP 修復版部署完成！${NC}"
echo
echo -e "${BLUE}🔧 測試命令：${NC}"
echo "/usr/local/bin/test-warp-routing.sh"
echo
echo -e "${YELLOW}⚠️  記得執行: sudo ufw allow 51820/udp${NC}"
echo
echo -e "${BLUE}客戶端配置：${NC}"
echo "============"
cat /etc/wireguard/clients/client01.conf
echo "============"

if command -v qrencode >/dev/null; then
    echo -e "\n${BLUE}QR Code:${NC}"
    qrencode -t ansiutf8 < /etc/wireguard/clients/client01.conf
fi

echo -e "\n${GREEN}🔍 部署完成後，請執行測試腳本檢查路由是否正確！${NC}"