#!/bin/bash
# =============================================================================
# WireGuard + WARP 路由隱藏真實IP方案
# 客戶端流量通過 WARP 出口，管理流量保持直連
# =============================================================================

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
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🌐 WireGuard + WARP IP隱藏方案${NC}"

# Root 檢查
[[ $EUID -eq 0 ]] || { echo "需要 root 權限"; exit 1; }

# 檢測 WAN
WAN_IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
echo -e "${GREEN}WAN 介面: $WAN_IF${NC}"

# 安裝套件
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools qrencode curl

# 下載 wgcf (WARP 客戶端)
echo -e "${BLUE}下載 WARP 客戶端...${NC}"
wget -q -O /usr/local/bin/wgcf https://github.com/ViRb3/wgcf/releases/download/v2.2.19/wgcf_2.2.19_linux_amd64
chmod +x /usr/local/bin/wgcf

# 生成 WireGuard 密鑰
mkdir -p /etc/wireguard/{clients,warp}
chmod 700 /etc/wireguard /etc/wireguard/clients /etc/wireguard/warp
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
CLIENT_PRIV=$(wg genkey)  
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
CLIENT_PSK=$(wg genpsk)

# 註冊 WARP (使用替代方案)
echo -e "${BLUE}設置 WARP 配置...${NC}"
cd /etc/wireguard/warp

# 嘗試註冊，失敗則使用公開配置
if timeout 30 /usr/local/bin/wgcf register --accept-tos 2>/dev/null && timeout 30 /usr/local/bin/wgcf generate 2>/dev/null; then
    echo -e "${GREEN}WARP 註冊成功${NC}"
    WARP_CONFIG="/etc/wireguard/warp/wgcf-profile.conf"
else
    echo -e "${YELLOW}WARP 註冊失敗，使用公開配置${NC}"
    # 創建公開 WARP 配置
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
    WARP_CONFIG="/etc/wireguard/warp/wgcf-profile.conf"
fi

# 提取 WARP 參數
WARP_ADDR=$(grep "^Address" $WARP_CONFIG | cut -d' ' -f3)
WARP_PRIV=$(grep "^PrivateKey" $WARP_CONFIG | cut -d' ' -f3)
WARP_PUB_PEER=$(grep "^PublicKey" $WARP_CONFIG | cut -d' ' -f3)
WARP_ENDPOINT=$(grep "^Endpoint" $WARP_CONFIG | cut -d' ' -f3)

echo -e "${GREEN}WARP 配置: $WARP_ADDR -> $WARP_ENDPOINT${NC}"

# 創建網路命名空間腳本
cat > /usr/local/bin/setup-warp-namespace.sh << 'NAMESPACE'
#!/bin/bash
set -e

WARP_NETNS="warp"
WARP_IF="wgcf"
WAN_IF="WAN_IF_PLACEHOLDER"

# 清理舊的 namespace
ip netns del $WARP_NETNS 2>/dev/null || true
ip link del veth-main 2>/dev/null || true

# 創建 namespace
ip netns add $WARP_NETNS
ip netns exec $WARP_NETNS ip link set lo up

# 創建 veth pair
ip link add veth-warp type veth peer name veth-main
ip link set veth-warp netns $WARP_NETNS
ip link set veth-main up

# 配置 IP
ip addr add 172.31.0.1/30 dev veth-main
ip netns exec $WARP_NETNS ip addr add 172.31.0.2/30 dev veth-warp
ip netns exec $WARP_NETNS ip link set veth-warp up
ip netns exec $WARP_NETNS ip route add default via 172.31.0.1

# 在 namespace 中創建 WARP 介面
ip netns exec $WARP_NETNS ip link add dev $WARP_IF type wireguard
ip netns exec $WARP_NETNS ip addr add WARP_ADDR_PLACEHOLDER dev $WARP_IF

# 設置 WARP WireGuard
ip netns exec $WARP_NETNS wg set $WARP_IF \
    private-key <(echo "WARP_PRIV_PLACEHOLDER") \
    peer WARP_PUB_PEER_PLACEHOLDER \
    allowed-ips 0.0.0.0/0 \
    endpoint WARP_ENDPOINT_PLACEHOLDER \
    persistent-keepalive 25

# 啟動 WARP 介面
ip netns exec $WARP_NETNS ip link set $WARP_IF up

# 設置 WARP 路由 (高優先級)
ip netns exec $WARP_NETNS ip route add default dev $WARP_IF table main metric 1

echo "WARP namespace 設置完成"
NAMESPACE

# 替換變數
sed -i "s/WAN_IF_PLACEHOLDER/$WAN_IF/g" /usr/local/bin/setup-warp-namespace.sh
sed -i "s/WARP_ADDR_PLACEHOLDER/$WARP_ADDR/g" /usr/local/bin/setup-warp-namespace.sh
sed -i "s/WARP_PRIV_PLACEHOLDER/$WARP_PRIV/g" /usr/local/bin/setup-warp-namespace.sh
sed -i "s/WARP_PUB_PEER_PLACEHOLDER/$WARP_PUB_PEER/g" /usr/local/bin/setup-warp-namespace.sh
sed -i "s/WARP_ENDPOINT_PLACEHOLDER/$WARP_ENDPOINT/g" /usr/local/bin/setup-warp-namespace.sh

chmod +x /usr/local/bin/setup-warp-namespace.sh

# 設置 WARP namespace
/usr/local/bin/setup-warp-namespace.sh

# 創建高級路由腳本
cat > /etc/wireguard/postup-warp.sh << 'POSTUP'
#!/bin/bash
set -e

WG_IF="awg0"
WG_NET="10.66.66.0/24"
WAN_IF="WAN_IF_PLACEHOLDER"
WARP_NETNS="warp"

# 基本設置
sysctl -w net.ipv4.ip_forward=1

# 🔥 關鍵：創建路由表和規則
# 創建自定義路由表
echo "200 warp_out" >> /etc/iproute2/rt_tables 2>/dev/null || true

# VPN 客戶端流量標記
iptables -t mangle -A PREROUTING -s $WG_NET -j MARK --set-mark 200

# 標記的流量走 WARP namespace
ip rule add fwmark 200 table warp_out 2>/dev/null || true
ip route add default via 172.31.0.2 dev veth-main table warp_out 2>/dev/null || true

# WARP namespace 的 NAT (關鍵！)
ip netns exec $WARP_NETNS iptables -t nat -A POSTROUTING -s 172.31.0.0/30 -o wgcf -j MASQUERADE

# veth-main 到 namespace 的轉發
iptables -A FORWARD -i $WG_IF -o veth-main -j ACCEPT
iptables -A FORWARD -i veth-main -o $WG_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s $WG_NET -o veth-main -j MASQUERADE

# 管理流量保持直連 (SSH 等)
iptables -t mangle -A OUTPUT -p tcp --dport 22 -j MARK --set-mark 100
ip rule add fwmark 100 table main 2>/dev/null || true

echo "$(date): WARP 路由啟動" >> /var/log/wireguard.log
logger "WireGuard WARP routing started"
POSTUP

sed -i "s/WAN_IF_PLACEHOLDER/$WAN_IF/g" /etc/wireguard/postup-warp.sh
chmod +x /etc/wireguard/postup-warp.sh

# PreDown 腳本
cat > /etc/wireguard/predown-warp.sh << 'PREDOWN'
#!/bin/bash

# 清理路由規則
ip rule del fwmark 200 table warp_out 2>/dev/null || true
ip rule del fwmark 100 table main 2>/dev/null || true
ip route del default via 172.31.0.2 dev veth-main table warp_out 2>/dev/null || true

# 清理 iptables 規則
iptables -t mangle -D PREROUTING -s 10.66.66.0/24 -j MARK --set-mark 200 2>/dev/null || true
iptables -t mangle -D OUTPUT -p tcp --dport 22 -j MARK --set-mark 100 2>/dev/null || true
iptables -D FORWARD -i awg0 -o veth-main -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i veth-main -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o veth-main -j MASQUERADE 2>/dev/null || true

# 清理 namespace NAT
ip netns exec warp iptables -t nat -D POSTROUTING -s 172.31.0.0/30 -o wgcf -j MASQUERADE 2>/dev/null || true

echo "$(date): WARP 路由關閉" >> /var/log/wireguard.log
logger "WireGuard WARP routing stopped"
PREDOWN

chmod +x /etc/wireguard/predown-warp.sh

# WireGuard 服務器配置
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
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wg-warp.conf
echo 'net.ipv4.conf.all.rp_filter = 0' >> /etc/sysctl.d/99-wg-warp.conf
echo 'net.ipv4.conf.default.rp_filter = 0' >> /etc/sysctl.d/99-wg-warp.conf
sysctl -p /etc/sysctl.d/99-wg-warp.conf

# 創建 systemd 服務
cat > /etc/systemd/system/warp-namespace.service << SERVICE
[Unit]
Description=WARP Namespace Setup
After=network.target
Before=wg-quick@awg0.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/setup-warp-namespace.sh
RemainAfterExit=yes
StandardOutput=journal

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable warp-namespace.service
systemctl start warp-namespace.service

# 啟動 WireGuard
systemctl enable wg-quick@${WG_IF}
systemctl start wg-quick@${WG_IF}

# 測試腳本
cat > /usr/local/bin/test-warp-routing.sh << 'TEST'
#!/bin/bash
echo "🧪 測試 WARP 路由..."

echo "1. VPS 直連 IP:"
curl -s --max-time 5 ifconfig.me

echo -e "\n2. WARP namespace IP:"
ip netns exec warp curl -s --max-time 5 ifconfig.me || echo "WARP 連接失敗"

echo -e "\n3. WireGuard 狀態:"
wg show awg0

echo -e "\n4. 路由規則:"
ip rule show | grep -E "(200|100)"

echo -e "\n5. WARP 介面狀態:"
ip netns exec warp wg show wgcf 2>/dev/null || echo "WARP 介面未啟動"
TEST

chmod +x /usr/local/bin/test-warp-routing.sh

echo -e "\n${GREEN}🎉 WireGuard + WARP 路由部署完成！${NC}"
echo
echo -e "${BLUE}📊 架構說明：${NC}"
echo "客戶端 → WireGuard VPS → WARP Namespace → Cloudflare 出口"
echo
echo -e "${BLUE}🔧 測試命令：${NC}"
echo "/usr/local/bin/test-warp-routing.sh"
echo
echo -e "${BLUE}📁 配置檔案：${NC}"
echo "客戶端：/etc/wireguard/clients/client01.conf"
echo "WARP 配置：/etc/wireguard/warp/wgcf-profile.conf"
echo
echo -e "${YELLOW}⚠️  重要：記得執行 'sudo ufw allow 51820/udp'${NC}"
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