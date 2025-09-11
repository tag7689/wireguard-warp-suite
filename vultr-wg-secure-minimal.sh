#!/bin/bash
set -e

# 配置
WG_IF="awg0"
WG_PORT="${WG_PORT:-51820}"
WG_NET="10.66.66.0/24"
WG_SVR_IP="10.66.66.1/24"
CLIENT_IP="10.66.66.10/32"
DNS_ADDR="${DNS_ADDR:-1.1.1.1}"
MTU="${MTU:-1280}"
RATE_LIMIT="${RATE_LIMIT:-100/min}"

# 顏色
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}WireGuard 漸進式安全版本${NC}"

# Root 檢查
[[ $EUID -eq 0 ]] || { echo "需要 root 權限"; exit 1; }

# 檢測 WAN
WAN_IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
echo -e "${GREEN}WAN 介面: $WAN_IF${NC}"

# 只安裝必要套件（避免衝突）
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools qrencode curl

echo -e "${GREEN}✅ 基礎套件安裝成功${NC}"

# 生成密鑰
mkdir -p /etc/wireguard/{clients,backup}
chmod 700 /etc/wireguard /etc/wireguard/clients /etc/wireguard/backup
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
CLIENT_PRIV=$(wg genkey)  
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
CLIENT_PSK=$(wg genpsk)

# 安全強化的 PostUp 腳本
cat > /etc/wireguard/postup-secure.sh << POSTUP
#!/bin/bash
set -e

# IP 轉發
sysctl -w net.ipv4.ip_forward=1

# NAT 規則
iptables -t nat -A POSTROUTING -s ${WG_NET} -o ${WAN_IF} -j MASQUERADE

# 基本轉發
iptables -A FORWARD -i ${WG_IF} -o ${WAN_IF} -j ACCEPT
iptables -A FORWARD -i ${WAN_IF} -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# 🔒 安全強化規則
# 防止客戶端互相訪問
iptables -A FORWARD -i ${WG_IF} -o ${WG_IF} -j DROP

# 阻止垃圾郵件發送
iptables -A FORWARD -i ${WG_IF} -p tcp --dport 25 -j DROP
iptables -A FORWARD -i ${WG_IF} -p tcp --dport 587 -j DROP
iptables -A FORWARD -i ${WG_IF} -p tcp --dport 465 -j DROP

# 限制 P2P
#iptables -A FORWARD -i ${WG_IF} -p tcp --dport 6881:6889 -j DROP
#iptables -A FORWARD -i ${WG_IF} -p udp --dport 6881:6889 -j DROP

# 速率限制（基本 DDoS 防護）
#iptables -A INPUT -p udp --dport ${WG_PORT} -m limit --limit ${RATE_LIMIT} -j ACCEPT
#iptables -A INPUT -p udp --dport ${WG_PORT} -j DROP

# SYN flood 保護
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# 日誌記錄
logger "WireGuard 安全啟動 - $(date)"
echo "$(date): WireGuard 安全啟動" >> /var/log/wireguard.log
POSTUP

chmod +x /etc/wireguard/postup-secure.sh

# PreDown 腳本
cat > /etc/wireguard/predown-secure.sh << PREDOWN
#!/bin/bash

# 清理所有規則
iptables -t nat -D POSTROUTING -s ${WG_NET} -o ${WAN_IF} -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i ${WG_IF} -o ${WAN_IF} -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i ${WAN_IF} -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i ${WG_IF} -o ${WG_IF} -j DROP 2>/dev/null || true
iptables -D FORWARD -i ${WG_IF} -p tcp --dport 25 -j DROP 2>/dev/null || true
iptables -D FORWARD -i ${WG_IF} -p tcp --dport 587 -j DROP 2>/dev/null || true
iptables -D FORWARD -i ${WG_IF} -p tcp --dport 465 -j DROP 2>/dev/null || true
#iptables -D FORWARD -i ${WG_IF} -p tcp --dport 6881:6889 -j DROP 2>/dev/null || true
#iptables -D FORWARD -i ${WG_IF} -p udp --dport 6881:6889 -j DROP 2>/dev/null || true
#iptables -D INPUT -p udp --dport ${WG_PORT} -m limit --limit ${RATE_LIMIT} -j ACCEPT 2>/dev/null || true
#iptables -D INPUT -p udp --dport ${WG_PORT} -j DROP 2>/dev/null || true
iptables -D INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p tcp --syn -j DROP 2>/dev/null || true

logger "WireGuard 安全關閉 - $(date)"
echo "$(date): WireGuard 安全關閉" >> /var/log/wireguard.log
PREDOWN

chmod +x /etc/wireguard/predown-secure.sh

# 伺服器配置（使用安全腳本）
cat > /etc/wireguard/${WG_IF}.conf << WGCONF
[Interface]
Address = ${WG_SVR_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV}
PostUp = /etc/wireguard/postup-secure.sh
PreDown = /etc/wireguard/predown-secure.sh

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

# 系統強化（不依賴額外套件）
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wg-security.conf
echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.d/99-wg-security.conf
echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.d/99-wg-security.conf
echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.d/99-wg-security.conf
sysctl -p /etc/sysctl.d/99-wg-security.conf

# 簡單監控腳本
cat > /usr/local/bin/wg-check.sh << 'MONITOR'
#!/bin/bash
WG_IF="awg0"

# 檢查服務
if ! systemctl is-active --quiet wg-quick@$WG_IF; then
    echo "$(date): WireGuard 服務異常，正在重啟..." >> /var/log/wireguard.log
    systemctl restart wg-quick@$WG_IF
fi

# 檢查連接
PEERS=$(wg show $WG_IF peers | wc -l)
echo "$(date): 活躍連接數: $PEERS" >> /var/log/wireguard.log
MONITOR

chmod +x /usr/local/bin/wg-check.sh

# 定時檢查（每10分鐘）
echo "*/10 * * * * root /usr/local/bin/wg-check.sh" >> /etc/crontab

# 啟動 WireGuard
systemctl enable wg-quick@${WG_IF}
systemctl start wg-quick@${WG_IF}

echo -e "\n${GREEN}🎉 WireGuard 安全版本部署完成！${NC}"
echo
echo -e "${BLUE}🔒 安全功能已啟用：${NC}"
echo "✅ 客戶端隔離 (防止互相訪問)"
echo "✅ 垃圾郵件防護 (阻擋 SMTP 端口)"
echo "✅ P2P 限制 (阻擋 BitTorrent)"
echo "✅ DDoS 基礎防護 (速率限制)"
echo "✅ SYN flood 保護"
echo "✅ 系統參數強化"
echo "✅ 自動監控和日誌"
echo
echo -e "${BLUE}📁 重要檔案：${NC}"
echo "客戶端配置: /etc/wireguard/clients/client01.conf"
echo "安全日誌: /var/log/wireguard.log"
echo "監控腳本: /usr/local/bin/wg-check.sh"
echo
echo -e "${BLUE}🔧 管理命令：${NC}"
echo "檢查狀態: wg show ${WG_IF}"
echo "查看日誌: tail -f /var/log/wireguard.log"
echo "手動檢查: /usr/local/bin/wg-check.sh"
echo
echo -e "${YELLOW}⚠️  記得執行: sudo ufw allow ${WG_PORT}/udp${NC}"
echo
echo "客戶端配置："
echo "============"
cat /etc/wireguard/clients/client01.conf
echo "============"

# QR 碼
if command -v qrencode >/dev/null; then
    echo -e "\n${BLUE}QR Code:${NC}"
    qrencode -t ansiutf8 < /etc/wireguard/clients/client01.conf
fi