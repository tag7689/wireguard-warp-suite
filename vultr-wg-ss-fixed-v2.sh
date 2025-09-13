#!/bin/bash

set -e

# ========================================
# WireGuard + Shadowsocks 一鍵部署腳本 (修正版)
# 適用於 Vultr VPS (Ubuntu 22.04+)
# ========================================

# 配置參數
WG_IF="awg0"
WG_PORT="${WG_PORT:-51820}"
SS_PORT="${SS_PORT:-8388}"
SS_LPORT="${SS_LPORT:-1080}"
SS_METHOD="chacha20-ietf-poly1305"
WG_NET="10.66.66.0/24"
WG_SVR_IP="10.66.66.1/24"
CLIENT_IP="10.66.66.10/32"
DNS_ADDR="${DNS_ADDR:-1.1.1.1}"
MTU="${MTU:-1280}"

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

# 獲取外部 IP
get_external_ip() {
    curl -4 -s --max-time 10 https://api.ipify.org || echo "YOUR_SERVER_IP"
}

# 功能選擇菜單
show_menu() {
    clear
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}  WireGuard + Shadowsocks 一鍵部署${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo
    echo -e "${GREEN}請選擇部署模式：${NC}"
    echo -e "  ${YELLOW}1)${NC} 僅安裝 WireGuard (原版功能)"
    echo -e "  ${YELLOW}2)${NC} 僅安裝 Shadowsocks"
    echo -e "  ${YELLOW}3)${NC} WireGuard + Shadowsocks 整合模式 ${GREEN}(推薦)${NC}"
    echo -e "  ${YELLOW}4)${NC} 顯示現有配置"
    echo -e "  ${YELLOW}5)${NC} 退出"
    echo
    echo -ne "${PURPLE}請輸入選項 [1-5]: ${NC}"
    read -r choice
}

# Root 權限檢查
check_root() {
    [[ $EUID -eq 0 ]] || { echo -e "${RED}需要 root 權限，請使用 sudo 執行${NC}"; exit 1; }
}

# 系統檢測與準備
prepare_system() {
    echo -e "${BLUE}正在準備系統...${NC}"
    
    # 檢測 WAN 介面
    WAN_IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    echo -e "${GREEN}WAN 介面: $WAN_IF${NC}"
    
    # 更新系統並安裝基礎套件
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
        curl wget gnupg lsb-release software-properties-common \
        iptables-persistent netfilter-persistent \
        wireguard wireguard-tools qrencode \
        python3 python3-pip build-essential \
        snapd
    
    echo -e "${GREEN}✅ 基礎套件安裝成功${NC}"
}

# 生成隨機密碼
generate_password() {
    openssl rand -base64 16 | tr -d "=+/" | cut -c1-16
}

# 安裝 Shadowsocks
install_shadowsocks() {
    echo -e "${BLUE}正在安裝 Shadowsocks...${NC}"
    
    # 使用 snap 安裝 shadowsocks-rust
    snap install shadowsocks-rust
    
    # 生成 Shadowsocks 配置
    SS_PASSWORD=$(generate_password)
    
    mkdir -p /var/snap/shadowsocks-rust/common/etc/shadowsocks-rust
    
    cat > /var/snap/shadowsocks-rust/common/etc/shadowsocks-rust/config.json << EOF
{
    "server": "0.0.0.0",
    "server_port": ${SS_PORT},
    "password": "${SS_PASSWORD}",
    "timeout": 300,
    "method": "${SS_METHOD}",
    "mode": "tcp_and_udp",
    "fast_open": true,
    "workers": 4,
    "prefer_ipv6": false,
    "no_delay": true,
    "keep_alive": 15
}
EOF
    
    # 啟動 Shadowsocks 服務
    snap start --enable shadowsocks-rust.ssserver-daemon
    
    echo -e "${GREEN}✅ Shadowsocks 安裝完成${NC}"
    echo -e "${YELLOW}端口: ${SS_PORT}${NC}"
    echo -e "${YELLOW}密碼: ${SS_PASSWORD}${NC}"
    echo -e "${YELLOW}加密: ${SS_METHOD}${NC}"
    
    # 保存配置
    export SS_PASSWORD
}

# WireGuard 安裝 (修正版)
install_wireguard() {
    echo -e "${BLUE}正在安裝 WireGuard...${NC}"
    
    # 創建目錄
    mkdir -p /etc/wireguard/{clients,backup}
    chmod 700 /etc/wireguard /etc/wireguard/clients /etc/wireguard/backup
    
    # 生成密鑰
    SERVER_PRIV=$(wg genkey)
    SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
    CLIENT_PRIV=$(wg genkey)
    CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
    CLIENT_PSK=$(wg genpsk)
    
    # 創建 PostUp 腳本 (使用 heredoc 避免 sed 問題)
    cat > /etc/wireguard/postup-secure.sh << EOF
#!/bin/bash
set -e

# 設置變數
WG_NET_VAR="${WG_NET}"
WAN_IF_VAR="${WAN_IF}"
WG_IF_VAR="${WG_IF}"

# IP 轉發
sysctl -w net.ipv4.ip_forward=1

# NAT 規則
iptables -t nat -A POSTROUTING -s \${WG_NET_VAR} -o \${WAN_IF_VAR} -j MASQUERADE

# 基本轉發
iptables -A FORWARD -i \${WG_IF_VAR} -o \${WAN_IF_VAR} -j ACCEPT
iptables -A FORWARD -i \${WAN_IF_VAR} -o \${WG_IF_VAR} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# 安全強化規則
iptables -A FORWARD -i \${WG_IF_VAR} -o \${WG_IF_VAR} -j DROP
iptables -A FORWARD -i \${WG_IF_VAR} -p tcp --dport 25 -j DROP
iptables -A FORWARD -i \${WG_IF_VAR} -p tcp --dport 587 -j DROP
iptables -A FORWARD -i \${WG_IF_VAR} -p tcp --dport 465 -j DROP

# DDoS 基礎防護
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# 日誌記錄
logger "WireGuard 安全啟動 - \$(date)"
echo "\$(date): WireGuard 安全啟動" >> /var/log/wireguard.log
EOF

    chmod +x /etc/wireguard/postup-secure.sh
    
    # 創建 PreDown 腳本
    cat > /etc/wireguard/predown-secure.sh << EOF
#!/bin/bash

# 設置變數
WG_NET_VAR="${WG_NET}"
WAN_IF_VAR="${WAN_IF}"
WG_IF_VAR="${WG_IF}"

# 清理 iptables 規則
iptables -t nat -D POSTROUTING -s \${WG_NET_VAR} -o \${WAN_IF_VAR} -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i \${WG_IF_VAR} -o \${WAN_IF_VAR} -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i \${WAN_IF_VAR} -o \${WG_IF_VAR} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i \${WG_IF_VAR} -o \${WG_IF_VAR} -j DROP 2>/dev/null || true
iptables -D FORWARD -i \${WG_IF_VAR} -p tcp --dport 25 -j DROP 2>/dev/null || true
iptables -D FORWARD -i \${WG_IF_VAR} -p tcp --dport 587 -j DROP 2>/dev/null || true
iptables -D FORWARD -i \${WG_IF_VAR} -p tcp --dport 465 -j DROP 2>/dev/null || true
iptables -D INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p tcp --syn -j DROP 2>/dev/null || true

# 日誌記錄
logger "WireGuard 安全關閉 - \$(date)"
echo "\$(date): WireGuard 安全關閉" >> /var/log/wireguard.log
EOF

    chmod +x /etc/wireguard/predown-secure.sh
    
    # 伺服器配置
    cat > /etc/wireguard/${WG_IF}.conf << EOF
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
EOF

    chmod 600 /etc/wireguard/${WG_IF}.conf
    
    # 獲取伺服器 IP
    SERVER_IP=$(get_external_ip)
    
    # 標準客戶端配置
    cat > /etc/wireguard/clients/client01-direct.conf << EOF
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
EOF
    
    chmod 600 /etc/wireguard/clients/client01-direct.conf
    
    # 系統強化
    cat > /etc/sysctl.d/99-wg-security.conf << EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
EOF
    
    sysctl -p /etc/sysctl.d/99-wg-security.conf >/dev/null 2>&1
    
    # 監控腳本
    cat > /usr/local/bin/wg-check.sh << EOF
#!/bin/bash
WG_IF="${WG_IF}"

if ! systemctl is-active --quiet wg-quick@\$WG_IF; then
    echo "\$(date): WireGuard 服務異常，正在重啟..." >> /var/log/wireguard.log
    systemctl restart wg-quick@\$WG_IF
fi

PEERS=\$(wg show \$WG_IF peers 2>/dev/null | wc -l)
echo "\$(date): 活躍連接數: \$PEERS" >> /var/log/wireguard.log
EOF

    chmod +x /usr/local/bin/wg-check.sh
    echo "*/10 * * * * root /usr/local/bin/wg-check.sh" >> /etc/crontab
    
    # 啟動服務
    systemctl enable wg-quick@${WG_IF}
    systemctl start wg-quick@${WG_IF}
    
    echo -e "${GREEN}✅ WireGuard 安裝完成${NC}"
}

# 創建整合配置
create_integrated_config() {
    echo -e "${BLUE}正在創建 WireGuard + Shadowsocks 整合配置...${NC}"
    
    # 獲取伺服器 IP
    SERVER_IP=$(get_external_ip)
    
    # Shadowsocks 客戶端配置
    cat > /etc/wireguard/clients/shadowsocks-client.json << EOF
{
    "server": "${SERVER_IP}",
    "server_port": ${SS_PORT},
    "password": "${SS_PASSWORD}",
    "method": "${SS_METHOD}",
    "mode": "tcp_and_udp",
    "locals": [
        {
            "protocol": "tunnel",
            "local_address": "127.0.0.1",
            "local_port": ${SS_LPORT},
            "forward_address": "${SERVER_IP}",
            "forward_port": ${WG_PORT}
        }
    ]
}
EOF
    
    # WireGuard 客戶端配置 (通過 Shadowsocks)
    cat > /etc/wireguard/clients/client01-via-shadowsocks.conf << EOF
[Interface]
Address = ${CLIENT_IP}
PrivateKey = ${CLIENT_PRIV}
DNS = ${DNS_ADDR}
MTU = ${MTU}

[Peer]
PublicKey = ${SERVER_PUB}
PresharedKey = ${CLIENT_PSK}
Endpoint = 127.0.0.1:${SS_LPORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    chmod 600 /etc/wireguard/clients/client01-via-shadowsocks.conf
    
    # 創建使用說明
    cat > /etc/wireguard/clients/README.md << EOF
# WireGuard + Shadowsocks 使用說明

## 伺服器信息
- 伺服器 IP: ${SERVER_IP}
- WireGuard 端口: ${WG_PORT}
- Shadowsocks 端口: ${SS_PORT}
- Shadowsocks 密碼: ${SS_PASSWORD}
- 加密方式: ${SS_METHOD}

## 使用方式

### 方式一：直接 WireGuard 連接
使用配置文件: client01-direct.conf

### 方式二：WireGuard over Shadowsocks (推薦)
1. 先啟動 Shadowsocks 客戶端，使用 shadowsocks-client.json
2. 再連接 WireGuard，使用 client01-via-shadowsocks.conf

## Windows 客戶端步驟
1. 下載 shadowsocks-rust Windows 版本
2. 使用 shadowsocks-client.json 配置啟動 Shadowsocks
3. 在 WireGuard 中導入 client01-via-shadowsocks.conf
4. 連接 WireGuard

這樣 WireGuard 流量會通過 Shadowsocks 加密封裝，有效對抗 DPI 檢測。
EOF
    
    echo -e "${GREEN}✅ 整合配置創建完成${NC}"
}

# 防火牆配置
configure_firewall() {
    echo -e "${BLUE}正在配置防火牆...${NC}"
    
    # 允許 SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
    
    # 允許 WireGuard
    iptables -A INPUT -p udp --dport ${WG_PORT} -j ACCEPT 2>/dev/null || true
    
    # 允許 Shadowsocks
    if [[ "$1" =~ (2|3) ]]; then
        iptables -A INPUT -p tcp --dport ${SS_PORT} -j ACCEPT 2>/dev/null || true
        iptables -A INPUT -p udp --dport ${SS_PORT} -j ACCEPT 2>/dev/null || true
    fi
    
    # 保存規則
    netfilter-persistent save >/dev/null 2>&1 || true
    
    echo -e "${GREEN}✅ 防火牆配置完成${NC}"
}

# 顯示配置信息
show_configs() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  配置信息總覽${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    SERVER_IP=$(get_external_ip)
    
    if systemctl is-active --quiet wg-quick@${WG_IF} 2>/dev/null; then
        echo -e "${GREEN}🟢 WireGuard 狀態: 運行中${NC}"
        echo -e "   端口: ${WG_PORT}"
    else
        echo -e "${RED}🔴 WireGuard 狀態: 未運行${NC}"
    fi
    
    if snap services shadowsocks-rust.ssserver-daemon 2>/dev/null | grep -q "active"; then
        echo -e "${GREEN}🟢 Shadowsocks 狀態: 運行中${NC}"
        echo -e "   端口: ${SS_PORT}"
        
        # 讀取密碼
        SS_CONFIG="/var/snap/shadowsocks-rust/common/etc/shadowsocks-rust/config.json"
        if [[ -f "$SS_CONFIG" ]]; then
            CURRENT_PASSWORD=$(grep '"password"' "$SS_CONFIG" | cut -d'"' -f4)
            echo -e "   密碼: ${CURRENT_PASSWORD}"
        fi
        echo -e "   加密: ${SS_METHOD}"
    else
        echo -e "${RED}🔴 Shadowsocks 狀態: 未運行${NC}"
    fi
    
    echo
    echo -e "${YELLOW}伺服器 IP: ${SERVER_IP}${NC}"
    echo -e "${YELLOW}管理命令:${NC}"
    echo -e "  檢查 WireGuard: wg show"
    echo -e "  檢查 Shadowsocks: snap services shadowsocks-rust"
    echo -e "  查看日誌: tail -f /var/log/wireguard.log"
    
    if [[ -d "/etc/wireguard/clients" ]]; then
        echo
        echo -e "${BLUE}客戶端配置文件:${NC}"
        ls -la /etc/wireguard/clients/ 2>/dev/null || true
    fi
}

# 顯示 QR Code
show_qr_code() {
    echo -e "${BLUE}QR Codes:${NC}"
    
    if [[ -f "/etc/wireguard/clients/client01-direct.conf" ]]; then
        echo -e "${GREEN}WireGuard 直連:${NC}"
        qrencode -t ansiutf8 < /etc/wireguard/clients/client01-direct.conf 2>/dev/null || echo "QR Code 生成失敗"
        echo
    fi
    
    if [[ -f "/etc/wireguard/clients/client01-via-shadowsocks.conf" ]]; then
        echo -e "${GREEN}WireGuard via Shadowsocks:${NC}"
        qrencode -t ansiutf8 < /etc/wireguard/clients/client01-via-shadowsocks.conf 2>/dev/null || echo "QR Code 生成失敗"
    fi
}

# 主函數
main() {
    check_root
    show_menu
    
    case $choice in
        1)
            echo -e "${GREEN}選擇: 僅安裝 WireGuard${NC}"
            prepare_system
            install_wireguard
            configure_firewall 1
            show_configs
            show_qr_code
            ;;
        2)
            echo -e "${GREEN}選擇: 僅安裝 Shadowsocks${NC}"
            prepare_system
            install_shadowsocks
            configure_firewall 2
            show_configs
            ;;
        3)
            echo -e "${GREEN}選擇: WireGuard + Shadowsocks 整合模式${NC}"
            prepare_system
            install_shadowsocks
            sleep 2
            install_wireguard
            create_integrated_config
            configure_firewall 3
            show_configs
            show_qr_code
            
            echo
            echo -e "${PURPLE}========================================${NC}"
            echo -e "${PURPLE}  🎉 整合模式部署完成！${NC}"
            echo -e "${PURPLE}========================================${NC}"
            echo -e "${YELLOW}📁 重要文件位置:${NC}"
            echo -e "  客戶端配置: /etc/wireguard/clients/"
            echo -e "  使用說明: /etc/wireguard/clients/README.md"
            echo
            echo -e "${GREEN}🔥 推薦使用方式:${NC}"
            echo -e "1. 先測試 client01-direct.conf (直連)"
            echo -e "2. 如遇限制，使用 Shadowsocks 整合方式"
            echo -e "3. 詳細說明請查看 README.md"
            ;;
        4)
            show_configs
            show_qr_code
            ;;
        5)
            echo -e "${GREEN}退出安裝${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}無效選項，請重新運行腳本${NC}"
            exit 1
            ;;
    esac
    
    echo
    echo -e "${GREEN}🎉 部署完成！${NC}"
    echo -e "${YELLOW}記得在 Vultr 防火牆中開放端口 ${WG_PORT} (UDP) 和 ${SS_PORT} (TCP/UDP)${NC}"
}

# 執行主函數
main
