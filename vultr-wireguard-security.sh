#!/bin/bash
# =============================================================================
# WireGuard Security Enhanced Deployment Script
# 基於最小化版本，加入企業級安全設定
# =============================================================================

set -e

# ===================== 配置區域 =====================
WG_IF="awg0"
WG_PORT="${WG_PORT:-51820}"
WG_NET="10.66.66.0/24"
WG_SVR_IP="10.66.66.1/24"
CLIENT_IP="10.66.66.10/32"
DNS_ADDR="${DNS_ADDR:-1.1.1.1}"
MTU="${MTU:-1280}"
MAX_CLIENTS="${MAX_CLIENTS:-10}"

# 安全設定
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-true}"
ENABLE_PORT_KNOCK="${ENABLE_PORT_KNOCK:-false}"
ENABLE_LOG_MONITOR="${ENABLE_LOG_MONITOR:-true}"
RATE_LIMIT="${RATE_LIMIT:-50/min}"
SSH_PORT="${SSH_PORT:-22}"

# 顏色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ===================== 函數庫 =====================
print_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║         WireGuard Security Enhanced Version                 ║
║               企業級安全強化部署腳本                        ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log() { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

check_root() {
    [[ $EUID -eq 0 ]] || { error "必須以 root 權限運行"; exit 1; }
}

detect_wan() {
    WAN_IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    success "檢測到 WAN 介面: $WAN_IF"
}

# ===================== 安全強化函數 =====================
install_security_packages() {
    log "安裝安全相關套件..."
    export DEBIAN_FRONTEND=noninteractive
    
    apt-get update -qq
    
    local packages="wireguard wireguard-tools qrencode curl"
    
    if [[ "$ENABLE_FAIL2BAN" == "true" ]]; then
        packages="$packages fail2ban"
    fi
    
    if [[ "$ENABLE_LOG_MONITOR" == "true" ]]; then
        packages="$packages logwatch rsyslog"
    fi
    
    # 安裝基本安全工具
    packages="$packages ufw iptables-persistent netfilter-persistent"
    
    apt-get install -y -qq $packages
    success "安全套件安裝完成"
}

setup_fail2ban() {
    if [[ "$ENABLE_FAIL2BAN" != "true" ]]; then
        return 0
    fi
    
    log "配置 fail2ban 防暴力破解..."
    
    # 創建 WireGuard fail2ban 規則
    cat > /etc/fail2ban/filter.d/wireguard.conf << 'F2BCONF'
[Definition]
failregex = .*: Invalid handshake initiation from <HOST>.*
ignoreregex =
F2BCONF

    # 創建 fail2ban jail
    cat > /etc/fail2ban/jail.d/wireguard.conf << 'JAILCONF'
[wireguard]
enabled = true
port = 51820
protocol = udp
filter = wireguard
logpath = /var/log/syslog
maxretry = 3
bantime = 3600
findtime = 600
action = iptables[name=wireguard, port=51820, protocol=udp]
JAILCONF

    # SSH 保護加強
    cat > /etc/fail2ban/jail.d/sshd.conf << 'SSHCONF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
findtime = 600
SSHCONF

    systemctl enable fail2ban
    systemctl restart fail2ban
    
    success "fail2ban 配置完成"
}

secure_ssh() {
    log "強化 SSH 安全設定..."
    
    # 備份原始配置
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # 安全設定
    cat >> /etc/ssh/sshd_config << 'SSHCONF'

# WireGuard 部署安全強化
Protocol 2
MaxAuthTries 3
LoginGraceTime 30
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
SSHCONF

    # 如果有自定義 SSH 端口
    if [[ "$SSH_PORT" != "22" ]]; then
        sed -i "s/^#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
        warn "SSH 端口已改為 $SSH_PORT，請確保防火牆允許此端口"
    fi
    
    # 驗證配置
    sshd -t && systemctl restart sshd
    
    success "SSH 安全設定完成"
}

setup_advanced_firewall() {
    log "設置進階防火牆規則..."
    
    # 重置 UFW
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny forward
    
    # SSH 保護
    if [[ "$SSH_PORT" == "22" ]]; then
        ufw limit ssh comment "SSH rate limit"
    else
        ufw limit $SSH_PORT comment "SSH custom port rate limit"
    fi
    
    # WireGuard 端口（有速率限制）
    iptables -A INPUT -p udp --dport $WG_PORT -m limit --limit $RATE_LIMIT --limit-burst 5 -j ACCEPT
    iptables -A INPUT -p udp --dport $WG_PORT -j DROP
    
    # 允許 WireGuard
    ufw allow $WG_PORT/udp comment "WireGuard VPN"
    
    # 防止常見攻擊
    # SYN flood 保護
    iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP
    
    # Ping flood 保護  
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    
    # 拒絕無效包
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    
    # 記錄被拒絕的包
    iptables -A INPUT -j LOG --log-prefix "UFW-BLOCKED: " --log-level 4 -m limit --limit 3/min
    
    # 保存 iptables 規則
    netfilter-persistent save
    
    # 啟用 UFW
    ufw --force enable
    
    success "進階防火牆配置完成"
}

generate_secure_keys() {
    log "生成安全密鑰..."
    
    mkdir -p /etc/wireguard/{clients,keys,backup}
    chmod 700 /etc/wireguard /etc/wireguard/clients /etc/wireguard/keys /etc/wireguard/backup
    
    # 生成密鑰
    SERVER_PRIV=$(wg genkey)
    SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
    CLIENT_PRIV=$(wg genkey)  
    CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
    CLIENT_PSK=$(wg genpsk)
    
    # 安全存儲密鑰
    echo "$SERVER_PRIV" > /etc/wireguard/keys/server_private.key
    echo "$SERVER_PUB" > /etc/wireguard/keys/server_public.key
    echo "$CLIENT_PRIV" > /etc/wireguard/keys/client_private.key
    echo "$CLIENT_PUB" > /etc/wireguard/keys/client_public.key
    echo "$CLIENT_PSK" > /etc/wireguard/keys/client_psk.key
    
    chmod 600 /etc/wireguard/keys/*.key
    
    # 記錄密鑰生成時間
    echo "$(date): Keys generated" >> /var/log/wireguard-security.log
    
    success "安全密鑰生成完成"
}

create_secure_config() {
    log "創建安全配置文件..."
    
    # 伺服器配置
    cat > /etc/wireguard/${WG_IF}.conf << WGCONF
[Interface]
Address = ${WG_SVR_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV}
PostUp = /etc/wireguard/postup-secure.sh
PreDown = /etc/wireguard/predown-secure.sh
SaveConfig = false

[Peer]
PublicKey = ${CLIENT_PUB}
PresharedKey = ${CLIENT_PSK}
AllowedIPs = ${CLIENT_IP}
PersistentKeepalive = 25
WGCONF

    chmod 600 /etc/wireguard/${WG_IF}.conf
    
    # 安全 PostUp 腳本
    cat > /etc/wireguard/postup-secure.sh << 'POSTUP'
#!/bin/bash
set -e

# 啟用 IP 轉發
sysctl -w net.ipv4.ip_forward=1

# NAT 規則
iptables -t nat -A POSTROUTING -s WG_NET_PLACEHOLDER -o WAN_IF_PLACEHOLDER -j MASQUERADE

# 轉發規則
iptables -A FORWARD -i WG_IF_PLACEHOLDER -o WAN_IF_PLACEHOLDER -j ACCEPT
iptables -A FORWARD -i WAN_IF_PLACEHOLDER -o WG_IF_PLACEHOLDER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# 防止客戶端互相訪問
iptables -A FORWARD -i WG_IF_PLACEHOLDER -o WG_IF_PLACEHOLDER -j DROP

# 限制客戶端只能訪問特定服務
iptables -A FORWARD -i WG_IF_PLACEHOLDER -p tcp --dport 25 -j DROP   # SMTP
iptables -A FORWARD -i WG_IF_PLACEHOLDER -p tcp --dport 587 -j DROP  # SMTP TLS
iptables -A FORWARD -i WG_IF_PLACEHOLDER -p tcp --dport 465 -j DROP  # SMTPS

# 日誌記錄
logger "WireGuard interface WG_IF_PLACEHOLDER started"
echo "$(date): WireGuard started" >> /var/log/wireguard-security.log
POSTUP

    # 替換變數
    sed -i "s/WG_NET_PLACEHOLDER/${WG_NET}/g" /etc/wireguard/postup-secure.sh
    sed -i "s/WAN_IF_PLACEHOLDER/${WAN_IF}/g" /etc/wireguard/postup-secure.sh
    sed -i "s/WG_IF_PLACEHOLDER/${WG_IF}/g" /etc/wireguard/postup-secure.sh
    
    # 安全 PreDown 腳本
    cat > /etc/wireguard/predown-secure.sh << 'PREDOWN'
#!/bin/bash

# 清理 NAT 規則
iptables -t nat -D POSTROUTING -s WG_NET_PLACEHOLDER -o WAN_IF_PLACEHOLDER -j MASQUERADE 2>/dev/null || true

# 清理轉發規則
iptables -D FORWARD -i WG_IF_PLACEHOLDER -o WAN_IF_PLACEHOLDER -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i WAN_IF_PLACEHOLDER -o WG_IF_PLACEHOLDER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i WG_IF_PLACEHOLDER -o WG_IF_PLACEHOLDER -j DROP 2>/dev/null || true

# 清理限制規則
iptables -D FORWARD -i WG_IF_PLACEHOLDER -p tcp --dport 25 -j DROP 2>/dev/null || true
iptables -D FORWARD -i WG_IF_PLACEHOLDER -p tcp --dport 587 -j DROP 2>/dev/null || true
iptables -D FORWARD -i WG_IF_PLACEHOLDER -p tcp --dport 465 -j DROP 2>/dev/null || true

# 日誌記錄
logger "WireGuard interface WG_IF_PLACEHOLDER stopped"
echo "$(date): WireGuard stopped" >> /var/log/wireguard-security.log
PREDOWN

    # 替換變數
    sed -i "s/WG_NET_PLACEHOLDER/${WG_NET}/g" /etc/wireguard/predown-secure.sh
    sed -i "s/WAN_IF_PLACEHOLDER/${WAN_IF}/g" /etc/wireguard/predown-secure.sh
    sed -i "s/WG_IF_PLACEHOLDER/${WG_IF}/g" /etc/wireguard/predown-secure.sh
    
    chmod +x /etc/wireguard/postup-secure.sh /etc/wireguard/predown-secure.sh
    
    success "安全配置文件創建完成"
}

create_client_config() {
    log "創建客戶端配置..."
    
    SERVER_IP=$(curl -4 -s --max-time 10 https://api.ipify.org || echo "YOUR_SERVER_IP")
    
    cat > /etc/wireguard/clients/client01.conf << CLIENTCONF
# WireGuard 安全客戶端配置
# 生成時間: $(date)
# 服務器: ${SERVER_IP}

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
    
    success "客戶端配置創建完成"
}

setup_monitoring() {
    if [[ "$ENABLE_LOG_MONITOR" != "true" ]]; then
        return 0
    fi
    
    log "設置監控和日誌..."
    
    # 創建監控腳本
    cat > /usr/local/bin/wg-monitor.sh << 'MONITOR'
#!/bin/bash
# WireGuard 安全監控腳本

LOG_FILE="/var/log/wireguard-security.log"
WG_IF="awg0"

# 檢查 WireGuard 狀態
if ! systemctl is-active --quiet wg-quick@$WG_IF; then
    echo "$(date): WireGuard service down!" >> $LOG_FILE
    systemctl restart wg-quick@$WG_IF
fi

# 檢查連接數
PEER_COUNT=$(wg show $WG_IF peers | wc -l)
if [[ $PEER_COUNT -gt MAX_CLIENTS_PLACEHOLDER ]]; then
    echo "$(date): Too many peers: $PEER_COUNT" >> $LOG_FILE
fi

# 檢查異常流量
wg show $WG_IF dump | while read -r line; do
    if [[ $(echo "$line" | awk '{print $6}') -gt 1000000000 ]]; then  # 1GB
        echo "$(date): High traffic detected: $line" >> $LOG_FILE
    fi
done

# 清理舊日誌（保留30天）
find /var/log -name "wireguard-*.log" -mtime +30 -delete
MONITOR

    sed -i "s/MAX_CLIENTS_PLACEHOLDER/${MAX_CLIENTS}/g" /usr/local/bin/wg-monitor.sh
    chmod +x /usr/local/bin/wg-monitor.sh
    
    # 創建定時任務
    cat > /etc/cron.d/wireguard-monitor << 'CRON'
# WireGuard 監控任務
*/5 * * * * root /usr/local/bin/wg-monitor.sh
0 2 * * * root /usr/sbin/logrotate /etc/logrotate.d/wireguard
CRON

    # 日誌輪轉配置
    cat > /etc/logrotate.d/wireguard << 'LOGROTATE'
/var/log/wireguard-security.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
LOGROTATE

    success "監控和日誌設置完成"
}

setup_auto_backup() {
    log "設置自動備份..."
    
    # 創建備份腳本
    cat > /usr/local/bin/wg-backup.sh << 'BACKUP'
#!/bin/bash
BACKUP_DIR="/etc/wireguard/backup"
DATE=$(date +%Y%m%d_%H%M%S)

# 創建備份目錄
mkdir -p $BACKUP_DIR

# 備份配置文件
tar -czf $BACKUP_DIR/wireguard_backup_$DATE.tar.gz \
    /etc/wireguard/*.conf \
    /etc/wireguard/keys/ \
    /etc/wireguard/clients/ \
    /etc/wireguard/*.sh

# 清理30天前的備份
find $BACKUP_DIR -name "wireguard_backup_*.tar.gz" -mtime +30 -delete

echo "$(date): Backup created: wireguard_backup_$DATE.tar.gz" >> /var/log/wireguard-security.log
BACKUP

    chmod +x /usr/local/bin/wg-backup.sh
    
    # 每日備份
    echo "0 3 * * * root /usr/local/bin/wg-backup.sh" >> /etc/crontab
    
    success "自動備份設置完成"
}

enable_system_hardening() {
    log "啟用系統強化設定..."
    
    # 內核參數強化
    cat > /etc/sysctl.d/99-wireguard-security.conf << 'SYSCTL'
# WireGuard 安全強化
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.core.netdev_max_backlog = 5000
SYSCTL

    sysctl -p /etc/sysctl.d/99-wireguard-security.conf
    
    success "系統強化完成"
}

# ===================== 主執行流程 =====================
main() {
    print_banner
    
    check_root
    detect_wan
    install_security_packages
    setup_fail2ban
    secure_ssh
    setup_advanced_firewall
    generate_secure_keys
    create_secure_config
    create_client_config
    setup_monitoring
    setup_auto_backup
    enable_system_hardening
    
    # 啟動 WireGuard
    systemctl enable wg-quick@${WG_IF}
    systemctl start wg-quick@${WG_IF}
    
    # 顯示結果
    echo -e "\n${GREEN}🎉 WireGuard 安全強化版本部署完成！${NC}"
    echo
    echo -e "${BLUE}📊 安全設定總結${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ Fail2ban 暴力破解防護"
    echo "✅ SSH 安全強化"
    echo "✅ 進階防火牆規則"
    echo "✅ 速率限制保護"
    echo "✅ 客戶端隔離"
    echo "✅ 自動監控和日誌"
    echo "✅ 定期備份"
    echo "✅ 系統內核強化"
    echo
    echo -e "${BLUE}📁 重要文件位置${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "客戶端配置: /etc/wireguard/clients/client01.conf"
    echo "安全日誌: /var/log/wireguard-security.log"
    echo "備份目錄: /etc/wireguard/backup/"
    echo "密鑰目錄: /etc/wireguard/keys/"
    echo
    echo -e "${BLUE}🔧 管理命令${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "檢查狀態: wg show ${WG_IF}"
    echo "查看日誌: tail -f /var/log/wireguard-security.log"
    echo "fail2ban 狀態: fail2ban-client status"
    echo "手動備份: /usr/local/bin/wg-backup.sh"
    echo "監控檢查: /usr/local/bin/wg-monitor.sh"
    echo
    echo -e "${GREEN}✅ 系統已經過安全強化，可安全投入生產使用！${NC}"
    
    # 顯示客戶端配置
    echo -e "\n${BLUE}📱 客戶端配置內容${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat /etc/wireguard/clients/client01.conf
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # QR 碼
    if command -v qrencode >/dev/null; then
        echo -e "\n${BLUE}📱 QR Code${NC}"
        qrencode -t ansiutf8 < /etc/wireguard/clients/client01.conf
    fi
}

# 執行主函數
main "$@"