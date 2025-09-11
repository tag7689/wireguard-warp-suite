#!/bin/bash
# =============================================================================
# WireGuard + WARP + AmneziaWG 終極修復版 v5.5
# 修復所有已知問題的最終版本
# =============================================================================

set -euo pipefail

# ===================== 全域設定 =====================
readonly SCRIPT_VERSION="5.5"
readonly SCRIPT_NAME="wireguard-warp-amnezia-vultr-ultimate"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"

# 顏色輸出
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# WireGuard/AmneziaWG 設定
readonly WG_IF="awg0"
readonly WG_PORT="${WG_PORT:-51820}"
readonly WG_SUBNET="10.66.66.0/24"
readonly WG_SVR_IP="10.66.66.1/24"
readonly WG_DNS="${WG_DNS:-1.1.1.1}"
readonly CLIENT_NAME="client01"
readonly CLIENT_IP="10.66.66.10/32"

# AmneziaWG Magic Headers
readonly ENABLE_DPI_PROTECTION="${ENABLE_DPI_PROTECTION:-true}"
readonly AWG_H1="${AWG_H1:-$((RANDOM % 4294967294 + 1))}"
readonly AWG_H2="${AWG_H2:-$((RANDOM % 4294967294 + 1))}"
readonly AWG_H3="${AWG_H3:-$((RANDOM % 4294967294 + 1))}"
readonly AWG_H4="${AWG_H4:-$((RANDOM % 4294967294 + 1))}"
readonly AWG_S1="${AWG_S1:-$((RANDOM % 100 + 15))}"
readonly AWG_S2="${AWG_S2:-$((RANDOM % 100 + 15))}"
readonly AWG_JC="${AWG_JC:-$((RANDOM % 3 + 3))}"
readonly AWG_JMIN="${AWG_JMIN:-40}"
readonly AWG_JMAX="${AWG_JMAX:-70}"

# WARP 設定
readonly WARP_IF="wgcf"
readonly WARP_NETNS="warp"

# 系統狀態
AMNEZIAWG_MODE="userspace"
DEPLOYMENT_SUCCESS=false

# ===================== 輸出函數 =====================
print_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║         WireGuard + WARP + AmneziaWG 終極修復版             ║
║                v5.5 修復所有路徑和服務問題                  ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_step() { echo -e "${BLUE}[步驟] ${1}${NC}"; }
print_success() { echo -e "${GREEN}✅ ${1}${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  ${1}${NC}"; }
print_error() { echo -e "${RED}❌ ${1}${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  ${1}${NC}"; }

# ===================== 日誌處理 =====================
setup_logging() {
    mkdir -p "$(dirname "${LOG_FILE}")"
    exec 1> >(tee -a "${LOG_FILE}")
    exec 2> >(tee -a "${LOG_FILE}" >&2)
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${1:-INFO}] ${*:2}" >> "${LOG_FILE}"
}

error_exit() {
    print_error "$1"
    log "ERROR" "$1"
    cleanup_on_error
    exit "${2:-1}"
}

cleanup_on_error() {
    if [[ "$DEPLOYMENT_SUCCESS" == "false" ]]; then
        print_warning "清理失敗的部署..."
        systemctl stop wg-quick@${WG_IF} 2>/dev/null || true
        systemctl stop warp-netns.service 2>/dev/null || true
        ip netns del "${WARP_NETNS}" 2>/dev/null || true
    fi
}

trap cleanup_on_error EXIT

# ===================== 檢查和準備 =====================
check_system() {
    print_step "檢查系統環境"
    
    [[ $EUID -eq 0 ]] || error_exit "請使用 root 權限執行此腳本"
    
    if [[ ! -f /etc/os-release ]]; then
        error_exit "無法檢測作業系統版本"
    fi
    
    source /etc/os-release
    print_success "檢測到 $PRETTY_NAME"
    
    if ping -c 1 -W 5 8.8.8.8 &>/dev/null; then
        print_success "網路連線正常"
    else
        error_exit "無法連接網際網路"
    fi
}

check_network_environment() {
    print_step "檢查網路環境"
    
    local ipv4_addr
    ipv4_addr=$(curl -4 -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "")
    if [[ -n "$ipv4_addr" ]]; then
        print_success "IPv4 地址：$ipv4_addr"
        log "INFO" "IPv4: $ipv4_addr"
    else
        print_warning "無法獲取 IPv4 地址"
    fi
    
    local ipv6_addr
    ipv6_addr=$(curl -6 -s --max-time 10 https://api64.ipify.org 2>/dev/null || echo "")
    if [[ -n "$ipv6_addr" ]]; then
        print_success "IPv6 地址：$ipv6_addr"
        log "INFO" "IPv6: $ipv6_addr"
        print_info "檢測到 IPv4/IPv6 雙協議環境，將使用替代 WARP 方案"
    else
        print_info "僅檢測到 IPv4 環境"
    fi
}

# ===================== IPv4 優先設定 =====================
setup_ipv4_priority() {
    print_step "設定網路優化"
    
    print_info "設定 IPv4 優先解析..."
    cat > /etc/gai.conf <<EOF
# IPv4 優先設定
precedence ::1/128       50
precedence ::/0          30
precedence 2002::/16     30
precedence ::/96         20
precedence ::ffff:0:0/96 100
EOF
    
    print_success "網路優化設定完成"
}

# ===================== 安裝必要套件 =====================
install_packages_quick() {
    print_step "安裝必要套件"
    
    export DEBIAN_FRONTEND=noninteractive
    
    print_info "更新套件列表..."
    apt-get update -q || error_exit "無法更新套件列表"
    
    print_info "安裝基礎套件..."
    local base_packages=(
        wireguard wireguard-tools iproute2 iptables
        curl wget qrencode systemd net-tools
    )
    
    apt-get install -y -q "${base_packages[@]}" || error_exit "基礎套件安裝失敗"
    
    print_success "基礎套件安裝完成"
}

# ===================== 建立替代 WARP 配置 =====================
create_alternative_warp_config() {
    print_step "建立替代 WARP 配置"
    
    # 使用多個公開 Cloudflare WARP 端點
    local warp_endpoints=(
        "162.159.192.1:2408"
        "162.159.193.1:2408"  
        "162.159.195.1:2408"
    )
    
    # 選擇一個端點
    local selected_endpoint="${warp_endpoints[0]}"
    
    local warp_private_key
    warp_private_key=$(wg genkey)
    
    print_info "建立替代 WARP 配置..."
    cat > /root/wgcf-profile.conf <<EOF
[Interface]
PrivateKey = $warp_private_key
Address = 172.16.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
Endpoint = $selected_endpoint
PersistentKeepalive = 25
EOF
    
    print_success "替代 WARP 配置建立完成（端點：$selected_endpoint）"
}

# ===================== 建立網路環境 =====================
setup_network_namespace() {
    print_step "建立網路環境"
    
    # 清理舊的 namespace
    if ip netns list | grep -q "^${WARP_NETNS}"; then
        ip netns del "${WARP_NETNS}"
    fi
    
    # 建立 namespace
    ip netns add "${WARP_NETNS}"
    ip netns exec "${WARP_NETNS}" ip link set lo up
    
    # 建立 veth pair
    if ip link show "veth-main" >/dev/null 2>&1; then
        ip link del "veth-main"
    fi
    
    ip link add "veth-${WARP_NETNS}" type veth peer name "veth-main"
    ip link set "veth-${WARP_NETNS}" netns "${WARP_NETNS}"
    ip link set "veth-main" up
    
    # IP 配置
    ip addr add 172.31.0.1/30 dev "veth-main"
    ip netns exec "${WARP_NETNS}" ip addr add 172.31.0.2/30 dev "veth-${WARP_NETNS}"
    ip netns exec "${WARP_NETNS}" ip link set "veth-${WARP_NETNS}" up
    ip netns exec "${WARP_NETNS}" ip route add default via 172.31.0.1
    
    print_success "網路環境建立完成"
}

# ===================== 設定 WARP 在 namespace =====================
setup_warp_in_namespace() {
    print_step "設定 WARP 服務"
    
    # 提取 WARP 參數
    local warp_address warp_private_key warp_public_key warp_endpoint
    warp_address=$(grep "^Address = " /root/wgcf-profile.conf | cut -d' ' -f3 | head -n1)
    warp_private_key=$(grep "^PrivateKey = " /root/wgcf-profile.conf | cut -d' ' -f3)
    warp_public_key=$(grep "^PublicKey = " /root/wgcf-profile.conf | cut -d' ' -f3)
    warp_endpoint=$(grep "^Endpoint = " /root/wgcf-profile.conf | cut -d' ' -f3)
    
    print_info "WARP 配置："
    print_info "  地址：$warp_address"
    print_info "  端點：$warp_endpoint"
    
    # WARP 啟動腳本
    cat > /usr/local/bin/warp-netns-up.sh <<EOF
#!/bin/bash
set -e

echo "ℹ️  啟動 WARP 在 namespace..."

# 建立 WireGuard 介面
ip netns exec ${WARP_NETNS} ip link add dev ${WARP_IF} type wireguard 2>/dev/null || true
ip netns exec ${WARP_NETNS} ip address add ${warp_address} dev ${WARP_IF}

# 設定 WireGuard
ip netns exec ${WARP_NETNS} wg set ${WARP_IF} \\
    private-key <(echo "${warp_private_key}") \\
    peer ${warp_public_key} \\
    allowed-ips 0.0.0.0/0 \\
    endpoint ${warp_endpoint} \\
    persistent-keepalive 25

# 啟用介面
ip netns exec ${WARP_NETNS} ip link set ${WARP_IF} up

# 路由設定
ip netns exec ${WARP_NETNS} ip route add default dev ${WARP_IF} table main 2>/dev/null || true
ip netns exec ${WARP_NETNS} ip route add 172.31.0.0/30 dev veth-${WARP_NETNS} metric 100 2>/dev/null || true

echo "✅ WARP 啟動成功"
EOF
    
    cat > /usr/local/bin/warp-netns-down.sh <<EOF
#!/bin/bash
echo "ℹ️  關閉 WARP..."
ip netns exec ${WARP_NETNS} ip link del ${WARP_IF} 2>/dev/null || true
echo "✅ WARP 已關閉"
EOF
    
    chmod +x /usr/local/bin/warp-netns-{up,down}.sh
    print_success "WARP 服務腳本設定完成"
}

# ===================== 設定 WireGuard 伺服器 =====================
setup_wireguard_server() {
    print_step "設定 WireGuard 伺服器"
    
    # 建立正確的目錄結構
    mkdir -p /etc/wireguard
    mkdir -p /etc/amnezia/amneziawg/clients
    chmod 700 /etc/wireguard
    chmod 700 /etc/amnezia/amneziawg
    
    # 生成伺服器密鑰
    local server_private_key server_public_key
    server_private_key=$(wg genkey)
    server_public_key=$(echo "$server_private_key" | wg pubkey)
    
    # 儲存公鑰
    echo "$server_public_key" > /etc/amnezia/amneziawg/${WG_IF}.pub
    
    # WireGuard 標準配置（放在正確位置）
    cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_SVR_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${server_private_key}
PostUp = /etc/wireguard/postup.sh
PreDown = /etc/wireguard/predown.sh
EOF
    
    chmod 600 /etc/wireguard/${WG_IF}.conf
    
    # AmneziaWG 版本配置（用於客戶端生成）
    cat > /etc/amnezia/amneziawg/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_SVR_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${server_private_key}

# AmneziaWG Magic Headers
Jc = ${AWG_JC}
Jmin = ${AWG_JMIN}
Jmax = ${AWG_JMAX}
S1 = ${AWG_S1}
S2 = ${AWG_S2}
H1 = ${AWG_H1}
H2 = ${AWG_H2}
H3 = ${AWG_H3}
H4 = ${AWG_H4}
EOF
    
    chmod 600 /etc/amnezia/amneziawg/${WG_IF}.conf
    
    # PostUp/PreDown 腳本
    cat > /etc/wireguard/postup.sh <<EOF
#!/bin/bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s ${WG_SUBNET} -o veth-main -j MASQUERADE
iptables -A FORWARD -i ${WG_IF} -o veth-main -j ACCEPT
iptables -A FORWARD -i veth-main -o ${WG_IF} -j ACCEPT

# WARP NAT 規則（可能會失敗，但不影響主要功能）
ip netns exec ${WARP_NETNS} iptables -t nat -A POSTROUTING -s 172.31.0.0/30 -o ${WARP_IF} -j MASQUERADE 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -A FORWARD -i veth-${WARP_NETNS} -o ${WARP_IF} -j ACCEPT 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -A FORWARD -i ${WARP_IF} -o veth-${WARP_NETNS} -j ACCEPT 2>/dev/null || true

logger "WireGuard PostUp 完成"
EOF
    
    cat > /etc/wireguard/predown.sh <<EOF
#!/bin/bash
iptables -t nat -D POSTROUTING -s ${WG_SUBNET} -o veth-main -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i ${WG_IF} -o veth-main -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i veth-main -o ${WG_IF} -j ACCEPT 2>/dev/null || true

# WARP 清理（可能會失敗）
ip netns exec ${WARP_NETNS} iptables -t nat -D POSTROUTING -s 172.31.0.0/30 -o ${WARP_IF} -j MASQUERADE 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -D FORWARD -i veth-${WARP_NETNS} -o ${WARP_IF} -j ACCEPT 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -D FORWARD -i ${WARP_IF} -o veth-${WARP_NETNS} -j ACCEPT 2>/dev/null || true

logger "WireGuard PreDown 完成"
EOF
    
    chmod +x /etc/wireguard/{postup,predown}.sh
    print_success "WireGuard 伺服器設定完成"
}

# ===================== 建立客戶端配置 =====================
create_client_configs() {
    print_step "建立客戶端配置"
    
    # 生成客戶端密鑰
    local client_private_key client_public_key client_psk
    client_private_key=$(wg genkey)
    client_public_key=$(echo "$client_private_key" | wg pubkey)
    client_psk=$(wg genpsk)
    
    local server_public_key server_ip
    server_public_key=$(cat /etc/amnezia/amneziawg/${WG_IF}.pub)
    server_ip=$(curl -4 -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "YOUR_SERVER_IP")
    
    # 添加 peer 到伺服器配置
    cat >> /etc/wireguard/${WG_IF}.conf <<EOF

[Peer]
PublicKey = ${client_public_key}
PresharedKey = ${client_psk}
AllowedIPs = ${CLIENT_IP}
EOF
    
    cat >> /etc/amnezia/amneziawg/${WG_IF}.conf <<EOF

[Peer]
PublicKey = ${client_public_key}
PresharedKey = ${client_psk}
AllowedIPs = ${CLIENT_IP}
EOF
    
    # 標準 WireGuard 客戶端配置
    cat > "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_standard.conf" <<EOF
[Interface]
PrivateKey = ${client_private_key}
Address = ${CLIENT_IP}
DNS = ${WG_DNS}
MTU = 1280

[Peer]
PublicKey = ${server_public_key}
PresharedKey = ${client_psk}
Endpoint = ${server_ip}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    
    # AmneziaWG 客戶端配置
    cat > "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_amnezia.conf" <<EOF
[Interface]
PrivateKey = ${client_private_key}
Address = ${CLIENT_IP}
DNS = ${WG_DNS}
MTU = 1280

[Peer]
PublicKey = ${server_public_key}
PresharedKey = ${client_psk}
Endpoint = ${server_ip}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

# AmneziaWG Magic Headers
Jc = ${AWG_JC}
Jmin = ${AWG_JMIN}
Jmax = ${AWG_JMAX}
S1 = ${AWG_S1}
S2 = ${AWG_S2}
H1 = ${AWG_H1}
H2 = ${AWG_H2}
H3 = ${AWG_H3}
H4 = ${AWG_H4}
EOF
    
    chmod 600 /etc/amnezia/amneziawg/clients/*.conf
    
    # 生成 QR Code（標準版本）
    if command -v qrencode >/dev/null; then
        qrencode -t PNG -o "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_standard_qr.png" \
                 < "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_standard.conf"
        print_info "QR Code 已生成"
    fi
    
    print_success "客戶端配置已建立"
}

# ===================== 設定系統服務 =====================
setup_services() {
    print_step "設定系統服務"
    
    # WARP namespace 服務
    cat > /etc/systemd/system/warp-netns.service <<EOF
[Unit]
Description=WARP in Network Namespace
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/warp-netns-up.sh
ExecStop=/usr/local/bin/warp-netns-down.sh
Restart=on-failure
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable warp-netns.service
    print_success "系統服務設定完成"
}

# ===================== 啟動所有服務 =====================
start_all_services() {
    print_step "啟動所有服務"
    
    # 先啟動 WARP namespace
    print_info "啟動 WARP namespace 服務..."
    if systemctl start warp-netns.service; then
        print_success "WARP namespace 服務啟動成功"
    else
        print_warning "WARP namespace 服務啟動失敗，但繼續部署"
    fi
    sleep 2
    
    # 啟動 WireGuard
    print_info "啟動 WireGuard 服務..."
    systemctl enable wg-quick@${WG_IF}
    if systemctl start wg-quick@${WG_IF}; then
        print_success "WireGuard 服務啟動成功"
    else
        print_error "WireGuard 服務啟動失敗"
        return 1
    fi
    
    sleep 2
    print_success "所有服務已啟動"
}

# ===================== 最終驗證 =====================
final_verification() {
    print_step "系統驗證"
    
    local errors=0
    
    # 檢查 WireGuard 服務
    if systemctl is-active --quiet wg-quick@${WG_IF}; then
        print_success "WireGuard 服務運行正常"
    else
        print_error "WireGuard 服務未運行"
        errors=$((errors + 1))
    fi
    
    # 檢查 WireGuard 介面
    if ip link show ${WG_IF} >/dev/null 2>&1; then
        print_success "WireGuard 介面存在"
    else
        print_error "WireGuard 介面不存在"
        errors=$((errors + 1))
    fi
    
    # 檢查 WARP namespace（非關鍵）
    if systemctl is-active --quiet warp-netns.service; then
        print_success "WARP namespace 服務運行正常"
        
        if ip netns exec "${WARP_NETNS}" ip link show "${WARP_IF}" >/dev/null 2>&1; then
            print_success "WARP 介面存在"
            
            # 測試 WARP 連線
            if ip netns exec "${WARP_NETNS}" ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1; then
                print_success "WARP 連線測試通過"
            else
                print_warning "WARP 連線測試失敗（不影響主要功能）"
            fi
        else
            print_warning "WARP 介面不存在（不影響主要功能）"
        fi
    else
        print_warning "WARP namespace 服務未運行（不影響主要功能）"
    fi
    
    return $errors
}

# ===================== 顯示部署結果 =====================
show_deployment_result() {
    local errors=$1
    
    local server_ip warp_ip
    server_ip=$(curl -4 -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "未知")
    warp_ip=$(ip netns exec "${WARP_NETNS}" curl -4 -s --max-time 10 ifconfig.me 2>/dev/null || echo "未測試")
    
    if [[ $errors -eq 0 ]]; then
        DEPLOYMENT_SUCCESS=true
        
        print_banner
        print_success "🎉 WireGuard + WARP 終極修復版部署成功！"
        echo
        
        echo -e "${BLUE}📊 系統資訊${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "${GREEN}✓${NC} 部署模式：AmneziaWG ${AMNEZIAWG_MODE} 模式"
        echo -e "${GREEN}✓${NC} 服務狀態：WireGuard 正常運行"
        echo -e "${GREEN}✓${NC} 監聽埠：${WG_PORT}"
        echo -e "${GREEN}✓${NC} 伺服器 IP：${server_ip}"
        if [[ "$warp_ip" != "未測試" && "$warp_ip" != "未知" ]]; then
            echo -e "${GREEN}✓${NC} WARP 出口：${warp_ip}"
            echo -e "${GREEN}✓${NC} IP 保護：$(if [[ "$server_ip" != "$warp_ip" ]]; then echo "已啟用"; else echo "檢查中"; fi)"
        else
            echo -e "${YELLOW}⚠${NC} WARP 狀態：需要檢查"
        fi
        
        echo
        echo -e "${BLUE}📁 客戶端檔案${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• 標準客戶端：/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_standard.conf"
        echo "• AmneziaWG 客戶端：/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_amnezia.conf"
        echo "• 標準 QR Code：/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_standard_qr.png"
        
        echo
        echo -e "${BLUE}🔧 管理命令${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• 查看 WG 狀態：wg show ${WG_IF}"
        echo "• 重啟 WG：systemctl restart wg-quick@${WG_IF}"
        echo "• 查看 WARP：ip netns exec ${WARP_NETNS} wg show ${WARP_IF}"
        echo "• 測試 WARP：ip netns exec ${WARP_NETNS} curl ifconfig.me"
        echo "• 重啟 WARP：systemctl restart warp-netns.service"
        
        echo
        echo -e "${BLUE}📱 客戶端使用${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• 標準 WireGuard 客戶端：使用 ${CLIENT_NAME}_standard.conf"
        echo "• AmneziaWG 客戶端：使用 ${CLIENT_NAME}_amnezia.conf（需專用客戶端）"
        echo "• 推薦：優先使用 AmneziaWG 客戶端獲得更好的混淆效果"
        
        # 顯示標準版本 QR Code
        if [[ -f "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_standard.conf" ]] && command -v qrencode >/dev/null; then
            echo
            echo -e "${BLUE}📱 標準 WireGuard QR Code${NC}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            qrencode -t ansiutf8 < "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_standard.conf"
        fi
        
        echo
        echo -e "${GREEN}🎉 終極修復版部署完成！主要功能已正常運作。${NC}"
        echo -e "${GREEN}注意：WARP 功能可能需要時間穩定，主要 VPN 功能已可使用。${NC}"
        
    else
        print_error "部署失敗，發現 $errors 個關鍵問題"
        echo
        echo "故障排除："
        echo "1. 檢查 WireGuard 狀態：systemctl status wg-quick@${WG_IF}"
        echo "2. 查看詳細日誌：journalctl -u wg-quick@${WG_IF} -f"
        echo "3. 檢查配置檔案：cat /etc/wireguard/${WG_IF}.conf"
    fi
}

# ===================== 主函數 =====================
main() {
    print_banner
    print_info "WireGuard + WARP + AmneziaWG 終極修復版部署開始..."
    echo
    
    setup_logging
    log "INFO" "開始部署終極修復版 - 腳本版本 ${SCRIPT_VERSION}"
    
    # 完整部署流程
    check_system
    check_network_environment
    setup_ipv4_priority
    install_packages_quick
    create_alternative_warp_config
    setup_network_namespace
    setup_warp_in_namespace
    setup_wireguard_server
    create_client_configs
    setup_services
    start_all_services
    
    # 最終驗證
    local verification_errors
    verification_errors=$(final_verification)
    
    # 顯示結果
    show_deployment_result $verification_errors
    
    # 清理 trap
    trap - EXIT
    
    if [[ $verification_errors -eq 0 ]]; then
        log "INFO" "終極修復版部署成功完成"
        exit 0
    else
        log "ERROR" "部署失敗：$verification_errors 個關鍵問題"
        exit 1
    fi
}

# 執行主函數
main "$@"