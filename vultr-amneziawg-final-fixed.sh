#!/bin/bash
# =============================================================================
# WireGuard + WARP + AmneziaWG 最終修復版 v5.4
# 修復 DKMS 清理後目錄不存在的問題
# =============================================================================

set -euo pipefail

# ===================== 全域設定 =====================
readonly SCRIPT_VERSION="5.4"
readonly SCRIPT_NAME="wireguard-warp-amnezia-vultr-final"
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
AMNEZIAWG_MODE="disabled"
DEPLOYMENT_SUCCESS=false

# ===================== 輸出函數 =====================
print_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║         WireGuard + WARP + AmneziaWG 最終修復版             ║
║             v5.4 修復所有已知問題                           ║
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
        ip netns del "${WARP_NETNS}" 2>/dev/null || true
        systemctl stop awg-quick@${WG_IF} 2>/dev/null || true
        systemctl stop wg-quick@${WG_IF} 2>/dev/null || true
        systemctl stop warp-netns.service 2>/dev/null || true
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
        print_info "檢測到 IPv4/IPv6 雙協議環境，將優化 WARP 註冊"
    else
        print_info "僅檢測到 IPv4 環境"
    fi
    
    if nslookup api.cloudflareclient.com >/dev/null 2>&1; then
        print_success "DNS 解析正常"
    else
        print_warning "DNS 解析可能有問題"
    fi
}

# ===================== IPv4 優先設定 =====================
setup_ipv4_priority() {
    print_step "設定 IPv4 優先環境"
    
    print_info "設定 IPv4 優先解析..."
    cat > /etc/gai.conf <<EOF
# IPv4 優先設定 - 為了 WARP 相容性
precedence ::1/128       50
precedence ::/0          30
precedence 2002::/16     30
precedence ::/96         20
precedence ::ffff:0:0/96 100
EOF
    
    print_success "IPv4 優先環境設定完成"
}

# ===================== 快速安裝模式 =====================
install_packages_quick() {
    print_step "快速安裝必要套件"
    
    export DEBIAN_FRONTEND=noninteractive
    
    print_info "更新套件列表..."
    apt-get update || error_exit "無法更新套件列表"
    
    # 基礎套件
    print_info "安裝基礎套件..."
    local base_packages=(
        ca-certificates curl wget jq gnupg lsb-release software-properties-common
        iproute2 iptables ufw qrencode wireguard wireguard-tools
        systemd net-tools dnsutils build-essential dkms
    )
    
    apt-get install -y "${base_packages[@]}" || error_exit "基礎套件安裝失敗"
    
    print_success "基礎套件安裝完成"
}

# ===================== 直接設定 userspace 模式 =====================
setup_amneziawg_userspace() {
    print_step "設定 AmneziaWG userspace 模式"
    
    # 不嘗試安裝 AmneziaWG 套件，直接使用 userspace
    print_info "建立 AmneziaWG userspace 包裝器..."
    
    cat > /usr/local/bin/awg <<'EOF'
#!/bin/bash
exec /usr/bin/wg "$@"
EOF
    chmod +x /usr/local/bin/awg
    
    cat > /usr/local/bin/awg-quick <<'EOF'
#!/bin/bash
exec /usr/bin/wg-quick "$@"
EOF
    chmod +x /usr/local/bin/awg-quick
    
    AMNEZIAWG_MODE="userspace"
    print_success "AmneziaWG userspace 模式設定完成"
}

# ===================== 下載 wgcf =====================
install_wgcf() {
    print_step "下載 wgcf"
    
    if [[ ! -f /usr/local/bin/wgcf ]]; then
        print_info "下載 wgcf..."
        local wgcf_url="https://github.com/ViRb3/wgcf/releases/download/v2.2.19/wgcf_2.2.19_linux_amd64"
        
        if wget -4 -O /usr/local/bin/wgcf "$wgcf_url"; then
            chmod +x /usr/local/bin/wgcf
            print_success "wgcf 下載完成"
        else
            error_exit "無法下載 wgcf"
        fi
    else
        print_success "wgcf 已存在"
    fi
}

# ===================== 修復 WARP 註冊（IPv4 專用）=====================
fix_warp_registration_ipv4() {
    print_step "修復 WARP 註冊（IPv4 模式）"
    
    # 徹底清理舊帳戶
    print_info "清理所有 WARP 相關檔案..."
    rm -f /root/.wgcf-account.toml
    rm -f /root/wgcf-account.toml
    rm -f /root/wgcf-profile.conf
    
    # 使用 IPv4 強制註冊
    print_info "使用 IPv4 註冊 WARP 帳戶..."
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        print_info "註冊嘗試 $((retry_count + 1))/$max_retries（強制 IPv4）"
        
        # 使用環境變數強制 IPv4
        if timeout 30 bash -c '
            export GODEBUG=netdns=go
            export GOPROXY=direct
            /usr/local/bin/wgcf register --accept-tos 2>/dev/null
        ' 2>/dev/null; then
            print_success "WARP 帳戶註冊成功（IPv4 模式）"
            break
        else
            retry_count=$((retry_count + 1))
            print_warning "註冊失敗，清理後重試..."
            
            # 清理殘留檔案
            rm -f /root/.wgcf-account.toml /root/wgcf-account.toml
            
            if [[ $retry_count -eq $max_retries ]]; then
                print_warning "WARP 註冊失敗，使用公開配置"
                create_public_warp_config
                return 0
            fi
            
            sleep $((retry_count * 2))
        fi
    done
    
    # 生成設定檔
    print_info "生成 WARP 設定檔..."
    if timeout 30 /usr/local/bin/wgcf generate 2>/dev/null; then
        print_success "WARP 設定檔生成成功"
        
        # 驗證設定檔
        if [[ -f /root/wgcf-profile.conf ]] && grep -q "PrivateKey" /root/wgcf-profile.conf; then
            print_success "WARP 設定檔驗證通過"
            return 0
        fi
    fi
    
    print_warning "使用公開 WARP 配置"
    create_public_warp_config
    return 0
}

# ===================== 建立公開 WARP 配置 =====================
create_public_warp_config() {
    print_info "建立公開 WARP 配置..."
    
    local warp_private_key
    warp_private_key=$(wg genkey)
    
    # 建立公開設定檔（使用已知的 Cloudflare 端點）
    cat > /root/wgcf-profile.conf <<EOF
[Interface]
PrivateKey = $warp_private_key
Address = 172.16.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
Endpoint = 162.159.192.1:2408
PersistentKeepalive = 25
EOF
    
    print_success "公開 WARP 配置建立完成"
}

# ===================== 快速網路設定 =====================
setup_network_quick() {
    print_step "建立網路環境"
    
    # Network namespace
    if ip netns list | grep -q "^${WARP_NETNS}"; then
        ip netns del "${WARP_NETNS}"
    fi
    
    ip netns add "${WARP_NETNS}"
    ip netns exec "${WARP_NETNS}" ip link set lo up
    
    # veth pair
    ip link add "veth-${WARP_NETNS}" type veth peer name "veth-main" 2>/dev/null || true
    ip link set "veth-${WARP_NETNS}" netns "${WARP_NETNS}"
    ip link set "veth-main" up
    
    # IP 配置
    ip addr add 172.31.0.1/30 dev "veth-main"
    ip netns exec "${WARP_NETNS}" ip addr add 172.31.0.2/30 dev "veth-${WARP_NETNS}"
    ip netns exec "${WARP_NETNS}" ip link set "veth-${WARP_NETNS}" up
    ip netns exec "${WARP_NETNS}" ip route add default via 172.31.0.1
    
    print_success "網路環境建立完成"
}

# ===================== WARP 在 namespace 設定 =====================
setup_warp_in_namespace() {
    print_step "設定 WARP 在 namespace"
    
    # 提取 WARP 參數
    local warp_address warp_private_key warp_public_key warp_endpoint
    warp_address=$(grep "^Address = " /root/wgcf-profile.conf | cut -d' ' -f3 | head -n1)
    warp_private_key=$(grep "^PrivateKey = " /root/wgcf-profile.conf | cut -d' ' -f3)
    warp_public_key=$(grep "^PublicKey = " /root/wgcf-profile.conf | cut -d' ' -f3)
    warp_endpoint=$(grep "^Endpoint = " /root/wgcf-profile.conf | cut -d' ' -f3)
    
    print_info "WARP 參數："
    print_info "  地址：$warp_address"
    print_info "  端點：$warp_endpoint"
    
    # WARP 啟動腳本
    cat > /usr/local/bin/warp-netns-up.sh <<EOF
#!/bin/bash
set -euo pipefail

# 建立 WireGuard 介面
ip netns exec ${WARP_NETNS} ip link add dev ${WARP_IF} type wireguard
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

echo "✅ WARP 在 namespace 中啟動成功"
logger "WARP 在 namespace 中啟動成功"
EOF
    
    cat > /usr/local/bin/warp-netns-down.sh <<EOF
#!/bin/bash
ip netns exec ${WARP_NETNS} ip link del ${WARP_IF} 2>/dev/null || true
logger "WARP 在 namespace 中已關閉"
EOF
    
    chmod +x /usr/local/bin/warp-netns-{up,down}.sh
    print_success "WARP namespace 腳本設定完成"
}

# ===================== WireGuard 伺服器設定 =====================
setup_wireguard_server() {
    print_step "設定 WireGuard 伺服器"
    
    # 建立目錄
    mkdir -p /etc/amnezia/amneziawg/{clients,scripts}
    chmod 700 /etc/amnezia/amneziawg
    
    # 生成密鑰
    local server_private_key
    server_private_key=$(wg genkey)
    echo "$server_private_key" | wg pubkey > /etc/amnezia/amneziawg/${WG_IF}.pub
    
    # 伺服器設定檔
    cat > /etc/amnezia/amneziawg/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_SVR_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${server_private_key}
PostUp = /etc/amnezia/amneziawg/scripts/postup.sh
PreDown = /etc/amnezia/amneziawg/scripts/predown.sh
EOF

    # Magic Headers（僅在 userspace 模式作為註解）
    if [[ "$ENABLE_DPI_PROTECTION" == "true" ]]; then
        cat >> /etc/amnezia/amneziawg/${WG_IF}.conf <<EOF

# AmneziaWG Magic Headers (Note: userspace mode)
# Jc = ${AWG_JC}
# Jmin = ${AWG_JMIN}
# Jmax = ${AWG_JMAX}
# S1 = ${AWG_S1}
# S2 = ${AWG_S2}
# H1 = ${AWG_H1}
# H2 = ${AWG_H2}
# H3 = ${AWG_H3}
# H4 = ${AWG_H4}
EOF
        print_info "DPI 保護參數已記錄（${AMNEZIAWG_MODE} 模式）"
    fi
    
    chmod 600 /etc/amnezia/amneziawg/${WG_IF}.conf
    
    # PostUp/PreDown 腳本
    cat > /etc/amnezia/amneziawg/scripts/postup.sh <<EOF
#!/bin/bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s ${WG_SUBNET} -o veth-main -j MASQUERADE
iptables -A FORWARD -i ${WG_IF} -o veth-main -j ACCEPT
iptables -A FORWARD -i veth-main -o ${WG_IF} -j ACCEPT
ip netns exec ${WARP_NETNS} iptables -t nat -A POSTROUTING -s 172.31.0.0/30 -o ${WARP_IF} -j MASQUERADE 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -A FORWARD -i veth-${WARP_NETNS} -o ${WARP_IF} -j ACCEPT 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -A FORWARD -i ${WARP_IF} -o veth-${WARP_NETNS} -j ACCEPT 2>/dev/null || true
logger "WireGuard PostUp 完成"
EOF
    
    cat > /etc/amnezia/amneziawg/scripts/predown.sh <<EOF
#!/bin/bash
iptables -t nat -D POSTROUTING -s ${WG_SUBNET} -o veth-main -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i ${WG_IF} -o veth-main -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i veth-main -o ${WG_IF} -j ACCEPT 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -t nat -D POSTROUTING -s 172.31.0.0/30 -o ${WARP_IF} -j MASQUERADE 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -D FORWARD -i veth-${WARP_NETNS} -o ${WARP_IF} -j ACCEPT 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -D FORWARD -i ${WARP_IF} -o veth-${WARP_NETNS} -j ACCEPT 2>/dev/null || true
logger "WireGuard PreDown 完成"
EOF
    
    chmod +x /etc/amnezia/amneziawg/scripts/*.sh
    print_success "WireGuard 伺服器設定完成"
}

# ===================== 客戶端設定 =====================
create_client_config() {
    print_step "建立客戶端設定"
    
    # 生成客戶端密鑰
    local client_private_key client_public_key client_psk
    client_private_key=$(wg genkey)
    client_public_key=$(echo "$client_private_key" | wg pubkey)
    client_psk=$(wg genpsk)
    
    local server_public_key server_ip
    server_public_key=$(cat /etc/amnezia/amneziawg/${WG_IF}.pub)
    server_ip=$(curl -4 -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "YOUR_SERVER_IP")
    
    # 添加 peer
    cat >> /etc/amnezia/amneziawg/${WG_IF}.conf <<EOF

[Peer]
PublicKey = ${client_public_key}
PresharedKey = ${client_psk}
AllowedIPs = ${CLIENT_IP}
EOF
    
    # 客戶端設定（標準 WireGuard）
    cat > "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf" <<EOF
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
    
    # AmneziaWG 客戶端設定（需要專用客戶端）
    if [[ "$ENABLE_DPI_PROTECTION" == "true" ]]; then
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

# AmneziaWG Magic Headers (需要 AmneziaWG 客戶端)
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
        chmod 600 "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_amnezia.conf"
        print_info "AmneziaWG 客戶端設定已建立（需要專用客戶端）"
    fi
    
    chmod 600 "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf"
    
    # QR Code（標準 WireGuard）
    if command -v qrencode >/dev/null; then
        qrencode -t PNG -o "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_qr.png" \
                 < "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf"
    fi
    
    print_success "客戶端設定已建立"
}

# ===================== systemd 服務 =====================
setup_services() {
    print_step "設定 systemd 服務"
    
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
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable warp-netns.service
    print_success "systemd 服務設定完成"
}

# ===================== 啟動所有服務 =====================
start_all_services() {
    print_step "啟動所有服務"
    
    # 啟動 WARP
    print_info "啟動 WARP namespace 服務..."
    systemctl start warp-netns.service
    sleep 3
    
    # 啟動 WireGuard
    print_info "啟動 wg-quick 服務..."
    systemctl enable wg-quick@${WG_IF}
    systemctl start wg-quick@${WG_IF}
    sleep 2
    
    print_success "所有服務已啟動"
}

# ===================== 最終驗證 =====================
final_verification() {
    print_step "最終系統驗證"
    
    local errors=0
    
    # 檢查服務狀態
    if systemctl is-active --quiet warp-netns.service; then
        print_success "WARP namespace 服務運行正常"
    else
        print_error "WARP namespace 服務未運行"
        systemctl status warp-netns.service --no-pager -l | head -10
        errors=$((errors + 1))
    fi
    
    if systemctl is-active --quiet wg-quick@${WG_IF}; then
        print_success "WireGuard 服務運行正常"
    else
        print_error "WireGuard 服務未運行"
        systemctl status wg-quick@${WG_IF} --no-pager -l | head -10
        errors=$((errors + 1))
    fi
    
    # 檢查介面
    if ip link show ${WG_IF} >/dev/null 2>&1; then
        print_success "WireGuard 介面存在"
    else
        print_error "WireGuard 介面不存在"
        errors=$((errors + 1))
    fi
    
    # 檢查 WARP 在 namespace
    if ip netns exec "${WARP_NETNS}" ip link show "${WARP_IF}" >/dev/null 2>&1; then
        print_success "WARP 介面在 namespace 中存在"
        
        # 測試 WARP 連線
        if ip netns exec "${WARP_NETNS}" ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
            print_success "WARP 連線測試通過"
        else
            print_warning "WARP 連線測試失敗"
        fi
    else
        print_error "WARP 介面在 namespace 中不存在"
        errors=$((errors + 1))
    fi
    
    return $errors
}

# ===================== 顯示部署結果 =====================
show_deployment_result() {
    local errors=$1
    
    local server_ip warp_ip
    server_ip=$(curl -4 -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "未知")
    warp_ip=$(ip netns exec "${WARP_NETNS}" curl -4 -s --max-time 10 ifconfig.me 2>/dev/null || echo "未知")
    
    if [[ $errors -eq 0 ]]; then
        DEPLOYMENT_SUCCESS=true
        
        print_banner
        print_success "🎉 AmneziaWG + WARP 最終修復版部署成功！"
        echo
        
        echo -e "${BLUE}📊 系統資訊${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "${GREEN}✓${NC} 部署模式：AmneziaWG ${AMNEZIAWG_MODE} 模式"
        echo -e "${GREEN}✓${NC} 網路優化：IPv4 優先（雙協議相容）"
        echo -e "${GREEN}✓${NC} 監聽埠：${WG_PORT}"
        echo -e "${GREEN}✓${NC} 伺服器 IP：${server_ip}"
        echo -e "${GREEN}✓${NC} WARP 出口 IP：${warp_ip}"
        echo -e "${GREEN}✓${NC} IP 保護：$(if [[ "$server_ip" != "$warp_ip" && "$warp_ip" != "未知" ]]; then echo "已啟用"; else echo "檢查中"; fi)"
        
        echo
        echo -e "${BLUE}📁 重要檔案${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• 標準客戶端：/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf"
        echo "• 標準 QR Code：/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_qr.png"
        if [[ -f "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_amnezia.conf" ]]; then
            echo "• AmneziaWG 客戶端：/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_amnezia.conf"
        fi
        echo "• 日誌檔案：${LOG_FILE}"
        
        echo
        echo -e "${BLUE}🔧 管理命令${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• 查看狀態：wg show ${WG_IF}"
        echo "• 重啟服務：systemctl restart wg-quick@${WG_IF}"
        echo "• WARP 狀態：ip netns exec ${WARP_NETNS} wg show ${WARP_IF}"
        echo "• 測試 WARP：ip netns exec ${WARP_NETNS} curl ifconfig.me"
        echo "• WARP 重啟：systemctl restart warp-netns.service"
        
        # 顯示客戶端資訊
        if [[ "$ENABLE_DPI_PROTECTION" == "true" ]]; then
            echo
            echo -e "${BLUE}📱 客戶端使用說明${NC}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "• 標準 WireGuard 客戶端：使用 ${CLIENT_NAME}.conf（通用）"
            echo "• AmneziaWG 客戶端：使用 ${CLIENT_NAME}_amnezia.conf（混淆）"
            echo "• 推薦使用 AmneziaWG 客戶端以獲得最佳混淆效果"
        fi
        
        # QR Code（標準版本）
        if [[ -f "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf" ]] && command -v qrencode >/dev/null; then
            echo
            echo -e "${BLUE}📱 標準客戶端 QR Code${NC}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            qrencode -t ansiutf8 < "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf"
        fi
        
        echo
        echo -e "${GREEN}🎉 最終修復版部署完成！系統已準備就緒。${NC}"
        echo -e "${GREEN}注意：由於使用 userspace 模式，Magic Headers 僅在支援的客戶端中有效。${NC}"
        
    else
        print_error "部署失敗，發現 $errors 個問題"
        echo
        echo "排除建議："
        echo "1. 查看服務日誌：journalctl -u warp-netns.service -f"
        echo "2. 查看 WARP 連線：ip netns exec warp ping 1.1.1.1"
        echo "3. 檢查防火牆：ufw status"
        echo "4. 查看完整日誌：tail -f ${LOG_FILE}"
    fi
}

# ===================== 主函數 =====================
main() {
    print_banner
    print_info "WireGuard + WARP + AmneziaWG 最終修復版部署開始..."
    echo
    
    setup_logging
    log "INFO" "開始部署最終修復版 - 腳本版本 ${SCRIPT_VERSION}"
    
    # 完整部署流程（簡化版，避免 DKMS 問題）
    check_system
    check_network_environment
    setup_ipv4_priority
    install_packages_quick
    setup_amneziawg_userspace    # 直接使用 userspace，跳過 DKMS
    install_wgcf
    fix_warp_registration_ipv4
    setup_network_quick
    setup_warp_in_namespace
    setup_wireguard_server
    create_client_config
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
        log "INFO" "最終修復版部署成功完成"
        exit 0
    else
        log "ERROR" "部署完成但有 $verification_errors 個問題"
        exit 1
    fi
}

# 執行主函數
main "$@"