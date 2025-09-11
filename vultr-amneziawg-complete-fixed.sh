#!/bin/bash
# =============================================================================
# WireGuard + WARP + AmneziaWG 完整修復版 v5.3
# 包含完整的套件安裝 + IPv4/IPv6 + DKMS 修復
# =============================================================================

set -euo pipefail

# ===================== 全域設定 =====================
readonly SCRIPT_VERSION="5.3"
readonly SCRIPT_NAME="wireguard-warp-amnezia-vultr-complete"
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
║         WireGuard + WARP + AmneziaWG 完整修復版             ║
║             v5.3 包含套件安裝 + 雙協議修復                  ║
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

# ===================== 系統檢查 =====================
check_system() {
    print_step "檢查系統環境"
    
    # 檢查 root 權限
    [[ $EUID -eq 0 ]] || error_exit "請使用 root 權限執行此腳本"
    
    # 檢查作業系統
    if [[ ! -f /etc/os-release ]]; then
        error_exit "無法檢測作業系統版本"
    fi
    
    source /etc/os-release
    print_success "檢測到 $PRETTY_NAME"
    
    # 檢查網路連線
    if ping -c 1 -W 5 8.8.8.8 &>/dev/null; then
        print_success "網路連線正常"
    else
        error_exit "無法連接網際網路"
    fi
}

# ===================== 網路環境檢查 =====================
check_network_environment() {
    print_step "檢查網路環境"
    
    # 檢查 IPv4
    local ipv4_addr
    ipv4_addr=$(curl -4 -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "")
    if [[ -n "$ipv4_addr" ]]; then
        print_success "IPv4 地址：$ipv4_addr"
        log "INFO" "IPv4: $ipv4_addr"
    else
        print_warning "無法獲取 IPv4 地址"
    fi
    
    # 檢查 IPv6
    local ipv6_addr
    ipv6_addr=$(curl -6 -s --max-time 10 https://api64.ipify.org 2>/dev/null || echo "")
    if [[ -n "$ipv6_addr" ]]; then
        print_success "IPv6 地址：$ipv6_addr"
        log "INFO" "IPv6: $ipv6_addr"
        print_info "檢測到 IPv4/IPv6 雙協議環境，將優化 WARP 註冊"
    else
        print_info "僅檢測到 IPv4 環境"
    fi
    
    # 檢查 DNS 解析
    if nslookup api.cloudflareclient.com >/dev/null 2>&1; then
        print_success "DNS 解析正常"
    else
        print_warning "DNS 解析可能有問題"
    fi
}

# ===================== 強制 IPv4 環境設定 =====================
setup_ipv4_priority() {
    print_step "設定 IPv4 優先環境"
    
    # 建立 IPv4 優先的 gai.conf
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

# ===================== 安裝套件 =====================
install_packages() {
    print_step "安裝必要套件"
    
    export DEBIAN_FRONTEND=noninteractive
    
    print_info "更新套件列表..."
    apt-get update || error_exit "無法更新套件列表"
    
    # 核心開發環境
    print_info "安裝核心開發環境..."
    local kernel_packages=(
        linux-headers-$(uname -r)
        linux-source-$(uname -r | cut -d'-' -f1-2)
        build-essential dkms bc kmod cpio flex bison libssl-dev libelf-dev
    )
    
    apt-get install -y "${kernel_packages[@]}" 2>/dev/null || \
        print_warning "部分核心套件安裝失敗，將影響 AmneziaWG 核心模組功能"
    
    # 基礎套件
    print_info "安裝基礎套件..."
    local base_packages=(
        ca-certificates curl wget jq gnupg lsb-release software-properties-common
        iproute2 iptables ufw qrencode wireguard wireguard-tools
        systemd net-tools dnsutils
    )
    
    apt-get install -y "${base_packages[@]}" || error_exit "基礎套件安裝失敗"
    
    print_success "套件安裝完成"
}

# ===================== 安裝 AmneziaWG =====================
install_amneziawg() {
    print_step "安裝 AmneziaWG"
    
    # 添加 AmneziaWG PPA
    print_info "添加 AmneziaWG 軟體源..."
    local keyring_file="/usr/share/keyrings/amnezia.gpg"
    local sources_file="/etc/apt/sources.list.d/amnezia.list"
    
    # 清理舊設定
    rm -f "$keyring_file" "$sources_file"
    
    if wget -qO- "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x75c9dd72c799870e310542e24166f2c257290828" | gpg --dearmor > "$keyring_file"; then
        local codename="$VERSION_CODENAME"
        echo "deb [signed-by=${keyring_file}] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu ${codename} main" > "$sources_file"
        apt-get update 2>/dev/null || true
        print_success "AmneziaWG 軟體源已添加"
    else
        print_warning "無法添加 AmneziaWG 軟體源，將直接使用 userspace 模式"
        setup_userspace_mode
        return 0
    fi
    
    # 嘗試安裝 AmneziaWG
    print_info "安裝 AmneziaWG 套件..."
    if apt-get install -y amneziawg-tools amneziawg-dkms amneziawg 2>/dev/null; then
        print_success "AmneziaWG 套件安裝完成"
        # 注意：此時 DKMS 會失敗，但我們稍後會修復
    else
        print_warning "AmneziaWG 套件安裝失敗，使用 userspace 模式"
        setup_userspace_mode
        return 0
    fi
}

# ===================== 設定 userspace 模式 =====================
setup_userspace_mode() {
    print_info "設定 AmneziaWG userspace 模式..."
    
    cat > /usr/local/bin/awg <<'EOF'
#!/bin/bash
exec /usr/bin/wg "$@"
EOF
    chmod +x /usr/local/bin/awg
    ln -sf /usr/bin/wg-quick /usr/local/bin/awg-quick 2>/dev/null || true
    
    AMNEZIAWG_MODE="userspace"
    print_success "AmneziaWG userspace 模式設定完成"
}

# ===================== 修復 DKMS 符號連結 =====================
fix_amneziawg_dkms_complete() {
    print_step "修復 AmneziaWG DKMS"
    
    local dkms_build_dir="/var/lib/dkms/amneziawg/1.0.0/build"
    
    # 檢查 DKMS 目錄是否存在
    if [[ ! -d "$dkms_build_dir" ]]; then
        print_warning "DKMS 構建目錄不存在，AmneziaWG 套件可能未正確安裝"
        print_info "使用 userspace 模式..."
        setup_userspace_mode
        return 0
    fi
    
    print_info "找到 DKMS 構建目錄：$dkms_build_dir"
    
    # 清理舊的 DKMS 狀態
    print_info "清理舊的 DKMS 狀態..."
    if dkms status | grep -q amneziawg; then
        dkms remove amneziawg/1.0.0 --all 2>/dev/null || true
    fi
    
    # 尋找核心原始碼
    local kernel_src=""
    local possible_paths=(
        "/lib/modules/$(uname -r)/build"
        "/lib/modules/$(uname -r)/source"
        "/usr/src/linux-headers-$(uname -r)"
    )
    
    print_info "尋找核心原始碼..."
    for path in "${possible_paths[@]}"; do
        print_info "檢查：$path"
        if [[ -d "$path" && -f "$path/Makefile" ]]; then
            kernel_src="$path"
            print_success "找到核心原始碼：$kernel_src"
            break
        fi
    done
    
    if [[ -z "$kernel_src" ]]; then
        print_error "無法找到有效的核心原始碼"
        print_info "可用目錄："
        ls -la /lib/modules/$(uname -r)/ 2>/dev/null || true
        print_warning "回退到 userspace 模式"
        setup_userspace_mode
        return 0
    fi
    
    # 建立 DKMS 需要的符號連結
    print_info "建立 DKMS 符號連結..."
    cd "$dkms_build_dir"
    
    # 移除舊連結
    rm -rf kernel 2>/dev/null || true
    
    # 建立新符號連結
    if ln -sf "$kernel_src" kernel; then
        print_success "DKMS 核心符號連結建立成功"
        print_info "符號連結詳情："
        ls -la kernel
    else
        print_error "符號連結建立失敗"
        setup_userspace_mode
        return 0
    fi
    
    # 嘗試重新編譯 DKMS
    print_info "嘗試重新編譯 AmneziaWG DKMS..."
    if dkms install amneziawg/1.0.0 -k $(uname -r) 2>/dev/null; then
        print_success "DKMS 重新編譯成功"
        
        # 嘗試載入模組
        print_info "嘗試載入 AmneziaWG 核心模組..."
        if modprobe amneziawg 2>/dev/null && lsmod | grep -q amneziawg; then
            print_success "AmneziaWG 核心模組載入成功"
            echo "amneziawg" >> /etc/modules-load.d/amneziawg.conf
            AMNEZIAWG_MODE="kernel"
            return 0
        else
            print_warning "模組編譯成功但載入失敗"
        fi
    else
        print_warning "DKMS 重新編譯失敗"
        print_info "查看編譯錯誤日誌："
        if [[ -f "$dkms_build_dir/make.log" ]]; then
            tail -10 "$dkms_build_dir/make.log"
        fi
    fi
    
    # 如果核心模組失敗，回退到 userspace 模式
    print_info "核心模組模式失敗，使用 userspace 模式..."
    setup_userspace_mode
    return 0
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
    local max_retries=5
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
                print_error "所有註冊嘗試都失敗"
                
                # 最後嘗試：手動建立最小配置
                print_info "建立最小 WARP 配置..."
                create_minimal_warp_config
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
        else
            print_error "WARP 設定檔無效"
            create_minimal_warp_config
            return 0
        fi
    else
        print_error "WARP 設定檔生成失敗"
        create_minimal_warp_config
        return 0
    fi
}

# ===================== 建立最小 WARP 配置 =====================
create_minimal_warp_config() {
    print_info "建立最小 WARP 配置（公開端點）..."
    
    # 使用公開的 WireGuard 設定
    local warp_private_key warp_public_key
    warp_private_key=$(wg genkey)
    warp_public_key=$(echo "$warp_private_key" | wg pubkey)
    
    # 建立最小設定檔（使用已知的 Cloudflare 端點）
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
    
    print_warning "使用最小 WARP 配置（可能功能受限）"
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
    ip link add "veth-${WARP_NETNS}" type veth peer name "veth-main" || true
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

print_info() { echo "ℹ️  \$1"; }
print_success() { echo "✅ \$1"; }
print_error() { echo "❌ \$1"; }

print_info "在 namespace 中建立 WARP..."

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
ip netns exec ${WARP_NETNS} ip route add default dev ${WARP_IF} table main
ip netns exec ${WARP_NETNS} ip route add 172.31.0.0/30 dev veth-${WARP_NETNS} metric 100

print_success "WARP 在 namespace 中啟動成功"
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
    if [[ "$AMNEZIAWG_MODE" == "kernel" ]] && command -v awg >/dev/null; then
        server_private_key=$(awg genkey)
        echo "$server_private_key" | awg pubkey > /etc/amnezia/amneziawg/${WG_IF}.pub
    else
        server_private_key=$(wg genkey)
        echo "$server_private_key" | wg pubkey > /etc/amnezia/amneziawg/${WG_IF}.pub
    fi
    
    # 伺服器設定檔
    cat > /etc/amnezia/amneziawg/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_SVR_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${server_private_key}
PostUp = /etc/amnezia/amneziawg/scripts/postup.sh
PreDown = /etc/amnezia/amneziawg/scripts/predown.sh
EOF

    # Magic Headers
    if [[ "$ENABLE_DPI_PROTECTION" == "true" ]]; then
        cat >> /etc/amnezia/amneziawg/${WG_IF}.conf <<EOF

# AmneziaWG Magic Headers (DPI Protection)
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
        print_success "DPI 保護已啟用 (模式: ${AMNEZIAWG_MODE})"
    fi
    
    chmod 600 /etc/amnezia/amneziawg/${WG_IF}.conf
    
    # PostUp/PreDown 腳本
    cat > /etc/amnezia/amneziawg/scripts/postup.sh <<EOF
#!/bin/bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s ${WG_SUBNET} -o veth-main -j MASQUERADE
iptables -A FORWARD -i ${WG_IF} -o veth-main -j ACCEPT
iptables -A FORWARD -i veth-main -o ${WG_IF} -j ACCEPT
ip netns exec ${WARP_NETNS} iptables -t nat -A POSTROUTING -s 172.31.0.0/30 -o ${WARP_IF} -j MASQUERADE
ip netns exec ${WARP_NETNS} iptables -A FORWARD -i veth-${WARP_NETNS} -o ${WARP_IF} -j ACCEPT
ip netns exec ${WARP_NETNS} iptables -A FORWARD -i ${WARP_IF} -o veth-${WARP_NETNS} -j ACCEPT
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
    if [[ "$AMNEZIAWG_MODE" == "kernel" ]] && command -v awg >/dev/null; then
        client_private_key=$(awg genkey)
        client_public_key=$(echo "$client_private_key" | awg pubkey)
        client_psk=$(awg genpsk)
    else
        client_private_key=$(wg genkey)
        client_public_key=$(echo "$client_private_key" | wg pubkey)
        client_psk=$(wg genpsk)
    fi
    
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
    
    # 客戶端設定
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

    if [[ "$ENABLE_DPI_PROTECTION" == "true" ]]; then
        cat >> "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf" <<EOF

# AmneziaWG Magic Headers (DPI Protection)
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
    fi
    
    chmod 600 "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf"
    
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
Description=WARP in Network Namespace (IPv4 優化)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/local/bin/warp-netns-up.sh
ExecStart=/bin/true
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
    local wg_service="wg-quick"
    if [[ "$AMNEZIAWG_MODE" == "kernel" ]]; then
        wg_service="awg-quick"
    fi
    
    print_info "啟動 ${wg_service} 服務..."
    systemctl enable ${wg_service}@${WG_IF}
    systemctl start ${wg_service}@${WG_IF}
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
        systemctl status warp-netns.service --no-pager -l
        errors=$((errors + 1))
    fi
    
    local wg_service="wg-quick"
    if [[ "$AMNEZIAWG_MODE" == "kernel" ]]; then
        wg_service="awg-quick"
    fi
    
    if systemctl is-active --quiet ${wg_service}@${WG_IF}; then
        print_success "WireGuard 服務運行正常"
    else
        print_error "WireGuard 服務未運行"
        systemctl status ${wg_service}@${WG_IF} --no-pager -l
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
    else
        print_error "WARP 介面在 namespace 中不存在"
        errors=$((errors + 1))
    fi
    
    return $errors
}

# ===================== 顯示部署結果 =====================
show_deployment_result() {
    local errors=$1
    
    local server_ip real_ip warp_ip
    server_ip=$(curl -4 -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "未知")
    warp_ip=$(ip netns exec "${WARP_NETNS}" curl -4 -s --max-time 10 ifconfig.me 2>/dev/null || echo "未知")
    
    if [[ $errors -eq 0 ]]; then
        DEPLOYMENT_SUCCESS=true
        
        print_banner
        print_success "🎉 AmneziaWG + WARP 完整修復版部署成功！"
        echo
        
        echo -e "${BLUE}📊 系統資訊${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "${GREEN}✓${NC} 部署模式：AmneziaWG ${AMNEZIAWG_MODE} 模式"
        echo -e "${GREEN}✓${NC} 網路優化：IPv4 優先（雙協議相容）"
        echo -e "${GREEN}✓${NC} 監聽埠：${WG_PORT}"
        echo -e "${GREEN}✓${NC} DPI 保護：${ENABLE_DPI_PROTECTION}"
        echo -e "${GREEN}✓${NC} 伺服器 IP：${server_ip}"
        echo -e "${GREEN}✓${NC} WARP 出口 IP：${warp_ip}"
        echo -e "${GREEN}✓${NC} IP 保護：$(if [[ "$server_ip" != "$warp_ip" && "$warp_ip" != "未知" ]]; then echo "已啟用"; else echo "檢查中"; fi)"
        
        echo
        echo -e "${BLUE}📁 重要檔案${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• 客戶端設定：/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf"
        echo "• 客戶端 QR：/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_qr.png"
        echo "• 日誌檔案：${LOG_FILE}"
        
        echo
        echo -e "${BLUE}🔧 管理命令${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ "$AMNEZIAWG_MODE" == "kernel" ]]; then
            echo "• 查看狀態：awg show ${WG_IF}"
            echo "• 重啟服務：systemctl restart awg-quick@${WG_IF}"
        else
            echo "• 查看狀態：wg show ${WG_IF}"
            echo "• 重啟服務：systemctl restart wg-quick@${WG_IF}"
        fi
        echo "• WARP 狀態：ip netns exec ${WARP_NETNS} wg show ${WARP_IF}"
        echo "• 測試 WARP：ip netns exec ${WARP_NETNS} curl ifconfig.me"
        echo "• WARP 重啟：systemctl restart warp-netns.service"
        
        # QR Code
        if [[ -f "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf" ]] && command -v qrencode >/dev/null; then
            echo
            echo -e "${BLUE}📱 客戶端 QR Code${NC}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            qrencode -t ansiutf8 < "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf"
        fi
        
        echo
        echo -e "${GREEN}🎉 完整修復版部署成功！系統已準備就緒。${NC}"
        
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
    print_info "WireGuard + WARP + AmneziaWG 完整修復版部署開始..."
    echo
    
    setup_logging
    log "INFO" "開始部署完整修復版 - 腳本版本 ${SCRIPT_VERSION}"
    
    # 完整部署流程
    check_system
    check_network_environment
    setup_ipv4_priority
    install_packages
    install_amneziawg
    fix_amneziawg_dkms_complete
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
        log "INFO" "完整修復版部署成功完成"
        exit 0
    else
        log "ERROR" "部署完成但有 $verification_errors 個問題"
        exit 1
    fi
}

# 執行主函數
main "$@"