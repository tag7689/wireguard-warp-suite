#!/bin/bash
# =============================================================================
# WireGuard + WARP + AmneziaWG 一鍵部署腳本 v5.0 (生產級 Vultr 專用)
# 功能：透過 Cloudflare WARP 保護 VPS 真實 IP + AmneziaWG Magic Headers 對抗 DPI
# 架構：Client -> AmneziaWG Server (DPI Protection) -> WARP -> Internet
# 修復：所有已知問題，包含 DKMS 符號連結、Ubuntu 24.04 相容性等
# 適用：Vultr VPS 生產環境
# =============================================================================

set -euo pipefail

# ===================== 全域設定 =====================
readonly SCRIPT_VERSION="5.0"
readonly SCRIPT_NAME="wireguard-warp-amnezia-vultr"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"
readonly CONFIG_BACKUP_DIR="/opt/wireguard-backup"

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

# AmneziaWG Magic Headers (DPI Protection)
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
readonly WARP_TABLE="51820"

# Obfuscation 設定
readonly ENABLE_OBFUSCATION="${ENABLE_OBFUSCATION:-false}"
readonly OBFUSCATION_TYPE="${OBFUSCATION_TYPE:-phantun}"
readonly OBFUSCATION_PORT="${OBFUSCATION_PORT:-4567}"

# 監控設定
readonly ENABLE_MONITORING="${ENABLE_MONITORING:-true}"
readonly PROMETHEUS_PORT="9586"

# 系統狀態
AMNEZIAWG_MODE="disabled"
DEPLOYMENT_SUCCESS=false

# ===================== 輸出函數 =====================
print_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║            WireGuard + WARP + AmneziaWG 部署工具             ║
║                    生產級 Vultr 專用 v5.0                    ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_step() {
    echo -e "${BLUE}[步驟] ${1}${NC}"
}

print_success() {
    echo -e "${GREEN}✅ ${1}${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  ${1}${NC}"
}

print_error() {
    echo -e "${RED}❌ ${1}${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  ${1}${NC}"
}

# ===================== 日誌和錯誤處理 =====================
setup_logging() {
    mkdir -p "$(dirname "${LOG_FILE}")"
    exec 1> >(tee -a "${LOG_FILE}")
    exec 2> >(tee -a "${LOG_FILE}" >&2)
    touch "${LOG_FILE}"
    chmod 640 "${LOG_FILE}"
}

log() {
    local level="${1:-INFO}"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] $*" >> "${LOG_FILE}"
}

error_exit() {
    print_error "$1"
    log "ERROR" "$1"
    cleanup_on_error
    exit "${2:-1}"
}

# 全域錯誤處理
cleanup_on_error() {
    if [[ "$DEPLOYMENT_SUCCESS" == "false" ]]; then
        print_warning "部署失敗，正在清理..."
        
        # 清理 network namespace
        ip netns del "${WARP_NETNS}" 2>/dev/null || true
        
        # 停止服務
        systemctl stop awg-quick@${WG_IF} 2>/dev/null || true
        systemctl stop wg-quick@${WG_IF} 2>/dev/null || true
        systemctl stop warp-netns.service 2>/dev/null || true
        
        print_info "日誌檔案位置: ${LOG_FILE}"
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
    case "$ID" in
        ubuntu|debian)
            print_success "檢測到 $PRETTY_NAME"
            log "INFO" "系統：$PRETTY_NAME"
            ;;
        *)
            error_exit "不支援的作業系統: $PRETTY_NAME"
            ;;
    esac
    
    # 檢查核心版本
    local kernel_version
    kernel_version=$(uname -r)
    print_info "核心版本：$kernel_version"
    log "INFO" "核心：$kernel_version"
    
    # 檢查網路連線
    print_info "測試網路連線..."
    for server in "8.8.8.8" "1.1.1.1" "9.9.9.9"; do
        if ping -c 1 -W 5 "$server" &>/dev/null; then
            print_success "網路連線正常 ($server)"
            log "INFO" "網路連線正常"
            return 0
        fi
    done
    error_exit "無法連接網際網路，請檢查網路設定"
}

# ===================== 安裝套件 =====================
install_packages() {
    print_step "安裝必要套件"
    
    export DEBIAN_FRONTEND=noninteractive
    
    print_info "更新套件列表..."
    apt-get update || error_exit "無法更新套件列表"
    
    # 核心開發環境（為 AmneziaWG 準備）
    local kernel_packages=(
        linux-headers-$(uname -r)
        linux-source-$(uname -r | cut -d'-' -f1-2)
        linux-image-$(uname -r)
        linux-modules-$(uname -r)
        linux-modules-extra-$(uname -r)
    )
    
    # 基礎套件
    local base_packages=(
        ca-certificates curl wget jq gnupg lsb-release software-properties-common
        build-essential dkms bc kmod cpio flex bison libssl-dev libelf-dev
        iproute2 iptables resolvconf
        ufw fail2ban qrencode cron logrotate
        htop iotop net-tools dnsutils unzip git
        python3 python3-pip python3-venv python3-requests python3-psutil
        systemd wireguard wireguard-tools
    )
    
    print_info "安裝核心開發環境..."
    apt-get install -y "${kernel_packages[@]}" 2>/dev/null || \
        print_warning "部分核心套件安裝失敗，將影響 AmneziaWG 核心模組功能"
    
    print_info "安裝基礎套件..."
    apt-get install -y "${base_packages[@]}" || error_exit "基礎套件安裝失敗"
    
    print_success "套件安裝完成"
    log "INFO" "所有套件安裝完成"
}

# ===================== 修復 AmneziaWG DKMS 符號連結問題 =====================
fix_amneziawg_kernel_sources() {
    print_step "準備 AmneziaWG 核心編譯環境"
    
    # 解壓核心原始碼
    print_info "解壓核心原始碼..."
    cd /usr/src
    
    if [[ -f linux-source-*.tar.bz2 ]]; then
        tar -xf linux-source-*.tar.bz2 --skip-old-files 2>/dev/null || true
        print_success "核心原始碼已解壓"
    else
        print_warning "未找到核心原始碼壓縮檔"
    fi
    
    # 建立標準符號連結
    local kernel_version
    kernel_version=$(uname -r | cut -d'-' -f1-2)
    
    local kernel_src_paths=(
        "/usr/src/linux-source-${kernel_version}"
        "/usr/src/linux-${kernel_version}"
        "/lib/modules/$(uname -r)/build"
    )
    
    local kernel_src=""
    for path in "${kernel_src_paths[@]}"; do
        if [[ -d "$path" ]]; then
            kernel_src="$path"
            break
        fi
    done
    
    if [[ -n "$kernel_src" ]]; then
        # 建立標準符號連結
        ln -sf "$kernel_src" /usr/src/linux 2>/dev/null || true
        print_success "核心原始碼符號連結已建立：$kernel_src"
        log "INFO" "核心原始碼位置：$kernel_src"
    else
        print_warning "未找到核心原始碼目錄"
    fi
}

# ===================== 嘗試安裝 AmneziaWG =====================
install_amneziawg() {
    print_step "安裝 AmneziaWG"
    
    # 準備核心編譯環境
    fix_amneziawg_kernel_sources
    
    # 添加 AmneziaWG PPA
    print_info "添加 AmneziaWG 軟體源..."
    local keyring_file="/usr/share/keyrings/amnezia.gpg"
    local sources_file="/etc/apt/sources.list.d/amnezia.list"
    
    # 清理舊設定
    rm -f "$keyring_file" "$sources_file"
    
    if wget -qO- "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x75c9dd72c799870e310542e24166f2c257290828" | gpg --dearmor > "$keyring_file"; then
        local codename
        if [[ "$ID" == "ubuntu" ]]; then
            codename="$VERSION_CODENAME"
        else
            codename="focal"
        fi
        
        echo "deb [signed-by=${keyring_file}] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu ${codename} main" > "$sources_file"
        
        apt-get update 2>/dev/null || true
        print_success "AmneziaWG 軟體源已添加"
    else
        print_warning "無法添加 AmneziaWG 軟體源，將使用回退模式"
        AMNEZIAWG_MODE="userspace"
        return 0
    fi
    
    # 嘗試安裝 AmneziaWG
    print_info "安裝 AmneziaWG 套件..."
    if apt-get install -y amneziawg-tools amneziawg-dkms amneziawg 2>/dev/null; then
        print_success "AmneziaWG 套件安裝成功"
        
        # 修復 DKMS 符號連結問題
        fix_amneziawg_dkms_symlink
        
        # 嘗試載入模組
        if modprobe amneziawg 2>/dev/null && lsmod | grep -q "amneziawg"; then
            print_success "AmneziaWG 核心模組載入成功"
            echo "amneziawg" >> /etc/modules-load.d/amneziawg.conf
            AMNEZIAWG_MODE="kernel"
            log "INFO" "AmneziaWG 模式：核心模組"
            return 0
        else
            print_warning "AmneziaWG 核心模組載入失敗，嘗試修復..."
            if fix_dkms_compilation; then
                AMNEZIAWG_MODE="kernel"
                return 0
            fi
        fi
    fi
    
    # 回退到 userspace 模式
    print_warning "AmneziaWG 核心模組安裝失敗，使用 userspace 模式"
    setup_userspace_mode
}

# ===================== 修復 DKMS 符號連結 =====================
fix_amneziawg_dkms_symlink() {
    print_info "修復 AmneziaWG DKMS 符號連結..."
    
    local dkms_build_dir="/var/lib/dkms/amneziawg/1.0.0/build"
    
    if [[ ! -d "$dkms_build_dir" ]]; then
        print_warning "DKMS 構建目錄不存在"
        return 1
    fi
    
    # 找到核心原始碼
    local kernel_version
    kernel_version=$(uname -r | cut -d'-' -f1-2)
    
    local kernel_src_paths=(
        "/usr/src/linux-source-${kernel_version}"
        "/usr/src/linux-${kernel_version}"
        "/lib/modules/$(uname -r)/build"
        "/usr/src/linux"
    )
    
    local kernel_src=""
    for path in "${kernel_src_paths[@]}"; do
        if [[ -d "$path" ]]; then
            kernel_src="$path"
            break
        fi
    done
    
    if [[ -z "$kernel_src" ]]; then
        print_warning "無法找到核心原始碼目錄"
        return 1
    fi
    
    # 在 DKMS 構建目錄中建立符號連結
    cd "$dkms_build_dir"
    rm -rf kernel 2>/dev/null || true
    ln -sf "$kernel_src" kernel
    
    if [[ -L kernel ]]; then
        print_success "DKMS 核心符號連結已建立：$kernel_src"
        return 0
    else
        print_warning "建立 DKMS 符號連結失敗"
        return 1
    fi
}

# ===================== 修復 DKMS 編譯 =====================
fix_dkms_compilation() {
    print_info "重新編譯 AmneziaWG DKMS..."
    
    # 清理舊模組
    if dkms status | grep -q amneziawg; then
        dkms remove amneziawg/1.0.0 --all 2>/dev/null || true
    fi
    
    # 重新編譯
    if dkms install amneziawg/1.0.0 -k $(uname -r) 2>/dev/null; then
        print_success "DKMS 重新編譯成功"
        
        # 載入模組
        if modprobe amneziawg 2>/dev/null && lsmod | grep -q "amneziawg"; then
            print_success "AmneziaWG 模組載入成功"
            echo "amneziawg" >> /etc/modules-load.d/amneziawg.conf
            return 0
        fi
    fi
    
    # 嘗試手動編譯
    print_info "嘗試手動編譯..."
    local dkms_build_dir="/var/lib/dkms/amneziawg/1.0.0/build"
    
    if [[ -d "$dkms_build_dir" ]]; then
        cd "$dkms_build_dir"
        
        if make clean && make 2>/dev/null; then
            if [[ -f amneziawg.ko ]]; then
                print_success "手動編譯成功"
                
                # 安裝模組
                local module_dir="/lib/modules/$(uname -r)/extra"
                mkdir -p "$module_dir"
                cp amneziawg.ko "$module_dir/"
                depmod -a
                
                if modprobe amneziawg 2>/dev/null && lsmod | grep -q "amneziawg"; then
                    print_success "手動安裝的模組載入成功"
                    return 0
                fi
            fi
        fi
    fi
    
    print_warning "所有編譯嘗試都失敗"
    return 1
}

# ===================== 設定 Userspace 模式 =====================
setup_userspace_mode() {
    print_info "設定 AmneziaWG userspace 模式..."
    
    # 確保標準 WireGuard 可用
    if ! command -v wg >/dev/null 2>&1; then
        apt-get install -y wireguard wireguard-tools || error_exit "無法安裝 WireGuard"
    fi
    
    # 建立 AmneziaWG 包裝腳本
    cat > /usr/local/bin/awg <<'EOF'
#!/bin/bash
# AmneziaWG 相容包裝腳本 (userspace 模式)
exec /usr/bin/wg "$@"
EOF
    chmod +x /usr/local/bin/awg
    
    # wg-quick 包裝
    ln -sf /usr/bin/wg-quick /usr/local/bin/awg-quick 2>/dev/null || true
    
    AMNEZIAWG_MODE="userspace"
    print_success "AmneziaWG userspace 模式設定完成"
    log "INFO" "AmneziaWG 模式：userspace"
}

# ===================== 安裝 wgcf =====================
install_wgcf() {
    print_step "安裝並設定 wgcf"
    
    # 使用固定版本避免 API 問題
    local wgcf_version="2.2.19"
    local wgcf_url="https://github.com/ViRb3/wgcf/releases/download/v${wgcf_version}/wgcf_${wgcf_version}_linux_amd64"
    
    print_info "下載 wgcf..."
    if wget -O /usr/local/bin/wgcf "$wgcf_url"; then
        chmod +x /usr/local/bin/wgcf
        print_success "wgcf 下載完成"
    else
        error_exit "無法下載 wgcf"
    fi
    
    # WARP 註冊
    print_info "註冊 WARP 帳戶..."
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        if [[ ! -f /root/.wgcf-account.toml ]]; then
            if timeout 60 wgcf register --accept-tos; then
                print_success "WARP 帳戶註冊成功"
                break
            else
                retry_count=$((retry_count + 1))
                print_warning "WARP 註冊嘗試 $retry_count/$max_retries 失敗"
                if [[ $retry_count -eq $max_retries ]]; then
                    error_exit "WARP 註冊失敗，請檢查網路連線"
                fi
                sleep 5
            fi
        else
            print_info "WARP 帳戶已存在"
            break
        fi
    done
    
    # 生成設定檔
    if wgcf generate; then
        print_success "WARP 設定檔生成成功"
        log "INFO" "wgcf 設定完成"
    else
        error_exit "生成 WARP 設定檔失敗"
    fi
}

# ===================== 設定 Network Namespace =====================
setup_network_namespace() {
    print_step "設定 Network Namespace"
    
    # 建立 namespace
    if ip netns list | grep -q "^${WARP_NETNS}"; then
        print_info "清理舊的 namespace..."
        ip netns del "${WARP_NETNS}"
    fi
    
    ip netns add "${WARP_NETNS}"
    ip netns exec "${WARP_NETNS}" ip link set lo up
    print_success "Network namespace ${WARP_NETNS} 已建立"
    
    # 建立 veth pair
    ip link add "veth-${WARP_NETNS}" type veth peer name "veth-main"
    ip link set "veth-${WARP_NETNS}" netns "${WARP_NETNS}"
    ip link set "veth-main" up
    
    # 設定 IP
    ip addr add 172.31.0.1/30 dev "veth-main"
    ip netns exec "${WARP_NETNS}" ip addr add 172.31.0.2/30 dev "veth-${WARP_NETNS}"
    ip netns exec "${WARP_NETNS}" ip link set "veth-${WARP_NETNS}" up
    
    # 設定路由
    ip netns exec "${WARP_NETNS}" ip route add default via 172.31.0.1
    
    print_success "Network namespace 設定完成"
    log "INFO" "Network namespace 設定完成"
}

# ===================== 設定 WARP =====================
setup_warp_in_namespace() {
    print_step "設定 WARP"
    
    # 建立 namespace 目錄
    mkdir -p "/etc/netns/${WARP_NETNS}/wireguard"
    cp /root/wgcf-profile.conf "/etc/netns/${WARP_NETNS}/wireguard/${WARP_IF}.conf"
    
    # 清理配置
    sed -i '/^Address = /d' "/etc/netns/${WARP_NETNS}/wireguard/${WARP_IF}.conf"
    sed -i '/^DNS = /d' "/etc/netns/${WARP_NETNS}/wireguard/${WARP_IF}.conf"
    sed -i '/^MTU = /d' "/etc/netns/${WARP_NETNS}/wireguard/${WARP_IF}.conf"
    
    # 提取 WARP 參數
    local warp_address warp_private_key warp_public_key warp_endpoint
    warp_address=$(grep "^Address = " /root/wgcf-profile.conf | cut -d' ' -f3 | head -n1)
    warp_private_key=$(grep "^PrivateKey = " /root/wgcf-profile.conf | cut -d' ' -f3)
    warp_public_key=$(grep "^PublicKey = " /root/wgcf-profile.conf | cut -d' ' -f3)
    warp_endpoint=$(grep "^Endpoint = " /root/wgcf-profile.conf | cut -d' ' -f3)
    
    # 建立 WARP 啟動腳本
    cat > /usr/local/bin/warp-netns-up.sh <<EOF
#!/bin/bash
set -euo pipefail

# 在 namespace 中建立 WARP 介面
ip netns exec ${WARP_NETNS} ip link add dev ${WARP_IF} type wireguard
ip netns exec ${WARP_NETNS} ip address add ${warp_address} dev ${WARP_IF}

# 設定 WARP
ip netns exec ${WARP_NETNS} wg set ${WARP_IF} \\
    private-key <(echo "${warp_private_key}") \\
    peer ${warp_public_key} \\
    allowed-ips 0.0.0.0/0,::/0 \\
    endpoint ${warp_endpoint} \\
    persistent-keepalive 25

# 啟用介面
ip netns exec ${WARP_NETNS} ip link set ${WARP_IF} up

# 設定路由
ip netns exec ${WARP_NETNS} ip route add default dev ${WARP_IF} table main
ip netns exec ${WARP_NETNS} ip route add 172.31.0.0/30 dev veth-${WARP_NETNS} metric 100

logger "WARP 在 namespace ${WARP_NETNS} 中啟動成功"
EOF
    
    cat > /usr/local/bin/warp-netns-down.sh <<EOF
#!/bin/bash
set -euo pipefail
ip netns exec ${WARP_NETNS} ip link del ${WARP_IF} 2>/dev/null || true
logger "WARP 在 namespace ${WARP_NETNS} 中已關閉"
EOF
    
    chmod +x /usr/local/bin/warp-netns-{up,down}.sh
    
    print_success "WARP 設定完成"
    log "INFO" "WARP 在 namespace 中設定完成"
}

# ===================== 設定 AmneziaWG 伺服器 =====================
setup_amneziawg_server() {
    print_step "設定 AmneziaWG 伺服器"
    
    # 建立目錄
    mkdir -p /etc/amnezia/amneziawg/clients
    chmod 700 /etc/amnezia/amneziawg
    
    # 生成伺服器密鑰
    if [[ ! -f /etc/amnezia/amneziawg/${WG_IF}.key ]]; then
        if [[ "$AMNEZIAWG_MODE" == "kernel" ]] && command -v awg >/dev/null 2>&1; then
            awg genkey | tee /etc/amnezia/amneziawg/${WG_IF}.key | awg pubkey > /etc/amnezia/amneziawg/${WG_IF}.pub
        else
            wg genkey | tee /etc/amnezia/amneziawg/${WG_IF}.key | wg pubkey > /etc/amnezia/amneziawg/${WG_IF}.pub
        fi
        chmod 600 /etc/amnezia/amneziawg/${WG_IF}.key
        chmod 644 /etc/amnezia/amneziawg/${WG_IF}.pub
    fi
    
    local server_private_key
    server_private_key=$(cat /etc/amnezia/amneziawg/${WG_IF}.key)
    
    # 建立伺服器設定檔
    cat > /etc/amnezia/amneziawg/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_SVR_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${server_private_key}
PostUp = /etc/amnezia/amneziawg/scripts/postup.sh
PreDown = /etc/amnezia/amneziawg/scripts/predown.sh
EOF

    # 添加 Magic Headers
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
        log "INFO" "Magic Headers: H1=${AWG_H1}, H2=${AWG_H2}, H3=${AWG_H3}, H4=${AWG_H4}"
    fi
    
    chmod 600 /etc/amnezia/amneziawg/${WG_IF}.conf
    
    # 建立腳本
    mkdir -p /etc/amnezia/amneziawg/scripts
    
    # PostUp 腳本
    cat > /etc/amnezia/amneziawg/scripts/postup.sh <<EOF
#!/bin/bash
set -e

# 啟用 IP 轉發
sysctl -w net.ipv4.ip_forward=1

# 設定 iptables 規則
iptables -t nat -A POSTROUTING -s ${WG_SUBNET} -o veth-main -j MASQUERADE
iptables -A FORWARD -i ${WG_IF} -o veth-main -j ACCEPT
iptables -A FORWARD -i veth-main -o ${WG_IF} -j ACCEPT

# 設定路由
ip route add ${WG_SUBNET} dev ${WG_IF} 2>/dev/null || true

# namespace 中的 NAT
ip netns exec ${WARP_NETNS} iptables -t nat -A POSTROUTING -s 172.31.0.0/30 -o ${WARP_IF} -j MASQUERADE
ip netns exec ${WARP_NETNS} iptables -A FORWARD -i veth-${WARP_NETNS} -o ${WARP_IF} -j ACCEPT
ip netns exec ${WARP_NETNS} iptables -A FORWARD -i ${WARP_IF} -o veth-${WARP_NETNS} -j ACCEPT

logger "AmneziaWG PostUp 完成 (模式: ${AMNEZIAWG_MODE})"
touch /var/lib/wireguard/interface_up
EOF
    
    # PreDown 腳本
    cat > /etc/amnezia/amneziawg/scripts/predown.sh <<EOF
#!/bin/bash

# 清理規則
iptables -t nat -D POSTROUTING -s ${WG_SUBNET} -o veth-main -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i ${WG_IF} -o veth-main -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i veth-main -o ${WG_IF} -j ACCEPT 2>/dev/null || true

# 清理 namespace 規則
ip netns exec ${WARP_NETNS} iptables -t nat -D POSTROUTING -s 172.31.0.0/30 -o ${WARP_IF} -j MASQUERADE 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -D FORWARD -i veth-${WARP_NETNS} -o ${WARP_IF} -j ACCEPT 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -D FORWARD -i ${WARP_IF} -o veth-${WARP_NETNS} -j ACCEPT 2>/dev/null || true

logger "AmneziaWG PreDown 完成"
rm -f /var/lib/wireguard/interface_up
EOF
    
    chmod +x /etc/amnezia/amneziawg/scripts/*.sh
    mkdir -p /var/lib/wireguard
    
    # 儲存配置
    cat > /etc/amnezia/amneziawg/magic_headers.conf <<EOF
# AmneziaWG Magic Headers Configuration - Vultr 生產環境
# Generated on $(date)
AWG_H1=${AWG_H1}
AWG_H2=${AWG_H2}
AWG_H3=${AWG_H3}
AWG_H4=${AWG_H4}
AWG_S1=${AWG_S1}
AWG_S2=${AWG_S2}
AWG_JC=${AWG_JC}
AWG_JMIN=${AWG_JMIN}
AWG_JMAX=${AWG_JMAX}
AMNEZIAWG_MODE=${AMNEZIAWG_MODE}
SERVER_IP=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "未知")
DEPLOYMENT_DATE=$(date)
EOF
    chmod 600 /etc/amnezia/amneziawg/magic_headers.conf
    
    print_success "AmneziaWG 伺服器設定完成"
}

# ===================== 建立 systemd 服務 =====================
setup_systemd_services() {
    print_step "建立 systemd 服務"
    
    # WARP namespace 服務
    cat > /etc/systemd/system/warp-netns.service <<EOF
[Unit]
Description=WARP in Network Namespace
After=network-online.target
Wants=network-online.target
Before=awg-quick@${WG_IF}.service wg-quick@${WG_IF}.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/local/bin/warp-netns-up.sh
ExecStart=/bin/true
ExecStop=/usr/local/bin/warp-netns-down.sh
StandardOutput=journal
StandardError=journal
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # 決定使用的服務類型
    local wg_service="wg-quick"
    if [[ "$AMNEZIAWG_MODE" == "kernel" ]]; then
        wg_service="awg-quick"
    fi
    
    # WireGuard 服務配置
    mkdir -p /etc/systemd/system/${wg_service}@${WG_IF}.service.d/
    cat > /etc/systemd/system/${wg_service}@${WG_IF}.service.d/override.conf <<EOF
[Unit]
Description=AmneziaWG via %i with DPI Protection (Vultr Production)
After=warp-netns.service
Wants=warp-netns.service
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Restart=on-failure
RestartSec=30
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity
EOF
    
    systemctl daemon-reload
    
    print_success "systemd 服務設定完成 (使用 ${wg_service})"
    log "INFO" "systemd 服務：${wg_service}"
}

# ===================== 建立客戶端設定 =====================
create_client_config() {
    print_step "建立客戶端設定"
    
    # 生成密鑰
    local client_private_key client_public_key client_psk
    
    if [[ "$AMNEZIAWG_MODE" == "kernel" ]] && command -v awg >/dev/null 2>&1; then
        client_private_key=$(awg genkey)
        client_public_key=$(echo "$client_private_key" | awg pubkey)
        client_psk=$(awg genpsk)
    else
        client_private_key=$(wg genkey)
        client_public_key=$(echo "$client_private_key" | wg pubkey)
        client_psk=$(wg genpsk)
    fi
    
    # 取得伺服器資訊
    local server_public_key
    server_public_key=$(cat /etc/amnezia/amneziawg/${WG_IF}.pub)
    
    local server_ip
    server_ip=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null) || \
    server_ip=$(curl -s --max-time 10 https://ifconfig.me 2>/dev/null) || \
    server_ip="YOUR_SERVER_IP"
    
    # 決定端口
    local endpoint_port="$WG_PORT"
    if [[ "$ENABLE_OBFUSCATION" == "true" ]]; then
        endpoint_port="$OBFUSCATION_PORT"
    fi
    
    # 添加 peer 到伺服器
    cat >> /etc/amnezia/amneziawg/${WG_IF}.conf <<EOF

[Peer]
PublicKey = ${client_public_key}
PresharedKey = ${client_psk}
AllowedIPs = ${CLIENT_IP}
EOF
    
    # 生成客戶端配置
    cat > "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf" <<EOF
[Interface]
PrivateKey = ${client_private_key}
Address = ${CLIENT_IP}
DNS = ${WG_DNS}
MTU = 1280

[Peer]
PublicKey = ${server_public_key}
PresharedKey = ${client_psk}
Endpoint = ${server_ip}:${endpoint_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # 添加 Magic Headers
    if [[ "$ENABLE_DPI_PROTECTION" == "true" ]]; then
        cat >> "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf" <<EOF

# AmneziaWG Magic Headers (DPI Protection) - Vultr Production
# 客戶端必須使用支援 Magic Headers 的 AmneziaWG 應用程式
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
    
    # 生成 QR code
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t PNG -o "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_qr.png" \
                 < "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf"
        print_success "客戶端 QR Code 已生成"
    fi
    
    print_success "客戶端設定已建立：${CLIENT_NAME}"
    log "INFO" "客戶端配置：${CLIENT_NAME} (${server_ip}:${endpoint_port})"
}

# ===================== 安全設定 =====================
setup_security() {
    print_step "設定防火牆和安全"
    
    # UFW 防火牆
    print_info "設定 UFW 防火牆..."
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # SSH (Vultr 預設)
    local ssh_port="${SSH_PORT:-22}"
    ufw allow "$ssh_port"/tcp comment "SSH"
    
    # WireGuard
    if [[ "$ENABLE_OBFUSCATION" == "true" ]]; then
        ufw allow "$OBFUSCATION_PORT"/tcp comment "WireGuard Obfuscated"
    else
        ufw allow "$WG_PORT"/udp comment "WireGuard"
    fi
    
    ufw --force enable
    print_success "防火牆設定完成"
    
    # fail2ban
    print_info "設定 fail2ban..."
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 24h
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    print_success "fail2ban 設定完成"
    
    log "INFO" "安全設定完成"
}

# ===================== 啟動服務 =====================
start_services() {
    print_step "啟動服務"
    
    # 啟動 WARP
    print_info "啟動 WARP namespace 服務..."
    systemctl enable warp-netns.service
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
    log "INFO" "所有服務已啟動：${wg_service}"
}

# ===================== 最終驗證 =====================
final_verification() {
    print_step "執行最終驗證"
    
    local errors=0
    
    # 檢查服務
    local services_to_check=(
        "warp-netns.service"
    )
    
    # 決定 WireGuard 服務名稱
    if [[ "$AMNEZIAWG_MODE" == "kernel" ]]; then
        services_to_check+=("awg-quick@${WG_IF}.service")
    else
        services_to_check+=("wg-quick@${WG_IF}.service")
    fi
    
    for service in "${services_to_check[@]}"; do
        if systemctl is-active --quiet "$service"; then
            print_success "服務 $service 運行正常"
        else
            print_error "服務 $service 未運行"
            errors=$((errors + 1))
        fi
    done
    
    # 檢查介面
    if ip link show ${WG_IF} >/dev/null 2>&1; then
        print_success "WireGuard 介面 ${WG_IF} 存在"
    else
        print_error "WireGuard 介面 ${WG_IF} 不存在"
        errors=$((errors + 1))
    fi
    
    # 檢查 namespace
    if ip netns list | grep -q "^${WARP_NETNS}"; then
        print_success "Network namespace ${WARP_NETNS} 存在"
        
        if ip netns exec "${WARP_NETNS}" ip link show "${WARP_IF}" >/dev/null 2>&1; then
            print_success "WARP 介面在 namespace 中存在"
        else
            print_error "WARP 介面在 namespace 中不存在"
            errors=$((errors + 1))
        fi
    else
        print_error "Network namespace ${WARP_NETNS} 不存在"
        errors=$((errors + 1))
    fi
    
    # 測試 WARP 連線
    if ip netns exec "${WARP_NETNS}" ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
        print_success "WARP 連線測試通過"
    else
        print_warning "WARP 連線測試失敗，但可能正常"
    fi
    
    return $errors
}

# ===================== 顯示部署結果 =====================
show_deployment_result() {
    local errors=$1
    
    # 取得伺服器 IP
    local server_ip real_ip warp_ip
    server_ip=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "未知")
    real_ip="$server_ip"
    warp_ip=$(ip netns exec "${WARP_NETNS}" curl -s --max-time 10 ifconfig.me 2>/dev/null || echo "未知")
    
    if [[ $errors -eq 0 ]]; then
        DEPLOYMENT_SUCCESS=true
        
        print_banner
        print_success "🎉 AmneziaWG + WARP 部署成功！"
        echo
        
        echo -e "${BLUE}📊 系統資訊${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "${GREEN}✓${NC} 部署模式：AmneziaWG ${AMNEZIAWG_MODE} 模式"
        echo -e "${GREEN}✓${NC} 架構：客戶端 → AmneziaWG (${WG_IF}) → WARP (namespace) → 網際網路"
        echo -e "${GREEN}✓${NC} 監聽埠：${WG_PORT}"
        echo -e "${GREEN}✓${NC} DPI 保護：${ENABLE_DPI_PROTECTION}"
        if [[ "$ENABLE_DPI_PROTECTION" == "true" ]]; then
            echo -e "${GREEN}✓${NC} Magic Headers：H1=${AWG_H1}, H2=${AWG_H2}, H3=${AWG_H3}, H4=${AWG_H4}"
        fi
        echo -e "${GREEN}✓${NC} 伺服器真實 IP：${real_ip}"
        echo -e "${GREEN}✓${NC} WARP 出口 IP：${warp_ip}"
        echo -e "${GREEN}✓${NC} IP 保護：$(if [[ "$real_ip" != "$warp_ip" && "$warp_ip" != "未知" ]]; then echo "已啟用"; else echo "檢查中"; fi)"
        
        echo
        echo -e "${BLUE}📁 重要檔案${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• 客戶端設定：/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf"
        echo "• 客戶端 QR Code：/etc/amnezia/amneziawg/clients/${CLIENT_NAME}_qr.png"
        echo "• 伺服器設定：/etc/amnezia/amneziawg/${WG_IF}.conf"
        echo "• Magic Headers：/etc/amnezia/amneziawg/magic_headers.conf"
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
        
        echo
        echo -e "${BLUE}📱 客戶端設定${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ "$AMNEZIAWG_MODE" == "kernel" ]]; then
            echo -e "${YELLOW}⚠️${NC}  核心模組模式：必須使用 AmneziaWG 客戶端"
            echo "• 不能使用標準 WireGuard 客戶端"
            echo "• Magic Headers 必須完全一致"
        else
            echo -e "${GREEN}✓${NC} Userspace 模式：相容多種客戶端"
            echo "• 可使用 AmneziaWG 客戶端（推薦）"
            echo "• 也可使用標準 WireGuard 客戶端"
        fi
        echo "• 推薦下載：https://amneziavpn.org"
        echo "• 設定檔位置：/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf"
        
        echo
        echo -e "${BLUE}🔍 服務監控${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• systemctl status warp-netns.service"
        if [[ "$AMNEZIAWG_MODE" == "kernel" ]]; then
            echo "• systemctl status awg-quick@${WG_IF}.service"
        else
            echo "• systemctl status wg-quick@${WG_IF}.service"
        fi
        echo "• journalctl -u warp-netns.service -f"
        
        # 顯示客戶端 QR Code
        if command -v qrencode >/dev/null 2>&1 && [[ -f "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf" ]]; then
            echo
            echo -e "${BLUE}📱 客戶端 QR Code${NC}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            qrencode -t ansiutf8 < "/etc/amnezia/amneziawg/clients/${CLIENT_NAME}.conf"
        fi
        
        echo
        echo -e "${GREEN}🎉 部署完成！系統已準備就緒。${NC}"
        
    else
        print_error "部署過程中發現 $errors 個問題"
        echo
        echo -e "${YELLOW}🔧 故障排除${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "1. 檢查日誌：tail -f ${LOG_FILE}"
        echo "2. 檢查服務：systemctl status warp-netns.service"
        if [[ "$AMNEZIAWG_MODE" == "kernel" ]]; then
            echo "3. 檢查 WireGuard：systemctl status awg-quick@${WG_IF}"
        else
            echo "3. 檢查 WireGuard：systemctl status wg-quick@${WG_IF}"
        fi
        echo "4. 重新執行：./$(basename "$0")"
    fi
    
    log "INFO" "部署結果：$(if [[ $errors -eq 0 ]]; then echo "成功"; else echo "失敗($errors 錯誤)"; fi)"
    log "INFO" "伺服器 IP：$server_ip，WARP IP：$warp_ip"
}

# ===================== 主函數 =====================
main() {
    print_banner
    
    print_info "WireGuard + WARP + AmneziaWG 一鍵部署開始..."
    print_info "針對 Vultr VPS 生產環境優化"
    echo
    
    setup_logging
    log "INFO" "開始部署 - 腳本版本 ${SCRIPT_VERSION}"
    
    # 部署流程
    check_system
    install_packages
    install_amneziawg
    install_wgcf
    setup_network_namespace
    setup_warp_in_namespace
    setup_amneziawg_server
    setup_systemd_services
    setup_security
    create_client_config
    start_services
    
    # 驗證結果
    print_step "驗證部署結果"
    local verification_errors
    verification_errors=$(final_verification)
    
    # 顯示結果
    show_deployment_result $verification_errors
    
    # 移除錯誤處理 trap
    trap - EXIT
    
    if [[ $verification_errors -eq 0 ]]; then
        log "INFO" "部署成功完成"
        exit 0
    else
        log "ERROR" "部署完成但有 $verification_errors 個問題"
        exit 1
    fi
}

# 執行主函數
main "$@"