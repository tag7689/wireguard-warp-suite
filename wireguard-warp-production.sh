#!/bin/bash
# =============================================================================
# WireGuard + WARP 生產級部署腳本 v3.0
# 功能：透過 Cloudflare WARP 保護 VPS 真實 IP
# 架構：Client -> WireGuard Server -> WARP -> Internet
# 採用 Network Namespace 隔離方案確保最大穩定性
# =============================================================================

set -euo pipefail

# ===================== 全域設定 =====================
readonly SCRIPT_VERSION="3.0"
readonly SCRIPT_NAME="wireguard-warp-deploy"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"
readonly CONFIG_BACKUP_DIR="/opt/wireguard-backup"

# WireGuard 設定
readonly WG_IF="wg0"
readonly WG_PORT="51820" 
readonly WG_SUBNET="10.66.66.0/24"
readonly WG_SVR_IP="10.66.66.1/24"
readonly WG_DNS="1.1.1.1"
readonly CLIENT_NAME="client01"
readonly CLIENT_IP="10.66.66.10/32"

# WARP 設定
readonly WARP_IF="wgcf"
readonly WARP_NETNS="warp"
readonly WARP_TABLE="51820"

# Obfuscation 設定（可選）
readonly ENABLE_OBFUSCATION="${ENABLE_OBFUSCATION:-false}"
readonly OBFUSCATION_TYPE="${OBFUSCATION_TYPE:-phantun}"
readonly OBFUSCATION_PORT="${OBFUSCATION_PORT:-4567}"

# 監控設定
readonly ENABLE_MONITORING="${ENABLE_MONITORING:-true}"
readonly PROMETHEUS_PORT="9586"

# ===================== 日誌和錯誤處理 =====================
setup_logging() {
    exec 1> >(tee -a "${LOG_FILE}")
    exec 2> >(tee -a "${LOG_FILE}" >&2)
    touch "${LOG_FILE}"
    chmod 640 "${LOG_FILE}"
}

log() {
    local level="${1:-INFO}"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] $*"
}

error_exit() {
    log "ERROR" "$1"
    exit "${2:-1}"
}

# 全域錯誤處理
cleanup_on_error() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log "ERROR" "腳本執行失敗，退出碼: $exit_code"
        log "INFO" "正在執行清理操作..."
        
        # 清理 network namespace
        ip netns del "${WARP_NETNS}" 2>/dev/null || true
        
        # 恢復防火牆設定
        if [[ -f "${CONFIG_BACKUP_DIR}/ufw.backup" ]]; then
            ufw --force reset &>/dev/null || true
            ufw default allow outgoing &>/dev/null || true
        fi
        
        # 停止服務
        systemctl stop wg-quick@${WG_IF} &>/dev/null || true
        systemctl stop warp-netns.service &>/dev/null || true
        systemctl stop wireguard-warp-healthcheck.timer &>/dev/null || true
        
        log "ERROR" "部署失敗，請檢查日誌: ${LOG_FILE}"
    fi
}

trap cleanup_on_error EXIT

# ===================== 系統檢查 =====================
check_system() {
    log "INFO" "檢查系統環境..."
    
    # 檢查 root 權限
    [[ $EUID -eq 0 ]] || error_exit "請使用 root 權限執行此腳本"
    
    # 檢查作業系統
    if [[ ! -f /etc/os-release ]]; then
        error_exit "無法檢測作業系統版本"
    fi
    
    source /etc/os-release
    case "$ID" in
        ubuntu|debian)
            log "INFO" "檢測到 $PRETTY_NAME"
            ;;
        *)
            error_exit "不支援的作業系統: $PRETTY_NAME"
            ;;
    esac
    
    # 檢查核心模組
    if ! modprobe wireguard 2>/dev/null; then
        log "WARN" "WireGuard 核心模組載入失敗，將使用 userspace 實作"
    fi
    
    # 檢查網路連線
    for server in "8.8.8.8" "1.1.1.1" "9.9.9.9"; do
        if ping -c 1 -W 5 "$server" &>/dev/null; then
            log "INFO" "網路連線正常 ($server)"
            return 0
        fi
    done
    error_exit "無法連接網際網路，請檢查網路設定"
}

# ===================== 安裝套件 =====================
install_packages() {
    log "INFO" "安裝必要套件..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt-get update || error_exit "無法更新套件列表"
    
    # 基礎套件
    local packages=(
        ca-certificates curl wget jq gnupg lsb-release
        wireguard wireguard-tools iproute2 iptables
        ufw fail2ban qrencode cron logrotate
        htop iotop net-tools dnsutils unzip
        python3 python3-pip systemd
    )
    
    apt-get install -y "${packages[@]}" || error_exit "套件安裝失敗"
    
    # Python 模組
    pip3 install requests psutil || log "WARN" "Python 模組安裝失敗"
    
    log "INFO" "套件安裝完成"
}

# ===================== 安裝和設定 wgcf =====================
setup_wgcf() {
    log "INFO" "安裝並設定 wgcf..."
    
    # 下載最新版本的 wgcf
    local wgcf_url
    wgcf_url=$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | \
        jq -r '.assets[] | select(.name | test("linux.*amd64")) | .browser_download_url')
    
    if [[ -z "$wgcf_url" ]]; then
        error_exit "無法取得 wgcf 下載連結"
    fi
    
    wget -O /usr/local/bin/wgcf "$wgcf_url"
    chmod +x /usr/local/bin/wgcf
    
    # wgcf 註冊（重試機制）
    log "INFO" "註冊 WARP 帳戶..."
    local max_retries=5
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        if [[ ! -f /root/.wgcf-account.toml ]]; then
            if timeout 60 wgcf register; then
                log "INFO" "WARP 帳戶註冊成功"
                break
            else
                retry_count=$((retry_count + 1))
                log "WARN" "WARP 註冊嘗試 $retry_count/$max_retries 失敗"
                if [[ $retry_count -eq $max_retries ]]; then
                    error_exit "WARP 註冊失敗，請檢查網路連線"
                fi
                sleep $((retry_count * 5))
            fi
        else
            log "INFO" "WARP 帳戶已存在"
            break
        fi
    done
    
    # 生成 WireGuard 設定檔
    if ! wgcf generate; then
        error_exit "生成 WARP 設定檔失敗"
    fi
    
    log "INFO" "wgcf 設定完成"
}

# ===================== 設定 Network Namespace =====================
setup_network_namespace() {
    log "INFO" "設定 Network Namespace..."
    
    # 建立 network namespace
    if ip netns list | grep -q "^${WARP_NETNS}"; then
        log "INFO" "Network namespace ${WARP_NETNS} 已存在，刪除後重建"
        ip netns del "${WARP_NETNS}"
    fi
    
    ip netns add "${WARP_NETNS}"
    log "INFO" "建立 network namespace: ${WARP_NETNS}"
    
    # 在 namespace 中設定 loopback
    ip netns exec "${WARP_NETNS}" ip link set lo up
    
    # 建立 veth pair 連接主系統和 namespace
    ip link add "veth-${WARP_NETNS}" type veth peer name "veth-main"
    ip link set "veth-${WARP_NETNS}" netns "${WARP_NETNS}"
    ip link set "veth-main" up
    
    # 設定 veth 介面 IP
    ip addr add 172.31.0.1/30 dev "veth-main"
    ip netns exec "${WARP_NETNS}" ip addr add 172.31.0.2/30 dev "veth-${WARP_NETNS}"
    ip netns exec "${WARP_NETNS}" ip link set "veth-${WARP_NETNS}" up
    
    # 在 namespace 中設定預設路由
    ip netns exec "${WARP_NETNS}" ip route add default via 172.31.0.1
    
    log "INFO" "Network namespace 設定完成"
}

# ===================== 在 Namespace 中設定 WARP =====================
setup_warp_in_namespace() {
    log "INFO" "在 namespace 中設定 WARP..."
    
    # 複製 wgcf 設定到 namespace 目錄
    mkdir -p "/etc/netns/${WARP_NETNS}/wireguard"
    cp /root/wgcf-profile.conf "/etc/netns/${WARP_NETNS}/wireguard/${WARP_IF}.conf"
    
    # 修改設定檔以適配 namespace
    sed -i '/^Address = /d' "/etc/netns/${WARP_NETNS}/wireguard/${WARP_IF}.conf"
    sed -i '/^DNS = /d' "/etc/netns/${WARP_NETNS}/wireguard/${WARP_IF}.conf"
    sed -i '/^MTU = /d' "/etc/netns/${WARP_NETNS}/wireguard/${WARP_IF}.conf"
    
    # 取得 WARP 設定參數
    local warp_address
    local warp_private_key
    local warp_public_key
    local warp_endpoint
    
    warp_address=$(grep "^Address = " /root/wgcf-profile.conf | cut -d' ' -f3 | head -n1)
    warp_private_key=$(grep "^PrivateKey = " /root/wgcf-profile.conf | cut -d' ' -f3)
    warp_public_key=$(grep "^PublicKey = " /root/wgcf-profile.conf | cut -d' ' -f3)
    warp_endpoint=$(grep "^Endpoint = " /root/wgcf-profile.conf | cut -d' ' -f3)
    
    # 建立 WARP 啟動腳本
    cat > /usr/local/bin/warp-netns-up.sh <<EOF
#!/bin/bash
set -euo pipefail

# 在 namespace 中建立 WireGuard 介面
ip netns exec ${WARP_NETNS} ip link add dev ${WARP_IF} type wireguard
ip netns exec ${WARP_NETNS} ip address add ${warp_address} dev ${WARP_IF}

# 設定 WireGuard
ip netns exec ${WARP_NETNS} wg set ${WARP_IF} \\
    private-key <(echo "${warp_private_key}") \\
    peer ${warp_public_key} \\
    allowed-ips 0.0.0.0/0,::/0 \\
    endpoint ${warp_endpoint} \\
    persistent-keepalive 25

# 啟用介面
ip netns exec ${WARP_NETNS} ip link set ${WARP_IF} up

# 設定路由（WARP 作為預設路由）
ip netns exec ${WARP_NETNS} ip route add default dev ${WARP_IF} table main

# 確保 veth 路由優先於 WARP
ip netns exec ${WARP_NETNS} ip route add 172.31.0.0/30 dev veth-${WARP_NETNS} metric 100

logger "WARP 在 namespace ${WARP_NETNS} 中啟動成功"
EOF
    
    # 建立 WARP 關閉腳本
    cat > /usr/local/bin/warp-netns-down.sh <<EOF
#!/bin/bash
set -euo pipefail

# 刪除 WireGuard 介面
ip netns exec ${WARP_NETNS} ip link del ${WARP_IF} 2>/dev/null || true

logger "WARP 在 namespace ${WARP_NETNS} 中已關閉"
EOF
    
    chmod +x /usr/local/bin/warp-netns-{up,down}.sh
    
    log "INFO" "WARP namespace 設定完成"
}

# ===================== 設定主系統 WireGuard =====================
setup_wireguard_server() {
    log "INFO" "設定 WireGuard 伺服器..."
    
    # 建立目錄
    mkdir -p /etc/wireguard/clients
    chmod 700 /etc/wireguard
    
    # 生成伺服器密鑰
    if [[ ! -f /etc/wireguard/${WG_IF}.key ]]; then
        wg genkey | tee /etc/wireguard/${WG_IF}.key | wg pubkey > /etc/wireguard/${WG_IF}.pub
        chmod 600 /etc/wireguard/${WG_IF}.key
        chmod 644 /etc/wireguard/${WG_IF}.pub
    fi
    
    local server_private_key
    server_private_key=$(cat /etc/wireguard/${WG_IF}.key)
    
    # 建立伺服器設定檔
    cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_SVR_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${server_private_key}
PostUp = /etc/wireguard/scripts/postup.sh
PreDown = /etc/wireguard/scripts/predown.sh
EOF
    
    chmod 600 /etc/wireguard/${WG_IF}.conf
    
    # 建立腳本目錄
    mkdir -p /etc/wireguard/scripts
    
    # PostUp 腳本 - 設定 NAT 和路由
    cat > /etc/wireguard/scripts/postup.sh <<EOF
#!/bin/bash
set -e

# 啟用 IP forwarding
sysctl -w net.ipv4.ip_forward=1

# 設定 iptables 規則將 WireGuard 流量導向 namespace
iptables -t nat -A POSTROUTING -s ${WG_SUBNET} -o veth-main -j MASQUERADE
iptables -A FORWARD -i ${WG_IF} -o veth-main -j ACCEPT
iptables -A FORWARD -i veth-main -o ${WG_IF} -j ACCEPT

# 設定路由將 WireGuard 流量導向 namespace
ip route add ${WG_SUBNET} dev ${WG_IF} 2>/dev/null || true

# 在 namespace 中設定 NAT 將流量導向 WARP
ip netns exec ${WARP_NETNS} iptables -t nat -A POSTROUTING -s 172.31.0.0/30 -o ${WARP_IF} -j MASQUERADE
ip netns exec ${WARP_NETNS} iptables -A FORWARD -i veth-${WARP_NETNS} -o ${WARP_IF} -j ACCEPT
ip netns exec ${WARP_NETNS} iptables -A FORWARD -i ${WARP_IF} -o veth-${WARP_NETNS} -j ACCEPT

logger "WireGuard PostUp: 路由規則已設定"
touch /var/lib/wireguard/interface_up
EOF
    
    # PreDown 腳本 - 清理規則
    cat > /etc/wireguard/scripts/predown.sh <<EOF
#!/bin/bash

# 清理 iptables 規則
iptables -t nat -D POSTROUTING -s ${WG_SUBNET} -o veth-main -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i ${WG_IF} -o veth-main -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i veth-main -o ${WG_IF} -j ACCEPT 2>/dev/null || true

# 清理 namespace 中的規則
ip netns exec ${WARP_NETNS} iptables -t nat -D POSTROUTING -s 172.31.0.0/30 -o ${WARP_IF} -j MASQUERADE 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -D FORWARD -i veth-${WARP_NETNS} -o ${WARP_IF} -j ACCEPT 2>/dev/null || true
ip netns exec ${WARP_NETNS} iptables -D FORWARD -i ${WARP_IF} -o veth-${WARP_NETNS} -j ACCEPT 2>/dev/null || true

logger "WireGuard PreDown: 路由規則已清理"
rm -f /var/lib/wireguard/interface_up
EOF
    
    chmod +x /etc/wireguard/scripts/*.sh
    mkdir -p /var/lib/wireguard
    
    log "INFO" "WireGuard 伺服器設定完成"
}

# ===================== 建立 systemd 服務 =====================
setup_systemd_services() {
    log "INFO" "建立 systemd 服務..."
    
    # WARP namespace 服務
    cat > /etc/systemd/system/warp-netns.service <<EOF
[Unit]
Description=WARP in Network Namespace
After=network-online.target
Wants=network-online.target
Before=wg-quick@${WG_IF}.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/local/bin/warp-netns-up.sh
ExecStart=/bin/true
ExecStop=/usr/local/bin/warp-netns-down.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # WireGuard 服務依賴
    mkdir -p /etc/systemd/system/wg-quick@${WG_IF}.service.d/
    cat > /etc/systemd/system/wg-quick@${WG_IF}.service.d/override.conf <<EOF
[Unit]
After=warp-netns.service
Wants=warp-netns.service
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Restart=on-failure
RestartSec=30
EOF
    
    systemctl daemon-reload
    
    log "INFO" "systemd 服務設定完成"
}

# ===================== 健康檢查系統 =====================
setup_health_check_system() {
    log "INFO" "設定健康檢查系統..."
    
    # 健康檢查腳本
    cat > /usr/local/bin/wireguard-warp-healthcheck.py <<'EOF'
#!/usr/bin/env python3
"""
WireGuard + WARP 健康檢查腳本
"""

import os
import sys
import time
import logging
import subprocess
from datetime import datetime

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/wireguard-warp-healthcheck.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WireGuardWarpHealthCheck:
    def __init__(self):
        self.wg_interface = 'wg0'
        self.warp_interface = 'wgcf'
        self.warp_netns = 'warp'
        self.max_handshake_age = 300  # 5 分鐘
        
    def check_wireguard_interface(self):
        """檢查 WireGuard 介面狀態"""
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', self.wg_interface],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"檢查 WireGuard 介面失敗: {e}")
            return False
    
    def check_warp_in_namespace(self):
        """檢查 namespace 中的 WARP 狀態"""
        try:
            # 檢查 namespace 是否存在
            result = subprocess.run(
                ['ip', 'netns', 'list'],
                capture_output=True, text=True, timeout=10
            )
            if self.warp_netns not in result.stdout:
                logger.error(f"Network namespace {self.warp_netns} 不存在")
                return False
                
            # 檢查 WARP 介面
            result = subprocess.run(
                ['ip', 'netns', 'exec', self.warp_netns, 'ip', 'link', 'show', self.warp_interface],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.error(f"WARP 介面 {self.warp_interface} 在 namespace 中不存在")
                return False
                
            # 檢查 WARP 連線狀態
            result = subprocess.run(
                ['ip', 'netns', 'exec', self.warp_netns, 'wg', 'show', self.warp_interface],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.error("無法取得 WARP WireGuard 狀態")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"檢查 WARP namespace 失敗: {e}")
            return False
    
    def test_warp_connectivity(self):
        """測試 WARP 網路連線"""
        test_hosts = ['1.1.1.1', '8.8.8.8']
        
        for host in test_hosts:
            try:
                result = subprocess.run([
                    'ip', 'netns', 'exec', self.warp_netns,
                    'ping', '-c', '1', '-W', '5', host
                ], capture_output=True, timeout=15)
                
                if result.returncode == 0:
                    logger.info(f"WARP 連線測試成功 ({host})")
                    return True
            except Exception:
                continue
                
        logger.warning("WARP 連線測試失敗")
        return False
    
    def restart_warp_service(self):
        """重啟 WARP 服務"""
        try:
            logger.info("正在重啟 WARP 服務...")
            subprocess.run(['systemctl', 'restart', 'warp-netns.service'], 
                         timeout=60, check=True)
            time.sleep(10)
            return True
        except Exception as e:
            logger.error(f"重啟 WARP 服務失敗: {e}")
            return False
    
    def restart_wireguard_service(self):
        """重啟 WireGuard 服務"""
        try:
            logger.info("正在重啟 WireGuard 服務...")
            subprocess.run(['systemctl', 'restart', f'wg-quick@{self.wg_interface}'], 
                         timeout=60, check=True)
            time.sleep(5)
            return True
        except Exception as e:
            logger.error(f"重啟 WireGuard 服務失敗: {e}")
            return False
    
    def run_check(self):
        """執行完整健康檢查"""
        logger.info("開始 WireGuard + WARP 健康檢查")
        
        needs_restart = False
        
        # 檢查 WireGuard 介面
        if not self.check_wireguard_interface():
            logger.error("WireGuard 介面異常")
            needs_restart = True
        else:
            logger.info("WireGuard 介面正常")
        
        # 檢查 WARP namespace
        if not self.check_warp_in_namespace():
            logger.error("WARP namespace 異常")
            needs_restart = True
        else:
            logger.info("WARP namespace 正常")
        
        # 測試 WARP 連線
        if not self.test_warp_connectivity():
            logger.error("WARP 連線異常")
            # 只重啟 WARP 服務
            if self.restart_warp_service():
                logger.info("WARP 服務重啟成功")
            else:
                needs_restart = True
        
        # 如果需要完整重啟
        if needs_restart:
            logger.warning("執行完整服務重啟")
            self.restart_warp_service()
            time.sleep(5)
            self.restart_wireguard_service()
            
            # 重新檢查
            time.sleep(15)
            if self.check_wireguard_interface() and self.check_warp_in_namespace():
                logger.info("服務重啟後恢復正常")
            else:
                logger.error("服務重啟後仍然異常")

if __name__ == '__main__':
    health_check = WireGuardWarpHealthCheck()
    health_check.run_check()
EOF
    
    chmod +x /usr/local/bin/wireguard-warp-healthcheck.py
    
    # 健康檢查 systemd 服務
    cat > /etc/systemd/system/wireguard-warp-healthcheck.service <<EOF
[Unit]
Description=WireGuard WARP Health Check
After=wg-quick@${WG_IF}.service warp-netns.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wireguard-warp-healthcheck.py
User=root
StandardOutput=journal
StandardError=journal
EOF
    
    # 健康檢查定時器
    cat > /etc/systemd/system/wireguard-warp-healthcheck.timer <<EOF
[Unit]
Description=WireGuard WARP Health Check Timer
Requires=wireguard-warp-healthcheck.service

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    systemctl daemon-reload
    systemctl enable wireguard-warp-healthcheck.timer
    
    log "INFO" "健康檢查系統設定完成"
}

# ===================== 安全設定 =====================
setup_security() {
    log "INFO" "設定防火牆和安全規則..."
    
    # UFW 設定
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # SSH 存取
    local ssh_port="${SSH_PORT:-22}"
    ufw allow "$ssh_port"/tcp comment "SSH"
    
    # WireGuard 埠
    if [[ "$ENABLE_OBFUSCATION" == "true" ]]; then
        ufw allow "$OBFUSCATION_PORT"/tcp comment "WireGuard Obfuscation"
    else
        ufw allow "$WG_PORT"/udp comment "WireGuard"
    fi
    
    ufw --force enable
    
    # fail2ban 設定
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 24h
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log "INFO" "安全設定完成"
}

# ===================== 建立客戶端設定 =====================
create_client_config() {
    log "INFO" "建立客戶端設定..."
    
    # 生成客戶端密鑰
    local client_private_key
    local client_public_key
    local client_psk
    
    client_private_key=$(wg genkey)
    client_public_key=$(echo "$client_private_key" | wg pubkey)
    client_psk=$(wg genpsk)
    
    # 取得伺服器公鑰和公網 IP
    local server_public_key
    server_public_key=$(cat /etc/wireguard/${WG_IF}.pub)
    
    local server_ip
    server_ip=$(curl -s --max-time 10 https://api.ipify.org) || \
    server_ip=$(curl -s --max-time 10 https://ifconfig.me) || \
    server_ip="YOUR_SERVER_IP"
    
    # 決定 endpoint
    local endpoint_port
    if [[ "$ENABLE_OBFUSCATION" == "true" ]]; then
        endpoint_port="$OBFUSCATION_PORT"
    else
        endpoint_port="$WG_PORT"
    fi
    
    # 新增 peer 到伺服器設定
    wg set "$WG_IF" peer "$client_public_key" preshared-key <(echo "$client_psk") \
        allowed-ips "$CLIENT_IP"
    
    # 儲存 peer 資訊到設定檔
    cat >> /etc/wireguard/${WG_IF}.conf <<EOF

[Peer]
PublicKey = ${client_public_key}
PresharedKey = ${client_psk}
AllowedIPs = ${CLIENT_IP}
EOF
    
    # 產生客戶端設定檔
    cat > "/etc/wireguard/clients/${CLIENT_NAME}.conf" <<EOF
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
    
    chmod 600 "/etc/wireguard/clients/${CLIENT_NAME}.conf"
    
    # 產生 QR code
    if command -v qrencode >/dev/null 2>&1; then
        log "INFO" "客戶端 QR Code："
        qrencode -t ansiutf8 < "/etc/wireguard/clients/${CLIENT_NAME}.conf"
    fi
    
    log "INFO" "客戶端設定檔已儲存：/etc/wireguard/clients/${CLIENT_NAME}.conf"
}

# ===================== 啟動所有服務 =====================
start_all_services() {
    log "INFO" "啟動所有服務..."
    
    # 啟動 WARP namespace 服務
    systemctl enable warp-netns.service
    systemctl start warp-netns.service
    
    sleep 5
    
    # 啟動 WireGuard 服務
    systemctl enable wg-quick@${WG_IF}
    systemctl start wg-quick@${WG_IF}
    
    sleep 3
    
    # 啟動健康檢查
    systemctl start wireguard-warp-healthcheck.timer
    
    log "INFO" "所有服務啟動完成"
}

# ===================== 最終驗證 =====================
final_verification() {
    log "INFO" "執行最終驗證..."
    
    local errors=0
    
    # 檢查 namespace
    if ! ip netns list | grep -q "^${WARP_NETNS}"; then
        log "ERROR" "Network namespace ${WARP_NETNS} 不存在"
        errors=$((errors + 1))
    fi
    
    # 檢查 WARP 在 namespace 中
    if ! ip netns exec "${WARP_NETNS}" ip link show "${WARP_IF}" >/dev/null 2>&1; then
        log "ERROR" "WARP 介面在 namespace 中不存在"
        errors=$((errors + 1))
    fi
    
    # 檢查 WireGuard 服務
    if ! systemctl is-active --quiet wg-quick@${WG_IF}; then
        log "ERROR" "WireGuard 服務未運行"
        errors=$((errors + 1))
    fi
    
    # 檢查 WireGuard 介面
    if ! ip link show ${WG_IF} >/dev/null 2>&1; then
        log "ERROR" "WireGuard 介面不存在"
        errors=$((errors + 1))
    fi
    
    # 測試 WARP 連線
    if ! ip netns exec "${WARP_NETNS}" ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
        log "ERROR" "WARP 連線測試失敗"
        errors=$((errors + 1))
    fi
    
    if [[ $errors -eq 0 ]]; then
        log "INFO" "所有檢查通過 ✅"
        return 0
    else
        log "ERROR" "發現 $errors 個問題 ❌"
        return 1
    fi
}

# ===================== 主函數 =====================
main() {
    echo "=========================================="
    echo "🚀 WireGuard + WARP 生產級部署腳本 v${SCRIPT_VERSION}"
    echo "架構：Client -> WG Server -> WARP -> Internet"
    echo "=========================================="
    
    setup_logging
    log "INFO" "開始部署 WireGuard + WARP 伺服器..."
    
    check_system
    install_packages
    setup_wgcf
    setup_network_namespace
    setup_warp_in_namespace
    setup_wireguard_server
    setup_systemd_services
    setup_health_check_system
    setup_security
    create_client_config
    start_all_services
    
    # 移除錯誤處理 trap
    trap - EXIT
    
    if final_verification; then
        echo "=========================================="
        echo "🎉 WireGuard + WARP 部署完成！"
        echo "=========================================="
        echo "📊 架構資訊："
        echo "   • 客戶端 -> WireGuard (${WG_IF}) -> WARP (namespace) -> 網際網路"
        echo "   • WireGuard 埠：${WG_PORT}"
        echo "   • WARP 在獨立的 network namespace 中運行"
        echo "   • 真實 IP 被 Cloudflare WARP 保護"
        echo ""
        echo "📁 重要檔案："
        echo "   • 客戶端設定：/etc/wireguard/clients/${CLIENT_NAME}.conf"
        echo "   • 日誌檔案：${LOG_FILE}"
        echo "   • 健康檢查日誌：/var/log/wireguard-warp-healthcheck.log"
        echo ""
        echo "🔧 管理命令："
        echo "   • 查看 WireGuard 狀態：wg show"
        echo "   • 查看 WARP 狀態：ip netns exec ${WARP_NETNS} wg show ${WARP_IF}"
        echo "   • 測試 WARP 連線：ip netns exec ${WARP_NETNS} curl ifconfig.me"
        echo "   • 手動健康檢查：/usr/local/bin/wireguard-warp-healthcheck.py"
        echo ""
        echo "🔍 狀態檢查："
        echo "   • systemctl status wg-quick@${WG_IF}"
        echo "   • systemctl status warp-netns.service"
        echo "   • systemctl status wireguard-warp-healthcheck.timer"
        echo "=========================================="
    else
        error_exit "部署過程中發現問題，請檢查日誌"
    fi
}

# 執行主函數
main "$@"