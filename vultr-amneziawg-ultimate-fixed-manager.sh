#!/bin/bash
# =============================================================================
# WireGuard + WARP + AmneziaWG 終極管理工具 v1.0
# 對應 vultr-amneziawg-ultimate-fixed.sh 的完整管理解決方案
# =============================================================================

set -euo pipefail

# ===================== 全域設定 =====================
readonly SCRIPT_VERSION="1.0"
readonly SCRIPT_NAME="wireguard-warp-amnezia-manager"
readonly LOG_FILE="/var/log/wireguard-warp-amnezia-vultr-ultimate.log"

# 顏色輸出
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'

# 系統路徑
readonly WG_IF="awg0"
readonly WG_CONFIG="/etc/wireguard/${WG_IF}.conf"
readonly AMNEZIA_CONFIG="/etc/amnezia/amneziawg/${WG_IF}.conf"
readonly CLIENT_DIR="/etc/amnezia/amneziawg/clients"
readonly WARP_NETNS="warp"
readonly WARP_IF="wgcf"
readonly WARP_PROFILE="/root/wgcf-profile.conf"

# ===================== 輸出函數 =====================
print_banner() {
    clear
    echo -e "${BLUE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║         WireGuard + WARP + AmneziaWG 管理工具               ║
║                    v1.0 完整管理解決方案                    ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_section() { echo -e "${CYAN}═══ ${1} ═══${NC}"; }
print_success() { echo -e "${GREEN}✅ ${1}${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  ${1}${NC}"; }
print_error() { echo -e "${RED}❌ ${1}${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  ${1}${NC}"; }

# ===================== 工具函數 =====================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此腳本需要 root 權限執行"
        exit 1
    fi
}

press_enter() {
    echo
    read -p "按 Enter 鍵繼續..."
}

get_server_ip() {
    curl -4 -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "未知"
}

get_warp_ip() {
    ip netns exec "${WARP_NETNS}" curl -4 -s --max-time 10 ifconfig.me 2>/dev/null || echo "未測試"
}

# ===================== 系統狀態檢查 =====================
check_system_status() {
    print_banner
    print_section "系統狀態檢查"
    
    local wg_status warp_status server_ip warp_ip
    
    # 檢查 WireGuard 服務
    if systemctl is-active --quiet wg-quick@${WG_IF}; then
        wg_status="${GREEN}運行中${NC}"
    else
        wg_status="${RED}已停止${NC}"
    fi
    
    # 檢查 WARP 服務
    if systemctl is-active --quiet warp-netns.service; then
        warp_status="${GREEN}運行中${NC}"
    else
        warp_status="${RED}已停止${NC}"
    fi
    
    # 獲取 IP 資訊
    server_ip=$(get_server_ip)
    warp_ip=$(get_warp_ip)
    
    echo -e "${BLUE}📊 服務狀態${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf "%-20s %s\n" "WireGuard 服務:" "$wg_status"
    printf "%-20s %s\n" "WARP 服務:" "$warp_status"
    echo
    
    echo -e "${BLUE}🌐 網路資訊${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf "%-20s %s\n" "伺服器 IP:" "$server_ip"
    printf "%-20s %s\n" "WARP 出口 IP:" "$warp_ip"
    if [[ "$warp_ip" != "未測試" && "$warp_ip" != "未知" && "$server_ip" != "$warp_ip" ]]; then
        printf "%-20s %s\n" "IP 保護狀態:" "${GREEN}已啟用${NC}"
    else
        printf "%-20s %s\n" "IP 保護狀態:" "${YELLOW}檢查中${NC}"
    fi
    echo
    
    # 檢查介面狀態
    echo -e "${BLUE}🔗 介面狀態${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if ip link show ${WG_IF} >/dev/null 2>&1; then
        printf "%-20s %s\n" "WireGuard 介面:" "${GREEN}存在${NC}"
        
        # 顯示 peer 資訊
        local peer_count
        peer_count=$(wg show ${WG_IF} peers 2>/dev/null | wc -l || echo "0")
        printf "%-20s %s\n" "連接客戶端:" "$peer_count"
    else
        printf "%-20s %s\n" "WireGuard 介面:" "${RED}不存在${NC}"
    fi
    
    if ip netns exec "${WARP_NETNS}" ip link show "${WARP_IF}" >/dev/null 2>&1; then
        printf "%-20s %s\n" "WARP 介面:" "${GREEN}存在${NC}"
    else
        printf "%-20s %s\n" "WARP 介面:" "${RED}不存在${NC}"
    fi
    
    echo
    
    # 顯示配置檔案狀態
    echo -e "${BLUE}📁 配置檔案${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local config_files=(
        "$WG_CONFIG:WireGuard 配置"
        "$AMNEZIA_CONFIG:AmneziaWG 配置"
        "$WARP_PROFILE:WARP 配置"
    )
    
    for config in "${config_files[@]}"; do
        local file="${config%:*}"
        local desc="${config#*:}"
        if [[ -f "$file" ]]; then
            printf "%-20s %s\n" "$desc:" "${GREEN}存在${NC}"
        else
            printf "%-20s %s\n" "$desc:" "${RED}缺失${NC}"
        fi
    done
    
    # 客戶端數量
    if [[ -d "$CLIENT_DIR" ]]; then
        local client_count
        client_count=$(find "$CLIENT_DIR" -name "*.conf" | wc -l)
        printf "%-20s %s\n" "客戶端配置:" "$client_count 個"
    fi
    
    press_enter
}

# ===================== 服務管理 =====================
service_management() {
    while true; do
        print_banner
        print_section "服務管理"
        
        echo "1) 啟動 WireGuard 服務"
        echo "2) 停止 WireGuard 服務"
        echo "3) 重啟 WireGuard 服務"
        echo "4) 啟動 WARP 服務"
        echo "5) 停止 WARP 服務"
        echo "6) 重啟 WARP 服務"
        echo "7) 啟動所有服務"
        echo "8) 停止所有服務"
        echo "9) 重啟所有服務"
        echo "0) 返回主選單"
        echo
        read -p "請選擇操作 [0-9]: " choice
        
        case $choice in
            1)
                print_info "啟動 WireGuard 服務..."
                if systemctl start wg-quick@${WG_IF}; then
                    print_success "WireGuard 服務已啟動"
                else
                    print_error "WireGuard 服務啟動失敗"
                fi
                press_enter
                ;;
            2)
                print_info "停止 WireGuard 服務..."
                systemctl stop wg-quick@${WG_IF}
                print_success "WireGuard 服務已停止"
                press_enter
                ;;
            3)
                print_info "重啟 WireGuard 服務..."
                systemctl restart wg-quick@${WG_IF}
                print_success "WireGuard 服務已重啟"
                press_enter
                ;;
            4)
                print_info "啟動 WARP 服務..."
                if systemctl start warp-netns.service; then
                    print_success "WARP 服務已啟動"
                else
                    print_error "WARP 服務啟動失敗"
                fi
                press_enter
                ;;
            5)
                print_info "停止 WARP 服務..."
                systemctl stop warp-netns.service
                print_success "WARP 服務已停止"
                press_enter
                ;;
            6)
                print_info "重啟 WARP 服務..."
                systemctl restart warp-netns.service
                print_success "WARP 服務已重啟"
                press_enter
                ;;
            7)
                print_info "啟動所有服務..."
                systemctl start warp-netns.service
                systemctl start wg-quick@${WG_IF}
                print_success "所有服務已啟動"
                press_enter
                ;;
            8)
                print_info "停止所有服務..."
                systemctl stop wg-quick@${WG_IF}
                systemctl stop warp-netns.service
                print_success "所有服務已停止"
                press_enter
                ;;
            9)
                print_info "重啟所有服務..."
                systemctl restart warp-netns.service
                sleep 2
                systemctl restart wg-quick@${WG_IF}
                print_success "所有服務已重啟"
                press_enter
                ;;
            0)
                break
                ;;
            *)
                print_error "無效選擇"
                press_enter
                ;;
        esac
    done
}

# ===================== 客戶端管理 =====================
list_clients() {
    print_banner
    print_section "客戶端列表"
    
    if [[ ! -d "$CLIENT_DIR" ]]; then
        print_warning "客戶端目錄不存在"
        return 1
    fi
    
    local standard_configs amnezia_configs
    standard_configs=$(find "$CLIENT_DIR" -name "*_standard.conf" 2>/dev/null | wc -l)
    amnezia_configs=$(find "$CLIENT_DIR" -name "*_amnezia.conf" 2>/dev/null | wc -l)
    
    echo -e "${BLUE}📱 客戶端統計${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf "%-20s %s\n" "標準配置:" "$standard_configs 個"
    printf "%-20s %s\n" "AmneziaWG 配置:" "$amnezia_configs 個"
    echo
    
    echo -e "${BLUE}📁 配置檔案${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local index=1
    for config in "$CLIENT_DIR"/*.conf; do
        if [[ -f "$config" ]]; then
            local basename=$(basename "$config")
            local size=$(stat -f%z "$config" 2>/dev/null || stat -c%s "$config" 2>/dev/null || echo "未知")
            printf "%2d) %-30s (%s bytes)\n" "$index" "$basename" "$size"
            ((index++))
        fi
    done
    
    if [[ $index -eq 1 ]]; then
        print_warning "沒有找到客戶端配置檔案"
    fi
    
    press_enter
}

add_client() {
    print_banner
    print_section "添加客戶端"
    
    # 檢查必要檔案
    if [[ ! -f "$WG_CONFIG" ]]; then
        print_error "WireGuard 配置檔案不存在"
        press_enter
        return 1
    fi
    
    echo -n "請輸入客戶端名稱: "
    read client_name
    
    if [[ -z "$client_name" ]]; then
        print_error "客戶端名稱不能為空"
        press_enter
        return 1
    fi
    
    # 檢查客戶端是否已存在
    if [[ -f "$CLIENT_DIR/${client_name}_standard.conf" ]]; then
        print_error "客戶端 $client_name 已存在"
        press_enter
        return 1
    fi
    
    print_info "正在生成客戶端配置..."
    
    # 生成密鑰
    local client_private_key client_public_key client_psk
    client_private_key=$(wg genkey)
    client_public_key=$(echo "$client_private_key" | wg pubkey)
    client_psk=$(wg genpsk)
    
    # 獲取伺服器資訊
    local server_public_key server_ip server_port
    server_public_key=$(grep "^PublicKey" "$WG_CONFIG" | head -1 | cut -d' ' -f3 2>/dev/null || \
                       awk '/\[Peer\]/{found=1; next} found && /PublicKey/{print $3; exit}' "$WG_CONFIG" 2>/dev/null || \
                       cat /etc/amnezia/amneziawg/${WG_IF}.pub 2>/dev/null || echo "")
    
    if [[ -z "$server_public_key" ]]; then
        print_error "無法獲取伺服器公鑰"
        press_enter
        return 1
    fi
    
    server_ip=$(get_server_ip)
    server_port=$(grep "^ListenPort" "$WG_CONFIG" | cut -d' ' -f3 || echo "51820")
    
    # 分配 IP（簡單分配邏輯）
    local client_ip="10.66.66.$((RANDOM % 200 + 11))/32"
    
    # 標準客戶端配置
    mkdir -p "$CLIENT_DIR"
    cat > "$CLIENT_DIR/${client_name}_standard.conf" <<EOF
[Interface]
PrivateKey = $client_private_key
Address = $client_ip
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = $server_public_key
PresharedKey = $client_psk
Endpoint = $server_ip:$server_port
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    
    # AmneziaWG 客戶端配置（如果有 AmneziaWG 設定）
    if [[ -f "$AMNEZIA_CONFIG" ]]; then
        local awg_params
        awg_params=$(grep -E "^(Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4)" "$AMNEZIA_CONFIG" 2>/dev/null || echo "")
        
        cat > "$CLIENT_DIR/${client_name}_amnezia.conf" <<EOF
[Interface]
PrivateKey = $client_private_key
Address = $client_ip
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = $server_public_key
PresharedKey = $client_psk
Endpoint = $server_ip:$server_port
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

# AmneziaWG Magic Headers
$awg_params
EOF
        chmod 600 "$CLIENT_DIR/${client_name}_amnezia.conf"
    fi
    
    chmod 600 "$CLIENT_DIR/${client_name}_standard.conf"
    
    # 生成 QR Code
    if command -v qrencode >/dev/null; then
        qrencode -t PNG -o "$CLIENT_DIR/${client_name}_qr.png" \
                 < "$CLIENT_DIR/${client_name}_standard.conf"
        print_info "QR Code 已生成: $CLIENT_DIR/${client_name}_qr.png"
    fi
    
    # 添加 peer 到伺服器配置
    cat >> "$WG_CONFIG" <<EOF

[Peer]
PublicKey = $client_public_key
PresharedKey = $client_psk
AllowedIPs = $client_ip
EOF
    
    if [[ -f "$AMNEZIA_CONFIG" ]]; then
        cat >> "$AMNEZIA_CONFIG" <<EOF

[Peer]
PublicKey = $client_public_key
PresharedKey = $client_psk
AllowedIPs = $client_ip
EOF
    fi
    
    print_success "客戶端 $client_name 已成功添加"
    print_info "標準配置: $CLIENT_DIR/${client_name}_standard.conf"
    if [[ -f "$CLIENT_DIR/${client_name}_amnezia.conf" ]]; then
        print_info "AmneziaWG 配置: $CLIENT_DIR/${client_name}_amnezia.conf"
    fi
    
    echo
    read -p "是否要重啟 WireGuard 服務以應用更改？[y/N]: " restart_choice
    if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
        systemctl restart wg-quick@${WG_IF}
        print_success "WireGuard 服務已重啟"
    fi
    
    press_enter
}

show_client_config() {
    print_banner
    print_section "顯示客戶端配置"
    
    if [[ ! -d "$CLIENT_DIR" ]] || [[ -z "$(ls -A "$CLIENT_DIR"/*.conf 2>/dev/null)" ]]; then
        print_warning "沒有找到客戶端配置檔案"
        press_enter
        return 1
    fi
    
    echo "選擇要顯示的配置檔案:"
    local configs=("$CLIENT_DIR"/*.conf)
    local index=1
    for config in "${configs[@]}"; do
        if [[ -f "$config" ]]; then
            printf "%2d) %s\n" "$index" "$(basename "$config")"
            ((index++))
        fi
    done
    
    echo "0) 返回"
    echo
    read -p "請選擇 [0-$((index-1))]: " choice
    
    if [[ "$choice" == "0" ]]; then
        return 0
    fi
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -lt "$index" ]]; then
        local selected_config="${configs[$((choice-1))]}"
        
        print_banner
        print_section "客戶端配置: $(basename "$selected_config")"
        
        echo -e "${BLUE}配置內容:${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        cat "$selected_config"
        
        echo
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        # 如果有對應的 QR Code 檔案，提供顯示選項
        local qr_file="${selected_config%.*}_qr.png"
        if [[ -f "$qr_file" ]] && command -v qrencode >/dev/null; then
            echo
            read -p "是否要顯示 QR Code？[y/N]: " show_qr
            if [[ "$show_qr" =~ ^[Yy]$ ]]; then
                echo
                echo -e "${BLUE}QR Code:${NC}"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                qrencode -t ansiutf8 < "$selected_config"
            fi
        fi
        
        press_enter
    else
        print_error "無效選擇"
        press_enter
    fi
}

remove_client() {
    print_banner
    print_section "移除客戶端"
    
    if [[ ! -d "$CLIENT_DIR" ]] || [[ -z "$(ls -A "$CLIENT_DIR"/*.conf 2>/dev/null)" ]]; then
        print_warning "沒有找到客戶端配置檔案"
        press_enter
        return 1
    fi
    
    echo "選擇要移除的客戶端:"
    local configs=("$CLIENT_DIR"/*.conf)
    local index=1
    for config in "${configs[@]}"; do
        if [[ -f "$config" ]]; then
            printf "%2d) %s\n" "$index" "$(basename "$config" | sed 's/_[^_]*\.conf$//')"
            ((index++))
        fi
    done
    
    echo "0) 返回"
    echo
    read -p "請選擇 [0-$((index-1))]: " choice
    
    if [[ "$choice" == "0" ]]; then
        return 0
    fi
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -lt "$index" ]]; then
        local selected_config="${configs[$((choice-1))]}"
        local client_name=$(basename "$selected_config" | sed 's/_[^_]*\.conf$//')
        
        print_warning "確認要移除客戶端 '$client_name' 嗎？"
        read -p "此操作不可復原！[y/N]: " confirm
        
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            # 獲取客戶端公鑰以從伺服器配置中移除
            local client_pubkey
            client_pubkey=$(grep "^PublicKey" "$selected_config" 2>/dev/null | head -1 | cut -d' ' -f3 || echo "")
            
            # 移除客戶端檔案
            rm -f "$CLIENT_DIR/${client_name}_standard.conf"
            rm -f "$CLIENT_DIR/${client_name}_amnezia.conf"
            rm -f "$CLIENT_DIR/${client_name}_qr.png"
            
            # 從伺服器配置中移除 peer（如果找到公鑰）
            if [[ -n "$client_pubkey" ]]; then
                # 創建臨時檔案來處理伺服器配置
                for config_file in "$WG_CONFIG" "$AMNEZIA_CONFIG"; do
                    if [[ -f "$config_file" ]]; then
                        local temp_file=$(mktemp)
                        local in_peer_section=false
                        local current_pubkey=""
                        
                        while IFS= read -r line; do
                            if [[ "$line" =~ ^\[Peer\] ]]; then
                                in_peer_section=true
                                current_pubkey=""
                                temp_peer_section="$line"$'\n'
                            elif [[ "$line" =~ ^\[ ]]; then
                                # 開始新的 section
                                if [[ "$in_peer_section" == true ]] && [[ "$current_pubkey" != "$client_pubkey" ]]; then
                                    echo -n "$temp_peer_section" >> "$temp_file"
                                fi
                                in_peer_section=false
                                echo "$line" >> "$temp_file"
                            elif [[ "$in_peer_section" == true ]]; then
                                temp_peer_section+="$line"$'\n'
                                if [[ "$line" =~ ^PublicKey ]]; then
                                    current_pubkey=$(echo "$line" | cut -d' ' -f3)
                                fi
                            else
                                echo "$line" >> "$temp_file"
                            fi
                        done < "$config_file"
                        
                        # 處理檔案末尾的 peer section
                        if [[ "$in_peer_section" == true ]] && [[ "$current_pubkey" != "$client_pubkey" ]]; then
                            echo -n "$temp_peer_section" >> "$temp_file"
                        fi
                        
                        mv "$temp_file" "$config_file"
                    fi
                done
            fi
            
            print_success "客戶端 '$client_name' 已成功移除"
            
            echo
            read -p "是否要重啟 WireGuard 服務以應用更改？[y/N]: " restart_choice
            if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
                systemctl restart wg-quick@${WG_IF}
                print_success "WireGuard 服務已重啟"
            fi
        else
            print_info "操作已取消"
        fi
    else
        print_error "無效選擇"
    fi
    
    press_enter
}

client_management() {
    while true; do
        print_banner
        print_section "客戶端管理"
        
        echo "1) 列出所有客戶端"
        echo "2) 添加新客戶端"
        echo "3) 顯示客戶端配置"
        echo "4) 移除客戶端"
        echo "0) 返回主選單"
        echo
        read -p "請選擇操作 [0-4]: " choice
        
        case $choice in
            1) list_clients ;;
            2) add_client ;;
            3) show_client_config ;;
            4) remove_client ;;
            0) break ;;
            *) 
                print_error "無效選擇"
                press_enter
                ;;
        esac
    done
}

# ===================== 網路診斷 =====================
network_diagnostics() {
    print_banner
    print_section "網路診斷"
    
    echo -e "${BLUE}🔍 網路連線測試${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # 基本連線測試
    print_info "測試基本網路連線..."
    if ping -c 3 -W 5 8.8.8.8 >/dev/null 2>&1; then
        print_success "基本網路連線正常"
    else
        print_error "基本網路連線失敗"
    fi
    
    # DNS 解析測試
    print_info "測試 DNS 解析..."
    if nslookup google.com >/dev/null 2>&1; then
        print_success "DNS 解析正常"
    else
        print_error "DNS 解析失敗"
    fi
    
    # WARP 連線測試
    print_info "測試 WARP 連線..."
    if ip netns exec "${WARP_NETNS}" ping -c 3 -W 5 1.1.1.1 >/dev/null 2>&1; then
        print_success "WARP 連線正常"
    else
        print_warning "WARP 連線異常"
    fi
    
    echo
    echo -e "${BLUE}📊 介面狀態${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # WireGuard 介面資訊
    if ip link show ${WG_IF} >/dev/null 2>&1; then
        print_success "WireGuard 介面 (${WG_IF}) 存在"
        echo "介面詳情:"
        ip addr show ${WG_IF} | sed 's/^/  /'
        
        echo
        echo "WireGuard 狀態:"
        wg show ${WG_IF} | sed 's/^/  /'
    else
        print_error "WireGuard 介面不存在"
    fi
    
    echo
    
    # WARP 介面資訊
    if ip netns exec "${WARP_NETNS}" ip link show "${WARP_IF}" >/dev/null 2>&1; then
        print_success "WARP 介面 (${WARP_IF}) 存在於 namespace"
        echo "WARP 介面詳情:"
        ip netns exec "${WARP_NETNS}" ip addr show "${WARP_IF}" | sed 's/^/  /'
        
        echo
        echo "WARP 狀態:"
        ip netns exec "${WARP_NETNS}" wg show "${WARP_IF}" 2>/dev/null | sed 's/^/  /' || echo "  無法獲取 WARP 狀態"
    else
        print_warning "WARP 介面不存在於 namespace"
    fi
    
    echo
    echo -e "${BLUE}🔗 路由資訊${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "主系統路由表:"
    ip route show | head -10 | sed 's/^/  /'
    
    echo
    echo "WARP namespace 路由表:"
    ip netns exec "${WARP_NETNS}" ip route show 2>/dev/null | sed 's/^/  /' || echo "  無法獲取 WARP 路由表"
    
    press_enter
}

# ===================== 日誌查看 =====================
view_logs() {
    while true; do
        print_banner
        print_section "日誌查看"
        
        echo "1) WireGuard 服務日誌"
        echo "2) WARP 服務日誌"
        echo "3) 系統部署日誌"
        echo "4) 即時日誌監控"
        echo "0) 返回主選單"
        echo
        read -p "請選擇要查看的日誌 [0-4]: " choice
        
        case $choice in
            1)
                print_banner
                print_section "WireGuard 服務日誌"
                echo "按 'q' 退出日誌檢視"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                journalctl -u wg-quick@${WG_IF} --no-pager -n 50
                press_enter
                ;;
            2)
                print_banner
                print_section "WARP 服務日誌"
                echo "按 'q' 退出日誌檢視"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                journalctl -u warp-netns.service --no-pager -n 50
                press_enter
                ;;
            3)
                print_banner
                print_section "系統部署日誌"
                if [[ -f "$LOG_FILE" ]]; then
                    echo "最近 50 行日誌:"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    tail -50 "$LOG_FILE"
                else
                    print_warning "部署日誌檔案不存在"
                fi
                press_enter
                ;;
            4)
                print_info "開始即時日誌監控，按 Ctrl+C 停止..."
                sleep 2
                journalctl -u wg-quick@${WG_IF} -u warp-netns.service -f
                ;;
            0)
                break
                ;;
            *)
                print_error "無效選擇"
                press_enter
                ;;
        esac
    done
}

# ===================== 配置管理 =====================
config_management() {
    while true; do
        print_banner
        print_section "配置管理"
        
        echo "1) 查看 WireGuard 配置"
        echo "2) 查看 AmneziaWG 配置"
        echo "3) 查看 WARP 配置"
        echo "4) 備份所有配置"
        echo "5) 還原配置備份"
        echo "0) 返回主選單"
        echo
        read -p "請選擇操作 [0-5]: " choice
        
        case $choice in
            1)
                print_banner
                print_section "WireGuard 配置"
                if [[ -f "$WG_CONFIG" ]]; then
                    echo "配置檔案位置: $WG_CONFIG"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    cat "$WG_CONFIG"
                else
                    print_error "WireGuard 配置檔案不存在"
                fi
                press_enter
                ;;
            2)
                print_banner
                print_section "AmneziaWG 配置"
                if [[ -f "$AMNEZIA_CONFIG" ]]; then
                    echo "配置檔案位置: $AMNEZIA_CONFIG"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    cat "$AMNEZIA_CONFIG"
                else
                    print_error "AmneziaWG 配置檔案不存在"
                fi
                press_enter
                ;;
            3)
                print_banner
                print_section "WARP 配置"
                if [[ -f "$WARP_PROFILE" ]]; then
                    echo "配置檔案位置: $WARP_PROFILE"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    cat "$WARP_PROFILE"
                else
                    print_error "WARP 配置檔案不存在"
                fi
                press_enter
                ;;
            4)
                print_info "開始備份配置..."
                local backup_dir="/root/wireguard-backup-$(date +%Y%m%d-%H%M%S)"
                mkdir -p "$backup_dir"
                
                # 備份配置檔案
                [[ -f "$WG_CONFIG" ]] && cp "$WG_CONFIG" "$backup_dir/"
                [[ -f "$AMNEZIA_CONFIG" ]] && cp "$AMNEZIA_CONFIG" "$backup_dir/"
                [[ -f "$WARP_PROFILE" ]] && cp "$WARP_PROFILE" "$backup_dir/"
                [[ -d "$CLIENT_DIR" ]] && cp -r "$CLIENT_DIR" "$backup_dir/"
                
                # 備份腳本
                [[ -f "/etc/wireguard/postup.sh" ]] && cp "/etc/wireguard/postup.sh" "$backup_dir/"
                [[ -f "/etc/wireguard/predown.sh" ]] && cp "/etc/wireguard/predown.sh" "$backup_dir/"
                [[ -f "/usr/local/bin/warp-netns-up.sh" ]] && cp "/usr/local/bin/warp-netns-up.sh" "$backup_dir/"
                [[ -f "/usr/local/bin/warp-netns-down.sh" ]] && cp "/usr/local/bin/warp-netns-down.sh" "$backup_dir/"
                
                # 備份系統服務
                [[ -f "/etc/systemd/system/warp-netns.service" ]] && cp "/etc/systemd/system/warp-netns.service" "$backup_dir/"
                
                print_success "配置已備份至: $backup_dir"
                press_enter
                ;;
            5)
                print_info "查找可用的備份..."
                local backups=($(find /root -maxdepth 1 -name "wireguard-backup-*" -type d 2>/dev/null | sort -r))
                
                if [[ ${#backups[@]} -eq 0 ]]; then
                    print_warning "沒有找到備份檔案"
                    press_enter
                    continue
                fi
                
                echo "可用的備份:"
                local index=1
                for backup in "${backups[@]}"; do
                    printf "%2d) %s\n" "$index" "$(basename "$backup")"
                    ((index++))
                done
                
                echo "0) 取消"
                echo
                read -p "請選擇要還原的備份 [0-$((index-1))]: " backup_choice
                
                if [[ "$backup_choice" == "0" ]]; then
                    continue
                fi
                
                if [[ "$backup_choice" =~ ^[0-9]+$ ]] && [[ "$backup_choice" -ge 1 ]] && [[ "$backup_choice" -lt "$index" ]]; then
                    local selected_backup="${backups[$((backup_choice-1))]}"
                    
                    print_warning "確認要還原備份嗎？這將覆蓋當前配置！"
                    read -p "繼續？[y/N]: " confirm
                    
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        print_info "正在還原備份..."
                        
                        # 停止服務
                        systemctl stop wg-quick@${WG_IF} 2>/dev/null || true
                        systemctl stop warp-netns.service 2>/dev/null || true
                        
                        # 還原檔案
                        [[ -f "$selected_backup/$(basename "$WG_CONFIG")" ]] && cp "$selected_backup/$(basename "$WG_CONFIG")" "$WG_CONFIG"
                        [[ -f "$selected_backup/$(basename "$AMNEZIA_CONFIG")" ]] && cp "$selected_backup/$(basename "$AMNEZIA_CONFIG")" "$AMNEZIA_CONFIG"
                        [[ -f "$selected_backup/$(basename "$WARP_PROFILE")" ]] && cp "$selected_backup/$(basename "$WARP_PROFILE")" "$WARP_PROFILE"
                        [[ -d "$selected_backup/clients" ]] && cp -r "$selected_backup/clients" "$(dirname "$CLIENT_DIR")/"
                        
                        # 還原腳本
                        [[ -f "$selected_backup/postup.sh" ]] && cp "$selected_backup/postup.sh" "/etc/wireguard/"
                        [[ -f "$selected_backup/predown.sh" ]] && cp "$selected_backup/predown.sh" "/etc/wireguard/"
                        [[ -f "$selected_backup/warp-netns-up.sh" ]] && cp "$selected_backup/warp-netns-up.sh" "/usr/local/bin/"
                        [[ -f "$selected_backup/warp-netns-down.sh" ]] && cp "$selected_backup/warp-netns-down.sh" "/usr/local/bin/"
                        [[ -f "$selected_backup/warp-netns.service" ]] && cp "$selected_backup/warp-netns.service" "/etc/systemd/system/"
                        
                        # 重新載入並啟動服務
                        systemctl daemon-reload
                        systemctl start warp-netns.service 2>/dev/null || true
                        sleep 2
                        systemctl start wg-quick@${WG_IF} 2>/dev/null || true
                        
                        print_success "配置已成功還原"
                    else
                        print_info "操作已取消"
                    fi
                else
                    print_error "無效選擇"
                fi
                
                press_enter
                ;;
            0)
                break
                ;;
            *)
                print_error "無效選擇"
                press_enter
                ;;
        esac
    done
}

# ===================== 故障排除 =====================
troubleshooting() {
    while true; do
        print_banner
        print_section "故障排除"
        
        echo "1) 自動診斷並修復"
        echo "2) 重置所有服務"
        echo "3) 檢查防火牆設定"
        echo "4) 修復權限問題"
        echo "5) 清理並重建 namespace"
        echo "6) 檢查埠佔用情況"
        echo "0) 返回主選單"
        echo
        read -p "請選擇操作 [0-6]: " choice
        
        case $choice in
            1)
                print_info "開始自動診斷..."
                
                # 檢查服務狀態
                local issues=0
                
                if ! systemctl is-active --quiet wg-quick@${WG_IF}; then
                    print_warning "WireGuard 服務未運行，嘗試啟動..."
                    if systemctl start wg-quick@${WG_IF}; then
                        print_success "WireGuard 服務已啟動"
                    else
                        print_error "WireGuard 服務啟動失敗"
                        ((issues++))
                    fi
                fi
                
                if ! systemctl is-active --quiet warp-netns.service; then
                    print_warning "WARP 服務未運行，嘗試啟動..."
                    if systemctl start warp-netns.service; then
                        print_success "WARP 服務已啟動"
                    else
                        print_warning "WARP 服務啟動失敗（不影響主要功能）"
                    fi
                fi
                
                # 檢查配置檔案
                if [[ ! -f "$WG_CONFIG" ]]; then
                    print_error "WireGuard 配置檔案不存在"
                    ((issues++))
                fi
                
                # 檢查介面
                if ! ip link show ${WG_IF} >/dev/null 2>&1; then
                    print_warning "WireGuard 介面不存在"
                    ((issues++))
                fi
                
                if [[ $issues -eq 0 ]]; then
                    print_success "自動診斷完成，沒有發現問題"
                else
                    print_warning "發現 $issues 個問題，可能需要手動修復"
                fi
                
                press_enter
                ;;
            2)
                print_warning "這將重置所有服務，確認繼續？"
                read -p "[y/N]: " confirm
                
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    print_info "重置所有服務..."
                    
                    systemctl stop wg-quick@${WG_IF} 2>/dev/null || true
                    systemctl stop warp-netns.service 2>/dev/null || true
                    
                    # 清理網路
                    ip netns del "${WARP_NETNS}" 2>/dev/null || true
                    
                    # 重新載入服務
                    systemctl daemon-reload
                    
                    # 重新啟動
                    systemctl start warp-netns.service 2>/dev/null || true
                    sleep 3
                    systemctl start wg-quick@${WG_IF} 2>/dev/null || true
                    
                    print_success "服務重置完成"
                else
                    print_info "操作已取消"
                fi
                
                press_enter
                ;;
            3)
                print_info "檢查防火牆設定..."
                
                echo -e "\n${BLUE}UFW 狀態:${NC}"
                ufw status verbose
                
                echo -e "\n${BLUE}iptables NAT 規則:${NC}"
                iptables -t nat -L POSTROUTING -v -n | head -10
                
                echo -e "\n${BLUE}iptables FORWARD 規則:${NC}"
                iptables -L FORWARD -v -n | head -10
                
                press_enter
                ;;
            4)
                print_info "修復權限問題..."
                
                # 修復配置檔案權限
                [[ -f "$WG_CONFIG" ]] && chmod 600 "$WG_CONFIG"
                [[ -f "$AMNEZIA_CONFIG" ]] && chmod 600 "$AMNEZIA_CONFIG"
                [[ -f "$WARP_PROFILE" ]] && chmod 600 "$WARP_PROFILE"
                
                # 修復腳本權限
                chmod +x /usr/local/bin/warp-netns-*.sh 2>/dev/null || true
                chmod +x /etc/wireguard/{postup,predown}.sh 2>/dev/null || true
                
                # 修復目錄權限
                [[ -d "$(dirname "$WG_CONFIG")" ]] && chmod 700 "$(dirname "$WG_CONFIG")"
                [[ -d "$(dirname "$AMNEZIA_CONFIG")" ]] && chmod 700 "$(dirname "$AMNEZIA_CONFIG")"
                [[ -d "$CLIENT_DIR" ]] && chmod 700 "$CLIENT_DIR"
                
                # 修復客戶端檔案權限
                find "$CLIENT_DIR" -name "*.conf" -exec chmod 600 {} \; 2>/dev/null || true
                
                print_success "權限修復完成"
                press_enter
                ;;
            5)
                print_info "清理並重建 namespace..."
                
                # 停止相關服務
                systemctl stop warp-netns.service 2>/dev/null || true
                
                # 清理舊 namespace
                ip netns del "${WARP_NETNS}" 2>/dev/null || true
                ip link del "veth-main" 2>/dev/null || true
                
                # 重建 namespace
                ip netns add "${WARP_NETNS}"
                ip netns exec "${WARP_NETNS}" ip link set lo up
                
                ip link add "veth-${WARP_NETNS}" type veth peer name "veth-main"
                ip link set "veth-${WARP_NETNS}" netns "${WARP_NETNS}"
                ip link set "veth-main" up
                
                ip addr add 172.31.0.1/30 dev "veth-main"
                ip netns exec "${WARP_NETNS}" ip addr add 172.31.0.2/30 dev "veth-${WARP_NETNS}"
                ip netns exec "${WARP_NETNS}" ip link set "veth-${WARP_NETNS}" up
                ip netns exec "${WARP_NETNS}" ip route add default via 172.31.0.1
                
                # 重啟 WARP 服務
                systemctl start warp-netns.service 2>/dev/null || true
                
                print_success "namespace 重建完成"
                press_enter
                ;;
            6)
                print_info "檢查埠佔用情況..."
                
                local wg_port=$(grep "^ListenPort" "$WG_CONFIG" 2>/dev/null | cut -d' ' -f3 || echo "51820")
                
                echo -e "\n${BLUE}WireGuard 埠 $wg_port 使用情況:${NC}"
                netstat -ulnp | grep ":$wg_port " || echo "埠未被佔用"
                
                echo -e "\n${BLUE}所有 WireGuard 相關埠:${NC}"
                netstat -ulnp | grep -E "(wireguard|wg|awg)" || echo "沒有找到相關埠"
                
                press_enter
                ;;
            0)
                break
                ;;
            *)
                print_error "無效選擇"
                press_enter
                ;;
        esac
    done
}

# ===================== 主選單 =====================
main_menu() {
    while true; do
        print_banner
        
        echo -e "${CYAN}主要功能${NC}"
        echo "1) 系統狀態檢查"
        echo "2) 服務管理"
        echo "3) 客戶端管理"
        echo "4) 網路診斷"
        echo "5) 日誌查看"
        echo "6) 配置管理"
        echo "7) 故障排除"
        echo "0) 退出"
        echo
        read -p "請選擇功能 [0-7]: " choice
        
        case $choice in
            1) check_system_status ;;
            2) service_management ;;
            3) client_management ;;
            4) network_diagnostics ;;
            5) view_logs ;;
            6) config_management ;;
            7) troubleshooting ;;
            0) 
                print_info "感謝使用 WireGuard + WARP + AmneziaWG 管理工具"
                exit 0
                ;;
            *)
                print_error "無效選擇"
                press_enter
                ;;
        esac
    done
}

# ===================== 主函數 =====================
main() {
    # 檢查權限
    check_root
    
    # 檢查基本系統
    if ! command -v wg >/dev/null; then
        print_error "WireGuard 工具未安裝"
        exit 1
    fi
    
    # 進入主選單
    main_menu
}

# 執行主函數
main "$@"