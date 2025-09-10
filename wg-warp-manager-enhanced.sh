#!/bin/bash
# WireGuard + WARP 增強管理腳本 v1.1
# 新增 DNS 設定修改功能

set -euo pipefail

WARP_NETNS="warp"
WG_IF="wg0"
WARP_IF="wgcf"
WG_CONFIG="/etc/wireguard/${WG_IF}.conf"
CLIENTS_DIR="/etc/wireguard/clients"
LOG_FILE="/var/log/wg-warp-manager.log"

# 日誌函數
log() {
    local level="${1:-INFO}"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] $*" | tee -a "${LOG_FILE}"
}

show_help() {
    echo "WireGuard + WARP 增強管理工具 v1.1"
    echo ""
    echo "用法: $0 [選項]"
    echo ""
    echo "基本功能:"
    echo "  status          顯示服務狀態"
    echo "  test            測試連線品質"
    echo "  restart-warp    重啟 WARP 服務"
    echo "  restart-wg      重啟 WireGuard 服務"
    echo "  restart-all     重啟所有服務"
    echo "  logs            顯示日誌"
    echo "  ip-check        檢查出口 IP"
    echo ""
    echo "客戶端管理:"
    echo "  add-client      新增客戶端"
    echo "  list-clients    列出客戶端"
    echo "  remove-client   移除客戶端"
    echo "  show-client     顯示客戶端設定"
    echo ""
    echo "設定管理:"
    echo "  change-dns      修改 DNS 設定"
    echo "  backup-config   備份設定檔"
    echo "  restore-config  還原設定檔"
    echo ""
    echo "進階功能:"
    echo "  health-check    手動健康檢查"
    echo "  update-warp     更新 WARP 設定"
    echo "  help            顯示此說明"
}

show_status() {
    echo "========== 服務狀態 =========="
    log "INFO" "檢查服務狀態"
    
    echo "WireGuard 服務:"
    if systemctl is-active --quiet wg-quick@${WG_IF}; then
        echo "  ✅ 正在運行"
        echo "     監聽埠: $(grep 'ListenPort' ${WG_CONFIG} | cut -d' ' -f3 2>/dev/null || echo '未知')"
        echo "     伺服器 IP: $(grep 'Address' ${WG_CONFIG} | cut -d' ' -f3 2>/dev/null || echo '未知')"
    else
        echo "  ❌ 未運行"
    fi
    
    echo ""
    echo "WARP Namespace 服務:"
    if systemctl is-active --quiet warp-netns.service; then
        echo "  ✅ 正在運行"
    else
        echo "  ❌ 未運行"
    fi
    
    echo ""
    echo "健康檢查定時器:"
    if systemctl is-active --quiet wireguard-warp-healthcheck.timer; then
        echo "  ✅ 正在運行"
        echo "     下次檢查: $(systemctl show wireguard-warp-healthcheck.timer -p NextElapseUSecMonotonic --value | xargs -I {} date -d @$((({}/1000000) + $(date +%s) - $(cat /proc/uptime | cut -d' ' -f1 | cut -d'.' -f1))) 2>/dev/null || echo '未知')"
    else
        echo "  ❌ 未運行"
    fi
    
    echo ""
    echo "========== 網路介面狀態 =========="
    if ip link show ${WG_IF} >/dev/null 2>&1; then
        echo "✅ WireGuard 介面 ${WG_IF} 存在"
        local peer_count
        peer_count=$(wg show ${WG_IF} peers 2>/dev/null | wc -l)
        echo "   已連接 peer 數量: ${peer_count}"
        
        if [[ $peer_count -gt 0 ]]; then
            echo "   最近握手時間:"
            wg show ${WG_IF} latest-handshakes 2>/dev/null | while read -r pubkey timestamp; do
                if [[ $timestamp -gt 0 ]]; then
                    local handshake_time
                    handshake_time=$(date -d "@${timestamp}" '+%Y-%m-%d %H:%M:%S')
                    echo "     ${pubkey:0:8}...${pubkey: -8}: ${handshake_time}"
                else
                    echo "     ${pubkey:0:8}...${pubkey: -8}: 從未握手"
                fi
            done
        fi
    else
        echo "❌ WireGuard 介面 ${WG_IF} 不存在"
    fi
    
    echo ""
    if ip netns list | grep -q "^${WARP_NETNS}"; then
        echo "✅ Network namespace ${WARP_NETNS} 存在"
        if ip netns exec ${WARP_NETNS} ip link show ${WARP_IF} >/dev/null 2>&1; then
            echo "✅ WARP 介面 ${WARP_IF} 存在"
            local warp_status
            warp_status=$(ip netns exec ${WARP_NETNS} wg show ${WARP_IF} 2>/dev/null)
            if [[ -n "$warp_status" ]]; then
                echo "   WARP 連線資訊:"
                echo "$warp_status" | sed 's/^/     /'
            fi
        else
            echo "❌ WARP 介面 ${WARP_IF} 不存在"
        fi
    else
        echo "❌ Network namespace ${WARP_NETNS} 不存在"
    fi
    
    echo ""
    echo "========== DNS 設定 =========="
    if [[ -f "$WG_CONFIG" ]]; then
        local current_dns
        current_dns=$(grep "^DNS = " ${CLIENTS_DIR}/*.conf 2>/dev/null | head -n1 | cut -d' ' -f3 || echo "未設定")
        echo "目前 DNS 設定: ${current_dns}"
    fi
}

test_connectivity() {
    echo "========== 連線測試 =========="
    log "INFO" "開始連線測試"
    
    echo "測試伺服器本機連線..."
    if timeout 5 ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        echo "✅ 本機網路連線正常"
    else
        echo "❌ 本機網路連線異常"
    fi
    
    echo ""
    echo "測試 WARP 連線..."
    if ip netns exec ${WARP_NETNS} timeout 10 ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
        echo "✅ WARP 連線正常"
        
        echo -n "WARP 出口 IP: "
        local warp_ip
        warp_ip=$(ip netns exec ${WARP_NETNS} timeout 10 curl -s ifconfig.me 2>/dev/null)
        if [[ -n "$warp_ip" ]]; then
            echo "$warp_ip"
            
            # 檢查 IP 位置
            echo "IP 位置資訊:"
            local location_info
            location_info=$(ip netns exec ${WARP_NETNS} timeout 10 curl -s "http://ip-api.com/json/${warp_ip}?fields=country,regionName,city,isp" 2>/dev/null)
            if [[ -n "$location_info" ]]; then
                echo "$location_info" | jq -r '"  國家: " + .country + "\n  地區: " + .regionName + "\n  城市: " + .city + "\n  ISP: " + .isp' 2>/dev/null || echo "  無法解析位置資訊"
            fi
        else
            echo "無法取得"
        fi
    else
        echo "❌ WARP 連線異常"
    fi
    
    echo ""
    echo "測試 DNS 解析..."
    local test_domains=("google.com" "cloudflare.com" "github.com")
    for domain in "${test_domains[@]}"; do
        if ip netns exec ${WARP_NETNS} timeout 5 nslookup "$domain" >/dev/null 2>&1; then
            echo "✅ ${domain} 解析正常"
        else
            echo "❌ ${domain} 解析失敗"
        fi
    done
}

change_dns() {
    echo "========== 修改 DNS 設定 =========="
    log "INFO" "開始修改 DNS 設定"
    
    # 顯示目前 DNS
    local current_dns
    if [[ -f "${CLIENTS_DIR}/client01.conf" ]]; then
        current_dns=$(grep "^DNS = " "${CLIENTS_DIR}/client01.conf" | cut -d' ' -f3 2>/dev/null || echo "未設定")
    else
        current_dns="未設定"
    fi
    
    echo "目前 DNS 設定: ${current_dns}"
    echo ""
    echo "常用 DNS 選項:"
    echo "  1) Cloudflare: 1.1.1.1"
    echo "  2) Google: 8.8.8.8"
    echo "  3) Quad9: 9.9.9.9"
    echo "  4) OpenDNS: 208.67.222.222"
    echo "  5) AdGuard: 94.140.14.14"
    echo "  6) 自訂 DNS"
    echo ""
    
    local choice
    read -r -p "請選擇 DNS (1-6): " choice
    
    local new_dns
    case $choice in
        1)
            new_dns="1.1.1.1"
            ;;
        2)
            new_dns="8.8.8.8"
            ;;
        3)
            new_dns="9.9.9.9"
            ;;
        4)
            new_dns="208.67.222.222"
            ;;
        5)
            new_dns="94.140.14.14"
            ;;
        6)
            read -r -p "請輸入自訂 DNS 地址: " new_dns
            ;;
        *)
            echo "無效選擇"
            return 1
            ;;
    esac
    
    # 驗證 DNS 格式
    if ! [[ "$new_dns" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "❌ DNS 地址格式無效"
        return 1
    fi
    
    # 測試 DNS 可用性
    echo ""
    echo "測試新 DNS 地址可用性..."
    if timeout 5 nslookup google.com "$new_dns" >/dev/null 2>&1; then
        echo "✅ DNS 地址測試通過"
    else
        echo "❌ DNS 地址測試失敗"
        read -r -p "是否仍要繼續? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "操作已取消"
            return 1
        fi
    fi
    
    echo ""
    echo "準備修改以下設定:"
    echo "  舊 DNS: ${current_dns}"
    echo "  新 DNS: ${new_dns}"
    echo ""
    
    read -r -p "確認執行修改? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "操作已取消"
        return 1
    fi
    
    # 建立備份
    local backup_dir="/opt/wireguard-backup/dns-change-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    echo ""
    echo "建立設定備份..."
    if [[ -d "$CLIENTS_DIR" ]]; then
        cp -r "$CLIENTS_DIR" "$backup_dir/clients" 2>/dev/null || true
        log "INFO" "客戶端設定已備份至 ${backup_dir}"
    fi
    
    # 修改所有客戶端設定檔
    echo ""
    echo "修改客戶端設定檔..."
    local modified_count=0
    
    if [[ -d "$CLIENTS_DIR" ]]; then
        for conf_file in "${CLIENTS_DIR}"/*.conf; do
            if [[ -f "$conf_file" ]]; then
                local client_name
                client_name=$(basename "$conf_file" .conf)
                
                # 檢查是否包含 DNS 設定
                if grep -q "^DNS = " "$conf_file"; then
                    # 修改現有 DNS
                    sed -i "s/^DNS = .*/DNS = ${new_dns}/" "$conf_file"
                    echo "  ✅ 已修改 ${client_name}"
                    modified_count=$((modified_count + 1))
                else
                    # 在 [Interface] 區段新增 DNS
                    sed -i "/^\[Interface\]/a DNS = ${new_dns}" "$conf_file"
                    echo "  ✅ 已新增 DNS 到 ${client_name}"
                    modified_count=$((modified_count + 1))
                fi
                
                # 產生新的 QR code 檔案
                if command -v qrencode >/dev/null 2>&1; then
                    qrencode -t PNG -o "${CLIENTS_DIR}/${client_name}_qr.png" < "$conf_file" 2>/dev/null || true
                fi
            fi
        done
    fi
    
    echo ""
    echo "總計修改了 ${modified_count} 個客戶端設定檔"
    log "INFO" "DNS 設定修改完成，共修改 ${modified_count} 個設定檔"
    
    # 重新啟動服務
    echo ""
    echo "重新啟動服務以套用變更..."
    
    log "INFO" "重新啟動 WireGuard 和 WARP 服務"
    
    # 重啟 WireGuard 服務
    echo "  重啟 WireGuard 服務..."
    if systemctl restart wg-quick@${WG_IF}; then
        echo "  ✅ WireGuard 服務重啟成功"
    else
        echo "  ❌ WireGuard 服務重啟失敗"
        log "ERROR" "WireGuard 服務重啟失敗"
    fi
    
    sleep 3
    
    # 重啟 WARP 服務
    echo "  重啟 WARP 服務..."
    if systemctl restart warp-netns.service; then
        echo "  ✅ WARP 服務重啟成功"
    else
        echo "  ❌ WARP 服務重啟失敗"
        log "ERROR" "WARP 服務重啟失敗"
    fi
    
    sleep 5
    
    # 重啟健康檢查
    echo "  重啟健康檢查定時器..."
    systemctl restart wireguard-warp-healthcheck.timer 2>/dev/null || true
    
    echo ""
    echo "========== 驗證修改結果 =========="
    
    # 檢查服務狀態
    if systemctl is-active --quiet wg-quick@${WG_IF} && systemctl is-active --quiet warp-netns.service; then
        echo "✅ 所有服務運行正常"
        
        # 測試 DNS 解析
        echo ""
        echo "測試新 DNS 設定..."
        if ip netns exec ${WARP_NETNS} timeout 5 nslookup google.com "$new_dns" >/dev/null 2>&1; then
            echo "✅ 新 DNS 設定測試通過"
        else
            echo "⚠️  新 DNS 設定測試失敗，但服務正常運行"
        fi
        
        echo ""
        echo "🎉 DNS 設定修改完成！"
        echo ""
        echo "📋 摘要:"
        echo "  • 新 DNS 地址: ${new_dns}"
        echo "  • 修改的設定檔數量: ${modified_count}"
        echo "  • 備份位置: ${backup_dir}"
        echo "  • 所有服務已重新啟動"
        echo ""
        echo "📱 客戶端更新:"
        echo "  客戶端需要重新匯入設定檔或重新掃描 QR code"
        echo "  設定檔位置: ${CLIENTS_DIR}/"
        
    else
        echo "❌ 部分服務啟動失敗"
        echo ""
        echo "🔧 故障排除建議:"
        echo "  1. 檢查服務狀態: $0 status"
        echo "  2. 查看日誌: $0 logs"
        echo "  3. 如需回復設定: $0 restore-config ${backup_dir}"
        log "ERROR" "DNS 修改後服務狀態異常"
    fi
}

backup_config() {
    echo "========== 備份設定檔 =========="
    
    local backup_dir="/opt/wireguard-backup/manual-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    echo "建立設定備份..."
    
    # 備份 WireGuard 設定
    if [[ -f "$WG_CONFIG" ]]; then
        cp "$WG_CONFIG" "$backup_dir/"
        echo "✅ WireGuard 伺服器設定已備份"
    fi
    
    # 備份客戶端設定
    if [[ -d "$CLIENTS_DIR" ]]; then
        cp -r "$CLIENTS_DIR" "$backup_dir/"
        echo "✅ 客戶端設定已備份"
    fi
    
    # 備份 systemd 服務設定
    local systemd_configs=(
        "/etc/systemd/system/warp-netns.service"
        "/etc/systemd/system/wg-quick@${WG_IF}.service.d/override.conf"
        "/etc/systemd/system/wireguard-warp-healthcheck.service"
        "/etc/systemd/system/wireguard-warp-healthcheck.timer"
    )
    
    mkdir -p "$backup_dir/systemd"
    for config in "${systemd_configs[@]}"; do
        if [[ -f "$config" ]]; then
            cp "$config" "$backup_dir/systemd/" 2>/dev/null || true
        fi
    done
    echo "✅ systemd 服務設定已備份"
    
    # 備份腳本
    local scripts=(
        "/usr/local/bin/warp-netns-up.sh"
        "/usr/local/bin/warp-netns-down.sh"
        "/usr/local/bin/wireguard-warp-healthcheck.py"
        "/etc/wireguard/scripts/postup.sh"
        "/etc/wireguard/scripts/predown.sh"
    )
    
    mkdir -p "$backup_dir/scripts"
    for script in "${scripts[@]}"; do
        if [[ -f "$script" ]]; then
            cp "$script" "$backup_dir/scripts/" 2>/dev/null || true
        fi
    done
    echo "✅ 腳本檔案已備份"
    
    # 建立備份資訊檔案
    cat > "$backup_dir/backup_info.txt" <<EOF
備份建立時間: $(date)
WireGuard 介面: ${WG_IF}
WARP Namespace: ${WARP_NETNS}
備份類型: 手動備份

服務狀態:
WireGuard: $(systemctl is-active wg-quick@${WG_IF} 2>/dev/null || echo "未知")
WARP: $(systemctl is-active warp-netns.service 2>/dev/null || echo "未知")
健康檢查: $(systemctl is-active wireguard-warp-healthcheck.timer 2>/dev/null || echo "未知")

當時的客戶端數量: $(find "${CLIENTS_DIR}" -name "*.conf" 2>/dev/null | wc -l)
EOF
    
    echo ""
    echo "🎉 備份完成！"
    echo "備份位置: ${backup_dir}"
    echo "備份內容: WireGuard 設定、客戶端設定、systemd 服務、腳本檔案"
    
    log "INFO" "手動備份完成: ${backup_dir}"
}

restore_config() {
    echo "========== 還原設定檔 =========="
    
    if [[ -z "${2:-}" ]]; then
        echo "可用的備份:"
        if [[ -d "/opt/wireguard-backup" ]]; then
            find /opt/wireguard-backup -maxdepth 1 -type d -name "*backup*" | sort -r | head -10
        else
            echo "沒有找到備份目錄"
        fi
        echo ""
        echo "用法: $0 restore-config <備份目錄路徑>"
        return 1
    fi
    
    local backup_dir="$2"
    
    if [[ ! -d "$backup_dir" ]]; then
        echo "❌ 備份目錄不存在: $backup_dir"
        return 1
    fi
    
    echo "準備從以下備份還原設定:"
    echo "  備份目錄: $backup_dir"
    
    if [[ -f "$backup_dir/backup_info.txt" ]]; then
        echo ""
        echo "備份資訊:"
        cat "$backup_dir/backup_info.txt" | sed 's/^/  /'
    fi
    
    echo ""
    read -r -p "確認執行還原? 這將覆蓋目前設定 (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "操作已取消"
        return 1
    fi
    
    log "INFO" "開始還原設定: ${backup_dir}"
    
    # 停止服務
    echo ""
    echo "停止服務中..."
    systemctl stop wg-quick@${WG_IF} 2>/dev/null || true
    systemctl stop warp-netns.service 2>/dev/null || true
    systemctl stop wireguard-warp-healthcheck.timer 2>/dev/null || true
    
    # 還原 WireGuard 設定
    if [[ -f "$backup_dir/${WG_IF}.conf" ]]; then
        cp "$backup_dir/${WG_IF}.conf" "$WG_CONFIG"
        echo "✅ WireGuard 伺服器設定已還原"
    fi
    
    # 還原客戶端設定
    if [[ -d "$backup_dir/clients" ]]; then
        rm -rf "$CLIENTS_DIR"
        mkdir -p "$CLIENTS_DIR"
        cp -r "$backup_dir/clients/"* "$CLIENTS_DIR/" 2>/dev/null || true
        chmod 600 "$CLIENTS_DIR"/*.conf 2>/dev/null || true
        echo "✅ 客戶端設定已還原"
    fi
    
    # 還原 systemd 設定
    if [[ -d "$backup_dir/systemd" ]]; then
        for config in "$backup_dir/systemd"/*; do
            if [[ -f "$config" ]]; then
                local config_name
                config_name=$(basename "$config")
                case "$config_name" in
                    "override.conf")
                        mkdir -p "/etc/systemd/system/wg-quick@${WG_IF}.service.d/"
                        cp "$config" "/etc/systemd/system/wg-quick@${WG_IF}.service.d/"
                        ;;
                    *)
                        cp "$config" "/etc/systemd/system/"
                        ;;
                esac
            fi
        done
        systemctl daemon-reload
        echo "✅ systemd 服務設定已還原"
    fi
    
    # 還原腳本
    if [[ -d "$backup_dir/scripts" ]]; then
        for script in "$backup_dir/scripts"/*; do
            if [[ -f "$script" ]]; then
                local script_name
                script_name=$(basename "$script")
                case "$script_name" in
                    "postup.sh"|"predown.sh")
                        mkdir -p "/etc/wireguard/scripts"
                        cp "$script" "/etc/wireguard/scripts/"
                        chmod +x "/etc/wireguard/scripts/$script_name"
                        ;;
                    *)
                        cp "$script" "/usr/local/bin/"
                        chmod +x "/usr/local/bin/$script_name"
                        ;;
                esac
            fi
        done
        echo "✅ 腳本檔案已還原"
    fi
    
    # 重新啟動服務
    echo ""
    echo "重新啟動服務..."
    systemctl start warp-netns.service
    sleep 3
    systemctl start wg-quick@${WG_IF}
    sleep 2
    systemctl start wireguard-warp-healthcheck.timer
    
    echo ""
    echo "🎉 設定還原完成！"
    log "INFO" "設定還原完成: ${backup_dir}"
    
    # 檢查服務狀態
    echo ""
    echo "檢查服務狀態..."
    if systemctl is-active --quiet wg-quick@${WG_IF} && systemctl is-active --quiet warp-netns.service; then
        echo "✅ 所有服務運行正常"
    else
        echo "⚠️  部分服務可能需要手動檢查"
        echo "建議執行: $0 status"
    fi
}

remove_client() {
    echo "========== 移除客戶端 =========="
    
    if [[ ! -d "$CLIENTS_DIR" ]]; then
        echo "❌ 客戶端目錄不存在"
        return 1
    fi
    
    # 列出現有客戶端
    echo "現有客戶端:"
    local clients=()
    for conf_file in "${CLIENTS_DIR}"/*.conf; do
        if [[ -f "$conf_file" ]]; then
            local client_name
            client_name=$(basename "$conf_file" .conf)
            clients+=("$client_name")
            echo "  ${#clients[@]}) $client_name"
        fi
    done
    
    if [[ ${#clients[@]} -eq 0 ]]; then
        echo "沒有找到客戶端設定檔"
        return 1
    fi
    
    echo ""
    read -r -p "請選擇要移除的客戶端編號 (1-${#clients[@]}): " choice
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ $choice -lt 1 ]] || [[ $choice -gt ${#clients[@]} ]]; then
        echo "❌ 無效選擇"
        return 1
    fi
    
    local client_name="${clients[$((choice-1))]}"
    local client_config="${CLIENTS_DIR}/${client_name}.conf"
    
    echo ""
    echo "準備移除客戶端: $client_name"
    
    # 取得客戶端公鑰
    local client_pubkey
    if [[ -f "$client_config" ]]; then
        client_pubkey=$(grep "^PublicKey = " "$client_config" | cut -d' ' -f3 2>/dev/null || echo "")
        if [[ -n "$client_pubkey" ]]; then
            echo "客戶端公鑰: ${client_pubkey:0:16}...${client_pubkey: -16}"
        fi
    fi
    
    read -r -p "確認移除此客戶端? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "操作已取消"
        return 1
    fi
    
    log "INFO" "移除客戶端: ${client_name}"
    
    # 從 WireGuard 介面移除 peer
    if [[ -n "$client_pubkey" ]]; then
        wg set ${WG_IF} peer "$client_pubkey" remove 2>/dev/null || true
        echo "✅ 已從 WireGuard 介面移除 peer"
    fi
    
    # 從設定檔中移除 peer
    if [[ -f "$WG_CONFIG" ]] && [[ -n "$client_pubkey" ]]; then
        # 建立臨時檔案移除對應的 [Peer] 區段
        awk -v pubkey="$client_pubkey" '
        BEGIN { skip = 0 }
        /^\[Peer\]/ { skip = 0; peer_section = 1; print; next }
        /^PublicKey = / && peer_section { 
            if ($3 == pubkey) { 
                skip = 1; 
                # 移除這行和之前的 [Peer] 行
                getline < "/dev/stdin"  # 跳過下一行
                while (getline > 0 && !/^\[/) { } # 跳到下個區段
                if (/^\[/) print  # 印出下個區段的標題
                next
            } else { 
                peer_section = 0 
            }
        }
        /^\[/ { peer_section = 0 }
        !skip { print }
        ' "$WG_CONFIG" > "${WG_CONFIG}.tmp" && mv "${WG_CONFIG}.tmp" "$WG_CONFIG"
        echo "✅ 已從伺服器設定檔移除 peer"
    fi
    
    # 移除客戶端設定檔
    rm -f "$client_config"
    rm -f "${CLIENTS_DIR}/${client_name}_qr.png" 2>/dev/null || true
    echo "✅ 已移除客戶端設定檔"
    
    echo ""
    echo "🎉 客戶端 ${client_name} 移除完成！"
    log "INFO" "客戶端移除完成: ${client_name}"
}

show_client() {
    echo "========== 顯示客戶端設定 =========="
    
    if [[ ! -d "$CLIENTS_DIR" ]]; then
        echo "❌ 客戶端目錄不存在"
        return 1
    fi
    
    # 列出現有客戶端
    echo "現有客戶端:"
    local clients=()
    for conf_file in "${CLIENTS_DIR}"/*.conf; do
        if [[ -f "$conf_file" ]]; then
            local client_name
            client_name=$(basename "$conf_file" .conf)
            clients+=("$client_name")
            echo "  ${#clients[@]}) $client_name"
        fi
    done
    
    if [[ ${#clients[@]} -eq 0 ]]; then
        echo "沒有找到客戶端設定檔"
        return 1
    fi
    
    echo ""
    read -r -p "請選擇要顯示的客戶端編號 (1-${#clients[@]}): " choice
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ $choice -lt 1 ]] || [[ $choice -gt ${#clients[@]} ]]; then
        echo "❌ 無效選擇"
        return 1
    fi
    
    local client_name="${clients[$((choice-1))]}"
    local client_config="${CLIENTS_DIR}/${client_name}.conf"
    
    echo ""
    echo "========== 客戶端 ${client_name} 設定 =========="
    echo ""
    cat "$client_config"
    echo ""
    
    # 顯示 QR code（如果存在）
    if command -v qrencode >/dev/null 2>&1; then
        echo "QR Code:"
        qrencode -t ansiutf8 < "$client_config"
        echo ""
    fi
    
    echo "設定檔位置: $client_config"
    
    # 提供匯出選項
    read -r -p "是否要匯出 QR code 圖片? (y/N): " export_qr
    if [[ "$export_qr" =~ ^[Yy]$ ]]; then
        if command -v qrencode >/dev/null 2>&1; then
            local qr_file="${CLIENTS_DIR}/${client_name}_qr.png"
            qrencode -t PNG -o "$qr_file" < "$client_config"
            echo "✅ QR code 已匯出: $qr_file"
        else
            echo "❌ qrencode 未安裝，無法匯出 QR code"
        fi
    fi
}

restart_warp() {
    echo "正在重啟 WARP 服務..."
    log "INFO" "手動重啟 WARP 服務"
    systemctl restart warp-netns.service
    sleep 5
    echo "✅ WARP 服務重啟完成"
}

restart_wireguard() {
    echo "正在重啟 WireGuard 服務..."
    log "INFO" "手動重啟 WireGuard 服務"
    systemctl restart wg-quick@${WG_IF}
    sleep 3
    echo "✅ WireGuard 服務重啟完成"
}

restart_all() {
    echo "正在重啟所有服務..."
    log "INFO" "手動重啟所有服務"
    
    systemctl restart warp-netns.service
    sleep 5
    systemctl restart wg-quick@${WG_IF}
    sleep 3
    systemctl restart wireguard-warp-healthcheck.timer
    
    echo "✅ 所有服務重啟完成"
}

show_logs() {
    echo "========== 最近日誌 =========="
    
    echo "WireGuard 服務日誌:"
    journalctl -u wg-quick@${WG_IF} --no-pager -n 15
    
    echo ""
    echo "WARP 服務日誌:"
    journalctl -u warp-netns.service --no-pager -n 15
    
    echo ""
    echo "健康檢查日誌:"
    if [[ -f "/var/log/wireguard-warp-healthcheck.log" ]]; then
        tail -n 15 /var/log/wireguard-warp-healthcheck.log
    else
        echo "無健康檢查日誌"
    fi
    
    echo ""
    echo "管理工具日誌:"
    if [[ -f "$LOG_FILE" ]]; then
        tail -n 10 "$LOG_FILE"
    else
        echo "無管理工具日誌"
    fi
}

add_client() {
    echo "========== 新增 WireGuard 客戶端 =========="
    log "INFO" "開始新增客戶端"
    
    read -r -p "客戶端名稱: " client_name
    
    if [[ -z "$client_name" ]]; then
        echo "❌ 客戶端名稱不能為空"
        return 1
    fi
    
    # 檢查客戶端是否已存在
    if [[ -f "${CLIENTS_DIR}/${client_name}.conf" ]]; then
        echo "❌ 客戶端 ${client_name} 已存在"
        return 1
    fi
    
    # 自動分配 IP
    local last_ip=10
    if [[ -d "$CLIENTS_DIR" ]]; then
        for conf_file in "${CLIENTS_DIR}"/*.conf; do
            if [[ -f "$conf_file" ]]; then
                local client_ip_num
                client_ip_num=$(grep "^Address = " "$conf_file" | cut -d' ' -f3 | cut -d'.' -f4 | cut -d'/' -f1)
                if [[ $client_ip_num -gt $last_ip ]]; then
                    last_ip=$client_ip_num
                fi
            fi
        done
    fi
    
    local new_ip_num=$((last_ip + 1))
    local client_ip="10.66.66.${new_ip_num}/32"
    
    echo "建議的客戶端 IP: $client_ip"
    read -r -p "按 Enter 使用建議 IP，或輸入自訂 IP (格式: 10.66.66.X/32): " custom_ip
    
    if [[ -n "$custom_ip" ]]; then
        client_ip="$custom_ip"
    fi
    
    # 檢查 IP 格式
    if ! [[ "$client_ip" =~ ^10\.66\.66\.[0-9]+/32$ ]]; then
        echo "❌ IP 格式不正確，應為 10.66.66.X/32"
        return 1
    fi
    
    # 檢查 IP 是否已被使用
    if [[ -d "$CLIENTS_DIR" ]]; then
        for conf_file in "${CLIENTS_DIR}"/*.conf; do
            if [[ -f "$conf_file" ]] && grep -q "Address = $client_ip" "$conf_file"; then
                echo "❌ IP $client_ip 已被使用"
                return 1
            fi
        done
    fi
    
    echo ""
    echo "準備新增客戶端:"
    echo "  名稱: $client_name"
    echo "  IP: $client_ip"
    
    read -r -p "確認新增? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "操作已取消"
        return 1
    fi
    
    # 生成密鑰
    local client_private_key
    local client_public_key
    local client_psk
    
    client_private_key=$(wg genkey)
    client_public_key=$(echo "$client_private_key" | wg pubkey)
    client_psk=$(wg genpsk)
    
    # 取得伺服器資訊
    local server_public_key
    local server_ip
    local server_port
    
    server_public_key=$(cat /etc/wireguard/${WG_IF}.pub)
    server_ip=$(timeout 10 curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    server_port=$(grep 'ListenPort' ${WG_CONFIG} | cut -d' ' -f3 2>/dev/null || echo "51820")
    
    # 取得當前 DNS 設定
    local dns_server="1.1.1.1"
    if [[ -f "${CLIENTS_DIR}/client01.conf" ]]; then
        dns_server=$(grep "^DNS = " "${CLIENTS_DIR}/client01.conf" | cut -d' ' -f3 2>/dev/null || echo "1.1.1.1")
    fi
    
    # 新增 peer 到運行中的介面
    wg set ${WG_IF} peer "$client_public_key" preshared-key <(echo "$client_psk") allowed-ips "$client_ip"
    
    # 新增 peer 到設定檔
    cat >> ${WG_CONFIG} <<EOF

[Peer]
PublicKey = ${client_public_key}
PresharedKey = ${client_psk}
AllowedIPs = ${client_ip}
EOF
    
    # 產生客戶端設定檔
    mkdir -p "$CLIENTS_DIR"
    cat > "${CLIENTS_DIR}/${client_name}.conf" <<EOF
[Interface]
PrivateKey = ${client_private_key}
Address = ${client_ip}
DNS = ${dns_server}
MTU = 1280

[Peer]
PublicKey = ${server_public_key}
PresharedKey = ${client_psk}
Endpoint = ${server_ip}:${server_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    
    chmod 600 "${CLIENTS_DIR}/${client_name}.conf"
    
    echo ""
    echo "✅ 客戶端 ${client_name} 新增成功！"
    echo ""
    echo "設定檔位置: ${CLIENTS_DIR}/${client_name}.conf"
    
    log "INFO" "新增客戶端完成: ${client_name} (${client_ip})"
    
    # 顯示 QR code
    if command -v qrencode >/dev/null 2>&1; then
        echo ""
        echo "QR Code:"
        qrencode -t ansiutf8 < "${CLIENTS_DIR}/${client_name}.conf"
        
        # 匯出 QR code 圖片
        qrencode -t PNG -o "${CLIENTS_DIR}/${client_name}_qr.png" < "${CLIENTS_DIR}/${client_name}.conf"
        echo ""
        echo "QR code 圖片已儲存: ${CLIENTS_DIR}/${client_name}_qr.png"
    fi
}

list_clients() {
    echo "========== 客戶端列表 =========="
    
    if [[ ! -d "$CLIENTS_DIR" ]]; then
        echo "客戶端目錄不存在"
        return 1
    fi
    
    local count=0
    echo "名稱                IP 地址              狀態"
    echo "----------------------------------------------------"
    
    for conf_file in "${CLIENTS_DIR}"/*.conf; do
        if [[ -f "$conf_file" ]]; then
            local client_name
            local client_ip
            local client_pubkey
            local status="未知"
            
            client_name=$(basename "$conf_file" .conf)
            client_ip=$(grep "^Address = " "$conf_file" | cut -d' ' -f3 | cut -d'/' -f1)
            
            # 從設定檔取得客戶端公鑰（需要從伺服器設定檔找）
            client_pubkey=$(grep -A 10 "AllowedIPs = ${client_ip}/32" "$WG_CONFIG" | grep "PublicKey = " | cut -d' ' -f3 | head -n1)
            
            # 檢查連線狀態
            if [[ -n "$client_pubkey" ]]; then
                local handshake
                handshake=$(wg show ${WG_IF} latest-handshakes 2>/dev/null | grep "$client_pubkey" | cut -f2)
                if [[ -n "$handshake" && "$handshake" != "0" ]]; then
                    local current_time
                    current_time=$(date +%s)
                    local time_diff=$((current_time - handshake))
                    if [[ $time_diff -lt 300 ]]; then  # 5 分鐘內
                        status="✅ 線上"
                    else
                        status="⚠️  閒置 (${time_diff}s)"
                    fi
                else
                    status="❌ 離線"
                fi
            fi
            
            printf "%-18s  %-18s  %s\n" "$client_name" "$client_ip" "$status"
            count=$((count + 1))
        fi
    done
    
    if [[ $count -eq 0 ]]; then
        echo "沒有找到客戶端設定檔"
    else
        echo "----------------------------------------------------"
        echo "總計: $count 個客戶端"
    fi
}

check_exit_ip() {
    echo "========== 出口 IP 檢查 =========="
    
    echo "檢查中..."
    
    # 伺服器真實 IP（透過預設路由）
    echo -n "伺服器真實 IP: "
    local real_ip
    real_ip=$(timeout 10 curl -s --interface eth0 ifconfig.me 2>/dev/null || timeout 10 curl -s ifconfig.me 2>/dev/null)
    echo "${real_ip:-無法取得}"
    
    # WARP 出口 IP
    echo -n "WARP 出口 IP: "
    local warp_ip
    warp_ip=$(ip netns exec ${WARP_NETNS} timeout 10 curl -s ifconfig.me 2>/dev/null)
    echo "${warp_ip:-無法取得}"
    
    # 比較兩個 IP
    if [[ -n "$real_ip" && -n "$warp_ip" && "$real_ip" != "$warp_ip" ]]; then
        echo "✅ IP 保護正常工作 (真實 IP 已隱藏)"
    elif [[ -n "$real_ip" && -n "$warp_ip" && "$real_ip" == "$warp_ip" ]]; then
        echo "⚠️  警告：WARP 可能未正常工作 (IP 相同)"
    else
        echo "❓ 無法確定 IP 保護狀態"
    fi
    
    # IP 地理位置資訊
    if [[ -n "$warp_ip" ]]; then
        echo ""
        echo "WARP 出口 IP 位置資訊:"
        local location_info
        location_info=$(ip netns exec ${WARP_NETNS} timeout 10 curl -s "http://ip-api.com/json/${warp_ip}?fields=country,regionName,city,isp,org" 2>/dev/null)
        if [[ -n "$location_info" ]]; then
            echo "$location_info" | jq -r '"  國家: " + .country + "\n  地區: " + .regionName + "\n  城市: " + .city + "\n  ISP: " + .isp + "\n  組織: " + .org' 2>/dev/null || echo "  無法解析位置資訊"
        else
            echo "  無法取得位置資訊"
        fi
    fi
}

health_check() {
    echo "========== 手動健康檢查 =========="
    log "INFO" "執行手動健康檢查"
    
    if [[ -x "/usr/local/bin/wireguard-warp-healthcheck.py" ]]; then
        echo "執行健康檢查腳本..."
        /usr/local/bin/wireguard-warp-healthcheck.py
    else
        echo "健康檢查腳本不存在，執行簡化檢查..."
        
        # 簡化的健康檢查
        local issues=0
        
        echo "檢查 WireGuard 服務..."
        if systemctl is-active --quiet wg-quick@${WG_IF}; then
            echo "✅ WireGuard 服務正常"
        else
            echo "❌ WireGuard 服務異常"
            issues=$((issues + 1))
        fi
        
        echo "檢查 WARP 服務..."
        if systemctl is-active --quiet warp-netns.service; then
            echo "✅ WARP 服務正常"
        else
            echo "❌ WARP 服務異常"
            issues=$((issues + 1))
        fi
        
        echo "檢查網路連線..."
        if ip netns exec ${WARP_NETNS} timeout 5 ping -c 1 1.1.1.1 >/dev/null 2>&1; then
            echo "✅ WARP 網路連線正常"
        else
            echo "❌ WARP 網路連線異常"
            issues=$((issues + 1))
        fi
        
        if [[ $issues -eq 0 ]]; then
            echo ""
            echo "🎉 所有檢查通過！系統運行正常"
        else
            echo ""
            echo "⚠️  發現 $issues 個問題，建議執行詳細檢查"
            echo "建議操作："
            echo "  • 查看狀態: $0 status"
            echo "  • 查看日誌: $0 logs"
            echo "  • 重啟服務: $0 restart-all"
        fi
    fi
}

update_warp() {
    echo "========== 更新 WARP 設定 =========="
    log "INFO" "開始更新 WARP 設定"
    
    echo "此功能將重新註冊 WARP 帳戶並更新設定"
    echo "⚠️  警告：這可能會導致短暫的服務中斷"
    echo ""
    
    read -r -p "確認繼續? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "操作已取消"
        return 1
    fi
    
    # 備份現有設定
    local backup_dir="/opt/wireguard-backup/warp-update-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    if [[ -f "/root/wgcf-profile.conf" ]]; then
        cp /root/wgcf-profile.conf "$backup_dir/"
    fi
    if [[ -f "/root/.wgcf-account.toml" ]]; then
        cp /root/.wgcf-account.toml "$backup_dir/"
    fi
    
    echo "已備份現有 WARP 設定到: $backup_dir"
    
    # 停止 WARP 服務
    echo "停止 WARP 服務..."
    systemctl stop warp-netns.service
    
    # 移除舊的帳戶檔案
    rm -f /root/.wgcf-account.toml /root/wgcf-profile.conf
    
    # 重新註冊
    echo "重新註冊 WARP 帳戶..."
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        if timeout 60 wgcf register; then
            echo "✅ WARP 帳戶註冊成功"
            break
        else
            retry_count=$((retry_count + 1))
            echo "⚠️  註冊嘗試 $retry_count/$max_retries 失敗"
            if [[ $retry_count -eq $max_retries ]]; then
                echo "❌ WARP 註冊失敗，恢復備份設定"
                cp "$backup_dir/.wgcf-account.toml" /root/ 2>/dev/null || true
                cp "$backup_dir/wgcf-profile.conf" /root/ 2>/dev/null || true
                systemctl start warp-netns.service
                return 1
            fi
            sleep 5
        fi
    done
    
    # 生成新設定
    echo "生成新的 WARP 設定..."
    if wgcf generate; then
        echo "✅ WARP 設定生成成功"
    else
        echo "❌ WARP 設定生成失敗"
        return 1
    fi
    
    # 重新啟動服務
    echo "重新啟動服務..."
    systemctl start warp-netns.service
    sleep 5
    
    # 驗證
    if ip netns exec ${WARP_NETNS} timeout 10 ping -c 1 1.1.1.1 >/dev/null 2>&1; then
        echo "✅ WARP 更新成功！"
        log "INFO" "WARP 設定更新完成"
        
        # 檢查新的出口 IP
        echo ""
        echo "新的出口 IP:"
        ip netns exec ${WARP_NETNS} timeout 10 curl -s ifconfig.me 2>/dev/null || echo "無法取得"
    else
        echo "❌ WARP 更新後連線異常"
        echo "正在恢復備份設定..."
        
        systemctl stop warp-netns.service
        cp "$backup_dir/.wgcf-account.toml" /root/ 2>/dev/null || true
        cp "$backup_dir/wgcf-profile.conf" /root/ 2>/dev/null || true
        systemctl start warp-netns.service
        
        echo "已恢復原設定"
        log "ERROR" "WARP 更新失敗，已恢復備份"
    fi
}

# 主程式邏輯
case "${1:-help}" in
    "status")
        show_status
        ;;
    "test")
        test_connectivity
        ;;
    "change-dns")
        change_dns
        ;;
    "backup-config")
        backup_config
        ;;
    "restore-config")
        restore_config "$@"
        ;;
    "restart-warp")
        restart_warp
        ;;
    "restart-wg")
        restart_wireguard
        ;;
    "restart-all")
        restart_all
        ;;
    "logs")
        show_logs
        ;;
    "add-client")
        add_client
        ;;
    "list-clients")
        list_clients
        ;;
    "remove-client")
        remove_client
        ;;
    "show-client")
        show_client
        ;;
    "ip-check")
        check_exit_ip
        ;;
    "health-check")
        health_check
        ;;
    "update-warp")
        update_warp
        ;;
    "help"|*)
        show_help
        ;;
esac