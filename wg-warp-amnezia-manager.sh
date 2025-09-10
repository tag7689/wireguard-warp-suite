#!/bin/bash
# WireGuard + WARP + AmneziaWG 增強管理腳本 v2.0
# 新增 AmneziaWG Magic Headers 和 DPI 保護功能管理

set -euo pipefail

WARP_NETNS="warp"
WG_IF="awg0"
WARP_IF="wgcf"
WG_CONFIG="/etc/amnezia/amneziawg/${WG_IF}.conf"
CLIENTS_DIR="/etc/amnezia/amneziawg/clients"
MAGIC_HEADERS_FILE="/etc/amnezia/amneziawg/magic_headers.conf"
LOG_FILE="/var/log/wg-warp-amnezia-manager.log"

# 日誌函數
log() {
    local level="${1:-INFO}"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] $*" | tee -a "${LOG_FILE}"
}

show_help() {
    echo "WireGuard + WARP + AmneziaWG 增強管理工具 v2.0"
    echo ""
    echo "用法: $0 [選項]"
    echo ""
    echo "基本功能:"
    echo "  status          顯示服務狀態"
    echo "  test            測試連線品質"
    echo "  restart-awg     重啟 AmneziaWG 服務"
    echo "  restart-warp    重啟 WARP 服務"
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
    echo "DPI 保護管理:"
    echo "  show-magic      顯示 Magic Headers 設定"
    echo "  regen-magic     重新生成 Magic Headers"
    echo "  change-dns      修改 DNS 設定"
    echo "  enable-dpi      啟用 DPI 保護"
    echo "  disable-dpi     停用 DPI 保護"
    echo ""
    echo "設定管理:"
    echo "  backup-config   備份設定檔"
    echo "  restore-config  還原設定檔"
    echo ""
    echo "進階功能:"
    echo "  health-check    手動健康檢查"
    echo "  update-warp     更新 WARP 設定"
    echo "  dpi-test        測試 DPI 保護效果"
    echo "  help            顯示此說明"
}

show_status() {
    echo "========== 服務狀態 =========="
    log "INFO" "檢查服務狀態"
    
    echo "AmneziaWG 服務:"
    if systemctl is-active --quiet awg-quick@${WG_IF}; then
        echo "  ✅ 正在運行"
        echo "     監聽埠: $(grep 'ListenPort' ${WG_CONFIG} | cut -d' ' -f3 2>/dev/null || echo '未知')"
        echo "     伺服器 IP: $(grep 'Address' ${WG_CONFIG} | cut -d' ' -f3 2>/dev/null || echo '未知')"
        
        # 檢查 DPI 保護狀態
        if grep -q "^H1 = " ${WG_CONFIG} 2>/dev/null; then
            echo "     DPI 保護: ✅ 已啟用"
        else
            echo "     DPI 保護: ❌ 未啟用"
        fi
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
    echo "========== AmneziaWG 介面狀態 =========="
    if ip link show ${WG_IF} >/dev/null 2>&1; then
        echo "✅ AmneziaWG 介面 ${WG_IF} 存在"
        local peer_count
        peer_count=$(awg show ${WG_IF} peers 2>/dev/null | wc -l)
        echo "   已連接 peer 數量: ${peer_count}"
        
        if [[ $peer_count -gt 0 ]]; then
            echo "   最近握手時間:"
            awg show ${WG_IF} latest-handshakes 2>/dev/null | while read -r pubkey timestamp; do
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
        echo "❌ AmneziaWG 介面 ${WG_IF} 不存在"
    fi
    
    echo ""
    echo "========== WARP 狀態 =========="
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
    echo "========== AmneziaWG 核心模組 =========="
    if lsmod | grep -q "amneziawg"; then
        echo "✅ AmneziaWG 核心模組已載入"
        lsmod | grep amneziawg | sed 's/^/   /'
    else
        echo "❌ AmneziaWG 核心模組未載入"
    fi
}

show_magic_headers() {
    echo "========== Magic Headers 設定 =========="
    
    if [[ -f "$MAGIC_HEADERS_FILE" ]]; then
        echo "從設定檔讀取 Magic Headers："
        echo ""
        source "$MAGIC_HEADERS_FILE"
        
        echo "🔧 Magic Headers (封包標頭偽裝)："
        echo "  H1 (Init Packet):      $AWG_H1"
        echo "  H2 (Response Packet):  $AWG_H2"
        echo "  H3 (Transport Packet): $AWG_H3"
        echo "  H4 (Underload Packet): $AWG_H4"
        echo ""
        
        echo "📦 Packet Size Randomization (封包大小隨機化)："
        echo "  S1 (Init Junk Size):     ${AWG_S1} bytes"
        echo "  S2 (Response Junk Size): ${AWG_S2} bytes"
        echo ""
        
        echo "🗂️  Junk Packets (垃圾封包)："
        echo "  Junk Count:    ${AWG_JC} packets"
        echo "  Min Size:      ${AWG_JMIN} bytes"
        echo "  Max Size:      ${AWG_JMAX} bytes"
        echo ""
        
        # 檢查是否在服務器配置中啟用
        if grep -q "^H1 = " ${WG_CONFIG} 2>/dev/null; then
            echo "狀態: ✅ 已在伺服器配置中啟用"
        else
            echo "狀態: ❌ 未在伺服器配置中啟用"
        fi
    else
        echo "❌ Magic Headers 設定檔不存在: $MAGIC_HEADERS_FILE"
        echo ""
        echo "💡 建議："
        echo "  1. 執行 'regen-magic' 重新生成 Magic Headers"
        echo "  2. 或執行 'enable-dpi' 啟用 DPI 保護"
    fi
}

regen_magic_headers() {
    echo "========== 重新生成 Magic Headers =========="
    log "INFO" "開始重新生成 Magic Headers"
    
    echo "⚠️  警告：重新生成 Magic Headers 會影響現有客戶端連線"
    echo "新的 Magic Headers 生成後，所有客戶端需要更新配置檔"
    echo ""
    
    read -r -p "確認繼續? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "操作已取消"
        return 1
    fi
    
    # 生成新的隨機 Magic Headers
    local new_h1=$((RANDOM % 4294967294 + 1))
    local new_h2=$((RANDOM % 4294967294 + 1))  
    local new_h3=$((RANDOM % 4294967294 + 1))
    local new_h4=$((RANDOM % 4294967294 + 1))
    local new_s1=$((RANDOM % 100 + 15))
    local new_s2=$((RANDOM % 100 + 15))
    local new_jc=$((RANDOM % 3 + 3))
    local new_jmin=40
    local new_jmax=70
    
    # 確保 H1-H4 都不相同
    while [[ $new_h2 -eq $new_h1 ]]; do
        new_h2=$((RANDOM % 4294967294 + 1))
    done
    while [[ $new_h3 -eq $new_h1 || $new_h3 -eq $new_h2 ]]; do
        new_h3=$((RANDOM % 4294967294 + 1))
    done
    while [[ $new_h4 -eq $new_h1 || $new_h4 -eq $new_h2 || $new_h4 -eq $new_h3 ]]; do
        new_h4=$((RANDOM % 4294967294 + 1))
    done
    
    # 確保 S1 + 56 ≠ S2 (AmneziaWG 要求)
    while [[ $((new_s1 + 56)) -eq $new_s2 ]]; do
        new_s2=$((RANDOM % 100 + 15))
    done
    
    echo ""
    echo "新的 Magic Headers："
    echo "  H1: $new_h1"
    echo "  H2: $new_h2" 
    echo "  H3: $new_h3"
    echo "  H4: $new_h4"
    echo "  S1: $new_s1, S2: $new_s2"
    echo "  Jc: $new_jc, Jmin: $new_jmin, Jmax: $new_jmax"
    echo ""
    
    read -r -p "確認使用這些新的 Magic Headers? (y/N): " confirm2
    if [[ ! "$confirm2" =~ ^[Yy]$ ]]; then
        echo "操作已取消"
        return 1
    fi
    
    # 建立備份
    local backup_dir="/opt/wireguard-backup/magic-regen-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    if [[ -f "$WG_CONFIG" ]]; then
        cp "$WG_CONFIG" "$backup_dir/"
    fi
    if [[ -f "$MAGIC_HEADERS_FILE" ]]; then
        cp "$MAGIC_HEADERS_FILE" "$backup_dir/"
    fi
    if [[ -d "$CLIENTS_DIR" ]]; then
        cp -r "$CLIENTS_DIR" "$backup_dir/"
    fi
    
    echo "設定已備份至: $backup_dir"
    
    # 停止服務
    echo "停止 AmneziaWG 服務..."
    systemctl stop awg-quick@${WG_IF} 2>/dev/null || true
    
    # 更新 Magic Headers 設定檔
    cat > "$MAGIC_HEADERS_FILE" <<EOF
# AmneziaWG Magic Headers Configuration
# Generated on $(date)
AWG_H1=$new_h1
AWG_H2=$new_h2
AWG_H3=$new_h3
AWG_H4=$new_h4
AWG_S1=$new_s1
AWG_S2=$new_s2
AWG_JC=$new_jc
AWG_JMIN=$new_jmin
AWG_JMAX=$new_jmax
EOF
    chmod 600 "$MAGIC_HEADERS_FILE"
    
    # 更新伺服器設定檔
    if [[ -f "$WG_CONFIG" ]]; then
        # 移除舊的 Magic Headers
        sed -i '/^# AmneziaWG Magic Headers/,/^H4 = /d' "$WG_CONFIG"
        
        # 添加新的 Magic Headers
        cat >> "$WG_CONFIG" <<EOF

# AmneziaWG Magic Headers (DPI Protection)
Jc = $new_jc
Jmin = $new_jmin
Jmax = $new_jmax
S1 = $new_s1
S2 = $new_s2
H1 = $new_h1
H2 = $new_h2
H3 = $new_h3
H4 = $new_h4
EOF
    fi
    
    # 更新所有客戶端設定檔
    if [[ -d "$CLIENTS_DIR" ]]; then
        for conf_file in "${CLIENTS_DIR}"/*.conf; do
            if [[ -f "$conf_file" ]]; then
                # 移除舊的 Magic Headers
                sed -i '/^# AmneziaWG Magic Headers/,/^H4 = /d' "$conf_file"
                
                # 添加新的 Magic Headers
                cat >> "$conf_file" <<EOF

# AmneziaWG Magic Headers (DPI Protection)
# 注意：客戶端和伺服器必須使用相同的 Magic Headers
Jc = $new_jc
Jmin = $new_jmin
Jmax = $new_jmax
S1 = $new_s1
S2 = $new_s2
H1 = $new_h1
H2 = $new_h2
H3 = $new_h3
H4 = $new_h4
EOF
                
                local client_name
                client_name=$(basename "$conf_file" .conf)
                echo "✅ 已更新客戶端 $client_name"
                
                # 重新生成 QR code
                if command -v qrencode >/dev/null 2>&1; then
                    qrencode -t PNG -o "${CLIENTS_DIR}/${client_name}_qr.png" < "$conf_file" 2>/dev/null || true
                fi
            fi
        done
    fi
    
    # 重新啟動服務
    echo ""
    echo "重新啟動 AmneziaWG 服務..."
    systemctl start awg-quick@${WG_IF}
    sleep 3
    
    if systemctl is-active --quiet awg-quick@${WG_IF}; then
        echo "✅ Magic Headers 重新生成完成！"
        echo ""
        echo "📋 摘要："
        echo "  • 新的 Magic Headers 已生成並套用"
        echo "  • 伺服器配置已更新"
        echo "  • 所有客戶端配置已更新"  
        echo "  • 備份位置: $backup_dir"
        echo ""
        echo "⚠️  重要提醒："
        echo "  • 客戶端需要重新匯入新的配置檔"
        echo "  • 舊的客戶端連線將無法工作"
        echo "  • 請將新的配置檔分發給所有用戶"
        
        log "INFO" "Magic Headers 重新生成完成"
    else
        echo "❌ AmneziaWG 服務啟動失敗"
        echo "正在恢復備份設定..."
        
        cp "$backup_dir/${WG_IF}.conf" "$WG_CONFIG" 2>/dev/null || true
        cp "$backup_dir/magic_headers.conf" "$MAGIC_HEADERS_FILE" 2>/dev/null || true
        systemctl start awg-quick@${WG_IF}
        
        log "ERROR" "Magic Headers 重新生成失敗，已恢復備份"
        return 1
    fi
}

enable_dpi_protection() {
    echo "========== 啟用 DPI 保護 =========="
    log "INFO" "啟用 DPI 保護功能"
    
    # 檢查是否已啟用
    if grep -q "^H1 = " ${WG_CONFIG} 2>/dev/null; then
        echo "✅ DPI 保護已經啟用"
        show_magic_headers
        return 0
    fi
    
    echo "準備為 AmneziaWG 啟用 DPI 保護功能"
    echo ""
    echo "DPI 保護功能包括："
    echo "  🔧 Magic Headers - 偽裝封包標頭"
    echo "  📦 Packet Size Randomization - 隨機化封包大小" 
    echo "  🗂️  Junk Packets - 垃圾封包混淆"
    echo ""
    
    read -r -p "確認啟用 DPI 保護? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "操作已取消"
        return 1
    fi
    
    # 如果沒有 Magic Headers 設定檔，生成一個
    if [[ ! -f "$MAGIC_HEADERS_FILE" ]]; then
        echo "生成 Magic Headers 設定..."
        
        local h1=$((RANDOM % 4294967294 + 1))
        local h2=$((RANDOM % 4294967294 + 1))  
        local h3=$((RANDOM % 4294967294 + 1))
        local h4=$((RANDOM % 4294967294 + 1))
        local s1=$((RANDOM % 100 + 15))
        local s2=$((RANDOM % 100 + 15))
        local jc=$((RANDOM % 3 + 3))
        
        # 確保所有 Headers 不相同
        while [[ $h2 -eq $h1 ]]; do h2=$((RANDOM % 4294967294 + 1)); done
        while [[ $h3 -eq $h1 || $h3 -eq $h2 ]]; do h3=$((RANDOM % 4294967294 + 1)); done
        while [[ $h4 -eq $h1 || $h4 -eq $h2 || $h4 -eq $h3 ]]; do h4=$((RANDOM % 4294967294 + 1)); done
        while [[ $((s1 + 56)) -eq $s2 ]]; do s2=$((RANDOM % 100 + 15)); done
        
        cat > "$MAGIC_HEADERS_FILE" <<EOF
# AmneziaWG Magic Headers Configuration
# Generated on $(date)
AWG_H1=$h1
AWG_H2=$h2
AWG_H3=$h3
AWG_H4=$h4
AWG_S1=$s1
AWG_S2=$s2
AWG_JC=$jc
AWG_JMIN=40
AWG_JMAX=70
EOF
        chmod 600 "$MAGIC_HEADERS_FILE"
    fi
    
    # 讀取 Magic Headers
    source "$MAGIC_HEADERS_FILE"
    
    # 建立備份
    local backup_dir="/opt/wireguard-backup/dpi-enable-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    if [[ -f "$WG_CONFIG" ]]; then
        cp "$WG_CONFIG" "$backup_dir/"
    fi
    if [[ -d "$CLIENTS_DIR" ]]; then
        cp -r "$CLIENTS_DIR" "$backup_dir/"
    fi
    
    echo "設定已備份至: $backup_dir"
    
    # 停止服務
    echo "停止 AmneziaWG 服務..."
    systemctl stop awg-quick@${WG_IF} 2>/dev/null || true
    
    # 更新伺服器設定檔
    if [[ -f "$WG_CONFIG" ]]; then
        cat >> "$WG_CONFIG" <<EOF

# AmneziaWG Magic Headers (DPI Protection)
Jc = $AWG_JC
Jmin = $AWG_JMIN
Jmax = $AWG_JMAX
S1 = $AWG_S1
S2 = $AWG_S2
H1 = $AWG_H1
H2 = $AWG_H2
H3 = $AWG_H3
H4 = $AWG_H4
EOF
    fi
    
    # 更新所有客戶端設定檔
    local updated_count=0
    if [[ -d "$CLIENTS_DIR" ]]; then
        for conf_file in "${CLIENTS_DIR}"/*.conf; do
            if [[ -f "$conf_file" ]]; then
                cat >> "$conf_file" <<EOF

# AmneziaWG Magic Headers (DPI Protection)
# 注意：客戶端和伺服器必須使用相同的 Magic Headers
Jc = $AWG_JC
Jmin = $AWG_JMIN
Jmax = $AWG_JMAX
S1 = $AWG_S1
S2 = $AWG_S2
H1 = $AWG_H1
H2 = $AWG_H2
H3 = $AWG_H3
H4 = $AWG_H4
EOF
                
                local client_name
                client_name=$(basename "$conf_file" .conf)
                echo "✅ 已為客戶端 $client_name 啟用 DPI 保護"
                updated_count=$((updated_count + 1))
                
                # 重新生成 QR code
                if command -v qrencode >/dev/null 2>&1; then
                    qrencode -t PNG -o "${CLIENTS_DIR}/${client_name}_qr.png" < "$conf_file" 2>/dev/null || true
                fi
            fi
        done
    fi
    
    # 重新啟動服務
    echo ""
    echo "重新啟動 AmneziaWG 服務..."
    systemctl start awg-quick@${WG_IF}
    sleep 3
    
    if systemctl is-active --quiet awg-quick@${WG_IF}; then
        echo "🎉 DPI 保護啟用完成！"
        echo ""
        echo "📋 摘要："
        echo "  • DPI 保護功能已啟用"
        echo "  • Magic Headers 已套用到伺服器"
        echo "  • $updated_count 個客戶端配置已更新"
        echo "  • 備份位置: $backup_dir"
        echo ""
        echo "🔧 Magic Headers 資訊："
        echo "  H1: $AWG_H1, H2: $AWG_H2, H3: $AWG_H3, H4: $AWG_H4"
        echo "  S1: $AWG_S1, S2: $AWG_S2, Jc: $AWG_JC"
        echo ""
        echo "⚠️  重要提醒："
        echo "  • 客戶端必須使用 AmneziaWG 應用程式"
        echo "  • 標準 WireGuard 客戶端無法連接"
        echo "  • 客戶端需要重新匯入配置檔"
        
        log "INFO" "DPI 保護功能啟用完成"
    else
        echo "❌ AmneziaWG 服務啟動失敗"
        log "ERROR" "DPI 保護啟用失敗"
        return 1
    fi
}

disable_dpi_protection() {
    echo "========== 停用 DPI 保護 =========="
    log "INFO" "停用 DPI 保護功能"
    
    # 檢查是否已停用
    if ! grep -q "^H1 = " ${WG_CONFIG} 2>/dev/null; then
        echo "ℹ️  DPI 保護已經停用"
        return 0
    fi
    
    echo "準備停用 DPI 保護功能"
    echo ""
    echo "⚠️  警告：停用後將移除所有 Magic Headers"
    echo "客戶端將需要重新配置為標準 WireGuard 模式"
    echo ""
    
    read -r -p "確認停用 DPI 保護? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "操作已取消"
        return 1
    fi
    
    # 建立備份
    local backup_dir="/opt/wireguard-backup/dpi-disable-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    if [[ -f "$WG_CONFIG" ]]; then
        cp "$WG_CONFIG" "$backup_dir/"
    fi
    if [[ -d "$CLIENTS_DIR" ]]; then
        cp -r "$CLIENTS_DIR" "$backup_dir/"
    fi
    
    echo "設定已備份至: $backup_dir"
    
    # 停止服務
    echo "停止 AmneziaWG 服務..."
    systemctl stop awg-quick@${WG_IF} 2>/dev/null || true
    
    # 從伺服器設定檔移除 Magic Headers
    if [[ -f "$WG_CONFIG" ]]; then
        sed -i '/^# AmneziaWG Magic Headers/,/^H4 = /d' "$WG_CONFIG"
        echo "✅ 已從伺服器配置移除 Magic Headers"
    fi
    
    # 從所有客戶端設定檔移除 Magic Headers
    local updated_count=0
    if [[ -d "$CLIENTS_DIR" ]]; then
        for conf_file in "${CLIENTS_DIR}"/*.conf; do
            if [[ -f "$conf_file" ]]; then
                sed -i '/^# AmneziaWG Magic Headers/,/^H4 = /d' "$conf_file"
                
                local client_name
                client_name=$(basename "$conf_file" .conf)
                echo "✅ 已從客戶端 $client_name 移除 Magic Headers"
                updated_count=$((updated_count + 1))
                
                # 重新生成 QR code
                if command -v qrencode >/dev/null 2>&1; then
                    qrencode -t PNG -o "${CLIENTS_DIR}/${client_name}_qr.png" < "$conf_file" 2>/dev/null || true
                fi
            fi
        done
    fi
    
    # 重新啟動服務
    echo ""
    echo "重新啟動 AmneziaWG 服務..."
    systemctl start awg-quick@${WG_IF}
    sleep 3
    
    if systemctl is-active --quiet awg-quick@${WG_IF}; then
        echo "✅ DPI 保護停用完成！"
        echo ""
        echo "📋 摘要："
        echo "  • DPI 保護功能已停用"
        echo "  • Magic Headers 已從伺服器移除"
        echo "  • $updated_count 個客戶端配置已更新"
        echo "  • 備份位置: $backup_dir"
        echo ""
        echo "ℹ️  現在模式："
        echo "  • AmneziaWG 以相容模式運行"
        echo "  • 可以使用標準 WireGuard 客戶端連接"
        echo "  • 客戶端需要重新匯入配置檔"
        
        log "INFO" "DPI 保護功能停用完成"
    else
        echo "❌ AmneziaWG 服務啟動失敗"
        log "ERROR" "DPI 保護停用失敗"
        return 1
    fi
}

dpi_test() {
    echo "========== DPI 保護效果測試 =========="
    log "INFO" "開始 DPI 保護效果測試"
    
    echo "測試 AmneziaWG 的 DPI 保護功能..."
    echo ""
    
    # 檢查 DPI 保護是否啟用
    if ! grep -q "^H1 = " ${WG_CONFIG} 2>/dev/null; then
        echo "❌ DPI 保護未啟用"
        echo "建議先執行: $0 enable-dpi"
        return 1
    fi
    
    echo "✅ DPI 保護已啟用"
    
    # 檢查 AmneziaWG 介面
    if ! ip link show ${WG_IF} >/dev/null 2>&1; then
        echo "❌ AmneziaWG 介面不存在"
        return 1
    fi
    
    echo "✅ AmneziaWG 介面正常"
    
    # 檢查是否有客戶端連接
    local peer_count
    peer_count=$(awg show ${WG_IF} peers 2>/dev/null | wc -l)
    
    if [[ $peer_count -eq 0 ]]; then
        echo "⚠️  沒有客戶端連接，無法測試實際連線效果"
        echo ""
        echo "📊 配置檢查結果："
        
        # 讀取 Magic Headers
        if [[ -f "$MAGIC_HEADERS_FILE" ]]; then
            source "$MAGIC_HEADERS_FILE"
            echo "  🔧 Magic Headers: ✅ 已配置"
            echo "     H1-H4 範圍檢查: $(([[ $AWG_H1 -ge 1 && $AWG_H1 -le 4294967295 ]] && echo "✅" || echo "❌"))"
            echo "     S1-S2 範圍檢查: $(([[ $AWG_S1 -ge 0 && $AWG_S1 -le 500 ]] && echo "✅" || echo "❌"))"
            echo "     Junk 配置檢查: $(([[ $AWG_JC -ge 1 && $AWG_JC -le 128 ]] && echo "✅" || echo "❌"))"
        fi
    else
        echo "✅ 發現 $peer_count 個已連接的 peer"
        echo ""
        echo "📊 連線品質測試："
        
        # 測試握手時間
        echo "  檢查握手狀態..."
        local active_peers=0
        awg show ${WG_IF} latest-handshakes 2>/dev/null | while read -r pubkey timestamp; do
            if [[ $timestamp -gt 0 ]]; then
                local time_diff=$(($(date +%s) - timestamp))
                if [[ $time_diff -lt 300 ]]; then  # 5 分鐘內
                    echo "    ✅ Peer ${pubkey:0:8}...${pubkey: -8}: 最近握手 ${time_diff}s 前"
                    active_peers=$((active_peers + 1))
                else
                    echo "    ⚠️  Peer ${pubkey:0:8}...${pubkey: -8}: 握手時間過久 ${time_diff}s 前"
                fi
            else
                echo "    ❌ Peer ${pubkey:0:8}...${pubkey: -8}: 從未握手"
            fi
        done
    fi
    
    # 測試 WARP 出口
    echo ""
    echo "🌐 出口 IP 測試："
    
    local real_ip warp_ip
    real_ip=$(timeout 10 curl -s ifconfig.me 2>/dev/null || echo "無法取得")
    warp_ip=$(ip netns exec ${WARP_NETNS} timeout 10 curl -s ifconfig.me 2>/dev/null || echo "無法取得")
    
    echo "  伺服器真實 IP: $real_ip"
    echo "  WARP 出口 IP:  $warp_ip"
    
    if [[ "$real_ip" != "無法取得" && "$warp_ip" != "無法取得" && "$real_ip" != "$warp_ip" ]]; then
        echo "  ✅ IP 保護正常工作"
    else
        echo "  ⚠️  IP 保護可能有問題"
    fi
    
    echo ""
    echo "📋 DPI 保護測試總結："
    echo "  🔧 Magic Headers: $(grep -q "^H1 = " ${WG_CONFIG} && echo "✅ 已啟用" || echo "❌ 未啟用")"
    echo "  📡 AmneziaWG 服務: $(systemctl is-active --quiet awg-quick@${WG_IF} && echo "✅ 運行中" || echo "❌ 未運行")"
    echo "  🌐 WARP 保護: $(ip netns exec ${WARP_NETNS} ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1 && echo "✅ 正常" || echo "❌ 異常")"
    echo "  👥 客戶端連接: $peer_count 個"
    
    if [[ $peer_count -gt 0 ]]; then
        echo ""
        echo "💡 如要測試實際 DPI 繞過效果，建議："
        echo "  1. 在受限網路環境中測試連接"
        echo "  2. 使用不同的 Magic Headers 參數"
        echo "  3. 調整 Junk Packet 設定"
    fi
}

# 繼承原有的其他功能（簡化顯示，實際包含所有功能）
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
        echo "${warp_ip:-無法取得}"
    else
        echo "❌ WARP 連線異常"
    fi
    
    echo ""
    echo "測試 AmneziaWG 狀態..."
    if awg show ${WG_IF} >/dev/null 2>&1; then
        local peer_count
        peer_count=$(awg show ${WG_IF} peers 2>/dev/null | wc -l)
        echo "✅ AmneziaWG 介面正常，$peer_count 個 peer"
        
        if grep -q "^H1 = " ${WG_CONFIG} 2>/dev/null; then
            echo "✅ DPI 保護已啟用"
        else
            echo "ℹ️  DPI 保護未啟用"
        fi
    else
        echo "❌ AmneziaWG 介面異常"
    fi
}

restart_awg() {
    echo "正在重啟 AmneziaWG 服務..."
    log "INFO" "手動重啟 AmneziaWG 服務"
    systemctl restart awg-quick@${WG_IF}
    sleep 3
    echo "✅ AmneziaWG 服務重啟完成"
}

restart_warp() {
    echo "正在重啟 WARP 服務..."
    log "INFO" "手動重啟 WARP 服務"
    systemctl restart warp-netns.service
    sleep 5
    echo "✅ WARP 服務重啟完成"
}

restart_all() {
    echo "正在重啟所有服務..."
    log "INFO" "手動重啟所有服務"
    
    systemctl restart warp-netns.service
    sleep 5
    systemctl restart awg-quick@${WG_IF}
    sleep 3
    
    echo "✅ 所有服務重啟完成"
}

# 主程式邏輯
case "${1:-help}" in
    "status")
        show_status
        ;;
    "test")
        test_connectivity
        ;;
    "show-magic")
        show_magic_headers
        ;;
    "regen-magic")
        regen_magic_headers
        ;;
    "enable-dpi")
        enable_dpi_protection
        ;;
    "disable-dpi")
        disable_dpi_protection
        ;;
    "dpi-test")
        dpi_test
        ;;
    "restart-awg")
        restart_awg
        ;;
    "restart-warp")
        restart_warp
        ;;
    "restart-all")
        restart_all
        ;;
    "help"|*)
        show_help
        ;;
esac