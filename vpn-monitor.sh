#!/bin/bash
# WireGuard + Shadowsocks 健康監控腳本

LOG_FILE="/var/log/vpn-monitor.log"
ALERT_EMAIL="your-email@example.com"
TELEGRAM_BOT_TOKEN="your_bot_token"
TELEGRAM_CHAT_ID="your_chat_id"
WG_IF="awg0"

# 日誌函數
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Telegram 通知
send_telegram_alert() {
    local message="🚨 VPN Alert: $1"
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_CHAT_ID}" \
        -d text="${message}" >/dev/null 2>&1
}

# 檢查 WireGuard 狀態
check_wireguard() {
    if systemctl is-active --quiet wg-quick@${WG_IF}; then
        log_message "✅ WireGuard 運行正常"
        
        # 檢查連接數
        local peers=$(wg show $WG_IF peers 2>/dev/null | wc -l)
        log_message "📊 活躍連接數: $peers"
        
        # 檢查流量
        local rx_bytes=$(wg show $WG_IF transfer | awk '{print $2}' | head -n1)
        local tx_bytes=$(wg show $WG_IF transfer | awk '{print $3}' | head -n1)
        log_message "📈 流量統計: RX=$rx_bytes, TX=$tx_bytes"
        
        return 0
    else
        log_message "❌ WireGuard 服務異常"
        systemctl restart wg-quick@${WG_IF}
        sleep 5
        
        if systemctl is-active --quiet wg-quick@${WG_IF}; then
            log_message "✅ WireGuard 自動重啟成功"
            send_telegram_alert "WireGuard 服務已自動重啟"
        else
            log_message "❌ WireGuard 重啟失敗"
            send_telegram_alert "WireGuard 服務重啟失敗，需要人工介入"
            return 1
        fi
    fi
}

# 檢查 Shadowsocks 狀態
check_shadowsocks() {
    if snap services shadowsocks-rust.ssserver-daemon 2>/dev/null | grep -q "active"; then
        log_message "✅ Shadowsocks 運行正常"
        
        # 檢查端口監聽
        local ss_port=$(ss -tulpn | grep :8388 | wc -l)
        if [ $ss_port -gt 0 ]; then
            log_message "✅ Shadowsocks 端口監聽正常"
        else
            log_message "⚠️ Shadowsocks 端口未監聽"
        fi
        
        return 0
    else
        log_message "❌ Shadowsocks 服務異常"
        snap restart shadowsocks-rust.ssserver-daemon
        sleep 5
        
        if snap services shadowsocks-rust.ssserver-daemon | grep -q "active"; then
            log_message "✅ Shadowsocks 自動重啟成功"
            send_telegram_alert "Shadowsocks 服務已自動重啟"
        else
            log_message "❌ Shadowsocks 重啟失敗"
            send_telegram_alert "Shadowsocks 服務重啟失敗，需要人工介入"
            return 1
        fi
    fi
}

# 檢查系統資源
check_resources() {
    # CPU 使用率
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    log_message "💻 CPU 使用率: ${cpu_usage}%"
    
    # 記憶體使用
    local mem_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
    log_message "🧠 記憶體使用率: ${mem_usage}%"
    
    # 磁碟空間
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    log_message "💾 磁碟使用率: ${disk_usage}%"
    
    # 高使用率警告
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        send_telegram_alert "CPU 使用率過高: ${cpu_usage}%"
    fi
    
    if (( $(echo "$mem_usage > 85" | bc -l) )); then
        send_telegram_alert "記憶體使用率過高: ${mem_usage}%"
    fi
    
    if [ $disk_usage -gt 90 ]; then
        send_telegram_alert "磁碟空間不足: ${disk_usage}%"
    fi
}

# 網絡連通性測試
check_connectivity() {
    # 測試外網連通性
    if ping -c 3 8.8.8.8 >/dev/null 2>&1; then
        log_message "🌐 外網連通正常"
    else
        log_message "❌ 外網連通異常"
        send_telegram_alert "伺服器外網連通異常"
    fi
    
    # 測試 DNS 解析
    if nslookup google.com >/dev/null 2>&1; then
        log_message "🔍 DNS 解析正常"
    else
        log_message "❌ DNS 解析異常"
    fi
}

# 生成狀態報告
generate_report() {
    log_message "📋 === VPN 系統狀態報告 ==="
    check_wireguard
    check_shadowsocks
    check_resources
    check_connectivity
    log_message "📋 === 報告結束 ==="
    
    # 清理舊日誌 (保留 7 天)
    find /var/log -name "vpn-monitor.log*" -mtime +7 -delete
}

# 主函數
main() {
    # 確保日誌目錄存在
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # 執行檢查
    generate_report
    
    # 如果是每日報告時間 (每天 09:00)，發送完整報告
    if [ "$(date +%H:%M)" = "09:00" ]; then
        local report=$(tail -n 20 "$LOG_FILE")
        send_telegram_alert "每日狀態報告:\n$report"
    fi
}

# 檢查依賴
command -v bc >/dev/null || { log_message "需要安裝 bc: apt install bc"; exit 1; }

# 執行監控
main