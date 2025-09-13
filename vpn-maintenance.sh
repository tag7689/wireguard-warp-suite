#!/bin/bash
# 自動維護和優化腳本

SCRIPT_DIR="/usr/local/bin/vpn-maintenance"
LOG_DIR="/var/log/vpn-maintenance"
DATE=$(date +%Y%m%d)

# 創建目錄
setup_directories() {
    mkdir -p "$SCRIPT_DIR" "$LOG_DIR"
}

# 系統更新和安全補丁
update_system() {
    echo "🔄 系統更新中..."
    apt update -qq
    apt upgrade -y -qq
    apt autoremove -y -qq
    snap refresh
    echo "✅ 系統更新完成" | tee -a "$LOG_DIR/maintenance_$DATE.log"
}

# 日誌清理
cleanup_logs() {
    echo "🧹 清理舊日誌..."
    
    # 清理 WireGuard 日誌
    journalctl --rotate
    journalctl --vacuum-time=7d
    
    # 清理自訂日誌
    find /var/log -name "*.log" -mtime +7 -delete
    find /var/log -name "*.log.*" -mtime +7 -delete
    
    # 清理備份文件
    find /etc/wireguard/backup -name "*.json" -mtime +30 -delete
    find /etc/wireguard/backup -name "*.conf" -mtime +30 -delete
    
    echo "✅ 日誌清理完成"
}

# 效能測試
performance_test() {
    echo "📊 執行效能測試..."
    
    # 測試網路延遲
    local ping_result=$(ping -c 4 8.8.8.8 | tail -1 | awk -F '/' '{print $5}')
    echo "網路延遲: ${ping_result}ms"
    
    # 測試 Shadowsocks 效能
    if command -v curl &> /dev/null; then
        local start_time=$(date +%s%N)
        curl -s --socks5 127.0.0.1:1080 --connect-timeout 10 https://www.google.com > /dev/null
        local end_time=$(date +%s%N)
        local duration=$(( ($end_time - $start_time) / 1000000 ))
        echo "Shadowsocks 響應時間: ${duration}ms"
    fi
    
    # 記錄系統資源
    echo "CPU 使用率: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')"
    echo "記憶體使用率: $(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100.0)}')"
    echo "磁碟使用率: $(df / | tail -1 | awk '{print $5}')"
}

# 備份重要配置
backup_configs() {
    echo "💾 備份配置文件..."
    
    local backup_dir="/etc/wireguard/backup/auto_backup_$DATE"
    mkdir -p "$backup_dir"
    
    # 備份 WireGuard 配置
    cp /etc/wireguard/*.conf "$backup_dir/" 2>/dev/null
    
    # 備份 Shadowsocks 配置
    cp /var/snap/shadowsocks-rust/common/etc/shadowsocks-rust/*.json "$backup_dir/" 2>/dev/null
    
    # 備份系統配置
    cp /etc/sysctl.d/99-wg-security.conf "$backup_dir/" 2>/dev/null
    
    # 壓縮備份
    tar -czf "$backup_dir.tar.gz" -C "$backup_dir" .
    rm -rf "$backup_dir"
    
    echo "✅ 配置備份完成: $backup_dir.tar.gz"
}

# 安全檢查
security_check() {
    echo "🔒 執行安全檢查..."
    
    # 檢查異常連接
    local suspicious_connections=$(netstat -tuln | grep ":22\|:8388\|:51820" | wc -l)
    if [ $suspicious_connections -gt 10 ]; then
        echo "⚠️ 發現異常連接數量: $suspicious_connections"
    fi
    
    # 檢查失敗的登入嘗試
    local failed_logins=$(grep "Failed password" /var/log/auth.log | wc -l)
    if [ $failed_logins -gt 50 ]; then
        echo "⚠️ 發現大量失敗登入嘗試: $failed_logins"
    fi
    
    # 檢查端口開放狀態
    nmap -sT -O localhost > "$LOG_DIR/port_scan_$DATE.txt"
    
    echo "✅ 安全檢查完成"
}

# 服務健康檢查
health_check() {
    echo "🏥 服務健康檢查..."
    
    # 檢查 WireGuard
    if systemctl is-active --quiet wg-quick@awg0; then
        echo "✅ WireGuard 運行正常"
    else
        echo "❌ WireGuard 服務異常"
        systemctl restart wg-quick@awg0
    fi
    
    # 檢查 Shadowsocks
    if snap services shadowsocks-rust.ssserver-daemon | grep -q "active"; then
        echo "✅ Shadowsocks 運行正常"
    else
        echo "❌ Shadowsocks 服務異常" 
        snap restart shadowsocks-rust.ssserver-daemon
    fi
    
    # 檢查防火牆規則
    local fw_rules=$(iptables -L | grep -E "8388|51820" | wc -l)
    if [ $fw_rules -lt 2 ]; then
        echo "⚠️ 防火牆規則可能不完整"
    fi
}

# 生成維護報告
generate_report() {
    local report_file="$LOG_DIR/maintenance_report_$DATE.md"
    
    cat > "$report_file" << EOF
# VPN 系統維護報告
## 日期: $(date)

### 系統狀態
$(systemctl status wg-quick@awg0 --no-pager -l)

### Shadowsocks 狀態  
$(snap services shadowsocks-rust.ssserver-daemon)

### 系統資源使用
- CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
- 記憶體: $(free -h | grep Mem | awk '{print $3 "/" $2}')
- 磁碟: $(df -h / | tail -1 | awk '{print $3 "/" $2 " (" $5 ")"}')

### 網絡連通性
$(ping -c 3 8.8.8.8 | tail -2)

### 活躍連接數
- WireGuard Peers: $(wg show awg0 peers 2>/dev/null | wc -l)
- 網絡連接: $(ss -tuln | wc -l)

### 執行的維護操作
- [x] 系統更新
- [x] 日誌清理  
- [x] 配置備份
- [x] 安全檢查
- [x] 效能測試

---
報告生成時間: $(date)
EOF

    echo "📋 維護報告已生成: $report_file"
}

# 設置定時任務
setup_crontab() {
    echo "⏰ 設置定時維護任務..."
    
    # 每週日凌晨 2 點執行完整維護
    echo "0 2 * * 0 root $SCRIPT_DIR/vpn-maintenance.sh full" >> /etc/crontab
    
    # 每天凌晨 3 點執行健康檢查
    echo "0 3 * * * root $SCRIPT_DIR/vpn-maintenance.sh health" >> /etc/crontab
    
    # 每小時執行監控
    echo "0 * * * * root $SCRIPT_DIR/vpn-monitor.sh" >> /etc/crontab
    
    systemctl reload cron
    echo "✅ 定時任務設置完成"
}

# 主函數
main() {
    setup_directories
    
    case "${1:-full}" in
        "full")
            echo "🚀 開始完整維護..."
            update_system
            cleanup_logs
            backup_configs
            security_check
            performance_test
            health_check
            generate_report
            echo "✅ 完整維護完成"
            ;;
        "health")
            echo "🏥 執行健康檢查..."
            health_check
            performance_test
            ;;
        "setup")
            echo "⚙️ 初始化維護系統..."
            setup_directories
            setup_crontab
            ;;
        *)
            echo "用法: $0 [full|health|setup]"
            echo "  full   - 完整維護 (預設)"
            echo "  health - 健康檢查"
            echo "  setup  - 初始化維護系統"
            ;;
    esac
}

# 確保以 root 權限執行
[[ $EUID -eq 0 ]] || { echo "需要 root 權限"; exit 1; }

# 執行主函數
main "$1"