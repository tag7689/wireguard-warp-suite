#!/bin/bash
# Shadowsocks 密鑰自動輪換腳本

CONFIG_FILE="/var/snap/shadowsocks-rust/common/etc/shadowsocks-rust/config.json"
BACKUP_DIR="/etc/wireguard/backup"
DATE=$(date +%Y%m%d_%H%M%S)

# 生成新密碼
generate_new_password() {
    openssl rand -base64 24 | tr -d "=+/" | cut -c1-20
}

# 備份舊配置
backup_config() {
    cp "$CONFIG_FILE" "$BACKUP_DIR/ss_config_$DATE.json"
    echo "✅ 配置已備份到: $BACKUP_DIR/ss_config_$DATE.json"
}

# 更新密碼
update_password() {
    local new_password=$(generate_new_password)
    
    # 使用 jq 更新密碼 (需要安裝 jq)
    if command -v jq &> /dev/null; then
        jq --arg pwd "$new_password" '.password = $pwd' "$CONFIG_FILE" > /tmp/ss_config_new.json
        mv /tmp/ss_config_new.json "$CONFIG_FILE"
    else
        # 手動替換 (備用方案)
        sed -i "s/\"password\": \"[^\"]*\"/\"password\": \"$new_password\"/" "$CONFIG_FILE"
    fi
    
    echo "🔐 新密碼: $new_password"
    echo "請更新客戶端配置！"
}

# 重啟服務
restart_service() {
    snap restart shadowsocks-rust.ssserver-daemon
    sleep 3
    if snap services shadowsocks-rust.ssserver-daemon | grep -q "active"; then
        echo "✅ Shadowsocks 服務重啟成功"
    else
        echo "❌ 服務重啟失敗，請檢查配置"
        # 回滾配置
        cp "$BACKUP_DIR/ss_config_$DATE.json" "$CONFIG_FILE"
        snap restart shadowsocks-rust.ssserver-daemon
    fi
}

# 主流程
main() {
    echo "🔄 開始 Shadowsocks 密鑰輪換..."
    backup_config
    update_password
    restart_service
    
    # 清理 30 天前的備份
    find "$BACKUP_DIR" -name "ss_config_*.json" -mtime +30 -delete
    
    echo "✅ 密鑰輪換完成"
    echo "⚠️  記得更新客戶端配置檔案！"
}

# 檢查權限
[[ $EUID -eq 0 ]] || { echo "需要 root 權限"; exit 1; }

# 執行
main