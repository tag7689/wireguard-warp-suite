#!/bin/bash
# 進階 DPI 對抗 - 動態端口輪換

SS_CONFIG="/var/snap/shadowsocks-rust/common/etc/shadowsocks-rust/config.json"
WG_CONFIG="/etc/wireguard/awg0.conf"
PORTS=(8443 9443 443 8080 3389 1194 1723)  # 常見服務端口偽裝

# 獲取當前端口
get_current_port() {
    grep '"server_port"' "$SS_CONFIG" | grep -o '[0-9]\+'
}

# 選擇新端口 (避免當前端口)
select_new_port() {
    local current_port=$(get_current_port)
    local new_port
    
    do {
        new_port=${PORTS[$RANDOM % ${#PORTS[@]}]}
    } while [ "$new_port" = "$current_port" ]
    
    echo $new_port
}

# 更新 Shadowsocks 端口
update_ss_port() {
    local new_port=$1
    local backup_file="$SS_CONFIG.backup.$(date +%s)"
    
    # 備份配置
    cp "$SS_CONFIG" "$backup_file"
    
    # 更新端口
    sed -i "s/\"server_port\": [0-9]*/\"server_port\": $new_port/" "$SS_CONFIG"
    
    # 更新防火牆規則
    iptables -D INPUT -p tcp --dport $(get_current_port) -j ACCEPT 2>/dev/null
    iptables -D INPUT -p udp --dport $(get_current_port) -j ACCEPT 2>/dev/null
    iptables -A INPUT -p tcp --dport $new_port -j ACCEPT
    iptables -A INPUT -p udp --dport $new_port -j ACCEPT
    
    # 保存防火牆規則
    netfilter-persistent save
    
    echo "✅ Shadowsocks 端口更新為: $new_port"
}

# 生成新的客戶端配置
generate_client_config() {
    local new_port=$1
    local server_ip=$(curl -4 -s --max-time 10 https://api.ipify.org)
    local password=$(grep '"password"' "$SS_CONFIG" | cut -d'"' -f4)
    
    cat > /etc/wireguard/clients/shadowsocks-client-$(date +%Y%m%d).json << EOF
{
    "server": "$server_ip",
    "server_port": $new_port,
    "password": "$password",
    "method": "chacha20-ietf-poly1305",
    "mode": "tcp_and_udp",
    "locals": [
        {
            "mode": "udp_only",
            "protocol": "tunnel",
            "local_address": "127.0.0.1",
            "local_port": 1080,
            "forward_address": "$server_ip",
            "forward_port": 51820
        }
    ]
}
EOF

    echo "✅ 新的客戶端配置已生成"
    echo "📁 位置: /etc/wireguard/clients/shadowsocks-client-$(date +%Y%m%d).json"
}

# 重啟服務
restart_services() {
    echo "🔄 重啟 Shadowsocks..."
    snap restart shadowsocks-rust.ssserver-daemon
    sleep 3
    
    if snap services shadowsocks-rust.ssserver-daemon | grep -q "active"; then
        echo "✅ Shadowsocks 重啟成功"
    else
        echo "❌ Shadowsocks 重啟失敗"
        return 1
    fi
}

# 主函數
main() {
    echo "🎭 開始 DPI 對抗 - 動態端口輪換"
    
    local current_port=$(get_current_port)
    local new_port=$(select_new_port)
    
    echo "📊 當前端口: $current_port"
    echo "🎯 新端口: $new_port"
    
    update_ss_port $new_port
    restart_services
    generate_client_config $new_port
    
    echo "✅ 動態端口輪換完成"
    echo "⚠️  請更新客戶端配置並重新連接"
}

# 檢查權限
[[ $EUID -eq 0 ]] || { echo "需要 root 權限"; exit 1; }

# 執行
main