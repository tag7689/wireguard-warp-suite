#!/bin/bash
echo "=== VPS SSH 故障檢查工具 ==="

# 1. 檢查 SSH 服務狀態
echo "[1] 檢查 sshd 服務狀態..."
if systemctl is-active --quiet sshd; then
    echo "✅ sshd 正在運行"
else
    echo "❌ sshd 沒有運行，嘗試啟動..."
    sudo systemctl start sshd
fi

# 2. 檢查 SSH 端口
PORT=$(grep -E "^Port " /etc/ssh/sshd_config | awk '{print $2}')
[ -z "$PORT" ] && PORT=22
echo "[2] SSH 端口設定為: $PORT"
sudo ss -tlnp | grep ":$PORT" >/dev/null && echo "✅ 端口 $PORT 已開啟" || echo "❌ 端口 $PORT 未開啟"

# 3. 檢查防火牆規則
echo "[3] 檢查防火牆..."
if command -v ufw >/dev/null; then
    sudo ufw status | grep "$PORT" && echo "✅ UFW 已允許端口 $PORT" || echo "⚠️ UFW 未允許端口 $PORT"
elif command -v firewall-cmd >/dev/null; then
    sudo firewall-cmd --list-ports | grep "$PORT" && echo "✅ firewalld 已允許端口 $PORT" || echo "⚠️ firewalld 未允許端口 $PORT"
else
    echo "ℹ️ 未檢測到常見防火牆工具，可能使用 iptables"
    sudo iptables -L -n | grep "$PORT"
fi

# 4. 檢查資源使用
echo "[4] 檢查系統資源..."
echo "CPU 使用率:"
top -bn1 | grep "Cpu(s)"
echo "記憶體使用率:"
free -h
echo "磁碟使用率:"
df -h /

# 5. 顯示外部 IP
echo "[5] VPS 公網 IP:"
curl -s ifconfig.me || echo "無法獲取外部 IP"

echo "=== 檢查完成 ==="