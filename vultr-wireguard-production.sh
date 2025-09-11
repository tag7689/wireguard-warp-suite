#!/bin/bash
# =============================================================================
# WireGuard Production Deployment Script for Vultr Ubuntu 24.04
# Fixes UFW forwarding, NAT, DNS resolution for Windows clients
# =============================================================================

set -euo pipefail

# ===================== Configuration =====================
readonly SCRIPT_VERSION="1.0"
readonly WG_IF="awg0"
readonly WG_PORT="${WG_PORT:-51820}"
readonly WG_NET="10.66.66.0/24"
readonly WG_SVR_IP="10.66.66.1/24"
readonly CLIENT_NAME="${CLIENT_NAME:-client01}"
readonly CLIENT_IP="10.66.66.10/32"
readonly DNS_ADDR="${DNS_ADDR:-1.1.1.1}"
readonly MTU="${MTU:-1280}"
readonly ENABLE_WARP="${ENABLE_WARP:-false}"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# ===================== Functions =====================
print_header() {
    echo -e "${BLUE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║         WireGuard Production Deployment for Vultr           ║
║                  v1.0 - DNS & UFW Fixed                     ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log() { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

check_root() {
    [[ $EUID -eq 0 ]] || error "This script must be run as root"
}

detect_wan_interface() {
    local wan_if
    wan_if=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    WAN_IF="${wan_if:-enp1s0}"
    success "Detected WAN interface: $WAN_IF"
}

install_packages() {
    log "Installing required packages..."
    export DEBIAN_FRONTEND=noninteractive
    
    apt-get update -qq
    apt-get install -y -qq \
        wireguard \
        wireguard-tools \
        ufw \
        qrencode \
        curl \
        net-tools \
        iptables-persistent
    
    success "Packages installed"
}

generate_keys() {
    log "Generating WireGuard keys..."
    
    mkdir -p /etc/wireguard/clients
    chmod 700 /etc/wireguard /etc/wireguard/clients
    
    # Server keys
    SERVER_PRIVATE_KEY=$(wg genkey)
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
    
    # Client keys  
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    CLIENT_PSK=$(wg genpsk)
    
    echo "$SERVER_PUBLIC_KEY" > /etc/wireguard/${WG_IF}.pub
    success "Keys generated"
}

create_server_config() {
    log "Creating server configuration..."
    
    cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_SVR_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVATE_KEY}
PostUp = /etc/wireguard/postup.sh
PreDown = /etc/wireguard/predown.sh

[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
PresharedKey = ${CLIENT_PSK}
AllowedIPs = ${CLIENT_IP}
EOF
    
    chmod 600 /etc/wireguard/${WG_IF}.conf
    success "Server config created"
}

create_client_config() {
    log "Creating client configuration..."
    
    local server_ip
    server_ip=$(curl -4 -s --max-time 10 https://api.ipify.org || echo "YOUR_SERVER_IP")
    
    cat > /etc/wireguard/clients/${CLIENT_NAME}.conf <<EOF
[Interface]
Address = ${CLIENT_IP}
PrivateKey = ${CLIENT_PRIVATE_KEY}
DNS = ${DNS_ADDR}
MTU = ${MTU}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
PresharedKey = ${CLIENT_PSK}
Endpoint = ${server_ip}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    chmod 600 /etc/wireguard/clients/${CLIENT_NAME}.conf
    
    # Generate QR code
    if command -v qrencode >/dev/null; then
        qrencode -t PNG -o /etc/wireguard/clients/${CLIENT_NAME}_qr.png \
                 < /etc/wireguard/clients/${CLIENT_NAME}.conf
        success "Client config and QR code created"
    else
        success "Client config created"
    fi
}

create_postup_predown_scripts() {
    log "Creating PostUp/PreDown scripts..."
    
    cat > /etc/wireguard/postup.sh <<EOF
#!/bin/bash
# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

# NAT for WireGuard subnet
iptables -t nat -C POSTROUTING -s ${WG_NET} -o ${WAN_IF} -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s ${WG_NET} -o ${WAN_IF} -j MASQUERADE

# Forward rules
iptables -C FORWARD -i ${WG_IF} -o ${WAN_IF} -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i ${WG_IF} -o ${WAN_IF} -j ACCEPT

iptables -C FORWARD -i ${WAN_IF} -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i ${WAN_IF} -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

logger "WireGuard PostUp completed"
EOF

    cat > /etc/wireguard/predown.sh <<EOF
#!/bin/bash
# Remove NAT rule
iptables -t nat -D POSTROUTING -s ${WG_NET} -o ${WAN_IF} -j MASQUERADE 2>/dev/null || true

# Remove forward rules
iptables -D FORWARD -i ${WG_IF} -o ${WAN_IF} -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i ${WAN_IF} -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

logger "WireGuard PreDown completed"
EOF

    chmod +x /etc/wireguard/postup.sh /etc/wireguard/predown.sh
    success "PostUp/PreDown scripts created"
}

configure_system_forwarding() {
    log "Configuring system IP forwarding..."
    
    # Enable IP forwarding in sysctl
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wireguard.conf
    sysctl -p /etc/sysctl.d/99-wireguard.conf
    
    success "System forwarding enabled"
}

configure_ufw() {
    log "Configuring UFW firewall..."
    
    # Enable forwarding policy
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    # Enable IP forwarding in UFW sysctl
    if grep -q '^#.*net/ipv4/ip_forward' /etc/ufw/sysctl.conf; then
        sed -i 's/^#net\/ipv4\/ip_forward=.*/net\/ipv4\/ip_forward=1/' /etc/ufw/sysctl.conf
    else
        echo 'net/ipv4/ip_forward=1' >> /etc/ufw/sysctl.conf
    fi
    
    # Add NAT rules to before.rules
    if ! grep -q "\*nat" /etc/ufw/before.rules; then
        # Backup original
        cp /etc/ufw/before.rules /etc/ufw/before.rules.backup
        
        # Add NAT block before the final COMMIT
        sed -i '/^COMMIT$/i \
# NAT rules for WireGuard\
*nat\
:POSTROUTING ACCEPT [0:0]\
-A POSTROUTING -s '"${WG_NET}"' -o '"${WAN_IF}"' -j MASQUERADE\
COMMIT\
' /etc/ufw/before.rules
    fi
    
    # Allow WireGuard port
    ufw allow ${WG_PORT}/udp comment "WireGuard"
    
    # Allow routing between interfaces
    ufw route allow in on ${WG_IF} out on ${WAN_IF} comment "WireGuard to WAN"
    ufw route allow in on ${WAN_IF} out on ${WG_IF} comment "WAN to WireGuard"
    
    # Enable UFW
    ufw --force enable
    
    success "UFW configured"
}

start_wireguard() {
    log "Starting WireGuard service..."
    
    systemctl enable wg-quick@${WG_IF}
    systemctl start wg-quick@${WG_IF}
    
    # Wait for interface to be up
    sleep 3
    
    if systemctl is-active --quiet wg-quick@${WG_IF}; then
        success "WireGuard service started"
    else
        error "Failed to start WireGuard service"
    fi
}

verify_installation() {
    log "Verifying installation..."
    
    # Check if interface exists
    if ! ip link show ${WG_IF} >/dev/null 2>&1; then
        error "WireGuard interface ${WG_IF} not found"
    fi
    
    # Check if service is running
    if ! systemctl is-active --quiet wg-quick@${WG_IF}; then
        error "WireGuard service not running"
    fi
    
    # Check UFW status
    if ! ufw status | grep -q "Status: active"; then
        warn "UFW is not active"
    fi
    
    success "Installation verified"
}

display_results() {
    local server_ip
    server_ip=$(curl -4 -s --max-time 10 https://api.ipify.org || echo "YOUR_SERVER_IP")
    
    print_header
    
    echo -e "${GREEN}🎉 WireGuard deployment completed successfully!${NC}"
    echo
    echo -e "${BLUE}📊 Server Information${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Server IP: ${server_ip}"
    echo "Listen Port: ${WG_PORT}"
    echo "WireGuard Interface: ${WG_IF}"
    echo "Network: ${WG_NET}"
    echo
    echo -e "${BLUE}📁 Client Configuration${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Config file: /etc/wireguard/clients/${CLIENT_NAME}.conf"
    if [[ -f "/etc/wireguard/clients/${CLIENT_NAME}_qr.png" ]]; then
        echo "QR code: /etc/wireguard/clients/${CLIENT_NAME}_qr.png"
    fi
    echo
    echo -e "${BLUE}🔧 Management Commands${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Check status: wg show ${WG_IF}"
    echo "Restart: systemctl restart wg-quick@${WG_IF}"
    echo "View logs: journalctl -u wg-quick@${WG_IF} -f"
    echo "View client config: cat /etc/wireguard/clients/${CLIENT_NAME}.conf"
    echo
    echo -e "${BLUE}💡 Client Setup Tips${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "• Import the client config to WireGuard or WireSock"
    echo "• For Windows: Use official WireGuard client or WireSock"
    echo "• MTU is set to ${MTU} for compatibility"
    echo "• DNS is set to ${DNS_ADDR}"
    echo "• If DNS doesn't work, try disabling IPv6 on client"
    echo
    echo -e "${GREEN}✅ Ready to use! Import the client config to start connecting.${NC}"
}

show_client_config() {
    echo
    echo -e "${BLUE}📱 Client Configuration Content${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat /etc/wireguard/clients/${CLIENT_NAME}.conf
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if command -v qrencode >/dev/null; then
        echo
        echo -e "${BLUE}📱 QR Code for Mobile Import${NC}"
        qrencode -t ansiutf8 < /etc/wireguard/clients/${CLIENT_NAME}.conf
    fi
}

# ===================== Main Execution =====================
main() {
    print_header
    
    log "Starting WireGuard deployment for Vultr Ubuntu 24.04..."
    
    check_root
    detect_wan_interface
    install_packages
    generate_keys
    create_server_config
    create_client_config
    create_postup_predown_scripts
    configure_system_forwarding
    configure_ufw
    start_wireguard
    verify_installation
    display_results
    show_client_config
    
    log "Deployment completed successfully!"
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo "Options:"
        echo "  --help, -h    Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  WG_PORT       WireGuard listen port (default: 51820)"
        echo "  CLIENT_NAME   Client configuration name (default: client01)"
        echo "  DNS_ADDR      DNS server for clients (default: 1.1.1.1)"
        echo "  MTU           MTU size (default: 1280)"
        echo ""
        echo "Example:"
        echo "  WG_PORT=51821 CLIENT_NAME=laptop ./vultr-wireguard-production.sh"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac