#!/bin/bash
set -euo pipefail

WireGuard one-click (Vultr/Ubuntu 24.04)
WG_IF="awg0"
WG_NET="10.66.66.0/24"
WG_SVR_IP="10.66.66.1/24"
WG_PORT="${WG_PORT:-51820}"
CLIENT_NAME="${CLIENT_NAME:-client01}"
CLIENT_IP="${CLIENT_IP:-10.66.66.10/32}"
DNS_ADDR="${DNS_ADDR:-1.1.1.1}"
MTU="${MTU:-1280}"
ENABLE_WARP="${ENABLE_WARP:-false}"

log(){ echo "[] $"; }
ok(){ echo "OK: $"; }
die(){ echo "ERR: $" >&2; exit 1; }

need_root(){ [[ $EUID -eq 0 ]] || die "run as root"; }

detect_wan(){
local dev
dev=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
WAN_IF="${WAN_IF:-${dev:-enp1s0}}"
ok "WAN_IF=$WAN_IF"
}

install_pkgs(){
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools ufw qrencode curl net-tools
}

gen_keys(){
mkdir -p /etc/wireguard/clients
chmod 700 /etc/wireguard
WG_PRIV=$(wg genkey)
WG_PUB=$(echo "$WG_PRIV" | wg pubkey)
CL_PRIV=$(wg genkey)
CL_PUB=$(echo "$CL_PRIV" | wg pubkey)
CL_PSK=$(wg genpsk)
echo "$WG_PUB" > /etc/wireguard/${WG_IF}.pub
}

write_hooks(){
cat > /etc/wireguard/postup.sh <<EOF
#!/bin/bash
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -C POSTROUTING -s ${WG_NET} -o ${WAN_IF} -j MASQUERADE 2>/dev/null ||
iptables -t nat -A POSTROUTING -s ${WG_NET} -o ${WAN_IF} -j MASQUERADE
iptables -C FORWARD -i ${WG_IF} -o ${WAN_IF} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${WG_IF} -o ${WAN_IF} -j ACCEPT
iptables -C FORWARD -i ${WAN_IF} -o ${WG_IF} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null ||
iptables -A FORWARD -i ${WAN_IF} -o ${WG_IF} -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
cat > /etc/wireguard/predown.sh <<EOF
#!/bin/bash
iptables -t nat -D POSTROUTING -s ${WG_NET} -o ${WAN_IF} -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i ${WG_IF} -o ${WAN_IF} -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i ${WAN_IF} -o ${WG_IF} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
EOF
chmod +x /etc/wireguard/postup.sh /etc/wireguard/predown.sh
}

write_server(){
cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_SVR_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${WG_PRIV}
PostUp = /etc/wireguard/postup.sh
PreDown = /etc/wireguard/predown.sh

[Peer]
PublicKey = ${CL_PUB}
PresharedKey = ${CL_PSK}
AllowedIPs = ${CLIENT_IP}
EOF
chmod 600 /etc/wireguard/${WG_IF}.conf
}

write_client(){
local PUB_SVR SVR_IPv4
PUB_SVR=$(cat /etc/wireguard/${WG_IF}.pub)
SVR_IPv4=$(curl -4 -s --max-time 5 https://api.ipify.org || echo YOUR_SERVER_IP)
cat > /etc/wireguard/clients/${CLIENT_NAME}.conf <<EOF
[Interface]
Address = ${CLIENT_IP}
PrivateKey = ${CL_PRIV}
DNS = ${DNS_ADDR}
MTU = ${MTU}

[Peer]
Endpoint = ${SVR_IPv4}:${WG_PORT}
PublicKey = ${PUB_SVR}
PresharedKey = ${CL_PSK}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/clients/${CLIENT_NAME}.conf
}

ufw_config(){
sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw || true
if grep -q '^#net/ipv4/ip_forward' /etc/ufw/sysctl.conf; then
sed -i 's/^#?net/ipv4/ip_forward=./net/ipv4/ip_forward=1/' /etc/ufw/sysctl.conf
else
echo 'net/ipv4/ip_forward=1' >> /etc/ufw/sysctl.conf
fi
if ! grep -q "*nat" /etc/ufw/before.rules; then
cat >> /etc/ufw/before.rules <<'NATBLOCK'

add nat block
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.66.66.0/24 -o enp1s0 -j MASQUERADE
COMMIT
NATBLOCK
fi
sed -i "s/-o [a-z0-9]+ -j MASQUERADE/-o ${WAN_IF} -j MASQUERADE/" /etc/ufw/before.rules
ufw allow ${WG_PORT}/udp || true
ufw route allow in on ${WG_IF} out on ${WAN_IF} || true
ufw --force enable
systemctl restart ufw
}

start_wg(){
systemctl enable wg-quick@${WG_IF}
systemctl restart wg-quick@${WG_IF}
}

summary(){
local ip4
ip4=$(curl -4 -s --max-time 5 https://api.ipify.org || echo YOUR_SERVER_IP)
echo
ok "WireGuard up. Endpoint: ${ip4}:${WG_PORT}"
echo "Client: /etc/wireguard/clients/${CLIENT_NAME}.conf"
echo "Import to WireGuard/WireSock; if DNS timeout, keep MTU=${MTU}."
}

main(){
need_root
detect_wan
install_pkgs
gen_keys
write_hooks
write_server
write_client
ufw_config
start_wg
summary
}
main "$@"