#!/bin/bash
set -euo pipefail

Config
WG_IF="awg0"
WG_NET="10.66.66.0/24"
WG_SVR_IP="10.66.66.1/24"
WG_PORT="${WG_PORT:-51820}"
CLIENT_NAME="${CLIENT_NAME:-client01}"
CLIENT_IP="${CLIENT_IP:-10.66.66.10/32}"
DNS_ADDR="${DNS_ADDR:-1.1.1.1}"
MTU="${MTU:-1280}"
WAN_IF="${WAN_IF:-enp1s0}"
ENABLE_WARP="${ENABLE_WARP:-false}"

log() { echo -e "[] $"; }
ok() { echo -e "✅ $"; }
warn() { echo -e "⚠️ $"; }
err() { echo -e "❌ $*" >&2; }

require_root() { [[ $EUID -eq 0 ]] || { err "Run as root"; exit 1; }; }

pkg_install() {
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools ufw qrencode net-tools curl
}

detect_wan() {
if ip route get 1.1.1.1 2>/dev/null | grep -oE "dev [^ ]+" >/dev/null; then
D=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
if [[ -n "$D" ]]; then WAN_IF="$D"; fi
fi
ok "WAN_IF=$WAN_IF"
}

gen_keys() {
mkdir -p /etc/wireguard/clients
chmod 700 /etc/wireguard
WG_PRIV=$(wg genkey)
WG_PUB=$(echo "$WG_PRIV" | wg pubkey)
CL_PRIV=$(wg genkey)
CL_PUB=$(echo "$CL_PRIV" | wg pubkey)
CL_PSK=$(wg genpsk)
echo "$WG_PUB" > /etc/wireguard/${WG_IF}.pub
}

write_post_scripts() {
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

write_server_conf() {
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

write_client_conf() {
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
ok "Client file: /etc/wireguard/clients/${CLIENT_NAME}.conf"
}

configure_ufw() {

enable forward policy
sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw || true

sysctl forwarding
sed -i 's/^#?net/ipv4/ip_forward=.*/net/ipv4/ip_forward=1/' /etc/ufw/sysctl.conf || echo "net/ipv4/ip_forward=1" >> /etc/ufw/sysctl.conf

before.rules NAT block
if ! grep -q "*nat" /etc/ufw/before.rules; then
cat >> /etc/ufw/before.rules <<'NATBLOCK'

add nat block
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.66.66.0/24 -o enp1s0 -j MASQUERADE

don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
NATBLOCK
# replace enp1s0 with detected WAN_IF
sed -i "s/enp1s0/${WAN_IF}/g" /etc/ufw/before.rules
else
# ensure rule uses current WAN_IF
sed -i "s/-o [a-z0-9]+ -j MASQUERADE/-o ${WAN_IF} -j MASQUERADE/" /etc/ufw/before.rules
fi

ufw allow ${WG_PORT}/udp || true
ufw route allow in on ${WG_IF} out on ${WAN_IF} || true
ufw --force enable
systemctl restart ufw
}

start_wg() {
systemctl enable wg-quick@${WG_IF}
systemctl restart wg-quick@${WG_IF}
ok "wg-quick started"
}

maybe_warp() {
if [[ "${ENABLE_WARP}" != "true" ]]; then
warn "WARP disabled (ENABLE_WARP=true to enable)"
return 0
fi
warn "WARP optional part skipped here for stability. Enable later after VPN OK."
}

summary() {
SVR_IPv4=$(curl -4 -s --max-time 5 https://api.ipify.org || echo YOUR_SERVER_IP)
echo
ok "Deployment complete"
echo "Server public IP: ${SVR_IPv4}"
echo "Listen: ${WG_PORT}/udp"
echo "Client config: /etc/wireguard/clients/${CLIENT_NAME}.conf"
echo "Tips: import to WireSock/WireGuard app; if DNS timeout, keep MTU=1280 and ensure IPv6 disabled on client."
}

main() {
require_root
pkg_install
detect_wan
gen_keys
write_post_scripts
write_server_conf
write_client_conf
configure_ufw
start_wg
maybe_warp
summary
}
main "$@"