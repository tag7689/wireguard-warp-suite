# wireguard-warp-suite
This a script created by perplexity.ai fufilled functions from my request for deploying a WireGuard VPN Server on VPS.

# WireGuard + WARP + AmneziaWG Production Deployment Suite

A comprehensive, production-ready solution for deploying and managing AmneziaWG VPN servers with Cloudflare WARP integration and advanced DPI (Deep Packet Inspection) protection on Ubuntu/Debian systems.

## 🛡️ What Makes This Special

### **Triple-Layer Protection**
```
Client → AmneziaWG (DPI Protection) → [Network Namespace: WARP] → Internet
```

- **AmneziaWG**: Advanced WireGuard fork with Magic Headers to bypass DPI detection
- **WARP Integration**: Hide your VPS real IP behind Cloudflare's network  
- **Network Namespace Isolation**: Maximum stability and security isolation

### **DPI Protection Technology**
- 🔧 **Magic Headers**: Disguise packet headers to avoid pattern recognition
- 📦 **Packet Size Randomization**: Break WireGuard's fixed packet size patterns  
- 🗂️ **Junk Packet Injection**: Confuse DPI systems with decoy traffic
- 🌐 **IP Address Masking**: Route all traffic through Cloudflare's global network

## 🌟 Features

### Core Functionality
- **One-Click Deployment**: Automated AmneziaWG + WARP server setup
- **Advanced DPI Bypassing**: Magic Headers technology to evade censorship
- **Production-Grade Security**: UFW firewall, fail2ban integration, and comprehensive hardening
- **Self-Healing System**: Automated health checks and service recovery
- **Network Namespace Isolation**: WARP runs isolated for maximum stability
- **Traffic Obfuscation**: Optional phantun/udp2raw/wstunnel support for double protection

### DPI Protection Management
- **Magic Headers Generator**: Automatically generate unique network fingerprints
- **DPI Test Suite**: Comprehensive testing of bypass effectiveness
- **Dynamic Configuration**: Enable/disable DPI protection without reinstalling
- **Header Regeneration**: Easily refresh Magic Headers for enhanced security
- **Compatibility Mode**: Option to run in standard WireGuard compatible mode

### Management Tools
- **Enhanced CLI Manager**: 20+ commands for comprehensive system management
- **Client Management**: Add, remove, and manage AmneziaWG clients with QR codes
- **Real-time Monitoring**: Service status, connection quality, and exit IP verification
- **Backup & Restore**: Automated configuration backups with one-click restore
- **Health Diagnostics**: Detailed system health checks and troubleshooting

### Advanced Features
- **Prometheus Monitoring**: Optional metrics export for Grafana integration
- **Systemd Integration**: Proper service dependencies and auto-restart capabilities
- **Log Management**: Structured logging with automatic rotation
- **Multi-Layer Protection**: Combine DPI bypassing with IP masking

## 🚀 Quick Start

### Prerequisites
- Ubuntu 20.04+ or Debian 11+ VPS
- Root access
- Active internet connection
- Kernel 5.4+ (recommended for AmneziaWG)

### Installation

```bash
# Download the deployment script
wget https://github.com/tag7689/wireguard-warp-amnezia-suite/raw/main/wireguard-warp-amnezia-production.sh

# Make it executable
chmod +x wireguard-warp-amnezia-production.sh

# Run the installation (DPI protection enabled by default)
sudo ./wireguard-warp-amnezia-production.sh
```

### Advanced Installation Options

```bash
# Custom Magic Headers
sudo AWG_H1=1234567890 AWG_H2=2345678901 AWG_S1=50 AWG_S2=75 \
     ./wireguard-warp-amnezia-production.sh

# Compatibility mode (standard WireGuard clients supported)
sudo ENABLE_DPI_PROTECTION=false ./wireguard-warp-amnezia-production.sh

# With additional obfuscation (double protection)
sudo ENABLE_OBFUSCATION=true OBFUSCATION_TYPE=phantun \
     ./wireguard-warp-amnezia-production.sh

# Full featured deployment
sudo ENABLE_DPI_PROTECTION=true ENABLE_OBFUSCATION=true ENABLE_MONITORING=true \
     ./wireguard-warp-amnezia-production.sh
```

## 🛠 Management

### Download Management Tool

```bash
# Download the enhanced management tool
wget https://github.com/tag7689/wireguard-warp-amnezia-suite/raw/main/wg-warp-amnezia-manager.sh
chmod +x wg-warp-amnezia-manager.sh
```

### Common Commands

```bash
# Check system status with DPI protection info
./wg-warp-amnezia-manager.sh status

# Show current Magic Headers configuration
./wg-warp-amnezia-manager.sh show-magic

# Test DPI protection effectiveness
./wg-warp-amnezia-manager.sh dpi-test

# Regenerate Magic Headers (breaks existing connections)
./wg-warp-amnezia-manager.sh regen-magic

# Add a new client with DPI protection
./wg-warp-amnezia-manager.sh add-client

# Test connectivity and bypass effectiveness
./wg-warp-amnezia-manager.sh test
```

## 🔧 DPI Protection Management

### Magic Headers Configuration

```bash
# View current Magic Headers
./wg-warp-amnezia-manager.sh show-magic

# Example output:
# 🔧 Magic Headers (封包標頭偽裝):
#   H1 (Init Packet):      2851294847
#   H2 (Response Packet):  1739462829  
#   H3 (Transport Packet): 3942851627
#   H4 (Underload Packet): 2184950371
#
# 📦 Packet Size Randomization:
#   S1 (Init Junk Size):     67 bytes
#   S2 (Response Junk Size): 42 bytes
#
# 🗂️ Junk Packets:
#   Junk Count:    4 packets
#   Min Size:      40 bytes  
#   Max Size:      70 bytes
```

### DPI Protection Controls

```bash
# Enable DPI protection
./wg-warp-amnezia-manager.sh enable-dpi

# Disable DPI protection (compatibility mode)
./wg-warp-amnezia-manager.sh disable-dpi

# Test DPI bypass effectiveness
./wg-warp-amnezia-manager.sh dpi-test

# Regenerate unique Magic Headers
./wg-warp-amnezia-manager.sh regen-magic
```

## 📋 Complete Command Reference

### Basic Operations
- `status` - Display comprehensive service status with DPI info
- `test` - Run connectivity and DPI bypass tests
- `restart-awg` - Restart AmneziaWG service
- `restart-warp` - Restart WARP service  
- `restart-all` - Restart all services safely
- `logs` - View system logs
- `ip-check` - Verify IP protection is working

### Client Management
- `add-client` - Add new AmneziaWG client with auto IP assignment
- `list-clients` - Show all clients and connection status
- `remove-client` - Safely remove client configuration
- `show-client` - Display client config and QR code

### DPI Protection Management
- `show-magic` - Display current Magic Headers configuration
- `regen-magic` - Regenerate Magic Headers (requires client updates)
- `enable-dpi` - Enable DPI protection features
- `disable-dpi` - Disable DPI protection (compatibility mode)
- `dpi-test` - Test DPI protection effectiveness

### Configuration Management
- `change-dns` - Modify DNS settings for all clients
- `backup-config` - Create configuration backup
- `restore-config` - Restore from backup

### Advanced Features
- `health-check` - Run comprehensive health diagnostics
- `update-warp` - Update WARP configuration
- `help` - Show detailed help information

## 🏗 Architecture

### Network Flow
```
Client (AmneziaWG) → VPS (awg0 interface) → [Network Namespace] → WARP → Internet
                                              ↑
                                         veth tunnel
```

### Key Components

1. **AmneziaWG Server** (`awg0`)
   - Handles client connections with DPI protection
   - Magic Headers disguise traffic patterns
   - Routes traffic to WARP namespace

2. **WARP Namespace** (`warp`)
   - Isolated Cloudflare WARP connection
   - Protects server's real IP address
   - Standard WireGuard connection to WARP

3. **DPI Protection Layer**
   - Magic Headers: H1, H2, H3, H4 (32-bit random values)
   - Packet Size Randomization: S1, S2 (15-114 bytes junk)
   - Junk Packet Injection: Jc count with Jmin-Jmax size range

4. **Health Check System**
   - Monitors AmneziaWG and WARP status
   - Automatic failure recovery
   - DPI effectiveness testing

5. **Security Layer**
   - UFW firewall configuration
   - fail2ban brute force protection
   - AmneziaWG kernel module security

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_DPI_PROTECTION` | `true` | Enable Magic Headers DPI protection |
| `AWG_H1` | `random` | Init packet magic header |
| `AWG_H2` | `random` | Response packet magic header |
| `AWG_H3` | `random` | Transport packet magic header |
| `AWG_H4` | `random` | Underload packet magic header |
| `AWG_S1` | `random` | Init packet junk size (15-114) |
| `AWG_S2` | `random` | Response packet junk size (15-114) |
| `AWG_JC` | `random` | Junk packet count (3-5) |
| `ENABLE_OBFUSCATION` | `false` | Enable additional traffic obfuscation |
| `OBFUSCATION_TYPE` | `phantun` | Obfuscation method (phantun/udp2raw/wstunnel) |
| `ENABLE_MONITORING` | `true` | Enable Prometheus metrics |

### Files and Directories

```
/etc/amnezia/amneziawg/
├── awg0.conf                        # Server configuration with Magic Headers
├── awg0.key                         # Server private key
├── awg0.pub                         # Server public key
├── magic_headers.conf               # Magic Headers parameters
├── clients/                         # Client configurations with DPI protection
│   ├── client01.conf
│   └── client01_qr.png
└── scripts/                         # PostUp/PostDown scripts
    ├── postup.sh
    └── predown.sh

/opt/wireguard-backup/               # Configuration backups
/var/log/                           # Log files
├── wireguard-warp-amnezia-deploy.log
└── wg-warp-amnezia-manager.log
```

### Client Configuration Example

```ini
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.66.66.10/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = SERVER_PUBLIC_KEY
PresharedKey = PRESHARED_KEY
Endpoint = YOUR_SERVER_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

# AmneziaWG Magic Headers (DPI Protection)
# Note: Must match server configuration exactly
Jc = 4
Jmin = 40
Jmax = 70
S1 = 67
S2 = 42
H1 = 2851294847
H2 = 1739462829
H3 = 3942851627
H4 = 2184950371
```

## 📱 Client Applications

### Recommended Clients

1. **AmneziaVPN Official App** (Recommended)
   - Download: [amneziavpn.org](https://amneziavpn.org)
   - Full Magic Headers support
   - Cross-platform (Windows, macOS, Linux, Android, iOS)
   - Automatic configuration import

2. **AmneziaWG CLI** (Linux/Advanced Users)
   - Install: `apt install amneziawg amneziawg-tools`
   - Command line interface
   - Systemd integration

### Important Client Notes
- **Standard WireGuard clients will NOT work** when DPI protection is enabled
- Magic Headers parameters must **exactly match** between server and client
- Use QR codes or configuration files generated by the management tool
- Clients can be switched between DPI and compatibility modes

## 📊 Monitoring

### Service Status
```bash
# Check all services
systemctl status awg-quick@awg0
systemctl status warp-netns.service

# AmneziaWG specific status
awg show awg0

# WARP status in namespace
ip netns exec warp wg show wgcf
```

### DPI Protection Verification
```bash
# Comprehensive DPI test
./wg-warp-amnezia-manager.sh dpi-test

# Check Magic Headers
./wg-warp-amnezia-manager.sh show-magic

# Verify different exit IPs
curl ifconfig.me                                    # Server real IP
ip netns exec warp curl ifconfig.me               # WARP exit IP
```

### Health Check Logs
```bash
# View management logs
tail -f /var/log/wg-warp-amnezia-manager.log

# System deployment logs
tail -f /var/log/wireguard-warp-amnezia-deploy.log
```

## 🔒 Security Features

### AmneziaWG Kernel Module
- **Kernel-level implementation** for maximum performance
- **Secure Magic Headers** processing in kernel space
- **Memory protection** against packet inspection
- **Automatic module loading** and integrity verification

### Firewall Configuration
- **UFW integration** with AmneziaWG-specific rules
- **Port management** for both standard and obfuscated connections  
- **fail2ban protection** against brute force attacks
- **Namespace isolation** preventing interference

### Network Security
- **Isolated WARP connection** in dedicated namespace
- **Encrypted tunnel chaining** (AmneziaWG → WARP → Internet)
- **No DNS leaks** through controlled routing
- **Real IP protection** via Cloudflare's network

## 🌐 DNS Configuration

The system supports multiple DNS providers with DPI protection:

| Provider | IP Address | Features | DPI Resistance |
|----------|------------|----------|----------------|
| Cloudflare | 1.1.1.1 | Fast, privacy-focused, DoH/DoT | High |
| Google | 8.8.8.8 | Reliable, high availability | Medium |
| Quad9 | 9.9.9.9 | Malware filtering, security | High |
| OpenDNS | 208.67.222.222 | Content filtering, controls | Medium |
| AdGuard | 94.140.14.14 | Ad blocking, privacy | High |

Change DNS for all clients:
```bash
./wg-warp-amnezia-manager.sh change-dns
```

## 🚨 Troubleshooting

### Common Issues

#### AmneziaWG Service Won't Start
```bash
# Check kernel module
lsmod | grep amneziawg
sudo modprobe amneziawg

# Check service status
systemctl status awg-quick@awg0
journalctl -u awg-quick@awg0 -f

# Verify configuration
awg show awg0
```

#### DPI Protection Not Working
```bash
# Test DPI effectiveness
./wg-warp-amnezia-manager.sh dpi-test

# Regenerate Magic Headers
./wg-warp-amnezia-manager.sh regen-magic

# Check Magic Headers configuration
./wg-warp-amnezia-manager.sh show-magic
```

#### Client Connection Issues
```bash
# Verify client is using AmneziaWG (not standard WireGuard)
# Check Magic Headers match between server and client
./wg-warp-amnezia-manager.sh show-client

# Test server connectivity
./wg-warp-amnezia-manager.sh test

# Check peer status
awg show awg0
```

#### WARP Connection Problems
```bash
# Test WARP in namespace
ip netns exec warp ping -c 1 1.1.1.1
ip netns exec warp wg show wgcf

# Update WARP configuration
./wg-warp-amnezia-manager.sh update-warp

# Check namespace status
ip netns list | grep warp
```

### Recovery Procedures

#### Service Recovery
```bash
# Automatic health check and recovery
./wg-warp-amnezia-manager.sh health-check

# Manual service restart sequence
systemctl restart warp-netns.service
sleep 5
systemctl restart awg-quick@awg0
```

#### Configuration Recovery
```bash
# List available backups
ls -la /opt/wireguard-backup/

# Restore from backup
./wg-warp-amnezia-manager.sh restore-config /opt/wireguard-backup/backup-YYYYMMDD_HHMMSS

# Emergency DPI disable
./wg-warp-amnezia-manager.sh disable-dpi
```

## 📚 Advanced Usage

### Custom Magic Headers Deployment
```bash
# Deploy with specific Magic Headers for your network
sudo AWG_H1=3141592653 AWG_H2=2718281828 AWG_H3=1414213562 AWG_H4=1732050808 \
     AWG_S1=89 AWG_S2=64 AWG_JC=5 \
     ./wireguard-warp-amnezia-production.sh
```

### Multiple Protection Layers
```bash
# Triple protection: AmneziaWG + Phantun + WARP
sudo ENABLE_DPI_PROTECTION=true ENABLE_OBFUSCATION=true OBFUSCATION_TYPE=phantun \
     ./wireguard-warp-amnezia-production.sh
```

### Monitoring Integration
```bash
# Enable Prometheus metrics for monitoring
sudo ENABLE_MONITORING=true ./wireguard-warp-amnezia-production.sh

# Access metrics
curl http://localhost:9586/metrics | grep amneziawg
```

### Scheduled Magic Headers Rotation
```bash
# Add to crontab for weekly Magic Headers regeneration
echo "0 2 * * 0 /path/to/wg-warp-amnezia-manager.sh regen-magic >/dev/null 2>&1" | crontab -
```

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests for any improvements.

### Development Setup
```bash
# Clone the repository
git clone https://github.com/tag7689/wireguard-warp-amnezia-suite.git
cd wireguard-warp-amnezia-suite

# Make scripts executable
chmod +x *.sh

# Test in a VM environment first
```

### Reporting Issues
Please include:
- Operating system and kernel version
- AmneziaWG version and kernel module status
- Magic Headers configuration (if relevant)
- Error messages and logs
- Steps to reproduce
- Network environment details

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [WireGuard](https://www.wireguard.com/) - Fast, modern, secure VPN tunnel
- [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module) - WireGuard fork with DPI protection
- [Cloudflare WARP](https://developers.cloudflare.com/warp-client/) - Privacy-focused VPN service
- [wgcf](https://github.com/ViRb3/wgcf) - Unofficial Cloudflare WARP CLI tool
- [Amnezia VPN](https://amneziavpn.org) - The team behind AmneziaWG Magic Headers technology
- The open-source community for continuous improvements and feedback

## ⭐ Support

If you find this project helpful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting issues
- 🔧 Contributing improvements
- 📢 Sharing with others
- 💬 Joining discussions about DPI bypassing techniques

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/tag7689/wireguard-warp-amnezia-suite/issues)
- **Discussions**: [GitHub Discussions](https://github.com/tag7689/wireguard-warp-amnezia-suite/discussions)
- **Documentation**: [Wiki](https://github.com/tag7689/wireguard-warp-amnezia-suite/wiki)
- **DPI Protection Guide**: See our comprehensive guide on Magic Headers configuration

---

**Disclaimer**: This project is not affiliated with WireGuard, AmneziaVPN, or Cloudflare. Use at your own risk and ensure compliance with your local laws and terms of service. The DPI protection features are designed for legitimate privacy needs and circumventing censorship in restricted networks.
