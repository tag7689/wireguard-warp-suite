# wireguard-warp-suite
This a script created by perplexity.ai fufilled functions from my request for deploying a WireGuard VPN Server on VPS.

# WireGuard + WARP Production Deployment Suite

A comprehensive, production-ready solution for deploying and managing WireGuard VPN servers with Cloudflare WARP integration on Ubuntu/Debian systems.

## 🌟 Features

### Core Functionality
- **One-Click Deployment**: Automated WireGuard + WARP server setup
- **Network Namespace Isolation**: WARP runs in isolated network namespace for maximum stability
- **Production-Grade Security**: UFW firewall, fail2ban integration, and comprehensive security hardening
- **Self-Healing System**: Automated health checks and service recovery
- **DNS Management**: Easy DNS configuration changes with service restart
- **Traffic Obfuscation**: Optional phantun/udp2raw/wstunnel support

### Management Tools
- **Enhanced CLI Manager**: Comprehensive management interface with 15+ commands
- **Client Management**: Add, remove, and manage WireGuard clients with QR codes
- **Real-time Monitoring**: Service status, connection quality, and exit IP verification
- **Backup & Restore**: Automated configuration backups with one-click restore
- **Health Diagnostics**: Detailed system health checks and troubleshooting

### Advanced Features
- **Prometheus Monitoring**: Optional metrics export for Grafana integration
- **Systemd Integration**: Proper service dependencies and auto-restart capabilities
- **Log Management**: Structured logging with automatic rotation
- **IP Protection**: Hide your VPS real IP behind Cloudflare's network

## 🚀 Quick Start

### Prerequisites
- Ubuntu 20.04+ or Debian 11+ VPS
- Root access
- Active internet connection

### Installation

```bash
# Download the deployment script
wget https://github.com/yourusername/wireguard-warp-suite/raw/main/wireguard-warp-production.sh

# Make it executable
chmod +x wireguard-warp-production.sh

# Run the installation
sudo ./wireguard-warp-production.sh
```

### With Additional Features

```bash
# Enable obfuscation (phantun)
sudo ENABLE_OBFUSCATION=true OBFUSCATION_TYPE=phantun ./wireguard-warp-production.sh

# Enable monitoring
sudo ENABLE_MONITORING=true ./wireguard-warp-production.sh

# Both
sudo ENABLE_OBFUSCATION=true ENABLE_MONITORING=true ./wireguard-warp-production.sh
```

## 🛠 Management

### Download Management Tool

```bash
# Download the enhanced management tool
wget https://github.com/yourusername/wireguard-warp-suite/raw/main/wg-warp-manager-enhanced.sh
chmod +x wg-warp-manager-enhanced.sh
```

### Common Commands

```bash
# Check system status
./wg-warp-manager-enhanced.sh status

# Add a new client
./wg-warp-manager-enhanced.sh add-client

# Change DNS settings
./wg-warp-manager-enhanced.sh change-dns

# Test connectivity
./wg-warp-manager-enhanced.sh test

# View logs
./wg-warp-manager-enhanced.sh logs

# Backup configuration
./wg-warp-manager-enhanced.sh backup-config
```

## 📋 Available Commands

### Basic Operations
- `status` - Display comprehensive service status
- `test` - Run connectivity and performance tests
- `restart-all` - Restart all services safely
- `logs` - View system logs
- `ip-check` - Verify IP protection is working

### Client Management
- `add-client` - Add new WireGuard client with auto IP assignment
- `list-clients` - Show all clients and connection status
- `remove-client` - Safely remove client configuration
- `show-client` - Display client config and QR code

### Configuration Management
- `change-dns` - Modify DNS settings for all clients
- `backup-config` - Create configuration backup
- `restore-config` - Restore from backup

### Advanced Features
- `health-check` - Run comprehensive health diagnostics
- `update-warp` - Update WARP configuration
- `help` - Show detailed help information

## 🏗 Architecture

```
Client → WireGuard Server → [Network Namespace: WARP] → Internet
```

### Key Components

1. **WireGuard Server** (`wg0`)
   - Handles client connections
   - Routes traffic to WARP namespace

2. **WARP Namespace** (`warp`)
   - Isolated Cloudflare WARP connection
   - Protects server's real IP address

3. **Health Check System**
   - Monitors service status
   - Automatic failure recovery
   - Detailed logging

4. **Security Layer**
   - UFW firewall configuration
   - fail2ban brute force protection
   - Secure file permissions

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_OBFUSCATION` | `false` | Enable traffic obfuscation |
| `OBFUSCATION_TYPE` | `phantun` | Obfuscation method (phantun/udp2raw/wstunnel) |
| `OBFUSCATION_PORT` | `4567` | Obfuscation listening port |
| `ENABLE_MONITORING` | `true` | Enable Prometheus metrics |
| `SSH_PORT` | `22` | SSH port for firewall rules |

### Files and Directories

```
/etc/wireguard/
├── wg0.conf                 # Server configuration
├── wg0.key                  # Server private key
├── wg0.pub                  # Server public key
├── clients/                 # Client configurations
│   ├── client01.conf
│   └── client01_qr.png
└── scripts/                 # PostUp/PostDown scripts
    ├── postup.sh
    └── predown.sh

/opt/wireguard-backup/       # Configuration backups
/var/log/                    # Log files
├── wireguard-warp-deploy.log
├── wireguard-warp-healthcheck.log
└── wg-warp-manager.log
```

## 📊 Monitoring

### Service Status
```bash
# Check all services
systemctl status wg-quick@wg0
systemctl status warp-netns.service
systemctl status wireguard-warp-healthcheck.timer
```

### Health Check Logs
```bash
# View health check logs
tail -f /var/log/wireguard-warp-healthcheck.log

# Manual health check
/usr/local/bin/wireguard-warp-healthcheck.py
```

### Prometheus Metrics (Optional)
```bash
# View metrics
curl http://localhost:9586/metrics
```

## 🔒 Security Features

### Firewall Configuration
- **Default Deny**: All incoming/outgoing traffic blocked by default
- **Selective Allow**: Only necessary ports opened
- **SSH Protection**: Configurable SSH access restrictions
- **Service-Specific Rules**: Tailored rules for WireGuard and obfuscation

### fail2ban Protection
- **SSH Brute Force**: Automatic IP banning for failed SSH attempts
- **Configurable Thresholds**: Customizable ban times and retry limits
- **Whitelist Support**: Trusted IP exemptions

### File Security
- **Restricted Permissions**: 600/700 permissions on sensitive files
- **Key Protection**: Private keys accessible only to root
- **Config Isolation**: Separate directories for different components

## 🌐 DNS Options

The system supports multiple DNS providers:

| Provider | IP Address | Features |
|----------|------------|----------|
| Cloudflare | 1.1.1.1 | Fast, privacy-focused, DoH/DoT support |
| Google | 8.8.8.8 | Reliable, high availability |
| Quad9 | 9.9.9.9 | Malware filtering, security-focused |
| OpenDNS | 208.67.222.222 | Content filtering, parental controls |
| AdGuard | 94.140.14.14 | Ad blocking, privacy-friendly |

## 🚨 Troubleshooting

### Common Issues

#### Services Won't Start
```bash
# Check service status
./wg-warp-manager-enhanced.sh status

# View detailed logs
journalctl -u wg-quick@wg0 -f
journalctl -u warp-netns.service -f

# Restart services
./wg-warp-manager-enhanced.sh restart-all
```

#### WARP Connection Issues
```bash
# Test WARP connectivity
ip netns exec warp ping -c 1 1.1.1.1

# Check WARP interface
ip netns exec warp wg show wgcf

# Update WARP configuration
./wg-warp-manager-enhanced.sh update-warp
```

#### Client Connection Problems
```bash
# Verify client configuration
./wg-warp-manager-enhanced.sh show-client

# Check server peer status
wg show wg0

# Test DNS resolution
./wg-warp-manager-enhanced.sh test
```

### Recovery Procedures

#### Service Recovery
```bash
# Automatic health check
./wg-warp-manager-enhanced.sh health-check

# Manual service restart
systemctl restart warp-netns.service
systemctl restart wg-quick@wg0
```

#### Configuration Recovery
```bash
# List available backups
ls -la /opt/wireguard-backup/

# Restore from backup
./wg-warp-manager-enhanced.sh restore-config /opt/wireguard-backup/backup-YYYYMMDD_HHMMSS
```

## 📚 Advanced Usage

### Custom DNS Configuration
```bash
# Interactive DNS change
./wg-warp-manager-enhanced.sh change-dns

# The tool will:
# 1. Show current DNS settings
# 2. Offer popular DNS options
# 3. Test new DNS availability
# 4. Update all client configs
# 5. Restart services
# 6. Verify changes
```

### Backup Management
```bash
# Manual backup
./wg-warp-manager-enhanced.sh backup-config

# Scheduled backups (add to crontab)
0 2 * * * /path/to/wg-warp-manager-enhanced.sh backup-config >/dev/null 2>&1
```

### Monitoring Integration
```bash
# Prometheus metrics
curl -s http://localhost:9586/metrics | grep wireguard

# Grafana dashboard setup
# Import dashboard ID: [dashboard-id] or use provided JSON
```

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests for any improvements.

### Development Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/wireguard-warp-suite.git
cd wireguard-warp-suite

# Make scripts executable
chmod +x *.sh

# Test in a VM environment first
```

### Reporting Issues
Please include:
- Operating system and version
- Error messages and logs
- Steps to reproduce
- Expected vs actual behavior

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [WireGuard](https://www.wireguard.com/) - Fast, modern, secure VPN tunnel
- [Cloudflare WARP](https://developers.cloudflare.com/warp-client/) - Privacy-focused VPN service
- [wgcf](https://github.com/ViRb3/wgcf) - Unofficial Cloudflare WARP CLI tool
- [phantun](https://github.com/dndx/phantun) - Transforms UDP stream into TCP
- The open-source community for continuous improvements and feedback

## ⭐ Support

If you find this project helpful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting issues
- 🔧 Contributing improvements
- 📢 Sharing with others

---

**Disclaimer**: This project is not affiliated with WireGuard or Cloudflare. Use at your own risk and ensure compliance with your local laws and terms of service.
