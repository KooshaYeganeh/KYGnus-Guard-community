# myEDR - Linux Endpoint Detection & Response

![License](https://img.shields.io/badge/License-GPLv3-blue.svg)

A customizable EDR solution offering both minimal protection and full enterprise-grade security for Linux systems.

## Key Features

### Deployment Options
- **Minimal EDR**: Lightweight monitoring (<5% CPU) with essential detection
- **Full Customizable**: Enterprise features with granular control
- **Hybrid Mode**: Mix and match components as needed

### Security Capabilities
✔ Real-time process monitoring  
✔ File integrity checking  
✔ Threat intelligence integration  
✔ Automated containment  
✔ Compliance reporting  
✔ Centralized management (enterprise version)

## Installation

### Quick Install (Minimal EDR)
```bash
curl -s https://example.com/install-myedr | bash -s -- --minimal
```

### Full Install (All Features)
```bash
curl -s https://example.com/install-myedr | bash -s -- --full
```

### Manual Installation
1. Download package:
   ```bash
   wget https://example.com/myedr-latest.tar.gz
   tar -xzf myedr-latest.tar.gz
   cd myedr/
   ```
2. Run installer:
   ```bash
   sudo ./install.sh
   ```

## Removal
```bash
sudo /opt/myedr/uninstall.sh
# Or for complete removal:
sudo /opt/myedr/uninstall.sh --purge
```

## Command Reference

### Core Commands
| Command | Description |
|---------|-------------|
| `myedr --scan PATH` | Scan directory/files |
| `myedr --monitor` | Start real-time monitoring |
| `myedr --status` | Show protection status |

### EDR Features
| Command | Description |
|---------|-------------|
| `myedr --baseline` | Create system baseline (what's this?) |
| `myedr --check-deviations` | Compare against baseline |
| `myedr --threat-hunt` | Active threat hunting |

### Management
| Command | Description |
|---------|-------------|
| `myedr --install-service` | Install as systemd service |
| `myedr --uninstall` | Remove myEDR |
| `myedr --update` | Fetch latest signatures |

## About Key Features

### System Baseline (`--baseline`)
Creates a snapshot of your system including:
- All file hashes and permissions
- Running processes
- Network configuration
- User accounts
- Installed packages

Used as reference for detecting changes during `--check-deviations`.

### Monitoring Modes
| Mode | CPU Usage | Protection Level | Best For |
|------|----------|------------------|----------|
| Minimal | 3-5% | Basic threats | Low-power devices |
| Standard | 5-15% | Most attacks | General servers |
| Full | 15-30% | Advanced threats | Critical systems |

## Configuration

Edit `/etc/myedr/config.yaml`:

```yaml
# Minimal EDR Example
mode: minimal
scan_schedule: daily

# Full EDR Example
mode: full
threat_intel:
  enabled: true
  api_url: "https://ti.example.com/api"
response:
  auto_contain: medium+
logging:
  siem_enabled: true
```

## Usage Examples

1. **Basic Protection**:
   ```bash
   myedr --install-service --mode minimal
   ```

2. **Enterprise Deployment**:
   ```bash
   myedr --install-service --mode full \
         --set threat_intel.api_url="https://ti.corp.com/v2" \
         --set response.auto_contain=high
   ```

3. **On-Demand Scanning**:
   ```bash
   myedr --scan /var/www --type deep
   ```

## Support Levels

| Tier | Includes | Response Time |
|------|----------|---------------|
| Community | Basic support | Best effort |
| Professional | Configuration help | <24 hours |
| Enterprise | 24/7 SOC integration | <1 hour |

**Contact:** security-support@example.com

## FAQ

**Q: How does baseline help security?**  
A: Baselines enable detection of unexpected changes - like when attackers modify system files.

**Q: Can I run this alongside other AV?**  
A: Yes, myEDR is designed to complement existing security tools.

**Q: What's the minimum supported OS?**  
A: Linux kernel 3.10+ (CentOS 7+, Ubuntu 16.04+)

