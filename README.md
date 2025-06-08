
# Hermes

A Flask-based web application to manage and monitor security on remote Linux servers via SSH from both Linux and Windows systems.

![hermes](hermes.png)

## Features

- **Dashboard**: Comprehensive system overview with security status
- **Antivirus Scanning**: Integration with ClamAV, rkhunter, chkrootkit, and YARA
- **Process Monitoring**: View and manage running processes with malicious activity detection
- **Network Monitoring**: Analyze active connections and flag suspicious ports/IPs
- **File Integrity Monitoring**: File hash verification and quarantine capabilities
- **Log Management**: Centralized view of security logs
- **Service Management**: Control system services and detect suspicious ones
- **Firewall Management**: Configure firewall rules and Fail2Ban
- **Kernel Module Analysis**: Detect malicious or vulnerable kernel modules
- **IDS/IPS Integration**: Suricata management for intrusion detection/prevention
- **Authentication**: Secure login with role-based access control

## Prerequisites

- Python 3.9+
- SSH access to target Linux servers
- Required Python packages (see Installation)
- On target servers:
  - SSH server running
  - sudo privileges for the SSH user
  - Security tools (optional but recommended):
    - ClamAV
    - rkhunter
    - chkrootkit
    - YARA
    - Suricata
    - Fail2Ban

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/KooshaYeganeh/Hermes.git
   cd Hermes
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/MacOS
   venv\Scripts\activate     # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure the application:
   - Copy `config.example.py` to `config.py`
   - Edit `config.py` with your SSH credentials and settings

## Configuration

Edit `config.py` with your specific settings:

```python
# SSH Configuration
SSH_HOST = 'your.server.ip'
SSH_PORT = 22
SSH_USERNAME = 'your_username'
SSH_PASSWORD = 'your_password'  # Or use SSH key
SSH_KEY = '/path/to/private/key'  # Set to None if using password

# Security Tools Configuration
EDR_SCAN_PATHS = ['/bin', '/usr/bin', '/sbin', '/usr/sbin']
YARA_RULES_DIR = '/usr/local/share/yara-rules'
QUARANTINE_DIR = '/var/quarantine'
LOG_DIR = '/var/log/edr'

# Suricata Configuration
SURICATA_ENABLED = True
SURICATA_INTERFACE = 'eth0'
SURICATA_RULES_DIR = '/etc/suricata/rules'
SURICATA_LOGS = '/var/log/suricata'
SURICATA_DIR = '/etc/suricata'

# Fail2Ban Configuration
FAIL2BAN_ENABLED = True
FAIL2BAN_JAILS = ['ssh', 'apache', 'nginx']
```

## Usage

1. Start the application:
   ```bash
   python main_linux.py
   ```

2. Access the web interface at `http://localhost:5005`

3. Default credentials:
   - Username: `admin`
   - Password: `admin` (change immediately after first login)

## Key Functionality

### Dashboard
- System information overview
- Security services status
- Recent security events
- Security alerts

### Antivirus Scanning
- Quick and full system scans
- Multiple scanner integration
- Quarantine management
- Signature updates

### Process Monitoring
- Real-time process listing
- Suspicious process detection
- Process termination capability

### Network Monitoring
- Active connections view
- Listening ports analysis
- Malicious IP/port detection

### Kernel Security
- Loaded module analysis
- Suspicious module detection
- Kernel configuration review
- Module signing verification

### IDS/IPS Management
- Suricata control
- Rule management
- Alert monitoring
- Live log streaming

## Security Best Practices

1. Change default admin credentials immediately
2. Use SSH keys instead of passwords when possible
3. Regularly update the application and dependencies
4. Restrict access to the web interface (firewall rules)
5. Monitor application logs regularly
6. Keep target server security tools updated

## Troubleshooting

**SSH Connection Issues:**
- Verify SSH credentials in config.py
- Check network connectivity to target server
- Ensure SSH service is running on target
- Verify firewall rules allow SSH connections

**Permission Errors:**
- Ensure the SSH user has sudo privileges
- Verify proper permissions on quarantine directory
- Check SELinux/AppArmor policies if applicable

**Tool-Specific Issues:**
- Verify required security tools are installed on target
- Check tool configurations on target server
- Review application logs for specific error messages

## License

[GPL3](LICENSE)

## Contributing

Contributions are welcome! Please open an issue or pull request for any bugs or feature requests.

