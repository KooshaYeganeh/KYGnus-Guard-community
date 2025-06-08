# In config.py
import tempfile  # Add this import at the top

SESSION_TYPE = 'filesystem'  # or 'redis', 'memcached', etc.
SESSION_FILE_DIR=tempfile.mkdtemp()
SESSION_PERMANENT=False
PERMANENT_SESSION_LIFETIME=3600
MAX_CONTENT_LENGTH=16 * 1024 * 1024
SSH_HOST="192.168.1.10"
SSH_PORT=22
SSH_USERNAME="koosha"
SSH_PASSWORD="K102030k"
SSH_KEY=None
Hermes_SCAN_PATHS=['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc', '/tmp' , '/' , '/home']
YARA_RULES_DIR='.'
QUARANTINE_DIR='/tmp/quarantine'
LOG_DIR='/tmp/Hermes'
SURICATA_ENABLED=False,
SURICATA_INTERFACE='eth0'
SURICATA_RULES_DIR='/etc/suricata/rules'
SURICATA_LOGS='/var/log/suricata'
SURICATA_DIR='/etc/suricata'
FAIL2BAN_ENABLED=False
FAIL2BAN_JAILS=['sshd', 'apache', 'nginx']
