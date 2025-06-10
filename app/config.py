# In config.py
import tempfile  # Add this import at the top
import os



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
QUARANTINE_DIR='./tmp/quarantine'
if not os.path.exists(QUARANTINE_DIR):
    try:
        os.makedirs(QUARANTINE_DIR)
        print(f"Directory '{QUARANTINE_DIR}' created")
    except OSError as error:
        print(f"Creation of directory '{QUARANTINE_DIR}' failed: {error}")
else:
    print(f"Directory '{QUARANTINE_DIR}' already exists")

LOG_DIR='./tmp/Hermes'

if not os.path.exists(LOG_DIR):
    try:
        os.makedirs(LOG_DIR)
        print(f"Directory '{LOG_DIR}' created")
    except OSError as error:
        print(f"Creation of directory '{LOG_DIR}' failed: {error}")
else:
    print(f"Directory '{LOG_DIR}' already exists")


SURICATA_ENABLED=False,
SURICATA_INTERFACE='eth0'
SURICATA_RULES_DIR='/etc/suricata/rules'
SURICATA_LOGS='/var/log/suricata'
SURICATA_DIR='/etc/suricata'
FAIL2BAN_ENABLED=False
FAIL2BAN_JAILS=['sshd', 'apache', 'nginx']
