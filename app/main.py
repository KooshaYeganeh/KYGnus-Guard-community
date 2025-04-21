"""
LinuxAV-Solutions Enterprise EDR Flask Application
Version: 5.0
Enhanced Features: 
- ClamAV, Maldet, Rkhunter, Chkrootkit, YARA scanning
- YARA rules integration
- Suricata IDS/IPS with live JSON log monitoring
- Fail2Ban integration
- Advanced system log management
- Firewall management with firewall-cmd
- Process and network monitoring
- Configuration management
"""

import re
from werkzeug.utils import secure_filename as werkzeug_secure_filename
from flask import Flask, jsonify, request, render_template , Response
import os
import subprocess
import json
import time
import psutil
import hashlib
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import socket
import requests
from functools import wraps
import yara
import pyinotify
import threading
import glob
import re
import shutil
from collections import defaultdict
import config
import json
import signal



app = Flask(__name__)


app.config['VERSION'] = '1.0.0'


# =============================================
# Configuration (Moved to config.py)
# =============================================
try:
    from config import EDRConfig
    app.config.from_object(EDRConfig)
except ImportError:
    # Fallback configuration
    class EDRConfig:
        # Directory Configuration
        APP_DIR = os.path.expanduser('~/.myEDR')
        LOG_DIR = os.path.join(APP_DIR, 'Log')
        QUARANTINE_DIR = os.path.join(APP_DIR, 'Quarantine')
        SIGNATURES_DIR = os.path.join(APP_DIR, 'Signatures')
        EDR_DIR = os.path.join(APP_DIR, 'EDR')
        BASELINE_DIR = os.path.join(EDR_DIR, 'baseline')
        CONFIG_DIR = os.path.join(EDR_DIR, 'config')
        RULES_DIR = os.path.join(EDR_DIR, 'rules')
        REPORT_DIR = os.path.join(APP_DIR, 'Reports')
        SURICATA_DIR = os.path.join(APP_DIR, 'Suricata')
        SURICATA_RULES = os.path.join(SURICATA_DIR, 'rules')
        SURICATA_LOGS = os.path.join(SURICATA_DIR, 'logs')
        YARA_RULES = os.path.join(APP_DIR, 'yara_rules')
        
        # Enterprise Configuration
        CENTRAL_MGMT_SERVER = "edr-mgmt.corporate.com"
        SIEM_SERVER = "siem.corporate.com:514"
        THREAT_INTEL_API = "https://ti.corporate.com/api/v1/check"
        MACHINE_ID = open('/etc/machine-id').read().strip() if os.path.exists('/etc/machine-id') else socket.gethostname()
        DEPLOYMENT_GROUP = "default"
        VERSION = "5.0.0"
        
        # Monitoring Configuration
        WATCH_FILES = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/crontab',
            '/var/spool/cron/'
        ]
        
        # Scanning Configuration
        SCAN_PATHS = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/tmp', '/var/www']
        SCAN_EXCLUDES = ['/proc', '/sys', '/dev']
        SCAN_INTERVAL = 86400  # Daily scans
        
        # YARA Configuration
        YARA_ENABLED = True
        YARA_RULE_FILES = ['malware_rules.yar', 'exploits.yar', 'packers.yar']
        
        # Suricata Configuration
        SURICATA_ENABLED = True
        SURICATA_INTERFACE = 'eth0'
        SURICATA_RULE_FILES = ['emerging-threats.rules', 'custom.rules']
        
        # Fail2Ban Configuration
        FAIL2BAN_ENABLED = True
        FAIL2BAN_JAILS = ['sshd', 'apache-auth']
        
        # Firewall Configuration
        FIREWALL_ENABLED = True
        FIREWALL_ZONE = 'public'
        FIREWALL_ALLOWED_PORTS = ['22/tcp', '80/tcp', '443/tcp']
    
    app.config.from_object(EDRConfig)

# =============================================
# Initialization
# =============================================

def init_directories():
    """Create all required directories and files"""
    dirs = [
        app.config['APP_DIR'],
        app.config['LOG_DIR'],
        app.config['QUARANTINE_DIR'],
        app.config['SIGNATURES_DIR'],
        app.config['EDR_DIR'],
        app.config['BASELINE_DIR'],
        app.config['CONFIG_DIR'],
        app.config['RULES_DIR'],
        app.config['REPORT_DIR']
    ]
    
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)
    
    # Initialize signature files
    signature_files = {
        'malware_signatures.txt': "# Malware signatures database\nd41d8cd98f00b204e9800998ecf8427e:TEST_SIGNATURE\n",
        'malicious_ips.txt': "# Known malicious IP addresses\n123.123.123.123\n",
        'suspicious_strings.txt': "# Suspicious strings\n/bin/sh\n/bin/bash\npython -c\n"
    }
    
    for filename, content in signature_files.items():
        if not os.path.exists(os.path.join(app.config['SIGNATURES_DIR'], filename)):
            with open(os.path.join(app.config['SIGNATURES_DIR'], filename), 'w') as f:
                f.write(content)
    
    # Initialize YARA rules
    if not os.path.exists(os.path.join(app.config['YARA_RULES'], 'malware_rules.yar')):
        with open(os.path.join(app.config['YARA_RULES'], 'malware_rules.yar'), 'w') as f:
            f.write("""
rule Malware_Generic {
    meta:
        description = "Detects generic malware characteristics"
        severity = "high"
    strings:
        $magic = { 4D 5A }  // MZ header
        $str1 = "malicious" nocase
        $str2 = "exploit" nocase
    condition:
        $magic at 0 and ($str1 or $str2)
}
""")
    
    # Initialize EDR rules
    rule_files = {
        'process_rules.txt': "# EDR Process Monitoring Rules\nnc:high:alert\nsocat:high:alert\nminer:critical:kill\n",
        'file_rules.txt': "# EDR File Monitoring Rules\n/etc/passwd:alert:critical\n/etc/shadow:alert:critical\n",
        'network_rules.txt': "# Network Connection Rules\n23.21.45.67:critical:block\n185.143.223.42:high:alert\n"
    }
    
    for filename, content in rule_files.items():
        if not os.path.exists(os.path.join(app.config['RULES_DIR'], filename)):
            with open(os.path.join(app.config['RULES_DIR'], filename), 'w') as f:
                f.write(content)
    
    # Initialize event log
    if not os.path.exists(os.path.join(app.config['EDR_DIR'], 'events.log')):
        with open(os.path.join(app.config['EDR_DIR'], 'events.log'), 'w') as f:
            f.write("# LinuxAV-Solutions EDR Event Log\n")





SCAN_LOG_FILE = os.path.join(app.config['LOG_DIR'], 'scan_results.log')

def log_scan_result(scan_type, scan_path, result):
    """Log scan results to a file"""
    try:
        with open(SCAN_LOG_FILE, 'a') as f:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'type': scan_type,
                'path': scan_path,
                'results': result,
                'status': 'infected' if result else 'clean'
            }
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        app.logger.error(f"Failed to log scan result: {str(e)}")

def get_last_scan_results(limit=10):
    """Get last scan results from log file"""
    try:
        if not os.path.exists(SCAN_LOG_FILE):
            return []
        
        with open(SCAN_LOG_FILE, 'r') as f:
            lines = f.readlines()
        
        # Get last 'limit' scans, most recent first
        scans = []
        for line in reversed(lines[-limit:]):
            try:
                scans.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
        
        return scans
    except Exception as e:
        app.logger.error(f"Failed to read scan results: {str(e)}")
        return []




def get_system_services():
    """Get list of all system services with their status"""
    services = []
    try:
        # For systemd systems
        if os.path.exists('/run/systemd/system'):
            cmd = ['systemctl', 'list-units', '--type=service', '--no-pager', '--no-legend']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        service = {
                            'name': parts[0],
                            'loaded': parts[1],
                            'active': parts[2],
                            'status': parts[3],
                            'description': ' '.join(parts[4:]) if len(parts) > 4 else ''
                        }
                        services.append(service)
        else:
            # For sysvinit systems
            cmd = ['service', '--status-all']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    match = re.match(r'\[ (\+|\-) \]\s+(\S+)', line.strip())
                    if match:
                        status = 'active' if match.group(1) == '+' else 'inactive'
                        services.append({
                            'name': match.group(2),
                            'loaded': 'loaded',
                            'active': status,
                            'status': status,
                            'description': ''
                        })
    except Exception as e:
        log_event("ERROR", "high", "Failed to get service list", {'error': str(e)})
    
    return services

def manage_service(service_name, action):
    """Manage a system service (start/stop/restart)"""
    valid_actions = ['start', 'stop', 'restart', 'enable', 'disable']
    if action not in valid_actions:
        return False, "Invalid action"
    
    try:
        # For systemd systems
        if os.path.exists('/run/systemd/system'):
            cmd = ['systemctl', action, service_name]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                log_event("SERVICE", "info", f"Service {service_name} {action}ed")
                return True, f"Service {service_name} {action}ed successfully"
            else:
                error_msg = result.stderr.strip() or f"Failed to {action} service {service_name}"
                log_event("ERROR", "high", error_msg)
                return False, error_msg
        else:
            # For sysvinit systems
            if action in ['enable', 'disable']:
                return False, "Enable/disable not supported on sysvinit systems"
            
            cmd = ['service', service_name, action]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                log_event("SERVICE", "info", f"Service {service_name} {action}ed")
                return True, f"Service {service_name} {action}ed successfully"
            else:
                error_msg = result.stderr.strip() or f"Failed to {action} service {service_name}"
                log_event("ERROR", "high", error_msg)
                return False, error_msg
    except Exception as e:
        error_msg = f"Error managing service {service_name}: {str(e)}"
        log_event("ERROR", "high", error_msg)
        return False, error_msg

# =============================================
# Service Management API Endpoints
# =============================================



def log_event(event_type, level, message, extra_info=None):
    # This is just a placeholder. Implement logging logic here.
    print(f"[{event_type}] [{level}] {message}")
    if extra_info:
        print(f"Additional Info: {extra_info}")


def quarantine_file(file):
    # Placeholder for quarantining logic (e.g., moving the file to a quarantine directory)
    print(f"File quarantined: {file}")

# Initialize logging
def setup_logging():
    """Configure application logging"""
    log_file = os.path.join(app.config['LOG_DIR'], 'edr.log')
    handler = RotatingFileHandler(log_file, maxBytes=1000000, backupCount=5)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

# =============================================
# Enhanced Scanning Functions
# =============================================

def run_clamav_scan(path):
    """Run ClamAV scan on specified path"""
    try:
        cmd = ['clamscan', '-r', '--infected', '--log=' + os.path.join(app.config['LOG_DIR'], 'clamav.log')]
        cmd.extend(path.split())
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 1:
            infected = re.findall(r': (.+) FOUND', result.stdout)
            for file in infected:
                log_event("SCAN", "high", f"ClamAV detected malware: {file}")
                quarantine_file(file)
            return infected
        return []
    except Exception as e:
        log_event("ERROR", "high", "ClamAV scan failed", {'error': str(e)})
        return []

def run_maldet_scan(path):
    """Run Linux Malware Detect scan"""
    try:
        cmd = ['/usr/local/sbin/maldet', '-a', path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 1:
            infected = re.findall(r'SCAN SUMMARY: (.+) hits', result.stdout)
            if infected and infected[0].isdigit() and int(infected[0]) > 0:
                log_event("SCAN", "high", f"Maldet detected {infected[0]} threats")
                return int(infected[0])
        return 0
    except Exception as e:
        log_event("ERROR", "high", "Maldet scan failed", {'error': str(e)})
        return 0

def run_rkhunter_scan():
    """Run Rootkit Hunter scan"""
    try:
        cmd = ['rkhunter', '--check', '--sk', '--rwo']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        warnings = re.findall(r'Warning: (.+)', result.stdout)
        for warning in warnings:
            log_event("SCAN", "high", f"Rkhunter warning: {warning}")
        return warnings
    except Exception as e:
        log_event("ERROR", "high", "Rkhunter scan failed", {'error': str(e)})
        return []

def run_chkrootkit_scan():
    """Run chkrootkit scan"""
    try:
        cmd = ['chkrootkit']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        infected = re.findall(r'INFECTED: (.+)', result.stdout)
        for file in infected:
            log_event("SCAN", "critical", f"chkrootkit detected infection: {file}")
        return infected
    except Exception as e:
        log_event("ERROR", "high", "chkrootkit scan failed", {'error': str(e)})
        return []

def compile_yara_rules():
    """Compile YARA rules from rule files"""
    try:
        rule_files = []
        for rule_file in app.config['YARA_RULE_FILES']:
            rule_path = os.path.join(app.config['YARA_RULES'], rule_file)
            if os.path.exists(rule_path):
                rule_files.append(rule_path)
        
        if rule_files:
            rules = yara.compile(filepaths={
                os.path.basename(f): f for f in rule_files
            })
            return rules
        return None
    except Exception as e:
        log_event("ERROR", "high", "YARA rule compilation failed", {'error': str(e)})
        return None

def yara_scan_file(file_path, yara_rules):
    """Scan a file with YARA rules"""
    try:
        matches = yara_rules.match(file_path)
        if matches:
            for match in matches:
                log_event("SCAN", "high", f"YARA rule match: {match.rule}", {
                    'file': file_path,
                    'tags': match.tags,
                    'meta': match.meta
                })
            return matches
        return []
    except Exception as e:
        log_event("ERROR", "medium", f"YARA scan failed for {file_path}", {'error': str(e)})
        return []

def full_system_scan():
    """Run comprehensive system scan with all tools"""
    scan_results = {
        'clamav': [],
        'maldet': 0,
        'rkhunter': [],
        'chkrootkit': [],
        'yara': []
    }
    
    # Run ClamAV scan
    for path in app.config['SCAN_PATHS']:
        if os.path.exists(path):
            scan_results['clamav'].extend(run_clamav_scan(path))
    
    # Run Maldet scan
    scan_results['maldet'] = run_maldet_scan(' '.join(app.config['SCAN_PATHS']))
    
    # Run rkhunter and chkrootkit
    scan_results['rkhunter'] = run_rkhunter_scan()
    scan_results['chkrootkit'] = run_chkrootkit_scan()
    
    # Run YARA scan if enabled
    if app.config['YARA_ENABLED']:
        yara_rules = compile_yara_rules()
        if yara_rules:
            for path in app.config['SCAN_PATHS']:
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        matches = yara_scan_file(file_path, yara_rules)
                        if matches:
                            scan_results['yara'].append({
                                'file': file_path,
                                'matches': [str(m) for m in matches]
                            })
    
    log_event("SCAN", "info", "Completed full system scan", {'results': scan_results})
    return scan_results

# =============================================
# Suricata Integration
# =============================================

def start_suricata():
    """Start Suricata IDS/IPS"""
    if not app.config['SURICATA_ENABLED']:
        return False
    
    try:
        # Check if Suricata is already running
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'suricata':
                return True
        
        # Start Suricata
        cmd = [
            'suricata',
            '-c', os.path.join(app.config['SURICATA_DIR'], 'suricata.yaml'),
            '-i', app.config['SURICATA_INTERFACE'],
            '--set', f'default-rule-path={app.config["SURICATA_RULES"]}',
            '--set', f'rule-files={",".join(app.config["SURICATA_RULE_FILES"])}',
            '--set', f'log-dir={app.config["SURICATA_LOGS"]}'
        ]
        
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_event("SURICATA", "info", "Started Suricata IDS/IPS")
        return True
    except Exception as e:
        log_event("ERROR", "high", "Failed to start Suricata", {'error': str(e)})
        return False

def monitor_suricata_logs():
    """Monitor Suricata logs for alerts"""
    if not app.config['SURICATA_ENABLED']:
        return
    
    eve_log = os.path.join(app.config['SURICATA_LOGS'], 'eve.json')
    if not os.path.exists(eve_log):
        return
    
    try:
        # Get the current position in the log file
        current_pos = os.path.getsize(eve_log)
        
        while True:
            new_size = os.path.getsize(eve_log)
            if new_size > current_pos:
                with open(eve_log, 'r') as f:
                    f.seek(current_pos)
                    for line in f:
                        try:
                            alert = json.loads(line)
                            if alert['event_type'] == 'alert':
                                log_event("SURICATA", "high", "Suricata alert detected", {
                                    'signature': alert['alert']['signature'],
                                    'source_ip': alert.get('src_ip', 'unknown'),
                                    'dest_ip': alert.get('dest_ip', 'unknown'),
                                    'action': alert.get('action', 'unknown')
                                })
                        except json.JSONDecodeError:
                            continue
                    current_pos = f.tell()
            time.sleep(5)
    except Exception as e:
        log_event("ERROR", "high", "Suricata log monitoring failed", {'error': str(e)})

# =============================================
# Fail2Ban Integration
# =============================================

def configure_fail2ban():
    """Configure and manage Fail2Ban"""
    if not app.config['FAIL2BAN_ENABLED']:
        return False
    
    try:
        # Check if Fail2Ban is running
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'fail2ban-server':
                return True
        
        # Start Fail2Ban
        subprocess.run(['systemctl', 'start', 'fail2ban'], check=True)
        
        # Configure jails
        for jail in app.config['FAIL2BAN_JAILS']:
            subprocess.run(['fail2ban-client', 'add', jail], check=True)
            subprocess.run(['fail2ban-client', 'start', jail], check=True)
        
        log_event("FAIL2BAN", "info", "Fail2Ban configured and started")
        return True
    except Exception as e:
        log_event("ERROR", "high", "Fail2Ban configuration failed", {'error': str(e)})
        return False

# =============================================
# Firewall Management
# =============================================

def manage_firewall():
    """Configure firewall rules using firewall-cmd"""
    if not app.config['FIREWALL_ENABLED']:
        return False
    
    try:
        # Ensure firewall is running
        subprocess.run(['systemctl', 'start', 'firewalld'], check=True)
        
        # Set default zone
        subprocess.run(['firewall-cmd', '--set-default-zone=' + app.config['FIREWALL_ZONE']], check=True)
        
        # Remove all existing ports (start fresh)
        current_ports = subprocess.run(
            ['firewall-cmd', '--list-ports'],
            capture_output=True, text=True
        ).stdout.split()
        
        for port in current_ports:
            subprocess.run(['firewall-cmd', '--remove-port=' + port, '--permanent'], check=True)
        
        # Add allowed ports
        for port in app.config['FIREWALL_ALLOWED_PORTS']:
            subprocess.run(['firewall-cmd', '--add-port=' + port, '--permanent'], check=True)
        
        # Reload firewall
        subprocess.run(['firewall-cmd', '--reload'], check=True)
        
        log_event("FIREWALL", "info", "Firewall configured", {
            'zone': app.config['FIREWALL_ZONE'],
            'allowed_ports': app.config['FIREWALL_ALLOWED_PORTS']
        })
        return True
    except Exception as e:
        log_event("ERROR", "high", "Firewall configuration failed", {'error': str(e)})
        return False

# =============================================
# Enhanced System Monitoring
# =============================================

def check_system_logs():
    """Monitor system logs for suspicious activity"""
    suspicious_entries = []
    log_files = [
        '/var/log/auth.log',
        '/var/log/secure',
        '/var/log/syslog',
        '/var/log/messages'
    ]
    
    suspicious_patterns = [
        r'Failed password',
        r'authentication failure',
        r'POSSIBLE BREAK-IN ATTEMPT',
        r'Invalid user',
        r'root login',
        r'session opened for user root',
        r'SUCCESSFUL SU DO',
        r'error: maximum authentication attempts exceeded'
    ]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        for pattern in suspicious_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                suspicious_entries.append({
                                    'log_file': log_file,
                                    'entry': line.strip(),
                                    'pattern': pattern
                                })
                                log_event("LOG", "medium", "Suspicious log entry found", {
                                    'log_file': log_file,
                                    'entry': line.strip(),
                                    'pattern': pattern
                                })
            except Exception as e:
                log_event("ERROR", "medium", f"Failed to read log file {log_file}", {'error': str(e)})
    
    return suspicious_entries

def find_suspicious_files():
    """Find suspicious files in common directories"""
    suspicious_files = []
    
    # Check for hidden files in system directories
    for root_dir in ['/', '/etc', '/var', '/tmp', '/usr']:
        if os.path.exists(root_dir):
            for root, dirs, files in os.walk(root_dir):
                for file in files:
                    if file.startswith('.') and file not in ['.', '..']:
                        file_path = os.path.join(root, file)
                        suspicious_files.append({
                            'path': file_path,
                            'reason': 'Hidden file in system directory'
                        })
    
    # Check for world-writable files
    for root_dir in ['/', '/etc', '/var', '/usr']:
        if os.path.exists(root_dir):
            for root, dirs, files in os.walk(root_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        mode = os.stat(file_path).st_mode
                        if mode & 0o002:  # World-writable
                            suspicious_files.append({
                                'path': file_path,
                                'reason': 'World-writable file'
                            })
                    except:
                        continue
    
    # Check for suspicious file extensions
    suspicious_extensions = ['.php', '.pl', '.py', '.sh', '.cgi', '.bin']
    for root_dir in ['/tmp', '/var/tmp', '/dev/shm']:
        if os.path.exists(root_dir):
            for root, dirs, files in os.walk(root_dir):
                for file in files:
                    if any(file.endswith(ext) for ext in suspicious_extensions):
                        file_path = os.path.join(root, file)
                        suspicious_files.append({
                            'path': file_path,
                            'reason': 'Suspicious file extension in temp directory'
                        })
    
    return suspicious_files

# =============================================
# Enhanced Process and Network Monitoring
# =============================================

def analyze_processes():
    """Analyze running processes for anomalies"""
    suspicious_processes = []
    
    # Get baseline of normal processes (would need to be established first)
    normal_processes = set()
    if os.path.exists(os.path.join(app.config['BASELINE_DIR'], 'process_baseline.txt')):
        with open(os.path.join(app.config['BASELINE_DIR'], 'process_baseline.txt')) as f:
            normal_processes = set(line.strip() for line in f)
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
        try:
            proc_info = proc.info
            
            # Check for processes with deleted binaries
            if proc_info['exe'] and not os.path.exists(proc_info['exe']):
                suspicious_processes.append({
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'reason': 'Binary deleted but process still running',
                    'exe': proc_info['exe']
                })
            
            # Check for processes not in baseline
            if normal_processes and proc_info['name'] not in normal_processes:
                suspicious_processes.append({
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'reason': 'Process not in baseline',
                    'cmdline': proc_info['cmdline']
                })
            
            # Check for hidden processes (PID mismatch)
            try:
                cmdline = open(f"/proc/{proc_info['pid']}/cmdline").read()
                if not cmdline or '\x00' not in cmdline:
                    suspicious_processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'reason': 'Possible hidden process'
                    })
            except:
                pass
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return suspicious_processes

def get_suspicious_connections():
    """Get suspicious network connections"""
    suspicious = []
    known_bad_ports = [6667, 31337, 12345, 54321] + get_custom_malicious_ports()
    
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and hasattr(conn, 'raddr') and conn.raddr:
                if conn.raddr.port in known_bad_ports:
                    try:
                        proc = psutil.Process(conn.pid)
                        suspicious.append({
                            'pid': conn.pid,
                            'name': proc.name(),
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': 'danger',
                            'port': conn.raddr.port,
                            'process': proc.name()
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        suspicious.append({
                            'pid': conn.pid,
                            'name': 'Unknown',
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': 'danger',
                            'port': conn.raddr.port,
                            'process': 'Unknown'
                        })
    except Exception as e:
        app.logger.error(f"Error getting network connections: {str(e)}")
    
    return suspicious

# =============================================
# API Endpoints (Enhanced)
# =============================================

@app.route('/')
def dashboard():
    """Main dashboard endpoint"""
    services = get_system_services()
    
    context = {
        'status': 'running',
        'version': app.config['VERSION'],

        'endpoints': {
            '/logs': 'Get recent events',
            '/files': 'Check file changes',
            '/processes': 'List suspicious processes',
            '/connections': 'Check malicious connections',
            '/scan': 'Run a scan',
            '/quarantine': 'Manage quarantined files',
            '/suricata': 'Suricata status',
            '/fail2ban': 'Fail2Ban status',
            '/firewall': 'Firewall status',
            '/services': 'List all services'
        }
    }
    return render_template('index.html', **context)

@app.route('/scan/full', methods=['POST'])
def run_full_scan():
    """Run full system scan with all tools"""
    scan_results = full_system_scan()
    return jsonify(scan_results)

@app.route('/suricata/status')
def suricata_status():
    """Check Suricata status"""
    status = {
        'enabled': app.config['SURICATA_ENABLED'],
        'running': False,
        'alerts': []
    }
    
    if app.config['SURICATA_ENABLED']:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'suricata':
                status['running'] = True
                break
        
        # Get recent alerts
        eve_log = os.path.join(app.config['SURICATA_LOGS'], 'eve.json')
        if os.path.exists(eve_log):
            try:
                with open(eve_log, 'r') as f:
                    for line in f:
                        try:
                            alert = json.loads(line)
                            if alert.get('event_type') == 'alert':
                                status['alerts'].append(alert)
                                if len(status['alerts']) >= 10:  # Limit to 10 most recent
                                    break
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                log_event("ERROR", "medium", "Failed to read Suricata logs", {'error': str(e)})
    
    return jsonify(status)



@app.route('/ids')
def ids_dashboard():
    """IDS/IPS Management Dashboard"""
    status = {
        'enabled': app.config['SURICATA_ENABLED'],
        'running': False,
        'mode': 'IDS',  # Default mode
        'interface': app.config['SURICATA_INTERFACE'],
        'rules_count': 0
    }
    
    if app.config['SURICATA_ENABLED']:
        # Check if Suricata is running and get mode
        for proc in psutil.process_iter(['name', 'cmdline']):
            if proc.info['name'] == 'suricata':
                status['running'] = True
                cmdline = ' '.join(proc.info['cmdline'])
                if '--ips' in cmdline:
                    status['mode'] = 'IPS'
                break
        
        # Count rule files
        if os.path.exists(app.config['SURICATA_RULES_DIR']):  # Changed to use SURICATA_RULES_DIR
            status['rules_count'] = len([
                f for f in os.listdir(app.config['SURICATA_RULES_DIR'])
                if f.endswith('.rules')
            ])
    
    return render_template('ids.html', status=status)

@app.route('/ids/rules', methods=['GET', 'POST'])
def manage_ids_rules():
    """Manage IDS/IPS rules"""
    if request.method == 'POST':
        rule_content = request.form.get('rule_content')
        rule_name = request.form.get('rule_name', 'custom.rules')
        
        if not rule_content:
            return jsonify({'status': 'error', 'message': 'No rule content provided'}), 400
            
        try:
            rule_path = os.path.join(app.config['SURICATA_RULES_DIR'], rule_name)  # Changed to SURICATA_RULES_DIR
            with open(rule_path, 'a') as f:
                f.write(rule_content + '\n')
            
            # Reload Suricata if running
            reload_suricata()
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # GET request - list available rules
    rules = []
    if os.path.exists(app.config['SURICATA_RULES_DIR']):  # Changed to SURICATA_RULES_DIR
        for f in os.listdir(app.config['SURICATA_RULES_DIR']):
            if f.endswith('.rules'):
                rules.append(f)
    return jsonify({'status': 'success', 'rules': rules})

@app.route('/ids/control', methods=['POST'])
def ids_control():
    """Start/Stop/Restart Suricata"""
    action = request.form.get('action')
    mode = request.form.get('mode', 'ids')
    
    if action == 'start':
        success = start_suricata(mode == 'ips')
        return jsonify({'status': 'success' if success else 'error'})
    elif action == 'stop':
        success = stop_suricata()
        return jsonify({'status': 'success' if success else 'error'})
    elif action == 'restart':
        stop_suricata()
        success = start_suricata(mode == 'ips')
        return jsonify({'status': 'success' if success else 'error'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid action'}), 400



@app.route('/ids/alerts')
def get_ids_alerts():
    """Get recent alerts (for live updates)"""
    alerts = []
    eve_log = os.path.join(app.config['SURICATA_LOGS'], 'eve.json')
    
    if os.path.exists(eve_log):
        try:
            with open(eve_log, 'r') as f:
                for line in f:
                    try:
                        alert = json.loads(line)
                        if alert.get('event_type') == 'alert':
                            alerts.append(alert)
                            if len(alerts) >= 50:  # Limit alerts
                                break
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            log_event("ERROR", "medium", "Failed to read Suricata logs", {'error': str(e)})
    
    return jsonify({'alerts': alerts})

# Helper functions
def start_suricata(ips_mode=False):
    """Start Suricata in IDS or IPS mode"""
    try:
        # Check if already running
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'suricata':
                return True
        
        cmd = [
            'suricata',
            '-c', os.path.join(app.config['SURICATA_DIR'], 'suricata.yaml'),
            '-i', app.config['SURICATA_INTERFACE'],
            '--set', f'default-rule-path={app.config["SURICATA_RULES"]}',
            '--set', f'log-dir={app.config["SURICATA_LOGS"]}'
        ]
        
        if ips_mode:
            cmd.append('--ips')
        
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_event("SURICATA", "info", f"Started Suricata in {'IPS' if ips_mode else 'IDS'} mode")
        return True
    except Exception as e:
        log_event("ERROR", "high", "Failed to start Suricata", {'error': str(e)})
        return False

def stop_suricata():
    """Stop Suricata"""
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'suricata':
                proc.terminate()
                proc.wait(timeout=10)
                log_event("SURICATA", "info", "Stopped Suricata")
                return True
        return False
    except Exception as e:
        log_event("ERROR", "high", "Failed to stop Suricata", {'error': str(e)})
        return False

def reload_suricata():
    """Reload Suricata rules"""
    try:
        for proc in psutil.process_iter(['name', 'pid']):
            if proc.info['name'] == 'suricata':
                os.kill(proc.info['pid'], signal.SIGUSR2)
                log_event("SURICATA", "info", "Reloaded Suricata rules")
                return True
        return False
    except Exception as e:
        log_event("ERROR", "high", "Failed to reload Suricata rules", {'error': str(e)})
        return False

def log_event(event_type, severity, message, details=None):
    """Helper function for logging events"""
    # Implement a simple logging system or integrate with a logging service
    print(f"{event_type} - {severity}: {message}")
    if details:
        print(f"Details: {details}")




@app.route('/ids/logs/live')
def live_suricata_logs():
    """Stream live Suricata logs"""
    eve_log = os.path.join(app.config['SURICATA_LOGS'], 'eve.json')
    
    def generate():
        try:
            # Get current file size
            current_pos = os.path.getsize(eve_log)
            
            while True:
                # Check if file has been rotated
                if not os.path.exists(eve_log):
                    yield "data: File not found\n\n"
                    time.sleep(5)
                    continue
                
                new_size = os.path.getsize(eve_log)
                
                # If file was rotated or truncated
                if new_size < current_pos:
                    current_pos = 0
                
                if new_size > current_pos:
                    with open(eve_log, 'r') as f:
                        f.seek(current_pos)
                        for line in f:
                            try:
                                yield f"data: {json.dumps(line.strip())}\n\n"
                            except:
                                continue
                        current_pos = f.tell()
                
                time.sleep(1)
        except Exception as e:
            log_event("ERROR", "high", "Live log streaming failed", {'error': str(e)})
    
    return Response(generate(), mimetype="text/event-stream")



@app.route('/fail2ban/status')
def fail2ban_status():
    """Check Fail2Ban status"""
    status = {
        'enabled': app.config['FAIL2BAN_ENABLED'],
        'running': False,
        'jails': {}
    }
    
    if app.config['FAIL2BAN_ENABLED']:
        try:
            # Check if running
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == 'fail2ban-server':
                    status['running'] = True
                    break
            
            # Get jail status
            for jail in app.config['FAIL2BAN_JAILS']:
                try:
                    result = subprocess.run(
                        ['fail2ban-client', 'status', jail],
                        capture_output=True, text=True
                    )
                    status['jails'][jail] = result.stdout
                except:
                    status['jails'][jail] = 'error'
        except Exception as e:
            log_event("ERROR", "medium", "Failed to check Fail2Ban status", {'error': str(e)})
    
    return jsonify(status)

@app.route('/firewall/status')
def firewall_status():
    """Check firewall status"""
    status = {
        'enabled': app.config['FIREWALL_ENABLED'],
        'active': False,
        'ports': []
    }
    
    if app.config['FIREWALL_ENABLED']:
        try:
            # Check if firewalld is running
            result = subprocess.run(
                ['systemctl', 'is-active', 'firewalld'],
                capture_output=True, text=True
            )
            status['active'] = result.stdout.strip() == 'active'
            
            # Get current ports
            result = subprocess.run(
                ['firewall-cmd', '--list-ports'],
                capture_output=True, text=True
            )
            status['ports'] = result.stdout.split()
        except Exception as e:
            log_event("ERROR", "medium", "Failed to check firewall status", {'error': str(e)})
    
    return jsonify(status)




@app.route('/firewall')
def firewall_management():
    """Firewall management dashboard"""
    # Get current firewall status
    status = firewall_status().get_json()
    
    # Get list of all services known to firewalld
    services = []
    try:
        result = subprocess.run(
            ['firewall-cmd', '--get-services'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            services = result.stdout.strip().split()
    except Exception as e:
        log_event("ERROR", "medium", "Failed to get firewall services", {'error': str(e)})
    
    # Get currently allowed services
    allowed_services = []
    try:
        result = subprocess.run(
            ['firewall-cmd', '--list-services'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            allowed_services = result.stdout.strip().split()
    except Exception as e:
        log_event("ERROR", "medium", "Failed to get allowed services", {'error': str(e)})
    
    return render_template('firewall.html',
                         status=status,
                         services=services,
                         allowed_services=allowed_services,
                         version=app.config['VERSION'],
                         year=datetime.now().year)

@app.route('/firewall/add_port', methods=['POST'])
def firewall_add_port():
    """Add a port to firewall rules"""
    port = request.form.get('port')
    protocol = request.form.get('protocol', 'tcp')
    
    if not port or not port.isdigit():
        return jsonify({'status': 'error', 'message': 'Invalid port number'}), 400
    
    full_port = f"{port}/{protocol}"
    
    try:
        # Add port temporarily
        subprocess.run(
            ['firewall-cmd', '--add-port', full_port],
            check=True
        )
        # Make permanent
        subprocess.run(
            ['firewall-cmd', '--add-port', full_port, '--permanent'],
            check=True
        )
        log_event("FIREWALL", "info", f"Added firewall port {full_port}")
        return jsonify({'status': 'success', 'message': f'Port {full_port} added'})
    except subprocess.CalledProcessError as e:
        log_event("ERROR", "high", f"Failed to add port {full_port}", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/firewall/remove_port', methods=['POST'])
def firewall_remove_port():
    """Remove a port from firewall rules"""
    port = request.form.get('port')
    protocol = request.form.get('protocol', 'tcp')
    
    if not port or not port.isdigit():
        return jsonify({'status': 'error', 'message': 'Invalid port number'}), 400
    
    full_port = f"{port}/{protocol}"
    
    try:
        # Remove port temporarily
        subprocess.run(
            ['firewall-cmd', '--remove-port', full_port],
            check=True
        )
        # Make permanent
        subprocess.run(
            ['firewall-cmd', '--remove-port', full_port, '--permanent'],
            check=True
        )
        log_event("FIREWALL", "info", f"Removed firewall port {full_port}")
        return jsonify({'status': 'success', 'message': f'Port {full_port} removed'})
    except subprocess.CalledProcessError as e:
        log_event("ERROR", "high", f"Failed to remove port {full_port}", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/firewall/add_service', methods=['POST'])
def firewall_add_service():
    """Add a service to firewall rules"""
    service = request.form.get('service')
    
    if not service:
        return jsonify({'status': 'error', 'message': 'Service name required'}), 400
    
    try:
        # Add service temporarily
        subprocess.run(
            ['firewall-cmd', '--add-service', service],
            check=True
        )
        # Make permanent
        subprocess.run(
            ['firewall-cmd', '--add-service', service, '--permanent'],
            check=True
        )
        log_event("FIREWALL", "info", f"Added firewall service {service}")
        return jsonify({'status': 'success', 'message': f'Service {service} added'})
    except subprocess.CalledProcessError as e:
        log_event("ERROR", "high", f"Failed to add service {service}", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/firewall/remove_service', methods=['POST'])
def firewall_remove_service():
    """Remove a service from firewall rules"""
    service = request.form.get('service')
    
    if not service:
        return jsonify({'status': 'error', 'message': 'Service name required'}), 400
    
    try:
        # Remove service temporarily
        subprocess.run(
            ['firewall-cmd', '--remove-service', service],
            check=True
        )
        # Make permanent
        subprocess.run(
            ['firewall-cmd', '--remove-service', service, '--permanent'],
            check=True
        )
        log_event("FIREWALL", "info", f"Removed firewall service {service}")
        return jsonify({'status': 'success', 'message': f'Service {service} removed'})
    except subprocess.CalledProcessError as e:
        log_event("ERROR", "high", f"Failed to remove service {service}", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/firewall/panic', methods=['POST'])
def firewall_panic_mode():
    """Toggle firewall panic mode (completely block all traffic)"""
    action = request.form.get('action')
    
    if action not in ['on', 'off']:
        return jsonify({'status': 'error', 'message': 'Invalid action'}), 400
    
    try:
        subprocess.run(
            ['firewall-cmd', '--panic-' + action],
            check=True
        )
        log_event("FIREWALL", "critical", f"Firewall panic mode {action}")
        return jsonify({'status': 'success', 'message': f'Panic mode turned {action}'})
    except subprocess.CalledProcessError as e:
        log_event("ERROR", "critical", f"Failed to set panic mode {action}", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500



@app.route('/services')
def services_page():
    services = get_system_services()
    return render_template('services.html', 
                         services=services,
                         version=app.config['VERSION'],
                         year=datetime.now().year)

@app.route('/services/<service_name>/<action>', methods=['POST'])
def service_action(service_name, action):
    """Perform an action on a service (start/stop/restart/enable/disable)"""
    success, message = manage_service(service_name, action)
    if success:
        return jsonify({'status': 'success', 'message': message})
    else:
        return jsonify({'status': 'error', 'message': message}), 400

@app.route('/services/status/<service_name>', methods=['GET'])
def service_status(service_name):
    """Get detailed status of a specific service"""
    try:
        # For systemd systems
        if os.path.exists('/run/systemd/system'):
            cmd = ['systemctl', 'show', service_name, '--no-pager']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return jsonify({'status': 'error', 'message': result.stderr.strip()}), 400
            
            status_info = {}
            for line in result.stdout.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    status_info[key] = value
            
            return jsonify({'status': 'success', 'service': service_name, 'details': status_info})
        else:
            # For sysvinit systems
            cmd = ['service', service_name, 'status']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            status_info = {
                'ActiveState': 'active' if result.returncode == 0 else 'inactive',
                'SubState': 'running' if result.returncode == 0 else 'stopped',
                'StatusText': result.stdout.strip()
            }
            
            return jsonify({'status': 'success', 'service': service_name, 'details': status_info})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    




def run_yara_scan(path, rule_name):
    """Run YARA scan on specified path with specific rule"""
    try:
        # Compile the specific rule
        rule_path = os.path.join(app.config['YARA_RULES'], rule_name)
        if not os.path.exists(rule_path):
            return {'error': 'Rule file not found'}

        rules = yara.compile(filepath=rule_path)
        matches = []

        # Scan all files in path
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    file_matches = rules.match(file_path)
                    if file_matches:
                        matches.append({
                            'file': file_path,
                            'matches': [str(m) for m in file_matches]
                        })
                except Exception as e:
                    log_event("ERROR", "medium", f"YARA scan failed for {file_path}", {'error': str(e)})
        
        return matches
    except Exception as e:
        log_event("ERROR", "high", "YARA scan failed", {'error': str(e)})
        return {'error': str(e)}

def secure_filename(filename):
    """Sanitize filename to prevent directory traversal and other security issues"""
    # Keep only alphanumeric, dots, underscores and hyphens
    filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    # Replace multiple underscores with single one
    filename = re.sub(r'_+', '_', filename)
    return filename

def get_last_scan_results(limit=5):
    """Get last scan results from log file"""
    scan_log = os.path.join(app.config['LOG_DIR'], 'edr.log')
    results = []
    
    if not os.path.exists(scan_log):
        return results
    
    try:
        with open(scan_log, 'r') as f:
            for line in f:
                if 'SCAN' in line and 'Completed full system scan' in line:
                    try:
                        # Extract JSON part from log line
                        json_part = line[line.find('{'):]
                        scan_data = json.loads(json_part)
                        results.append(scan_data)
                        if len(results) >= limit:
                            break
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        log_event("ERROR", "medium", "Failed to read scan log", {'error': str(e)})
    
    return results



@app.route('/scan')
def scan_dashboard():
    """Scan management dashboard"""
    # Get YARA rule files
    yara_rules = []
    if app.config['YARA_ENABLED']:
        yara_rules = [f for f in os.listdir(app.config['YARA_RULES']) 
                     if f.endswith('.yar') or f.endswith('.yara')]
    
    context = {
        'scan_paths': app.config['SCAN_PATHS'],
        'yara_rules': yara_rules,
        'last_scans': get_last_scan_results(),
        'version': app.config['VERSION'],
        'year': datetime.now().year
    }
    return render_template('scans.html', **context)

@app.route('/scan/run', methods=['POST'])
def run_scan():
    """Run a specific scan"""
    scan_type = request.form.get('scan_type')
    scan_path = request.form.get('scan_path', '')
    yara_rule = request.form.get('yara_rule', '')
    
    try:
        if scan_type == 'clamav':
            result = run_clamav_scan(scan_path)
            log_scan_result('clamav', scan_path, result)
            return jsonify({'status': 'success', 'result': result})
        elif scan_type == 'maldet':
            result = run_maldet_scan(scan_path)
            log_scan_result('maldet', scan_path, result)
            return jsonify({'status': 'success', 'result': result})
        elif scan_type == 'rkhunter':
            result = run_rkhunter_scan()
            log_scan_result('rkhunter', 'system', result)
            return jsonify({'status': 'success', 'result': result})
        elif scan_type == 'yara':
            if not yara_rule:
                return jsonify({'status': 'error', 'message': 'No YARA rule selected'}), 400
            result = run_yara_scan(scan_path, yara_rule)
            log_scan_result('yara', scan_path, result)
            return jsonify({'status': 'success', 'result': result})
        else:
            return jsonify({'status': 'error', 'message': 'Invalid scan type'}), 400
    except Exception as e:
        app.logger.error(f"Scan failed: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/scan/yara/rules', methods=['GET', 'POST'])
def manage_yara_rules():
    """Manage YARA rules"""
    if request.method == 'POST':
        # Handle file upload
        if 'yara_file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file uploaded'}), 400
            
        file = request.files['yara_file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No selected file'}), 400
            
        if file and (file.filename.endswith('.yar') or file.filename.endswith('.yara')):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['YARA_RULES'], filename))
            return jsonify({'status': 'success', 'message': 'YARA rule uploaded'})
    
    # GET request - list rules
    yara_rules = [f for f in os.listdir(app.config['YARA_RULES']) 
                 if f.endswith('.yar') or f.endswith('.yara')]
    return jsonify({'status': 'success', 'rules': yara_rules})

def get_last_scan_results():
    """Get last scan results from logs"""
    # Implement this based on your logging system
    return []


def process_connection(conn, malicious_ports):
    """
    Process an established network connection to a malicious port
    Returns detailed connection information including process details
    """
    port = conn.raddr.port
    proc_info = get_process_info(conn.pid)
    
    connection_data = {
        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
        'port': port,
        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
        'threat_info': malicious_ports.get(port, "Unknown threat"),
        'process': proc_info,
        'status': 'established',
        'connection_time': get_connection_duration(conn.pid, conn.laddr.port),
        'timestamp': datetime.now().isoformat()
    }
    
    # Add geographical info if available
    if has_geoip():
        connection_data['geoip'] = get_geoip_info(conn.raddr.ip)
    
    return connection_data

def process_listening_port(conn, malicious_ports):
    """
    Process a listening port that matches malicious ports list
    Returns detailed information about the listening service
    """
    port = conn.laddr.port
    proc_info = get_process_info(conn.pid)
    
    listening_data = {
        'port': port,
        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
        'threat_info': malicious_ports.get(port, "Unknown threat"),
        'process': proc_info,
        'bind_address': conn.laddr.ip,
        'status': 'listening',
        'timestamp': datetime.now().isoformat()
    }
    
    # Add service detection if available
    service_info = detect_service(port, conn.type)
    if service_info:
        listening_data.update(service_info)
    
    return listening_data

# Helper functions used by the processors
def get_process_info(pid):
    """Get detailed process information with error handling"""
    try:
        with psutil.Process(pid) as proc:
            return {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': proc.cmdline(),
                'username': proc.username(),
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'status': proc.status(),
                'cpu_percent': proc.cpu_percent(),
                'memory_percent': proc.memory_percent()
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {'error': str(e), 'pid': pid}
    except Exception as e:
        log_event("WARNING", "medium", "Process info error", {'pid': pid, 'error': str(e)})
        return {'error': 'Process info unavailable', 'pid': pid}

def get_connection_duration(pid, port):
    """Estimate connection duration (Linux only)"""
    try:
        if os.path.exists(f"/proc/{pid}/net/tcp"):
            with open(f"/proc/{pid}/net/tcp") as f:
                for line in f:
                    parts = line.strip().split()
                    local_addr = parts[1]
                    if f":{port:04X}" in local_addr:
                        hex_timestamp = parts[13]
                        if hex_timestamp != '00000000':
                            return int(hex_timestamp, 16)
    except:
        pass
    return None

def has_geoip():
    """Check if GeoIP functionality is available"""
    try:
        import geoip2.database
        return os.path.exists(EDRConfig.GEOIP_DB_PATH)
    except:
        return False

def get_geoip_info(ip_address):
    """Get GeoIP information for an IP address"""
    try:
        import geoip2.database
        with geoip2.database.Reader(EDRConfig.GEOIP_DB_PATH) as reader:
            response = reader.city(ip_address)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'location': {
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude
                },
                'asn': get_asn_info(ip_address)
            }
    except:
        return None

def get_asn_info(ip_address):
    """Get ASN information for an IP address"""
    try:
        import geoip2.database
        with geoip2.database.Reader(EDRConfig.ASN_DB_PATH) as reader:
            response = reader.asn(ip_address)
            return {
                'asn': response.autonomous_system_number,
                'org': response.autonomous_system_organization
            }
    except:
        return None

def detect_service(port, conn_type):
    """Detect service running on a port"""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if conn_type == socket.SOCK_STREAM else socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(('127.0.0.1', port))
        service = socket.getservbyport(port, 'tcp' if conn_type == socket.SOCK_STREAM else 'udp')
        s.close()
        return {'detected_service': service}
    except:
        return None

@app.route('/network')
def network_monitoring():
    """Network monitoring dashboard with malicious port detection"""
    try:
        # Get malicious ports from config
        malicious_ports = EDRConfig.get_malicious_ports(EDRConfig)
        
        # Get all network data
        network_data = get_network_data(malicious_ports)
        
        return render_template("network.html",
            malicious_connections=network_data['malicious_connections'],
            malicious_listening_ports=network_data['malicious_listening_ports'],
            network_interfaces=network_data['interfaces'],
            bandwidth_stats=network_data['bandwidth_stats'],  # Make sure this matches the template
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            version=EDRConfig.VERSION,
            year=datetime.now().year,
            malicious_ports_config=malicious_ports
        )

    except Exception as e:
        log_event("ERROR", "high", "Network monitoring failed", {'error': str(e)})
        return render_template("network.html",
            error=str(e),
            version=EDRConfig.VERSION,
            year=datetime.now().year
        ), 500

def get_network_data(malicious_ports):
    """Collect all network data efficiently"""
    data = {
        'malicious_connections': [],
        'malicious_listening_ports': [],
        'interfaces': [],
        'bandwidth_stats': {
            'total': {
                'bytes_sent': 0,
                'bytes_recv': 0,
                'packets_sent': 0,
                'packets_recv': 0,
                'error_in': 0,
                'error_out': 0,
                'drop_in': 0,
                'drop_out': 0
            }
        }
    }
    
    # Get network I/O counters
    try:
        net_io = psutil.net_io_counters()
        data['bandwidth_stats']['total'] = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'error_in': net_io.errin,
            'error_out': net_io.errout,
            'drop_in': net_io.dropin,
            'drop_out': net_io.dropout
        }
    except Exception as e:
        log_event("WARNING", "medium", "Failed to get network stats", {'error': str(e)})
        # Keep the default initialized values if there's an error
    
    # Rest of your function remains the same...
    # Get all connections once
    try:
        all_conns = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        log_event("WARNING", "high", "Insufficient permissions to access network connections")
        all_conns = []
    
    # Process connections
    for conn in all_conns:
        try:
            # Established connections to malicious ports
            if conn.status == 'ESTABLISHED' and hasattr(conn, 'raddr') and conn.raddr:
                if conn.raddr.port in malicious_ports:
                    data['malicious_connections'].append({
                        'process': {
                            'name': psutil.Process(conn.pid).name() if conn.pid else 'N/A',
                            'pid': conn.pid
                        },
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'port': conn.raddr.port,
                        'threat_info': malicious_ports.get(conn.raddr.port, 'Unknown')
                    })
            
            # Listening on malicious ports
            elif conn.status == 'LISTEN' and hasattr(conn, 'laddr') and conn.laddr.port in malicious_ports:
                data['malicious_listening_ports'].append({
                    'process': {
                        'name': psutil.Process(conn.pid).name() if conn.pid else 'N/A',
                        'pid': conn.pid
                    },
                    'port': conn.laddr.port,
                    'protocol': 'TCP',  # Assuming TCP for simplicity
                    'threat_info': malicious_ports.get(conn.laddr.port, 'Unknown')
                })
                
        except Exception as e:
            log_event("WARNING", "medium", "Failed to process connection", 
                     {'error': str(e), 'conn': str(conn)})
    
    # Get interface details
    try:
        io_counters = psutil.net_io_counters(pernic=True)
        for interface, addrs in psutil.net_if_addrs().items():
            data['interfaces'].append({
                'interface': interface,
                'addresses': [f"{addr.family.name}: {addr.address}" for addr in addrs],
                'stats': io_counters.get(interface, {})
            })
    except Exception as e:
        log_event("WARNING", "medium", "Failed to get interface details", {'error': str(e)})
    
    return data




@app.route('/network/ports', methods=['GET', 'POST', 'DELETE'])
def manage_malicious_ports():
    """Manage malicious ports configuration"""
    config_path = os.path.join(EDRConfig.CONFIG_DIR, 'malicious_ports.json')
    
    if request.method == 'GET':
        try:
            if os.path.exists(config_path):
                with open(config_path) as f:
                    return jsonify(json.load(f))
            return jsonify({})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            port = request.form.get('port')
            description = request.form.get('description', '')
            
            if not port:
                return jsonify({'error': 'Port number is required'}), 400
            
            # Load existing or create new
            current = {}
            if os.path.exists(config_path):
                with open(config_path) as f:
                    current = json.load(f)
            
            # Add/update port
            current[port] = description
            
            # Save back to file
            with open(config_path, 'w') as f:
                json.dump(current, f, indent=2)
            
            return jsonify({'status': 'success'})
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            port = request.args.get('port')
            if not port:
                return jsonify({'error': 'Port number is required'}), 400
            
            if os.path.exists(config_path):
                with open(config_path) as f:
                    current = json.load(f)
                
                if port in current:
                    del current[port]
                    
                    with open(config_path, 'w') as f:
                        json.dump(current, f, indent=2)
                
                return jsonify({'status': 'success'})
            return jsonify({'error': 'No custom ports configured'}), 404
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500


# =============================================
# Background Monitoring Threads
# =============================================

class FileEventHandler(pyinotify.ProcessEvent):
    """Handler for file system events"""
    def process_default(self, event):
        if event.maskname == 'IN_MODIFY':
            log_event("FS", "medium", f"File modified: {event.pathname}")
        elif event.maskname == 'IN_CREATE':
            log_event("FS", "medium", f"File created: {event.pathname}")
        elif event.maskname == 'IN_DELETE':
            log_event("FS", "medium", f"File deleted: {event.pathname}")

def start_file_monitoring():
    """Start file system monitoring with inotify"""
    wm = pyinotify.WatchManager()
    mask = pyinotify.IN_MODIFY | pyinotify.IN_CREATE | pyinotify.IN_DELETE
    
    notifier = pyinotify.Notifier(wm, FileEventHandler())
    
    # Watch important directories
    for path in ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/tmp']:
        if os.path.exists(path):
            wm.add_watch(path, mask, rec=True)
    
    # Start monitoring in a separate thread
    def monitor():
        while True:
            try:
                notifier.process_events()
                if notifier.check_events():
                    notifier.read_events()
            except Exception as e:
                log_event("ERROR", "high", "File monitoring error", {'error': str(e)})
            time.sleep(1)
    
    thread = threading.Thread(target=monitor)
    thread.daemon = True
    thread.start()

def start_periodic_scans():
    """Start periodic scanning"""
    def scan_loop():
        while True:
            log_event("SCAN", "info", "Starting periodic scan")
            full_system_scan()
            time.sleep(app.config['SCAN_INTERVAL'])
    
    thread = threading.Thread(target=scan_loop)
    thread.daemon = True
    thread.start()

# =============================================
# Initialization
# =============================================
# Add this to your Flask app (where you initialize your app)
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.strftime(format)


if __name__ == '__main__':
    # Initialize directories and logging
    init_directories()
    setup_logging()
    
    # Log startup
    log_event("SYSTEM", "info", "EDR system starting up", {
        'version': app.config['VERSION'],
        'machine_id': app.config['MACHINE_ID']
    })
    
    # Start security services
    if app.config['SURICATA_ENABLED']:
        start_suricata()
        threading.Thread(target=monitor_suricata_logs, daemon=True).start()
    
    if app.config['FAIL2BAN_ENABLED']:
        configure_fail2ban()
    
    if app.config['FIREWALL_ENABLED']:
        manage_firewall()
    
    # Start monitoring threads
    try:
        start_file_monitoring()
    except Exception as e:
        log_event("ERROR", "high", "Failed to start file monitoring", {'error': str(e)})
    
    start_periodic_scans()



    
    
    # Start the Flask app
    app.run(host='0.0.0.0', port=5005, debug=True)