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
import datetime




now = datetime.datetime.now()

config.init_directories()




app = Flask(__name__)



# =============================================
# Initialization
# =============================================

def init_directories():
    """Create all required directories and files"""
    dirs = [
        config.APP_DIR,
        config.LOG_DIR,
        config.QUARANTINE_DIR,
        config.SIGNATURES_DIR,
        config.EDR_DIR,
        config.BASELINE_DIR,
        config.CONFIG_DIR,
        config.RULES_DIR,
        config.REPORT_DIR
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
        if not os.path.exists(os.path.join(config.SIGNATURES_DIR, filename)):
            with open(os.path.join(config.SIGNATURES_DIR, filename), 'w') as f:
                f.write(content)
    
    # Initialize YARA rules
    if not os.path.exists(os.path.join(config.YARA_RULES, 'malware_rules.yar')):
        with open(os.path.join(config.YARA_RULES, 'malware_rules.yar'), 'w') as f:
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
        if not os.path.exists(os.path.join(config.RULES_DIR, filename)):
            with open(os.path.join(config.RULES_DIR, filename), 'w') as f:
                f.write(content)
    
    # Initialize event log
    if not os.path.exists(os.path.join(config.EDR_DIR, 'events.log')):
        with open(os.path.join(config.EDR_DIR, 'events.log'), 'w') as f:
            f.write("# LinuxAV-Solutions EDR Event Log\n")





SCAN_LOG_FILE = os.path.join(config.LOG_DIR , 'scan_results.log')

def log_scan_result(scan_type, scan_path, result):
    """Log scan results to a file"""
    try:
        with open(SCAN_LOG_FILE, 'a') as f:
            log_entry = {
                'timestamp': now.isoformat(),
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
    log_file = os.path.join(config.LOG_DIR, 'edr.log')
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
        cmd = ['clamscan', '-r', '--infected', '--log=' + os.path.join(config.LOG_DIR, 'clamav.log')]
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
        for rule_file in config.YARA_RULE_FILES:
            rule_path = os.path.join(config.YARA_RULES, rule_file)
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
    for path in config.SCAN_PATHS:
        if os.path.exists(path):
            scan_results['clamav'].extend(run_clamav_scan(path))
    
    # Run Maldet scan
    scan_results['maldet'] = run_maldet_scan(' '.join(config.SCAN_PATHS))
    
    # Run rkhunter and chkrootkit
    scan_results['rkhunter'] = run_rkhunter_scan()
    scan_results['chkrootkit'] = run_chkrootkit_scan()
    
    # Run YARA scan if enabled
    if config.YARA_ENABLED:
        yara_rules = compile_yara_rules()
        if yara_rules:
            for path in config.SCAN_PATHS:
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
    if not config.SURICATA_ENABLED:
        return False
    
    try:
        # Check if Suricata is already running
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'suricata':
                return True
        
        # Start Suricata
        cmd = [
            'suricata',
            '-c', os.path.join(config.SURICATA_DIR , 'suricata.yaml'),
            '-i', config.SURICATA_INTERFACE,
            '--set', f'default-rule-path={config.SURICATA_RULES}',
            '--set', f'rule-files={",".join(config.SURICATA_RULE_FILES)}',
            '--set', f'log-dir={config.SURICATA_LOGS}'
        ]
        
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_event("SURICATA", "info", "Started Suricata IDS/IPS")
        return True
    except Exception as e:
        log_event("ERROR", "high", "Failed to start Suricata", {'error': str(e)})
        return False

def monitor_suricata_logs():
    """Monitor Suricata logs for alerts"""
    if not config.SURICATA_ENABLED:
        return
    
    eve_log = os.path.join(config.SURICATA_LOGS, 'eve.json')
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
    if not config.FAIL2BAN_ENABLED:
        return False
    
    try:
        # Check if Fail2Ban is running
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'fail2ban-server':
                return True
        
        # Start Fail2Ban
        subprocess.run(['systemctl', 'start', 'fail2ban'], check=True)
        
        # Configure jails
        for jail in config.FAIL2BAN_JAILS:
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
    if not config.FIREWALL_ENABLED:
        return False
    
    try:
        # Ensure firewall is running
        subprocess.run(['systemctl', 'start', 'firewalld'], check=True)
        
        # Set default zone
        subprocess.run(['firewall-cmd', '--set-default-zone=' + config.FIREWALL_ZONE], check=True)
        
        # Remove all existing ports (start fresh)
        current_ports = subprocess.run(
            ['firewall-cmd', '--list-ports'],
            capture_output=True, text=True
        ).stdout.split()
        
        for port in current_ports:
            subprocess.run(['firewall-cmd', '--remove-port=' + port, '--permanent'], check=True)
        
        # Add allowed ports
        for port in config.FIREWALL_ALLOWED_PORTS:
            subprocess.run(['firewall-cmd', '--add-port=' + port, '--permanent'], check=True)
        
        # Reload firewall
        subprocess.run(['firewall-cmd', '--reload'], check=True)
        
        log_event("FIREWALL", "info", "Firewall configured", {
            'zone': config.FIREWALL_ZONE,
            'allowed_ports': config.FIREWALL_ALLOWED_PORTS
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
    if os.path.exists(os.path.join(config.BASELINE_DIR, 'process_baseline.txt')):
        with open(os.path.join(config.BASELINE_DIR, 'process_baseline.txt')) as f:
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
    known_bad_ports = [
    21, 22, 23, 25, 53, 80, 111, 135, 139, 445, 512, 513, 514, 1080,
    1433, 2049, 3306, 3389, 5000, 5432, 5800, 5900, 6660, 6667, 6669,
    7000, 8080, 9000, 12345, 27374, 31337, 32764, 4444, 5555, 6666,
    7788, 8081, 8888, 9001
    ]
    
    try:
        # Add ports from config
        custom_ports = config.get_malicious_ports()
        known_bad_ports += list(custom_ports.keys())
        
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


@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.strftime(format)



@app.route('/api/system/stats')
def system_stats():
    """Get current system statistics"""
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    
    # Simple network activity calculation
    net1 = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
    time.sleep(1)
    net2 = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
    net_activity = (net2 - net1) / 1024  # KB/s
    
    return jsonify({
        'cpu_usage': cpu,
        'memory_usage': mem,
        'disk_usage': disk,
        'network_activity': f'{net_activity:.1f} KB/s',
        'network_percent': min(100, net_activity / 1024 * 100)  # Scale to 100% at 1MB/s
    })

@app.route('/api/services/status')
def services_status():
    """Get status of security services"""
    return jsonify({
        'clamav': is_service_running('clamav'),
        'suricata': is_service_running('suricata'),
        'fail2ban': is_service_running('fail2ban'),
        'firewall': is_service_running('firewalld'),
        'yara': True  # YARA is a library, not a service
    })

def is_service_running(service_name):
    """Check if a service is running"""
    try:
        if os.path.exists('/run/systemd/system'):
            cmd = ['systemctl', 'is-active', service_name]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout.strip() == 'active'
        else:
            cmd = ['service', service_name, 'status']
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
    except:
        return False







def calculate_threat_trend():
    """Calculate threat trend based on historical data"""
    try:
        # Get last 24 hours of threat data from logs
        threat_log = os.path.join(config.LOG_DIR, 'edr.log')
        threat_counts = []
        
        if os.path.exists(threat_log):
            # Count threats in each hour of the last 24 hours
            current_time = datetime.datetime.now()
            for hour in range(24):
                hour_start = current_time - datetime.timedelta(hours=hour+1)
                hour_end = current_time - datetime.timedelta(hours=hour)
                count = 0
                
                with open(threat_log, 'r') as f:
                    for line in f:
                        if 'SCAN' in line or 'ALERT' in line:
                            try:
                                # Extract timestamp from log line
                                log_time_str = line.split(' - ')[0]
                                log_time = datetime.datetime.strptime(log_time_str, '%Y-%m-%d %H:%M:%S')
                                
                                if hour_start <= log_time <= hour_end:
                                    count += 1
                            except:
                                continue
                
                threat_counts.append(count)
            
            # Calculate trend (simple linear regression)
            if len(threat_counts) >= 3:
                x = range(len(threat_counts))
                y = threat_counts
                n = len(x)
                
                sum_x = sum(x)
                sum_y = sum(y)
                sum_xy = sum(xi*yi for xi, yi in zip(x, y))
                sum_x2 = sum(xi**2 for xi in x)
                
                slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x**2)
                
                if slope > 0.5:
                    return "increasing"
                elif slope < -0.5:
                    return "decreasing"
                else:
                    return "stable"
        
        return "unknown"
    except Exception as e:
        log_event("ERROR", "medium", "Failed to calculate threat trend", {'error': str(e)})
        return "error"





def is_port_open(port):
    """Check if a port is open/listening on the local system"""
    try:
        port = int(port)  # Ensure port is an integer
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and hasattr(conn, 'laddr') and conn.laddr.port == port:
                return True
        return False
    except (ValueError, TypeError):
        return False
    except Exception as e:
        log_event("ERROR", "medium", f"Failed to check port {port}", {'error': str(e)})
        return False




@app.route('/api/threats/count')
def threats_count():
    """Get counts of current threats"""
    malicious_ports = config.get_malicious_ports()
    malicious_conns = get_suspicious_connections()
    malicious_procs = analyze_processes()
    
    return jsonify({
        'total_threats': len(malicious_conns) + len(malicious_procs),
        'malicious_processes': len(malicious_procs),
        'malicious_connections': len(malicious_conns),
        'ports_secured': len([p for p in malicious_ports if not is_port_open(p)]),
        'total_ports': len(malicious_ports),
        'threat_trend': calculate_threat_trend()  # Implement this based on your historical data
    })

@app.route('/api/scans/last')
def last_scan():
    """Get last scan information"""
    scans = get_last_scan_results(1)
    return jsonify({
        'last_scan': scans[0]['timestamp'] if scans else None,
        'active_scans': 0  # You might track active scans differently
    })

@app.route('/api/process/kill', methods=['POST'])
def kill_process():
    """Kill a process"""
    pid = request.form.get('pid')
    try:
        os.kill(int(pid), signal.SIGKILL)
        log_event("ACTION", "high", f"Process {pid} killed by admin")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/api/firewall/block', methods=['POST'])
def block_connection():
    """Block a connection in firewall"""
    ip = request.form.get('ip')
    port = request.form.get('port')
    
    try:
        # For firewalld
        subprocess.run(['firewall-cmd', '--permanent', '--add-rich-rule', 
                       f'rule family="ipv4" source address="{ip}" port port="{port}" protocol="tcp" reject'])
        subprocess.run(['firewall-cmd', '--reload'])
        
        log_event("ACTION", "high", f"Blocked {ip}:{port} in firewall")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/')
def dashboard():
    """Main dashboard endpoint"""
    services = get_system_services()
    now  = datetime.datetime.now()
    context = {
        'status': 'running',
        'version': config.VERSION,
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
    return render_template('index.html', **context , now = now)

@app.route('/scan/full', methods=['POST'])
def run_full_scan():
    """Run full system scan with all tools"""
    scan_results = full_system_scan()
    return jsonify(scan_results)

@app.route('/suricata/status')
def suricata_status():
    """Check Suricata status"""
    status = {
        'enabled': config.SURICATA_ENABLED,
        'running': False,
        'alerts': []
    }
    
    if config.SURICATA_ENABLED:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'suricata':
                status['running'] = True
                break
        
        # Get recent alerts
        eve_log = os.path.join(config.SURICATA_LOGS, 'eve.json')
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
        'enabled': config.SURICATA_ENABLED,
        'running': False,
        'mode': 'IDS',  # Default mode
        'interface': config.SURICATA_INTERFACE,
        'rules_count': 0,
        'alerts': []  # Initialize alerts list
    }
    
    if config.SURICATA_ENABLED:
        # Check if Suricata is running and get mode
        for proc in psutil.process_iter(['name', 'cmdline']):
            if proc.info['name'] == 'suricata':
                status['running'] = True
                cmdline = ' '.join(proc.info['cmdline'])
                if '--ips' in cmdline:
                    status['mode'] = 'IPS'
                break
        
        # Count rule files
        if os.path.exists(config.SURICATA_RULES_DIR):
            status['rules_count'] = len([
                f for f in os.listdir(config.SURICATA_RULES_DIR)
                if f.endswith('.rules')
            ])
        
        # Load recent alerts
        status['alerts'] = get_recent_alerts()
    
    return render_template('ids.html', status=status, now=now)

def get_recent_alerts(limit=50):
    """Helper function to get recent alerts"""
    alerts = []
    eve_log = os.path.join(config.SURICATA_LOGS, 'eve.json')
    
    if os.path.exists(eve_log):
        try:
            with open(eve_log, 'r') as f:
                for line in f:
                    try:
                        alert = json.loads(line)
                        if alert.get('event_type') == 'alert':
                            alerts.append(alert)
                            if len(alerts) >= limit:
                                break
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            log_event("ERROR", "medium", "Failed to read Suricata logs", {'error': str(e)})
    
    return alerts

@app.route('/ids/rules', methods=['GET', 'POST'])
def manage_ids_rules():
    """Manage IDS/IPS rules"""
    if request.method == 'POST':
        rule_content = request.form.get('rule_content')
        rule_name = request.form.get('rule_name', 'custom.rules')
        
        if not rule_content:
            return jsonify({'status': 'error', 'message': 'No rule content provided'}), 400
            
        try:
            rule_path = os.path.join(config.SURICATA_RULES_DIR, rule_name)  # Changed to SURICATA_RULES_DIR
            with open(rule_path, 'a') as f:
                f.write(rule_content + '\n')
            
            # Reload Suricata if running
            reload_suricata()
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # GET request - list available rules
    rules = []
    if os.path.exists(config.SURICATA_RULES_DIR):  # Changed to SURICATA_RULES_DIR
        for f in os.listdir(config.SURICATA_RULES_DIR):
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
    eve_log = os.path.join(config.SURICATA_LOGS, 'eve.json')
    
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
            '-c', os.path.join(config.SURICATA_DIR , 'suricata.yaml'),
            '-i', config.SURICATA_INTERFACE,
            '--set', f'default-rule-path={config.SURICATA_RULES_DIR}',
            '--set', f'log-dir={config.SURICATA_LOGS}'
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
    eve_log = os.path.join(config.SURICATA_LOGS, 'eve.json')
    
    def generate():
        try:
            # Get current file size
            current_pos = os.path.getsize(eve_log) if os.path.exists(eve_log) else 0
            
            while True:
                # Check if file exists
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
                                # Properly format as SSE
                                yield f"data: {line.strip()}\n\n"
                            except:
                                continue
                        current_pos = f.tell()
                
                time.sleep(1)
        except Exception as e:
            log_event("ERROR", "high", "Live log streaming failed", {'error': str(e)})
            yield "data: Error in log stream\n\n"
    
    return Response(generate(), mimetype="text/event-stream")



@app.route('/fail2ban/status')
def fail2ban_status():
    """Check Fail2Ban status"""
    status = {
        'enabled': config.FAIL2BAN_ENABLED,
        'running': False,
        'jails': {}
    }
    
    if config.FAIL2BAN_ENABLED:
        try:
            # Check if running
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == 'fail2ban-server':
                    status['running'] = True
                    break
            
            # Get jail status
            for jail in config.FAIL2BAN_JAILS:
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
        'enabled': config.FIREWALL_ENABLED,
        'active': False,
        'ports': []
    }
    
    if config.FIREWALL_ENABLED:
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
                         version=config.VERSION,
                         now = now,
                         year=now.year)

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
                         version=config.VERSION,
                         now = now ,
                         year=now.year)

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
        rule_path = os.path.join(config.YARA_RULES, rule_name)
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
    scan_log = os.path.join(config.LOG_DIR, 'edr.log')
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
    if config.YARA_ENABLED:
        yara_rules = [f for f in os.listdir(config.YARA_RULES) 
                     if f.endswith('.yar') or f.endswith('.yara')]
    
    context = {
        'scan_paths': config.SCAN_PATHS,
        'yara_rules': yara_rules,
        'last_scans': get_last_scan_results(),
        'version': config.VERSION,
        'year': now.year
    }
    return render_template('scans.html', **context , now = now)

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
            file.save(os.path.join(config.YARA_RULES, filename))
            return jsonify({'status': 'success', 'message': 'YARA rule uploaded'})
    
    # GET request - list rules
    yara_rules = [f for f in os.listdir(config.YARA_RULES) 
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
        'timestamp': now.isoformat()
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
        'timestamp': now.isoformat()
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
        return os.path.exists(config.GEOIP_DB_PATH)
    except:
        return False

def get_geoip_info(ip_address):
    """Get GeoIP information for an IP address"""
    try:
        import geoip2.database
        with geoip2.database.Reader(config.GEOIP_DB_PATH) as reader:
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
        with geoip2.database.Reader(config.ASN_DB_PATH) as reader:
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
        malicious_ports = config.get_malicious_ports()
        
        # Get all network data
        network_data = get_network_data(malicious_ports)
        
        return render_template("network.html",
            malicious_connections=network_data['malicious_connections'],
            malicious_listening_ports=network_data['malicious_listening_ports'],
            network_interfaces=network_data['interfaces'],
            bandwidth_stats=network_data['bandwidth_stats'],  # Make sure this matches the template
            scan_time=now.strftime("%Y-%m-%d %H:%M:%S"),
            version=config.VERSION,
            year=now.year,
            malicious_ports_config=malicious_ports
        )

    except Exception as e:
        log_event("ERROR", "high", "Network monitoring failed", {'error': str(e)})
        return render_template("network.html",
            error=str(e),
            version=config.VERSION,
            year=now.year
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
    config_path = os.path.join(config.CONFIG_DIR, 'malicious_ports.json')
    
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
        






def analyze_processes():
    """Analyze running processes for malicious behavior and anomalies"""
    suspicious_processes = []
    normal_processes = set()
    
    # Load baseline of normal processes
    baseline_path = os.path.join(config.BASELINE_DIR, 'process_baseline.txt')
    if os.path.exists(baseline_path):
        with open(baseline_path, 'r') as f:
            normal_processes = set(line.strip() for line in f)
    
    # Load malicious process patterns from config or file
    malicious_patterns = [
        r'miner', r'crypto', r'coinminer', r'worm', r'botnet',
        r'backdoor', r'trojan', r'keylogger', r'ransomware'
    ]
    malicious_process_file = os.path.join(config.SIGNATURES_DIR, 'malicious_processes.txt')
    if os.path.exists(malicious_process_file):
        with open(malicious_process_file, 'r') as f:
            malicious_patterns.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time', 'cpu_percent', 'memory_percent']):
        try:
            proc_info = proc.info
            suspicion_score = 0
            reasons = []
            
            # Check for processes with deleted binaries
            if proc_info['exe'] and not os.path.exists(proc_info['exe']):
                suspicion_score += 30
                reasons.append('Binary deleted but process still running')
            
            # Check for processes not in baseline
            if normal_processes and proc_info['name'] not in normal_processes:
                suspicion_score += 20
                reasons.append('Process not in baseline')
            
            # Check for suspicious names/patterns
            for pattern in malicious_patterns:
                if re.search(pattern, proc_info['name'].lower(), re.IGNORECASE) or \
                   (proc_info['cmdline'] and any(re.search(pattern, ' '.join(proc_info['cmdline']).lower(), re.IGNORECASE) for cmd in proc_info['cmdline'])):
                    suspicion_score += 40
                    reasons.append(f'Matches malicious pattern: {pattern}')
            
            # Check for high resource usage
            cpu_percent = proc_info['cpu_percent'] or 0
            memory_percent = proc_info['memory_percent'] or 0
            if cpu_percent > 80:
                suspicion_score += 15
                reasons.append(f'High CPU usage: {cpu_percent}%')
            if memory_percent > 50:
                suspicion_score += 15
                reasons.append(f'High memory usage: {memory_percent}%')
            
            # Check for hidden processes
            try:
                cmdline = open(f"/proc/{proc_info['pid']}/cmdline").read()
                if not cmdline or '\x00' not in cmdline:
                    suspicion_score += 30
                    reasons.append('Possible hidden process')
            except:
                pass
            
            if suspicion_score >= 30 or reasons:
                suspicious_processes.append({
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'exe': proc_info['exe'] or 'N/A',
                    'cmdline': proc_info['cmdline'] or [],
                    'username': proc_info['username'] or 'N/A',
                    'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat(),
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory_percent,
                    'suspicion_score': suspicion_score,
                    'reasons': reasons
                })
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            log_event("ERROR", "medium", f"Process analysis failed for PID {proc_info['pid']}", {'error': str(e)})
    
    return sorted(suspicious_processes, key=lambda x: x['suspicion_score'], reverse=True)

def get_high_resource_processes(limit=10):
    """Get processes with highest CPU and RAM usage"""
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cpu_percent', 'memory_percent', 'memory_info']):
        try:
            proc_info = proc.info
            memory_usage = proc_info['memory_info'].rss / 1024 / 1024  # Convert to MB
            
            processes.append({
                'pid': proc_info['pid'],
                'name': proc_info['name'],
                'exe': proc_info['exe'] or 'N/A',
                'username': proc_info['username'] or 'N/A',
                'cpu_percent': proc_info['cpu_percent'] or 0,
                'memory_percent': proc_info['memory_percent'] or 0,
                'memory_mb': round(memory_usage, 2),
                'combined_score': (proc_info['cpu_percent'] or 0) + (proc_info['memory_percent'] or 0)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            log_event("ERROR", "medium", f"Resource analysis failed for PID {proc_info['pid']}", {'error': str(e)})
    
    # Sort by combined score and limit results
    return sorted(processes, key=lambda x: x['combined_score'], reverse=True)[:limit]

@app.route('/process')
def process_dashboard():
    """Process monitoring dashboard"""
    try:
        malicious_processes = analyze_processes()
        high_resource_processes = get_high_resource_processes()
        
        context = {
            'malicious_processes': malicious_processes,
            'high_resource_processes': high_resource_processes,
            'version': config.VERSION,
            'year': now.year,
            'scan_time': now.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return render_template('process.html', **context, now=now)
    except Exception as e:
        log_event("ERROR", "high", "Process monitoring dashboard failed", {'error': str(e)})
        return render_template('process.html',
                             error=str(e),
                             version=config.VERSION,
                             year=now.year,
                             now=now), 500

@app.route('/api/process/malicious')
def get_malicious_processes():
    """API endpoint for malicious processes"""
    try:
        malicious_processes = analyze_processes()
        return jsonify({
            'status': 'success',
            'processes': malicious_processes,
            'count': len(malicious_processes)
        })
    except Exception as e:
        log_event("ERROR", "high", "Failed to get malicious processes", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/process/resources')
def get_resource_processes():
    """API endpoint for high resource usage processes"""
    try:
        high_resource_processes = get_high_resource_processes()
        return jsonify({
            'status': 'success',
            'processes': high_resource_processes,
            'count': len(high_resource_processes)
        })
    except Exception as e:
        log_event("ERROR", "high", "Failed to get resource processes", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500



@app.route('/manage_users')
def manage_users():
    """User management dashboard with accessibility checks and abnormal activity detection"""
    try:
        # Get all system users
        users = get_system_users()
        
        # Check for suspicious user accounts
        suspicious_users = detect_suspicious_users(users)
        
        # Check for abnormal user activity
        abnormal_activity = detect_abnormal_user_activity()
        
        # Get sudoers list
        sudoers = get_sudoers_list()
        
        # Get recent failed login attempts
        failed_logins = get_failed_login_attempts()
        
        # Get users with active sessions
        active_sessions = get_active_sessions()
        
        context = {
            'users': users,
            'suspicious_users': suspicious_users,
            'abnormal_activity': abnormal_activity,
            'sudoers': sudoers,
            'failed_logins': failed_logins,
            'active_sessions': active_sessions,
            'version': config.VERSION,
            'year': now.year,
            'scan_time': now.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return render_template('manage_users.html', **context, now=now)
        
    except Exception as e:
        log_event("ERROR", "high", "User management dashboard failed", {'error': str(e)})
        return render_template('manage_users.html',
                            error=str(e),
                            version=config.VERSION,
                            year=now.year,
                            now=now), 500

def get_system_users():
    """Get all system users with detailed information"""
    users = []
    
    try:
        # Read /etc/passwd
        with open('/etc/passwd', 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        users.append({
                            'username': parts[0],
                            'uid': parts[2],
                            'gid': parts[3],
                            'home': parts[5],
                            'shell': parts[6],
                            'last_login': get_last_login(parts[0]),
                            'password_status': get_password_status(parts[0]),
                            'locked': is_account_locked(parts[0])
                        })
    except Exception as e:
        log_event("ERROR", "high", "Failed to read /etc/passwd", {'error': str(e)})
    
    return users

def detect_suspicious_users(users):
    """Detect suspicious user accounts"""
    suspicious = []
    
    # Common suspicious patterns
    suspicious_patterns = [
        r'backdoor', r'rootkit', r'admin\d+', r'guest\d+', 
        r'test\d+', r'user\d+', r'default', r'toor'
    ]
    
    for user in users:
        try:
            reasons = []
            
            # Check for UID 0 (root equivalent)
            if user['uid'] == '0' and user['username'] != 'root':
                reasons.append('Non-root user with UID 0 (root privileges)')
            
            # Check for suspicious usernames
            for pattern in suspicious_patterns:
                if re.search(pattern, user['username'], re.IGNORECASE):
                    reasons.append(f'Suspicious username pattern: {pattern}')
            
            # Check for users with no password
            if user['password_status'] == 'no password':
                reasons.append('Account has no password set')
            
            # Check for locked accounts
            if user['locked']:
                reasons.append('Account is locked')
            
            # Check for unusual home directories
            if not user['home'].startswith('/home/') and user['home'] != '/':
                reasons.append(f'Unusual home directory: {user["home"]}')
            
            # Check for unusual shells
            unusual_shells = ['/bin/false', '/usr/sbin/nologin', '/dev/null']
            if user['shell'] in unusual_shells:
                reasons.append(f'Unusual shell: {user["shell"]}')
            
            if reasons:
                suspicious.append({
                    'username': user['username'],
                    'uid': user['uid'],
                    'reasons': reasons,
                    'home': user['home'],
                    'shell': user['shell']
                })
                
        except Exception as e:
            log_event("ERROR", "medium", f"Failed to analyze user {user['username']}", {'error': str(e)})
    
    return suspicious

def detect_abnormal_user_activity():
    """Detect abnormal user activity from logs"""
    abnormal = []
    
    # Check for suspicious login patterns
    try:
        log_files = [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/utmp',
            '/var/log/wtmp',
            '/var/log/btmp'
        ]
        
        suspicious_patterns = [
            r'Failed password for .* from',
            r'authentication failure',
            r'POSSIBLE BREAK-IN ATTEMPT',
            r'Invalid user',
            r'user .* not allowed to execute',
            r'session opened for user root',
            r'SUDO: .* : user NOT in sudoers'
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    for line in f:
                        for pattern in suspicious_patterns:
                            if re.search(pattern, line):
                                abnormal.append({
                                    'log_file': log_file,
                                    'entry': line.strip(),
                                    'pattern': pattern,
                                    'timestamp': extract_log_timestamp(line)
                                })
                                break  # Only count once per line
    except Exception as e:
        log_event("ERROR", "high", "Failed to detect abnormal user activity", {'error': str(e)})
    
    return abnormal

def get_sudoers_list():
    """Get list of users with sudo privileges"""
    sudoers = []
    
    try:
        # Check /etc/sudoers and /etc/sudoers.d/*
        sudo_files = ['/etc/sudoers']
        sudo_files.extend(glob.glob('/etc/sudoers.d/*'))
        
        for sudo_file in sudo_files:
            if os.path.isfile(sudo_file):
                with open(sudo_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Match user privilege lines
                            match = re.match(r'^(\S+)\s+.*=.*\(.*\)\s*.*$', line)
                            if match:
                                username = match.group(1)
                                if username not in ['root', '%admin', '%sudo']:
                                    sudoers.append({
                                        'username': username,
                                        'privilege': line,
                                        'source_file': sudo_file
                                    })
    except Exception as e:
        log_event("ERROR", "high", "Failed to get sudoers list", {'error': str(e)})
    
    return sudoers

def get_failed_login_attempts(limit=20):
    """Get recent failed login attempts"""
    failed_logins = []
    
    try:
        # Check btmp (failed logins)
        if os.path.exists('/var/log/btmp'):
            result = subprocess.run(
                ['lastb', '-a', '-n', str(limit)],
                capture_output=True, text=True
            )
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        failed_logins.append({
                            'username': parts[0],
                            'ip': parts[-1],
                            'device': parts[1],
                            'timestamp': ' '.join(parts[2:-1])
                        })
    except Exception as e:
        log_event("ERROR", "medium", "Failed to get failed logins", {'error': str(e)})
    
    return failed_logins

def get_active_sessions():
    """Get currently active user sessions"""
    sessions = []
    
    try:
        # Check who command
        result = subprocess.run(
            ['who', '-u'],
            capture_output=True, text=True
        )
        
        for line in result.stdout.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 7:
                    sessions.append({
                        'username': parts[0],
                        'terminal': parts[1],
                        'login_time': ' '.join(parts[2:5]),
                        'idle': parts[5],
                        'pid': parts[6],
                        'ip': parts[7] if len(parts) > 7 else 'local'
                    })
    except Exception as e:
        log_event("ERROR", "medium", "Failed to get active sessions", {'error': str(e)})
    
    return sessions

def get_last_login(username):
    """Get last login time for a user"""
    try:
        result = subprocess.run(
            ['last', '-n', '1', username],
            capture_output=True, text=True
        )
        
        if result.stdout.strip():
            line = result.stdout.split('\n')[0]
            if 'still logged in' in line:
                return 'Currently logged in'
            parts = line.split()
            if len(parts) >= 4:
                return ' '.join(parts[3:7])
        return 'Never logged in'
    except:
        return 'Unknown'

def get_password_status(username):
    """Get password status for a user"""
    try:
        result = subprocess.run(
            ['passwd', '-S', username],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            parts = result.stdout.split()
            if len(parts) >= 2:
                return parts[1]
        return 'Unknown'
    except:
        return 'Unknown'

def is_account_locked(username):
    """Check if user account is locked"""
    try:
        result = subprocess.run(
            ['passwd', '-S', username],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            return 'locked' in result.stdout.lower()
        return False
    except:
        return False

def extract_log_timestamp(log_line):
    """Extract timestamp from log line"""
    try:
        # Common log formats
        formats = [
            '%b %d %H:%M:%S',  # Month Day Time
            '%Y-%m-%d %H:%M:%S'  # ISO format
        ]
        
        for fmt in formats:
            try:
                # Try to find timestamp in first 20 chars
                ts_str = log_line[:20].strip()
                ts = datetime.strptime(ts_str, fmt)
                return ts.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                continue
        return 'Unknown'
    except:
        return 'Unknown'

@app.route('/api/user/lock', methods=['POST'])
def lock_user_account():
    """Lock a user account"""
    username = request.form.get('username')
    if not username:
        return jsonify({'status': 'error', 'message': 'Username required'}), 400
    
    try:
        result = subprocess.run(
            ['passwd', '-l', username],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            log_event("USER", "high", f"Locked user account: {username}")
            return jsonify({'status': 'success', 'message': f'Locked user {username}'})
        else:
            error = result.stderr.strip() or 'Unknown error'
            log_event("ERROR", "high", f"Failed to lock user {username}", {'error': error})
            return jsonify({'status': 'error', 'message': error}), 400
    except Exception as e:
        log_event("ERROR", "high", f"Failed to lock user {username}", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/user/unlock', methods=['POST'])
def unlock_user_account():
    """Unlock a user account"""
    username = request.form.get('username')
    if not username:
        return jsonify({'status': 'error', 'message': 'Username required'}), 400
    
    try:
        result = subprocess.run(
            ['passwd', '-u', username],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            log_event("USER", "high", f"Unlocked user account: {username}")
            return jsonify({'status': 'success', 'message': f'Unlocked user {username}'})
        else:
            error = result.stderr.strip() or 'Unknown error'
            log_event("ERROR", "high", f"Failed to unlock user {username}", {'error': error})
            return jsonify({'status': 'error', 'message': error}), 400
    except Exception as e:
        log_event("ERROR", "high", f"Failed to unlock user {username}", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/user/kill_session', methods=['POST'])
def kill_user_session():
    """Kill a user session"""
    pid = request.form.get('pid')
    if not pid:
        return jsonify({'status': 'error', 'message': 'PID required'}), 400
    
    try:
        os.kill(int(pid), signal.SIGKILL)
        log_event("USER", "high", f"Killed user session with PID: {pid}")
        return jsonify({'status': 'success', 'message': f'Killed session {pid}'})
    except Exception as e:
        log_event("ERROR", "high", f"Failed to kill session {pid}", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500






@app.route('/manage_kernel_modules')
def manage_kernel_modules():
    """Kernel module management dashboard with suspicious module detection"""
    try:
        # Get all loaded kernel modules
        loaded_modules = get_loaded_kernel_modules()
        
        # Get all available kernel modules
        all_modules = get_all_kernel_modules()
        
        # Detect suspicious modules
        suspicious_modules = detect_suspicious_modules(loaded_modules)
        
        # Check kernel module signing status
        signing_status = check_module_signing()
        
        # Check for module hijacking vulnerabilities
        hijacking_vulns = check_module_hijacking()
        
        # Get kernel configuration
        kernel_config = get_kernel_config()
        
        context = {
            'loaded_modules': loaded_modules,
            'all_modules': all_modules,
            'suspicious_modules': suspicious_modules,
            'signing_status': signing_status,
            'hijacking_vulns': hijacking_vulns,
            'kernel_config': kernel_config,
            'version': config.VERSION,
            'year': now.year,
            'scan_time': now.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return render_template('kernel_modules.html', **context, now=now)
        
    except Exception as e:
        log_event("ERROR", "high", "Kernel module management failed", {'error': str(e)})
        return render_template('kernel_modules.html',
                            error=str(e),
                            version=config.VERSION,
                            year=now.year,
                            now=now), 500

def get_loaded_kernel_modules():
    """Get currently loaded kernel modules with details"""
    modules = []
    
    try:
        # Read /proc/modules
        with open('/proc/modules', 'r') as f:
            for line in f:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        modules.append({
                            'name': parts[0],
                            'size': int(parts[1]),
                            'refcount': int(parts[2]),
                            'used_by': parts[3:-1],
                            'status': parts[-1],
                            'signature': check_module_signature(parts[0]),
                            'tainted': is_module_tainted(parts[0]),
                            'path': find_module_path(parts[0])
                        })
    except Exception as e:
        log_event("ERROR", "high", "Failed to read loaded modules", {'error': str(e)})
    
    return modules

def get_all_kernel_modules():
    """Get all available kernel modules (not necessarily loaded)"""
    modules = []
    module_dirs = [
        '/lib/modules/' + os.uname().release,
        '/usr/lib/modules/' + os.uname().release
    ]
    
    for module_dir in module_dirs:
        if os.path.exists(module_dir):
            for root, _, files in os.walk(module_dir):
                for file in files:
                    if file.endswith('.ko') or file.endswith('.ko.xz'):
                        modules.append({
                            'name': os.path.splitext(os.path.splitext(file)[0])[0],
                            'path': os.path.join(root, file),
                            'size': os.path.getsize(os.path.join(root, file)),
                            'loaded': is_module_loaded(os.path.splitext(os.path.splitext(file)[0])[0])
                        })
    
    return modules

def detect_suspicious_modules(loaded_modules):
    """Detect suspicious or malicious kernel modules"""
    suspicious = []
    
    # Known malicious/suspicious module patterns
    malicious_patterns = [
        r'rootkit', r'backdoor', r'hide', r'stealth', r'keylogger',
        r'hook', r'inject', r'\.hidden$', r'_hack', r'_malicious'
    ]
    
    # Known vulnerable modules
    vulnerable_modules = [
        'nvidia', 'vmware', 'virtualbox', 'dccp', 'sctp', 'tipc'
    ]
    
    for module in loaded_modules:
        try:
            reasons = []
            
            # Check for malicious name patterns
            for pattern in malicious_patterns:
                if re.search(pattern, module['name'], re.IGNORECASE):
                    reasons.append(f'Matches malicious pattern: {pattern}')
            
            # Check for unsigned modules
            if module.get('signature') == 'unsigned':
                reasons.append('Module is unsigned')
            
            # Check for tainted modules
            if module.get('tainted'):
                reasons.append('Module is tainted')
            
            # Check for vulnerable modules
            if module['name'] in vulnerable_modules:
                reasons.append('Known vulnerable module')
            
            # Check for unusual paths
            if module.get('path') and not any(p in module['path'] for p in ['/lib/modules/', '/usr/lib/modules/']):
                reasons.append(f'Unusual module path: {module["path"]}')
            
            # Check for hidden modules (present in memory but not in /proc/modules)
            if not module.get('path') or not os.path.exists(module['path']):
                reasons.append('Module file not found on disk (possible hidden module)')
            
            if reasons:
                suspicious.append({
                    'name': module['name'],
                    'reasons': reasons,
                    'size': module.get('size', 0),
                    'refcount': module.get('refcount', 0),
                    'path': module.get('path', 'unknown'),
                    'signature': module.get('signature', 'unknown')
                })
                
        except Exception as e:
            log_event("ERROR", "medium", f"Failed to analyze module {module['name']}", {'error': str(e)})
    
    return suspicious

def check_module_signing():
    """Check kernel module signing enforcement status"""
    try:
        # Check if module signing is enforced
        with open('/proc/sys/kernel/modules_disabled', 'r') as f:
            modules_disabled = f.read().strip()
        
        with open('/proc/sys/kernel/module_sig_enforce', 'r') as f:
            sig_enforce = f.read().strip()
        
        with open('/proc/sys/kernel/module_sig_all', 'r') as f:
            sig_all = f.read().strip()
        
        return {
            'modules_disabled': modules_disabled,
            'sig_enforce': sig_enforce,
            'sig_all': sig_all,
            'secureboot': check_secureboot_status()
        }
    except Exception as e:
        log_event("ERROR", "high", "Failed to check module signing", {'error': str(e)})
        return {
            'modules_disabled': 'unknown',
            'sig_enforce': 'unknown',
            'sig_all': 'unknown',
            'secureboot': 'unknown'
        }

def check_module_hijacking():
    """Check for kernel module hijacking vulnerabilities"""
    vulns = []
    
    # Check for world-writable module directories
    module_dirs = [
        '/lib/modules',
        '/usr/lib/modules',
        '/etc/modprobe.d',
        '/etc/modules-load.d'
    ]
    
    for module_dir in module_dirs:
        if os.path.exists(module_dir):
            mode = os.stat(module_dir).st_mode
            if mode & 0o002:  # World-writable
                vulns.append({
                    'path': module_dir,
                    'issue': 'World-writable module directory',
                    'severity': 'high'
                })
    
    # Check for modprobe.d hijacking
    modprobe_paths = [
        '/etc/modprobe.d',
        '/run/modprobe.d',
        '/usr/local/lib/modprobe.d',
        '/usr/lib/modprobe.d'
    ]
    
    for path in modprobe_paths:
        if os.path.exists(path):
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    mode = os.stat(file_path).st_mode
                    if mode & 0o002:  # World-writable
                        vulns.append({
                            'path': file_path,
                            'issue': 'World-writable modprobe configuration',
                            'severity': 'critical'
                        })
    
    return vulns

def get_kernel_config():
    """Get important kernel configuration parameters"""
    config = {}
    
    try:
        # Try to read /proc/config.gz
        if os.path.exists('/proc/config.gz'):
            result = subprocess.run(
                ['zcat', '/proc/config.gz'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('CONFIG_'):
                        key, val = line.split('=', 1)
                        config[key] = val.strip('"')
        
        # Try to read /boot/config-*
        for config_file in glob.glob('/boot/config-*'):
            with open(config_file, 'r') as f:
                for line in f:
                    if line.startswith('CONFIG_'):
                        key, val = line.split('=', 1)
                        config[key] = val.strip('"')
    
    except Exception as e:
        log_event("ERROR", "medium", "Failed to read kernel config", {'error': str(e)})
    
    # Filter for important security-related parameters
    important_params = {
        'CONFIG_MODULE_SIG': 'Module signing',
        'CONFIG_MODULE_SIG_FORCE': 'Force module signing',
        'CONFIG_MODULE_SIG_ALL': 'Sign all modules',
        'CONFIG_DEBUG_KERNEL': 'Kernel debugging',
        'CONFIG_STRICT_DEVMEM': 'Restrict /dev/mem access',
        'CONFIG_IO_STRICT_DEVMEM': 'Strict /dev/mem I/O',
        'CONFIG_SECURITY': 'Security framework',
        'CONFIG_SECURITY_YAMA': 'Yama security module',
        'CONFIG_SECURITY_SELINUX': 'SELinux',
        'CONFIG_SECURITY_APPARMOR': 'AppArmor',
        'CONFIG_CC_STACKPROTECTOR': 'Stack protector',
        'CONFIG_CC_STACKPROTECTOR_STRONG': 'Strong stack protector',
        'CONFIG_RANDOMIZE_BASE': 'KASLR (Address space randomization)',
        'CONFIG_STACKPROTECTOR': 'Stack protection',
        'CONFIG_SYN_COOKIES': 'SYN flood protection',
        'CONFIG_DEBUG_CREDENTIALS': 'Credential debugging'
    }
    
    filtered_config = {}
    for param, desc in important_params.items():
        filtered_config[desc] = config.get(param, 'not set')
    
    return filtered_config

# Helper functions
def check_module_signature(module_name):
    """Check if a module is signed"""
    try:
        result = subprocess.run(
            ['modinfo', module_name],
            capture_output=True, text=True
        )
        
        if 'signer:' in result.stdout:
            return 'signed'
        return 'unsigned'
    except:
        return 'unknown'

def is_module_tainted(module_name):
    """Check if a module is tainted"""
    try:
        with open('/proc/sys/kernel/tainted', 'r') as f:
            tainted = int(f.read().strip())
        
        # Check if tainted by external module (bit 1)
        return bool(tainted & (1 << 1))
    except:
        return False

def find_module_path(module_name):
    """Find the path to a kernel module file"""
    try:
        result = subprocess.run(
            ['modinfo', '-F', 'filename', module_name],
            capture_output=True, text=True
        )
        return result.stdout.strip()
    except:
        return None

def is_module_loaded(module_name):
    """Check if a module is currently loaded"""
    try:
        with open('/proc/modules', 'r') as f:
            for line in f:
                if line.startswith(module_name + ' '):
                    return True
        return False
    except:
        return False

def check_secureboot_status():
    """Check if Secure Boot is enabled"""
    try:
        if os.path.exists('/sys/firmware/efi/efivars/SecureBoot-*'):
            return 'enabled'
        
        result = subprocess.run(
            ['mokutil', '--sb-state'],
            capture_output=True, text=True
        )
        if 'SecureBoot enabled' in result.stdout:
            return 'enabled'
        return 'disabled'
    except:
        return 'unknown'

@app.route('/api/kernel_modules/load', methods=['POST'])
def load_kernel_module():
    """Load a kernel module"""
    module_name = request.form.get('module_name')
    if not module_name:
        return jsonify({'status': 'error', 'message': 'Module name required'}), 400
    
    try:
        result = subprocess.run(
            ['modprobe', module_name],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            log_event("KERNEL", "info", f"Loaded kernel module: {module_name}")
            return jsonify({'status': 'success', 'message': f'Loaded module {module_name}'})
        else:
            error = result.stderr.strip() or 'Unknown error'
            log_event("ERROR", "high", f"Failed to load module {module_name}", {'error': error})
            return jsonify({'status': 'error', 'message': error}), 400
    except Exception as e:
        log_event("ERROR", "high", f"Failed to load module {module_name}", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/kernel_modules/unload', methods=['POST'])
def unload_kernel_module():
    """Unload a kernel module"""
    module_name = request.form.get('module_name')
    if not module_name:
        return jsonify({'status': 'error', 'message': 'Module name required'}), 400
    
    try:
        result = subprocess.run(
            ['rmmod', module_name],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            log_event("KERNEL", "info", f"Unloaded kernel module: {module_name}")
            return jsonify({'status': 'success', 'message': f'Unloaded module {module_name}'})
        else:
            error = result.stderr.strip() or 'Unknown error'
            log_event("ERROR", "high", f"Failed to unload module {module_name}", {'error': error})
            return jsonify({'status': 'error', 'message': error}), 400
    except Exception as e:
        log_event("ERROR", "high", f"Failed to unload module {module_name}", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/kernel_modules/blacklist', methods=['POST'])
def blacklist_kernel_module():
    """Blacklist a kernel module"""
    module_name = request.form.get('module_name')
    if not module_name:
        return jsonify({'status': 'error', 'message': 'Module name required'}), 400
    
    try:
        blacklist_path = '/etc/modprobe.d/blacklist.conf'
        with open(blacklist_path, 'a') as f:
            f.write(f'\nblacklist {module_name}\n')
        
        log_event("KERNEL", "info", f"Blacklisted kernel module: {module_name}")
        return jsonify({'status': 'success', 'message': f'Blacklisted module {module_name}'})
    except Exception as e:
        log_event("ERROR", "high", f"Failed to blacklist module {module_name}", {'error': str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500






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
            time.sleep(config.SCAN_INTERVAL)
    
    thread = threading.Thread(target=scan_loop)
    thread.daemon = True
    thread.start()

# =============================================
# Initialization
# =============================================
# Add this to your Flask app (where you initialize your app)



if __name__ == '__main__':
    # Initialize directories and logging
    init_directories()
    setup_logging()
    
    # Log startup
    log_event("SYSTEM", "info", "EDR system starting up", {
        'version': config.VERSION,
        'machine_id': config.MACHINE_ID
    })
    
    # Start security services
    if config.SURICATA_ENABLED:
        start_suricata()
        threading.Thread(target=monitor_suricata_logs, daemon=True).start()
    
    if config.FAIL2BAN_ENABLED:
        configure_fail2ban()
    
    if config.FIREWALL_ENABLED:
        manage_firewall()
    
    # Start monitoring threads
    try:
        start_file_monitoring()
    except Exception as e:
        log_event("ERROR", "high", "Failed to start file monitoring", {'error': str(e)})
    
    start_periodic_scans()



    
    
    # Start the Flask app
    app.run(host='0.0.0.0', port=5005, debug=True)