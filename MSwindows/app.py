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
import threading
import glob
import re
import shutil
import winreg
import wmi
import pythoncom
from flask import Flask, jsonify, request, render_template, Response, redirect, url_for

app = Flask(__name__)

# =============================================
# Configuration
# =============================================

class Config:
    # Directories
    APP_DIR = os.path.join(os.environ['PROGRAMDATA'], 'WindowsEDR')
    LOG_DIR = os.path.join(APP_DIR, 'logs')
    QUARANTINE_DIR = os.path.join(APP_DIR, 'quarantine')
    SIGNATURES_DIR = os.path.join(APP_DIR, 'signatures')
    YARA_RULES = os.path.join(APP_DIR, 'yara_rules')
    REPORT_DIR = os.path.join(APP_DIR, 'reports')
    
    # Scanning
    SCAN_TIMEOUT = 300  # 5 minutes
    SCAN_INTERVAL = 3600  # 1 hour
    
    # Services
    SURICATA_ENABLED = False
    SURICATA_DIR = os.path.join(APP_DIR, 'suricata')
    SURICATA_RULES = os.path.join(SURICATA_DIR, 'rules')
    SURICATA_LOGS = os.path.join(SURICATA_DIR, 'logs')
    
    # Version
    VERSION = "1.0"
    
    @staticmethod
    def init_directories():
        """Create all required directories"""
        dirs = [
            Config.APP_DIR,
            Config.LOG_DIR,
            Config.QUARANTINE_DIR,
            Config.SIGNATURES_DIR,
            Config.YARA_RULES,
            Config.REPORT_DIR,
            Config.SURICATA_DIR,
            Config.SURICATA_RULES,
            Config.SURICATA_LOGS
        ]
        
        for dir_path in dirs:
            os.makedirs(dir_path, exist_ok=True)

# =============================================
# Initialization
# =============================================

def init_directories():
    """Initialize all required directories"""
    Config.init_directories()

def setup_logging():
    """Configure application logging"""
    log_file = os.path.join(Config.LOG_DIR, 'edr.log')
    handler = RotatingFileHandler(log_file, maxBytes=1000000, backupCount=5)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

def log_event(event_type, level, message, extra_info=None):
    """Log security events"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': event_type,
        'level': level,
        'message': message
    }
    
    if extra_info:
        log_entry['extra_info'] = extra_info
    
    app.logger.info(json.dumps(log_entry))

# =============================================
# Antivirus Scanning
# =============================================

def run_clamav_scan(scan_path):
    """Run ClamAV scan on Windows"""
    try:
        clamscan_path = r'C:\Program Files\ClamAV\clamscan.exe'
        if not os.path.exists(clamscan_path):
            return {
                'status': 'error',
                'message': 'ClamAV not found',
                'timestamp': datetime.now().isoformat()
            }
        
        cmd = [clamscan_path, '-r', '--infected', '--no-summary']
        if scan_path:
            cmd.append(scan_path)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.SCAN_TIMEOUT
        )
        
        infected_files = []
        if result.returncode == 1:  # Found viruses
            for line in result.stdout.split('\n'):
                if 'FOUND' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        infected_files.append({
                            'file': parts[0].strip(),
                            'detection': parts[1].strip()
                        })
        
        status = 'clean' if result.returncode == 0 else 'infected'
        
        return {
            'status': status,
            'infected_files': infected_files,
            'infected_count': len(infected_files),
            'output': result.stdout,
            'message': f"Found {len(infected_files)} infected files" if infected_files else "No threats found",
            'timestamp': datetime.now().isoformat()
        }
        
    except subprocess.TimeoutExpired:
        return {
            'status': 'error',
            'message': 'Scan timed out',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }

def run_defender_scan(scan_path):
    """Run Windows Defender scan"""
    try:
        cmd = ['powershell', '-Command', 
               f'Start-MpScan -ScanPath "{scan_path}" -ScanType FullScan | ConvertTo-Json']
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.SCAN_TIMEOUT
        )
        
        try:
            scan_result = json.loads(result.stdout)
            return {
                'status': 'success',
                'result': scan_result,
                'timestamp': datetime.now().isoformat()
            }
        except json.JSONDecodeError:
            return {
                'status': 'error',
                'message': 'Failed to parse Defender output',
                'output': result.stdout,
                'timestamp': datetime.now().isoformat()
            }
            
    except subprocess.TimeoutExpired:
        return {
            'status': 'error',
            'message': 'Scan timed out',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }

def run_yara_scan(scan_path, rule_name):
    """Run YARA scan on Windows"""
    try:
        rule_path = os.path.join(Config.YARA_RULES, rule_name)
        if not os.path.isfile(rule_path):
            return {
                'status': 'error',
                'message': f'YARA rule file not found: {rule_name}',
                'timestamp': datetime.now().isoformat()
            }
        
        rules = yara.compile(filepath=rule_path)
        matches = []
        
        if os.path.isdir(scan_path):
            for root, _, files in os.walk(scan_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        for match in rules.match(file_path):
                            matches.append({
                                'file': file_path,
                                'rule': match.rule,
                                'tags': list(match.tags),
                                'meta': dict(match.meta)
                            })
                    except Exception as e:
                        app.logger.warning(f"Error scanning {file_path}: {str(e)}")
        elif os.path.isfile(scan_path):
            for match in rules.match(scan_path):
                matches.append({
                    'file': scan_path,
                    'rule': match.rule,
                    'tags': list(match.tags),
                    'meta': dict(match.meta)
                })
        
        status = 'clean' if not matches else 'matches'
        
        return {
            'status': status,
            'matches': matches,
            'match_count': len(matches),
            'rule': rule_name,
            'message': f"Found {len(matches)} matches" if matches else "No matches found",
            'timestamp': datetime.now().isoformat()
        }
        
    except yara.SyntaxError as e:
        return {
            'status': 'error',
            'message': f"YARA rule syntax error: {str(e)}",
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }

# =============================================
# Firewall Management
# =============================================

def get_firewall_status():
    """Get Windows Firewall status"""
    try:
        cmd = ['netsh', 'advfirewall', 'show', 'allprofiles']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        status = {
            'domain': {},
            'private': {},
            'public': {}
        }
        
        current_profile = None
        for line in result.stdout.split('\n'):
            line = line.strip()
            if 'Profile Settings:' in line:
                current_profile = line.split()[0].lower()
            elif current_profile and 'State' in line:
                status[current_profile]['state'] = line.split()[-1]
            elif current_profile and 'Firewall Policy' in line:
                status[current_profile]['policy'] = ' '.join(line.split()[2:])
        
        return {
            'status': 'success',
            'result': status,
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }

def manage_firewall_rule(action, rule_name, direction='in', protocol='tcp', 
                        local_port='any', remote_ip='any', profile='any'):
    """Manage Windows Firewall rules"""
    try:
        cmd = ['netsh', 'advfirewall', 'firewall']
        
        if action == 'add':
            cmd.extend([
                'add', 'rule',
                f'name="{rule_name}"',
                f'dir={direction}',
                f'action=allow',
                f'protocol={protocol}',
                f'localport={local_port}',
                f'remoteip={remote_ip}',
                f'profile={profile}'
            ])
        elif action == 'delete':
            cmd.extend(['delete', 'rule', f'name="{rule_name}"'])
        else:
            return {
                'status': 'error',
                'message': 'Invalid action',
                'timestamp': datetime.now().isoformat()
            }
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            return {
                'status': 'success',
                'message': result.stdout.strip(),
                'timestamp': datetime.now().isoformat()
            }
        else:
            return {
                'status': 'error',
                'message': result.stderr.strip(),
                'timestamp': datetime.now().isoformat()
            }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }

# =============================================
# Suricata Integration
# =============================================

def start_suricata():
    """Start Suricata IDS/IPS on Windows"""
    if not Config.SURICATA_ENABLED:
        return False
    
    try:
        suricata_path = os.path.join(Config.SURICATA_DIR, 'suricata.exe')
        if not os.path.exists(suricata_path):
            log_event("SURICATA", "error", "Suricata executable not found")
            return False
        
        # Get network interfaces
        interfaces = get_network_interfaces()
        if not interfaces:
            log_event("SURICATA", "error", "No network interfaces found")
            return False
        
        # Start Suricata on first interface
        interface = interfaces[0]['name']
        cmd = [
            suricata_path,
            '-c', os.path.join(Config.SURICATA_DIR, 'suricata.yaml'),
            '-i', interface,
            '--set', f'default-rule-path={Config.SURICATA_RULES}',
            '--set', f'rule-files={",".join(os.listdir(Config.SURICATA_RULES))}',
            '--set', f'log-dir={Config.SURICATA_LOGS}'
        ]
        
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_event("SURICATA", "info", "Started Suricata IDS/IPS")
        return True
    except Exception as e:
        log_event("ERROR", "high", "Failed to start Suricata", {'error': str(e)})
        return False

def monitor_suricata_logs():
    """Monitor Suricata logs for alerts"""
    if not Config.SURICATA_ENABLED:
        return
    
    eve_log = os.path.join(Config.SURICATA_LOGS, 'eve.json')
    if not os.path.exists(eve_log):
        return
    
    try:
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
# Process Monitoring
# =============================================

def analyze_processes():
    """Analyze running processes for anomalies"""
    suspicious_processes = []
    
    # Known malicious process patterns
    malicious_patterns = [
        'mimikatz', 'cobaltstrike', 'metasploit', 'empire', 
        'powersploit', 'bloodhound', 'netspy', 'njrat',
        'quasar', 'darkcomet', 'nanocore', 'gh0st'
    ]
    
    try:
        pythoncom.CoInitialize()
        c = wmi.WMI()
        
        for process in c.Win32_Process():
            try:
                suspicion_score = 0
                reasons = []
                
                # Check process name against malicious patterns
                for pattern in malicious_patterns:
                    if re.search(pattern, process.Name, re.IGNORECASE):
                        suspicion_score += 40
                        reasons.append(f"Matches malicious pattern: {pattern}")
                
                # Check for unsigned processes
                if not is_process_signed(process.ProcessId):
                    suspicion_score += 20
                    reasons.append("Process is unsigned")
                
                # Check for hidden processes (no associated executable)
                if not process.ExecutablePath:
                    suspicion_score += 30
                    reasons.append("No executable path (possible hidden process)")
                
                # Check for unusual parent processes
                if process.ParentProcessId != 0:
                    parent = c.Win32_Process(ProcessId=process.ParentProcessId)
                    if parent and parent[0].Name.lower() not in ['explorer.exe', 'svchost.exe', 'services.exe']:
                        suspicion_score += 15
                        reasons.append(f"Unusual parent process: {parent[0].Name}")
                
                # Check for process injection
                if is_process_injected(process.ProcessId):
                    suspicion_score += 50
                    reasons.append("Possible process injection detected")
                
                if suspicion_score >= 30:
                    suspicious_processes.append({
                        'pid': process.ProcessId,
                        'name': process.Name,
                        'path': process.ExecutablePath or 'N/A',
                        'command_line': process.CommandLine or 'N/A',
                        'user': process.GetOwner()[0] if process.GetOwner() else 'N/A',
                        'creation_date': process.CreationDate,
                        'suspicion_score': suspicion_score,
                        'reasons': reasons
                    })
                    
            except Exception as e:
                app.logger.warning(f"Failed to analyze process {process.Name}: {str(e)}")
                continue
                
    except Exception as e:
        log_event("ERROR", "high", "Process analysis failed", {'error': str(e)})
    finally:
        pythoncom.CoUninitialize()
    
    return sorted(suspicious_processes, key=lambda x: x['suspicion_score'], reverse=True)

def is_process_signed(pid):
    """Check if a process is signed (simplified)"""
    try:
        process = psutil.Process(pid)
        exe_path = process.exe()
        if not exe_path:
            return False
            
        # In a real implementation, you would verify the digital signature
        # This is a simplified check
        return os.path.exists(exe_path)
    except:
        return False

def is_process_injected(pid):
    """Check for signs of process injection (simplified)"""
    try:
        process = psutil.Process(pid)
        
        # Check for mismatched memory regions
        # In a real implementation, you would analyze memory regions
        return False
    except:
        return False

# =============================================
# Registry Monitoring
# =============================================

def scan_registry_for_abnormalities():
    """Scan Windows Registry for suspicious entries"""
    suspicious_entries = []
    
    # Common persistence locations
    persistence_locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    ]
    
    # Known malicious patterns
    malicious_patterns = [
        'powershell -nop -w hidden -c',
        'rundll32',
        'regsvr32',
        'mshta',
        'wscript',
        'cscript',
        'certutil',
        'bitsadmin'
    ]
    
    for root, subkey in persistence_locations:
        try:
            with winreg.OpenKey(root, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                        
                        # Check for suspicious values
                        for pattern in malicious_patterns:
                            if isinstance(value, str) and pattern.lower() in value.lower():
                                suspicious_entries.append({
                                    'root': root,
                                    'subkey': subkey,
                                    'name': name,
                                    'value': value,
                                    'reason': f"Matches malicious pattern: {pattern}"
                                })
                                break
                                
                    except WindowsError:
                        break
        except WindowsError as e:
            app.logger.warning(f"Failed to access registry key {subkey}: {str(e)}")
    
    return suspicious_entries

# =============================================
# Memory Scanning
# =============================================

def scan_memory_for_malicious_activity():
    """Scan system memory for signs of malicious activity"""
    suspicious_memory = []
    
    try:
        pythoncom.CoInitialize()
        c = wmi.WMI()
        
        # Scan for suspicious modules in memory
        for process in c.Win32_Process():
            try:
                for module in process.Associators("Win32_ProcessToModule"):
                    module_name = module.Name.lower()
                    
                    # Check for known malicious patterns
                    if any(x in module_name for x in ['inject', 'hook', 'mimikatz', 'meterpreter']):
                        suspicious_memory.append({
                            'process_id': process.ProcessId,
                            'process_name': process.Name,
                            'module_name': module.Name,
                            'module_path': module.ExecutablePath,
                            'reason': "Suspicious module name"
                        })
            except Exception as e:
                app.logger.warning(f"Failed to scan memory for process {process.Name}: {str(e)}")
                
    except Exception as e:
        log_event("ERROR", "high", "Memory scanning failed", {'error': str(e)})
    finally:
        pythoncom.CoUninitialize()
    
    return suspicious_memory

# =============================================
# Network Monitoring
# =============================================

def get_network_interfaces():
    """Get list of network interfaces"""
    interfaces = []
    
    try:
        pythoncom.CoInitialize()
        c = wmi.WMI()
        
        for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            interfaces.append({
                'name': interface.Description,
                'ip_address': interface.IPAddress[0] if interface.IPAddress else 'N/A',
                'mac_address': interface.MACAddress,
                'is_dhcp_enabled': interface.DHCPEnabled
            })
            
    except Exception as e:
        log_event("ERROR", "high", "Failed to get network interfaces", {'error': str(e)})
    finally:
        pythoncom.CoUninitialize()
    
    return interfaces

def get_network_connections():
    """Get active network connections"""
    connections = []
    
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                try:
                    process = psutil.Process(conn.pid)
                    connections.append({
                        'pid': conn.pid,
                        'process_name': process.name(),
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status
                    })
                except psutil.NoSuchProcess:
                    connections.append({
                        'pid': conn.pid,
                        'process_name': 'Unknown',
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status
                    })
    except Exception as e:
        log_event("ERROR", "high", "Failed to get network connections", {'error': str(e)})
    
    return connections

# =============================================
# Flask Routes
# =============================================

@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html',
                         version=Config.VERSION,
                         timestamp=datetime.now().isoformat())

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scan endpoint"""
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        scan_path = request.form.get('scan_path', 'C:\\')
        
        if scan_type == 'clamav':
            result = run_clamav_scan(scan_path)
        elif scan_type == 'defender':
            result = run_defender_scan(scan_path)
        elif scan_type == 'yara':
            rule_name = request.form.get('yara_rule')
            result = run_yara_scan(scan_path, rule_name)
        else:
            result = {
                'status': 'error',
                'message': 'Invalid scan type',
                'timestamp': datetime.now().isoformat()
            }
        
        return jsonify(result)
    
    return render_template('scan.html',
                         yara_rules=os.listdir(Config.YARA_RULES),
                         version=Config.VERSION)

@app.route('/firewall', methods=['GET', 'POST'])
def firewall():
    """Firewall management"""
    if request.method == 'POST':
        action = request.form.get('action')
        rule_name = request.form.get('rule_name')
        
        if action == 'status':
            return jsonify(get_firewall_status())
        else:
            direction = request.form.get('direction', 'in')
            protocol = request.form.get('protocol', 'tcp')
            local_port = request.form.get('local_port', 'any')
            remote_ip = request.form.get('remote_ip', 'any')
            profile = request.form.get('profile', 'any')
            
            return jsonify(manage_firewall_rule(
                action, rule_name, direction, protocol, 
                local_port, remote_ip, profile
            ))
    
    return render_template('firewall.html',
                         version=Config.VERSION)

@app.route('/processes')
def processes():
    """Process monitoring"""
    return jsonify({
        'status': 'success',
        'processes': analyze_processes(),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/registry')
def registry():
    """Registry monitoring"""
    return jsonify({
        'status': 'success',
        'suspicious_entries': scan_registry_for_abnormalities(),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/memory')
def memory():
    """Memory scanning"""
    return jsonify({
        'status': 'success',
        'suspicious_memory': scan_memory_for_malicious_activity(),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/network')
def network():
    """Network monitoring"""
    return jsonify({
        'status': 'success',
        'interfaces': get_network_interfaces(),
        'connections': get_network_connections(),
        'timestamp': datetime.now().isoformat()
    })

# =============================================
# Main Execution
# =============================================

if __name__ == '__main__':
    init_directories()
    setup_logging()
    
    # Start Suricata if enabled
    if Config.SURICATA_ENABLED:
        if start_suricata():
            threading.Thread(target=monitor_suricata_logs, daemon=True).start()
    
    app.run(host='0.0.0.0', port=5000, debug=True)