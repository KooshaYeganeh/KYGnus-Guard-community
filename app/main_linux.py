# Configuration
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_session import Session
import paramiko
from io import StringIO
import os
import json
import re
from datetime import datetime
import tempfile
import config  # Import the config file
import logging
from logging.handlers import RotatingFileHandler
import yara
import threading
import time
import glob
import subprocess
import psutil
import signal
import datetime as mydate
import shlex
import traceback
from functools import lru_cache
import platform




app = Flask(__name__)
app.secret_key = 'Hermes'




# Load configuration from config.py
app.config.update(
    SESSION_TYPE=config.SESSION_TYPE,
    SESSION_FILE_DIR=config.SESSION_FILE_DIR,
    SESSION_PERMANENT=config.SESSION_PERMANENT,
    PERMANENT_SESSION_LIFETIME=config.PERMANENT_SESSION_LIFETIME,
    MAX_CONTENT_LENGTH=config.MAX_CONTENT_LENGTH,
    SSH_HOST=config.SSH_HOST,
    SSH_PORT=config.SSH_PORT,
    SSH_USERNAME=config.SSH_USERNAME,
    SSH_PASSWORD=config.SSH_PASSWORD,
    SSH_KEY=config.SSH_KEY,
    Hermes_SCAN_PATHS=config.Hermes_SCAN_PATHS,
    YARA_RULES_DIR=config.YARA_RULES_DIR,
    QUARANTINE_DIR=config.QUARANTINE_DIR,
    LOG_DIR=config.LOG_DIR,
    SURICATA_ENABLED=config.SURICATA_ENABLED,
    SURICATA_INTERFACE=config.SURICATA_INTERFACE,
    SURICATA_RULES_DIR=config.SURICATA_RULES_DIR,
    SURICATA_LOGS=config.SURICATA_LOGS,
    SURICATA_DIR=config.SURICATA_DIR,
    FAIL2BAN_ENABLED=config.FAIL2BAN_ENABLED,
    FAIL2BAN_JAILS=config.FAIL2BAN_JAILS
)

def log_event(event_type, level, message, details=None):
    """Log an event to the system log"""
    event_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"{event_time} | {event_type} | {level} | {message} | {details if details else ''}"
    with open("/tmp/Hermes.log", "a") as log_file:
        log_file.write(log_message + "\n")

def log_action(action, user_id):
    """Log an action performed by a user"""
    log_message = f"User {user_id} performed action: {action}"
    with open("/var/log/action_logs.log", "a") as log_file:
        log_file.write(log_message + "\n")

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
Session(app)



class User(UserMixin):
    """User model for authentication"""
    def __init__(self, id, username, password, role='user'):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

# Mock user database
users = {
    1: User(1, 'admin', bcrypt.generate_password_hash('admin').decode('utf-8'), 'admin')
}

class SSHManager:
    """Manages SSH connections with improved connection handling"""
    def __init__(self):
        self.connections = {}  # Initialize the connections dictionary
    
    def get_connection(self, host=None, username=None, password=None, key=None, port=None, force_new=False):
        """Get or create an SSH connection"""
        # Use config values if parameters are not provided
        host = host or app.config['SSH_HOST']
        username = username or app.config['SSH_USERNAME']
        password = password or app.config['SSH_PASSWORD']
        key = key or app.config['SSH_KEY']
        port = port or app.config['SSH_PORT']
        
        conn_key = f"{username}@{host}:{port}"
        
        if force_new and conn_key in self.connections:
            self.connections[conn_key].close()
            del self.connections[conn_key]
        
        if conn_key not in self.connections or force_new:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                # Disable SSH agent and look for keys to prevent local interference
                ssh.load_system_host_keys = False
                
                if password:
                    ssh.connect(
                        hostname=host,
                        port=port,
                        username=username,
                        password=password,
                        allow_agent=False,
                        look_for_keys=False,
                        timeout=10  # Added timeout
                    )
                elif key:
                    if os.path.exists(key):
                        pkey = paramiko.RSAKey.from_private_key_file(key)
                    else:
                        pkey = paramiko.RSAKey.from_private_key(StringIO(key))
                    ssh.connect(
                        hostname=host,
                        port=port,
                        username=username,
                        pkey=pkey,
                        allow_agent=False,
                        look_for_keys=False,
                        timeout=10  # Added timeout
                    )
                else:
                    raise ValueError("Either password or key must be provided")
                
                self.connections[conn_key] = ssh
            except Exception as e:
                error_msg = f"SSH Connection failed to {host}: {str(e)}"
                app.logger.error(error_msg)
                if hasattr(app, 'logger'):
                    app.logger.error(f"SSH Connection details - Host: {host}, User: {username}, Port: {port}")
                    print(f"SSH Connection details - Host: {host}, User: {username}, Port: {port}")
                return None
        
        return self.connections[conn_key]
    
    def close_all(self):
        """Close all SSH connections"""
        for conn_key, conn in list(self.connections.items()):
            try:
                conn.close()
            except:
                pass
            del self.connections[conn_key]

ssh_manager = SSHManager()

def test_initial_connection():
    try:
        conn = ssh_manager.get_connection()
        if conn:
            print("Initial SSH connection test successful")
        else:
            print("Initial SSH connection test failed")
    except Exception as e:
        print(f"Initial SSH connection test error: {str(e)}")

test_initial_connection()


def is_connection_alive(ssh):
    try:
        transport = ssh.get_transport()
        return transport and transport.is_active()
    except:
        return False

@app.route('/test_ssh')
@login_required
def test_ssh():
    """Test SSH connection and return debug info"""
    ssh = ssh_manager.get_connection()
    if not ssh:
        return jsonify({
            'status': 'error',
            'message': 'SSH connection failed',
            'config': {
                'host': app.config['SSH_HOST'],
                'port': app.config['SSH_PORT'],
                'username': app.config['SSH_USERNAME'],
                'password_set': bool(app.config['SSH_PASSWORD']),
                'key_set': bool(app.config['SSH_KEY'])
            }
        }), 400
    
    # Test a simple command
    try:
        stdin, stdout, stderr = ssh.exec_command('echo "SSH Connection Successful"')
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        return jsonify({
            'status': 'success',
            'message': output or error,
            'connection': str(ssh.get_transport()) if ssh.get_transport() else 'No transport'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f"Command execution failed: {str(e)}"
        }), 500

def run_command(cmd, timeout=60, get_pty=False):
    """Execute command on remote host via SSH with timeout support"""
    ssh = ssh_manager.get_connection()
    
    if not ssh:
        return "ERROR: Could not establish SSH connection"
    
    try:
        # For sudo commands, use get_pty=True and handle password input
        if 'sudo' in cmd and app.config['SSH_PASSWORD']:
            get_pty = True
        
        # Set the channel timeout
        transport = ssh.get_transport()
        if transport:
            transport.set_keepalive(30)  # Optional: keep connection alive
        
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout, get_pty=get_pty)
        
        # If using sudo with password, send the password via stdin
        if get_pty and 'sudo' in cmd and app.config['SSH_PASSWORD']:
            stdin.write(f"{app.config['SSH_PASSWORD']}\n")
            stdin.flush()
        
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        if stdout.channel.recv_exit_status() != 0:
            return f"ERROR: {error or output}"
        return output
    except paramiko.SSHException as e:
        return f"SSH ERROR: {str(e)}"
    except Exception as e:
        return f"EXCEPTION: {str(e)}"
    


def log_action(action, user_id=None):
    """Log actions with timestamp and user info"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    user_info = f"User:{user_id}" if user_id else "System"
    log_entry = f"[{timestamp}] {user_info} - {action}\n"
    
    try:
        with open("myNAS.log", "a") as log_file:
            log_file.write(log_entry)
    except IOError as e:
        print(f"Failed to write to log file: {str(e)}")

# Authentication Routes
@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        # Input validation
        if not username or not password:
            flash('Please fill in all fields', 'error')
            return redirect(url_for('login'))
        
        if len(username) > 20 or len(password) > 50:
            flash('Invalid input length', 'error')
            return redirect(url_for('login'))
            
        user = next((user for user in users.values() if user.username == username), None)
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=remember)
            
            # Log successful login
            log_action(f"User {username} logged in successfully", user.id)
            log_event("AUTH", "info", "Successful login", {
                "username": username,
                "ip": request.remote_addr,
                "user_agent": request.headers.get('User-Agent')
            })
            
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            # Log failed attempt
            log_event("AUTH", "warning", "Failed login attempt", {
                "username": username,
                "ip": request.remote_addr,
                "user_agent": request.headers.get('User-Agent')
            })
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_action("User logged out", current_user.id)
    log_event("AUTH", "info", "User logged out", {
        "username": current_user.username,
        "ip": request.remote_addr
    })
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/configure_ssh', methods=['GET', 'POST'])
@login_required
def configure_ssh():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page', 'error')
        return redirect(url_for('dashboard'))
    
    # Clear existing connections before configuring new ones
    ssh_manager.close_all()

    if request.method == 'POST':
        # Validate inputs
        ssh_host = request.form.get('ssh_host')
        ssh_port = request.form.get('ssh_port', '22')
        ssh_username = request.form.get('ssh_username')
        ssh_password = request.form.get('ssh_password')
        ssh_key = request.form.get('ssh_key')
        
        # Basic validation
        if not ssh_host or not ssh_username:
            flash('Host and username are required', 'error')
            return redirect(url_for('configure_ssh'))
            
        try:
            port = int(ssh_port)
            if port <= 0 or port > 65535:
                raise ValueError
        except ValueError:
            flash('Invalid port number', 'error')
            return redirect(url_for('configure_ssh'))
        
        # Update configuration
        app.config.update({
            'SSH_HOST': ssh_host,
            'SSH_PORT': port,
            'SSH_USERNAME': ssh_username,
            'SSH_PASSWORD': ssh_password if ssh_password else app.config['SSH_PASSWORD'],
            'SSH_KEY': ssh_key if ssh_key else app.config['SSH_KEY']
        })
        
        # Test the connection
        test_result = run_command("echo 'SSH connection test successful'")
        
        if "ERROR" in test_result:
            flash(f"SSH Configuration Failed: {test_result}", "error")
            log_event("SSH", "error", "SSH configuration failed", {
                "host": ssh_host,
                "port": port,
                "username": ssh_username,
                "error": test_result
            })
        else:
            flash(f"SSH Configuration Successful: {test_result}", "success")
            log_action("Configured SSH connection", current_user.id)
            log_event("SSH", "info", "SSH configuration updated", {
                "host": ssh_host,
                "port": port,
                "username": ssh_username
            })
            return redirect(url_for('dashboard'))
    
    return render_template('configure_ssh.html',
                         current_config={
                             'host': app.config['SSH_HOST'],
                             'port': app.config['SSH_PORT'],
                             'username': app.config['SSH_USERNAME']
                         })





# Hermes Dashboard
@app.route('/')
@login_required
def dashboard():
    now = mydate.datetime.now()
    """Enhanced Hermes Dashboard with more system information"""
    if not app.config['SSH_HOST']:
        flash("Please configure SSH connection first", "error")
        return redirect(url_for('configure_ssh'))
    

    # Get comprehensive system information
    system_info = {
        'hostname': run_command("hostname"),
        'os': run_command("cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"'"),
        'kernel': run_command("uname -r"),
        'uptime': run_command("uptime -p"),
        'load': run_command("cat /proc/loadavg | awk '{print $1, $2, $3}'"),
        'memory': run_command("free -h | awk '/Mem:/ {print $3 \"/\" $2}'"),
        'disk': run_command("df -h / | awk 'NR==2 {print $3 \"/\" $2}'"),
        'cpu': run_command("lscpu | grep 'Model name' | cut -d':' -f2 | sed 's/^[ \t]*//'"),
        'cpu_cores': run_command("nproc"),
        'last_boot': run_command("who -b | awk '{print $3 \" \" $4}'")
    }
    
    # Get security services status with more details
    services = {
        "clamav": {
            "status": run_command("systemctl is-active clamav-daemon"),
            "version": run_command("clamscan --version | awk '{print $2}'")
        },
        "fail2ban": {
            "status": run_command("systemctl is-active fail2ban"),
            "jails": run_command("fail2ban-client status | grep 'Jail list' | cut -d':' -f2 | sed 's/^[ \t]*//'")
        },
        "suricata": {
            "status": run_command("systemctl is-active suricata"),
            "version": run_command("suricata --version 2>&1 | head -n1")
        },
        "yara": {
            "status": "active" if os.path.exists(app.config['YARA_RULES_DIR']) else "inactive",
            "version": run_command("yara --version")
        }
    }
    
    # Get security alerts and warnings
    security_alerts = []
    
    # Check for root logins
    root_logins = run_command("last root | head -n5")
    if root_logins and not root_logins.startswith("ERROR"):
        security_alerts.extend([f"Root login: {line}" for line in root_logins.split('\n') if line.strip()])
    
    # Check for failed logins
    failed_logins = run_command("grep 'Failed password' /var/log/auth.log | tail -n5")
    if failed_logins and not failed_logins.startswith("ERROR"):
        security_alerts.extend([f"Failed login: {line}" for line in failed_logins.split('\n') if line.strip()])
    
    # Get recent security events from Hermes log
    recent_events = []
    try:
        events_output = run_command(f"tail -n 10 {os.path.join(app.config['LOG_DIR'], 'Hermes_events.log')}")
        recent_events = [line.strip() for line in events_output.split('\n') if line.strip()]
    except Exception as e:
        log_event("DASHBOARD", "error", "Failed to read recent events", {"error": str(e)})
    
    # Get system updates information
    updates_info = {
        "available": run_command("apt list --upgradable 2>/dev/null | wc -l"),
        "last_update": run_command("stat -c %y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || echo 'Never'")
    }
    
    return render_template('index.html',
                        system_info=system_info,
                        services=services,
                        recent_events=recent_events,
                        security_alerts=security_alerts,
                        updates_info=updates_info)
    


# Scanning Functions
@app.route('/antivirus', methods=['GET', 'POST'])
@login_required
def antivirus():
    """Run antivirus scans"""
    if request.method == 'POST':
        scan_path = request.form.get('scan_path', '/').strip()
        scan_type = request.form.get('scan_type', 'quick')
        scanners = request.form.getlist('scanners') or (['clamav', 'rkhunter'] if scan_type == 'quick' else ['clamav', 'maldet', 'rkhunter', 'chkrootkit', 'yara'])
        
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as tmp:
            results = {}
            
            if 'clamav' in scanners:
                results['clamav'] = run_command(f"clamscan --remove --recursive --infected --verbose {scan_path}", timeout=600)

            if 'maldet' in scanners:
                # Option 1: Use sudo -S with password (less secure)
                # results['maldet'] = run_command(f"echo {app.config['SSH_PASSWORD']} | sudo -S /usr/local/sbin/maldet --scan-all {scan_path}", timeout=600)
                
                # Option 2: Use get_pty (better)
                results['maldet'] = run_command(f"sudo /usr/local/sbin/maldet --scan-all {scan_path}", 
                                              timeout=600, get_pty=True)

            if 'rkhunter' in scanners:
                results['rkhunter'] = run_command("sudo rkhunter --check --skip-keypress", 
                                                timeout=300, get_pty=True)

            if 'chkrootkit' in scanners:
                results['chkrootkit'] = run_command("sudo chkrootkit", 
                                                  timeout=300, get_pty=True)

            if 'yara' in scanners:
                yara_rules = request.form.get('yara_rules', '/usr/local/share/yara-rules').strip()
                results['yara'] = run_command(f"yara -r {yara_rules} {scan_path}", timeout=600)
            
            json.dump(results, tmp)
            tmp_path = tmp.name
        
        log_action(f"Antivirus {scan_type} scan initiated on {scan_path}")
        session['scan_results_path'] = tmp_path
        return redirect(url_for('antivirus_results'))
    
    return render_template('antivirus.html')

def run_clamav_scan(scan_path):
    """Run ClamAV scan"""
    cmd = f"clamscan -r --infected --no-summary {scan_path}"
    output = run_command(cmd, timeout=600)
    
    if "ERROR" in output:
        return {'status': 'error', 'error': output}
    
    # Parse results
    infected_files = []
    for line in output.split('\n'):
        if 'FOUND' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                infected_files.append({
                    'file': parts[0].strip(),
                    'detection': parts[1].strip()
                })
    
    return {
        'status': 'completed',
        'infected': bool(infected_files),
        'infected_files': infected_files,
        'infected_count': len(infected_files),
        'output': output
    }

def run_maldet_scan(scan_path):
    """Run Linux Malware Detect (maldet) scan"""
    # First check if maldet is installed
    check_cmd = "which maldet"
    if "ERROR" in run_command(check_cmd):
        return {'status': 'error', 'error': 'Maldet not installed'}
    
    # Run the scan
    cmd = f"maldet --scan-recent {scan_path} --no-color"
    output = run_command(cmd, timeout=600)
    
    if "ERROR" in output:
        return {'status': 'error', 'error': output}
    
    # Parse results
    infected_files = []
    detection_summary = ""
    scan_id = ""
    
    for line in output.split('\n'):
        if 'SCAN ID:' in line:
            scan_id = line.split('SCAN ID:')[1].strip()
        elif 'TOTAL HITS:' in line:
            detection_summary = line.strip()
        elif scan_id and 'hits:' in line and not line.strip().startswith('['):
            file_path = line.split('hits:')[0].strip()
            infected_files.append(file_path)
    
    return {
        'status': 'completed',
        'infected': bool(infected_files),
        'scan_id': scan_id,
        'detection_summary': detection_summary,
        'infected_files': infected_files,
        'infected_count': len(infected_files),
        'output': output
    }

def run_rkhunter_scan():
    """Run Rkhunter scan"""
    cmd = "rkhunter --check --sk --nocolors"
    output = run_command(cmd, timeout=600)
    
    if "ERROR" in output:
        return {'status': 'error', 'error': output}
    
    # Parse results
    warnings = [line.strip() for line in output.split('\n') if 'Warning:' in line]
    
    return {
        'status': 'completed',
        'warnings': bool(warnings),
        'warning_count': len(warnings),
        'warnings_list': warnings,
        'output': output
    }

def run_chkrootkit_scan():
    """Run chkrootkit scan"""
    cmd = "chkrootkit -q"
    output = run_command(cmd, timeout=600)
    
    if "ERROR" in output:
        return {'status': 'error', 'error': output}
    
    # Parse results
    infected = []
    for line in output.split('\n'):
        if any(x in line for x in ['INFECTED', 'Warning', 'Vulnerable']):
            infected.append(line.strip())
    
    return {
        'status': 'completed',
        'infected': bool(infected),
        'infected_count': len(infected),
        'infected_list': infected,
        'output': output
    }

def run_yara_scan(scan_path, rules_path):
    """Run YARA scan"""
    cmd = f"yara -r {rules_path}/*.yar {scan_path}"
    output = run_command(cmd, timeout=600)
    
    if "ERROR" in output:
        return {'status': 'error', 'error': output}
    
    # Parse results
    matches = []
    for line in output.split('\n'):
        if line.strip():
            parts = line.split(' ')
            if len(parts) >= 2:
                matches.append({
                    'rule': parts[0],
                    'file': ' '.join(parts[1:])
                })
    
    return {
        'status': 'completed',
        'matches': bool(matches),
        'match_count': len(matches),
        'matches_list': matches,
        'output': output
    }

# YARA Rules Management
@app.route('/yara_rules', methods=['GET', 'POST'])
@login_required
def manage_yara_rules():
    """Manage YARA rules"""
    if request.method == 'POST':
        if 'yara_rule' not in request.files:
            flash("No file uploaded", "error")
            return redirect(url_for('manage_yara_rules'))
        
        file = request.files['yara_rule']
        if file.filename == '':
            flash("No selected file", "error")
            return redirect(url_for('manage_yara_rules'))
        
        if not (file.filename.endswith('.yar') or file.filename.endswith('.yara')):
            flash("Invalid file type - must be .yar or .yara", "error")
            return redirect(url_for('manage_yara_rules'))
        
        # Upload the file
        try:
            content = file.read().decode('utf-8')
            # Validate YARA syntax
            try:
                yara.compile(source=content)
            except yara.SyntaxError as e:
                flash(f"Invalid YARA syntax: {str(e)}", "error")
                return redirect(url_for('manage_yara_rules'))
            
            # Save to remote system
            temp_path = f"/tmp/{file.filename}"
            upload_cmd = f"echo '{content}' > {temp_path} && sudo mv {temp_path} {os.path.join(app.config['YARA_RULES_DIR'], file.filename)}"
            result = run_command(upload_cmd)
            
            if "ERROR" in result:
                flash(f"Failed to upload rule: {result}", "error")
            else:
                flash("YARA rule uploaded successfully", "success")
                log_action(f"Uploaded YARA rule: {file.filename}", current_user.id)
                log_event("YARA", "info", f"New YARA rule uploaded: {file.filename}")
            
        except Exception as e:
            flash(f"Error processing file: {str(e)}", "error")
            log_event("YARA", "error", "YARA rule upload failed", {"error": str(e)})
        
        return redirect(url_for('manage_yara_rules'))
    
    # List existing rules
    yara_rules = []
    if app.config['SSH_HOST']:
        rules_output = run_command(f"ls {app.config['YARA_RULES_DIR']}")
        if rules_output and not rules_output.startswith("ERROR"):
            yara_rules = [rule for rule in rules_output.split('\n') if rule.endswith(('.yar', '.yara'))]
    
    return render_template('yara_rules.html', yara_rules=yara_rules)

@app.route('/delete_yara_rule', methods=['POST'])
@login_required
def delete_yara_rule():
    """Delete a YARA rule"""
    rule_name = request.form.get('rule_name')
    if not rule_name:
        flash("No rule specified", "error")
        return redirect(url_for('manage_yara_rules'))
    
    # Security check - prevent path traversal
    if '/' in rule_name or '..' in rule_name:
        flash("Invalid rule name", "error")
        return redirect(url_for('manage_yara_rules'))
    
    cmd = f"sudo rm {os.path.join(app.config['YARA_RULES_DIR'], rule_name)}"
    result = run_command(cmd)
    
    if "ERROR" in result:
        flash(f"Failed to delete rule: {result}", "error")
        log_event("YARA", "error", f"Failed to delete YARA rule: {rule_name}", {"error": result})
    else:
        flash("YARA rule deleted successfully", "success")
        log_action(f"Deleted YARA rule: {rule_name}", current_user.id)
        log_event("YARA", "info", f"YARA rule deleted: {rule_name}")
    
    return redirect(url_for('manage_yara_rules'))

@app.route('/antivirus/update')
@login_required
def antivirus_update():
    """Update antivirus databases with proper sudo password handling"""
    tools = request.args.getlist('tools') or ['clamav', 'maldet', 'rkhunter']
    results = {}
    ssh_password = app.config.get('SSH_PASSWORD', '')
    
    try:
        if 'clamav' in tools:
            # Using echo to pass password to sudo -S
            cmd = f"echo '{ssh_password}' | sudo -S freshclam" if ssh_password else "sudo freshclam"
            results['clamav'] = run_command(cmd, timeout=300, get_pty=True)
        
        if 'maldet' in tools:
            cmd = f"echo '{ssh_password}' | sudo -S /usr/local/sbin/maldet -u" if ssh_password else "sudo /usr/local/sbin/maldet -u"
            results['maldet'] = run_command(cmd, timeout=300, get_pty=True)
        
        if 'rkhunter' in tools:
            cmd = f"echo '{ssh_password}' | sudo -S rkhunter --update" if ssh_password else "sudo rkhunter --update"
            results['rkhunter'] = run_command(cmd, timeout=300, get_pty=True)
        
        log_action(f"Updated antivirus databases: {', '.join(tools)}")
        flash("Antivirus update completed", "success")
        
    except Exception as e:
        flash(f"Error during update: {str(e)}", "error")
        log_action(f"Antivirus update failed: {str(e)}")
    
    return render_template('antivirus_update.html', 
                         results=results,
                         now=datetime.now(),
                         selected_tools=tools)




@app.route('/antivirus/results')
@login_required
def antivirus_results():
    """Display antivirus scan results"""
    tmp_path = session.get('scan_results_path')
    if not tmp_path or not os.path.exists(tmp_path):
        flash("No scan results found or results expired.", "error")
        return redirect(url_for('antivirus'))
    
    try:
        with open(tmp_path) as f:
            results = json.load(f)
        os.unlink(tmp_path)  # Clean up
        session.pop('scan_results_path', None)
        
        formatted_results = "\n\n".join(
            f"=== {tool.upper()} ===\n{output}" 
            for tool, output in results.items()
        )
        return render_template('antivirus_results.html', results=formatted_results)
    except Exception as e:
        flash(f"Error reading scan results: {str(e)}", "error")
        return redirect(url_for('antivirus'))



def update_clamav():
    """Update ClamAV databases"""
    cmd = "freshclam"
    output = run_command(cmd, timeout=300)
    
    if "ERROR" in output:
        return {'status': 'error', 'error': output}
    
    return {
        'status': 'completed',
        'output': output
    }

def update_maldet():
    """Update Maldet signatures"""
    # First check if maldet is installed
    check_cmd = "which maldet"
    if "ERROR" in run_command(check_cmd):
        return {'status': 'error', 'error': 'Maldet not installed'}
    
    cmd = "maldet --update-ver"
    output = run_command(cmd, timeout=300)
    
    if "ERROR" in output:
        return {'status': 'error', 'error': output}
    
    return {
        'status': 'completed',
        'output': output
    }

def update_rkhunter():
    """Update Rkhunter databases"""
    cmd = "rkhunter --update"
    output = run_command(cmd, timeout=300)
    
    if "ERROR" in output:
        return {'status': 'error', 'error': output}
    
    return {
        'status': 'completed',
        'output': output
    }

def update_yara():
    """Update YARA rules"""
    # This would depend on how you manage YARA rules
    # Here's a simple implementation that pulls from a git repo
    if not os.path.exists(app.config['YARA_RULES_DIR']):
        return {'status': 'error', 'error': 'YARA rules directory not found'}
    
    cmd = f"cd {app.config['YARA_RULES_DIR']} && git pull origin master"
    output = run_command(cmd, timeout=300)
    
    if "ERROR" in output:
        return {'status': 'error', 'error': output}
    
    return {
        'status': 'completed',
        'output': output
    }





# Process Monitoring
@app.route('/processes')
@login_required
def process_monitoring():
    """Monitor running processes with advanced detection for malicious activities"""
    ps_output = run_command("ps aux --sort=-%cpu | head -n 20")
    processes = []
    suspicious_processes = []

    # List of known suspicious commands or patterns
    suspicious_patterns = [
        "wget", "curl", "bash", "nc", "python", "perl", "php", "python3", "java", "sh", "tar"
    ]
    
    if ps_output and not ps_output.startswith("ERROR"):
        for line in ps_output.split('\n')[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 11:
                user = parts[0]
                pid = parts[1]
                cpu = parts[2]
                mem = parts[3]
                command = ' '.join(parts[10:])
                
                process_info = {
                    'user': user,
                    'pid': pid,
                    'cpu': cpu,
                    'mem': mem,
                    'command': command
                }
                
                # Flag suspicious commands
                if any(pattern in command.lower() for pattern in suspicious_patterns):
                    suspicious_processes.append({**process_info, 'reason': 'Suspicious command detected'})
                
                # Flag processes with high CPU or memory usage
                try:
                    if float(cpu) > 50.0:  # Flag processes using > 50% CPU
                        suspicious_processes.append({**process_info, 'reason': 'High CPU usage'})
                    elif float(mem) > 50.0:  # Flag processes using > 50% memory
                        suspicious_processes.append({**process_info, 'reason': 'High memory usage'})
                except ValueError:
                    pass

                # Flag processes running as root or unusual users
                if user in ['root', 'admin', 'system']:
                    suspicious_processes.append({**process_info, 'reason': 'Running with elevated privileges'})

                processes.append(process_info)
    
    # Store suspicious processes in session for /kill_process to access
    session['suspicious_processes'] = suspicious_processes
    
    return render_template('processes.html', processes=processes, suspicious_processes=suspicious_processes , current_year=datetime.now().year)


@app.route('/kill_process', methods=['POST'])
@login_required
def kill_process():
    """Kill a process and log malicious activities"""
    pid = request.form.get('pid')
    if not pid or not pid.isdigit():
        flash("Invalid PID", "error")
        return redirect(url_for('process_monitoring'))
    
    # Get the suspicious processes from session
    suspicious_processes = session.get('suspicious_processes', [])
    killed_process_info = None
    
    # Check if the killed process was flagged as suspicious
    for proc in suspicious_processes:
        if proc['pid'] == pid:
            killed_process_info = proc
            break
    
    cmd = f"sudo kill -9 {pid}"
    result = run_command(cmd)
    
    if "ERROR" in result:
        flash(f"Failed to kill process: {result}", "error")
        log_event("PROCESS", "error", f"Failed to kill process {pid}", {"error": result})
    else:
        flash(f"Process {pid} killed successfully", "success")
        log_action(f"Killed process: {pid}", current_user.id)
        log_event("PROCESS", "warning", f"Process {pid} killed by admin")
        
        # If it was a suspicious process, log additional details
        if killed_process_info:
            log_event("PROCESS", "warning", f"Malicious process {pid} killed by admin", killed_process_info)
    
    return redirect(url_for('process_monitoring'))


# Network Monitoring
@app.route('/network')
@login_required
def network_monitoring():
    """Monitor network connections and flag malicious ports and IPs"""

    # List of known malicious/suspicious ports
    malicious_ports = {
        '23', '69', '135', '137', '138', '139', '445', '1433', '3306', '4444',
        '5554', '6660', '6661', '6662', '6663', '6664', '6665', '6666', '6667',
        '6668', '6669', '31337', '12345', '27374', '2323', '8080', '9001',
        '37215', '52869'
    }

    # Load malicious IPs from file
    malicious_ips = set()
    try:
        with open('malware_ips.txt', 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith('#'):
                    malicious_ips.add(ip)
    except FileNotFoundError:
        flash("Malicious IP list not found", "error")

    # Get listening ports
    listen_output = run_command("ss -tulnp")
    listening = []
    suspicious_listening = []

    if listen_output and not listen_output.startswith("ERROR"):
        for line in listen_output.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 6:
                local_address = parts[4]
                process = parts[5]
                port = local_address.split(':')[-1]
                
                # Extract PID more reliably
                pid = None
                if "pid=" in process:
                    pid = process.split('pid=')[1].split(',')[0]
                elif "," in process:  # Alternative format: "process,1234"
                    pid = process.split(',')[-1]
                
                entry = {
                    'netid': parts[0],
                    'state': parts[1],
                    'local': local_address,
                    'process': process,
                    'port': port,
                    'pid': pid  # Add the extracted PID to the entry
                }

                if port in malicious_ports:
                    entry['reason'] = 'Known malicious listening port'
                    suspicious_listening.append(entry)

                listening.append(entry)

    # Get established connections
    est_output = run_command("ss -tupn")
    established = []
    suspicious_established = []

    if est_output and not est_output.startswith("ERROR"):
        for line in est_output.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 6:
                local_address = parts[4]
                remote_address = parts[5]
                port = remote_address.split(':')[-1]
                remote_ip = remote_address.split(':')[0]
                process = parts[6] if len(parts) > 6 else 'N/A'
                
                # Extract PID more reliably
                pid = None
                if "pid=" in process:
                    pid = process.split('pid=')[1].split(',')[0]
                elif "," in process:  # Alternative format: "process,1234"
                    pid = process.split(',')[-1]
                
                entry = {
                    'netid': parts[0],
                    'state': parts[1],
                    'local': local_address,
                    'remote': remote_address,
                    'process': process,
                    'port': port,
                    'pid': pid
                }

                is_suspicious = False
                if port in malicious_ports:
                    entry['reason'] = 'Connected to known malicious port'
                    is_suspicious = True
                if remote_ip in malicious_ips:
                    entry['reason'] = 'Connected to known malicious IP'
                    is_suspicious = True

                if is_suspicious:
                    suspicious_established.append(entry)
                established.append(entry)

    return render_template(
        'network.html',
        listening=listening,
        established=established,
        suspicious_listening=suspicious_listening,
        suspicious_established=suspicious_established,
        malicious_ports=malicious_ports,
        malicious_ips=malicious_ips,
        current_year=datetime.now().year  # Add this line
    )


# File Integrity Monitoring
@app.route('/file_integrity', methods=['GET', 'POST'])
@login_required
def file_integrity():
    """File integrity monitoring"""
    if request.method == 'POST':
        action = request.form.get('action')
        file_path = request.form.get('file_path')
        
        if action == 'hash':
            if not file_path:
                flash("Please enter a file path", "error")
                return redirect(url_for('file_integrity'))
            
            cmd = f"sha256sum {file_path}"
            result = run_command(cmd)
            
            if "ERROR" in result:
                flash(f"Failed to get hash: {result}", "error")
            else:
                flash(f"Hash for {file_path}: {result.split()[0]}", "success")
                log_action(f"Checked hash for {file_path}", current_user.id)
        
        elif action == 'quarantine':
            if not file_path:
                flash("Please enter a file path", "error")
                return redirect(url_for('file_integrity'))
            
            cmd = f"sudo mv {file_path} {app.config['QUARANTINE_DIR']}"
            result = run_command(cmd)
            
            if "ERROR" in result:
                flash(f"Failed to quarantine file: {result}", "error")
                log_event("FIM", "error", f"Failed to quarantine {file_path}", {"error": result})
            else:
                flash(f"File {file_path} quarantined successfully", "success")
                log_action(f"Quarantined file: {file_path}", current_user.id)
                log_event("FIM", "warning", f"File quarantined: {file_path}")
        
        return redirect(url_for('file_integrity'))
    
    # List quarantined files
    quarantined = []
    if os.path.exists(app.config['QUARANTINE_DIR']):
        cmd = f"ls -la {app.config['QUARANTINE_DIR']}"
        result = run_command(cmd)
        
        if result and not result.startswith("ERROR"):
            quarantined = [line.strip() for line in result.split('\n') if line.strip()]
    
    return render_template('file_integrity.html', quarantined=quarantined)

# Log Management
@app.route('/logs')
@login_required
def log_management():
    """View security logs"""
    log_files = {
        'auth': '/var/log/auth.log',
        'syslog': '/var/log/syslog',
        'Hermes_events': os.path.join(app.config['LOG_DIR'], 'Hermes_events.log'),
        'admin_actions': os.path.join(app.config['LOG_DIR'], 'admin_actions.log')
    }
    
    selected_log = request.args.get('log', 'Hermes_events')
    log_content = []
    
    if selected_log in log_files:
        cmd = f"tail -n 100 {log_files[selected_log]}"
        result = run_command(cmd)
        
        if result and not result.startswith("ERROR"):
            log_content = [line.strip() for line in result.split('\n') if line.strip()]
    
    return render_template('logs.html',
                         log_files=log_files.keys(),
                         selected_log=selected_log,
                         log_content=log_content)

# System Services Management



@app.route('/services', methods=['GET', 'POST'])
@login_required
def service_management():
    now = mydate.datetime.now()
    suspicious_services = []

    if request.method == 'POST':
        service = request.form.get('service')
        action = request.form.get('action')

        if not service or not action:
            flash("Service and action are required", "error")
            return redirect(url_for('service_management'))

        valid_actions = ['start', 'stop', 'restart', 'enable', 'disable']
        if action not in valid_actions:
            flash("Invalid action", "error")
            return redirect(url_for('service_management'))

        # Sanitize input
        service = shlex.quote(service)
        action = shlex.quote(action)

        cmd = f"sudo systemctl {action} {service}"
        result = run_command(cmd)

        if "ERROR" in result:
            flash(f"Failed to {action} service: {result}", "error")
            log_event("SERVICE", "error", f"Failed to {action} {service}", {"error": result})
        else:
            flash(f"Service {service} {action}ed successfully", "success")
            log_action(f"{action}ed service: {service}", current_user.id)
            log_event("SERVICE", "info", f"Service {service} {action}ed")

        return redirect(url_for('service_management'))

    # List all services
    services = []
    cmd = "systemctl list-units --type=service --no-pager --no-legend"
    result = run_command(cmd)

    if result and not result.startswith("ERROR"):
        for line in result.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 4:
                    service_name = parts[0]
                    loaded = parts[1]
                    active = parts[2]
                    sub = parts[3]

                    is_suspicious = False
                    reason = ""

                    # Check for suspicious name
                    if is_suspicious_service(service_name):
                        is_suspicious = True
                        reason = 'Suspicious service name detected'

                    # Check path of unit file
                    path_cmd = f"systemctl show -p FragmentPath {service_name}"
                    path_result = run_command(path_cmd)
                    if "ERROR" not in path_result and "FragmentPath=" in path_result:
                        fragment_path = path_result.split('=')[1].strip()
                        if fragment_path.startswith('/tmp') or fragment_path.startswith('/var/tmp') or '/home/' in fragment_path:
                            is_suspicious = True
                            reason = f"Service file loaded from suspicious path: {fragment_path}"

                    # Check unknown but active services
                    allowlist = ["ssh.service", "nginx.service", "apache2.service", "docker.service"]
                    if service_name not in allowlist and active == "active" and sub == "running":
                        is_suspicious = True
                        reason = "Unknown active service"

                    if is_suspicious:
                        suspicious_services.append({
                            'name': service_name,
                            'loaded': loaded,
                            'active': active,
                            'sub': sub,
                            'reason': reason
                        })

                    # Add all services to list
                    services.append({
                        'name': service_name,
                        'loaded': loaded,
                        'active': active,
                        'sub': sub
                    })

    return render_template('services.html', services=services, suspicious_services=suspicious_services, now=now)


# ----------------------------
# Suspicious Service Detector
# ----------------------------

def is_suspicious_service(service_name):
    """
    Heuristics to detect suspicious service names.
    Expand this logic based on threat intelligence.
    """
    suspicious_patterns = [
        # ⛔ Hidden or dot-prefixed services
        r'^\.',                                 # Hidden services like `.hidden.service`

        # 🔐 Random or Obfuscated Names
        r'^[a-z0-9]{12,}\.service$',            # Long hash-like names
        r'^[A-Z0-9]{8,}\.service$',             # Uppercase encoded-looking names

        # 🕵️ Known masquerading or fake services
        r'^(kworker|ksoftirqd|kthreadd|rc\.local|dbus|udevd|systemd-update|syslog-ng|acpid)\.service$',
        r'^(sshd|ntpd|named|crond|networkd|auditd)\.service$',  # Known targets for spoofing
        r'(sysd|systemd-|systemdd|sshd_|cronjob|dockerd|initd)',  # Close variants of legit names

        # 💥 Malware or backdoor keywords
        r'(backdoor|keylogger|reverse_shell|meterpreter|empire|revshell|rat)',
        r'(malware|exploit|infect|payload|trojan|dropper|bindshell|spysvc)',

        # 💾 Suspicious execution paths
        r'^.*\.service.*(tmp|/home/|/mnt/|/media/|/dev/shm/|/run/user/).*$',  # Service files from unsafe locations

        # 🧠 Indicators of evasion or stealth
        r'(auditbypass|disablelogs|antiav|rootkit|invis)',
        r'(hiddenservice|cloak|ghost|undetected)',

        # 🧩 YARA-style naming patterns from threat research
        r'(xsser|remcos|quasar|nanocore|njrat|darkcomet|cobaltstrike|sliver)',

        # 🛠️ Maliciously re-used system names with typos or extensions
        r'(systemd\d+|init\d+|syslogd\d+)\.service$',
        r'(ssh\.service\.bak|cron\.service\.disabled|sshd\.1\.service)'
    ]


    for pattern in suspicious_patterns:
        if re.search(pattern, service_name, re.IGNORECASE):
            return True
    return False



def is_suspicious_service(service_name):
    """Detect suspicious services based on name, path, or behavior"""
    
    suspicious_keywords = [
        "malware", "backdoor", "trojan", "random", "worm", "crypt", "exploit"
    ]
    
    # Check for suspicious keywords in the service name
    if any(keyword in service_name.lower() for keyword in suspicious_keywords):
        return True
    
    # Additional checks (e.g., services running from unusual locations)
    service_path = f"/etc/systemd/system/{service_name}.service"
    
    # Check if the service file exists in non-standard locations (indicative of tampering)
    if not os.path.exists(service_path):
        return False
    
    # Check for strange file paths or suspicious commands (i.e., services running from temp dirs, etc.)
    with open(service_path, 'r') as f:
        content = f.read().lower()
        if "execstart" in content:
            exec_start_index = content.find("execstart") + len("execstart") + 1
            exec_start_command = content[exec_start_index:].splitlines()[0].strip()
            suspicious_paths = ["/tmp", "/dev/shm", "/var/tmp"]
            if any(path in exec_start_command for path in suspicious_paths):
                return True
    
    return False


@app.route('/firewall', methods=['GET', 'POST'])
@login_required
def firewall():
    """Manage firewall rules with improved error handling and debugging"""
    if request.method == 'POST':
        action = request.form.get('action')
        port = request.form.get('port')
        service = request.form.get('service')
        zone = request.form.get('zone', 'public')

        if not action:
            flash("Action is required.", "error")
            return redirect(url_for('firewall'))
        
        if not port and not service:
            flash("Provide either a port or a service.", "error")
            return redirect(url_for('firewall'))

        if port and service:
            flash("Provide only a port or a service, not both.", "error")
            return redirect(url_for('firewall'))

        try:
            if port:
                # Clean the port input (remove any spaces or unwanted characters)
                port = port.strip()
                
                if action == "allow":
                    command = f"sudo firewall-cmd --zone={zone} --add-port={port}/tcp --permanent"
                    log_msg = f"Adding port {port} to zone {zone}"
                elif action == "deny":
                    # First verify the port exists and is in the correct format
                    if not re.match(r'^\d+(-\d+)?$', port):
                        flash(f"Invalid port format: {port}. Use single port (80) or range (8000-9000)", "error")
                        return redirect(url_for('firewall'))
                    
                    # Check if port exists in the zone
                    check_cmd = f"sudo firewall-cmd --zone={zone} --query-port={port}/tcp"
                    port_exists = run_command(check_cmd, get_pty=True)
                    
                    if "yes" not in port_exists.lower():
                        flash(f"Port {port} doesn't exist in zone {zone}", "warning")
                        return redirect(url_for('firewall'))
                    
                    command = f"sudo firewall-cmd --zone={zone} --remove-port={port}/tcp --permanent"
                    log_msg = f"Removing port {port} from zone {zone}"
                else:
                    raise ValueError("Invalid action")
                
                # Execute the command with detailed error handling
                output = run_command(command, get_pty=True)
                
                # Debug output
                print(f"DEBUG - Command: {command}")
                print(f"DEBUG - Output: {output}")
                
                # Verify the change was applied
                verify_cmd = f"sudo firewall-cmd --zone={zone} --list-ports"
                current_ports = run_command(verify_cmd, get_pty=True)
                
                if action == "allow":
                    if port not in current_ports:
                        raise Exception(f"Failed to add port {port}. Command output: {output}. Current ports: {current_ports}")
                    flash(f"Successfully added port {port} to zone {zone}", "success")
                elif action == "deny":
                    if port in current_ports:
                        raise Exception(f"Failed to remove port {port}. Command output: {output}. Current ports: {current_ports}")
                    flash(f"Successfully removed port {port} from zone {zone}", "success")
                
                log_action(f"{log_msg}. Output: {output}")
            
            elif service:
                # Similar handling for services (unchanged from your original)
                if action == "allow":
                    command = f"sudo firewall-cmd --zone={zone} --add-service={service} --permanent"
                elif action == "deny":
                    check_cmd = f"sudo firewall-cmd --zone={zone} --query-service={service}"
                    service_exists = run_command(check_cmd, get_pty=True)
                    
                    if "yes" not in service_exists.lower():
                        flash(f"Service {service} doesn't exist in zone {zone}", "warning")
                        return redirect(url_for('firewall'))
                    command = f"sudo firewall-cmd --zone={zone} --remove-service={service} --permanent"
                else:
                    raise ValueError("Invalid action")
                
                output = run_command(command, get_pty=True)
                log_action(f"Firewall {action} service {service}: {output}")
                flash(f"Service {service} {action}ed in zone {zone}", "success")

            # Reload firewall with verification
            reload_output = run_command("sudo firewall-cmd --reload", get_pty=True)
            if "success" not in reload_output.lower():
                raise Exception(f"Firewall reload failed: {reload_output}")
            
            print(f"DEBUG - Reload output: {reload_output}")

        except Exception as e:
            error_msg = str(e)
            print(f"ERROR - {error_msg}")  # Debug output
            flash(f"Firewall operation failed: {error_msg}", "error")
            log_action(f"Firewall error: {error_msg}")

        return redirect(url_for('firewall'))

    # Get firewall status with error handling
    try:
        # Get both runtime and permanent configurations
        runtime_status = run_command("sudo firewall-cmd --list-all", get_pty=True)
        permanent_status = run_command("sudo firewall-cmd --list-all --permanent", get_pty=True)
        
        firewall_status = f"=== Runtime Configuration ===\n{runtime_status}\n\n=== Permanent Configuration ===\n{permanent_status}"
        
        if "ERROR" in firewall_status:
            firewall_status = f"Error retrieving full status. Runtime config:\n{runtime_status}"
    except Exception as e:
        firewall_status = f"Error getting firewall status: {str(e)}"
    
    # Get current default zone
    try:
        current_zone = run_command("sudo firewall-cmd --get-default-zone", get_pty=True)
    except:
        current_zone = "Unknown"
    
    return render_template('firewall.html', 
                         firewall_status=firewall_status,
                         current_zone=current_zone)



@app.route('/firewall/fail2ban', methods=['GET', 'POST'])
@login_required
def fail2ban():
    """Manage Fail2Ban jails and rules."""
    if request.method == 'POST':
        action = request.form.get('action')
        jail = request.form.get('jail')
        ip = request.form.get('ip')
        bantime = request.form.get('bantime')
        findtime = request.form.get('findtime')
        maxretry = request.form.get('maxretry')
        
        try:
            if action == "ban":
                if not ip:
                    flash("IP address is required for banning.", "error")
                    return redirect(url_for('fail2ban'))
                command = f"sudo fail2ban-client set {jail} banip {ip}"
                output = run_command(command, get_pty=True)
                log_action(f"Fail2Ban banned IP {ip} in jail {jail}")
                flash(f"IP {ip} banned in {jail}: {output}", "success")
                
            elif action == "unban":
                if not ip:
                    flash("IP address is required for unbanning.", "error")
                    return redirect(url_for('fail2ban'))
                command = f"sudo fail2ban-client set {jail} unbanip {ip}"
                output = run_command(command, get_pty=True)
                log_action(f"Fail2Ban unbanned IP {ip} in jail {jail}")
                flash(f"IP {ip} unbanned in {jail}: {output}", "success")
                
            elif action == "add_jail":
                if not jail or not bantime or not findtime or not maxretry:
                    flash("All fields are required to create a new jail.", "error")
                    return redirect(url_for('fail2ban'))
                
                # Create a simple jail configuration
                jail_config = f"""
[{jail}]
enabled = true
port = ssh
filter = {jail}
logpath = /var/log/auth.log
bantime = {bantime}
findtime = {findtime}
maxretry = {maxretry}
"""
                # Write to a new jail file using sudo
                jail_file = f"/etc/fail2ban/jail.d/{jail}.local"
                cmd = f"echo '{jail_config}' | sudo tee {jail_file}"
                output = run_command(cmd, get_pty=True)
                
                # Restart fail2ban
                restart_output = run_command("sudo systemctl restart fail2ban", get_pty=True)
                log_action(f"Fail2Ban created new jail {jail}")
                flash(f"New jail {jail} created and Fail2Ban restarted", "success")
                
            return redirect(url_for('fail2ban'))
        
        except Exception as e:
            flash(f"Fail2Ban operation failed: {str(e)}", "error")
            log_action(f"Fail2Ban error: {str(e)}")
            return redirect(url_for('fail2ban'))
    
    # Get current Fail2Ban status
    try:
        status = run_command("sudo fail2ban-client status", get_pty=True)
        jails_output = run_command("sudo fail2ban-client status | grep 'Jail list:'", get_pty=True)
        jails = jails_output.split(':')[-1].strip().split(', ') if jails_output else []
        
        banned_ips = {}
        for jail in jails:
            jail = jail.strip()
            if jail:
                ips = run_command(f"sudo fail2ban-client get {jail} banip", get_pty=True)
                banned_ips[jail] = ips.split() if ips else []
        
        return render_template('fail2ban.html', 
                            status=status, 
                            jails=jails, 
                            banned_ips=banned_ips)
    
    except Exception as e:
        flash(f"Error retrieving Fail2Ban status: {str(e)}", "error")
        return render_template('fail2ban_logs.html', 
                            status="Error", 
                            jails=[], 
                            banned_ips={})

@app.route('/firewall/fail2ban/logs')
@login_required
def fail2ban_logs():
    """View Fail2Ban logs."""
    try:
        logs = run_command("sudo tail -n 100 /var/log/fail2ban.log", get_pty=True)
        return render_template('fail2ban_logs.html', logs=logs)
    except Exception as e:
        flash(f"Error retrieving Fail2Ban logs: {str(e)}", "error")
        return render_template('fail2ban_logs.html', logs="Error loading logs")







## Kernel Management System
## Find Malicious Modules and All loaded Modules


# Kernel Management System - Remote SSH Version

# Cache expiration time (5 minutes)
CACHE_EXPIRATION = 300

def remote_file_exists(path):
    """Check if file exists on remote system"""
    cmd = f"[ -f '{path}' ] && echo 'exists' || echo 'not found'"
    result = run_command(cmd)
    return result == 'exists'

def remote_dir_exists(path):
    """Check if directory exists on remote system"""
    cmd = f"[ -d '{path}' ] && echo 'exists' || echo 'not found'"
    result = run_command(cmd)
    return result == 'exists'

def remote_walk(path):
    """Simulate os.walk for remote system"""
    try:
        cmd = f"find '{path}' -type d -printf '%p\\n' 2>/dev/null"
        dirs = run_command(cmd).split('\n')
        
        result = []
        for d in dirs:
            if not d:
                continue
            # Get files in directory
            files_cmd = f"find '{d}' -maxdepth 1 -type f -printf '%f\\n' 2>/dev/null"
            files = run_command(files_cmd).split('\n')
            # Get subdirectories
            subdirs_cmd = f"find '{d}' -maxdepth 1 -type d -printf '%f\\n' 2>/dev/null | tail -n +2"
            subdirs = run_command(subdirs_cmd).split('\n')
            result.append((d, [sd for sd in subdirs if sd], [f for f in files if f]))
        return result
    except Exception as e:
        log_event("REMOTE", "error", "Remote walk failed", {
            'path': path,
            'error': str(e)
        })
        return []

def remote_stat(path):
    """Get file stats from remote system"""
    cmd = f"stat -c '%a %u %g %s' '{path}' 2>/dev/null"
    result = run_command(cmd)
    if result.startswith("ERROR"):
        return None
    try:
        mode, uid, gid, size = result.split()
        return {
            'mode': int(mode, 8),
            'uid': int(uid),
            'gid': int(gid),
            'size': int(size)
        }
    except:
        return None

@lru_cache(maxsize=1)
def get_kernel_release():
    """Get kernel release from remote system with caching"""
    result = run_command("uname -r").strip()
    return result if not result.startswith("ERROR") else "unknown"

def cache_with_expiration(seconds):
    """Decorator for time-based cache invalidation"""
    def decorator(func):
        @lru_cache(maxsize=32)
        def cached_func(*args, **kwargs):
            return (func(*args, **kwargs), time.time())
        
        def wrapper(*args, **kwargs):
            result, timestamp = cached_func(*args, **kwargs)
            if time.time() - timestamp > seconds:
                cached_func.cache_clear()
                result, timestamp = cached_func(*args, **kwargs)
            return result
        return wrapper
    return decorator

@cache_with_expiration(CACHE_EXPIRATION)
def check_module_signing_cached():
    """Cached version of module signing check for remote system"""
    try:
        # Single command to get all signing info
        cmd = """cat /proc/sys/kernel/module_sig_enforce /proc/sys/kernel/module_sig_all /proc/sys/kernel/modules_disabled 2>/dev/null"""
        output = run_command(cmd)
        
        if output.startswith("ERROR"):
            raise Exception(output)
            
        values = output.split('\n')
        if len(values) >= 3:
            sig_enforce, sig_all, modules_disabled = values[0], values[1], values[2]
        else:
            sig_enforce = sig_all = modules_disabled = 'unknown'
        
        secureboot = run_command("[ -d /sys/firmware/efi/efivars ] && echo 'enabled' || echo 'disabled'")
        if secureboot.startswith("ERROR"):
            secureboot = 'unknown'
        
        return {
            'modules_disabled': modules_disabled.strip(),
            'sig_enforce': sig_enforce.strip(),
            'sig_all': sig_all.strip(),
            'secureboot': secureboot.strip()
        }
    except Exception as e:
        log_event("KERNEL", "error", "Failed to check module signing", {'error': str(e)})
        return {
            'modules_disabled': 'unknown',
            'sig_enforce': 'unknown',
            'sig_all': 'unknown',
            'secureboot': 'unknown'
        }

@cache_with_expiration(CACHE_EXPIRATION)
def check_module_hijacking_cached():
    """Optimized module hijacking check with caching for remote system"""
    vulns = []
    paths_to_check = [
        '/lib/modules',
        '/usr/lib/modules',
        '/etc/modprobe.d',
        '/etc/modules-load.d',
        '/run/modprobe.d',
        '/usr/local/lib/modprobe.d',
        '/usr/lib/modprobe.d'
    ]
    
    try:
        # Check world-writable directories
        for path in paths_to_check:
            if remote_dir_exists(path):
                for root, dirs, files in remote_walk(path):
                    for name in dirs:
                        full_path = os.path.join(root, name)
                        stat = remote_stat(full_path)
                        if stat and stat['mode'] & 0o002:
                            vulns.append({
                                'path': full_path,
                                'issue': 'World-writable module directory',
                                'severity': 'high',
                                'mode': oct(stat['mode']),
                                'owner': f"{stat['uid']}:{stat['gid']}"
                            })
        
        # Check world-writable files
        config_paths = [
            '/etc/modprobe.d',
            '/run/modprobe.d',
            '/usr/local/lib/modprobe.d',
            '/usr/lib/modprobe.d'
        ]
        
        for path in config_paths:
            if remote_dir_exists(path):
                for root, _, files in remote_walk(path):
                    for name in files:
                        full_path = os.path.join(root, name)
                        stat = remote_stat(full_path)
                        if stat and stat['mode'] & 0o002:
                            vulns.append({
                                'path': full_path,
                                'issue': 'World-writable modprobe configuration',
                                'severity': 'critical',
                                'mode': oct(stat['mode']),
                                'owner': f"{stat['uid']}:{stat['gid']}"
                            })
        
        return vulns
    except Exception as e:
        log_event("KERNEL", "error", "Failed to check module hijacking", {'error': str(e)})
        return []

@cache_with_expiration(CACHE_EXPIRATION)
def get_kernel_config_cached():
    """Cached kernel config reader for remote system"""
    config = {}
    kernel_release = get_kernel_release()
    config_paths = [
        '/proc/config.gz',
        f'/boot/config-{kernel_release}',
        f'/lib/modules/{kernel_release}/build/.config'
    ]
    
    try:
        for path in config_paths:
            if remote_file_exists(path):
                if path.endswith('.gz'):
                    cmd = f"zcat {path}"
                else:
                    cmd = f"cat {path}"
                
                output = run_command(cmd)
                if not output.startswith("ERROR"):
                    for line in output.split('\n'):
                        if line.startswith('CONFIG_'):
                            key, val = line.split('=', 1)
                            config[key] = val.strip('"')
                    break
        
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
        
        return {desc: config.get(param, 'not set') for param, desc in important_params.items()}
    
    except Exception as e:
        log_event("KERNEL", "error", "Failed to read kernel config", {'error': str(e)})
        return {}

@cache_with_expiration(CACHE_EXPIRATION)
def get_all_kernel_modules_cached():
    """Get all kernel modules from remote system"""
    try:
        kernel_release = get_kernel_release()
        module_dir = f"/lib/modules/{kernel_release}"
        
        # Get all modules in one command for efficiency
        cmd = f"find {module_dir} -type f \( -name '*.ko' -o -name '*.ko.xz' \) -printf '%p %s\\n' 2>/dev/null"
        output = run_command(cmd)
        
        modules = []
        for line in output.split('\n'):
            if line.strip():
                try:
                    path, size = line.rsplit(' ', 1)
                    # Extract module name from filename (remove .ko or .ko.xz)
                    base = os.path.basename(path)
                    module_name = os.path.splitext(os.path.splitext(base)[0])[0]
                    modules.append({
                        'name': module_name,
                        'path': path,
                        'size': int(size)
                    })
                except ValueError:
                    continue  # Skip malformed lines
        
        return modules
        
    except Exception as e:
        log_event("KERNEL", "error", "Failed to get all kernel modules", {
            'error': str(e),
            'traceback': traceback.format_exc()
        })
        return []

@cache_with_expiration(CACHE_EXPIRATION)
def get_loaded_kernel_modules_cached():
    """Get loaded kernel modules from remote system"""
    try:
        # Get basic module info in one command
        cmd = "lsmod | awk 'NR>1 {print $1,$2,$3}'"
        lsmod_output = run_command(cmd)
        
        if lsmod_output.startswith("ERROR"):
            raise Exception(lsmod_output)
            
        modules = []
        module_names = []
        
        # First parse lsmod output
        for line in lsmod_output.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    module = {
                        'name': parts[0],
                        'size': parts[1],
                        'refcount': parts[2],
                        'path': 'unknown',
                        'signature': 'unknown',
                        'status': 'loaded'
                    }
                    modules.append(module)
                    module_names.append(parts[0])
        
        # Batch process module info (more efficient than one-by-one)
        if module_names:
            # Get paths for all modules in one call
            paths_cmd = f"modinfo -F filename {' '.join(module_names)} 2>/dev/null"
            paths_output = run_command(paths_cmd)
            paths = paths_output.split('\n') if paths_output else []
            
            # Get signature status for all modules in one call
            sig_cmd = f"for m in {' '.join(module_names)}; do modinfo $m | grep -q '^sig_id:' && echo 'signed' || echo 'unsigned'; done 2>/dev/null"
            sig_output = run_command(sig_cmd)
            signatures = sig_output.split('\n') if sig_output else []
            
            # Update modules with additional info
            for i, module in enumerate(modules):
                if i < len(paths) and paths[i].strip():
                    module['path'] = paths[i].strip()
                if i < len(signatures) and signatures[i].strip():
                    module['signature'] = signatures[i].strip()
                
                # Check for tainting (once per module)
                module['tainted'] = check_if_tainted(module['name'])
        
        return modules
        
    except Exception as e:
        log_event("KERNEL", "error", "Failed to get loaded modules", {
            'error': str(e),
            'traceback': traceback.format_exc()
        })
        return []

def check_if_tainted(module_name):
    """Check if a specific module contributes to kernel tainting on remote system"""
    try:
        taint_output = run_command("cat /proc/sys/kernel/tainted 2>/dev/null")
        if taint_output.isdigit():
            taint_flags = int(taint_output)
            # Flag 11 is for externally-built module (P)
            # Flag 12 is for unsigned module (F)
            if taint_flags & (1 << 11) or taint_flags & (1 << 12):
                mod_output = run_command(f"grep -l {module_name} /sys/module/*/taint 2>/dev/null")
                return "Yes" if mod_output and not mod_output.startswith("ERROR") else "No"
        return "No"
    except:
        return "Unknown"

@cache_with_expiration(CACHE_EXPIRATION)
def detect_suspicious_modules_cached():
    """Detect suspicious kernel modules on remote system"""
    try:
        modules = get_loaded_kernel_modules_cached()
        
        # Pre-compiled patterns for better performance
        MALICIOUS_PATTERNS = [
            re.compile(r'rootkit', re.IGNORECASE),
            re.compile(r'backdoor', re.IGNORECASE),
            re.compile(r'hid(e|den)', re.IGNORECASE),
            re.compile(r'stealth', re.IGNORECASE),
            re.compile(r'keylog', re.IGNORECASE),
            re.compile(r'hook', re.IGNORECASE),
            re.compile(r'inject', re.IGNORECASE),
            re.compile(r'\.hidden$', re.IGNORECASE),
            re.compile(r'_hack', re.IGNORECASE),
            re.compile(r'_mal(ware|icious)', re.IGNORECASE)
        ]
        
        VULNERABLE_MODULES = {
            'nvidia', 'vmware', 'virtualbox', 'dccp', 'sctp', 'tipc',
            'ath3k', 'bluetooth', 'cdc_ether', 'rds', 'iwlwifi'
        }
        
        suspicious = []
        
        for module in modules:
            reasons = []
            name = module.get('name', '').lower()
            path = module.get('path', '').lower()
            
            # Check against malicious patterns
            for pattern in MALICIOUS_PATTERNS:
                if pattern.search(name) or pattern.search(path):
                    reasons.append(f"Name/path matches pattern: {pattern.pattern}")
            
            # Check known vulnerable modules
            if name in VULNERABLE_MODULES:
                reasons.append("Known vulnerable module")
            
            # Check module signature
            if module.get('signature') == 'unsigned':
                reasons.append("Unsigned module")
            
            # Check module path
            if path and not any(p in path for p in ['/lib/modules/', '/usr/lib/modules/']):
                reasons.append(f"Unusual module path: {module.get('path')}")
            
            # Check for hidden modules (not in /proc/modules but loaded)
            if not is_module_in_proc_modules(module['name']):
                reasons.append("Module hidden from /proc/modules")
            
            if reasons:
                suspicious.append({
                    'name': module['name'],
                    'reasons': reasons,
                    'size': module.get('size', 'unknown'),
                    'refcount': module.get('refcount', 'unknown'),
                    'path': module.get('path', 'unknown'),
                    'signature': module.get('signature', 'unknown'),
                    'tainted': module.get('tainted', 'unknown')
                })
        
        return suspicious
        
    except Exception as e:
        log_event("KERNEL", "error", "Suspicious module detection failed", {
            'error': str(e),
            'traceback': traceback.format_exc()
        })
        return []

def is_module_in_proc_modules(module_name):
    """Check if module appears in /proc/modules on remote system"""
    try:
        cmd = f"grep -q '^{module_name} ' /proc/modules && echo 'yes' || echo 'no'"
        result = run_command(cmd)
        return result == 'yes'
    except:
        return True  # If we can't check, assume it's visible

@app.route('/kernel_modules')
@login_required
def manage_kernel_modules():
    """Kernel module management dashboard with all required data"""
    now = datetime.now()

    # Load fast components
    kernel_config = get_kernel_config_cached()
    loaded_modules = get_loaded_kernel_modules_cached()
    signing_status = check_module_signing_cached()

    # Don't load heavy data here
    return render_template('kernel_modules.html',
        loaded_modules=loaded_modules,
        signing_status=signing_status,
        kernel_config=kernel_config ,
        now=now,
        initial_load=True)


@app.route('/api/kernel_modules/full_data')
@login_required
def get_full_kernel_data():
    """Endpoint for loading full dataset asynchronously"""
    try:
        loaded_modules = get_loaded_kernel_modules_cached()
        return jsonify({
            'all_modules': get_all_kernel_modules_cached(),
            'suspicious_modules': detect_suspicious_modules_cached(),
            'hijacking_vulns': check_module_hijacking_cached(),
            'kernel_config': get_kernel_config_cached()
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500










# IDS Management 
@app.route('/ids')
@login_required
def ids_dashboard():
    now = mydate.datetime.now()
    """IDS/IPS Management Dashboard"""
    if not app.config['SSH_HOST']:
        flash("Please configure SSH connection first", "error")
        return redirect(url_for('configure_ssh'))
    
    # Initialize status dictionary
    status = {
        'enabled': False,
        'running': False,
        'mode': 'IDS',
        'interface': 'eth0',
        'rules_count': 0,
        'alerts': [],
        'version': 'Unknown'
    }
    
    try:
        # Check if Suricata is installed
        check_installed = run_command("which suricata")
        if "ERROR" in check_installed or not check_installed.strip():
            flash("Suricata is not installed on the remote system", "warning")
            return render_template('ids.html', status=status)
        
        # Get Suricata version
        version_output = run_command("suricata -V")
        if version_output and not version_output.startswith("ERROR"):
            version_line = version_output.split('\n')[0]
            status['version'] = version_line.split(' ')[1] if ' ' in version_line else version_line
        
        # Check if Suricata is running
        ps_output = run_command("ps aux | grep [s]uricata")
        if ps_output and "suricata" in ps_output:
            status['running'] = True
            status['enabled'] = True
            if "--ips" in ps_output:
                status['mode'] = 'IPS'
            
            # Get running interface
            if "-i" in ps_output:
                try:
                    interface = ps_output.split("-i")[1].split()[0]
                    status['interface'] = interface
                except:
                    pass
        
        # Count rule files
        rules_output = run_command(f"find {app.config['SURICATA_RULES_DIR']} -name '*.rules' | wc -l")
        if rules_output and not rules_output.startswith("ERROR"):
            status['rules_count'] = int(rules_output.strip())
        
        # Load recent alerts
        status['alerts'] = get_recent_alerts()
        
    except Exception as e:
        flash(f"Error checking Suricata status: {str(e)}", "error")
        log_event("IDS", "error", "Failed to check Suricata status", {"error": str(e)})
    
    return render_template('ids.html', status=status , now = now)

def get_recent_alerts(limit=50):
    """Get recent alerts from Suricata's eve.json"""
    alerts = []
    eve_log = os.path.join(app.config['SURICATA_LOGS'], 'eve.json')
    
    # Check if log file exists
    check_cmd = f"test -f {eve_log} && echo exists"
    if run_command(check_cmd) != "exists":
        return alerts
    
    # Get recent alerts
    cmd = f"tail -n {limit} {eve_log} 2>/dev/null | grep '\"event_type\":\"alert\"'"
    output = run_command(cmd)
    
    if output and not output.startswith("ERROR"):
        for line in output.split('\n'):
            try:
                alert = json.loads(line)
                
                # Standardize alert format
                standardized = {
                    'timestamp': alert.get('timestamp', ''),
                    'event_type': alert.get('event_type', 'alert'),
                    'src_ip': alert.get('src_ip', ''),
                    'src_port': alert.get('src_port', ''),
                    'dest_ip': alert.get('dest_ip', ''),
                    'dest_port': alert.get('dest_port', ''),
                    'proto': alert.get('proto', ''),
                    'alert': {
                        'signature': alert.get('alert', {}).get('signature', 'Unknown'),
                        'severity': alert.get('alert', {}).get('severity', 3),
                        'category': alert.get('alert', {}).get('category', 'Unknown')
                    }
                }
                
                # Add HTTP info if available
                if 'http' in alert:
                    standardized['http'] = {
                        'hostname': alert['http'].get('hostname', ''),
                        'url': alert['http'].get('url', ''),
                        'http_method': alert['http'].get('http_method', ''),
                        'http_user_agent': alert['http'].get('http_user_agent', '')
                    }
                
                alerts.append(standardized)
            except json.JSONDecodeError:
                continue
    
    return alerts

@app.route('/ids/rules', methods=['GET', 'POST'])
@login_required
def manage_ids_rules():
    """Manage IDS/IPS rules"""
    if not app.config['SSH_HOST']:
        flash("Please configure SSH connection first", "error")
        return redirect(url_for('configure_ssh'))
    
    if request.method == 'POST':
        rule_content = request.form.get('rule_content')
        rule_name = request.form.get('rule_name', 'custom.rules')
        
        if not rule_content:
            flash("No rule content provided", "error")
            return redirect(url_for('ids_dashboard'))
            
        try:
            # Validate rule name
            if not rule_name.endswith('.rules'):
                rule_name += '.rules'
            
            # Security check - prevent path traversal
            if '/' in rule_name or '..' in rule_name:
                flash("Invalid rule name", "error")
                return redirect(url_for('ids_dashboard'))
            
            # Upload the rule file
            temp_path = f"/tmp/{rule_name}"
            upload_cmd = f"echo '{rule_content}' > {temp_path} && sudo mv {temp_path} {os.path.join(app.config['SURICATA_RULES_DIR'], rule_name)}"
            result = run_command(upload_cmd)
            
            if "ERROR" in result:
                flash(f"Failed to save rule: {result}", "error")
                log_event("IDS", "error", "Failed to save rule", {"rule": rule_name, "error": result})
            else:
                # Reload Suricata if running
                reload_suricata()
                flash("Rule added successfully", "success")
                log_action(f"Added IDS rule: {rule_name}", current_user.id)
                log_event("IDS", "info", f"New rule added: {rule_name}")
            
            return redirect(url_for('ids_dashboard'))
        except Exception as e:
            flash(f"Error processing rule: {str(e)}", "error")
            log_event("IDS", "error", "Rule addition failed", {"error": str(e)})
            return redirect(url_for('ids_dashboard'))
    
    # GET request - list available rules
    rules = []
    if app.config['SSH_HOST']:
        rules_output = run_command(f"ls {app.config['SURICATA_RULES_DIR']}/*.rules")
        if rules_output and not rules_output.startswith("ERROR"):
            rules = [os.path.basename(rule) for rule in rules_output.split('\n') if rule.strip()]
    
    return render_template('ids_rules.html', rules=rules)

@app.route('/ids/control', methods=['POST'])
@login_required
def ids_control():
    """Control Suricata service"""
    if not app.config['SSH_HOST']:
        return jsonify({'status': 'error', 'message': 'SSH not configured'}), 400
    
    action = request.form.get('action')
    mode = request.form.get('mode', 'ids')
    
    try:
        if action == 'start':
            success = start_suricata(mode == 'ips')
            if success:
                log_action(f"Started Suricata in {mode.upper()} mode", current_user.id)
                log_event("IDS", "info", f"Suricata started in {mode.upper()} mode")
                return jsonify({'status': 'success', 'message': 'Suricata started successfully'})
            else:
                log_event("IDS", "error", "Failed to start Suricata")
                return jsonify({'status': 'error', 'message': 'Failed to start Suricata'}), 500
                
        elif action == 'stop':
            success = stop_suricata()
            if success:
                log_action("Stopped Suricata", current_user.id)
                log_event("IDS", "info", "Suricata stopped")
                return jsonify({'status': 'success', 'message': 'Suricata stopped successfully'})
            else:
                log_event("IDS", "error", "Failed to stop Suricata")
                return jsonify({'status': 'error', 'message': 'Failed to stop Suricata'}), 500
                
        elif action == 'restart':
            stop_suricata()
            success = start_suricata(mode == 'ips')
            if success:
                log_action(f"Restarted Suricata in {mode.upper()} mode", current_user.id)
                log_event("IDS", "info", f"Suricata restarted in {mode.upper()} mode")
                return jsonify({'status': 'success', 'message': 'Suricata restarted successfully'})
            else:
                log_event("IDS", "error", "Failed to restart Suricata")
                return jsonify({'status': 'error', 'message': 'Failed to restart Suricata'}), 500
                
        else:
            return jsonify({'status': 'error', 'message': 'Invalid action'}), 400
            
    except Exception as e:
        log_event("IDS", "error", f"Control action failed: {action}", {"error": str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

def start_suricata(ips_mode=False):
    """Start Suricata service"""
    mode_flag = "--ips" if ips_mode else ""
    interface = app.config['SURICATA_INTERFACE']
    
    cmd = f"sudo suricata -c /etc/suricata/suricata.yaml -i {interface} {mode_flag} -D"
    output = run_command(cmd)
    
    if "ERROR" in output:
        return False
    
    # Verify it's running
    ps_output = run_command("ps aux | grep [s]uricata")
    return ps_output and "suricata" in ps_output

def stop_suricata():
    """Stop Suricata service"""
    # First try graceful stop
    output = run_command("sudo pkill -15 suricata")
    
    # Wait a bit and check
    time.sleep(2)
    ps_output = run_command("ps aux | grep [s]uricata")
    
    if ps_output and "suricata" in ps_output:
        # Force kill if needed
        run_command("sudo pkill -9 suricata")
        time.sleep(1)
        ps_output = run_command("ps aux | grep [s]uricata")
    
    return not (ps_output and "suricata" in ps_output)

def reload_suricata():
    """Reload Suricata rules without restarting"""
    if not app.config['SSH_HOST']:
        return False
    
    # Check if Suricata is running
    ps_output = run_command("ps aux | grep [s]uricata")
    if not ps_output or "suricata" not in ps_output:
        return False
    
    # Send USR2 signal to reload rules
    output = run_command("sudo pkill -USR2 suricata")
    return "ERROR" not in output

@app.route('/ids/alerts')
@login_required
def get_ids_alerts():
    """Get recent alerts (for AJAX updates)"""
    alerts = get_recent_alerts(50)
    return jsonify({'alerts': alerts})

@app.route('/ids/logs/live')
@login_required
def live_suricata_logs():
    """Stream live Suricata logs via SSE"""
    eve_log = os.path.join(app.config['SURICATA_LOGS'], 'eve.json')
    
    def generate():
        try:
            # Get initial file size
            size_cmd = f"wc -c < {eve_log}" if run_command(f"test -f {eve_log} && echo exists") == "exists" else "0"
            current_pos = int(run_command(size_cmd) or 0)
            
            while True:
                # Check if file exists
                if run_command(f"test -f {eve_log} && echo exists") != "exists":
                    yield "data: " + json.dumps({'error': 'File not found'}) + "\n\n"
                    time.sleep(5)
                    continue
                
                # Get current size
                new_size = int(run_command(f"wc -c < {eve_log}") or 0)
                
                # If file was rotated or truncated
                if new_size < current_pos:
                    current_pos = 0
                
                if new_size > current_pos:
                    # Read new content
                    cmd = f"tail -c +{current_pos + 1} {eve_log} | head -c {new_size - current_pos}"
                    new_content = run_command(cmd)
                    
                    if new_content and not new_content.startswith("ERROR"):
                        for line in new_content.split('\n'):
                            if line.strip():
                                try:
                                    entry = json.loads(line)
                                    yield "data: " + json.dumps(entry) + "\n\n"
                                except json.JSONDecodeError:
                                    continue
                        current_pos = new_size
                
                time.sleep(1)
        except Exception as e:
            log_event("ERROR", "high", "Live log streaming failed", {'error': str(e)})
            yield "data: " + json.dumps({'error': str(e)}) + "\n\n"
    
    return Response(generate(), mimetype="text/event-stream")

@app.route('/ids/update_rules')
@login_required
def update_ids_rules():
    """Update Suricata rules"""
    if not app.config['SSH_HOST']:
        return jsonify({'status': 'error', 'message': 'SSH not configured'}), 400
    
    try:
        # Pull rules updates
        cmd = "sudo suricata-update"
        output = run_command(cmd, timeout=300)
        
        if "ERROR" in output:
            log_event("IDS", "error", "Failed to update rules", {"error": output})
            return jsonify({'status': 'error', 'message': output})
        
        # Reload rules if Suricata is running
        reload_suricata()
        
        log_action("Updated Suricata rules", current_user.id)
        log_event("IDS", "info", "Rules updated successfully")
        
        return jsonify({
            'status': 'success',
            'message': 'Rules updated successfully',
            'output': output
        })
        
    except Exception as e:
        log_event("IDS", "error", "Rule update failed", {"error": str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/fail2ban')
@login_required
def fail2ban_dashboard():
    """Fail2Ban Management Dashboard"""
    if not app.config['SSH_HOST']:
        flash("Please configure SSH connection first", "error")
        return redirect(url_for('configure_ssh'))
    
    status = {
        'enabled': app.config['FAIL2BAN_ENABLED'],
        'running': False,
        'jails': {}
    }
    
    if app.config['FAIL2BAN_ENABLED']:
        # Check if running
        ps_output = run_command("ps aux | grep [f]ail2ban-server")
        if ps_output and "fail2ban-server" in ps_output:
            status['running'] = True
        
        # Get jail status
        for jail in app.config['FAIL2BAN_JAILS']:
            result = run_command(f"sudo fail2ban-client status {jail}")
            if result and not result.startswith("ERROR"):
                status['jails'][jail] = result
            else:
                status['jails'][jail] = 'error'
    
    return render_template('fail2ban.html', status=status)

@app.route('/fail2ban/control', methods=['POST'])
@login_required
def fail2ban_control():
    """Start/Stop/Restart Fail2Ban"""
    action = request.form.get('action')
    
    if action == 'start':
        result = run_command("sudo systemctl start fail2ban")
        if "ERROR" in result:
            flash("Failed to start Fail2Ban", "error")
            log_event("FAIL2BAN", "error", "Failed to start Fail2Ban")
        else:
            flash("Fail2Ban started successfully", "success")
            log_action("Started Fail2Ban", current_user.id)
            log_event("FAIL2BAN", "info", "Fail2Ban started")
    elif action == 'stop':
        result = run_command("sudo systemctl stop fail2ban")
        if "ERROR" in result:
            flash("Failed to stop Fail2Ban", "error")
            log_event("FAIL2BAN", "error", "Failed to stop Fail2Ban")
        else:
            flash("Fail2Ban stopped successfully", "success")
            log_action("Stopped Fail2Ban", current_user.id)
            log_event("FAIL2BAN", "info", "Fail2Ban stopped")
    elif action == 'restart':
        result = run_command("sudo systemctl restart fail2ban")
        if "ERROR" in result:
            flash("Failed to restart Fail2Ban", "error")
            log_event("FAIL2BAN", "error", "Failed to restart Fail2Ban")
        else:
            flash("Fail2Ban restarted successfully", "success")
            log_action("Restarted Fail2Ban", current_user.id)
            log_event("FAIL2BAN", "info", "Fail2Ban restarted")
    else:
        flash("Invalid action", "error")
    
    return redirect(url_for('fail2ban_dashboard'))

@app.route('/fail2ban/unban', methods=['POST'])
@login_required
def fail2ban_unban():
    """Unban an IP in a Fail2Ban jail"""
    jail = request.form.get('jail')
    ip = request.form.get('ip')
    
    if not jail or not ip:
        flash("Jail and IP address are required", "error")
        return redirect(url_for('fail2ban_dashboard'))
    
    result = run_command(f"sudo fail2ban-client set {jail} unbanip {ip}")
    if "ERROR" in result:
        flash(f"Failed to unban IP: {result}", "error")
        log_event("FAIL2BAN", "error", f"Failed to unban {ip} in {jail}", {"error": result})
    else:
        flash(f"IP {ip} unbanned from {jail} successfully", "success")
        log_action(f"Unbanned {ip} from {jail}", current_user.id)
        log_event("FAIL2BAN", "info", f"IP {ip} unbanned from {jail}")
    
    return redirect(url_for('fail2ban_dashboard'))

# Helper functions for Suricata
def start_suricata(ips_mode=False):
    """Start Suricata in IDS or IPS mode"""
    cmd = [
        'sudo suricata',
        '-c', os.path.join(app.config['SURICATA_DIR'], 'suricata.yaml'),
        '-i', app.config['SURICATA_INTERFACE'],
        '--set', f'default-rule-path={app.config["SURICATA_RULES_DIR"]}',
        '--set', f'log-dir={app.config["SURICATA_LOGS"]}'
    ]
    
    if ips_mode:
        cmd.append('--ips')
    
    cmd.append('&')  # Run in background
    result = run_command(' '.join(cmd))
    
    return not result.startswith("ERROR")

def stop_suricata():
    """Stop Suricata"""
    result = run_command("sudo pkill -9 suricata")
    return not result.startswith("ERROR")

def reload_suricata():
    """Reload Suricata rules"""
    result = run_command("sudo pkill -USR2 suricata")
    return not result.startswith("ERROR")




# Monitoring                                                                                                                                      
@app.route("/monitoring")                                                                                                                         
@login_required                                                                                                                                   
def monitoring():                                                                                                                                 
    """Redirect to monitoring dashboard"""                                                                                                        
    server_ip = app.config['SSH_HOST']                                                                                                            
    if server_ip:                                                                                                                                 
        return redirect(f"http://{server_ip}:19999")                                                                                              
    else:                                                                                                                                         
        return "Server IP could not be determined.", 500  
    



class WinRMManager:
    """Manages Windows Remote Management connections"""
    def __init__(self):
        self.sessions = {}
    
    def get_session(self, host=None, username=None, password=None, transport=None, force_new=False):
        """Get or create a WinRM session"""
        host = host or app.config['WINRM_HOST']
        username = username or app.config['WINRM_USERNAME']
        password = password or app.config['WINRM_PASSWORD']
        transport = transport or app.config['WINRM_TRANSPORT']
        
        conn_key = f"{username}@{host}"
        
        if force_new and conn_key in self.sessions:
            self.sessions[conn_key].close()
            del self.sessions[conn_key]
        
        if conn_key not in self.sessions or force_new:
            try:
                session = winrm.Session(
                    host,
                    auth=(username, password),
                    transport=transport,
                    server_cert_validation=app.config['WINRM_SERVER_CERT_VALIDATION']
                )
                self.sessions[conn_key] = session
            except Exception as e:
                error_msg = f"WinRM Connection failed to {host}: {str(e)}"
                app.logger.error(error_msg)
                return None
        
        return self.sessions[conn_key]
    
    def close_all(self):
        """Close all WinRM sessions"""
        for conn_key, session in list(self.sessions.items()):
            try:
                session.close()
            except:
                pass
            del self.sessions[conn_key]

winrm_manager = WinRMManager()











# Main
if __name__ == '__main__':
    # Setup logging
    os.makedirs(app.config['LOG_DIR'], exist_ok=True)
    os.makedirs(app.config['QUARANTINE_DIR'], exist_ok=True)
    
    handler = RotatingFileHandler(
        os.path.join(app.config['LOG_DIR'], 'Hermes.log'),
        maxBytes=1000000,
        backupCount=5
    )
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    
    try:
        app.run(host='0.0.0.0', port=5005, debug=True)
    finally:
        ssh_manager.close_all()
