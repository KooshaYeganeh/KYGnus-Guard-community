import psutil
import sqlite3
import hashlib
import os
import time
import win32api
import win32con
import win32security
import win32serviceutil
import win32service
import win32event
import json
import threading
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import winreg

# Configuration
CONFIG = {
    'DB_PATH': 'edr_agent.db',
    'MONITOR_PATHS': [r'C:\Windows\System32', r'C:\Program Files'],
    'REGISTRY_KEYS': [
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    ],
    'WEB_INTERFACE': {
        'HOST': '127.0.0.1',
        'PORT': 5000,
        'SECRET_KEY': 'your-secret-key-here',
        'USERNAME': 'admin',
        'PASSWORD_HASH': 'sha256$yourpasswordhash'  # Generate with hashlib
    }
}

# Flask Application Setup
app = Flask(__name__)
app.secret_key = CONFIG['WEB_INTERFACE']['SECRET_KEY']

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id) if user_id == CONFIG['WEB_INTERFACE']['USERNAME'] else None

# EDR Agent Core
class EDRAgent:
    def __init__(self):
        self.agent_id = self.get_system_fingerprint()
        self.db_path = CONFIG['DB_PATH']
        self.running = False
        self.init_database()
        self.init_web_users()
        
    def get_system_fingerprint(self):
        """Create a unique identifier for this endpoint"""
        info = f"{os.environ['COMPUTERNAME']}-{psutil.cpu_count()}-{psutil.virtual_memory().total}"
        return hashlib.sha256(info.encode()).hexdigest()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # System events table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                event_data TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                processed BOOLEAN DEFAULT 0,
                severity TEXT DEFAULT 'info'
            )
            ''')
            
            # System baseline table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_type TEXT NOT NULL,
                item_path TEXT NOT NULL,
                item_hash TEXT,
                permissions TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                whitelisted BOOLEAN DEFAULT 0
            )
            ''')
            
            # Alerts table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER,
                alert_type TEXT NOT NULL,
                description TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0,
                FOREIGN KEY(event_id) REFERENCES events(id)
            )
            ''')
            
            # Web users table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                last_login DATETIME,
                is_admin BOOLEAN DEFAULT 0
            )
            ''')
            
            conn.commit()
    
    def init_web_users(self):
        """Initialize web interface users"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if admin user exists
            cursor.execute('SELECT 1 FROM users WHERE username = ?', 
                         (CONFIG['WEB_INTERFACE']['USERNAME'],))
            if not cursor.fetchone():
                cursor.execute('''
                INSERT INTO users (username, password_hash, is_admin)
                VALUES (?, ?, 1)
                ''', (CONFIG['WEB_INTERFACE']['USERNAME'], 
                     CONFIG['WEB_INTERFACE']['PASSWORD_HASH']))
                conn.commit()
    
    def log_event(self, event_type, event_data, severity='info'):
        """Store event in local database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO events (event_type, event_data, severity)
            VALUES (?, ?, ?)
            ''', (event_type, json.dumps(event_data), severity))
            conn.commit()
            return cursor.lastrowid
    
    def create_alert(self, event_id, alert_type, description):
        """Create an alert from an event"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO alerts (event_id, alert_type, description)
            VALUES (?, ?, ?)
            ''', (event_id, alert_type, description))
            conn.commit()
    
    def start_monitoring(self):
        """Start all monitoring threads"""
        if self.running:
            return False
        
        self.running = True
        self.establish_baseline()
        
        # Start monitoring threads
        self.monitor_threads = [
            threading.Thread(target=self.monitor_processes),
            threading.Thread(target=self.monitor_file_changes, 
                           args=(CONFIG['MONITOR_PATHS'],)),
            threading.Thread(target=self.monitor_registry_keys, 
                           args=(CONFIG['REGISTRY_KEYS'],)),
            threading.Thread(target=self.monitor_network_connections),
            threading.Thread(target=self.monitor_services),
            threading.Thread(target=self.analyze_events)
        ]
        
        for t in self.monitor_threads:
            t.daemon = True
            t.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop all monitoring threads"""
        self.running = False
        for t in self.monitor_threads:
            if t.is_alive():
                t.join(timeout=5)
    
    def establish_baseline(self):
        """Create initial baseline of system state"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Record running processes
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
                try:
                    cursor.execute('''
                    INSERT OR IGNORE INTO system_baseline 
                    (item_type, item_path, item_hash, permissions)
                    VALUES (?, ?, ?, ?)
                    ''', ('process', proc.info['exe'], 
                         self.get_file_hash(proc.info['exe']) if proc.info['exe'] else None, 
                         self.get_process_permissions(proc.pid)))
                except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
                    continue
            
            # Record critical files
            for path in CONFIG['MONITOR_PATHS']:
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            cursor.execute('''
                            INSERT OR IGNORE INTO system_baseline 
                            (item_type, item_path, item_hash, permissions)
                            VALUES (?, ?, ?, ?)
                            ''', ('file', file_path, self.get_file_hash(file_path), 
                                 self.get_file_permissions(file_path)))
                        except (PermissionError, FileNotFoundError):
                            continue
            
            conn.commit()
    
    def get_process_permissions(self, pid):
        """Get process security permissions"""
        try:
            process = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION, False, pid)
            sd = win32security.GetSecurityInfo(
                process, win32security.SE_KERNEL_OBJECT,
                win32security.DACL_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl()
            return str([(str(ace[0]), ace[1]) for ace in dacl])
        except Exception as e:
            return str(e)
    
    def get_file_permissions(self, filepath):
        """Get file security permissions"""
        try:
            sd = win32security.GetFileSecurity(
                filepath, win32security.DACL_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl()
            return str([(str(ace[0]), ace[1]) for ace in dacl])
        except Exception as e:
            return str(e)
    
    def monitor_processes(self):
        """Monitor process creation and termination"""
        known_processes = set()
        
        while self.running:
            current_processes = {p.pid for p in psutil.process_iter()}
            
            # New processes
            new_pids = current_processes - known_processes
            for pid in new_pids:
                try:
                    p = psutil.Process(pid)
                    self.log_process_event(p, "creation")
                except psutil.NoSuchProcess:
                    continue
            
            # Terminated processes
            terminated_pids = known_processes - current_processes
            for pid in terminated_pids:
                self.log_event("process_termination", {"pid": pid})
            
            known_processes = current_processes
            time.sleep(1)
    
    def log_process_event(self, process, event_type):
        """Log process-related events"""
        try:
            event_data = {
                "pid": process.pid,
                "name": process.name(),
                "exe": process.exe(),
                "cmdline": process.cmdline(),
                "username": process.username(),
                "create_time": process.create_time(),
                "permissions": self.get_process_permissions(process.pid)
            }
            
            event_id = self.log_event(f"process_{event_type}", event_data)
            
            # Check if this is a new/unrecognized process
            if event_type == "creation":
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                    SELECT 1 FROM system_baseline 
                    WHERE item_type = 'process' AND item_path = ? AND whitelisted = 1
                    ''', (process.exe(),))
                    
                    if not cursor.fetchone():
                        self.create_alert(
                            event_id, 
                            "unknown_process", 
                            f"New process detected: {process.name()} ({process.exe()})"
                        )
                        
        except (psutil.NoSuchProcess, FileNotFoundError):
            pass
    
    def monitor_file_changes(self, directories):
        """Monitor specified directories for file changes"""
        file_hashes = {}
        
        # Initial scan
        for root_dir in directories:
            for root, _, files in os.walk(root_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        file_hashes[file_path] = self.get_file_hash(file_path)
                    except (PermissionError, FileNotFoundError):
                        continue
        
        # Continuous monitoring
        while self.running:
            for root_dir in directories:
                for root, _, files in os.walk(root_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            current_hash = self.get_file_hash(file_path)
                            
                            if file_path not in file_hashes:
                                # New file detected
                                event_id = self.log_event("file_creation", {
                                    "path": file_path,
                                    "hash": current_hash,
                                    "permissions": self.get_file_permissions(file_path)
                                })
                                
                                with sqlite3.connect(self.db_path) as conn:
                                    cursor = conn.cursor()
                                    cursor.execute('''
                                    SELECT 1 FROM system_baseline 
                                    WHERE item_type = 'file' AND item_path = ? AND whitelisted = 1
                                    ''', (file_path,))
                                    
                                    if not cursor.fetchone():
                                        self.create_alert(
                                            event_id, 
                                            "new_file", 
                                            f"New file detected: {file_path}"
                                        )
                                
                                file_hashes[file_path] = current_hash
                            elif file_hashes[file_path] != current_hash:
                                # File modified
                                event_id = self.log_event("file_modification", {
                                    "path": file_path,
                                    "old_hash": file_hashes[file_path],
                                    "new_hash": current_hash,
                                    "permissions": self.get_file_permissions(file_path)
                                }, severity='warning')
                                
                                with sqlite3.connect(self.db_path) as conn:
                                    cursor = conn.cursor()
                                    cursor.execute('''
                                    SELECT 1 FROM system_baseline 
                                    WHERE item_type = 'file' AND item_path = ? AND whitelisted = 1
                                    ''', (file_path,))
                                    
                                    if not cursor.fetchone():
                                        self.create_alert(
                                            event_id, 
                                            "file_modified", 
                                            f"Critical file modified: {file_path}"
                                        )
                                
                                file_hashes[file_path] = current_hash
                                
                        except (PermissionError, FileNotFoundError):
                            if file_path in file_hashes:
                                # File deleted
                                event_id = self.log_event("file_deletion", {
                                    "path": file_path,
                                    "hash": file_hashes[file_path]
                                }, severity='warning')
                                
                                self.create_alert(
                                    event_id, 
                                    "file_deleted", 
                                    f"File deleted: {file_path}"
                                )
                                
                                del file_hashes[file_path]
                            continue
            
            time.sleep(60)
    
    def get_file_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def monitor_registry_keys(self, keys_to_watch):
        """Monitor important registry keys for changes"""
        original_values = {}
        for key_path in keys_to_watch:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                original_values[key_path] = winreg.QueryValueEx(key, "")[0]
                winreg.CloseKey(key)
            except WindowsError:
                continue
        
        while self.running:
            for key_path in keys_to_watch:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    current_value = winreg.QueryValueEx(key, "")[0]
                    
                    if original_values.get(key_path) != current_value:
                        event_id = self.log_event("registry_change", {
                            "key": key_path,
                            "old_value": original_values.get(key_path),
                            "new_value": current_value
                        }, severity='warning')
                        
                        self.create_alert(
                            event_id,
                            "registry_modified",
                            f"Registry key modified: {key_path}"
                        )
                        
                        original_values[key_path] = current_value
                    
                    winreg.CloseKey(key)
                except WindowsError:
                    if key_path in original_values:
                        # Key was deleted
                        event_id = self.log_event("registry_deletion", {
                            "key": key_path,
                            "old_value": original_values[key_path]
                        }, severity='high')
                        
                        self.create_alert(
                            event_id,
                            "registry_deleted",
                            f"Registry key deleted: {key_path}"
                        )
                        
                        del original_values[key_path]
                    continue
            
            time.sleep(60)
    
    def monitor_network_connections(self):
        """Monitor network connections"""
        known_connections = set()
        
        while self.running:
            current_connections = set()
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    conn_id = (conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
                    current_connections.add(conn_id)
                    
                    if conn_id not in known_connections:
                        try:
                            p = psutil.Process(conn.pid)
                            event_id = self.log_event("network_connection", {
                                "pid": conn.pid,
                                "process_name": p.name(),
                                "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                                "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                                "status": conn.status
                            })
                            
                            # Check if this is a known process
                            with sqlite3.connect(self.db_path) as conn_db:
                                cursor = conn_db.cursor()
                                cursor.execute('''
                                SELECT 1 FROM system_baseline 
                                WHERE item_type = 'process' AND item_path = ? AND whitelisted = 1
                                ''', (p.exe(),))
                                
                                if not cursor.fetchone():
                                    self.create_alert(
                                        event_id,
                                        "new_connection",
                                        f"New network connection from {p.name()} to {conn.raddr.ip}:{conn.raddr.port}"
                                    )
                            
                        except (psutil.NoSuchProcess, AttributeError):
                            continue
            
            # Detect closed connections
            closed_connections = known_connections - current_connections
            for conn_id in closed_connections:
                self.log_event("network_disconnection", {
                    "connection": conn_id
                })
            
            known_connections = current_connections
            time.sleep(5)
    
    def monitor_services(self):
        """Monitor Windows services"""
        known_services = {s.name() for s in psutil.win_service_iter()}
        
        while self.running:
            current_services = {s.name() for s in psutil.win_service_iter()}
            
            # New services
            new_services = current_services - known_services
            for service_name in new_services:
                try:
                    service = psutil.win_service_get(service_name)
                    event_id = self.log_event("service_creation", {
                        "name": service.name(),
                        "display_name": service.display_name(),
                        "status": service.status(),
                        "binpath": service.binpath()
                    }, severity='warning')
                    
                    self.create_alert(
                        event_id,
                        "new_service",
                        f"New service detected: {service.name()} ({service.binpath()})"
                    )
                except psutil.NoSuchProcess:
                    continue
            
            # Removed services
            removed_services = known_services - current_services
            for service_name in removed_services:
                self.log_event("service_removal", {
                    "name": service_name
                }, severity='warning')
            
            known_services = current_services
            time.sleep(60)
    
    def analyze_events(self):
        """Analyze events for suspicious patterns"""
        while self.running:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check for suspicious process chains
                cursor.execute('''
                SELECT e.id, e.event_data
                FROM events e
                WHERE e.event_type = 'process_creation'
                AND e.processed = 0
                AND json_extract(e.event_data, '$.name') IN 
                    ('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe')
                ''')
                
                for event_id, event_data in cursor.fetchall():
                    data = json.loads(event_data)
                    self.create_alert(
                        event_id,
                        "suspicious_process",
                        f"Suspicious process executed: {data['name']} with command: {data['cmdline']}"
                    )
                
                # Check for DLL injection patterns
                cursor.execute('''
                SELECT e.id, e.event_data
                FROM events e
                WHERE e.event_type = 'process_creation'
                AND e.processed = 0
                AND json_extract(e.event_data, '$.cmdline') LIKE '%rundll32%'
                ''')
                
                for event_id, event_data in cursor.fetchall():
                    data = json.loads(event_data)
                    self.create_alert(
                        event_id,
                        "possible_dll_injection",
                        f"Possible DLL injection detected: {data['cmdline']}"
                    )
                
                # Mark events as processed
                cursor.execute('''
                UPDATE events SET processed = 1 WHERE processed = 0
                ''')
                
                conn.commit()
            
            time.sleep(30)

# Windows Service Wrapper
class EDRService(win32serviceutil.ServiceFramework):
    _svc_name_ = "PythonEDR"
    _svc_display_name_ = "Python EDR Agent"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.agent = EDRAgent()
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.web_thread = None
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.agent.stop_monitoring()
        
        if self.web_thread and self.web_thread.is_alive():
            # Shutdown Flask server
            func = request.environ.get('werkzeug.server.shutdown')
            if func:
                func()
            self.web_thread.join(timeout=5)
        
        win32event.SetEvent(self.stop_event)
    
    def SvcDoRun(self):
        # Start monitoring
        self.agent.start_monitoring()
        
        # Start web interface in a separate thread
        self.web_thread = threading.Thread(target=self.run_web_interface)
        self.web_thread.daemon = True
        self.web_thread.start()
        
        # Wait for stop signal
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
    
    def run_web_interface(self):
        """Run the Flask web interface"""
        # Web Interface Routes
        @app.route('/')
        @login_required
        def dashboard():
            with sqlite3.connect(CONFIG['DB_PATH']) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get recent alerts
                cursor.execute('''
                SELECT a.*, e.event_type, e.event_data, e.timestamp as event_time
                FROM alerts a
                JOIN events e ON a.event_id = e.id
                WHERE a.resolved = 0
                ORDER BY a.timestamp DESC
                LIMIT 50
                ''')
                alerts = cursor.fetchall()
                
                # Get stats
                cursor.execute('SELECT COUNT(*) FROM events')
                total_events = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM alerts WHERE resolved = 0')
                active_alerts = cursor.fetchone()[0]
                
                cursor.execute('''
                SELECT event_type, COUNT(*) as count 
                FROM events 
                GROUP BY event_type
                ORDER BY count DESC
                LIMIT 10
                ''')
                event_types = cursor.fetchall()
            
            return render_template(
                'dashboard.html',
                alerts=alerts,
                total_events=total_events,
                active_alerts=active_alerts,
                event_types=event_types
            )
        
        @app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                
                with sqlite3.connect(CONFIG['DB_PATH']) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                    SELECT password_hash FROM users WHERE username = ?
                    ''', (username,))
                    result = cursor.fetchone()
                
                if result and result[0] == hashlib.sha256(password.encode()).hexdigest():
                    user = User(username)
                    login_user(user)
                    return redirect(url_for('dashboard'))
                
                return render_template('login.html', error='Invalid credentials')
            
            return render_template('login.html')
        
        @app.route('/logout')
        @login_required
        def logout():
            logout_user()
            return redirect(url_for('login'))
        
        @app.route('/events')
        @login_required
        def events():
            page = request.args.get('page', 1, type=int)
            per_page = 50
            offset = (page - 1) * per_page
            
            with sqlite3.connect(CONFIG['DB_PATH']) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                SELECT * FROM events
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                ''', (per_page, offset))
                events = cursor.fetchall()
                
                cursor.execute('SELECT COUNT(*) FROM events')
                total = cursor.fetchone()[0]
            
            return render_template(
                'events.html',
                events=events,
                pagination={
                    'page': page,
                    'per_page': per_page,
                    'total': total
                }
            )
        
        @app.route('/alerts')
        @login_required
        def alerts():
            resolved = request.args.get('resolved', '0')
            
            with sqlite3.connect(CONFIG['DB_PATH']) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                SELECT a.*, e.event_type, e.event_data, e.timestamp as event_time
                FROM alerts a
                JOIN events e ON a.event_id = e.id
                WHERE a.resolved = ?
                ORDER BY a.timestamp DESC
                ''', (resolved,))
                alerts = cursor.fetchall()
            
            return render_template('alerts.html', alerts=alerts, resolved=resolved)
        
        @app.route('/resolve_alert/<int:alert_id>', methods=['POST'])
        @login_required
        def resolve_alert(alert_id):
            with sqlite3.connect(CONFIG['DB_PATH']) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                UPDATE alerts SET resolved = 1 WHERE id = ?
                ''', (alert_id,))
                conn.commit()
            
            return redirect(url_for('alerts'))
        
        @app.route('/whitelist', methods=['GET', 'POST'])
        @login_required
        def whitelist():
            if request.method == 'POST':
                item_type = request.form.get('item_type')
                item_path = request.form.get('item_path')
                
                with sqlite3.connect(CONFIG['DB_PATH']) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                    INSERT OR REPLACE INTO system_baseline 
                    (item_type, item_path, whitelisted)
                    VALUES (?, ?, 1)
                    ''', (item_type, item_path))
                    conn.commit()
                
                return redirect(url_for('whitelist'))
            
            with sqlite3.connect(CONFIG['DB_PATH']) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                SELECT * FROM system_baseline
                WHERE whitelisted = 1
                ORDER BY item_type, item_path
                ''')
                whitelist = cursor.fetchall()
            
            return render_template('whitelist.html', whitelist=whitelist)
        
        @app.route('/remove_whitelist/<int:item_id>', methods=['POST'])
        @login_required
        def remove_whitelist(item_id):
            with sqlite3.connect(CONFIG['DB_PATH']) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                UPDATE system_baseline SET whitelisted = 0 WHERE id = ?
                ''', (item_id,))
                conn.commit()
            
            return redirect(url_for('whitelist'))
        
        @app.route('/api/events', methods=['GET'])
        @login_required
        def api_events():
            limit = request.args.get('limit', 100, type=int)
            event_type = request.args.get('type')
            
            query = 'SELECT * FROM events'
            params = []
            
            if event_type:
                query += ' WHERE event_type = ?'
                params.append(event_type)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            with sqlite3.connect(CONFIG['DB_PATH']) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(query, params)
                events = cursor.fetchall()
            
            return jsonify([dict(event) for event in events])
        
        # Run the Flask app
        app.run(
            host=CONFIG['WEB_INTERFACE']['HOST'],
            port=CONFIG['WEB_INTERFACE']['PORT'],
            threaded=True
        )

# Command Line Interface
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'run':
        # Run in console mode (for debugging)
        agent = EDRAgent()
        agent.start_monitoring()
        
        # Start web interface in main thread
        app.run(
            host=CONFIG['WEB_INTERFACE']['HOST'],
            port=CONFIG['WEB_INTERFACE']['PORT']
        )
    else:
        # Handle Windows service commands
        win32serviceutil.HandleCommandLine(EDRService)
