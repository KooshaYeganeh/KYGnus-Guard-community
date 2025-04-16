#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import time
import threading
import signal
from datetime import datetime
import logging
import configparser
import sqlite3
import hashlib
import argparse
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
from pathlib import Path

# Configuration

ETC = os.path.join("etc")
os.makedirs(ETC, exist_ok=True)



VAR = os.path.join("var")
os.makedirs(VAR, exist_ok=True)


LOG = os.path.join("var/log")
os.makedirs(LOG, exist_ok=True)



LIB = os.path.join("var/lib")
os.makedirs(LIB, exist_ok=True)

CONFIG_FILE = 'etc/config.ini'
DB_FILE = 'var/lib/edr.db'
LOG_FILE = 'var/log/edr.log'

# Initialize logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('LinuxEDR')

def load_config():
    """Load configuration from INI file"""
    config = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        create_default_config(config)
    config.read(CONFIG_FILE)
    return config

def create_default_config(config):
    """Create default configuration file"""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    config['DEFAULT'] = {
        'scan_interval': '3600',
        'monitor_paths': '/bin,/sbin,/usr/bin,/usr/sbin,/lib,/lib64,/usr/lib,/usr/lib64',
        'exclude_paths': '/proc,/sys,/dev,/run',
        'malware_scan_enabled': 'true',
        'rootkit_scan_enabled': 'true',
        'audit_enabled': 'true',
        'firewall_enabled': 'true',
        'ids_enabled': 'true',
        'ml_enabled': 'true',
        'ml_model_path': '/var/lib/linux_edr/ml_models/',
        'ml_train_interval': '86400',
        'ml_anomaly_threshold': '0.65'
    }
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def setup_database():
    """Initialize SQLite database for event storage"""
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME,
        event_type TEXT,
        severity TEXT,
        source TEXT,
        details TEXT,
        action_taken TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_hashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT UNIQUE,
        file_hash TEXT,
        last_scanned DATETIME
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        check_name TEXT,
        last_run DATETIME,
        status TEXT,
        findings TEXT
    )
    ''')

    conn.commit()
    return conn

def log_event(conn, event_type, severity, source, details, action_taken=""):
    """Log security event to database"""
    timestamp = datetime.now().isoformat()
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO events (timestamp, event_type, severity, source, details, action_taken)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, event_type, severity, source, details, action_taken))
    conn.commit()
    logger.info(f"{event_type} - {severity} - {source} - {details}")

def run_malware_scan(conn, config):
    """Run malware scan using ClamAV and LMD"""
    logger.info("Starting malware scan")
    try:
        # Run ClamAV scan
        scan_paths = config['DEFAULT']['monitor_paths']
        result = subprocess.run(
            ['clamscan', '-r', '--infected', '--log', LOG_FILE] + scan_paths.split(','),
            capture_output=True,
            text=True
        )

        if result.returncode == 1:
            infected = [line for line in result.stdout.split('\n') if 'FOUND' in line]
            for infection in infected:
                log_event(
                    conn,
                    'MALWARE_DETECTED',
                    'CRITICAL',
                    'ClamAV',
                    infection,
                    'Quarantine recommended'
                )

        # Run Linux Malware Detect (LMD)
        result = subprocess.run(
            ['maldet', '--scan-all', scan_paths],
            capture_output=True,
            text=True
        )

        if 'hit(s)' in result.stdout:
            log_event(
                conn,
                'MALWARE_DETECTED',
                'CRITICAL',
                'LMD',
                result.stdout,
                'Review detected items'
            )

        # Update system checks table
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO system_checks (check_name, last_run, status, findings)
        VALUES (?, ?, ?, ?)
        ''', (
            'malware_scan',
            datetime.now().isoformat(),
            'completed',
            json.dumps({'clamav': result.stdout, 'maldet': result.stdout})
        ))
        conn.commit()
        logger.info("Malware scan completed")

    except Exception as e:
        logger.error(f"Malware scan failed: {str(e)}")
        log_event(
            conn,
            'SCAN_FAILURE',
            'HIGH',
            'MalwareScanner',
            str(e)
        )

def run_rootkit_scan(conn, config):
    """Run rootkit scan using rkhunter and chkrootkit"""
    logger.info("Starting rootkit scan")
    try:
        # Run rkhunter
        result = subprocess.run(
            ['rkhunter', '--check', '--sk', '--nocolors'],
            capture_output=True,
            text=True
        )

        if 'Warning:' in result.stdout:
            warnings = [line for line in result.stdout.split('\n') if 'Warning:' in line]
            for warning in warnings:
                log_event(
                    conn,
                    'ROOTKIT_WARNING',
                    'HIGH',
                    'RKHunter',
                    warning,
                    'Investigation required'
                )

        # Run chkrootkit
        result = subprocess.run(
            ['chkrootkit'],
            capture_output=True,
            text=True
        )

        if 'INFECTED' in result.stdout:
            infections = [line for line in result.stdout.split('\n') if 'INFECTED' in line]
            for infection in infections:
                log_event(
                    conn,
                    'ROOTKIT_DETECTED',
                    'CRITICAL',
                    'CHKRootkit',
                    infection,
                    'Immediate action required'
                )

        # Update system checks table
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO system_checks (check_name, last_run, status, findings)
        VALUES (?, ?, ?, ?)
        ''', (
            'rootkit_scan',
            datetime.now().isoformat(),
            'completed',
            json.dumps({'rkhunter': result.stdout, 'chkrootkit': result.stdout})
        ))
        conn.commit()
        logger.info("Rootkit scan completed")

    except Exception as e:
        logger.error(f"Rootkit scan failed: {str(e)}")
        log_event(
            conn,
            'SCAN_FAILURE',
            'HIGH',
            'RootkitScanner',
            str(e)
        )

def run_security_audit(conn, config):
    """Run security audit using Lynis and custom checks"""
    logger.info("Starting security audit")
    try:
        # Run Lynis audit
        result = subprocess.run(
            ['lynis', 'audit', 'system', '--quick'],
            capture_output=True,
            text=True
        )

        # Parse Lynis results
        warnings = [line for line in result.stdout.split('\n') if '[warning]' in line]
        suggestions = [line for line in result.stdout.split('\n') if '[suggestion]' in line]

        for warning in warnings:
            log_event(
                conn,
                'SECURITY_WARNING',
                'MEDIUM',
                'Lynis',
                warning,
                'Review recommendation'
            )

        # Update system checks table
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO system_checks (check_name, last_run, status, findings)
        VALUES (?, ?, ?, ?)
        ''', (
            'security_audit',
            datetime.now().isoformat(),
            'completed',
            json.dumps({'lynis': result.stdout})
        ))
        conn.commit()
        logger.info("Security audit completed")

    except Exception as e:
        logger.error(f"Security audit failed: {str(e)}")
        log_event(
            conn,
            'SCAN_FAILURE',
            'HIGH',
            'SecurityAudit',
            str(e)
        )

def monitor_file_changes(conn, config):
    """Monitor important system files for changes"""
    critical_files = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/ssh/sshd_config',
        '/etc/crontab',
        '/etc/hosts',
        '/etc/resolv.conf'
    ]

    for file_path in critical_files:
        if not os.path.exists(file_path):
            continue

        current_hash = calculate_file_hash(file_path)
        cursor = conn.cursor()
        cursor.execute('SELECT file_hash FROM file_hashes WHERE file_path = ?', (file_path,))
        row = cursor.fetchone()

        if row:
            if row[0] != current_hash:
                log_event(
                    conn,
                    'FILE_MODIFIED',
                    'HIGH',
                    'FileMonitor',
                    f"Critical file modified: {file_path}",
                    'Investigate change'
                )
                # Update hash in database
                cursor.execute('''
                UPDATE file_hashes
                SET file_hash = ?, last_scanned = ?
                WHERE file_path = ?
                ''', (current_hash, datetime.now().isoformat(), file_path))
                conn.commit()
        else:
            # First time seeing this file
            cursor.execute('''
            INSERT INTO file_hashes (file_path, file_hash, last_scanned)
            VALUES (?, ?, ?)
            ''', (file_path, current_hash, datetime.now().isoformat()))
            conn.commit()

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)  # 64kb chunks
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

def manage_firewall(conn, config):
    """Configure and monitor firewalld"""
    try:
        # Check firewalld status
        result = subprocess.run(
            ['firewall-cmd', '--state'],
            capture_output=True,
            text=True
        )

        if 'running' not in result.stdout.lower():
            log_event(
                conn,
                'FIREWALL_STATUS',
                'HIGH',
                'FirewallD',
                'Firewalld is not running',
                'Start firewalld service'
            )
            subprocess.run(['systemctl', 'start', 'firewalld'])

        # Check default zone
        result = subprocess.run(
            ['firewall-cmd', '--get-default-zone'],
            capture_output=True,
            text=True
        )
        default_zone = result.stdout.strip()

        if default_zone != 'public':
            log_event(
                conn,
                'FIREWALL_CONFIG',
                'MEDIUM',
                'FirewallD',
                f"Default zone is {default_zone}",
                'Consider changing to public zone'
            )

        # Log firewall changes
        log_event(
            conn,
            'FIREWALL_STATUS',
            'INFO',
            'FirewallD',
            f"Firewall active with zone {default_zone}"
        )

    except Exception as e:
        logger.error(f"Firewall check failed: {str(e)}")
        log_event(
            conn,
            'FIREWALL_ERROR',
            'HIGH',
            'FirewallD',
            str(e)
        )

def manage_fail2ban(conn, config):
    """Configure and monitor Fail2Ban"""
    try:
        # Check Fail2Ban status
        result = subprocess.run(
            ['fail2ban-client', 'status'],
            capture_output=True,
            text=True
        )

        if 'is not running' in result.stderr.lower():
            log_event(
                conn,
                'FAIL2BAN_STATUS',
                'HIGH',
                'Fail2Ban',
                'Fail2Ban is not running',
                'Start Fail2Ban service'
            )
            subprocess.run(['systemctl', 'start', 'fail2ban'])

        # Get banned IPs
        result = subprocess.run(
            ['fail2ban-client', 'status', 'sshd'],
            capture_output=True,
            text=True
        )

        banned_ips = []
        for line in result.stdout.split('\n'):
            if 'Banned IP list:' in line:
                banned_ips = line.split(':')[1].strip().split()
                break

        if banned_ips:
            log_event(
                conn,
                'FAIL2BAN_BANS',
                'INFO',
                'Fail2Ban',
                f"Banned IPs: {', '.join(banned_ips)}",
                'Review if expected'
            )

    except Exception as e:
        logger.error(f"Fail2Ban check failed: {str(e)}")
        log_event(
            conn,
            'FAIL2BAN_ERROR',
            'HIGH',
            'Fail2Ban',
            str(e)
        )

def monitor_snort_alerts(conn, config):
    """Monitor Snort alerts"""
    snort_alert_file = '/var/log/snort/alert'
    if not os.path.exists(snort_alert_file):
        return

    # Track last read position
    last_pos = 0
    if os.path.exists('/tmp/snort_last_pos'):
        with open('/tmp/snort_last_pos', 'r') as f:
            last_pos = int(f.read())

    with open(snort_alert_file, 'r') as f:
        f.seek(last_pos)
        new_alerts = f.read()
        last_pos = f.tell()

    if new_alerts:
        log_event(
            conn,
            'IDS_ALERT',
            'HIGH',
            'Snort',
            new_alerts,
            'Investigate network activity'
        )

    # Save last position
    with open('/tmp/snort_last_pos', 'w') as f:
        f.write(str(last_pos))

def extract_features_from_event(event):
    """Convert event data to ML features"""
    features = {
        'event_type': event[2],  # Type of event
        'severity': {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}[event[3]],
        'source': event[4],  # Source component
        'hour_of_day': datetime.strptime(event[1], '%Y-%m-%dT%H:%M:%S.%f').hour,
        'is_weekend': int(datetime.strptime(event[1], '%Y-%m-%dT%H:%M:%S.%f').weekday()) >= 5
    }
    return features

def prepare_training_data(conn):
    """Prepare training data from historical events"""
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM events')
    events = cursor.fetchall()

    # Convert to DataFrame
    data = []
    for event in events:
        try:
            features = extract_features_from_event(event)
            data.append(features)
        except:
            continue

    df = pd.DataFrame(data)

    # One-hot encode categorical features
    df = pd.get_dummies(df, columns=['event_type', 'source'])

    return df

def train_anomaly_detection_model(conn, config):
    """Train and save an Isolation Forest model"""
    logger.info("Training ML anomaly detection model")
    model_path = config.get('ML', 'ml_model_path')
    Path(model_path).mkdir(parents=True, exist_ok=True)

    df = prepare_training_data(conn)
    if len(df) < 100:  # Need sufficient data
        logger.warning("Insufficient data for training (need at least 100 events)")
        return None

    X = df.drop(columns=['severity']) if 'severity' in df.columns else df

    # Train Isolation Forest for anomaly detection
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )
    model.fit(X)

    # Save the model
    model_file = os.path.join(model_path, 'anomaly_detection.pkl')
    with open(model_file, 'wb') as f:
        pickle.dump(model, f)

    # Save the scaler and feature names
    scaler = StandardScaler()
    scaler.fit(X)

    meta = {
        'feature_names': list(X.columns),
        'scaler': scaler
    }

    with open(os.path.join(model_path, 'meta.pkl'), 'wb') as f:
        pickle.dump(meta, f)

    logger.info(f"ML model trained and saved to {model_path}")
    return model

def load_ml_model(config):
    """Load trained ML model"""
    model_path = config.get('ML', 'ml_model_path')
    model_file = os.path.join(model_path, 'anomaly_detection.pkl')
    meta_file = os.path.join(model_path, 'meta.pkl')

    if not os.path.exists(model_file):
        return None, None

    with open(model_file, 'rb') as f:
        model = pickle.load(f)

    with open(meta_file, 'rb') as f:
        meta = pickle.load(f)

    return model, meta

def detect_anomalies(conn, config):
    """Detect anomalous events using ML"""
    if not config.getboolean('ML', 'ml_enabled'):
        return

    model, meta = load_ml_model(config)
    if model is None:
        return

    cursor = conn.cursor()
    cursor.execute('SELECT * FROM events WHERE timestamp > datetime("now", "-1 hour")')
    recent_events = cursor.fetchall()

    for event in recent_events:
        try:
            features = extract_features_from_event(event)
            df = pd.DataFrame([features])
            df = pd.get_dummies(df, columns=['event_type', 'source'])

            # Ensure we have all expected columns
            for col in meta['feature_names']:
                if col not in df.columns:
                    df[col] = 0

            # Reorder columns to match training
            df = df[meta['feature_names']]

            # Scale features
            X = meta['scaler'].transform(df)

            # Predict anomaly score (-1 to 1 where -1 is anomaly)
            score = model.decision_function(X)[0]
            anomaly_prob = (1 - (score + 1) / 2)  # Convert to 0-1 probability

            if anomaly_prob > config.getfloat('ML', 'ml_anomaly_threshold'):
                log_event(
                    conn,
                    'ML_ANOMALY_DETECTED',
                    'HIGH',
                    'ML_Engine',
                    f"Anomalous event detected (score: {anomaly_prob:.2f}): {event[2]} from {event[4]}",
                    "Review event for potential threat"
                )
        except Exception as e:
            logger.error(f"Anomaly detection failed for event {event[0]}: {str(e)}")

def print_events(conn, limit=50):
    """Print recent events to console"""
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?', (limit,))
    events = cursor.fetchall()

    print("\nRecent Security Events:")
    print("-" * 80)
    print(f"{'Time':20} | {'Type':15} | {'Severity':8} | {'Source':15} | Details")
    print("-" * 80)
    for event in events:
        print(f"{event[1]:20} | {event[2]:15} | {event[3]:8} | {event[4]:15} | {event[5][:50]}...")

def print_scan_results(conn, limit=5):
    """Print recent scan results to console"""
    cursor = conn.cursor()
    cursor.execute('SELECT check_name, last_run, status FROM system_checks ORDER BY last_run DESC LIMIT ?', (limit,))
    scans = cursor.fetchall()

    print("\nRecent Scan Results:")
    print("-" * 80)
    print(f"{'Scan Type':20} | {'Last Run':20} | {'Status':10}")
    print("-" * 80)
    for scan in scans:
        print(f"{scan[0]:20} | {scan[1]:20} | {scan[2]:10}")

def signal_handler(sig, frame):
    """Handle shutdown signals"""
    global running
    logger.info("Shutting down Linux EDR system")
    running = False

def daemon_mode(config):
    """Run EDR in continuous monitoring mode"""
    conn = setup_database()
    last_ml_train = time.time()

    logger.info("Starting Linux EDR in daemon mode")
    print("EDR daemon started. Monitoring system... (Ctrl+C to stop)")

    while running:
        try:
            # Retrain ML model periodically
            if time.time() - last_ml_train > config.getint('ML', 'ml_train_interval'):
                train_anomaly_detection_model(conn, config)
                last_ml_train = time.time()

            # Run scheduled scans
            if config.getboolean('DEFAULT', 'malware_scan_enabled'):
                run_malware_scan(conn, config)

            if config.getboolean('DEFAULT', 'rootkit_scan_enabled'):
                run_rootkit_scan(conn, config)

            if config.getboolean('DEFAULT', 'audit_enabled'):
                run_security_audit(conn, config)

            # Continuous monitoring
            monitor_file_changes(conn, config)

            if config.getboolean('DEFAULT', 'firewall_enabled'):
                manage_firewall(conn, config)

            if config.getboolean('DEFAULT', 'ids_enabled'):
                manage_fail2ban(conn, config)
                monitor_snort_alerts(conn, config)

            # ML anomaly detection
            if config.getboolean('ML', 'ml_enabled'):
                detect_anomalies(conn, config)

            # Sleep for configured interval
            time.sleep(config.getint('DEFAULT', 'scan_interval'))

        except Exception as e:
            logger.error(f"Daemon loop error: {str(e)}")
            time.sleep(60)  # Wait before retrying

    conn.close()

def main():
    """Main entry point with command-line arguments"""
    parser = argparse.ArgumentParser(description='Linux Endpoint Detection and Response Tool')

    # Operational modes
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--daemon', action='store_true', help='Run in continuous monitoring mode')
    group.add_argument('--malware-scan', action='store_true', help='Run malware scan and exit')
    group.add_argument('--rootkit-scan', action='store_true', help='Run rootkit scan and exit')
    group.add_argument('--security-audit', action='store_true', help='Run security audit and exit')
    group.add_argument('--train-ml', action='store_true', help='Train ML model and exit')
    group.add_argument('--check-status', action='store_true', help='Show current status and recent events')

    # Configuration overrides
    parser.add_argument('--config', help='Alternative config file path')
    parser.add_argument('--scan-interval', type=int, help='Set scan interval in seconds')
    parser.add_argument('--enable-ml', action='store_true', help='Enable machine learning features')
    parser.add_argument('--disable-ml', action='store_true', help='Disable machine learning features')

    args = parser.parse_args()

    # Load config
    config = load_config()
    if args.config:
        config.read(args.config)

    # Apply command-line overrides
    if args.scan_interval:
        config['DEFAULT']['scan_interval'] = str(args.scan_interval)
    if args.enable_ml:
        config['ML']['ml_enabled'] = 'true'
    if args.disable_ml:
        config['ML']['ml_enabled'] = 'false'

    conn = setup_database()

    if args.daemon:
        # Handle Ctrl+C
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        daemon_mode(config)
    elif args.malware_scan:
        run_malware_scan(conn, config)
        print_scan_results(conn)
    elif args.rootkit_scan:
        run_rootkit_scan(conn, config)
        print_scan_results(conn)
    elif args.security_audit:
        run_security_audit(conn, config)
        print_scan_results(conn)
    elif args.train_ml:
        train_anomaly_detection_model(conn, config)
    elif args.check_status:
        print_events(conn)
        print_scan_results(conn)
    else:
        parser.print_help()

    conn.close()

if __name__ == '__main__':
    main()
