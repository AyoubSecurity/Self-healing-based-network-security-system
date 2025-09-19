from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import socket
import threading
import subprocess
import os
import shutil
import time
import sqlite3
from datetime import datetime, timedelta
from scapy.all import sniff, ARP, Ether, srp, conf, IP, TCP, sr
from collections import defaultdict
import re
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import sys
import select
import logging

app = Flask(__name__)
app.secret_key = 'abcde98765fghij43210klmnop01234ab'

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

ADMIN_PORT = 5555
WINDOW_SIZE = 60
DB_LOCK = threading.Lock()
traffic_stats = defaultdict(lambda: {'count': 0, 'timestamps': []})
connected_guests = {}
blocked_ips = {}
monitoring_thread = None
BACKUP_INTERVAL = 60
last_backup_check_time = 0
BLOCKED_MAC_FILE = "blocked_mac.txt"
BLOCKED_IP_FILE = "blocked_ip.txt"
BLOCKED_PORTS_FILE = "blocked_ports.txt"
WHITELIST_FILE = "whitelist.txt"
SPECIFIED_PORTS_FILE = "specified_ports.txt"
BACKUP_SPECIFIED_PORTS_DIR = "backups_specified_ports"
BACKUP_BLOCKED_PORTS_DIR = "backups_blocked_ports"

THRESHOLD = 1000
monitoring_active = threading.Event()
monitoring_active.set()

auto_block_ip_enabled = False

last_alert_times = defaultdict(lambda: 0)

SCAN_DB = "scan_results.db"
PACKET_DB = "packet_logs.db"
INSTRUCTION_LOGS_DB = "instruction_logs.db"
BACKUP_SCAN_DIR = "backups_scan"
BACKUP_PACKET_DIR = "backups_packet"
BACKUP_INSTRUCTION_LOGS_DIR = "backups_instruction_logs"
BACKUP_WHITELIST_DIR = "backups_whitelist"
BACKUP_FILES = [SCAN_DB, PACKET_DB, INSTRUCTION_LOGS_DB, WHITELIST_FILE, BLOCKED_PORTS_FILE, SPECIFIED_PORTS_FILE]

local_ip = None
default_subnet = None
current_subnet = None
current_start_ip = 0
current_end_ip = 255
scan_settings_updated = False
scan_enabled = True
scan_thread = None
current_scan_ports = set()
estimated_scan_duration = 60
scan_cycle_start_time = None
connected_guests = {}

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {message}", flush=True)
    sys.stdout.flush()

def init_db():
    with DB_LOCK:
        conn = sqlite3.connect(SCAN_DB)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scans
                     (scan_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_time TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS ips
                     (ip_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, ip_address TEXT UNIQUE,
                      status TEXT, test_time TEXT, os TEXT, mac_address TEXT,
                      FOREIGN KEY(scan_id) REFERENCES scans(scan_id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS ports
                     (port_id INTEGER PRIMARY KEY AUTOINCREMENT, ip_id INTEGER, port_number INTEGER, status TEXT,
                      FOREIGN KEY(ip_id) REFERENCES ips(ip_id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)''')
        conn.commit()
        conn.close()

def add_default_user():
    conn = sqlite3.connect(SCAN_DB)
    c = conn.cursor()
    try:
        hashed_password = generate_password_hash('admin')
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()

def init_packet_db():
    with DB_LOCK:
        conn = sqlite3.connect(PACKET_DB)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS packet_logs
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, src_ip TEXT, protocol TEXT,
                      packet_size INTEGER, dest_ip TEXT, dest_port INTEGER)''')
        c.execute('''CREATE TABLE IF NOT EXISTS alert_logs
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, src_ip TEXT, packet_count INTEGER, action TEXT)''')
        c.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON packet_logs (timestamp)")
        conn.commit()
        conn.close()

def init_instruction_logs_db():
    with DB_LOCK:
        try:
            conn = sqlite3.connect(INSTRUCTION_LOGS_DB)
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS instruction_logs
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
                          event_details TEXT NOT NULL)''')
            c.execute('''CREATE TABLE IF NOT EXISTS alerts
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, alert_type TEXT NOT NULL,
                          details TEXT NOT NULL, seen INTEGER DEFAULT 0)''')
            conn.commit()
        except Exception as e:
            log(f"Error initializing {INSTRUCTION_LOGS_DB}: {e}")
        finally:
            conn.close()

def check_db_integrity(db_path):
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("PRAGMA integrity_check")
        result = c.fetchone()[0]
        conn.close()
        return result == "ok"
    except sqlite3.DatabaseError as e:
        log(f"Database integrity check failed for {db_path}: {e}")
        return False

def backup_database(db_path, backup_dir):
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(backup_dir, f"{os.path.basename(db_path)}_{timestamp}.bak")
    shutil.copy2(db_path, backup_path)
    log(f"Backed up {db_path} to {backup_path}")

def restore_database(db_path, backup_dir):
    log(f"Attempting to restore {db_path} from backup")
    backups = sorted([f for f in os.listdir(backup_dir) if f.endswith('.bak')], reverse=True)
    if not backups:
        log(f"No backups found for {db_path}. Reinitializing.")
        log_instruction("database_reinitialization", f"Reinitialized {db_path} due to no backups")
        os.remove(db_path) if os.path.exists(db_path) else None
        if "scan_results" in db_path:
            init_db()
        elif "packet_logs" in db_path:
            init_packet_db()
        else:
            init_instruction_logs_db()
        return

    for backup in backups:
        backup_path = os.path.join(backup_dir, backup)
        if check_backup_integrity(backup_path):
            shutil.copy2(backup_path, db_path)
            log(f"Restored {db_path} from {backup_path}")
            log_instruction("database_recovery", f"Restored {db_path} from {backup_path}")
            return
    log(f"No valid backups found for {db_path}. Reinitializing.")
    os.remove(db_path) if os.path.exists(db_path) else None
    if "scan_results" in db_path:
        init_db()
    elif "packet_logs" in db_path:
        init_packet_db()
    else:
        init_instruction_logs_db()

def check_backup_integrity(backup_path):
    try:
        conn = sqlite3.connect(backup_path)
        c = conn.cursor()
        c.execute("PRAGMA integrity_check")
        result = c.fetchone()[0]
        conn.close()
        return result == "ok"
    except sqlite3.DatabaseError as e:
        log(f"Backup integrity check failed for {backup_path}: {e}")
        return False

def prune_packet_logs(db_path, retention_days=7):
    try:
        with DB_LOCK:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            cutoff_time = (datetime.now() - timedelta(days=retention_days)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("DELETE FROM packet_logs WHERE timestamp < ?", (cutoff_time,))
            deleted_rows = conn.total_changes
            c.execute("DELETE FROM alert_logs WHERE timestamp < ?", (cutoff_time,))
            deleted_rows += conn.total_changes
            conn.commit()
            log(f"Pruned {deleted_rows} old entries from {db_path}")
            c.execute("VACUUM")
            conn.commit()
    except Exception as e:
        log(f"Error pruning {db_path}: {e}")
    finally:
        conn.close()

def prune_instruction_logs(db_path, retention_days=3):
    try:
        with DB_LOCK:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            cutoff_time = (datetime.now() - timedelta(days=retention_days)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("DELETE FROM instruction_logs WHERE timestamp < ?", (cutoff_time,))
            deleted_rows = conn.total_changes
            conn.commit()
            log(f"Pruned {deleted_rows} old entries from {db_path}")
            c.execute("VACUUM")
            conn.commit()
    except Exception as e:
        log(f"Error pruning {db_path}: {e}")
    finally:
        conn.close()

def prune_alerts(db_path, retention_days=30):
    try:
        with DB_LOCK:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            cutoff_time = (datetime.now() - timedelta(days=retention_days)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff_time,))
            deleted_rows = conn.total_changes
            conn.commit()
            log(f"Pruned {deleted_rows} old alerts from {db_path}")
    except Exception as e:
        log(f"Error pruning alerts from {db_path}: {e}")
    finally:
        conn.close()

def periodic_db_check_and_backup(db_path, backup_dir, interval_seconds=60, keep_backups=50):
    while True:
        start_time = time.time()
        log(f"Checking integrity of database {db_path}")
        if not os.path.exists(db_path) or not check_db_integrity(db_path):
            log(f"Database {db_path} is missing or corrupted. Attempting to restore from backup.")
            restore_database(db_path, backup_dir)
        else:
            log(f"Database {db_path} integrity check passed. No restoration needed.")
        if db_path == PACKET_DB:
            prune_packet_logs(db_path, retention_days=7)
        elif db_path == INSTRUCTION_LOGS_DB:
            prune_instruction_logs(db_path, retention_days=3)
            prune_alerts(db_path, retention_days=30)
        backup_database(db_path, backup_dir)
        cleanup_backups(backup_dir, keep_backups)
        last_backup_check_time = start_time
        elapsed_time = time.time() - start_time
        time.sleep(max(0, interval_seconds - elapsed_time))

def log_instruction(event_type, event_details):
    with DB_LOCK:
        try:
            conn = sqlite3.connect(INSTRUCTION_LOGS_DB)
            c = conn.cursor()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute('''INSERT INTO instruction_logs (timestamp, event_type, event_details)
                         VALUES (?, ?, ?)''', (timestamp, event_type, event_details))
            conn.commit()
        except Exception as e:
            log(f"Error logging event: {e}")
        finally:
            conn.close()

def log_alert(alert_type, details):
    global last_alert_times
    key = f"{alert_type}_{details}"
    current_time = time.time()
    if current_time - last_alert_times.get(key, 0) < 60:
        log(f"Alert suppressed: {alert_type} - {details}")
        return
    last_alert_times[key] = current_time
    with DB_LOCK:
        try:
            conn = sqlite3.connect(INSTRUCTION_LOGS_DB)
            c = conn.cursor()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute('''INSERT INTO alerts (timestamp, alert_type, details, seen)
                         VALUES (?, ?, ?, 0)''', (timestamp, alert_type, details))
            conn.commit()
            log(f"Alert logged: {alert_type} - {details}")
        except Exception as e:
            log(f"Error logging alert: {e}")
        finally:
            conn.close()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(SCAN_DB)
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        return User(id=user_data[0], username=user_data[1])
    return None

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", key_func=lambda: request.remote_addr, methods=["POST"])
@limiter.limit("10 per minute", key_func=lambda: request.form.get('username', ''), methods=["POST"])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect(SCAN_DB)
        c = conn.cursor()
        c.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user_data = c.fetchone()
        conn.close()
        if user_data and check_password_hash(user_data[2], password):
            user = User(id=user_data[0], username=user_data[1])
            login_user(user)
            log_instruction("login_success", f"User {username} logged in successfully")
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            log_instruction("login_failure", f"Failed login attempt for username: {username}")
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.errorhandler(429)
def ratelimit_handler(e):
    username = request.form.get('username', 'unknown')
    ip = request.remote_addr
    log_instruction("rate_limit_exceeded", f"Rate limit exceeded for username: {username}, IP: {ip}")
    flash("Too many login attempts. Please try again later.", "error")
    return render_template("login.html"), 429

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    log_instruction("logout", f"User {username} logged out")
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return '127.0.0.1'

def tcp_syn_check(ip, ports=[80, 443]):
    for port in ports:
        try:
            syn = IP(dst=ip) / TCP(dport=port, flags="S")
            ans, _ = sr(syn, timeout=2, verbose=0)
            for _, received in ans:
                if received.haslayer(TCP):
                    flags = received[TCP].flags
                    if flags == "SA" or flags == "R":
                        log(f"Host {ip} responded on port {port} with flags {flags}")
                        return True
        except Exception as e:
            log(f"Error in TCP SYN check for {ip}:{port}: {e}")
            continue
    return False

def is_host_active(ip):
    param = '-n' if os.name == 'nt' else '-c'
    timeout_param = '-w' if os.name == 'nt' else '-W'
    command = ['ping', param, '2', timeout_param, '4000', ip]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        if result.returncode == 0:
            log(f"Host {ip} is up (ping)")
            return True
    except Exception as e:
        log(f"Ping failed for {ip}: {e}")
    if tcp_syn_check(ip, [80, 443]):
        log(f"Host {ip} is up (TCP SYN)")
        return True
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]
        if len(result) > 0:
            log(f"Host {ip} is up (ARP)")
            return True
        return False
    except Exception as e:
        log(f"ARP request failed for {ip}: {e}")
        return False

def get_os(ip):
    try:
        param = '-n' if os.name == 'nt' else '-c'
        command = ['ping', param, '1', '-w', '4000', ip]
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL, timeout=5).decode('utf-8', errors='replace')
        ttl_match = re.search(r'ttl=(\d+)', result, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            elif ttl <= 255:
                return "Solaris/AIX"
        return "Unknown"
    except Exception:
        return "Unknown"

def get_mac_address(ip):
    try:
        arp_command = ['arp', '-a', ip] if os.name == 'nt' else ['arp', '-n', ip]
        result = subprocess.check_output(arp_command, stderr=subprocess.DEVNULL, timeout=2).decode()
        for line in result.splitlines():
            if ip in line:
                parts = line.split()
                for part in parts:
                    if '-' in part or ':' in part:
                        return part.upper()
        return "Unknown"
    except Exception:
        return "Unknown"

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return "open" if result == 0 else "closed"
    except Exception:
        return "closed"

last_scan_time = 0
current_ip_scanning = None
auto_block_enabled = False

def load_specified_ports():
    if not os.path.exists(SPECIFIED_PORTS_FILE):
        with open(SPECIFIED_PORTS_FILE, 'w') as f:
            pass
        return set()
    with open(SPECIFIED_PORTS_FILE, 'r') as f:
        return set(int(line.strip()) for line in f if line.strip().isdigit())

def add_to_specified_ports(port):
    if not isinstance(port, int) or port < 1 or port > 65535:
        return
    with open(SPECIFIED_PORTS_FILE, 'a') as f:
        f.write(f"{port}\n")
    log_instruction("specified_ports_add", f"Added port {port} to specified ports")

def remove_from_specified_ports(port):
    specified_ports = load_specified_ports()
    if port in specified_ports:
        specified_ports.remove(port)
        with open(SPECIFIED_PORTS_FILE, 'w') as f:
            for p in specified_ports:
                f.write(f"{p}\n")
        log_instruction("specified_ports_remove", f"Removed port {port} from specified ports")

def load_blocked_ports():
    ports = load_blocked_list(BLOCKED_PORTS_FILE)
    return set(int(port) for port in ports if port.isdigit())

def add_to_blocked_ports(port):
    if not isinstance(port, int) or port < 1 or port > 65535:
        return
    add_to_blocked_list(BLOCKED_PORTS_FILE, str(port))
    manage_firewall('block', 'PORT', str(port))
    broadcast_block_instruction("PORT", str(port), "block")
    log_instruction("blocked_ports_add", f"Added port {port} to blocked ports")
    log_instruction("broadcast_block_port", f"Broadcasted block instruction for port {port} to guests")

def remove_from_blocked_ports(port):
    if not isinstance(port, int) or port < 1 or port > 65535:
        return
    remove_from_blocked_list(BLOCKED_PORTS_FILE, str(port))
    manage_firewall('unblock', 'PORT', str(port))
    broadcast_block_instruction("PORT", str(port), "unblock")
    log_instruction("blocked_ports_remove", f"Removed port {port} from blocked ports")
    log_instruction("broadcast_unblock_port", f"Broadcasted unblock instruction for port {port} to guests")

def backup_specified_ports():
    if not os.path.exists(BACKUP_SPECIFIED_PORTS_DIR):
        os.makedirs(BACKUP_SPECIFIED_PORTS_DIR)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_SPECIFIED_PORTS_DIR, f"specified_ports_{timestamp}.bak")
    shutil.copy2(SPECIFIED_PORTS_FILE, backup_path)
    log(f"Backed up specified ports to {backup_path}")

def restore_specified_ports():
    log(f"Attempting to restore {SPECIFIED_PORTS_FILE} from backup")
    backups = sorted([f for f in os.listdir(BACKUP_SPECIFIED_PORTS_DIR) if f.endswith('.bak')], reverse=True)
    if not backups:
        log(f"No backups found for specified ports. Creating empty file.")
        log_instruction("file_reinitialization", f"Reinitialized {SPECIFIED_PORTS_FILE} due to no backups")
        with open(SPECIFIED_PORTS_FILE, 'w') as f:
            pass
        return
    for backup in backups:
        backup_path = os.path.join(BACKUP_SPECIFIED_PORTS_DIR, backup)
        try:
            shutil.copy2(backup_path, SPECIFIED_PORTS_FILE)
            log(f"Restored {SPECIFIED_PORTS_FILE} from {backup_path}")
            log_instruction("file_recovery", f"Restored {SPECIFIED_PORTS_FILE} from {backup_path}")
            return
        except Exception as e:
            log(f"Failed to restore from {backup_path}: {e}")
    log(f"No valid backups found for specified ports. Creating empty file.")
    log_instruction("file_reinitialization", f"Reinitialized {SPECIFIED_PORTS_FILE} due to no valid backups")
    with open(SPECIFIED_PORTS_FILE, 'w') as f:
        pass

def backup_blocked_ports():
    if not os.path.exists(BACKUP_BLOCKED_PORTS_DIR):
        os.makedirs(BACKUP_BLOCKED_PORTS_DIR)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_BLOCKED_PORTS_DIR, f"blocked_ports_{timestamp}.bak")
    shutil.copy2(BLOCKED_PORTS_FILE, backup_path)
    log(f"Backed up blocked ports to {backup_path}")

def restore_blocked_ports():
    log(f"Attempting to restore {BLOCKED_PORTS_FILE} from backup")
    backups = sorted([f for f in os.listdir(BACKUP_BLOCKED_PORTS_DIR) if f.endswith('.bak')], reverse=True)
    if not backups:
        log(f"No backups found for blocked ports. Creating empty file.")
        log_instruction("file_reinitialization", f"Reinitialized {BLOCKED_PORTS_FILE} due to no backups")
        with open(BLOCKED_PORTS_FILE, 'w') as f:
            pass
        return
    for backup in backups:
        backup_path = os.path.join(BACKUP_BLOCKED_PORTS_DIR, backup)
        try:
            shutil.copy2(backup_path, BLOCKED_PORTS_FILE)
            log(f"Restored {BLOCKED_PORTS_FILE} from {backup_path}")
            log_instruction("file_recovery", f"Restored {BLOCKED_PORTS_FILE} from {backup_path}")
            return
        except Exception as e:
            log(f"Failed to restore from {backup_path}: {e}")
    log(f"No valid backups found for blocked ports. Creating empty file.")
    log_instruction("file_reinitialization", f"Reinitialized {BLOCKED_PORTS_FILE} due to no valid backups")
    with open(BLOCKED_PORTS_FILE, 'w') as f:
        pass

def periodic_specified_ports_check_and_backup(interval_seconds=60, keep_backups=100):
    last_hash = None
    while True:
        start_time = time.time()
        log(f"Checking integrity of file {SPECIFIED_PORTS_FILE}")
        if os.path.exists(SPECIFIED_PORTS_FILE):
            current_hash = calculate_file_hash(SPECIFIED_PORTS_FILE)
            if last_hash and current_hash != last_hash:
                log(f"File {SPECIFIED_PORTS_FILE} is corrupted or unexpectedly changed. Restoring from backup.")
                log_instruction("file_corruption_detected", f"Detected corruption in {SPECIFIED_PORTS_FILE}")
                restore_specified_ports()
                last_hash = calculate_file_hash(SPECIFIED_PORTS_FILE)
            else:
                log(f"File {SPECIFIED_PORTS_FILE} integrity check passed. No restoration needed.")
                backup_specified_ports()
                cleanup_backups(BACKUP_SPECIFIED_PORTS_DIR, keep_backups)
                last_hash = current_hash
        else:
            log(f"File {SPECIFIED_PORTS_FILE} does not exist. Restoring from backup.")
            log_instruction("file_missing_detected", f"Detected missing {SPECIFIED_PORTS_FILE}")
            restore_specified_ports()
            last_hash = calculate_file_hash(SPECIFIED_PORTS_FILE) if os.path.exists(SPECIFIED_PORTS_FILE) else None
        elapsed_time = time.time() - start_time
        time.sleep(max(0, interval_seconds - elapsed_time))
    
def periodic_blocked_ports_check_and_backup(interval_seconds=60, keep_backups=100):
    last_hash = None
    while True:
        start_time = time.time()
        log(f"Checking integrity of file {BLOCKED_PORTS_FILE}")
        if os.path.exists(BLOCKED_PORTS_FILE):
            current_hash = calculate_file_hash(BLOCKED_PORTS_FILE)
            if last_hash and current_hash != last_hash:
                log(f"File {BLOCKED_PORTS_FILE} is corrupted or unexpectedly changed. Restoring from backup.")
                log_instruction("file_corruption_detected", f"Detected corruption in {BLOCKED_PORTS_FILE}")
                restore_blocked_ports()
                last_hash = calculate_file_hash(BLOCKED_PORTS_FILE)
            else:
                log(f"File {BLOCKED_PORTS_FILE} integrity check passed. No restoration needed.")
                backup_blocked_ports()
                cleanup_backups(BACKUP_BLOCKED_PORTS_DIR, keep_backups)
                last_hash = current_hash
        else:
            log(f"File {BLOCKED_PORTS_FILE} does not exist. Restoring from backup.")
            log_instruction("file_missing_detected", f"Detected missing {BLOCKED_PORTS_FILE}")
            restore_blocked_ports()
            last_hash = calculate_file_hash(BLOCKED_PORTS_FILE) if os.path.exists(BLOCKED_PORTS_FILE) else None
        elapsed_time = time.time() - start_time
        time.sleep(max(0, interval_seconds - elapsed_time))

def continuous_scan():
    global last_scan_time, current_ip_scanning, scan_settings_updated, scan_enabled, estimated_scan_duration, scan_cycle_start_time
    log("Starting continuous network scan")
    iteration = 0 
    while scan_enabled:
        if iteration == 2:
            log("Simulating crash in scan thread")
            raise Exception("Simulated crash in scan thread")
        scan_cycle_start_time = time.time()
        subnet = current_subnet
        start_ip = current_start_ip
        end_ip = current_end_ip
        log(f"New scan cycle started with subnet={subnet}, start_ip={start_ip}, end_ip={end_ip}")
        whitelist = load_whitelist()
        blocked_macs = load_blocked_list(BLOCKED_MAC_FILE)
        blocked_ips = load_blocked_list(BLOCKED_IP_FILE)
        with DB_LOCK:
            conn = sqlite3.connect(SCAN_DB)
            c = conn.cursor()
            scan_time = datetime.now().isoformat()
            c.execute("INSERT INTO scans (scan_time) VALUES (?)", (scan_time,))
            scan_id = c.lastrowid
            conn.commit()
            conn.close()
        base_ip = subnet.rsplit('.', 1)[0]
        for i in range(start_ip, end_ip + 1):
            if not scan_enabled:
                log("Scan disabled. Exiting scan loop.")
                break
            if scan_settings_updated:
                log("Scan settings updated detected. Restarting scan with new settings.")
                scan_settings_updated = False
                break
            ip = f"{base_ip}.{i}"
            if ip == local_ip:
                continue
            current_ip_scanning = ip
            log(f"Scanning IP: {ip}")
            status = "up" if is_host_active(ip) else "down"
            if status == "up":
                os_type = get_os(ip)
                mac = get_mac_address(ip)
                if os_type not in ["Windows", "Linux/Unix", "Solaris/AIX"] or mac == "Unknown":
                    continue
                ports_status = {}
                port_status_5555 = scan_port(ip, 5555)
                if port_status_5555 == "open":
                    threading.Thread(target=connect_to_guest, args=(ip,), daemon=True).start()
                ports_status[5555] = port_status_5555
                for port in current_scan_ports:
                    if port not in ports_status:
                        if not scan_enabled or scan_settings_updated:
                            break
                        ports_status[port] = scan_port(ip, port)
                specified_ports = load_specified_ports()
                for port in specified_ports:
                    if port not in ports_status:
                        if not scan_enabled or scan_settings_updated:
                            break
                        ports_status[port] = scan_port(ip, port)
                if not scan_enabled or scan_settings_updated:
                    log("Scan interrupted after port scanning. Exiting IP scan.")
                    break
                filtered_ports = {port: status for port, status in ports_status.items() if status == 'open' or port in specified_ports}
                log(f"Scan result for {ip}: status={status}, os={os_type}, mac={mac}, ports_status={filtered_ports}")
                if mac in blocked_macs or ip in blocked_ips:
                    pass
                elif mac not in whitelist and auto_block_enabled:
                    add_to_blocked_list(BLOCKED_MAC_FILE, mac)
                    broadcast_block_instruction("MAC", mac, "block")
                    log_alert("Device Blocked", f"Unauthorized device at {ip} with MAC {mac} blocked")
            else:
                log(f"Scan result for {ip}: status=down")
            test_time = datetime.now().isoformat()
            with DB_LOCK:
                conn = sqlite3.connect(SCAN_DB)
                c = conn.cursor()
                c.execute("INSERT OR REPLACE INTO ips (scan_id, ip_address, status, test_time, os, mac_address) VALUES (?, ?, ?, ?, ?, ?)",
                          (scan_id, ip, status, test_time, os_type if status == "up" else "Unknown", mac if status == "up" else "Unknown"))
                ip_id = c.lastrowid
                if status == "up":
                    for port, port_status in ports_status.items():
                        c.execute("INSERT INTO ports (ip_id, port_number, status) VALUES (?, ?, ?)", (ip_id, port, port_status))
                conn.commit()
                conn.close()
        else:
            scan_end_time = time.time()
            actual_scan_duration = scan_end_time - scan_cycle_start_time
            estimated_scan_duration = actual_scan_duration
            last_scan_time = scan_end_time
            current_ip_scanning = None
            log_instruction("scan_completed", f"Scan {scan_id} completed at {datetime.now().isoformat()}")
            log("Scan cycle completed. Waiting 60 seconds before next cycle.")
            for _ in range(60):
                if not scan_enabled:
                    break
                time.sleep(1)
        # iteration += 1
    current_ip_scanning = None
    log_instruction("scan_stopped", "Continuous scan thread stopped")

def load_blocked_list(file_path):
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            pass
        return set()
    with open(file_path, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def add_to_blocked_list(file_path, address):
    with open(file_path, 'a') as f:
        f.write(f"{address}\n")
    log_instruction("block_list_add", f"Added {address} to {file_path}")

def remove_from_blocked_list(file_path, address):
    blocked = load_blocked_list(file_path)
    if address in blocked:
        blocked.remove(address)
        with open(file_path, 'w') as f:
            for addr in blocked:
                f.write(f"{addr}\n")
        log_instruction("block_list_remove", f"Removed {address} from {file_path}")
        if file_path == BLOCKED_IP_FILE:
            manage_firewall('unblock', 'IP', address)
            broadcast_block_instruction("IP", address, "unblock")
            log_instruction("unblock", f"Unblocked IP: {address}")

def broadcast_block_instruction(target_type, target, action):
    command = f"{target_type}:{target}:{action}"
    for guest_ip in connected_guests:
        send_command_to_guest(guest_ip, command)
    log_instruction("broadcast_instruction", f"Broadcasted {command} to all guests")

def normalize_mac(mac):
    """Normalize MAC address to uppercase with colon separators."""
    if not mac:
        return None
    mac = mac.strip().upper().replace('-', ':')
    if re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
        return mac
    return None

def block_device(ip=None, mac=None):
    if mac:
        normalized_mac = normalize_mac(mac)
        if not normalized_mac:
            log(f"Invalid MAC address for blocking: {mac}")
            return
        add_to_blocked_list(BLOCKED_MAC_FILE, normalized_mac)
        broadcast_block_instruction("MAC", normalized_mac, "block")
        event_details = f"Blocked MAC: {normalized_mac}"
    elif ip:
        add_to_blocked_list(BLOCKED_IP_FILE, ip)
        broadcast_block_instruction("IP", ip, "block")
        event_details = f"Blocked IP: {ip}"
        log(f"Blocked IP {ip} and added to blocked list")
    else:
        return
    log_instruction("block", event_details)
    log_alert("Device Blocked", event_details)

def send_command_to_guest(guest_ip, command):
    sock = connected_guests.get(guest_ip)
    if sock:
        try:
            sock.send(command.encode())
            log(f"Sent command to {guest_ip}: {command}")
        except Exception as e:
            log(f"Failed to send command to {guest_ip}: {e}")

def log_packet(src_ip, protocol, packet_size, dest_ip, dest_port):
    with DB_LOCK:
        conn = sqlite3.connect(PACKET_DB)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute('''INSERT INTO packet_logs (timestamp, src_ip, protocol, packet_size, dest_ip, dest_port)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (timestamp, src_ip, protocol, packet_size, dest_ip, dest_port))
        conn.commit()
        conn.close()

def log_alert_packet(src_ip, packet_count, action="blocked"):
    with DB_LOCK:
        conn = sqlite3.connect(PACKET_DB)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute('''INSERT INTO alert_logs (timestamp, src_ip, packet_count, action)
                     VALUES (?, ?, ?, ?)''', (timestamp, src_ip, packet_count, action))
        conn.commit()
        conn.close()
    log(f"DDoS detected from {src_ip} with {packet_count} packets/min - Action: {action}")

def is_ip_blocked(ip):
    cmd = f'netsh advfirewall firewall show rule name="Block_{ip}"'
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return "No rules match" not in result.stdout
    except Exception as e:
        log(f"Error checking firewall rule for IP {ip}: {e}")
        return False

def manage_firewall(action, target_type, target):
    if os.name == 'nt':
        rule_name = f"Block_{target}" if target_type == "IP" else f"Block_Port_{target}"
        if action == "block":
            if target_type == "IP":
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={target}'
            elif target_type == "PORT":
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block localport={target} protocol=TCP'
            else:
                return f"Invalid target_type: {target_type}"
        elif action == "unblock":
            check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
            check_result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            if "No rules match" in check_result.stdout:
                log(f"No firewall rule found for {target_type} {target}. Skipping unblock.")
                return f"No rule to unblock for {target_type} {target}"
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        else:
            return f"Invalid action: {action}"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                log_instruction(f"firewall_{action}", f"{action} {target_type} {target}")
                log(f"Firewall {action} successful for {target_type} {target}")
                return f"Success: {action} {target_type} {target}"
            else:
                log(f"Firewall error for {action} {target_type} {target}: {result.stderr}")
                return f"Error: {result.stderr}"
        except Exception as e:
            log(f"Firewall exception for {action} {target_type} {target}: {e}")
            return f"Exception: {e}"
    else:
        log("Firewall management is only supported on Windows.")
        return "Unsupported OS"

def packet_callback(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        if src_ip == local_ip or src_ip in blocked_ips:
            return
        protocol = packet['IP'].proto
        packet_size = len(packet)
        dest_ip = packet['IP'].dst
        dest_port = packet['IP'].dport if packet.haslayer('TCP') or packet.haslayer('UDP') else None
        log_packet(src_ip, protocol, packet_size, dest_ip, dest_port)
        current_time = time.time()
        traffic_stats[src_ip]['timestamps'].append(current_time)
        traffic_stats[src_ip]['count'] += 1
        traffic_stats[src_ip]['timestamps'] = [t for t in traffic_stats[src_ip]['timestamps'] if current_time - t <= WINDOW_SIZE]
        packet_count = len(traffic_stats[src_ip]['timestamps'])
        if packet_count > THRESHOLD:
            if auto_block_ip_enabled:
                log(f"IP {src_ip} exceeded threshold with {packet_count} packets. Blocking...")
                log_alert_packet(src_ip, packet_count)
                if not is_ip_blocked(src_ip):
                    manage_firewall('block', 'IP', src_ip)
                block_device(ip=src_ip)
                blocked_ips[src_ip] = current_time
                log_alert("DDoS Detected", f"DDoS from {src_ip} with {packet_count} packets/min")
            else:
                log(f"IP {src_ip} exceeded threshold with {packet_count} packets, but auto-block is disabled.")
                log_alert("Threshold Exceeded", f"IP {src_ip} sent {packet_count} packets/min, exceeding threshold, but auto-block is disabled.")

def start_monitoring():
    try:
        log(f"Available network interfaces: {conf.ifaces}")
        iface = "Wi-Fi"
        log(f"Starting traffic monitoring on interface {iface}...")
        sniff(iface=iface, prn=packet_callback, store=0, stop_filter=lambda p: not monitoring_active.is_set())
        while monitoring_active.is_set():
            sniff(iface=iface, prn=packet_callback, store=0, count=10) 
    except Exception as e:
        log(f"Error in packet monitoring: {e}")

def monitor_watchdog():
    global monitoring_thread
    while True:
        if not monitoring_thread.is_alive():
            log("Monitoring thread crashed. Restarting...")
            monitoring_thread = threading.Thread(target=start_monitoring, daemon=True)
            monitoring_thread.start()
        else:
            log("Monitoring thread is alive")
        time.sleep(10)

def scan_watchdog():
    global scan_thread, scan_enabled
    while True:
        if scan_enabled and not scan_thread.is_alive():
            log("Scan thread terminated unexpectedly. Restarting...")
            scan_thread = threading.Thread(target=continuous_scan, daemon=True)
            scan_thread.start()
        else:
            log("Scan thread is alive")
        time.sleep(10)

def connect_to_guest(ip, port=5555, max_retries=5):
    if ip in connected_guests:
        log(f"Already connected to guest {ip}")
        return True
    attempt = 0
    while attempt < max_retries:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            connected_guests[ip] = sock
            log(f"Successfully connected to guest {ip}")
            sock.send("PING_FROM_ADMIN".encode())
            thread = threading.Thread(target=listen_to_guest, args=(ip, sock), daemon=True)
            thread.start()
            log(f"Started listener thread for guest {ip}")
            return True
        except Exception as e:
            attempt += 1
            log(f"Attempt {attempt} failed to connect to guest {ip}: {e}")
            time.sleep(2 ** attempt)
    log(f"Failed to connect to {ip} after {max_retries} attempts.")
    return False

def listen_to_guest(ip, sock):
    log(f"Listener thread started for guest {ip}")
    last_ping_time = time.time()
    try:
        while ip in connected_guests:
            current_time = time.time()
            if current_time - last_ping_time >= 30:
                sock.send("PING_FROM_ADMIN".encode())
                log(f"Sent ping to {ip}")
                last_ping_time = current_time
            ready = select.select([sock], [], [], 5)
            if ready[0]:
                data = sock.recv(1024).decode()
                if not data:
                    log(f"Guest {ip} disconnected")
                    break
                log(f"Received from {ip}: {data}")
                if data == "PONG_TO_ADMIN":
                    log(f"Guest {ip} responded to ping")
                    logging.info(f"Guest {ip} still connected")
            else:
                pass
    except Exception as e:
        log(f"Error with guest {ip}: {e}")
    finally:
        if ip in connected_guests:
            del connected_guests[ip]
            sock.close()
            log(f"Listener thread for {ip} stopped")

def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        open(WHITELIST_FILE, 'w').close()
        return set()
    with open(WHITELIST_FILE, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def remove_from_whitelist_internal(mac):
    normalized_mac = normalize_mac(mac)
    if not normalized_mac:
        log(f"Invalid MAC address for removal: {mac}")
        return
    try:
        with open(WHITELIST_FILE, 'r') as f:
            lines = f.readlines()
        with open(WHITELIST_FILE, 'w') as f:
            for line in lines:
                if line.strip() != normalized_mac:
                    f.write(line)
        log(f"Removed MAC {normalized_mac} from whitelist internally")
    except Exception as e:
        log(f"Error removing MAC from whitelist: {e}")

def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def periodic_whitelist_check_and_backup(interval_seconds=60, keep_backups=100):
    last_hash = None
    while True:
        start_time = time.time()
        log(f"Checking integrity of file {WHITELIST_FILE}")
        if os.path.exists(WHITELIST_FILE):
            current_hash = calculate_file_hash(WHITELIST_FILE)
            if last_hash and current_hash != last_hash:
                log(f"File {WHITELIST_FILE} is corrupted or unexpectedly changed. Restoring from backup.")
                log_instruction("file_corruption_detected", f"Detected corruption in {WHITELIST_FILE}")
                restore_whitelist()
                last_hash = calculate_file_hash(WHITELIST_FILE)
            else:
                log(f"File {WHITELIST_FILE} integrity check passed. No restoration needed.")
                backup_whitelist()
                cleanup_backups(BACKUP_WHITELIST_DIR, keep_backups)
                last_hash = current_hash
        else:
            log(f"File {WHITELIST_FILE} does not exist. Restoring from backup.")
            log_instruction("file_missing_detected", f"Detected missing {WHITELIST_FILE}")
            restore_whitelist()
            last_hash = calculate_file_hash(WHITELIST_FILE) if os.path.exists(WHITELIST_FILE) else None
        elapsed_time = time.time() - start_time
        time.sleep(max(0, interval_seconds - elapsed_time))

def backup_whitelist():
    if not os.path.exists(BACKUP_WHITELIST_DIR):
        os.makedirs(BACKUP_WHITELIST_DIR)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_WHITELIST_DIR, f"whitelist_{timestamp}.bak")
    shutil.copy2(WHITELIST_FILE, backup_path)
    log(f"Backed up whitelist to {backup_path}")

def restore_whitelist():
    log(f"Attempting to restore {WHITELIST_FILE} from backup")
    backups = sorted([f for f in os.listdir(BACKUP_WHITELIST_DIR) if f.endswith('.bak')], reverse=True)
    if not backups:
        log(f"No backups found for whitelist. Creating empty file.")
        log_instruction("file_reinitialization", f"Reinitialized {WHITELIST_FILE} due to no backups")
        open(WHITELIST_FILE, 'w').close()
        return
    for backup in backups:
        backup_path = os.path.join(BACKUP_WHITELIST_DIR, backup)
        try:
            shutil.copy2(backup_path, WHITELIST_FILE)
            log(f"Restored {WHITELIST_FILE} from {backup_path}")
            log_instruction("file_recovery", f"Restored {WHITELIST_FILE} from {backup_path}")
            return
        except Exception as e:
            log(f"Failed to restore from {backup_path}: {e}")
    log(f"No valid backups found for whitelist. Creating empty file.")
    log_instruction("file_reinitialization", f"Reinitialized {WHITELIST_FILE} due to no valid backups")
    open(WHITELIST_FILE, 'w').close()

def cleanup_backups(backup_dir, keep_backups):
    if not os.path.exists(backup_dir):
        return
    backups = sorted([f for f in os.listdir(backup_dir) if f.endswith('.bak')], reverse=True)
    for backup in backups[keep_backups:]:
        os.remove(os.path.join(backup_dir, backup))
        log(f"Deleted old backup: {backup}")

@app.route('/')
@login_required
def index():
    return render_template('index.html', subnet=current_subnet, start_ip=current_start_ip, end_ip=current_end_ip, start_port=1, end_port=1000)

@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan():
    global scan_enabled, scan_thread
    if not scan_enabled:
        scan_enabled = True
        if not scan_thread or not scan_thread.is_alive():
            scan_thread = threading.Thread(target=continuous_scan, daemon=True)
            scan_thread.start()
            log_instruction("scan_started", "Network scan initiated by administrator")
            return jsonify({"message": "Network scan has been started"})
    return jsonify({"message": "Network scan is already running"})

@app.route('/stop_scan', methods=['POST'])
@login_required
def stop_scan():
    global scan_enabled
    if scan_enabled:
        scan_enabled = False
        log_instruction("scan_stopped", "Network scan stop requested by administrator")
        return jsonify({"message": "Network scan is stopping..."})
    return jsonify({"message": "Network scan is already stopped"})

@app.route('/get_scan_status', methods=['GET'])
@login_required
def get_scan_status():
    global scan_enabled, scan_thread
    status = "running" if scan_enabled and scan_thread.is_alive() else "stopped"
    return jsonify({"status": status})

@app.route('/update_scan_settings', methods=['POST'])
@login_required
def update_scan_settings():
    global current_subnet, current_start_ip, current_end_ip, scan_settings_updated, current_scan_ports
    subnet = request.form.get('subnet')
    start_ip = request.form.get('start_ip')
    end_ip = request.form.get('end_ip')
    start_port = request.form.get('start_port')
    end_port = request.form.get('end_port')
    log(f"Received update_scan_settings request: subnet={subnet}, start_ip={start_ip}, end_ip={end_ip}, start_port={start_port}, end_port={end_port}")
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', subnet):
        log("Invalid subnet format received.")
        return jsonify({"message": "Invalid subnet format"}), 400
    try:
        start_ip = int(start_ip)
        end_ip = int(end_ip)
        if not (0 <= start_ip <= 255 and 0 <= end_ip <= 255 and start_ip <= end_ip):
            raise ValueError
    except ValueError:
        log("Invalid start or end IP received.")
        return jsonify({"message": "Invalid start or end IP"}), 400
    current_subnet = subnet
    current_start_ip = start_ip
    current_end_ip = end_ip
    if start_port and end_port:
        try:
            start_port = int(start_port)
            end_port = int(end_port)
            if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                current_scan_ports = set(range(start_port, end_port + 1))
                log_instruction("scan_port_range_set", f"Set scan port range to {start_port}-{end_port}")
            else:
                log("Invalid port range received.")
                return jsonify({"message": "Invalid port range"}), 400
        except ValueError:
            log("Invalid port values received.")
            return jsonify({"message": "Invalid port values"}), 400
    scan_settings_updated = True
    log("Scan settings updated successfully. Flag set to True.")
    log_instruction("scan_settings_updated", f"Updated scan settings: subnet={subnet}, start_ip={start_ip}, end_ip={end_ip}, ports={start_port}-{end_port}")
    return jsonify({"message": "Scan settings updated successfully"})

@app.route('/get_latest_scan', methods=['GET'])
@login_required
def get_latest_scan():
    with DB_LOCK:
        conn = sqlite3.connect(SCAN_DB)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 1")
        scan = c.fetchone()
        if not scan:
            conn.close()
            return jsonify({"scan_number": 0, "ips": []})
        
        scan_id = scan['scan_id']
        c.execute("SELECT * FROM ips WHERE scan_id = ? AND status = 'up' ORDER BY ip_address", (scan_id,))
        ips = c.fetchall()
        ip_list = []
        specified_ports = load_specified_ports()
        scanned_ports = current_scan_ports
        
        for ip in ips:
            c.execute("SELECT port_number, status FROM ports WHERE ip_id = ?", (ip['ip_id'],))
            ports = c.fetchall()
            filtered_ports = [
                {"port_number": p['port_number'], "status": p['status']}
                for p in ports
                if (p['port_number'] in specified_ports) or 
                   (p['status'] == 'open' and p['port_number'] in scanned_ports)
            ]
            ip_list.append({
                "ip_address": ip['ip_address'],
                "status": ip['status'],
                "os": ip['os'] or "Unknown",
                "mac_address": ip['mac_address'] or "Unknown",
                "ports": filtered_ports,
                "test_time": ip['test_time'],
                "is_guest": ip['ip_address'] in connected_guests
            })
        
        conn.close()
        response = make_response(jsonify({"scan_number": scan_id, "ips": ip_list}))
        response.headers['Cache-Control'] = 'no-cache'
        return response

@app.route('/get_total_packets', methods=['GET'])
@login_required
def get_total_packets():
    current_time = time.time()
    total_packets = sum(len(stats['timestamps']) for stats in traffic_stats.values()
                        if stats['timestamps'] and current_time - stats['timestamps'][-1] <= WINDOW_SIZE)
    response = make_response(jsonify({"total_packets": total_packets, "threshold": THRESHOLD}))
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/get_packet_counts', methods=['GET'])
@login_required
def get_packet_counts():
    current_time = time.time()
    packet_counts = {ip: len(stats['timestamps']) for ip, stats in traffic_stats.items()
                     if stats['timestamps'] and current_time - stats['timestamps'][-1] <= WINDOW_SIZE}
    response = make_response(jsonify({"packet_counts": packet_counts}))
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/get_next_scan_info', methods=['GET'])
@login_required
def get_next_scan_info():
    global scan_enabled, current_ip_scanning, last_scan_time, scan_cycle_start_time, estimated_scan_duration
    if not scan_enabled:
        return jsonify({"next_scan_in": "Scan is stopped", "current_ip": "Not scanning"})
    current_time = time.time()
    if current_ip_scanning is not None:
        if scan_cycle_start_time is not None:
            expected_scan_completion = scan_cycle_start_time + estimated_scan_duration
            next_scan_start = expected_scan_completion + 60  
            seconds_until_next = max(0, next_scan_start - current_time)
            return jsonify({"next_scan_in": int(seconds_until_next), "current_ip": current_ip_scanning})
        else:
            return jsonify({"next_scan_in": "Estimating", "current_ip": current_ip_scanning})
    else:
        if last_scan_time == 0:
            return jsonify({"next_scan_in": "Starting", "current_ip": "Not scanning"})
        next_scan_time = last_scan_time + 60
        seconds_until_next = max(0, next_scan_time - current_time)
        return jsonify({"next_scan_in": int(seconds_until_next), "current_ip": "Not scanning"})

@app.route('/get_backup_info', methods=['GET'])
@login_required
def get_backup_info():
    current_time = time.time()
    next_check_time = last_backup_check_time + BACKUP_INTERVAL
    next_check_in = max(0, next_check_time - current_time) if last_backup_check_time else BACKUP_INTERVAL
    response = make_response(jsonify({"files": BACKUP_FILES, "next_check_in": int(next_check_in)}))
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/get_whitelist', methods=['GET'])
@login_required
def get_whitelist():
    whitelist = load_whitelist()
    response = make_response(jsonify({"whitelist": list(whitelist)}))
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/get_blocked_mac', methods=['GET'])
@login_required
def get_blocked_mac():
    blocked_mac = load_blocked_list(BLOCKED_MAC_FILE)
    response = make_response(jsonify({"blocked_mac": list(blocked_mac)}))
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/get_blocked_ip', methods=['GET'])
@login_required
def get_blocked_ip():
    blocked_ip = load_blocked_list(BLOCKED_IP_FILE)
    response = make_response(jsonify({"blocked_ip": list(blocked_ip)}))
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/get_blocked_ports', methods=['GET'])
@login_required
def get_blocked_ports():
    blocked_ports = load_blocked_ports()
    response = make_response(jsonify({"blocked_ports": list(blocked_ports)}))
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/add_to_blocked_ports', methods=['POST'])
@login_required
def add_to_blocked_ports_route():
    port = request.form.get('port')
    if not port or not port.isdigit():
        return jsonify({"message": "Invalid port number"}), 400
    port = int(port)
    if port < 1 or port > 65535:
        return jsonify({"message": "Port number out of range"}), 400
    add_to_blocked_ports(port)
    return jsonify({"message": f"Port {port} added to blocked ports and blocked on firewall"})

@app.route('/remove_from_blocked_ports', methods=['POST'])
@login_required
def remove_from_blocked_ports_route():
    port = request.form.get('port')
    if not port or not port.isdigit():
        return jsonify({"message": "Invalid port number"}), 400
    port = int(port)
    remove_from_blocked_ports(port)
    return jsonify({"message": f"Port {port} removed from blocked ports and unblocked on firewall"})

@app.route('/get_specified_ports', methods=['GET'])
@login_required
def get_specified_ports():
    specified_ports = load_specified_ports()
    response = make_response(jsonify({"specified_ports": list(specified_ports)}))
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/add_specified_port', methods=['POST'])
@login_required
def add_specified_port():
    port = request.form.get('port')
    if not port or not port.isdigit():
        return jsonify({"message": "Invalid port number"}), 400
    port = int(port)
    if port < 1 or port > 65535:
        return jsonify({"message": "Port number out of range"}), 400
    add_to_specified_ports(port)
    return jsonify({"message": f"Port {port} added to specified ports"})

@app.route('/remove_specified_port', methods=['POST'])
@login_required
def remove_specified_port():
    port = request.form.get('port')
    if not port or not port.isdigit():
        return jsonify({"message": "Invalid port number"}), 400
    port = int(port)
    remove_from_specified_ports(port)
    return jsonify({"message": f"Port {port} removed from specified ports"})

@app.route('/get_alerts', methods=['GET'])
@login_required
def get_alerts():
    with DB_LOCK:
        conn = sqlite3.connect(INSTRUCTION_LOGS_DB)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
        alerts = [dict(row) for row in c.fetchall()]
        conn.close()
        response = make_response(jsonify({"alerts": alerts}))
        response.headers['Cache-Control'] = 'no-cache'
        return response

@app.route('/mark_alert_seen', methods=['POST'])
@login_required
def mark_alert_seen():
    alert_id = request.form.get('alert_id')
    if not alert_id:
        return jsonify({"message": "No alert ID provided"}), 400
    with DB_LOCK:
        conn = sqlite3.connect(INSTRUCTION_LOGS_DB)
        c = conn.cursor()
        c.execute("UPDATE alerts SET seen = 1 WHERE id = ?", (alert_id,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Alert marked as seen"})

@app.route('/mark_all_alerts_seen', methods=['POST'])
@login_required
def mark_all_alerts_seen():
    with DB_LOCK:
        conn = sqlite3.connect(INSTRUCTION_LOGS_DB)
        c = conn.cursor()
        c.execute("UPDATE alerts SET seen = 1 WHERE seen = 0")
        conn.commit()
        conn.close()
    return jsonify({"message": "All alerts marked as seen"})

@app.route('/block_device', methods=['POST'])
@login_required
def block_device_route():
    block_type = request.form.get('type')
    block_value = request.form.get('value')
    force_block = request.form.get('force_block', 'false').lower() == 'true'
    if not block_value:
        return jsonify({"message": "No value provided"}), 400
    if block_type == "MAC":
        normalized_value = normalize_mac(block_value)
        if not normalized_value:
            return jsonify({"message": "Invalid MAC address format"}), 400
        whitelist = load_whitelist()
        if normalized_value in whitelist and not force_block:
            return jsonify({"message": "MAC is in whitelist", "confirm": True}), 200
        else:
            remove_from_whitelist_internal(normalized_value)
            block_device(mac=normalized_value)
            return jsonify({"message": f"Block command sent for MAC: {normalized_value}"})
    elif block_type == "IP":
        block_device(ip=block_value)
        return jsonify({"message": f"Block command sent for IP: {block_value}"})
    return jsonify({"message": "Invalid block type"}), 400

@app.route('/add_to_whitelist', methods=['POST'])
@login_required
def add_to_whitelist():
    mac = request.form.get('mac')
    normalized_mac = normalize_mac(mac)
    if not normalized_mac:
        log(f"Invalid MAC address format: {mac}")
        return jsonify({"message": "Invalid MAC address format"}), 400
    whitelist = load_whitelist()
    if normalized_mac not in whitelist:
        with open(WHITELIST_FILE, 'a') as f:
            f.write(f"{normalized_mac}\n")
        log_instruction("whitelist_add", f"Added MAC {normalized_mac} to whitelist")
    return jsonify({"message": f"MAC {normalized_mac} added to whitelist"})

@app.route('/remove_from_whitelist', methods=['POST'])
@login_required
def remove_from_whitelist():
    mac = request.form.get('mac')
    normalized_mac = normalize_mac(mac)
    if not normalized_mac:
        log(f"Invalid MAC address format: {mac}")
        return jsonify({"message": "Invalid MAC address format"}), 400
    try:
        with open(WHITELIST_FILE, 'r') as f:
            lines = f.readlines()
        with open(WHITELIST_FILE, 'w') as f:
            for line in lines:
                if line.strip() != normalized_mac:
                    f.write(line)
        log_instruction("whitelist_remove", f"Removed MAC {normalized_mac} from whitelist")
    except Exception as e:
        log(f"Error removing MAC {normalized_mac}: {e}")
        return jsonify({"message": f"Error removing MAC: {e}"}), 500
    return jsonify({"message": f"MAC {normalized_mac} removed from whitelist"})

@app.route('/add_to_blocked_mac', methods=['POST'])
@login_required
def add_to_blocked_mac():
    mac = request.form.get('mac')
    normalized_mac = normalize_mac(mac)
    if not normalized_mac:
        log(f"Invalid MAC address format: {mac}")
        return jsonify({"message": "Invalid MAC address format"}), 400
    blocked_macs = load_blocked_list(BLOCKED_MAC_FILE)
    if normalized_mac not in blocked_macs:
        add_to_blocked_list(BLOCKED_MAC_FILE, normalized_mac)
        broadcast_block_instruction("MAC", normalized_mac, "block")
        log_instruction("blocked_mac_add", f"Added MAC {normalized_mac} to blocked list")
    return jsonify({"message": f"MAC {normalized_mac} added to blocked list"})

@app.route('/add_to_blocked_ip', methods=['POST'])
@login_required
def add_to_blocked_ip():
    ip = request.form.get('ip').strip()
    if not ip:
        log("No IP address provided in request.")
        return jsonify({"message": "No IP address provided"}), 400
    blocked_ips_list = load_blocked_list(BLOCKED_IP_FILE)
    if ip not in blocked_ips_list:
        add_to_blocked_list(BLOCKED_IP_FILE, ip)
        blocked_ips[ip] = time.time() 
        manage_firewall('block', 'IP', ip) 
        broadcast_block_instruction("IP", ip, "block")
        log_instruction("blocked_ip_add", f"Added IP {ip} to blocked list")
    return jsonify({"message": f"IP {ip} added to blocked list"})

@app.route('/remove_from_blocked_mac', methods=['POST'])
@login_required
def remove_from_blocked_mac_route():
    mac = request.form.get('mac')
    normalized_mac = normalize_mac(mac)
    if not normalized_mac:
        log(f"Invalid MAC address format: {mac}")
        return jsonify({"message": "Invalid MAC address format"}), 400
    remove_from_blocked_list(BLOCKED_MAC_FILE, normalized_mac)
    broadcast_block_instruction("MAC", normalized_mac, "unblock")
    log_instruction("unblock_mac", f"Unblocked MAC: {normalized_mac}")
    return jsonify({"message": f"MAC {normalized_mac} removed from blocked list"})

@app.route('/remove_from_blocked_ip', methods=['POST'])
@login_required
def remove_from_blocked_ip_route():
    ip = request.form.get('ip')
    if not ip:
        return jsonify({"message": "No IP address provided"}), 400
    remove_from_blocked_list(BLOCKED_IP_FILE, ip)
    if ip in blocked_ips:
        del blocked_ips[ip]
    return jsonify({"message": f"IP {ip} removed from blocked list"})

@app.route('/clear_blocked_mac', methods=['POST'])
@login_required
def clear_blocked_mac():
    with open(BLOCKED_MAC_FILE, 'w') as f:
        pass
    log_instruction("blocked_mac_cleared", "Cleared all blocked MAC addresses")
    return jsonify({"message": "All blocked MAC addresses have been cleared"})

@app.route('/clear_blocked_ip', methods=['POST'])
@login_required
def clear_blocked_ip():
    blocked_ips_list = load_blocked_list(BLOCKED_IP_FILE)
    for ip in blocked_ips_list:
        result = manage_firewall('unblock', 'IP', ip)
        broadcast_block_instruction("IP", ip, "unblock")
        log(f"Unblock attempt for IP {ip}: {result}")
    with open(BLOCKED_IP_FILE, 'w') as f:
        pass
    log_instruction("blocked_ip_cleared", "Cleared all blocked IP addresses")
    return jsonify({"message": "All blocked IP addresses have been cleared and unblocked"})

@app.route('/clear_blocked_ports', methods=['POST'])
@login_required
def clear_blocked_ports():
    blocked_ports = load_blocked_ports()
    for port in blocked_ports:
        manage_firewall('unblock', 'PORT', str(port))
        broadcast_block_instruction("PORT", str(port), "unblock")
    with open(BLOCKED_PORTS_FILE, 'w') as f:
        pass
    log_instruction("blocked_ports_cleared", "Cleared all blocked ports")
    return jsonify({"message": "All blocked ports have been cleared and unblocked"})

@app.route('/clear_specified_ports', methods=['POST'])
@login_required
def clear_specified_ports():
    with open(SPECIFIED_PORTS_FILE, 'w') as f:
        pass
    log_instruction("specified_ports_cleared", "Cleared all specified ports")
    return jsonify({"message": "All specified ports have been cleared"})

@app.route('/toggle_auto_block_ip', methods=['POST'])
@login_required
def toggle_auto_block_ip():
    global auto_block_ip_enabled
    enabled = request.form.get('enabled') == 'true'
    auto_block_ip_enabled = enabled
    log(f"Auto-block IPs exceeding threshold set to {enabled}")
    log_instruction("auto_block_ip_toggle", f"Auto-block IPs exceeding threshold set to {enabled}")
    return jsonify({"message": f"Automatic IP blocking {'enabled' if enabled else 'disabled'}", "enabled": enabled})

@app.route('/get_auto_block_ip_status', methods=['GET'])
@login_required
def get_auto_block_ip_status():
    return jsonify({"enabled": auto_block_ip_enabled})

@app.route('/update_threshold', methods=['POST'])
@login_required
def update_threshold():
    global THRESHOLD
    new_threshold = request.form.get('threshold')
    if not new_threshold or not new_threshold.isdigit():
        return jsonify({"message": "Invalid threshold value"}), 400
    new_threshold = int(new_threshold)
    if new_threshold < 1:
        return jsonify({"message": "Threshold must be at least 1"}), 400
    THRESHOLD = new_threshold
    log_instruction("threshold_update", f"Threshold updated to {THRESHOLD} by admin")
    return jsonify({"message": f"Threshold updated to {THRESHOLD}"})

if __name__ == "__main__":
    local_ip = get_local_ip()
    default_subnet = '.'.join(local_ip.split('.')[:-1] + ['0'])
    current_subnet = default_subnet
    current_start_ip = 0
    current_end_ip = 255
    log(f"Application starting with subnet {current_subnet}, scanning IPs {current_start_ip} to {current_end_ip}")

    init_db()
    add_default_user()
    init_packet_db()
    init_instruction_logs_db()
    prune_packet_logs(PACKET_DB, retention_days=7)
    prune_instruction_logs(INSTRUCTION_LOGS_DB, retention_days=3)
    cleanup_backups(BACKUP_SCAN_DIR, 50)
    cleanup_backups(BACKUP_PACKET_DIR, 20)
    cleanup_backups(BACKUP_INSTRUCTION_LOGS_DIR, 50)
    cleanup_backups(BACKUP_WHITELIST_DIR, 100)
    log_instruction('System started', 'The system started running')

    backup_configs = [
        (SCAN_DB, BACKUP_SCAN_DIR, 60, 50),
        (PACKET_DB, BACKUP_PACKET_DIR, 60, 20),
        (INSTRUCTION_LOGS_DB, BACKUP_INSTRUCTION_LOGS_DIR, 60, 50),
    ]
    for db, backup_dir, interval, keep in backup_configs:
        threading.Thread(target=periodic_db_check_and_backup, args=(db, backup_dir, interval, keep), daemon=True).start()
    threading.Thread(target=periodic_whitelist_check_and_backup, args=(60, 100), daemon=True).start()
    threading.Thread(target=periodic_specified_ports_check_and_backup, args=(60, 100), daemon=True).start()
    threading.Thread(target=periodic_blocked_ports_check_and_backup, args=(60, 100), daemon=True).start()

    scan_thread = threading.Thread(target=continuous_scan, daemon=True)
    scan_thread.start()
    monitoring_thread = threading.Thread(target=start_monitoring, daemon=True)
    monitoring_thread.start()
    threading.Thread(target=monitor_watchdog, daemon=True).start()
    threading.Thread(target=scan_watchdog, daemon=True).start()

    app.run(host='0.0.0.0', port=5000, debug=False)