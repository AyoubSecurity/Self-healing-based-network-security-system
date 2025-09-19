import socket
import threading
import subprocess
import os
import time
from scapy.all import sniff, conf
from collections import defaultdict
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import sqlite3
import sys

# Configuration
ADMIN_PORT = 5555
HOST_LISTEN_IP = '0.0.0.0'
THRESHOLD = 1000
WINDOW_SIZE = 60
traffic_stats = defaultdict(lambda: {'timestamps': [], 'count': 0})
DB_FILE = "packet_logs.db"
db_lock = threading.Lock()
last_alert_times = defaultdict(lambda: 0)  # Track last alert time per IP

# Global admin socket for sending alerts, with thread-safe access
admin_socket = None
admin_socket_lock = threading.Lock()

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [GUEST] {message}")

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

local_ip = get_local_ip()

def send_to_admin(message):
    global admin_socket
    with admin_socket_lock:
        if admin_socket:
            try:
                admin_socket.sendall(message.encode())
                log(f"Sent to admin: {message}")
                return True
            except socket.error as e:
                log(f"Failed to send to admin: {e}. Connection might be closed.")
                admin_socket = None
                return False
        else:
            log("Not connected to admin. Cannot send message.")
            return False

def send_alert_email(ip_address):
    admin_email = "ayoubscispace@gmail.com"
    sender_email = "myalertshbnss@gmail.com"
    subject = f"DDoS Alert from Guest {local_ip}: IP {ip_address} triggered threshold"
    body = f"A potential DDoS attack was detected from IP {ip_address} on guest machine {local_ip}.\n" \
           f"Action taken: Alert sent to admin. Current guest THRESHOLD: {THRESHOLD}.\n" \
           f"Please review the admin logs for further details and firewall actions."
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = admin_email
    
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "myalertshbnss@gmail.com"
    smtp_password = os.environ.get("SMTP_PASSWORD")

    if not smtp_password:
        log("SMTP password not configured. Cannot send email.")
        return

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(sender_email, [admin_email], msg.as_string())
            log(f"Alert email sent to {admin_email} regarding IP {ip_address}")
    except Exception as e:
        log(f"Failed to send alert email: {e}")

def start_guest_command_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST_LISTEN_IP, ADMIN_PORT))
    server_socket.listen(5)
    log(f"Guest listening for admin commands on {HOST_LISTEN_IP}:{ADMIN_PORT}")
    while True:
        admin_socket, admin_addr = server_socket.accept()
        log(f"Accepted connection from admin {admin_addr}")
        threading.Thread(target=handle_admin_commands, args=(admin_socket, admin_addr), daemon=True).start()

def handle_admin_commands(admin_socket, admin_addr):
    log(f"Admin connected from {admin_addr} for sending commands.")
    try:
        while True:
            data = admin_socket.recv(1024)
            if not data:
                log(f"Admin {admin_addr} disconnected from commands channel.")
                break
            command = data.decode().strip()
            log(f"Received command from admin {admin_addr}: {command}")
            if command == "PING_FROM_ADMIN":
                admin_socket.send("PONG_TO_ADMIN".encode())
                log("Responded to PING_FROM_ADMIN with PONG_TO_ADMIN")
            else:
                parts = command.split(':')
                if len(parts) == 3:
                    target_type, target, action = parts
                    if target_type in ["IP", "PORT"] and action in ["block", "unblock"]:
                        result = manage_firewall(action, target_type, target)
                        admin_socket.send(f"ACK: {result}".encode())
                    else:
                        admin_socket.send(f"ACK: Invalid command format or unsupported target_type/action".encode())
                else:
                    admin_socket.send(f"ACK: Invalid command format".encode())
    except Exception as e:
        log(f"Error handling commands from admin {admin_addr}: {e}")
    finally:
        admin_socket.close()
        log(f"Closed connection with admin {admin_addr}.")

def manage_firewall(action, target_type, target):
    cmd = None
    if os.name == 'nt':
        if target_type == "IP":
            rule_name = f"GuestBlock_IP_{target}".replace(":", "_")
            if action == 'block':
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={target}'
            elif action == 'unblock':
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            else:
                return f"Invalid action: {action}"
        elif target_type == "PORT":
            rule_name = f"GuestBlock_PORT_{target}"
            if action == 'block':
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block protocol=TCP localport={target}'
            elif action == 'unblock':
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            else:
                return f"Invalid action: {action}"
        else:
            return f"Invalid target_type: {target_type}"
    else:
        return f"Firewall management not supported on guest OS: {os.name}"
    
    try:
        log(f"Guest executing firewall command: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            log(f"Guest firewall success: {action} {target_type} {target}")
            return f"Guest Success: {action} {target_type} {target}"
        else:
            error_msg = result.stderr or result.stdout or "Unknown error"
            log(f"Guest firewall error: {action} {target_type} {target} - {error_msg}")
            return f"Guest Error: {error_msg}"
    except Exception as e:
        log(f"Guest firewall exception: {e}")
        return f"Guest Exception: {e}"

def init_database():
    with db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packet_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, src_ip TEXT, protocol TEXT,
                packet_size INTEGER, dest_ip TEXT, dest_port INTEGER )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, src_ip TEXT, packet_count INTEGER, action TEXT )
        """)
        conn.commit()
        conn.close()
    log(f"Guest database {DB_FILE} initialized.")

def log_packet(src_ip, protocol, packet_size, dest_ip, dest_port):
    with db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            cursor.execute("""
                INSERT INTO packet_logs (timestamp, src_ip, protocol, packet_size, dest_ip, dest_port)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (timestamp, src_ip, protocol, packet_size, dest_ip, dest_port))
            conn.commit()
        except Exception as e:
            log(f"Error logging packet to guest DB: {e}")
        finally:
            conn.close()

def log_alert(src_ip, packet_count, action="local_threshold_exceeded"):
    with db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            cursor.execute("""
                INSERT INTO alert_logs (timestamp, src_ip, packet_count, action)
                VALUES (?, ?, ?, ?)
            """, (timestamp, src_ip, packet_count, action))
            conn.commit()
            log(f"Guest logged local alert for {src_ip}, count {packet_count}, action {action}")
        except Exception as e:
            log(f"Error logging alert to guest DB: {e}")
        finally:
            conn.close()

def get_interface_by_ip(ip):
    for iface in conf.ifaces:
        ip_attrs = ['ip', 'ipv4_addr', 'ip4']
        for attr in ip_attrs:
            if hasattr(iface, attr) and getattr(iface, attr) == ip:
                log(f"Found interface {iface.name} with IP {ip}")
                return iface.name
    log(f"No interface found with IP {ip}. Available interfaces: {conf.ifaces}")
    return None

def packet_callback(packet):
    global THRESHOLD, last_alert_times
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        if src_ip == local_ip:
            return

        protocol_num = packet['IP'].proto
        protocol_str = str(protocol_num)
        packet_size = len(packet)
        dest_ip = packet['IP'].dst
        dest_port = None

        if packet.haslayer('TCP'):
            dest_port = packet['TCP'].dport
            protocol_str = "TCP"
        elif packet.haslayer('UDP'):
            dest_port = packet['UDP'].dport
            protocol_str = "UDP"
        
        log_packet(src_ip, protocol_str, packet_size, dest_ip, dest_port)
        
        current_time = time.time()
        stat = traffic_stats[src_ip]
        stat['timestamps'].append(current_time)
        
        stat['timestamps'] = [t for t in stat['timestamps'] if current_time - t <= WINDOW_SIZE]
        packet_count_in_window = len(stat['timestamps'])
        stat['count'] = packet_count_in_window

        if packet_count_in_window > THRESHOLD:
            last_alert = last_alert_times[src_ip]
            if current_time - last_alert >= 60:  # 60 seconds = 1 minute
                log(f"GUEST: Threshold EXCEEDED by {src_ip}! Packets: {packet_count_in_window}, Threshold: {THRESHOLD}")
                alert_message = f"DDOS_ALERT:{src_ip}"
                if send_to_admin(alert_message):
                    log(f"Alert sent to admin for IP {src_ip}")
                    send_alert_email(src_ip)
                    last_alert_times[src_ip] = current_time
                log_alert(src_ip, packet_count_in_window)
            else:
                log(f"Alert for IP {src_ip} suppressed (last alert sent {(current_time - last_alert):.2f} seconds ago)")
            traffic_stats[src_ip]['timestamps'] = []
            stat['count'] = 0

def log_packet_rates():
    while True:
        time.sleep(60)
        current_time = time.time()
        for ip, stat in traffic_stats.items():
            recent_packets = [t for t in stat['timestamps'] if current_time - t <= 60]
            packet_count = len(recent_packets)
            log(f"Packet rate from {ip}: {packet_count} packets/min")
            if packet_count > THRESHOLD:
                log(f"ALERT: Packet rate from {ip} exceeds threshold ({packet_count} > {THRESHOLD})")

monitoring_active_guest = threading.Event()
monitoring_active_guest.set()
guest_monitoring_thread = None

def start_guest_monitoring():
    global guest_monitoring_thread
    if guest_monitoring_thread and guest_monitoring_thread.is_alive():
        log("Guest monitoring thread already running.")
        return
    
    interface_name = get_interface_by_ip(local_ip)
    if not interface_name:
        log("Monitoring not started due to interface detection failure.")
        return
    
    monitoring_active_guest.set()
    guest_monitoring_thread = threading.Thread(
        target=lambda: sniff(
            iface=interface_name,
            prn=packet_callback,
            store=0,
            stop_filter=lambda p: not monitoring_active_guest.is_set()
        ),
        daemon=True
    )
    guest_monitoring_thread.start()
    log(f"Guest traffic monitoring thread started on interface: {interface_name}.")

def stop_guest_monitoring():
    global guest_monitoring_thread
    if guest_monitoring_thread and guest_monitoring_thread.is_alive():
        monitoring_active_guest.clear()
        guest_monitoring_thread.join(timeout=5)
        log("Guest monitoring thread stopped.")
    guest_monitoring_thread = None

if __name__ == "__main__":
    if len(sys.argv) > 1:
        ADMIN_IP = sys.argv[1]
    else:
        log("Please provide the admin's IP address as a command-line argument (e.g., python guest.py 192.168.1.12)")
        sys.exit(1)
    log(f"Guest script started. My IP: {local_ip}")
    init_database()

    guest_server_thread = threading.Thread(target=start_guest_command_server, daemon=True)
    guest_server_thread.start()

    start_guest_monitoring()
    
    packet_rate_thread = threading.Thread(target=log_packet_rates, daemon=True)
    packet_rate_thread.start()
    
    log("Guest setup complete. Monitoring traffic and listening for Admin commands.")
    
    try:
        while True:
            cmd_input = input("Guest> ").strip().lower()
            if cmd_input == "exit":
                log("Guest shutting down...")
                break
            elif cmd_input == "status":
                log(f"Current Guest THRESHOLD: {THRESHOLD}")
                with admin_socket_lock:
                    log(f"Connected to Admin: {'Yes' if admin_socket else 'No'}")
            else:
                time.sleep(1)
    except KeyboardInterrupt:
        log("Guest script interrupted.")
    finally:
        monitoring_active_guest.clear()
        if guest_monitoring_thread and guest_monitoring_thread.is_alive():
            guest_monitoring_thread.join(timeout=5)
        with admin_socket_lock:
            if admin_socket:
                admin_socket.close()
        log("Guest script finished.")