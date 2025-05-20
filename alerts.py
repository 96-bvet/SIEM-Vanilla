import json
import datetime
import os
import time
import hashlib
import subprocess
import sqlite3
import re
import threading
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Corrected path for security alerts
SECURITY_ALERTS_FILE = os.path.expanduser("~/Desktop/SIEM/security_alerts.json")
DB_FILE = os.path.expanduser("~/Desktop/SIEM/db/siem.db")

IGNORED_FILE_PATTERNS = ["/var/log/", "/tmp/", "/run/"]
ALERTED_PROCESSES = set()
RECENTLY_ALERTED_FILES = {}
ALERT_SUPPRESS_SECONDS = 10  # Suppress duplicate alerts for the same file within this window

log_lock = threading.Lock()

def log_security_event(alert_type, message):
    """Logs security alerts to JSON file (thread-safe)."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    log_entry = {"timestamp": timestamp, "alert_type": alert_type, "message": message}

    with log_lock:
        if not os.path.exists(SECURITY_ALERTS_FILE):
            with open(SECURITY_ALERTS_FILE, "w") as file:
                json.dump([], file)  # Initialize empty JSON list

        with open(SECURITY_ALERTS_FILE, "r+") as file:
            try:
                logs = json.load(file)
            except Exception:
                logs = []
            logs.append(log_entry)
            file.seek(0)
            json.dump(logs, file, indent=4)
            file.truncate()  # Ensure old content is removed

    print(f"🚨 Security Log: [{alert_type}] - {message}")

def send_popup_alert(message):
    """Triggers a pop-up security notification."""
    try:
        os.system(f'notify-send "SECURITY ALERT" "{message}"')
    except Exception as e:
        print(f"⚠️ Pop-up alert failed: {e}")

def hash_file(filepath):
    """Returns the SHA256 hash of the file, or None if not found."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def should_ignore_file(filepath):
    return any(filepath.startswith(pattern) for pattern in IGNORED_FILE_PATTERNS)

def suppress_duplicate_file_alert(filepath):
    """Suppress duplicate alerts for the same file within a short window."""
    now = time.time()
    last_alert = RECENTLY_ALERTED_FILES.get(filepath, 0)
    if now - last_alert < ALERT_SUPPRESS_SECONDS:
        return True
    RECENTLY_ALERTED_FILES[filepath] = now
    # Clean up old entries
    for f in list(RECENTLY_ALERTED_FILES):
        if now - RECENTLY_ALERTED_FILES[f] > ALERT_SUPPRESS_SECONDS:
            del RECENTLY_ALERTED_FILES[f]
    return False

def monitor_files(tracked_files, interval=60):
    """
    Polls a portion of tracked files each interval for changes.
    Only isolates if malware is found.
    """
    print("🔄 Starting optimized polling-based file monitoring...")
    file_hashes = {file: hash_file(file) for file in tracked_files}
    # Batch: check 1/6th of files per interval (so all files checked every 6*interval seconds)
    batch_size = max(1, len(tracked_files) // 6)
    file_queue = deque(tracked_files)

    try:
        while True:
            for _ in range(batch_size):
                if not file_queue:
                    file_queue = deque(tracked_files)
                file = file_queue.popleft()
                if should_ignore_file(file):
                    continue
                current_hash = hash_file(file)
                if current_hash != file_hashes.get(file):
                    if suppress_duplicate_file_alert(file):
                        continue
                    message = f"File modified: {file}"
                    log_security_event("FILE_MODIFICATION", message)
                    send_popup_alert(message)
                    if scan_with_clamav(file):
                        isolate_system(f"Malware detected in: {file}")
                    file_hashes[file] = current_hash
            time.sleep(interval)
    except KeyboardInterrupt:
        print("🛑 File monitoring stopped by user.")

def scan_with_clamav(filepath):
    """Scan a file with ClamAV and return True if malware is found."""
    try:
        result = subprocess.run(['clamscan', filepath], capture_output=True, text=True)
        if "FOUND" in result.stdout:
            log_security_event("MALWARE_DETECTED", f"Malware found in {filepath}")
            send_popup_alert(f"Malware found in {filepath}")
            return True
    except Exception as e:
        log_security_event("CLAMAV_ERROR", f"Error scanning {filepath}: {e}")
    return False

def load_blacklisted_ips():
    """
    Loads blacklisted IPs from the SIEM database (e.g., from DShield or AlienVault sources).
    Returns a set of IP addresses.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT query FROM threats WHERE threat_type='IP Reputation'")
    ips = {row[0] for row in cursor.fetchall()}
    conn.close()
    return ips

def monitor_network_connections(blacklist=None, interval=10, refresh_blacklist_func=None, refresh_interval=600):
    """
    Monitors active network connections.
    If a connection to a blacklisted IP is detected, logs and sends a popup alert.
    Optionally refreshes the blacklist every `refresh_interval` seconds.
    """
    print("🌐 Starting active network monitoring...")
    if blacklist is None:
        blacklist = set()
    last_refresh = time.time()

    try:
        while True:
            # Refresh blacklist if needed
            if refresh_blacklist_func and (time.time() - last_refresh > refresh_interval):
                blacklist = refresh_blacklist_func()
                last_refresh = time.time()

            result = subprocess.run(['ss', '-tunap'], capture_output=True, text=True)
            connections = result.stdout.splitlines()
            for conn in connections:
                for bad_ip in blacklist:
                    if bad_ip in conn:
                        message = f"Suspicious network connection detected: {conn.strip()}"
                        log_security_event("NETWORK_ALERT", message)
                        send_popup_alert(message)
                        isolate_system(f"Connection to blacklisted IP: {bad_ip}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("🛑 Network monitoring stopped by user.")

def isolate_system(reason="Threat detected"):
    """Isolate the system in response to a critical attack."""
    log_security_event("ISOLATION", f"System isolation triggered: {reason}")
    send_popup_alert(f"System isolation triggered: {reason}")
    os.system("nmcli networking off")
    os.system("iptables -P OUTPUT DROP")

def monitor_suricata_alerts(logfile="/var/log/suricata/fast.log", interval=5):
    """
    Monitors Suricata's fast.log for new alerts and triggers SIEM responses.
    """
    print("🛡️  Monitoring Suricata alerts...")
    try:
        with open(logfile, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(interval)
                    continue
                log_security_event("SURICATA_ALERT", line.strip())
                send_popup_alert(f"Suricata Alert: {line.strip()}")
                if "ET TROJAN" in line or "ET MALWARE" in line or "SQL Injection" in line:
                    isolate_system(f"Suricata detected: {line.strip()}")
    except Exception as e:
        log_security_event("SURICATA_ERROR", f"Error monitoring Suricata: {e}")

def monitor_suricata_eve(logfile="/var/log/suricata/eve.json", interval=5):
    """
    Monitors Suricata's eve.json for new alerts and triggers SIEM responses.
    """
    print("🛡️  Monitoring Suricata eve.json alerts...")
    CRITICAL_SURICATA_KEYWORDS = ["ET TROJAN", "ET MALWARE", "SQL Injection"]
    try:
        with open(logfile, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(interval)
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        msg = event["alert"]["signature"]
                        log_security_event("SURICATA_ALERT", msg)
                        send_popup_alert(f"Suricata Alert: {msg}")
                        if any(keyword in msg for keyword in CRITICAL_SURICATA_KEYWORDS):
                            isolate_system(f"Suricata detected: {msg}")
                except Exception as e:
                    log_security_event("SURICATA_JSON_ERROR", f"Error parsing eve.json: {e}")
    except Exception as e:
        log_security_event("SURICATA_ERROR", f"Error monitoring Suricata eve.json: {e}")

def get_all_files(root_dirs, exclude_dirs=None):
    file_list = []
    for root_dir in root_dirs:
        for root, dirs, files in os.walk(root_dir):
            # Prune excluded directories from recursion
            if exclude_dirs:
                dirs[:] = [d for d in dirs if not any(os.path.join(root, d).startswith(ex) for ex in exclude_dirs)]
            for name in files:
                full_path = os.path.join(root, name)
                if exclude_dirs and any(full_path.startswith(ex) for ex in exclude_dirs):
                    continue
                file_list.append(full_path)
    return file_list

class SIEMFileEventHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        # Handle created, modified, moved, deleted
        if event.is_directory or should_ignore_file(event.src_path):
            return
        if event.event_type in ("modified", "created", "moved", "deleted"):
            if suppress_duplicate_file_alert(event.src_path):
                return
            message = f"File {event.event_type} (inotify): {event.src_path}"
            log_security_event("FILE_EVENT", message)
            send_popup_alert(message)
            if event.event_type in ("modified", "created") and scan_with_clamav(event.src_path):
                isolate_system(f"Malware detected in: {event.src_path}")

def start_inotify_monitor(directories):
    print("👁️  Starting inotify-based real-time file monitoring...")
    event_handler = SIEMFileEventHandler()
    observer = Observer()
    for directory in directories:
        if os.path.exists(directory):
            observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def monitor_processes(baseline=None, interval=10):
    print("🔎 Monitoring all processes...")
    if baseline is None or not baseline:
        baseline = {
            "systemd", "bash", "sshd", "python", "python3", "ps", "init", "cron", "dbus-daemon",
            "rsyslogd", "NetworkManager", "agetty", "login", "sudo", "nano", "vim", "top"
        }
    known_pids = set()
    try:
        while True:
            result = subprocess.run(['ps', '-eo', 'pid,comm'], capture_output=True, text=True)
            lines = result.stdout.splitlines()[1:]
            for line in lines:
                pid, proc = line.strip().split(None, 1)
                if proc not in baseline and pid not in known_pids:
                    log_security_event("PROCESS_ALERT", f"Unknown process: {proc} (PID: {pid})")
                    send_popup_alert(f"Unknown process: {proc} (PID: {pid})")
                    ALERTED_PROCESSES.add(proc)
                    known_pids.add(pid)
            # Clean up known_pids for exited processes
            current_pids = {line.strip().split(None, 1)[0] for line in lines}
            known_pids &= current_pids
            time.sleep(interval)
    except KeyboardInterrupt:
        print("🛑 Process monitoring stopped by user.")

def is_known_good_connection(conn):
    return any(pattern in conn for pattern in KNOWN_GOOD_PATTERNS)

# Baseline for known good connections (adjust as needed)
KNOWN_GOOD_PATTERNS = [
    "127.0.0.1",
    "192.168.1.",
    "239.255.255.250",
    "[ff02::c]",
    "[fe80::",
    "[2603:",
    "::1",
    ":3702",
    ":68",
    ":67",
    ":546",
    "firefox-esr",
    "code",
    "python3"
]

# Example Usage:
if __name__ == "__main__":
    log_security_event("FILE_MODIFICATION", "/etc/passwd was altered!")
    send_popup_alert("Critical system file modified: /etc/passwd")
    root_dirs = ["/etc", "/usr", "/var"]
    exclude_dirs = ["/proc", "/sys", "/dev", "/run", "/tmp", "/var/log"]
    tracked_files = get_all_files(root_dirs, exclude_dirs)

    # Start polling-based file monitoring in a thread (with longer interval due to inotify)
    file_thread = threading.Thread(target=monitor_files, args=(tracked_files, 60), daemon=True)
    file_thread.start()

    # Start inotify-based real-time monitoring in a thread
    inotify_thread = threading.Thread(target=start_inotify_monitor, args=(root_dirs,), daemon=True)
    inotify_thread.start()

    # Start network monitoring in a thread
    net_thread = threading.Thread(
        target=monitor_network_connections,
        kwargs={
            'blacklist': load_blacklisted_ips(),
            'interval': 10,
            'refresh_blacklist_func': load_blacklisted_ips,
            'refresh_interval': 600
        },
        daemon=True
    )
    net_thread.start()

    # Start Suricata fast.log monitoring in a thread
    suricata_fast_thread = threading.Thread(target=monitor_suricata_alerts, args=("/var/log/suricata/fast.log", 5), daemon=True)
    suricata_fast_thread.start()

    # Start Suricata eve.json monitoring in a thread
    suricata_eve_thread = threading.Thread(target=monitor_suricata_eve, args=("/var/log/suricata/eve.json", 5), daemon=True)
    suricata_eve_thread.start()

    # Start process monitoring in a thread (use default baseline)
    process_thread = threading.Thread(target=monitor_processes, daemon=True)
    process_thread.start()

    # Keep the main thread alive
    while True:
        time.sleep(60)
