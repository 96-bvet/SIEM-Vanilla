import hashlib
import sqlite3
import os
import datetime
from alerts import send_popup_alert

DB_FILE = "db/siem.db"
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

def initialize_db():
    """Initialize file integrity database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS integrity_baseline (
        file_path TEXT PRIMARY KEY,
        baseline_hash TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS integrity_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        file_path TEXT,
        alert_message TEXT
    )
    """)
    conn.commit()
    conn.close()

initialize_db()

def compute_file_hash(file_path):
    """Generate SHA-256 hash of a file"""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):  # Read in 8KB chunks
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        print(f"⚠️ File not found: {file_path}")
        return None
    except PermissionError:
        print(f"⚠️ Permission denied: {file_path}")
        return None

def store_baseline_hashes(files=None):
    """Store file integrity hashes"""
    if files is None:
        files = ["/etc/passwd", "/etc/group", "/etc/hosts"]  # Default files to monitor

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        for file in files:
            file_hash = compute_file_hash(file)
            if file_hash:
                cursor.execute("INSERT OR REPLACE INTO integrity_baseline (file_path, baseline_hash) VALUES (?, ?)",
                               (file, file_hash))
            else:
                print(f"⚠️ Skipped {file}: Unable to compute hash.")

        conn.commit()
        conn.close()
        print("🔒 Baseline hashes stored securely!")
    except sqlite3.OperationalError as e:
        print(f"❌ Database error while storing baseline hashes: {e}")

def log_integrity_alert(file_path, message):
    """Log integrity alerts to the database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute("INSERT INTO integrity_alerts (file_path, alert_message) VALUES (?, ?)",
                       (file_path, message))

        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(f"❌ Database error while logging alert: {e}")

def check_file_integrity():
    """Check file integrity and trigger alerts"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT file_path, baseline_hash FROM integrity_baseline")
        baseline_data = cursor.fetchall()

        for file_path, baseline_hash in baseline_data:
            current_hash = compute_file_hash(file_path)
            if current_hash is None:
                print(f"⚠️ Skipped {file_path}: File not found or unreadable.")
                continue

            if current_hash != baseline_hash:
                alert_message = f"🚨 ALERT: {file_path} has been modified!"
                send_popup_alert(alert_message)
                log_integrity_alert(file_path, alert_message)
                print(alert_message)

        conn.close()
        print("✅ File integrity check completed.")
    except sqlite3.OperationalError as e:
        print(f"❌ Database error while checking file integrity: {e}")
