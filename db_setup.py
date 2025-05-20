import sqlite3
import os

# Corrected database path
DB_FILE = os.path.expanduser("~/Desktop/SIEM/db/siem.db")  # ✅ Updated path
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

def initialize_db():
    """Creates tables for storing known threats."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Threat intelligence table for tracking malicious indicators
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query TEXT UNIQUE,       -- IP, domain, file hash, CVE
        threat_type TEXT,        -- Malware, Phishing, Intrusion
        severity INTEGER,        -- 1 (Low) to 5 (Critical)
        source TEXT,             -- OTX, VirusTotal, Abuse.ch, etc.
        api_name TEXT,           -- API source (e.g., AlienVault OTX, NIST NVD)
        last_seen TEXT,          -- Timestamp for last detection
        description TEXT         -- Details about the threat
    );
    """)

    # Integrity monitoring alerts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS integrity_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        file_path TEXT,
        alert_message TEXT
    );
    """)

    conn.commit()
    conn.close()
    print("✅ Threat intelligence database setup completed!")

# Run setup manually when needed
if __name__ == "__main__":
    initialize_db()
