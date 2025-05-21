import sqlite3
import os
import logging
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logging.info("Initializing database...")

# Load environment variables
load_dotenv()

# Cross-platform database path
BASE_DIR = os.getenv("BASE_DIR", os.path.expanduser(os.path.join("~", "Desktop", "SIEM")))
DB_FILE = os.path.join(BASE_DIR, "db", "siem.db")

# Ensure the directory exists before connecting
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

def initialize_db():
    """Creates tables for storing known threats and integrity alerts."""
    conn = None
    try:
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
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_path TEXT,
            alert_message TEXT
        );
        """)

        # Database versioning table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS db_version (
            version INTEGER PRIMARY KEY,
            applied_on DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # Add indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_query ON threats (query);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_type ON threats (threat_type);")

        conn.commit()
        logging.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def get_db_connection():
    return sqlite3.connect(DB_FILE)

def backup_database():
    """Creates a backup of the database."""
    backup_file = os.path.join(BASE_DIR, "db", "siem_backup.db")
    try:
        conn = sqlite3.connect(DB_FILE)
        with open(backup_file, 'wb') as f:
            for line in conn.iterdump():
                f.write(f"{line}\n".encode())
        logging.info(f"Database backup created at {backup_file}")
    except sqlite3.Error as e:
        logging.error(f"Error creating database backup: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    initialize_db()
    # Uncomment the line below to create a backup
    # backup_database()
