import sqlite3
import requests
import json
import datetime
import os
import logging
import time
from dotenv import load_dotenv
from tqdm import tqdm

try:
    from plyer import notification
    HAS_PLYER = True
except ImportError:
    HAS_PLYER = False

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

# Load the .env file from a cross-platform path
load_dotenv()
BASE_DIR = os.getenv("BASE_DIR", os.path.expanduser(os.path.join("~", "Desktop", "SIEM")))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
ENV_FILE = os.path.join(CONFIG_DIR, ".env")
if os.path.exists(ENV_FILE):
    load_dotenv(dotenv_path=ENV_FILE)

# Load API keys from environment variables
ALIENVAULT_API = os.getenv("ALIENVAULT_API")
IPINFO_API = os.getenv("IPINFO_API")
MALWAREBAZAAR_API = os.getenv("MALWAREBAZAAR_API")
DSHIELD_API = os.getenv("DSHIELD_API")

# Configurable severity threshold
SEVERITY_THRESHOLD = int(os.getenv("SEVERITY_THRESHOLD", 75))

# Cross-platform database path
DB_FILE = os.path.join(BASE_DIR, "db", "siem.db")
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
THREAT_JSON_FILE = os.path.join(BASE_DIR, "db", "threats.json")

def safe_request(method, url, retries=3, timeout=15, **kwargs):
    """Make a safe HTTP request with retries and timeout."""
    for attempt in range(retries):
        try:
            response = method(url, timeout=timeout, **kwargs)
            return response
        except requests.RequestException as e:
            logging.warning(f"Request error: {e}. Retrying ({attempt+1}/{retries})...")
            time.sleep(2)
    logging.error(f"Failed to fetch {url} after {retries} attempts.")
    return None

def notify_user(message):
    """Cross-platform notification."""
    if HAS_PLYER:
        notification.notify(title="SIEM Alert", message=message)
    else:
        logging.warning("plyer not installed, falling back to print for notifications.")
        print(f"NOTIFY: {message}")

def initialize_db():
    """Creates tables for storing known threats."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query TEXT UNIQUE,
        threat_type TEXT,
        severity INTEGER,
        source TEXT,
        api_name TEXT,
        last_seen TEXT,
        description TEXT,
        result TEXT
    );
    """)
    conn.commit()
    conn.close()

initialize_db()

def save_to_db_and_json(api_name, query, result, threat_type="Unknown", severity=1, description=""):
    """Stores threat intelligence results in the database and JSON file if they are new."""
    # Save to DB (only high-risk threats)
    if severity >= SEVERITY_THRESHOLD:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM threats WHERE query=?", (query,))
        existing_entry = cursor.fetchone()
        if existing_entry:
            conn.close()
        else:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
            INSERT INTO threats (query, threat_type, severity, source, api_name, last_seen, description, result)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (query, threat_type, severity, api_name, api_name, timestamp, description, result))
            conn.commit()
            conn.close()

    # Save to JSON (all threats)
    threat_entry = {
        "query": query,
        "threat_type": threat_type,
        "severity": severity,
        "source": api_name,
        "api_name": api_name,
        "last_seen": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "description": description,
        "result": result
    }
    # Load existing data
    if os.path.exists(THREAT_JSON_FILE):
        with open(THREAT_JSON_FILE, "r") as f:
            try:
                data = json.load(f)
            except Exception:
                data = []
    else:
        data = []
    # Avoid duplicates
    if not any(entry["query"] == query for entry in data):
        data.append(threat_entry)
        with open(THREAT_JSON_FILE, "w") as f:
            json.dump(data, f, indent=2)

def search_stored_threat(query):
    """Search for stored threat data in the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT result FROM threats WHERE query=?", (query,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def alert_critical_threat(threat):
    """Alert user about critical threats (risk ≥ 90)."""
    message = f"⚠️ CRITICAL THREAT DETECTED: {threat['indicator']} ({threat['description']})"
    notify_user(message)
    print(message)

class ThreatIntelligence:

    @staticmethod
    def check_malware_hash(hash_value):
        """Check malware hash reputation on MalwareBazaar"""
        stored_result = search_stored_threat(hash_value)
        if stored_result:
            return stored_result

        url = "https://mb-api.abuse.ch/api/v1/"
        headers = {"API-KEY": MALWAREBAZAAR_API}
        payload = {"query": "get_info", "hash": hash_value}

        response = safe_request(requests.post, url, headers=headers, data=payload)
        result = response.json() if response and response.status_code == 200 else "Error fetching malware hash."

        save_to_db_and_json(
            api_name="MalwareBazaar",
            query=hash_value,
            result=json.dumps(result),
            threat_type="Malware Hash",
            severity=4,
            description="Hash reputation data from MalwareBazaar"
        )
        return result

    @staticmethod
    def fetch_malwarebazaar_bulk():
        """Download bulk malware hashes from MalwareBazaar and save to DB/JSON"""
        url = "https://mb-api.abuse.ch/api/v1/"
        headers = {"API-KEY": MALWAREBAZAAR_API}
        payload = {"query": "get_recent"}

        try:
            response = safe_request(requests.post, url, headers=headers, data=payload)
            count = 0
            if response and response.status_code == 200:
                results = response.json()
                data = results.get("data", [])
                for entry in data:
                    hash_value = entry.get("sha256_hash")
                    description = entry.get("file_type")
                    save_to_db_and_json(
                        api_name="MalwareBazaar",
                        query=hash_value,
                        result=json.dumps(entry),
                        threat_type="Malware Hash",
                        severity=4,
                        description=f"File type: {description}"
                    )
                    count += 1
            else:
                logging.error("❌ Failed to download MalwareBazaar hashes.")
            return count
        except Exception as e:
            logging.error(f"❌ Error fetching MalwareBazaar: {e}")
            return 0

    @staticmethod
    def fetch_dshield_blocklist():
        """Download DShield blocklist and save to DB/JSON"""
        url = "https://isc.sans.edu/api/threatlist/dshieldblocklist"
        try:
            response = safe_request(requests.get, url)
            count = 0
            if response and response.status_code == 200:
                blocklist = response.text.splitlines()
                for ip in blocklist:
                    save_to_db_and_json(
                        api_name="DShield",
                        query=ip,
                        result="Listed in DShield blocklist",
                        threat_type="IP Reputation",
                        severity=3,
                        description="IP listed in DShield blocklist"
                    )
                    count += 1
            else:
                logging.error("❌ Failed to download DShield blocklist.")
            return count
        except Exception as e:
            logging.error(f"❌ Error fetching DShield: {e}")
            return 0

    @staticmethod
    def fetch_alienvault_reputation():
        """Download AlienVault IP reputation data and save to DB/JSON"""
        url = "https://reputation.alienvault.com/reputation.data"
        try:
            response = safe_request(requests.get, url)
            count = 0
            if response and response.status_code == 200:
                lines = response.text.splitlines()
                for line in lines:
                    if line.startswith("#") or not line.strip():
                        continue
                    ip = line.split()[0]
                    save_to_db_and_json(
                        api_name="AlienVault",
                        query=ip,
                        result="Listed in AlienVault reputation",
                        threat_type="IP Reputation",
                        severity=3,
                        description="IP listed in AlienVault reputation"
                    )
                    count += 1
            else:
                logging.error("❌ Failed to download AlienVault reputation data.")
            return count
        except Exception as e:
            logging.error(f"❌ Error fetching AlienVault: {e}")
            return 0

    @staticmethod
    def fetch_cisa_kev():
        """Download CISA Known Exploited Vulnerabilities and save to DB/JSON"""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        count = 0
        try:
            response = safe_request(requests.get, url, timeout=30)
            if response and response.status_code == 200:
                kev_data = response.json()
                vulnerabilities = kev_data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cve_id = vuln.get("cveID")
                    description = (
                        vuln.get("vendorProject", "") + " " +
                        vuln.get("product", "") + " - " +
                        vuln.get("vulnerabilityName", "")
                    )
                    save_to_db_and_json(
                        api_name="CISA KEV",
                        query=cve_id,
                        result=json.dumps(vuln),
                        threat_type="Known Exploited Vulnerability",
                        severity=90,
                        description=description
                    )
                    count += 1
            else:
                logging.error("❌ Failed to download CISA KEV vulnerabilities.")
        except Exception as e:
            logging.error(f"❌ Error fetching CISA KEV: {e}")
        return count

if __name__ == "__main__":
    handler = ThreatIntelligence()
    fetch_functions = [
        ("MalwareBazaar", handler.fetch_malwarebazaar_bulk),
        ("DShield", handler.fetch_dshield_blocklist),
        ("AlienVault", handler.fetch_alienvault_reputation),
        ("CISA KEV", handler.fetch_cisa_kev)
    ]

    logging.info("⬇️  Fetching threat intelligence updates...")
    total_sources = len(fetch_functions)
    with tqdm(total=total_sources, desc="Overall Progress", unit="source") as pbar:
        for name, func in fetch_functions:
            count = func()
            logging.info(f"{name}: {count} items processed.")
            pbar.update(1)
    logging.info("✅ All threat intelligence sources updated.")
