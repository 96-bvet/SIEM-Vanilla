import sys
import os
import sqlite3
import subprocess
import db_setup  # ✅ Automatically initializes the database

# Adjust the import path for Modules directory
module_path = os.path.expanduser("~/Desktop/SIEM/Modules")
if module_path not in sys.path:
    sys.path.append(module_path)

from user_auth import UserAuth
from api_handler import ThreatIntelligence
from file_integrity import check_file_integrity
from alerts import (
    send_popup_alert,
    monitor_files,
    monitor_network_connections,
    load_blacklisted_ips
)

DB_FILE = os.path.expanduser("~/Desktop/SIEM/db/siem.db")
SECURITY_ALERTS_FILE = os.path.expanduser("~/Desktop/SIEM/security_alerts.json")
USER_LOG_FILE = os.path.expanduser("~/Desktop/SIEM/user_log.json")

def register_user_prompt():
    print("\n--- Register New User ---")
    username = input("Choose a username: ").strip()
    password = input("Choose a password: ").strip()
    confirm = input("Confirm password: ").strip()
    if password != confirm:
        print("❌ Passwords do not match.")
        return False
    UserAuth.register_user(username, password)
    return True

def main():
    print("Welcome to SIEM!")
    print("1. Login")
    print("2. Register")
    choice = input("Select an option (1 or 2): ").strip()
    if choice == "2":
        register_user_prompt()
        # After registration, continue to login

    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    if not UserAuth.authenticate_user(username, password):
        print("❌ Authentication failed. Exiting...")
        exit()

    # ---- SIEM LOGIC STARTS HERE ----

    def store_threat(indicator, threat_type, severity, source, description, result):
        from api_handler import save_to_db_and_json
        save_to_db_and_json(
            api_name=source,
            query=indicator,
            result=result,
            threat_type=threat_type,
            severity=severity,
            description=description
        )

    def fetch_threat_intelligence():
        ThreatIntelligence.fetch_malwarebazaar_bulk()
        ThreatIntelligence.fetch_dshield_blocklist()
        ThreatIntelligence.fetch_alienvault_reputation()
        ThreatIntelligence.fetch_cisa_kev()

    fetch_threat_intelligence()

    def get_installed_packages():
        result = subprocess.run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"], capture_output=True, text=True)
        installed_packages = result.stdout.strip().split("\n")
        return [pkg.split(" ")[0] for pkg in installed_packages]

    def check_local_vulnerabilities():
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT query FROM threats WHERE api_name='NIST NVD'")
        stored_cves = [row[0] for row in cursor.fetchall()]
        installed_packages = get_installed_packages()
        for package in installed_packages:
            for cve in stored_cves:
                if package.lower() in cve.lower():
                    alert_message = f"⚠️ Vulnerability Detected: {package} matches {cve}"
                    send_popup_alert(alert_message)
        conn.close()

    check_local_vulnerabilities()

    tracked_files = ["/etc/passwd", "/etc/group", "/etc/hosts"]
    print("\n🔍 Starting file integrity monitoring...")
    monitor_files(tracked_files, interval=10)

    print("\n🌐 Starting network monitoring...")
    monitor_network_connections(
        blacklist=load_blacklisted_ips(),
        interval=10,
        refresh_blacklist_func=load_blacklisted_ips,
        refresh_interval=600
    )

if __name__ == "__main__":
    main()
