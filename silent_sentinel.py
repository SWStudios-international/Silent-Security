import os
import time
from datetime import datetime, timedelta, date, time as dt_time
import logging
import json
from collections import Counter
from silent_reports import generate_daily_excel, send_email_with_excel
from silent_db import init_db, add_suspicious_entry, mark_file_processed, is_file_processed, fetch_daily_entries
from silent_quantum import aggregate_log_entries, quantum_score, detect_quantum_patterns, generate_quantum_key

excel_file = generate_daily_excel()
if excel_file:
    send_email_with_excel(excel_file)  

with open("config.json", "r") as config_file:
    config = json.load(config_file)

LOG_FOLDER = config.get("log_folder", "logs")
REPORT_FOLDER = config.get("report_folder", "reports")
SUSPICIOUS_PATTERNS = config.get("suspicious_patterns", [])
EMAIL_CONFIG = config.get("email_notifications", {})
PASSKEY = config.get("passkey", "")

os.makedirs(REPORT_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)

init_db()

log_file = os.path.join(LOG_FOLDER, "silent_sentinel.log")
logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logging.info("Silent Sentinel Log Monitor started.")

def scan_log_file(file_path):
    suspicious_entries = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                entry = line.strip()
                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern.lower() in entry.lower():
                        suspicious_entries.append(entry)
                        break
                entry_score = quantum_score(entry)
                if entry_score >= 2:
                    logging.warning(f"Highly suspicious quantum entry: {entry} (Score: {entry_score})")
                elif entry_score == 1:
                    logging.info(f"Suspicious quantum entry: {entry} (Score: {entry_score})")
    except Exception as e:
        logging.error(f"Error reading {file_path}: {e}")
    return suspicious_entries

def alert_terminal(suspicious_entries):
    if suspicious_entries:
        print("\nSuspicious Entries Detected:")
        for entry in suspicious_entries:
            print(f"- {entry}")
        print()

def generate_report(file_path, suspicious_entries):
    if not suspicious_entries:
        return
    report_file = os.path.join(REPORT_FOLDER, f"report_{os.path.basename(file_path)}_{int(time.time())}.txt")
    try:
        with open(report_file, "w") as report:
            report.write(f"Suspicious Activity Report for {file_path}\n")
            report.write(f"Generated on: {datetime.now()}\n\n")
            for entry, count in Counter(suspicious_entries).items():
                report.write(f"{entry} - Occurrences: {count}\n")
        logging.info(f"Report generated: {report_file}")
    except Exception as e:
        logging.error(f"Error writing report for {file_path}: {e}")

def monitor_logs(interval=60):
    last_email_time = datetime.min
    api_key_input = os.environ.get("SENTINEL_KEY", "")
    if api_key_input != PASSKEY:
        logging.error("Passkey mismatch. Exiting monitor.")
        print("Invalid passkey. Exiting.")
        return

    while True:
        new_entries = []
        try:
            for filename in os.listdir(LOG_FOLDER):
                file_path = os.path.join(LOG_FOLDER, filename)
                if os.path.isfile(file_path) and not is_file_processed(file_path):
                    logging.info(f"Scanning log file: {file_path}")
                    entries = scan_log_file(file_path)

                    quantum_results = aggregate_log_entries(entries)
                    for entry, score in quantum_results['detailed'].items():
                        if score >= 2:
                            logging.warning(f"Highly suspicious quantum entry detected: {entry}")
                        elif score == 1:
                            logging.info(f"Suspicious quantum entry detected: {entry}")
                        else:
                            logging.debug(f"Safe entry: {entry}")

                    alert_terminal(entries)
                    generate_report(file_path, entries)

                    for entry in entries:
                        add_suspicious_entry(file_path, entry)
                    mark_file_processed(file_path)

                    new_entries.extend(entries)

        except Exception as e:
            logging.error(f"Error monitoring logs: {e}")

        now = datetime.now()
        if EMAIL_CONFIG.get("enabled", False) and now - last_email_time >= timedelta(days=1):
            daily_entries = fetch_daily_entries(date.today())
            if daily_entries:
                excel_file = generate_daily_excel(daily_entries)
                send_email_with_excel(excel_file)
            last_email_time = now

        if new_entries:
            quantum_summary = aggregate_log_entries(new_entries)
            logging.info(f"Quantum summary for batch: {quantum_summary}")

        time.sleep(interval)

def main():
    print("Starting Silent Sentinel Log Monitor...")
    monitor_logs(interval=60)

if __name__ == "__main__":
    main()

####Prototype v1.05####
####TODO: DONE: Implement email notification for generated reports####
####TODO: DONE: Add configuration file support for customizable settings####
####TODO: DONE: Integrate with a database for storing processed logs and reports####
####TODO: DONE: Enhance quantum computing detection algorithms####
####TODO: Implement GUI for streamlining user interaction####
