import os
import time
from datetime import datetime, timedelta
import logging
from collections import Counter
from silent_reports import generate_daily_excel, send_email_with_excel, get_recipient_email

LOG_FOLDER = "logs"
REPORT_FOLDER = "reports"
SUSPICIOUS_PATTERNS = ["malware", "phishing", "ransomware", "failed login", "unauthorized access", "error"]

os.makedirs(REPORT_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)
processed_files = set()

log_file = os.path.join(LOG_FOLDER, 'silent_sentinel.log')
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_log_file(file_path):
    suspicious_entries = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern in line.lower():
                        suspicious_entries.append(line.strip())
                        break
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
    entry_counts = Counter(suspicious_entries)
    report_file = os.path.join(REPORT_FOLDER, f"report_{os.path.basename(file_path)}_{int(time.time())}.txt")
    try:
        with open(report_file, 'w') as report:
            report.write(f"Suspicious Activity Report for {file_path}\n")
            report.write(f"Generated on: {datetime.now()}\n\n")
            for entry, count in entry_counts.items():
                report.write(f"{entry} - Occurrences: {count}\n")
        logging.info(f"Report generated: {report_file}")
    except Exception as e:
        logging.error(f"Error writing report for {file_path}: {e}")

def monitor_logs(interval=60):
    last_email_time = datetime.min
    daily_entries = []
    recipient_email = get_recipient_email()

    while True:
        new_entries = []
        try:
            for filename in os.listdir(LOG_FOLDER):
                file_path = os.path.join(LOG_FOLDER, filename)
                if file_path not in processed_files and os.path.isfile(file_path):
                    logging.info(f"Scanning log file: {file_path}")
                    entries = scan_log_file(file_path)
                    alert_terminal(entries)
                    generate_report(file_path, entries)
                    new_entries.extend(entries)
                    processed_files.add(file_path)
        except Exception as e:
            logging.error(f"Error monitoring logs: {e}")

        daily_entries.extend(new_entries)

        now = datetime.now()
        if daily_entries and (now - last_email_time >= timedelta(days=1)):
            excel_file = generate_daily_excel(daily_entries)
            send_email_with_excel(excel_file)
            daily_entries.clear()
            last_email_time = now

        time.sleep(interval)

def main():
    print("Starting Silent Sentinel Log Monitor...")
    monitor_logs(interval=60)

if __name__ == "__main__":
    main()

####Prototype v1.04####
####TODO: DONE: Implement email notification for generated reports####
####TODO: DONE: Add configuration file support for customizable settings####
####TODO: Integrate with a database for storing processed logs and reports####
####TODO: Enhance quantum computing detection algorithms####
####TODO: Implement GUI for streamlining user interaction####
