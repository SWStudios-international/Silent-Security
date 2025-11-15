import os
import time
from datetime import datetime
import logging
from collections import Counter
from silent_reports import get_user_email, generate_daily_excel, send_email_with_excel

LOG_FOLDER = "logs"
REPORT_FOLDER = "reports"
SUSPICIOUS_PATTERNS = ["malware", "phishing", "ransomware", "failed login", "unauthorized access", "error"]

os.makedirs(REPORT_FOLDER, exist_ok=True)
processed_files = set()

logging.basicConfig(
    filename=os.path.join(LOG_FOLDER, 'silent_sentinel.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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
    if not suspicious_entries:
        return
    print("\n\033[91m=== Suspicious Activity Detected ===\033[0m")
    entry_counts = Counter(suspicious_entries)
    for entry, count in entry_counts.items():
        print(f"{entry} - Occurrences: {count}")
    print("\033[91m====================================\033[0m\n")

def update_daily_summary(suspicious_entries):
    if not suspicious_entries:
        return
    summary_file = os.path.join(REPORT_FOLDER, "daily_summary.txt")
    with open(summary_file, "a") as f:
        for entry in suspicious_entries:
            f.write(f"{datetime.now()}: {entry}\n")

def generate_report(file_path, suspicious_entries):
    if not suspicious_entries:
        return
    entry_counts = Counter(suspicious_entries)
    report_file = os.path.join(REPORT_FOLDER, f"report_{os.path.basename(file_path)}_{int(time.time())}.txt")
    try:
        with open(report_file, 'w') as report:
            report.write(f"Suspicious Activity Report for {file_path}\n")
            report.write(f"Generated on: {datetime.now()}\n\n")
            report.write("Entry Occurrences:\n")
            for entry, count in entry_counts.items():
                report.write(f"{entry} - Occurrences: {count}\n")
        logging.info(f"Report generated: {report_file}")
    except Exception as e:
        logging.error(f"Error writing report for {file_path}: {e}")

def monitor_logs(log_directory, interval=60, recipient_email=None, send_daily_email=False):
    while True:
        all_suspicious_entries = []
        try:
            for filename in os.listdir(log_directory):
                file_path = os.path.join(log_directory, filename)
                if file_path not in processed_files and os.path.isfile(file_path):
                    logging.info(f"Scanning log file: {file_path}")
                    suspicious_entries = scan_log_file(file_path)
                    alert_terminal(suspicious_entries)
                    generate_report(file_path, suspicious_entries)
                    update_daily_summary(suspicious_entries)
                    all_suspicious_entries.extend(suspicious_entries)
                    processed_files.add(file_path)
        except Exception as e:
            logging.error(f"Error monitoring logs: {e}")

        if send_daily_email and all_suspicious_entries and recipient_email:
            excel_file = generate_daily_excel(all_suspicious_entries)
            send_email_with_excel(
                excel_file,
                recipient_email,
                sender_email="your_email@gmail.com",
                sender_password="your_app_password"
            )

        time.sleep(interval)

def main():
    print("Starting Silent Sentinel Log Monitor...")
    recipient_email = get_user_email()
    for filename in os.listdir(LOG_FOLDER):
        file_path = os.path.join(LOG_FOLDER, filename)
        if os.path.isfile(file_path):
            logging.info(f"Initial scan of log file: {file_path}")
            suspicious_entries = scan_log_file(file_path)
            alert_terminal(suspicious_entries)
            generate_report(file_path, suspicious_entries)
            update_daily_summary(suspicious_entries)
            processed_files.add(file_path)
    monitor_logs(LOG_FOLDER, interval=60, recipient_email=recipient_email, send_daily_email=True)

if __name__ == "__main__":
    main()
