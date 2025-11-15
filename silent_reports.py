import os
from datetime import datetime
import logging
import pandas as pd
from email.message import EmailMessage
import smtplib
import ssl

report_folder = "reports"
log_folder = "logs"

def get_user_email():
    email_file = "user_email.txt"
    if os.path.exists(email_file):
        with open(email_file, 'r') as f:
            email = f.read().strip()
            return email if email else None
    else:
        email = input("Enter your email address for report delivery: ").strip()
        with open(email_file, 'w') as f:
            f.write(email)
        return email

def setup_logging():
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)
    log_filename = os.path.join(log_folder, f"report_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    logging.basicConfig(
        filename=log_filename,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return log_filename

def generate_daily_excel(suspicious_entries):
    if not os.path.exists(report_folder):
        os.makedirs(report_folder)

    report_filename = os.path.join(report_folder, f"suspicious_report_{datetime.now().strftime('%Y%m%d')}.xlsx")

    # suspicious_entries should be a list of dictionaries or a DataFrame-ready structure
    if suspicious_entries:
        df = pd.DataFrame(suspicious_entries)
        if os.path.exists(report_filename):
            # Append to existing file if it exists
            existing_df = pd.read_excel(report_filename)
            df = pd.concat([existing_df, df], ignore_index=True)
        df.to_excel(report_filename, index=False)

    return report_filename

def send_email_with_excel(report_filename, recipient_email, sender_email, sender_password):
    msg = EmailMessage()
    msg['Subject'] = f"Silent Sentinel Daily Log: {os.path.basename(report_filename)}"
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg.set_content("Attached is your daily suspicious activity summary.")

    with open(report_filename, 'rb') as f:
        file_data = f.read()
        file_name = os.path.basename(report_filename)
    msg.add_attachment(file_data, maintype='application', subtype='vnd.openxmlformats-officedocument.spreadsheetml.sheet', filename=file_name)

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(sender_email, sender_password)
            smtp.send_message(msg)
        print(f"Daily log emailed to {recipient_email}")
    except Exception as e:
        logging.error(f"Failed to send daily email: {e}")
