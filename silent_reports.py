import os
import pandas as pd
from datetime import date
from silent_db import fetch_daily_entries
from email.message import EmailMessage
import smtplib
import ssl
import logging
import json

# Load email config
with open("config.json", "r") as config_file:
    config = json.load(config_file)

REPORT_FOLDER = config.get("report_folder", "reports")
EMAIL_CONFIG = config.get("email_notifications", {})

os.makedirs(REPORT_FOLDER, exist_ok=True)

def generate_daily_excel(daily_entries=None, target_date=date.today()):
    """
    Generates a daily Excel report of suspicious entries.
    If daily_entries is None, fetch from DB for target_date.
    Returns the file path of the Excel report.
    """
    if daily_entries is None:
        daily_entries = fetch_daily_entries(target_date)

    if not daily_entries:
        logging.info("No suspicious entries for today; skipping Excel generation.")
        return None

    report_filename = os.path.join(REPORT_FOLDER, f"suspicious_report_{target_date.strftime('%Y%m%d')}.xlsx")

    # Convert to DataFrame
    df = pd.DataFrame(daily_entries, columns=["log_file", "entry", "detected_at"])

    # Append if file exists
    if os.path.exists(report_filename):
        existing_df = pd.read_excel(report_filename)
        df = pd.concat([existing_df, df], ignore_index=True)

    df.to_excel(report_filename, index=False)
    logging.info(f"Daily Excel report generated: {report_filename}")
    return report_filename

def send_email_with_excel(report_filename):
    """
    Sends an email with the daily Excel report attached.
    """
    if not EMAIL_CONFIG.get("enabled", False):
        logging.info("Email notifications are disabled in config.")
        return

    sender_email = EMAIL_CONFIG.get("username")
    sender_password = EMAIL_CONFIG.get("password")
    recipient_email = EMAIL_CONFIG.get("recipient")
    smtp_server = EMAIL_CONFIG.get("smtp_server", "smtp.gmail.com")
    smtp_port = EMAIL_CONFIG.get("smtp_port", 465)

    if not (sender_email and sender_password and recipient_email):
        logging.error("Email credentials or recipient not provided; cannot send email.")
        return

    msg = EmailMessage()
    msg["Subject"] = f"Silent Sentinel Daily Log: {os.path.basename(report_filename)}"
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg.set_content("Attached is your daily suspicious activity summary.")

    with open(report_filename, "rb") as f:
        file_data = f.read()
        file_name = os.path.basename(report_filename)
    msg.add_attachment(
        file_data,
        maintype="application",
        subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=file_name
    )

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as smtp:
            smtp.login(sender_email, sender_password)
            smtp.send_message(msg)
        logging.info(f"Daily log emailed to {recipient_email}")
    except Exception as e:
        logging.error(f"Failed to send daily email: {e}")
    return report_filename