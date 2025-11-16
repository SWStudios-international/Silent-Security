import sqlite3
from datetime import datetime, date, time
import os

db_file = "silent_sentinel.db"

def init_db(db_file=db_file):
    # Create parent directory if needed
    if os.path.dirname(db_file):
        os.makedirs(os.path.dirname(db_file), exist_ok=True)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Table for processed logs
    cursor.execute(''' 
        CREATE TABLE IF NOT EXISTS processed_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            processed_at TIMESTAMP NOT NULL
        )
    ''')

    # Table for suspicious entries
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS suspicious_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_file TEXT NOT NULL,
            entry TEXT NOT NULL,
            detected_at TIMESTAMP NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

def add_suspicious_entry(log_file, entry, db_file=db_file):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO suspicious_entries (log_file, entry, detected_at)
        VALUES (?, ?, ?)
    ''', (log_file, entry, datetime.now()))
    conn.commit()
    conn.close()

def mark_file_processed(file_name, db_file=db_file):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO processed_logs (file_name, processed_at)
        VALUES (?, ?)
    ''', (file_name, datetime.now()))
    conn.commit()
    conn.close()

def is_file_processed(file_name, db_file=db_file):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT COUNT(*) FROM processed_logs WHERE file_name = ?
    ''', (file_name,))
    result = cursor.fetchone()
    conn.close()
    return result[0] > 0 

def fetch_daily_entries(target_date=date.today(), db_file=db_file):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    start_dt = datetime.combine(target_date, time.min)
    end_dt = datetime.combine(target_date, time.max)
    cursor.execute('''
        SELECT log_file, entry, detected_at FROM suspicious_entries
        WHERE detected_at BETWEEN ? AND ?
    ''', (start_dt, end_dt))
    entries = cursor.fetchall()
    conn.close()
    return entries
####Prototype v1.05####