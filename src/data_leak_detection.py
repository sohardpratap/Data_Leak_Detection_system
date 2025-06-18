import os
import sqlite3
import logging
import re
from watchdog.observers import Observer
from event_handler import MyHandler
import docx

# Configure logging
logging.basicConfig(
    filename='logs/data_leak_detection.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

DATABASE_PATH = 'database/data_metadata.db'

def initialize_database():
    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    # Create a table to store metadata
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            access_count INTEGER DEFAULT 0,
            UNIQUE(file_path)
        )
    ''')

    connection.commit()
    connection.close()

def log_access(file_path):
    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    # Update access count
    cursor.execute('''
        INSERT OR IGNORE INTO file_metadata (file_path) VALUES (?)
    ''', (file_path,))
    cursor.execute('''
        UPDATE file_metadata SET access_count = access_count + 1 WHERE file_path = ?
    ''', (file_path,))

    connection.commit()
    connection.close()

def log_event(event_type, file_path):
    log_message = f"{event_type.upper()} event: {file_path}"
    if event_type.lower() == 'alert':
        log_message += " (ALERT! Potential data leak detected)"
        # Simulate sending alerts (you can customize this based on your preferred notification mechanism)

    logging.info(log_message)
    print(log_message)

def read_file(file_path):
    try:
        # Check access controls (e.g., file permissions)
        if os.access(file_path, os.R_OK):
            with open(file_path, 'r') as file:
                content = file.read()
                print(f"Read content from {file_path}:\n{content}")
                log_event('access', file_path)
                log_access(file_path)
        else:
            print(f"Access denied. Unable to read file: {file_path}")
            log_event('access_denied', file_path)
    except FileNotFoundError:
        print(f"File not found: {file_path}")

def modify_file(file_path, new_content):
    try:
        # Check access controls (e.g., file permissions)
        if os.access(file_path, os.W_OK):
            with open(file_path, 'w') as file:
                file.write(new_content)
                print(f"Modified content of {file_path}")
                log_event('modify', file_path)
                log_access(file_path)
        else:
            print(f"Access denied. Unable to modify file: {file_path}")
            log_event('access_denied', file_path)
    except FileNotFoundError:
        print(f"File not found: {file_path}")

# def scan_for_patterns(directory):
#     for root, dirs, files in os.walk(directory):
#         for file_name in files:
#             file_path = os.path.join(root, file_name)

#             try:
#                 with open(file_path, 'r') as file:
#                     content = file.read()

#                     # Check for data leak patterns
#                     leak_patterns = ["confidential", r"\b\d{16}\b", "password"]  # Add your patterns here
#                     for pattern in leak_patterns:
#                         matches = re.finditer(pattern, content, re.IGNORECASE)
#                         for match in matches:
#                             start, end = match.span()
#                             matched_text = match.group()
#                             alert_message = f"Potential data leak pattern detected in {file_path}: {pattern} ({matched_text})"
#                             log_event('alert', alert_message)

#             except FileNotFoundError:
#                 print(f"File not found: {file_path}")


def scan_for_patterns(directory):
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)

            try:
                content = ""  # Initialize content to ensure it's always defined
                if file_path.endswith('.docx'):
                    try:
                        doc = docx.Document(file_path)
                        content = '\n'.join([paragraph.text for paragraph in doc.paragraphs])
                    except Exception as e:
                        print(f"Error processing DOCX file {file_path}: {e}")
                        # content remains "" as initialized or could use 'continue'
                else:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                        content = file.read()

                # Check for data leak patterns
                leak_patterns = ["confidential", r"\b\d{16}\b", "password"]  # Add your patterns here
                for pattern in leak_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        start, end = match.span()
                        matched_text = match.group()
                        alert_message = f"Potential data leak pattern detected in {file_path}: {pattern} ({matched_text})"
                        log_event('alert', alert_message)

            except FileNotFoundError as e:
                print(e)
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")

# Initialize the database
initialize_database()
