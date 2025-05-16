import os
import logging

class MyHandler:
    def on_created(self, event):
        file_path = event.src_path
        log_event('created', file_path)

    def on_modified(self, event):
        file_path = event.src_path
        log_event('modified', file_path)

    def on_deleted(self, event):
        file_path = event.src_path
        log_event('deleted', file_path)

def log_event(event_type, file_path):
    log_message = f"{event_type.upper()} event: {file_path}"
    if event_type.lower() == 'alert':
        log_message += " (ALERT! Potential data leak detected)"
        # Simulate sending alerts (customize based on your preferred notification mechanism)

    logging.info(log_message)
    print(log_message)
