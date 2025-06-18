import os
from data_leak_detection import read_file , modify_file , scan_for_patterns
from event_handler import MyHandler
from watchdog.observers import Observer

def main():
    # Example usage
    read_file('data/cloud_storage/documents/file1.txt')
    modify_file('data/cloud_storage/confidential/secret.docx', 'New confidential content')

    # Simulate scanning for data leak patterns
    scan_for_patterns('data/cloud_storage')

    # Simulate an event that triggers an alert (modify a file with a potential data leak pattern)
    sensitive_file_path = 'data/cloud_storage/confidential/sensitive_data.txt'
    if not os.path.exists(sensitive_file_path):
        os.makedirs(os.path.dirname(sensitive_file_path), exist_ok=True)
        open(sensitive_file_path, 'w').close()  # Create empty file
    modify_file(sensitive_file_path, 'Potential data leak: confidential information')

    # Test access controls (modify a read-only file)
    modify_file('data/cloud_storage/documents/file1.txt', 'Attempt to modify read-only file')

    # Additional normal access
    file2_path = 'data/cloud_storage/documents/file2.txt'
    if not os.path.exists(file2_path):
        os.makedirs(os.path.dirname(file2_path), exist_ok=True)
        open(file2_path, 'w').close()  # Create empty file
    read_file(file2_path)

    top_secret_file_path = 'data/cloud_storage/confidential/top_secret.txt'
    if not os.path.exists(top_secret_file_path):
        os.makedirs(os.path.dirname(top_secret_file_path), exist_ok=True)
        open(top_secret_file_path, 'w').close()  # Create empty file
    modify_file(top_secret_file_path, 'Updated top-secret content')

    # Simulate file system event monitoring
    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, path='data/cloud_storage', recursive=True)
    observer.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
