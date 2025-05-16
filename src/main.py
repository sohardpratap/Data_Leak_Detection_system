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
    modify_file('data/cloud_storage/confidential/sensitive_data.txt', 'Potential data leak: confidential information')

    # Test access controls (modify a read-only file)
    modify_file('data/cloud_storage/documents/file1.txt', 'Attempt to modify read-only file')

    # Additional normal access
    read_file('data/cloud_storage/documents/file2.txt')
    modify_file('data/cloud_storage/confidential/top_secret.txt', 'Updated top-secret content')

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
