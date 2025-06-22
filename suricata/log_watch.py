import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import subprocess
import os

LOG_FILE = "/var/log/suricata/eve.json"

class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == LOG_FILE:
            print("[WATCHDOG] Alteração no eve.json detectada.")
            subprocess.run(["python3", "/app/alg_dosDetect.py"])

if __name__ == "__main__":
    print("[WATCHDOG] Iniciado, a monitorizar eve.json...")
    event_handler = LogHandler()
    observer = Observer()
    observer.schedule(event_handler, path="/var/log/suricata", recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
