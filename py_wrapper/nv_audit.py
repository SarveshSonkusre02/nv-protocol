import os
import json
import datetime
import threading

class AuditLogger:
    def __init__(self, log_path=None):
        if log_path is None:
            home_dir = os.path.expanduser("~")
            log_path = os.path.join(home_dir, ".nv", "audit.log")
        self.log_path = log_path
        self.lock = threading.Lock()
        
        try:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        except Exception:
            pass

    def log(self, key, host, method, path, pid, process_name, status, message):
        event = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "key": key,
            "host": host,
            "method": method,
            "path": path,
            "pid": pid,
            "process_name": process_name,
            "status": status,
            "message": message
        }
        
        with self.lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
            except Exception as e:
                import sys
                print(f"Warning: Failed to write to audit log: {e}", file=sys.stderr)
