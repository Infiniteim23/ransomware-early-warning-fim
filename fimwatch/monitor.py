import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .hashutil import sha256_file, safe_stat

class Handler(FileSystemEventHandler):
    def __init__(self, db, detector, cfg):
        super().__init__()
        self.db, self.detector, self.cfg = db, detector, cfg

    def _record(self, event_type, path, old_path=None, is_directory=False):
        ts = time.time()
        p = Path(path)
        st = safe_stat(path)
        size = st.st_size if st and p.is_file() else None
        digest = None
        if st and p.is_file():
            try:
                digest = sha256_file(path, self.cfg.hash_chunk_size)
            except (PermissionError, OSError):
                pass

        event = {
            "ts": ts, "event_type": event_type, "path": str(path),
            "old_path": str(old_path) if old_path else None,
            "is_directory": is_directory, "size": size, "sha256": digest
        }
        self.db.add_event(
            ts, event_type, str(path), str(old_path) if old_path else None,
            is_directory, size, digest
        )
        alert = self.detector.observe(event)
        if alert:
            print("[ALERT] {} score={}: {}".format(
                alert["severity"], alert["score"], " | ".join(alert["reasons"])
            ))

    def on_created(self, event):
        self._record("created", event.src_path, is_directory=event.is_directory)

    def on_modified(self, event):
        self._record("modified", event.src_path, is_directory=event.is_directory)

    def on_deleted(self, event):
        self._record("deleted", event.src_path, is_directory=event.is_directory)

    def on_moved(self, event):
        self._record("moved", event.dest_path, event.src_path, event.is_directory)

def monitor(path, db, detector, cfg):
    target = str(Path(path).resolve())
    observer = Observer()
    observer.schedule(Handler(db, detector, cfg), target, recursive=True)
    observer.start()
    print(f"[+] Monitoring: {target}")
    print("[+] Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
