import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    event_type TEXT NOT NULL,
    path TEXT NOT NULL,
    old_path TEXT,
    is_directory INTEGER NOT NULL DEFAULT 0,
    size INTEGER,
    sha256 TEXT,
    process_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    reason TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    unique_files INTEGER NOT NULL,
    affected_paths TEXT,
    process_json TEXT
);

CREATE TABLE IF NOT EXISTS baseline (
    path TEXT PRIMARY KEY,
    size INTEGER,
    mtime_ns INTEGER,
    sha256 TEXT NOT NULL,
    captured_ts REAL NOT NULL
);
"""

class Database:
    def __init__(self, path="fimwatch.db"):
        self.path = str(Path(path))
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def add_event(self, ts, event_type, path, old_path=None,
                  is_directory=False, size=None, sha256=None, process_json=None):
        self.conn.execute(
            """INSERT INTO events
            (ts,event_type,path,old_path,is_directory,size,sha256,process_json)
            VALUES(?,?,?,?,?,?,?,?)""",
            (ts, event_type, path, old_path, int(is_directory),
             size, sha256, process_json)
        )
        self.conn.commit()

    def add_alert(self, ts, severity, score, reason, event_count,
                  unique_files, affected_paths, process_json=None):
        self.conn.execute(
            """INSERT INTO alerts
            (ts,severity,score,reason,event_count,unique_files,affected_paths,process_json)
            VALUES(?,?,?,?,?,?,?,?)""",
            (ts, severity, score, reason, event_count, unique_files,
             affected_paths, process_json)
        )
        self.conn.commit()

    def set_baseline(self, rows):
        self.conn.execute("DELETE FROM baseline")
        self.conn.executemany(
            "INSERT INTO baseline(path,size,mtime_ns,sha256,captured_ts) VALUES(?,?,?,?,?)",
            list(rows)
        )
        self.conn.commit()

    def fetch_events(self, limit=500):
        return self.conn.execute(
            """SELECT id,ts,event_type,path,old_path,is_directory,size,sha256,process_json
            FROM events ORDER BY ts DESC LIMIT ?""", (limit,)
        ).fetchall()

    def fetch_alerts(self, limit=200):
        return self.conn.execute(
            """SELECT id,ts,severity,score,reason,event_count,unique_files,affected_paths,process_json
            FROM alerts ORDER BY ts DESC LIMIT ?""", (limit,)
        ).fetchall()

    def fetch_baseline(self):
        return self.conn.execute(
            "SELECT path,size,mtime_ns,sha256,captured_ts FROM baseline ORDER BY path"
        ).fetchall()
