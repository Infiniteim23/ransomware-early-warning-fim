import time
from pathlib import Path
from .hashutil import sha256_file

def build_baseline(root, db, chunk_size=1024*1024):
    root = Path(root).resolve()
    rows = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            st = path.stat()
            digest = sha256_file(str(path), chunk_size)
            rows.append((str(path), st.st_size, st.st_mtime_ns, digest, time.time()))
        except (PermissionError, OSError):
            continue
    db.set_baseline(rows)
    return len(rows)

def verify_baseline(db, root, chunk_size=1024*1024):
    baseline = {row[0]: row for row in db.fetch_baseline()}
    current = {}
    root = Path(root).resolve()

    for path in root.rglob("*"):
        if path.is_file():
            try:
                st = path.stat()
                current[str(path)] = (
                    str(path), st.st_size, st.st_mtime_ns,
                    sha256_file(str(path), chunk_size), time.time()
                )
            except (PermissionError, OSError):
                pass

    changed, missing, new = [], [], []
    for p, row in baseline.items():
        if p not in current:
            missing.append(p)
        elif current[p][3] != row[3]:
            changed.append(p)
    for p in current:
        if p not in baseline:
            new.append(p)

    return {
        "changed": changed, "missing": missing, "new": new,
        "baseline_count": len(baseline), "current_count": len(current)
    }
