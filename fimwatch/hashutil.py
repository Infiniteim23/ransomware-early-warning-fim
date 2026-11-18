import hashlib
from pathlib import Path

def sha256_file(path, chunk_size=1024*1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def safe_stat(path):
    try:
        return Path(path).stat()
    except (FileNotFoundError, PermissionError, OSError):
        return None
