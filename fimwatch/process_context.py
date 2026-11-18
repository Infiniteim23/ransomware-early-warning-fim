import json
import os
import psutil

def process_snapshot(max_items=8):
    # Best-effort context only; this is not forensic process attribution.
    items = []
    try:
        me = psutil.Process(os.getpid())
        items.append({
            "pid": me.pid,
            "name": me.name(),
            "cmdline": me.cmdline()[:12],
            "username": me.username(),
        })
    except Exception:
        pass

    try:
        for p in psutil.process_iter(["pid", "name", "username", "cmdline", "create_time"]):
            if len(items) >= max_items:
                break
            try:
                if p.info["pid"] == os.getpid():
                    continue
                items.append({
                    "pid": p.info.get("pid"),
                    "name": p.info.get("name"),
                    "username": p.info.get("username"),
                    "cmdline": (p.info.get("cmdline") or [])[:12],
                    "create_time": p.info.get("create_time"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return items

def json_snapshot(max_items=8):
    return json.dumps(process_snapshot(max_items), default=str)
