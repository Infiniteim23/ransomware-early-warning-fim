from collections import deque
from pathlib import Path

class Detector:
    def __init__(self, config, db, process_context_fn):
        self.cfg = config
        self.db = db
        self.process_context_fn = process_context_fn
        self.events = deque()

    def observe(self, event):
        now = event["ts"]
        self.events.append(event)
        cutoff = now - self.cfg.burst_window_seconds
        while self.events and self.events[0]["ts"] < cutoff:
            self.events.popleft()

        recent = list(self.events)
        file_events = [e for e in recent if not e["is_directory"]]
        unique = {e["path"] for e in file_events}
        destructive = sum(e["event_type"] in ("deleted", "moved") for e in file_events)
        extension_changes = sum(
            1 for e in file_events
            if e["event_type"] == "moved"
            and e.get("old_path")
            and Path(e["old_path"]).suffix.lower() != Path(e["path"]).suffix.lower()
        )

        score = 0
        reasons = []

        if len(file_events) >= self.cfg.burst_event_threshold:
            score += 30
            reasons.append(f"{len(file_events)} file events in {self.cfg.burst_window_seconds}s")
        if len(unique) >= self.cfg.unique_file_threshold:
            score += 25
            reasons.append(f"{len(unique)} unique files touched")
        ratio = destructive / max(1, len(file_events))
        if ratio >= self.cfg.delete_rename_ratio_threshold:
            score += 20
            reasons.append(f"high delete/rename ratio ({ratio:.0%})")
        if extension_changes >= self.cfg.extension_change_threshold:
            score += 30
            reasons.append(f"{extension_changes} extension-changing renames")
        if len(file_events) >= self.cfg.high_burst_threshold:
            score += 25
            reasons.append("very high activity burst")

        severity = "LOW" if score < 30 else "MEDIUM" if score < 55 else "HIGH" if score < 80 else "CRITICAL"

        if score >= 55:
            paths = [e["path"] for e in file_events[-50:]]
            proc = self.process_context_fn(self.cfg.max_process_candidates)
            self.db.add_alert(
                now, severity, score, "; ".join(reasons),
                len(file_events), len(unique), "\n".join(paths), proc
            )
            return {"severity": severity, "score": score, "reasons": reasons}
        return None
