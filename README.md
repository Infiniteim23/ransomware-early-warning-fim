# Ransomware Early-Warning & File Integrity Monitoring

A safe endpoint-monitoring prototype for an isolated test environment.

## Features
- Real-time create/modify/delete/rename monitoring.
- SHA-256 file-integrity baseline and verification.
- Burst/anomaly detection using multiple signals.
- Best-effort process context using psutil.
- SQLite evidence store.
- Streamlit SOC-style dashboard.
- Non-destructive ransomware-behavior simulator.

## Safe demo

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m fimwatch.cli init-lab --path ./lab_data --files 60
python -m fimwatch.cli baseline --path ./lab_data
python -m fimwatch.cli monitor --path ./lab_data
```

In another terminal:
```bash
python -m fimwatch.cli simulate --path ./lab_data --files 60
python -m fimwatch.cli verify --path ./lab_data
```

Dashboard:
```bash
streamlit run dashboard.py
```

## Safety
The simulator only operates below the supplied lab directory. It does not encrypt,
destroy, exfiltrate, persist, disable security controls, or touch arbitrary files.
Use a disposable directory or VM.

## Production upgrade path
Python watchdog is suitable for a prototype. Production telemetry should use
OS-native sources such as Windows ETW/Sysmon/EDR, Linux fanotify/inotify plus
audit/eBPF/EDR, or macOS Endpoint Security. Process attribution in this prototype
is explicitly best-effort and is not forensic proof.

## Detection signals
- file-event burst
- number of unique files
- delete/rename ratio
- extension-changing renames
- very high event volume
- SHA-256 baseline mismatch

Alerts are scored rather than triggered by a single rule to reduce false positives.

## Response recommendations
1. Isolate the endpoint using approved EDR/network controls.
2. Preserve logs and evidence.
3. Identify the responsible process/account.
4. Stop or quarantine the suspicious process through approved controls.
5. Protect backups.
6. Verify backups before restoration.
7. Restore to a clean system.
8. Re-run integrity verification.
9. Document the timeline.

The prototype does not perform destructive automatic containment.
