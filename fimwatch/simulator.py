from pathlib import Path

def prepare_lab(path, count=30):
    root = Path(path).resolve()
    root.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        p = root / f"document_{i:04d}.txt"
        p.write_text(
            f"LAB DATA ONLY\nRecord: {i}\nDisposable test content.\n",
            encoding="utf-8"
        )
    return root

def simulate(path, files=80, burst=2.0):
    """
    Safe ransomware-like behavior simulation.
    Only operates below `path`; no encryption or destructive deletion.
    """
    root = Path(path).resolve()
    root.mkdir(parents=True, exist_ok=True)
    prepare_lab(root, max(10, files))
    targets = sorted(root.glob("document_*.txt"))[:files]

    for p in targets:
        p.write_text(
            p.read_text(encoding="utf-8") +
            "SIMULATED MASS-MODIFICATION EVENT\n",
            encoding="utf-8"
        )

    for p in targets:
        new = p.with_suffix(".locked.TEST")
        if p.exists():
            p.rename(new)

    print(f"[SIMULATION] {len(targets)} files modified/renamed.")
    print("[SIMULATION] No encryption or destructive deletion performed.")
