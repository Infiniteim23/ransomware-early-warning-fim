import argparse
from .config import Config
from .db import Database
from .baseline import build_baseline, verify_baseline
from .detector import Detector
from .monitor import monitor
from .process_context import json_snapshot
from .simulator import prepare_lab, simulate

def main():
    parser = argparse.ArgumentParser(description="Safe ransomware early-warning + FIM prototype")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init-lab"); p.add_argument("--path", required=True); p.add_argument("--files", type=int, default=30)
    p = sub.add_parser("baseline"); p.add_argument("--path", required=True); p.add_argument("--db", default="fimwatch.db")
    p = sub.add_parser("verify"); p.add_argument("--path", required=True); p.add_argument("--db", default="fimwatch.db")
    p = sub.add_parser("monitor"); p.add_argument("--path", required=True); p.add_argument("--db", default="fimwatch.db")
    p = sub.add_parser("simulate"); p.add_argument("--path", required=True); p.add_argument("--files", type=int, default=80)

    args = parser.parse_args()
    cfg = Config()

    if args.cmd == "init-lab":
        print("[+] Lab:", prepare_lab(args.path, args.files)); return

    db = Database(args.db) if hasattr(args, "db") else Database()

    if args.cmd == "baseline":
        print("[+] Baseline captured:", build_baseline(args.path, db, cfg.hash_chunk_size), "files"); return

    if args.cmd == "verify":
        r = verify_baseline(db, args.path, cfg.hash_chunk_size)
        print(f"Baseline={r['baseline_count']} Current={r['current_count']} Changed={len(r['changed'])} Missing={len(r['missing'])} New={len(r['new'])}")
        for k in ("changed", "missing", "new"):
            if r[k]:
                print("\n[" + k.upper() + "]\n" + "\n".join(r[k][:50]))
        return

    if args.cmd == "monitor":
        monitor(args.path, db, Detector(cfg, db, json_snapshot), cfg); return

    if args.cmd == "simulate":
        simulate(args.path, args.files); return

if __name__ == "__main__":
    main()
