#!/usr/bin/env python3
"""
QSB GPU Search Wrapper
======================

Thin wrapper around the current qsb_search binary.
Works with the export files produced by pipeline/qsb_pipeline.py.

Usage:
  python3 run_search.py bench-pinning
  python3 run_search.py bench-digest
  python3 run_search.py pinning --params ../pinning.bin --start-seq 0 --num-seqs 1 --easy
  python3 run_search.py digest --params ../digest_r1.bin --start 0 --end 100000 --easy
"""

import argparse
import os
import subprocess
import sys


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
QSB_SEARCH_BIN = os.path.join(SCRIPT_DIR, "qsb_search")


def require_binary():
    if os.path.exists(QSB_SEARCH_BIN):
        return
    raise SystemExit(
        f"qsb_search not found at {QSB_SEARCH_BIN}. Run `make` in {SCRIPT_DIR} first."
    )


def run_cmd(args):
    require_binary()
    cmd = [QSB_SEARCH_BIN] + args
    print("Running:", " ".join(cmd))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main():
    parser = argparse.ArgumentParser(description="QSB GPU search wrapper")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("bench-pinning", help="Run qsb_search bench_pinning")
    sub.add_parser("bench-digest", help="Run qsb_search bench_digest")

    p_pin = sub.add_parser("pinning", help="Run pinning search on an exported pinning.bin")
    p_pin.add_argument("--params", default="../pinning.bin", help="Path to pinning.bin")
    p_pin.add_argument("--start-seq", type=int, default=0, help="Inclusive starting sequence")
    p_pin.add_argument("--num-seqs", type=int, default=1, help="Number of sequences to search")
    p_pin.add_argument("--easy", action="store_true", help="Enable easy DER mode")

    p_digest = sub.add_parser("digest", help="Run digest search on an exported digest_r*.bin")
    p_digest.add_argument("--params", required=True, help="Path to digest_r1.bin or digest_r2.bin")
    p_digest.add_argument("--start", type=int, required=True, help="Inclusive first-index start")
    p_digest.add_argument("--end", type=int, required=True, help="Exclusive first-index end")
    p_digest.add_argument("--easy", action="store_true", help="Enable easy DER mode")

    args = parser.parse_args()

    if args.command == "bench-pinning":
        run_cmd(["bench_pinning"])
    elif args.command == "bench-digest":
        run_cmd(["bench_digest"])
    elif args.command == "pinning":
        cmd = ["pinning", args.params, str(args.start_seq), str(args.num_seqs)]
        if args.easy:
            cmd.append("easy")
        run_cmd(cmd)
    elif args.command == "digest":
        cmd = ["digest", args.params, str(args.start), str(args.end)]
        if args.easy:
            cmd.append("easy")
        run_cmd(cmd)
    else:
        parser.print_help()
        raise SystemExit(1)


if __name__ == "__main__":
    main()
