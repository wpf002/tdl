#!/usr/bin/env python3
"""Regenerate each rule's Splunk SPL from its pseudo_logic (SPL specialist agent).

Writes results to exports/regen_spl.json ({rule_id: {spl, cost}}) so they can be
validated in the test-lab BEFORE any write-back to the rule YAML. Hard --max-cost
cap; resumable via --resume.

    ANTHROPIC_API_KEY=... python -m tools.regen_spl --max-cost 13 --workers 6
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
OUT = ROOT / "exports" / "regen_spl.json"


def load_rules():
    out = []
    for p in sorted(RULES_DIR.rglob("*.yaml")):
        try:
            d = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(d, dict) and d.get("rule_id"):
            out.append(d)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-cost", type=float, default=13.0)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--resume", action="store_true", help="Skip rules already in regen_spl.json")
    ap.add_argument("--limit", type=int)
    args = ap.parse_args()

    from tools.agents import get_agent
    spl = get_agent("spl")

    existing = {}
    if OUT.exists():
        try:
            existing = json.loads(OUT.read_text())
        except json.JSONDecodeError:
            existing = {}

    rules = load_rules()
    if args.resume:
        rules = [r for r in rules if r["rule_id"] not in existing]
    if args.limit:
        rules = rules[: args.limit]
    if not rules:
        print("Nothing to do.")
        return 0

    lock = threading.Lock()
    run_cost = [0.0]
    done = [0]
    stop = threading.Event()

    def save():
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(existing, indent=2))

    def work(r):
        if stop.is_set():
            return None  # past the cap — no API call, no cost
        res = spl.generate_query(r.get("pseudo_logic"), r.get("tactic"),
                                 r.get("technique_id"), r.get("platform"), r.get("data_sources"))
        return r["rule_id"], res["query"], float(res["usage"]["cost_usd"])

    print(f"Regenerating SPL for {len(rules)} rules · cap ${args.max_cost:.2f} · {args.workers} workers\n")
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(work, r) for r in rules]
        for f in as_completed(futs):
            try:
                res = f.result()
            except Exception as e:
                print(f"  ✗ {type(e).__name__}: {str(e)[:80]}", file=sys.stderr)
                continue
            if not res:
                continue
            rid, q, c = res
            with lock:
                existing[rid] = {"spl": q, "cost": round(c, 6)}
                run_cost[0] += c
                done[0] += 1
                if done[0] % 25 == 0:
                    save()
                    print(f"  … {done[0]} done · ${run_cost[0]:.2f}")
                if run_cost[0] >= args.max_cost and not stop.is_set():
                    stop.set()
                    print(f"\n  ✋ CAP ${args.max_cost:.2f} reached at {done[0]} rules — stopping (resume later).")
    save()
    print(f"\nDone: {done[0]} SPL regenerated this run · ${run_cost[0]:.2f} · total in file: {len(existing)}")
    print(f"Report: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
