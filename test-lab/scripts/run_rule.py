#!/usr/bin/env python3
"""Run TDL detection rules (their SPL) against the lab Splunk and report hits.

This is the payoff: point your rules at REAL logs and see which actually fire —
surfacing field-name/logic mismatches that a synthetic check can't.

    pip install requests pyyaml
    python run_rule.py TDL-CA-000019            # one rule
    python run_rule.py --all --limit 50         # first 50 rules, hit summary
    python run_rule.py --tactic credential-access
Env (defaults target this repo's docker-compose):
    SPLUNK_URL   (default https://localhost:8089)
    SPLUNK_USER  (default admin)
    SPLUNK_PASSWORD (default tdl-splunk-lab)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import urllib3
import yaml
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "rules"
URL = os.environ.get("SPLUNK_URL", "https://localhost:8089")
AUTH = (os.environ.get("SPLUNK_USER", "admin"), os.environ.get("SPLUNK_PASSWORD", "tdl-splunk-lab"))


def load_rules(tactic=None, rule_id=None):
    base = RULES_DIR / tactic if tactic else RULES_DIR
    out = []
    for p in sorted(base.rglob("*.yaml")):
        try:
            d = yaml.safe_load(p.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(d, dict):
            continue
        if rule_id and d.get("rule_id") != rule_id:
            continue
        spl = (d.get("queries") or {}).get("spl")
        if spl:
            out.append((d.get("rule_id"), d.get("name"), spl))
    return out


def run_spl(spl: str) -> tuple[int, str]:
    """Oneshot search over all time. Returns (result_count, error)."""
    search = spl.strip()
    # Normalize any hardcoded index (index=windows, index=network, …) to index=*
    # so a rule is tested against the lab data regardless of the index name it
    # assumes. (Hardcoded indexes not matching your deployment is itself a common
    # rule bug — worth fixing in the library separately.)
    search = re.sub(r'\bindex\s*=\s*"?[\w*-]+"?', 'index=*', search, flags=re.IGNORECASE)
    if not search.lower().startswith(("search ", "|")):
        search = "search " + search
    try:
        r = requests.post(
            f"{URL}/services/search/jobs", auth=AUTH, verify=False, timeout=120,
            data={"search": search, "exec_mode": "oneshot", "output_mode": "json",
                  "earliest_time": "0", "latest_time": "now", "count": "0"},
        )
    except requests.RequestException as e:
        return -1, f"{type(e).__name__}: {e}"
    if r.status_code >= 300:
        return -1, f"HTTP {r.status_code}: {r.text[:160]}"
    try:
        return len(r.json().get("results", [])), ""
    except Exception as e:
        return -1, f"parse: {e}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rule_id", nargs="?")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--tactic")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--workers", type=int, default=6, help="Parallel searches (default 6)")
    ap.add_argument("--quiet", action="store_true", help="Only print fired/errored + summary")
    ap.add_argument("--spl-from", help="JSON {rule_id: {spl}} to test instead of the YAML SPL (e.g. exports/regen_spl.json)")
    args = ap.parse_args()

    rules = load_rules(tactic=args.tactic, rule_id=args.rule_id)
    if args.spl_from:
        override = json.loads(Path(args.spl_from).read_text())
        rules = [(rid, name, (override.get(rid) or {}).get("spl") or spl)
                 for (rid, name, spl) in rules]
    if args.limit:
        rules = rules[: args.limit]
    if not rules:
        sys.exit("No matching rules with an SPL query.")

    print(f"Running {len(rules)} rule(s) against {URL} with {args.workers} workers …\n")
    fired = errored = 0
    done = 0

    def work(rule):
        rid, name, spl = rule
        n, err = run_spl(spl)
        return rid, name, n, err

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        for rid, name, n, err in (f.result() for f in as_completed(
                pool.submit(work, r) for r in rules)):
            done += 1
            if err:
                errored += 1
                print(f"  ⚠ {rid:<20} ERROR  {err[:70]}")
            elif n > 0:
                fired += 1
                print(f"  ✓ {rid:<20} {n:>5} hits  {name[:48]}")
            elif not args.quiet:
                print(f"  · {rid:<20} {'0':>5} hits  {name[:48]}")
    print(f"\n{fired} FIRED · {len(rules)-fired-errored} no-hit · {errored} errored "
          f"(of {len(rules)} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
