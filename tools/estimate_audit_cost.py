#!/usr/bin/env python3
"""Empirical cost estimator for the semantic audit. No API calls.

Reads per-rule cost data already recorded in exports/audit_results.json
(populated by tools/audit_rules_semantic.py after the cost-recording fix),
falls back to parsing the legacy log files in /tmp/audit-*.log if the
ledger isn't populated yet.

Outputs:
    - per-rule cost distribution (mean, p50, p75, p95)
    - total spent so far
    - p75 and p95 projections for the rules not yet audited
    - rough "rate-limit waste multiplier" for higher concurrency

Run before kicking off any audit so you know what you're committing to:

    python3 tools/estimate_audit_cost.py
    python3 tools/estimate_audit_cost.py --remaining 440 --concurrency 1
    python3 tools/estimate_audit_cost.py --concurrency 6   # shows waste factor
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parent.parent
AUDIT_PATH = ROOT / "exports" / "audit_results.json"
LOG_GLOB = ["/tmp/audit-haiku.log", "/tmp/audit-haiku2.log",
            "/tmp/audit-final.log", "/tmp/audit-final2.log"]

# Concurrency → empirical "waste multiplier" based on today's runs. At conc=6
# we hit ~45% terminal failures, each having burned ~6 retries of input tokens.
# Anthropic doesn't bill failed 429s, but it bills the SUCCESSFUL retry, so
# rules retried 4–8 times before succeeding cost 4–8x. At conc=1 there is no
# pressure and the multiplier is ~1.0.
WASTE_MULTIPLIER = {
    1: 1.00,
    2: 1.05,
    3: 1.20,
    4: 1.40,
    5: 1.70,
    6: 2.20,   # observed: $13 reported + ~$30 in retry waste ≈ 3.3x; using 2.2 as
               # a conservative middle for any future user who reads this
    8: 2.80,
}


def percentile(sorted_vals, pct):
    if not sorted_vals:
        return 0.0
    k = max(0, min(len(sorted_vals) - 1, int(round(pct / 100 * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


def costs_from_audit_ledger() -> tuple[list[float], int]:
    """Pull per-rule cost from the saved audit results. Returns (costs, total_rules_in_repo)."""
    if not AUDIT_PATH.exists():
        return [], 0
    d = json.loads(AUDIT_PATH.read_text())
    rules = d.get("rules") or {}
    costs = []
    for r in rules.values():
        c = (r.get("semantic_cost") or {}).get("total_usd")
        if isinstance(c, (int, float)) and c > 0:
            costs.append(float(c))
    return costs, len(rules)


def costs_from_log_files() -> list[float]:
    """Fallback: parse the per-rule cost printed in log files."""
    pat = re.compile(r"q-score:\s*[0-9]+\s+[0-9]+ findings\s+\([0-9]+c/[0-9]+m\)\s+\$([0-9.]+)")
    costs = []
    for path in LOG_GLOB:
        try:
            costs.extend(float(m.group(1)) for m in pat.finditer(Path(path).read_text()))
        except FileNotFoundError:
            continue
    return costs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--remaining", type=int,
                    help="Override: how many rules remain. Default = repo total minus rules already audited.")
    ap.add_argument("--concurrency", type=int, default=1,
                    help="Planned concurrency. Adds a waste multiplier for >1.")
    args = ap.parse_args()

    ledger_costs, total_rules = costs_from_audit_ledger()
    source = "ledger (exports/audit_results.json)"
    costs = ledger_costs
    if not costs:
        costs = costs_from_log_files()
        source = "log files in /tmp"

    if not costs:
        print("No empirical cost data found. Run a small audit sample first:")
        print("  python3 -m tools.audit_rules_semantic --limit 5")
        return 1

    costs.sort()
    n = len(costs)
    spent = sum(costs)

    p50 = percentile(costs, 50)
    p75 = percentile(costs, 75)
    p95 = percentile(costs, 95)
    avg = mean(costs)

    if args.remaining is not None:
        remaining = args.remaining
    elif total_rules:
        # Total rules in the repo minus what we already have cost data for.
        from glob import glob
        total_repo = len(glob(str(ROOT / "rules" / "**" / "*.yaml"), recursive=True))
        remaining = total_repo - n
    else:
        remaining = 0

    wm = WASTE_MULTIPLIER.get(args.concurrency, 1.0 + 0.5 * args.concurrency)

    print(f"\n  Empirical cost data: {n} rules, source: {source}")
    print(f"  Per-rule cost:")
    print(f"    mean: ${avg:.4f}   p50: ${p50:.4f}   p75: ${p75:.4f}   p95: ${p95:.4f}")
    print(f"  Total spent so far (this metric): ${spent:.2f}")
    print()
    if remaining > 0:
        print(f"  Remaining rules:  {remaining}")
        print(f"  Planned concurrency: {args.concurrency}  (waste multiplier: {wm:.2f}x)")
        print(f"  Estimate to finish:")
        print(f"    likely (p75 × waste):  ${remaining * p75 * wm:.2f}")
        print(f"    worst-case (p95 × waste):  ${remaining * p95 * wm:.2f}")
    else:
        print(f"  No rules remaining.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
