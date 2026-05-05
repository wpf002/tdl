#!/usr/bin/env python3
"""One-shot: generate `pseudo_logic` for rules in rules/*.yaml that are missing it.

Reads the rule's name, description, queries, technique, and data sources, then
asks Claude Sonnet 4.6 to produce a plain-English detection-logic description
in the style of existing TDL rules. Writes back to the YAML in place.

Run patterns:

    # count what's missing, no API calls (free)
    ANTHROPIC_API_KEY=... python3 -m tools.backfill_pseudo_logic --dry-run

    # process the first N for spot-checking (real spend, small)
    ANTHROPIC_API_KEY=... python3 -m tools.backfill_pseudo_logic --limit 3

    # process all missing rules
    ANTHROPIC_API_KEY=... python3 -m tools.backfill_pseudo_logic
"""

from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"

MODEL = os.environ.get("AI_BUILDER_MODEL", "claude-sonnet-4-6")
MAX_OUTPUT_TOKENS = 800
PARALLEL_WORKERS = 4

# Pricing — Sonnet 4.6 sync, no Batch API:
INPUT_PRICE = 3.00 / 1_000_000
CACHE_WRITE_PRICE = 3.75 / 1_000_000  # 1.25× base
CACHE_READ_PRICE = 0.30 / 1_000_000   # 0.10× base
OUTPUT_PRICE = 15.00 / 1_000_000

SYSTEM_PROMPT = """You write plain-English `pseudo_logic` descriptions for TDL detection rules.

Style guide (mirror this format exactly):
- Open with thresholds and the time window in plain English. Example: "4 Instances over 1 hour of 2 Windows Authentication Failure events".
- Then list filter clauses, one per line, beginning with "From", "Where", or "With".
- Use exact field names and event IDs the queries reference.
- Mention exclusion lists when present (admin allow-lists, vendor IPs, etc.).
- End with the correlation key — e.g. "With the same Destination Username and Source IP" — and any deduplication / minimum-spacing rule.

Do NOT include preamble, markdown fences, or commentary. Output the pseudo_logic body only.
"""


def find_missing():
    out = []
    for p in sorted(RULES_DIR.rglob("*.yaml")):
        try:
            d = yaml.safe_load(p.read_text())
        except Exception:
            continue
        if not isinstance(d, dict) or not d.get("rule_id"):
            continue
        if not (d.get("pseudo_logic") or "").strip():
            out.append((p, d))
    return out


def build_user_msg(rule: dict) -> str:
    queries = rule.get("queries") or {}
    sample = queries.get("spl") or queries.get("kql") or next(iter(queries.values()), "")
    return (
        f"Rule ID: {rule.get('rule_id')}\n"
        f"Name: {rule.get('name')}\n"
        f"Description: {rule.get('description')}\n"
        f"Tactic: {rule.get('tactic')} ({rule.get('tactic_id')})\n"
        f"Technique: {rule.get('technique_id')} — {rule.get('technique_name')}\n"
        f"Platforms: {rule.get('platform') or []}\n"
        f"Data sources: {rule.get('data_sources') or []}\n"
        f"False positives: {rule.get('false_positives') or []}\n"
        f"Severity / fidelity: {rule.get('severity')} / {rule.get('fidelity')}\n"
        f"\nSample query (use this to derive thresholds, fields, and exclusions):\n```\n{sample}\n```\n"
    )


def gen_one(client, rule: dict) -> tuple[str, dict]:
    """Call Claude for one rule; return (pseudo_logic_text, usage_dict)."""
    resp = client.messages.create(
        model=MODEL,
        max_tokens=MAX_OUTPUT_TOKENS,
        system=[{
            "type": "text",
            "text": SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{"role": "user", "content": build_user_msg(rule)}],
    )
    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text").strip()
    u = resp.usage
    usage = {
        "input": getattr(u, "input_tokens", 0) or 0,
        "cache_write": getattr(u, "cache_creation_input_tokens", 0) or 0,
        "cache_read": getattr(u, "cache_read_input_tokens", 0) or 0,
        "output": getattr(u, "output_tokens", 0) or 0,
    }
    return text, usage


def write_back(path: Path, rule: dict, pseudo_logic: str):
    rule["pseudo_logic"] = pseudo_logic
    path.write_text(yaml.safe_dump(rule, sort_keys=False, allow_unicode=True))


def estimate_cost_for(n: int) -> tuple[float, float]:
    """Return (typical_estimate_usd, ceiling_usd) for n rules."""
    # Per-call rough numbers based on the rule shape we send:
    # ~2,000 user input tokens + ~150 system cache read
    # ~400 output tokens typical, MAX_OUTPUT_TOKENS=800 ceiling
    sys_write_per_run = 200  # one cache write at start of each parallel worker
    user_in_per_call = 2000
    sys_read_per_call = 200
    typical_out = 400

    typical = (
        sys_write_per_run * PARALLEL_WORKERS * CACHE_WRITE_PRICE
        + n * user_in_per_call * INPUT_PRICE
        + n * sys_read_per_call * CACHE_READ_PRICE
        + n * typical_out * OUTPUT_PRICE
    )
    ceiling = (
        sys_write_per_run * PARALLEL_WORKERS * CACHE_WRITE_PRICE
        + n * user_in_per_call * INPUT_PRICE
        + n * sys_read_per_call * CACHE_READ_PRICE
        + n * MAX_OUTPUT_TOKENS * OUTPUT_PRICE
    )
    return typical, ceiling


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="Count + cost estimate; no API calls")
    ap.add_argument("--limit", type=int, default=None, help="Process at most N rules")
    args = ap.parse_args()

    missing = find_missing()
    n = len(missing) if args.limit is None else min(args.limit, len(missing))
    typical, ceiling = estimate_cost_for(n)

    print(f"Rules missing pseudo_logic : {len(missing)}")
    if args.limit is not None:
        print(f"Limit                      : {args.limit}  →  processing {n}")
    print(f"Model                      : {MODEL}")
    print(f"Parallel workers           : {PARALLEL_WORKERS}")
    print(f"Estimated cost (typical)   : ${typical:.4f}")
    print(f"Estimated cost (ceiling)   : ${ceiling:.4f}  ← absolute upper bound")

    if args.dry_run:
        print("\n--dry-run: no API calls made")
        return 0

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("\nERROR: ANTHROPIC_API_KEY is not set", file=sys.stderr)
        return 1

    try:
        from anthropic import Anthropic
    except ImportError:
        print("\nERROR: pip install anthropic", file=sys.stderr)
        return 1
    client = Anthropic()

    work = missing[:n]
    print(f"\nProcessing {len(work)} rules with {PARALLEL_WORKERS} workers…\n")

    total_in = total_cw = total_cr = total_out = 0
    successes = []
    failures = []

    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as ex:
        futures = {ex.submit(gen_one, client, rule): (path, rule) for path, rule in work}
        for fut in as_completed(futures):
            path, rule = futures[fut]
            try:
                text, usage = fut.result()
                if not text:
                    raise RuntimeError("empty pseudo_logic")
                write_back(path, rule, text)
                total_in += usage["input"]
                total_cw += usage["cache_write"]
                total_cr += usage["cache_read"]
                total_out += usage["output"]
                successes.append(rule["rule_id"])
                print(f"  ✓ {rule['rule_id']}  ({usage['input']+usage['cache_read']} in / {usage['output']} out)")
            except Exception as e:
                failures.append((rule["rule_id"], f"{type(e).__name__}: {e}"))
                print(f"  ✗ {rule['rule_id']}  →  {e}", file=sys.stderr)

    actual_cost = (
        total_in * INPUT_PRICE
        + total_cw * CACHE_WRITE_PRICE
        + total_cr * CACHE_READ_PRICE
        + total_out * OUTPUT_PRICE
    )
    print()
    print(f"Successes : {len(successes)}")
    print(f"Failures  : {len(failures)}")
    print(f"Tokens    : {total_in:,} in / {total_cw:,} cache-write / {total_cr:,} cache-read / {total_out:,} out")
    print(f"Actual $  : ${actual_cost:.4f}")
    if failures:
        print("\nFailed rule_ids:")
        for rid, err in failures:
            print(f"  {rid}  {err}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
