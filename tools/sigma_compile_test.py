#!/usr/bin/env python3
"""
TDL Playbook — Sigma → SIEM compile test.

Picks a sample of Sigma rules from sigma/ and compiles them to:
  - Splunk SPL  (pysigma-backend-splunk)
  - Microsoft Sentinel KQL  (pysigma-backend-microsoft365defender)

Verifies that pySigma backends successfully parse and emit valid query strings.
Reports per-rule results and exits non-zero if no rules compiled successfully
to either backend.

Usage:
  python3 tools/sigma_compile_test.py
  python3 tools/sigma_compile_test.py --count 20 --pattern 'sigma/credential-access/*.yml'
"""

from __future__ import annotations

import argparse
import glob
import io
import sys
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

# pySigma imports
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.kusto import KustoBackend


SAMPLE_PATTERNS = [
    "sigma/credential-access/*.yml",
    "sigma/execution/*.yml",
    "sigma/persistence/*.yml",
    "sigma/defense-evasion/*.yml",
    "sigma/discovery/*.yml",
    "sigma/lateral-movement/*.yml",
    "sigma/command-and-control/*.yml",
    "sigma/exfiltration/*.yml",
    "sigma/impact/*.yml",
    "sigma/collection/*.yml",
]


def pick_sample(count: int, pattern: str | None) -> list[Path]:
    if pattern:
        return [Path(p) for p in sorted(glob.glob(str(ROOT / pattern)))[:count]]
    chosen: list[Path] = []
    per_bucket = max(1, count // len(SAMPLE_PATTERNS))
    for pat in SAMPLE_PATTERNS:
        hits = sorted(glob.glob(str(ROOT / pat)))[:per_bucket]
        chosen.extend(Path(h) for h in hits)
        if len(chosen) >= count:
            break
    return chosen[:count]


def normalize(rule_path: Path) -> str:
    """Return a Sigma YAML string with custom/non-standard fields stripped
    and the TDL rule id replaced with a deterministic UUID5 so pySigma accepts it."""
    raw = yaml.safe_load(rule_path.read_text())
    raw.pop("custom", None)
    rid = str(raw.get("id", rule_path.stem))
    raw["id"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"tdl-playbook/{rid}"))
    return yaml.safe_dump(raw, sort_keys=False)


def compile_one(rule_yaml: str, backend, label: str) -> tuple[bool, str]:
    try:
        collection = SigmaCollection.from_yaml(rule_yaml)
        results = backend.convert(collection)
        if not results:
            return False, f"{label}: empty result"
        out = results[0] if isinstance(results, list) else str(results)
        return True, out if isinstance(out, str) else str(out)
    except Exception as e:
        return False, f"{label} error: {type(e).__name__}: {e}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--pattern", default=None)
    args = ap.parse_args()

    sample = pick_sample(args.count, args.pattern)
    if not sample:
        print("No Sigma rules matched.", file=sys.stderr)
        return 2

    splunk = SplunkBackend()
    kql = KustoBackend()

    print(f"\n  TDL Playbook — pySigma compile test ({len(sample)} rules)\n")
    print(f"  {'Rule':<42}  {'SPL':<6}  {'KQL':<6}")
    print(f"  {'-'*42}  {'-'*6}  {'-'*6}")

    spl_ok = kql_ok = 0
    failures: list[str] = []
    samples: list[tuple[str, str, str]] = []

    for rule_path in sample:
        rule_id = rule_path.stem
        rule_yaml = normalize(rule_path)

        ok_spl, out_spl = compile_one(rule_yaml, splunk, "splunk")
        ok_kql, out_kql = compile_one(rule_yaml, kql, "kql")

        spl_ok += int(ok_spl)
        kql_ok += int(ok_kql)
        if not ok_spl:
            failures.append(f"  {rule_id} {out_spl}")
        if not ok_kql:
            failures.append(f"  {rule_id} {out_kql}")
        if ok_spl and ok_kql and len(samples) < 2:
            samples.append((rule_id, out_spl, out_kql))

        spl_mark = "✓" if ok_spl else "✗"
        kql_mark = "✓" if ok_kql else "✗"
        print(f"  {rule_id:<42}  {spl_mark:<6}  {kql_mark:<6}")

    total = len(sample)
    print(f"\n  Splunk SPL:        {spl_ok}/{total} compiled")
    print(f"  Microsoft 365/KQL: {kql_ok}/{total} compiled\n")

    if samples:
        print("  Sample compiled output\n  " + "─" * 60)
        for rid, spl, kql in samples:
            print(f"\n  [{rid}]")
            print(f"  SPL: {spl[:240]}{'…' if len(spl) > 240 else ''}")
            print(f"  KQL: {kql[:240]}{'…' if len(kql) > 240 else ''}")
        print()

    if failures and (spl_ok == 0 and kql_ok == 0):
        print("  Failures:")
        for f in failures[:10]:
            print(f)
        return 1

    if spl_ok == 0 and kql_ok == 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
