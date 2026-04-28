#!/usr/bin/env python3
"""Add `triage_steps` to every rule using the per-tactic playbook KB.

Idempotent: re-running rewrites the steps based on the rule's current shape.
"""

from pathlib import Path
import yaml

from triage_kb import steps_for

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "rules"


def main():
    paths = sorted(RULES_DIR.rglob("*.yaml"))
    written = 0
    for p in paths:
        try:
            with p.open() as f:
                rule = yaml.safe_load(f)
        except Exception as e:
            print(f"  skip {p}: {e}")
            continue
        if not isinstance(rule, dict):
            continue
        rule["triage_steps"] = steps_for(rule)
        with p.open("w") as f:
            yaml.safe_dump(rule, f, sort_keys=False, default_flow_style=False, width=120)
        written += 1
    print(f"wrote/updated triage_steps on {written} rules")


if __name__ == "__main__":
    main()
