#!/usr/bin/env python3
"""Dump Postgres rules → rules/<tactic>/<rule_id>.yaml.

Inverse of seed_db.py. Run after rules are edited via the API to refresh
on-disk YAML so audit/regen tooling (which reads YAML) sees the latest state.

No-op if DATABASE_URL is unset.
"""

import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

import yaml

from tools.db import db_enabled, session_scope
from tools.models import Rule

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"

YAML_KEYS = [
    "rule_id", "name", "description",
    "tactic", "tactic_id", "technique_id", "technique_name",
    "platform", "data_sources",
    "severity", "fidelity", "lifecycle", "risk_score",
    "queries", "pseudo_logic", "false_positives", "triage_steps", "tags",
    "test_method", "tuning_guidance",
    "author", "created", "last_modified",
]


def main():
    if not db_enabled():
        print("DATABASE_URL not set — skipping dump.")
        return 0
    if not RULES_DIR.exists():
        RULES_DIR.mkdir(parents=True)

    written = 0
    with session_scope() as s:
        for r in s.query(Rule).order_by(Rule.rule_id).all():
            payload = {k: getattr(r, k) for k in YAML_KEYS}
            payload = {k: v for k, v in payload.items() if v is not None and v != ""}
            tactic_slug = (r.tactic or "uncategorized").lower().replace(" ", "-")
            out_dir = RULES_DIR / tactic_slug
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{r.rule_id}.yaml"
            with out_path.open("w", encoding="utf-8") as f:
                yaml.safe_dump(payload, f, sort_keys=False, allow_unicode=True)
            written += 1

    print(f"Dumped {written} rules → {RULES_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
