#!/usr/bin/env python3
"""Seed the rules table from rules/**/*.yaml.

Idempotent: upserts on rule_id. Skips rules where is_custom=true in the DB so
re-seeding does not clobber user-created or user-edited rules. (When the editor
lands in Phase 3, edited rules will have is_custom=true and survive re-seed.)

We seed from YAML rather than ui/src/data/rules.json because the latter
truncates pseudo_logic and per-SIEM queries (see tools/export_ui_data.py).

Safe to run on every deploy. No-op if DATABASE_URL is unset.
"""

import sys
from pathlib import Path

import yaml
from sqlalchemy.dialects.postgresql import insert

from tools.db import db_enabled, session_scope
from tools.models import Rule

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"

QUERY_KEYS = ["spl", "kql", "aql", "yara_l", "esql", "leql", "crowdstrike", "xql", "lucene", "sumo"]
RULE_COLUMNS = {
    "rule_id", "name", "description",
    "tactic", "tactic_id", "technique_id", "technique_name",
    "platform", "data_sources",
    "severity", "fidelity", "lifecycle",
    "risk_score",
    "queries", "pseudo_logic", "false_positives", "triage_steps", "tags",
    "test_method", "tuning_guidance",
    "author", "created",
}


def to_row(doc):
    queries_in = doc.get("queries") or {}
    queries = {k: queries_in[k] for k in QUERY_KEYS if k in queries_in}

    row = {k: doc.get(k) for k in RULE_COLUMNS}
    row["queries"] = queries
    row["last_modified"] = doc.get("last_modified") or doc.get("created")
    row["is_custom"] = False
    return row


def load_yaml_rules():
    rules = []
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        with path.open("r", encoding="utf-8") as f:
            try:
                doc = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"YAML parse error in {path}: {e}", file=sys.stderr)
                continue
        if not isinstance(doc, dict) or not doc.get("rule_id"):
            continue
        rid = doc["rule_id"]
        if isinstance(rid, str) and rid.startswith("TDE-"):
            print(f"skipping legacy TDE- rule_id from {path.name}", file=sys.stderr)
            continue
        rules.append(doc)
    return rules


def main():
    if not db_enabled():
        print("DATABASE_URL not set — skipping seed.")
        return 0
    if not RULES_DIR.exists():
        print(f"rules/ not found at {RULES_DIR}", file=sys.stderr)
        return 1

    rules = load_yaml_rules()
    print(f"Loaded {len(rules)} rules from rules/")

    rows = [to_row(r) for r in rules]

    inserted = 0
    updated = 0
    skipped_custom = 0

    with session_scope() as s:
        existing = {
            r.rule_id: r.is_custom
            for r in s.query(Rule.rule_id, Rule.is_custom).all()
        }

        rows_to_write = []
        for row in rows:
            rid = row["rule_id"]
            if existing.get(rid) is True:
                skipped_custom += 1
                continue
            rows_to_write.append(row)
            if rid in existing:
                updated += 1
            else:
                inserted += 1

        if rows_to_write:
            stmt = insert(Rule).values(rows_to_write)
            update_cols = {c.name: c for c in stmt.excluded if c.name not in ("id", "rule_id", "is_custom")}
            stmt = stmt.on_conflict_do_update(index_elements=["rule_id"], set_=update_cols)
            s.execute(stmt)
            s.flush()

        total = s.query(Rule).count()

    print(f"Inserted: {inserted}  Updated: {updated}  Skipped (is_custom): {skipped_custom}")
    print(f"Total rules in DB: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
