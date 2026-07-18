#!/usr/bin/env python3
"""Write the regenerated SPL (exports/regen_spl.json) back into each rule's YAML
queries.spl, after lab validation. Skips rules whose regenerated SPL failed to
parse (kept in --skip), preserving their original query rather than shipping a
broken one.

    python -m tools.apply_regen_spl --skip TDL-C2-000430
    python -m tools.apply_regen_spl --dry-run
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
REGEN = ROOT / "exports" / "regen_spl.json"


class BlockStr(str):
    """Emit as a YAML literal block (preserve newlines)."""


yaml.add_representer(BlockStr, lambda d, data: d.represent_scalar("tag:yaml.org,2002:str", data, style="|"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip", nargs="*", default=[], help="rule_ids to leave unchanged")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    regen = json.loads(REGEN.read_text())
    skip = set(args.skip)
    written = skipped = 0

    for path in sorted(RULES_DIR.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        rid = doc.get("rule_id")
        entry = regen.get(rid)
        if not rid or not entry or rid in skip:
            skipped += 1
            continue
        new_spl = (entry.get("spl") or "").strip()
        if not new_spl:
            skipped += 1
            continue
        if not isinstance(doc.get("queries"), dict):
            doc["queries"] = {}
        if (doc["queries"].get("spl") or "").strip() == new_spl:
            skipped += 1
            continue
        doc["queries"]["spl"] = BlockStr(new_spl + "\n")
        doc["last_modified"] = date.today().isoformat()
        if not args.dry_run:
            with path.open("w", encoding="utf-8") as f:
                yaml.dump(doc, f, default_flow_style=False, allow_unicode=True,
                          sort_keys=False, width=140)
        written += 1

    print(f"{'DRY-RUN: would write' if args.dry_run else 'Wrote'} {written} rules · skipped {skipped}"
          f"{' (incl. ' + ', '.join(skip) + ')' if skip else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
