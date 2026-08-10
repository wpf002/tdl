#!/usr/bin/env python3
"""Write the regenerated 9 dialects (exports/regen_dialects.json) into each rule's
YAML queries.<lang>. Leaves SPL untouched (already remediated separately).

    python -m tools.apply_regen_dialects [--dry-run]
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
REGEN = ROOT / "exports" / "regen_dialects.json"
LANGS = ["kql", "aql", "yara_l", "esql", "leql", "crowdstrike", "xql", "lucene", "sumo"]


class BlockStr(str):
    pass


yaml.add_representer(BlockStr, lambda d, data: d.represent_scalar("tag:yaml.org,2002:str", data, style="|"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    regen = json.loads(REGEN.read_text())
    written = 0
    changed_langs = 0

    for path in sorted(RULES_DIR.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        rid = doc.get("rule_id")
        entry = regen.get(rid)
        if not rid or not entry:
            continue
        if not isinstance(doc.get("queries"), dict):
            doc["queries"] = {}
        touched = False
        for lang in LANGS:
            q = (entry.get(lang) or "").strip()
            if not q:
                continue
            if (doc["queries"].get(lang) or "").strip() == q:
                continue
            doc["queries"][lang] = BlockStr(q + "\n")
            changed_langs += 1
            touched = True
        if touched:
            doc["last_modified"] = date.today().isoformat()
            if not args.dry_run:
                with path.open("w", encoding="utf-8") as f:
                    yaml.dump(doc, f, default_flow_style=False, allow_unicode=True,
                              sort_keys=False, width=140)
            written += 1

    print(f"{'DRY-RUN: would update' if args.dry_run else 'Updated'} {written} rules "
          f"· {changed_langs} dialect queries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
