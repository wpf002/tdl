#!/usr/bin/env python3
"""Export the YAML rule library to ui/src/data/rules.json for the dashboard."""

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
OUT_PATH = ROOT / "ui" / "src" / "data" / "rules.json"
AUDIT_PATH = ROOT / "exports" / "audit_results.json"

QUERY_KEYS = ["spl", "kql", "aql", "yara_l", "esql", "leql", "crowdstrike", "xql", "lucene", "sumo"]
PSEUDO_MAX = 300
QUERY_MAX = 800


def truncate(value, limit):
    if not isinstance(value, str):
        return value
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def load_audit_index():
    """Return {rule_id: audit_entry} or {} if no audit has been run."""
    if not AUDIT_PATH.exists():
        return {}
    try:
        doc = json.loads(AUDIT_PATH.read_text())
    except json.JSONDecodeError:
        return {}
    return doc.get("rules") or {}


def normalize(rule, audit_index):
    queries_in = rule.get("queries") or {}
    queries_out = {}
    for key in QUERY_KEYS:
        v = queries_in.get(key)
        if isinstance(v, str):
            queries_out[key] = truncate(v, QUERY_MAX)
        elif v is not None:
            queries_out[key] = truncate(str(v), QUERY_MAX)

    rid = rule.get("rule_id")
    audit = audit_index.get(rid) or {}
    structural = audit.get("structural_issues") or []
    semantic = audit.get("semantic_issues") or []
    all_issues = [*structural, *semantic]
    counts = {"critical": 0, "major": 0, "minor": 0}
    for i in all_issues:
        sev = (i.get("severity") or "minor").lower()
        if sev in counts:
            counts[sev] += 1

    return {
        "rule_id": rid,
        "name": rule.get("name"),
        "tactic": rule.get("tactic"),
        "tactic_id": rule.get("tactic_id"),
        "technique_id": rule.get("technique_id"),
        "technique_name": rule.get("technique_name"),
        "platform": rule.get("platform") or [],
        "severity": rule.get("severity"),
        "fidelity": rule.get("fidelity"),
        "lifecycle": rule.get("lifecycle"),
        "risk_score": rule.get("risk_score"),
        "tags": rule.get("tags") or [],
        "data_sources": rule.get("data_sources") or [],
        "false_positives": rule.get("false_positives") or [],
        "triage_steps": rule.get("triage_steps") or [],
        "tuning_guidance": rule.get("tuning_guidance"),
        "description": rule.get("description"),
        "pseudo_logic": truncate(rule.get("pseudo_logic"), PSEUDO_MAX),
        "queries": queries_out,
        "author": rule.get("author"),
        "created": rule.get("created"),
        "test_method": rule.get("test_method"),
        "audit": {
            "structural_issues": structural,
            "semantic_issues": semantic,
            "counts": counts,
            "total": len(all_issues),
            "semantic_audited_at": audit.get("semantic_audited_at"),
        },
    }


def main():
    if not RULES_DIR.exists():
        print(f"rules/ not found at {RULES_DIR}", file=sys.stderr)
        sys.exit(1)

    audit_index = load_audit_index()

    rules = []
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        with path.open("r", encoding="utf-8") as f:
            try:
                doc = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"YAML parse error in {path}: {e}", file=sys.stderr)
                sys.exit(2)
        if not isinstance(doc, dict):
            continue
        rid = doc.get("rule_id", "")
        if isinstance(rid, str) and rid.startswith("TDE-"):
            print(f"refusing to export legacy TDE- rule_id from {path}", file=sys.stderr)
            sys.exit(3)
        rules.append(normalize(doc, audit_index))

    rules.sort(key=lambda r: (r.get("rule_id") or ""))

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", encoding="utf-8") as f:
        json.dump(rules, f, ensure_ascii=False, indent=2)

    print(f"Exported {len(rules)} rules → {OUT_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
