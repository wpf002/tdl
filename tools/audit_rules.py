#!/usr/bin/env python3
"""Structural rule audit — free, deterministic, runs in seconds.

Checks every rule for issues that don't need an LLM to find:
  - missing/short required fields
  - missing query languages
  - broken related_rules cross-references
  - technique_id hierarchy mismatches (name says sub-technique, id is parent)
  - data_sources values not present in log-sources/catalog.yaml
  - no-op query thresholds (`where count >= 1`)
  - tag hygiene (missing technique_id / platform tags)
  - generic-only false_positives lists
  - triage_steps that are clearly templated

Writes findings to exports/audit_results.json keyed by rule_id, merged with any
existing semantic-audit findings already in that file.

Run:
    python3 tools/audit_rules.py
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
CATALOG_PATH = ROOT / "log-sources" / "catalog.yaml"
OUT_PATH = ROOT / "exports" / "audit_results.json"

QUERY_LANGS = ["spl", "kql", "aql", "yara_l", "esql", "leql",
               "crowdstrike", "xql", "lucene", "sumo"]

GENERIC_FP_PHRASES = {
    "security software", "authorized admin tools", "admin tools",
    "legitimate use", "legitimate user", "authorized scanning",
    "normal activity", "internal scanners",
}

# Patterns that signal a no-op threshold gate.
NOOP_THRESHOLD_PATTERNS = [
    re.compile(r"\bcount\s*>=?\s*[01]\b", re.I),
    re.compile(r"\bcount\s*>\s*0\b", re.I),
]


def load_catalog_names() -> set[str]:
    if not CATALOG_PATH.exists():
        return set()
    try:
        doc = yaml.safe_load(CATALOG_PATH.read_text())
    except yaml.YAMLError:
        return set()
    names: set[str] = set()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("name", "source", "id") and isinstance(v, str):
                    names.add(v)
                walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(doc)
    return names


def issue(code: str, severity: str, message: str, **kw) -> dict:
    """severity: critical | major | minor"""
    out = {"code": code, "severity": severity, "message": message}
    out.update(kw)
    return out


def audit_rule(rule: dict, all_ids: set[str], catalog_names: set[str]) -> list[dict]:
    issues: list[dict] = []

    name = (rule.get("name") or "").strip()
    rid = rule.get("rule_id") or ""
    tactic = rule.get("tactic")
    technique_id = rule.get("technique_id") or ""
    technique_name = (rule.get("technique_name") or "").strip()
    pseudo = (rule.get("pseudo_logic") or "").strip()
    queries = rule.get("queries") or {}
    fps = rule.get("false_positives") or []
    triage = rule.get("triage_steps") or []
    tags = [t.lower() for t in (rule.get("tags") or [])]
    data_sources = rule.get("data_sources") or []
    related = rule.get("related_rules") or []
    requirements = rule.get("requirements") or {}
    platforms = rule.get("platform") or []
    severity = rule.get("severity")
    lifecycle = rule.get("lifecycle")

    # ── pseudo_logic ────────────────────────────────────────────────
    if not pseudo:
        issues.append(issue("pseudo_logic_missing", "major", "pseudo_logic is empty"))
    elif len(pseudo) < 20:
        issues.append(issue("pseudo_logic_short", "major",
                            f"pseudo_logic is only {len(pseudo)} chars"))

    # ── queries ─────────────────────────────────────────────────────
    for lang in QUERY_LANGS:
        v = queries.get(lang)
        if not (isinstance(v, str) and v.strip()):
            issues.append(issue("query_missing", "minor",
                                f"queries.{lang} is missing or empty", lang=lang))
            continue
        for pat in NOOP_THRESHOLD_PATTERNS:
            if pat.search(v):
                issues.append(issue("query_noop_threshold", "major",
                                    f"queries.{lang} contains a no-op threshold ({pat.pattern!r}) — will alert on every event",
                                    lang=lang))
                break

    # ── requirements ────────────────────────────────────────────────
    if not (requirements.get("log_sources") if isinstance(requirements, dict) else None):
        issues.append(issue("requirements_missing", "minor",
                            "requirements.log_sources is empty — UI quality score docks 20 pts"))

    # ── related_rules ───────────────────────────────────────────────
    for r in related:
        if r not in all_ids:
            issues.append(issue("related_rule_broken", "major",
                                f"related_rules references {r!r} which doesn't exist on disk",
                                target=r))

    # ── data_sources ────────────────────────────────────────────────
    seen_ds = set()
    for ds in data_sources:
        if ds in seen_ds:
            issues.append(issue("data_source_duplicate", "minor",
                                f"duplicate data_source: {ds!r}", value=ds))
        seen_ds.add(ds)
        if catalog_names and ds not in catalog_names:
            issues.append(issue("data_source_unknown", "minor",
                                f"data_source {ds!r} not found in log-sources/catalog.yaml",
                                value=ds))

    # ── technique_id hierarchy ──────────────────────────────────────
    # If name or technique_name looks like a specific sub-technique (e.g. mentions
    # "Kerberoasting") but technique_id is a parent (no dotted suffix), that's
    # a likely miscategorization. Heuristic: name has a strong keyword that
    # maps to a sub-technique under the listed parent.
    SUBTECHNIQUE_HINTS = {
        "kerberoasting": "T1558.003",
        "as-rep roasting": "T1558.004",
        "golden ticket": "T1558.001",
        "silver ticket": "T1558.002",
        "lsass": "T1003.001",
        "ntds": "T1003.003",
        "dcsync": "T1003.006",
        "scheduled task": "T1053.005",
        "powershell": "T1059.001",
        "cmd ": "T1059.003",
    }
    name_l = (name + " " + technique_name).lower()
    for hint, expected in SUBTECHNIQUE_HINTS.items():
        if hint in name_l:
            if technique_id != expected:
                issues.append(issue("technique_id_wrong_level", "major",
                                    f"name mentions {hint!r} which is technique {expected}, but technique_id is {technique_id!r}",
                                    expected=expected, actual=technique_id))
            break

    # ── tags hygiene ────────────────────────────────────────────────
    if technique_id and technique_id.lower() not in tags:
        issues.append(issue("tag_missing_technique", "minor",
                            f"tags do not include technique_id {technique_id!r}",
                            expected=technique_id))
    plat_tags = {p.lower() for p in platforms}
    if plat_tags and not (plat_tags & set(tags)):
        issues.append(issue("tag_missing_platform", "minor",
                            f"tags do not include any platform from {platforms}",
                            platforms=platforms))

    # ── false_positives ─────────────────────────────────────────────
    if not fps:
        issues.append(issue("false_positives_missing", "major",
                            "false_positives list is empty"))
    else:
        normalized = [f.strip().lower() for f in fps if isinstance(f, str)]
        if all(any(g in fp for g in GENERIC_FP_PHRASES) or len(fp) < 25 for fp in normalized):
            issues.append(issue("false_positives_generic", "minor",
                                "all false_positives entries are short/generic phrases",
                                values=fps))

    # ── triage_steps ────────────────────────────────────────────────
    if not triage:
        issues.append(issue("triage_steps_missing", "major",
                            "triage_steps list is empty"))
    elif len(triage) < 4:
        issues.append(issue("triage_steps_too_few", "minor",
                            f"only {len(triage)} triage_steps (UI quality score wants ≥4)"))

    # Templated triage detection: steps mention "this technique" without naming
    # the actual technique, or repeat a generic LSASS/DC/KDC line on a non-LSASS
    # rule, etc. Heuristic only — keep noise low.
    if triage:
        joined = " ".join(triage).lower()
        if "this technique" in joined and (technique_name.lower() not in joined):
            issues.append(issue("triage_steps_templated", "minor",
                                "triage_steps say 'this technique' but don't name the actual technique"))

    # ── severity / lifecycle sanity ─────────────────────────────────
    if severity == "Critical" and lifecycle == "Proposed":
        issues.append(issue("severity_lifecycle_mismatch", "minor",
                            "Critical-severity rule still in Proposed lifecycle"))

    return issues


def main() -> int:
    if not RULES_DIR.exists():
        print(f"rules/ not found at {RULES_DIR}", file=sys.stderr)
        return 1

    catalog_names = load_catalog_names()

    docs: list[tuple[Path, dict]] = []
    parse_failures: list[dict] = []
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            parse_failures.append({"file": str(path.relative_to(ROOT)), "error": str(e)})
            continue
        if isinstance(doc, dict):
            docs.append((path, doc))

    all_ids = {d.get("rule_id") for _, d in docs if d.get("rule_id")}

    # Merge with any existing audit_results.json so semantic findings aren't wiped.
    existing: dict = {}
    if OUT_PATH.exists():
        try:
            existing = json.loads(OUT_PATH.read_text())
        except json.JSONDecodeError:
            existing = {}

    results: dict[str, dict] = {}
    severity_counts: Counter = Counter()
    code_counts: Counter = Counter()
    rules_with_issues = 0

    for path, doc in docs:
        rid = doc.get("rule_id") or path.stem
        issues = audit_rule(doc, all_ids, catalog_names)
        prev = (existing.get("rules") or {}).get(rid, {}) if isinstance(existing.get("rules"), dict) else {}
        semantic = prev.get("semantic_issues") or []

        entry = {
            "rule_id": rid,
            "file": str(path.relative_to(ROOT)),
            "name": doc.get("name"),
            "structural_issues": issues,
            "semantic_issues": semantic,
        }
        results[rid] = entry
        if issues:
            rules_with_issues += 1
        for i in issues:
            severity_counts[i["severity"]] += 1
            code_counts[i["code"]] += 1

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_rules": len(docs),
        "rules_with_structural_issues": rules_with_issues,
        "structural_severity_counts": dict(severity_counts),
        "structural_code_counts": dict(code_counts.most_common()),
        "parse_failures": parse_failures,
        "rules": results,
    }
    OUT_PATH.write_text(json.dumps(payload, indent=2))

    print(f"\n  TDL Audit — Structural\n")
    print(f"  Rules scanned:           {len(docs)}")
    print(f"  Rules with issues:       {rules_with_issues}")
    print(f"  Issues by severity:      {dict(severity_counts)}")
    print(f"  Top issue codes:")
    for code, n in code_counts.most_common(10):
        print(f"    {n:5d}  {code}")
    if parse_failures:
        print(f"  YAML parse failures:     {len(parse_failures)}")
    print(f"\n  Report: {OUT_PATH.relative_to(ROOT)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
