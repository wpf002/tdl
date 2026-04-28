#!/usr/bin/env python3
"""Generate TDL detection rules for every uncovered (tactic, technique) cell
in the canonical ATT&CK matrix.

Inputs (read):
  ui/src/data/attack-matrix.js   → canonical (tactic, technique) cells
  rules/**/*.yaml                → existing coverage (we skip cells we already have)

Output (write):
  rules/<tactic-folder>/TDL-<NNNNNN>.yaml   one per gap cell

Each rule lifecycle is `Proposed`. SPL+KQL+seven other SIEMs are templated from
`tools/gen/query_templates.py` using the per-technique knowledge base.
"""

import json
import re
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from gen.technique_kb import TECHNIQUES, TACTIC_IDS, TACTIC_FOLDER, TACTIC_PREFIX  # noqa: E402
from gen.query_templates import render  # noqa: E402
from gen.triage_kb import steps_for  # noqa: E402

RULES_DIR = ROOT / "rules"
MATRIX_JS = ROOT / "ui" / "src" / "data" / "attack-matrix.js"


def parse_canonical_matrix():
    """Parse the canonical (tactic, technique) cells from attack-matrix.js."""
    text = MATRIX_JS.read_text()
    # Slice from `export const ATTACK_MATRIX = {` to the matching closing `}`.
    start = text.index("export const ATTACK_MATRIX")
    # Walk braces from that point.
    brace = 0
    end = start
    started = False
    for i, c in enumerate(text[start:], start):
        if c == "{":
            brace += 1
            started = True
        elif c == "}":
            brace -= 1
            if started and brace == 0:
                end = i + 1
                break
    block = text[start:end]

    matrix = {}
    current = None
    techs = []
    for line in block.splitlines():
        m_tac = re.match(r"\s*'([A-Za-z &]+)':\s*\{", line)
        m_tec = re.match(r"\s*\{\s*id:\s*'(T\d+)',\s*name:\s*'([^']+)'\s*\},?", line)
        if m_tac:
            if current:
                matrix[current] = techs
            current = m_tac.group(1)
            techs = []
        elif m_tec and current:
            techs.append((m_tec.group(1), m_tec.group(2)))
    if current:
        matrix[current] = techs
    # Trim Reconnaissance / non-applicable headers if any leaked in.
    matrix.pop("ATTACK_MATRIX", None)
    return matrix


def existing_pairs():
    """Return set of (tactic, technique_id) cells that already have ≥1 rule."""
    pairs = set()
    for path in RULES_DIR.rglob("*.yaml"):
        try:
            doc = yaml.safe_load(path.read_text())
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        t = doc.get("tactic")
        tid = doc.get("technique_id")
        if t and tid:
            pairs.add((t, tid.split(".")[0]))
    return pairs


def next_id_counter(start=700):
    """Return a callable that yields TDL-<NNNNNN> v4 IDs starting at `start`."""
    seen = set()
    for path in RULES_DIR.rglob("*.yaml"):
        m = re.search(r"(\d{6})", path.name)
        if m:
            seen.add(int(m.group(1)))
    counter = max(start - 1, max(seen) if seen else 0)

    def nxt():
        nonlocal counter
        counter += 1
        return counter

    return nxt


def build_rule(tactic, technique_id, technique_name, v4_id):
    """Build a single rule YAML dict for the given gap cell."""
    kb = TECHNIQUES.get(technique_id)
    if not kb:
        # Generic fallback if KB lacks this technique
        kb = {
            "name": technique_name,
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["EDR"],
            "severity": "Medium",
            "fidelity": "Low",
            "tags": [],
            "intents": {},
        }

    intent = kb["intents"].get(tactic)
    if intent is None:
        # Use any available intent as the structural template, but rewrite the
        # title to reflect the current tactic's lens.
        if kb["intents"]:
            base = next(iter(kb["intents"].values()))
            intent = {
                "title": f"{technique_name} Activity Observed (tactic: {tactic})",
                "pseudo": base["pseudo"],
                "hint": base["hint"],
            }
        else:
            intent = {
                "title": f"{technique_name} Activity Observed",
                "pseudo": f"Generic {technique_name} ({technique_id}) detection. Tune to environment.",
                "hint": {"event": "ProcessCreate", "command": "", "field": "process.command_line"},
            }

    prefix = TACTIC_PREFIX[tactic]
    rule_id = f"TDL-{prefix}-{v4_id:06d}"
    queries = render(
        rule_id=rule_id,
        technique_id=technique_id,
        tactic_id=TACTIC_IDS[tactic],
        name=intent["title"],
        severity=kb["severity"],
        hint=intent["hint"],
    )

    today = date.today().isoformat()
    rule = {
        "rule_id": rule_id,
        "v4_id": f"{v4_id:06d}",
        "name": intent["title"],
        "description": (
            f"{intent['pseudo']} Generated from gap analysis against "
            f"canonical ATT&CK Enterprise matrix ({technique_id} under {tactic})."
        ),
        "tactic": tactic,
        "tactic_id": TACTIC_IDS[tactic],
        "technique_id": technique_id,
        "technique_name": technique_name,
        "platform": kb["platforms"],
        "data_sources": kb["data_sources"],
        "severity": kb["severity"],
        "fidelity": kb["fidelity"],
        "lifecycle": "Proposed",
        "queries": queries,
        "pseudo_logic": intent["pseudo"],
        "false_positives": [
            "Sanctioned admin or engineering activity",
            "Approved automation / CI workflows",
        ],
        "tuning_guidance": (
            "Proposed rule generated from ATT&CK gap analysis — review the "
            "pseudo_logic, scope filters to the right asset group, and refine "
            "thresholds using ≥7 days of telemetry before promoting."
        ),
        "tuning_period": "14 days",
        "triage_steps": [],  # filled below once we have the rule shape
        "tags": list(kb.get("tags", [])) + [technique_id.lower(), TACTIC_FOLDER[tactic]],
        "references": [
            f"https://attack.mitre.org/techniques/{technique_id}/",
        ],
        "author": "TDL gap-analysis generator",
        "created": today,
        "last_modified": today,
        "test_method": "none",
    }
    rule["triage_steps"] = steps_for(rule)
    return rule


def write_rule(rule):
    folder = RULES_DIR / TACTIC_FOLDER[rule["tactic"]]
    folder.mkdir(parents=True, exist_ok=True)
    fname = f"TDL-{int(rule['v4_id']):06d}.yaml"
    path = folder / fname
    with path.open("w") as f:
        yaml.safe_dump(rule, f, sort_keys=False, default_flow_style=False, width=120)
    return path


def main():
    matrix = parse_canonical_matrix()
    existing = existing_pairs()
    nxt = next_id_counter()

    gaps = []
    for tactic, techs in matrix.items():
        for tid, tname in techs:
            if (tactic, tid) not in existing:
                gaps.append((tactic, tid, tname))

    print(f"Canonical cells:    {sum(len(v) for v in matrix.values())}")
    print(f"Already covered:    {len(existing)}")
    print(f"Gaps to fill:       {len(gaps)}")

    written = []
    for tactic, tid, tname in gaps:
        v4 = nxt()
        rule = build_rule(tactic, tid, tname, v4)
        path = write_rule(rule)
        written.append((rule["rule_id"], path.relative_to(ROOT)))

    print(f"\nWrote {len(written)} new rule(s):")
    for rid, path in written[:5]:
        print(f"  {rid}  →  {path}")
    if len(written) > 5:
        print(f"  ... and {len(written)-5} more")


if __name__ == "__main__":
    main()
