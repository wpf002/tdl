#!/usr/bin/env python3
"""Anthropic Batch API pipeline: audit + regenerate SIEM queries.

Pipeline (run in order):

    python3 tools/regen/batch.py audit-extract
    python3 tools/regen/batch.py audit-submit
    python3 tools/regen/batch.py audit-fetch
    python3 tools/regen/batch.py audit-summary
    python3 tools/regen/batch.py regen-extract
    python3 tools/regen/batch.py regen-submit
    python3 tools/regen/batch.py regen-fetch
    python3 tools/regen/batch.py apply             # writes back to rules/*.yaml

Cost estimate (Sonnet 4.6, Batch API = 50% off, prompt caching on system):
    Audit ~715 rules → ~$5-8
    Regen ~half the rules → ~$8-12
    Total ~$15-20 (vs interactive Claude Code burn).

Requires:
    pip install anthropic pyyaml
    export ANTHROPIC_API_KEY=...
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "rules"
WORK_DIR = ROOT / ".regen-validation"
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"

AUDIT_REQUESTS = WORK_DIR / "audit_requests.jsonl"
AUDIT_BATCH_ID = WORK_DIR / "audit_batch_id.txt"
AUDIT_RESULTS_DIR = WORK_DIR / "audit_results"
AUDIT_SUMMARY = WORK_DIR / "audit_summary.json"

REGEN_REQUESTS = WORK_DIR / "regen_requests.jsonl"
REGEN_BATCH_ID = WORK_DIR / "regen_batch_id.txt"
REGEN_RESULTS_DIR = WORK_DIR / "regen_results"

MODEL = os.environ.get("REGEN_MODEL", "claude-sonnet-4-6")
QUERY_KEYS = ["spl", "kql", "aql", "yara_l", "esql", "leql",
              "crowdstrike", "xql", "lucene", "sumo"]


# ── rule discovery ──────────────────────────────────────────────────────────

def iter_rules():
    """Yield (path, rule_dict) for every YAML rule under rules/."""
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        try:
            with open(path) as f:
                rule = yaml.safe_load(f)
        except Exception as e:
            print(f"[skip] {path}: {e}", file=sys.stderr)
            continue
        if not isinstance(rule, dict) or not rule.get("rule_id"):
            continue
        yield path, rule


def rule_audit_payload(rule: dict) -> dict:
    """Compact payload sent to the audit prompt."""
    queries = rule.get("queries", {}) or {}
    return {
        "rule_id": rule["rule_id"],
        "name": rule.get("name", ""),
        "pseudo_logic": rule.get("pseudo_logic", ""),
        "data_sources": rule.get("data_sources", []),
        "platform": rule.get("platform", []),
        "severity": rule.get("severity", ""),
        "queries": {k: queries.get(k, "") for k in QUERY_KEYS},
    }


def rule_regen_payload(rule: dict) -> dict:
    """Compact payload sent to the regen prompt."""
    return {
        "rule_id": rule["rule_id"],
        "name": rule.get("name", ""),
        "description": rule.get("description", ""),
        "pseudo_logic": rule.get("pseudo_logic", ""),
        "data_sources": rule.get("data_sources", []),
        "platform": rule.get("platform", []),
        "technique_id": rule.get("technique_id", ""),
        "severity": rule.get("severity", ""),
    }


# ── batch request builders ──────────────────────────────────────────────────

def load_prompt(name: str) -> str:
    return (PROMPTS_DIR / f"{name}.md").read_text()


def build_request(custom_id: str, system_prompt: str, user_payload: dict) -> dict:
    """One Batch API request. System prompt is cached so all requests share it."""
    return {
        "custom_id": custom_id,
        "params": {
            "model": MODEL,
            "max_tokens": 4096,
            "system": [
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            "messages": [
                {
                    "role": "user",
                    "content": json.dumps(user_payload, ensure_ascii=False),
                }
            ],
        },
    }


# ── extract steps ───────────────────────────────────────────────────────────

def cmd_audit_extract(args):
    WORK_DIR.mkdir(exist_ok=True)
    system = load_prompt("audit")
    n = 0
    with open(AUDIT_REQUESTS, "w") as f:
        for _, rule in iter_rules():
            if not rule.get("pseudo_logic"):
                continue
            req = build_request(rule["rule_id"], system, rule_audit_payload(rule))
            f.write(json.dumps(req) + "\n")
            n += 1
    print(f"wrote {n} audit requests → {AUDIT_REQUESTS}")


def cmd_regen_extract(args):
    WORK_DIR.mkdir(exist_ok=True)
    if not AUDIT_SUMMARY.exists():
        sys.exit(f"missing {AUDIT_SUMMARY} — run audit-summary first")
    summary = json.loads(AUDIT_SUMMARY.read_text())
    flagged = {r["rule_id"] for r in summary["rules"]
               if r["recommendation"] == "regenerate"}
    if not flagged:
        sys.exit("no rules flagged for regen — nothing to do")

    system = load_prompt("regen")
    n = 0
    with open(REGEN_REQUESTS, "w") as f:
        for _, rule in iter_rules():
            if rule["rule_id"] not in flagged:
                continue
            req = build_request(rule["rule_id"], system, rule_regen_payload(rule))
            f.write(json.dumps(req) + "\n")
            n += 1
    print(f"wrote {n} regen requests → {REGEN_REQUESTS}")


# ── submit / fetch ──────────────────────────────────────────────────────────

def _client():
    try:
        from anthropic import Anthropic
    except ImportError:
        sys.exit("pip install anthropic")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY not set")
    return Anthropic()


def _submit(jsonl_path: Path, batch_id_path: Path):
    client = _client()
    requests = [json.loads(line) for line in jsonl_path.read_text().splitlines() if line]
    print(f"submitting {len(requests)} requests …")
    batch = client.messages.batches.create(requests=requests)
    batch_id_path.write_text(batch.id)
    print(f"batch_id = {batch.id}  (saved to {batch_id_path})")
    print("Anthropic processes batches within 24h — usually much faster.")
    print(f"Run `python3 {sys.argv[0]} {jsonl_path.stem.replace('_requests', '')}-fetch` to poll.")


def _fetch(batch_id_path: Path, results_dir: Path, kind: str):
    client = _client()
    if not batch_id_path.exists():
        sys.exit(f"missing {batch_id_path} — submit the batch first")
    batch_id = batch_id_path.read_text().strip()
    results_dir.mkdir(exist_ok=True)

    while True:
        batch = client.messages.batches.retrieve(batch_id)
        counts = batch.request_counts
        print(f"[{kind}] status={batch.processing_status} "
              f"processing={counts.processing} succeeded={counts.succeeded} "
              f"errored={counts.errored} canceled={counts.canceled} "
              f"expired={counts.expired}")
        if batch.processing_status == "ended":
            break
        time.sleep(30)

    print("downloading results …")
    n_ok, n_err = 0, 0
    for entry in client.messages.batches.results(batch_id):
        custom_id = entry.custom_id
        if entry.result.type == "succeeded":
            text = entry.result.message.content[0].text
            try:
                parsed = json.loads(_strip_json_fence(text))
                (results_dir / f"{custom_id}.json").write_text(
                    json.dumps(parsed, indent=2)
                )
                n_ok += 1
            except json.JSONDecodeError:
                (results_dir / f"{custom_id}.raw.txt").write_text(text)
                n_err += 1
        else:
            (results_dir / f"{custom_id}.error.json").write_text(
                json.dumps(entry.result.model_dump(), indent=2)
            )
            n_err += 1
    print(f"done. ok={n_ok} err={n_err} → {results_dir}")


def _strip_json_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:] if lines[0].startswith("```") else lines
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    return text


def cmd_audit_submit(args):
    _submit(AUDIT_REQUESTS, AUDIT_BATCH_ID)


def cmd_audit_fetch(args):
    _fetch(AUDIT_BATCH_ID, AUDIT_RESULTS_DIR, "audit")


def cmd_regen_submit(args):
    _submit(REGEN_REQUESTS, REGEN_BATCH_ID)


def cmd_regen_fetch(args):
    _fetch(REGEN_BATCH_ID, REGEN_RESULTS_DIR, "regen")


# ── audit summary ───────────────────────────────────────────────────────────

def cmd_audit_summary(args):
    if not AUDIT_RESULTS_DIR.exists():
        sys.exit(f"missing {AUDIT_RESULTS_DIR} — run audit-fetch first")
    rules = []
    for path in sorted(AUDIT_RESULTS_DIR.glob("*.json")):
        if path.name.endswith(".error.json"):
            continue
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        rules.append({
            "rule_id": data.get("rule_id", path.stem),
            "min_score": data.get("min_score"),
            "max_score": data.get("max_score"),
            "mean_score": data.get("mean_score"),
            "recommendation": data.get("recommendation"),
        })

    by_rec = {"regenerate": 0, "tune": 0, "ok": 0}
    for r in rules:
        by_rec[r.get("recommendation", "")] = by_rec.get(r.get("recommendation", ""), 0) + 1

    summary = {"total": len(rules), "by_recommendation": by_rec, "rules": rules}
    AUDIT_SUMMARY.write_text(json.dumps(summary, indent=2))
    print(f"audited {len(rules)} rules:")
    for k, v in by_rec.items():
        print(f"  {k}: {v}")
    print(f"summary → {AUDIT_SUMMARY}")


# ── apply ───────────────────────────────────────────────────────────────────

class _BlockStr(str):
    pass


def _block_str_rep(d, data):
    return d.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(_BlockStr, _block_str_rep)


def cmd_apply(args):
    if not REGEN_RESULTS_DIR.exists():
        sys.exit(f"missing {REGEN_RESULTS_DIR} — run regen-fetch first")
    rules_by_id = {rule["rule_id"]: path for path, rule in iter_rules()}

    n_applied, n_skipped = 0, 0
    for path in sorted(REGEN_RESULTS_DIR.glob("*.json")):
        if path.name.endswith(".error.json"):
            continue
        rule_id = path.stem
        target = rules_by_id.get(rule_id)
        if not target:
            print(f"[skip] no YAML for {rule_id}")
            n_skipped += 1
            continue
        try:
            new_queries = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            print(f"[skip] {rule_id}: {e}")
            n_skipped += 1
            continue
        if not isinstance(new_queries, dict):
            print(f"[skip] {rule_id}: not a dict")
            n_skipped += 1
            continue
        missing = [k for k in QUERY_KEYS if k not in new_queries]
        if missing:
            print(f"[skip] {rule_id}: missing keys {missing}")
            n_skipped += 1
            continue

        with open(target) as f:
            rule = yaml.safe_load(f)
        rule["queries"] = {k: _BlockStr(new_queries[k].rstrip() + "\n")
                           for k in QUERY_KEYS}
        with open(target, "w") as f:
            yaml.dump(rule, f, sort_keys=False, allow_unicode=True, width=120)
        n_applied += 1

    print(f"applied {n_applied} rules; skipped {n_skipped}")


# ── main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, fn in [
        ("audit-extract", cmd_audit_extract),
        ("audit-submit", cmd_audit_submit),
        ("audit-fetch", cmd_audit_fetch),
        ("audit-summary", cmd_audit_summary),
        ("regen-extract", cmd_regen_extract),
        ("regen-submit", cmd_regen_submit),
        ("regen-fetch", cmd_regen_fetch),
        ("apply", cmd_apply),
    ]:
        p = sub.add_parser(name)
        p.set_defaults(func=fn)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
