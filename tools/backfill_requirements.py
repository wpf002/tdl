#!/usr/bin/env python3
"""Backfill the `requirements` field onto rules that don't have one.

For each rule with requirements IS NULL:
  1. Heuristic pass — parse data_sources + triage_steps + pseudo_logic + queries
     to extract log-source names and any event IDs mentioned. Windows event IDs
     get friendly names from a built-in map; required-ness is inferred from
     whether the ID appears in the detection logic vs. only in triage.
  2. Claude fallback — for rules where the heuristic finds no event IDs, ask
     Claude to structure a requirements object (real spend; ~$5–8 for 821 rules).

ALWAYS dry-run first. Real spend only with --apply. Claude fallback only with
--use-claude (and --apply).

Run patterns:
    # count + cost estimate, no DB writes, no API calls (free)
    python3 -m tools.backfill_requirements --dry-run

    # heuristic-only backfill (free; no Claude)
    python3 -m tools.backfill_requirements --apply

    # heuristic + Claude fallback for the hard ones (REAL SPEND — asks first)
    ANTHROPIC_API_KEY=... python3 -m tools.backfill_requirements --apply --use-claude
"""

from __future__ import annotations

import argparse
import os
import re
import sys

from dotenv import load_dotenv
load_dotenv()

MODEL = os.environ.get("AI_BUILDER_MODEL", "claude-sonnet-4-6")
MAX_OUTPUT_TOKENS = 800
INPUT_PRICE = 3.00 / 1_000_000
OUTPUT_PRICE = 15.00 / 1_000_000

# Friendly names for the Windows event IDs that show up most in detections.
WINDOWS_EVENT_NAMES = {
    "1102": "Security Log Cleared", "4624": "Successful Logon",
    "4625": "Failed Logon", "4634": "Logoff", "4648": "Logon with Explicit Credentials",
    "4662": "Object Access (DS)", "4663": "Object Access Attempt",
    "4670": "Permissions Changed", "4672": "Special Privileges Assigned",
    "4688": "Process Creation", "4689": "Process Termination",
    "4697": "Service Installed (Security)", "4698": "Scheduled Task Created",
    "4720": "User Account Created", "4722": "User Account Enabled",
    "4724": "Password Reset Attempt", "4728": "Member Added to Global Group",
    "4732": "Member Added to Local Group", "4738": "User Account Changed",
    "4740": "Account Locked Out", "4768": "Kerberos TGT Requested",
    "4769": "Kerberos Service Ticket Requested", "4771": "Kerberos Pre-auth Failed",
    "4776": "NTLM Credential Validation", "5140": "Network Share Accessed",
    "5145": "Network Share Detailed Access", "7045": "New Service Installed (System)",
    "4104": "PowerShell Script Block", "4103": "PowerShell Module Logging",
    "1": "Sysmon Process Creation", "3": "Sysmon Network Connection",
    "7": "Sysmon Image Loaded", "8": "Sysmon CreateRemoteThread",
    "10": "Sysmon Process Access", "11": "Sysmon File Created",
    "13": "Sysmon Registry Value Set", "22": "Sysmon DNS Query",
}

EVENT_ID_RE = re.compile(r"\b(?:event\s*(?:id|code)\s*[:=]?\s*)?(\d{1,5})\b", re.IGNORECASE)
# Only treat numbers that look like Windows event IDs (3–4 digits, or known small Sysmon IDs).
KNOWN_IDS = set(WINDOWS_EVENT_NAMES.keys())


def _ids_in_text(text: str) -> set[str]:
    found = set()
    for m in EVENT_ID_RE.finditer(text or ""):
        n = m.group(1)
        if n in KNOWN_IDS:
            found.add(n)
    return found


def heuristic_requirements(rule: dict) -> dict | None:
    """Build a requirements object from the rule's own fields. None if nothing found."""
    queries_text = " ".join((rule.get("queries") or {}).values()) if rule.get("queries") else ""
    logic_text = " ".join(filter(None, [rule.get("pseudo_logic") or "", queries_text]))
    triage_text = " ".join(rule.get("triage_steps") or [])

    required_ids = _ids_in_text(logic_text)         # in detection logic → required
    optional_ids = _ids_in_text(triage_text) - required_ids  # only in triage → optional
    all_ids = required_ids | optional_ids
    if not all_ids:
        return None

    # Group every found event under the rule's first/primary data source name.
    sources = rule.get("data_sources") or []
    primary = sources[0] if sources else "Unknown log source"

    events = []
    for eid in sorted(all_ids, key=lambda x: int(x)):
        events.append({
            "id": eid,
            "name": WINDOWS_EVENT_NAMES.get(eid, f"Event {eid}"),
            "required": eid in required_ids,
        })
    return {"log_sources": [{"source": primary, "events": events}]}


# ── Claude fallback ──────────────────────────────────────────────────────────

CLAUDE_SYSTEM = """You extract a structured `requirements` object for a detection rule.

Given the rule, identify the log source(s) and the specific event IDs each rule
depends on. Mark an event required=true if the detection cannot fire without it,
false if it merely enriches triage. Use real event IDs and names for the platform
(Windows Security/System, Sysmon, etc.). Call report_requirements exactly once."""

REQ_TOOL = {
    "name": "report_requirements",
    "description": "Report the log-source + event-ID requirements for a rule.",
    "input_schema": {
        "type": "object",
        "properties": {
            "log_sources": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "source": {"type": "string"},
                        "events": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "id": {"type": "string"},
                                    "name": {"type": "string"},
                                    "required": {"type": "boolean"},
                                },
                                "required": ["id", "name", "required"],
                            },
                        },
                    },
                    "required": ["source", "events"],
                },
            },
        },
        "required": ["log_sources"],
    },
}


def claude_requirements(client, rule: dict) -> tuple[dict | None, dict]:
    sample = ""
    q = rule.get("queries") or {}
    if q:
        sample = q.get("spl") or q.get("kql") or next(iter(q.values()), "")
    user = (
        f"Name: {rule.get('name')}\n"
        f"Description: {rule.get('description')}\n"
        f"Technique: {rule.get('technique_id')} — {rule.get('technique_name')}\n"
        f"Platforms: {rule.get('platform') or []}\n"
        f"Data sources: {rule.get('data_sources') or []}\n"
        f"Pseudo logic: {rule.get('pseudo_logic') or ''}\n"
        f"Triage steps: {rule.get('triage_steps') or []}\n"
        f"\nSample query:\n```\n{sample}\n```\n"
    )
    resp = client.messages.create(
        model=MODEL,
        max_tokens=MAX_OUTPUT_TOKENS,
        system=[{"type": "text", "text": CLAUDE_SYSTEM, "cache_control": {"type": "ephemeral"}}],
        tools=[REQ_TOOL],
        tool_choice={"type": "tool", "name": "report_requirements"},
        messages=[{"role": "user", "content": user}],
    )
    out = None
    for b in resp.content:
        if getattr(b, "type", None) == "tool_use" and b.name == "report_requirements":
            out = dict(b.input)
            break
    u = resp.usage
    usage = {
        "input": (getattr(u, "input_tokens", 0) or 0) + (getattr(u, "cache_read_input_tokens", 0) or 0)
        + (getattr(u, "cache_creation_input_tokens", 0) or 0),
        "output": getattr(u, "output_tokens", 0) or 0,
    }
    return out, usage


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="Count + cost estimate; no writes, no API")
    ap.add_argument("--apply", action="store_true", help="Write requirements to the DB")
    ap.add_argument("--use-claude", action="store_true", help="Claude fallback for rules with no parsable event IDs (REAL SPEND)")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    from tools.db import db_enabled, session_scope
    from tools.models import Rule

    if not db_enabled():
        print("DATABASE_URL not set — this script operates on the database.", file=sys.stderr)
        return 1

    with session_scope() as s:
        rows = s.query(Rule).filter(Rule.requirements.is_(None)).order_by(Rule.rule_id).all()
        rules = [{
            "rule_id": r.rule_id, "name": r.name, "description": r.description,
            "technique_id": r.technique_id, "technique_name": r.technique_name,
            "platform": r.platform, "data_sources": r.data_sources,
            "pseudo_logic": r.pseudo_logic, "triage_steps": r.triage_steps,
            "queries": r.queries,
        } for r in rows]

    if args.limit is not None:
        rules = rules[:args.limit]

    # Heuristic pass (free).
    heuristic_hits, needs_claude = {}, []
    for r in rules:
        req = heuristic_requirements(r)
        if req:
            heuristic_hits[r["rule_id"]] = req
        else:
            needs_claude.append(r)

    n_claude = len(needs_claude) if args.use_claude else 0
    est_cost = n_claude * (2200 * INPUT_PRICE + 300 * OUTPUT_PRICE)

    print(f"Rules missing requirements : {len(rules)}")
    print(f"  resolved by heuristics   : {len(heuristic_hits)}")
    print(f"  would need Claude        : {len(needs_claude)}"
          f"{'  (skipped — pass --use-claude)' if not args.use_claude else ''}")
    if args.use_claude:
        print(f"Estimated Claude cost      : ${est_cost:.2f}  (model {MODEL})")

    if args.dry_run or not args.apply:
        print("\nDry run (no --apply): nothing written.")
        return 0

    # Claude fallback (real spend) — confirm first.
    claude_hits = {}
    if args.use_claude and needs_claude:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
            return 1
        resp = input(f"\nProceed with ~${est_cost:.2f} of Claude calls for {len(needs_claude)} rules? [y/N] ")
        if resp.strip().lower() not in ("y", "yes"):
            print("Aborted by user. Heuristic results will still be applied.")
            needs_claude = []
        else:
            from anthropic import Anthropic
            from concurrent.futures import ThreadPoolExecutor, as_completed
            client = Anthropic()
            total_in = total_out = 0
            with ThreadPoolExecutor(max_workers=4) as ex:
                futs = {ex.submit(claude_requirements, client, r): r for r in needs_claude}
                for fut in as_completed(futs):
                    r = futs[fut]
                    try:
                        req, usage = fut.result()
                        if req and req.get("log_sources"):
                            claude_hits[r["rule_id"]] = req
                        total_in += usage["input"]; total_out += usage["output"]
                    except Exception as e:
                        print(f"  ✗ {r['rule_id']}: {e}", file=sys.stderr)
            print(f"Claude actual: {total_in:,} in / {total_out:,} out  "
                  f"= ${total_in*INPUT_PRICE + total_out*OUTPUT_PRICE:.2f}")

    all_hits = {**heuristic_hits, **claude_hits}
    if not all_hits:
        print("Nothing to write.")
        return 0

    with session_scope() as s:
        for rule_id, req in all_hits.items():
            row = s.query(Rule).filter(Rule.rule_id == rule_id).one_or_none()
            if row is not None and row.requirements is None:
                row.requirements = req
    print(f"\n✓ Wrote requirements to {len(all_hits)} rules "
          f"({len(heuristic_hits)} heuristic, {len(claude_hits)} Claude).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
