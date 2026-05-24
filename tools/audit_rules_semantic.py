#!/usr/bin/env python3
"""Semantic rule audit — uses the per-language SIEM specialist agents
(tools/agents/) for per-query validation, plus one small generalist call for
cross-cutting checks (false_positives, triage_steps, severity sanity).

Per-query: each query is graded by the specialist for that language
(SPLAgent, KQLAgent, …). The specialist scores 0–100 and lists specific
issues — wrong field names, missing thresholds, syntax bugs, logic gaps.

Cross-cutting: one Claude call with just the non-query fields, focused on
whether the false_positives are realistic, triage_steps name the actual
technique, and severity/fidelity match the detection profile.

Results are merged into exports/audit_results.json under each rule's
`semantic_issues` array, alongside the structural findings from
tools/audit_rules.py.

USAGE
    # cost-only estimate, no API calls (free)
    python3 tools/audit_rules_semantic.py --dry-run

    # validate the wiring on a small sample
    ANTHROPIC_API_KEY=... python3 tools/audit_rules_semantic.py --limit 5

    # full run
    ANTHROPIC_API_KEY=... python3 tools/audit_rules_semantic.py

    # resume — skip rules that already have semantic_issues recorded
    ANTHROPIC_API_KEY=... python3 tools/audit_rules_semantic.py --resume

    # filter
    python3 tools/audit_rules_semantic.py --tactic credential-access
    python3 tools/audit_rules_semantic.py --rule-id TDL-CA-000019
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
OUT_PATH = ROOT / "exports" / "audit_results.json"

# Models. Both are env-overridable. Defaults are Haiku 4.5 — cheap + fast +
# higher rate limits, plenty capable for grading a query against pseudo-logic.
# (The per-language specialists are pinned via the AGENT_MODEL env var that
# tools/agents/base_agent.py already reads.)
import os as _os
CROSS_MODEL = _os.environ.get("AUDIT_CROSS_MODEL", "claude-haiku-4-5")
CROSS_MAX_TOKENS = 1500

# Batch runs ride out 429 storms instead of dropping calls — the runtime server
# uses the lower default (2) in base_agent.py to keep /generate responsive.
_os.environ.setdefault("AGENT_MAX_RETRIES", "6")

# Haiku 4.5 pricing (USD per MTok)
INPUT_PRICE = 1.00
OUTPUT_PRICE = 5.00

# Cap per-language issues — anything beyond this is the model going off the
# rails. Earlier runs produced rules with 1000+ findings from one language.
MAX_ISSUES_PER_LANG = 15


CROSS_SYSTEM_PROMPT = """You are a senior detection engineer reviewing the NON-QUERY parts of a rule.

You will NOT review the queries themselves — language specialists handle that.

Audit these dimensions and call `record_cross_audit` with your findings:

1. FALSE_POSITIVES_PLAUSIBLE — are the listed false_positives realistic for THIS specific technique, or generic filler ("Security software", "Authorized admin tools", "Legitimate use")? Real FPs name specific tools, workflows, or scenarios that match this exact detection.

2. TRIAGE_STEPS_ACTIONABLE — do the triage_steps name this specific technique and give technique-specific investigation actions (referencing actual event fields, encryption types, IPs, accounts)? Generic steps that could apply to any rule in this tactic are a problem.

3. SEVERITY_FIDELITY_SANE — is severity / fidelity consistent with the realism of the detection and the false-positive risk? Rules with generic FPs and shallow triage should probably not be Critical/High-fidelity.

Rules:
- Be terse — one short sentence per finding.
- Only report real problems. Don't pad. Empty findings list is the right answer for a solid rule.
- Severity levels: "critical" (rule is broken or misleading), "major" (significant gap), "minor" (polish).
"""

CROSS_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "enum": [
                            "false_positives_generic",
                            "false_positives_missing_scenario",
                            "triage_steps_generic",
                            "triage_steps_missing_indicator",
                            "severity_overrated",
                            "severity_underrated",
                            "other",
                        ],
                    },
                    "severity": {"type": "string", "enum": ["critical", "major", "minor"]},
                    "message": {"type": "string"},
                },
                "required": ["code", "severity", "message"],
            },
        }
    },
    "required": ["findings"],
}


def cross_cost(base_in: int, cache_create: int, cache_read: int, output_tok: int) -> float:
    """Correct per-token-bucket pricing. Cache creation = 1.25x, cache read = 0.1x."""
    return (
        (base_in / 1_000_000) * INPUT_PRICE
        + (cache_create / 1_000_000) * INPUT_PRICE * 1.25
        + (cache_read / 1_000_000) * INPUT_PRICE * 0.10
        + (output_tok / 1_000_000) * OUTPUT_PRICE
    )


def score_to_severity(score: int) -> str:
    """Map a specialist's 0–100 score onto our finding severity scale."""
    if score < 50:
        return "critical"
    if score < 75:
        return "major"
    return "minor"


def cross_payload(rule: dict) -> str:
    keep = {
        "rule_id": rule.get("rule_id"),
        "name": rule.get("name"),
        "description": rule.get("description"),
        "tactic": rule.get("tactic"),
        "technique_id": rule.get("technique_id"),
        "technique_name": rule.get("technique_name"),
        "platform": rule.get("platform"),
        "data_sources": rule.get("data_sources"),
        "severity": rule.get("severity"),
        "fidelity": rule.get("fidelity"),
        "pseudo_logic": rule.get("pseudo_logic"),
        "false_positives": rule.get("false_positives"),
        "triage_steps": rule.get("triage_steps"),
    }
    return json.dumps(keep, indent=2, default=str)


def cross_audit(client, rule: dict) -> dict:
    """Run the non-query audit. Returns {findings, input_tokens, output_tokens, cost_usd}."""
    resp = client.messages.create(
        model=CROSS_MODEL,
        max_tokens=CROSS_MAX_TOKENS,
        system=[{
            "type": "text",
            "text": CROSS_SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }],
        tools=[{
            "name": "record_cross_audit",
            "description": "Record non-query audit findings for a detection rule.",
            "input_schema": CROSS_TOOL_SCHEMA,
        }],
        tool_choice={"type": "tool", "name": "record_cross_audit"},
        messages=[{"role": "user", "content": f"Audit this rule (non-query fields only):\n\n{cross_payload(rule)}"}],
    )
    findings: list[dict] = []
    for block in resp.content:
        if getattr(block, "type", None) == "tool_use" and block.name == "record_cross_audit":
            findings = list((block.input or {}).get("findings") or [])
            break

    u = resp.usage
    base_in = getattr(u, "input_tokens", 0) or 0
    cache_create = getattr(u, "cache_creation_input_tokens", 0) or 0
    cache_read = getattr(u, "cache_read_input_tokens", 0) or 0
    output_tok = getattr(u, "output_tokens", 0) or 0
    return {
        "findings": findings,
        "input_tokens": base_in + cache_create + cache_read,
        "output_tokens": output_tok,
        "cost_usd": cross_cost(base_in, cache_create, cache_read, output_tok),
    }


def audit_one_rule(client, orchestrator, rule: dict) -> dict:
    """One rule → semantic_issues list + cost + per-language scores."""
    # 1. Per-language query validation via the specialist agents (parallel).
    val = orchestrator.validate_rule_queries(rule)
    semantic_issues: list[dict] = []
    per_lang_scores = {}
    for lang, result in (val.get("results") or {}).items():
        score = result.get("score") or 0
        per_lang_scores[lang] = score
        issues = result.get("issues") or []
        if not issues:
            continue
        # Cap hallucinated runs — if a specialist returns more issues than this,
        # keep only the first N (they're typically sorted by importance).
        if len(issues) > MAX_ISSUES_PER_LANG:
            issues = issues[:MAX_ISSUES_PER_LANG]
        sev = score_to_severity(score)
        for msg in issues:
            semantic_issues.append({
                "code": "pseudo_query_mismatch" if not result.get("valid") else "query_quality_low",
                "severity": sev,
                "lang": lang,
                "score": score,
                "message": msg,
            })

    agents_total = val.get("total") or {}

    # 2. Cross-cutting (non-query) audit.
    cross = cross_audit(client, rule)
    for f in cross["findings"]:
        semantic_issues.append({
            "code": f.get("code"),
            "severity": f.get("severity"),
            "message": f.get("message"),
        })

    return {
        "semantic_issues": semantic_issues,
        "per_language_scores": per_lang_scores,
        "overall_query_score": val.get("overall_score"),
        "agents_cost_usd": float(agents_total.get("cost_usd") or 0.0),
        "agents_input_tokens": int(agents_total.get("input_tokens") or 0),
        "agents_output_tokens": int(agents_total.get("output_tokens") or 0),
        "cross_cost_usd": float(cross["cost_usd"]),
        "cross_input_tokens": int(cross["input_tokens"]),
        "cross_output_tokens": int(cross["output_tokens"]),
    }


def load_rules(tactic: str | None, rule_id: str | None) -> list[tuple[Path, dict]]:
    base = RULES_DIR / tactic if tactic else RULES_DIR
    out = []
    for path in sorted(base.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        if rule_id and doc.get("rule_id") != rule_id:
            continue
        out.append((path, doc))
    return out


def load_existing() -> dict:
    if not OUT_PATH.exists():
        return {}
    try:
        return json.loads(OUT_PATH.read_text())
    except json.JSONDecodeError:
        return {}


def save(existing: dict) -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(existing, indent=2))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--tactic")
    ap.add_argument("--rule-id")
    ap.add_argument("--resume", action="store_true",
                    help="Skip rules that already have semantic_issues recorded.")
    ap.add_argument("--concurrency", type=int, default=1,
                    help="How many rules to audit in parallel. Each rule fans out 10 specialists + 1 generalist, so effective in-flight requests = 11×concurrency. Default 1 keeps bursts under Haiku tier limits; raise only if you've checked headroom.")
    ap.add_argument("--max-cost", type=float, default=10.0,
                    help="HARD CEILING: abort the run cleanly when this dollar amount is spent. "
                         "Default $10. Pass a larger value to permit a bigger run. Set to 0 to disable.")
    ap.add_argument("--yes", action="store_true",
                    help="Skip the pre-flight confirmation prompt. Without --yes you'll see the "
                         "cost estimate and have to confirm before any API calls happen.")
    args = ap.parse_args()

    rules = load_rules(args.tactic, args.rule_id)
    existing = load_existing()
    existing_rules = existing.get("rules") or {}

    if args.resume:
        rules = [(p, r) for (p, r) in rules
                 if not (existing_rules.get(r.get("rule_id") or "") or {}).get("semantic_issues")]

    if args.limit:
        rules = rules[: args.limit]

    if not rules:
        print("No rules in scope.")
        return 0

    # Cost estimate uses EMPIRICAL data from already-audited rules in this
    # repo's ledger (exports/audit_results.json). Falls back to a rough $0.013
    # per rule if no data is available yet.
    ledger_costs = []
    if OUT_PATH.exists():
        try:
            led = json.loads(OUT_PATH.read_text())
            for r in (led.get("rules") or {}).values():
                c = (r.get("semantic_cost") or {}).get("total_usd")
                if isinstance(c, (int, float)) and c > 0:
                    ledger_costs.append(float(c))
        except json.JSONDecodeError:
            pass
    if ledger_costs:
        ledger_costs.sort()
        p75 = ledger_costs[int(len(ledger_costs) * 0.75)]
        p95 = ledger_costs[min(len(ledger_costs) - 1, int(len(ledger_costs) * 0.95))]
        est_likely = len(rules) * p75
        est_worst = len(rules) * p95
        est_source = f"empirical (n={len(ledger_costs)} prior rules)"
    else:
        p75 = p95 = 0.013
        est_likely = est_worst = len(rules) * 0.013
        est_source = "rough default (no empirical data yet)"

    waste = {1: 1.00, 2: 1.05, 3: 1.20, 4: 1.40, 5: 1.70, 6: 2.20, 8: 2.80} \
              .get(args.concurrency, 1.0 + 0.4 * args.concurrency)

    agent_model = _os.environ.get("AGENT_MODEL", "default (see base_agent.AGENT_MODEL)")
    print(f"\n  Semantic audit (specialist agents + cross-cutting)")
    print(f"  Rules to audit:    {len(rules)}")
    print(f"  Specialist model:  {agent_model}")
    print(f"  Cross-cut model:   {CROSS_MODEL}")
    print(f"  Cost basis:        {est_source}, per-rule p75=${p75:.4f} p95=${p95:.4f}")
    print(f"  Concurrency:       {args.concurrency}  (rate-limit waste multiplier: {waste:.2f}x)")
    print(f"  Estimated cost:")
    print(f"    likely (p75 × waste):     ${est_likely * waste:.2f}")
    print(f"    worst-case (p95 × waste): ${est_worst * waste:.2f}")
    print(f"  Hard ceiling (--max-cost):  ${args.max_cost:.2f}" + (" (DISABLED)" if args.max_cost == 0 else ""))
    print()

    if args.dry_run:
        return 0

    if not args.yes:
        reply = input("  Continue? Type 'yes' to proceed: ").strip().lower()
        if reply != "yes":
            print("  Aborted. No API calls made.")
            return 0

    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY is not set", file=sys.stderr)
        return 2
    try:
        from anthropic import Anthropic
    except ImportError:
        print("anthropic SDK not installed — pip install anthropic", file=sys.stderr)
        return 2

    from tools.agents import AgentOrchestrator
    orchestrator = AgentOrchestrator()
    # 2 retries with backoff. Beyond that, the rule is skipped — --resume will
    # pick it up later. 8 retries (the prior setting) is what made the conc=6
    # run burn ~$30 of input tokens on rules that ultimately failed anyway.
    client = Anthropic(max_retries=2)

    if not existing:
        existing = {"generated_at": datetime.now(timezone.utc).isoformat(), "rules": {}}
    if "rules" not in existing:
        existing["rules"] = {}

    total_cost = 0.0
    total_findings = 0
    done = 0
    started = time.time()
    save_lock = __import__("threading").Lock()
    aborted = False

    def submit(rule):
        return audit_one_rule(client, orchestrator, rule)

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(submit, doc): (path, doc) for path, doc in rules}
        for fut in as_completed(futures):
            path, doc = futures[fut]
            rid = doc.get("rule_id") or path.stem

            # Hard ceiling — stop accepting results once we cross the budget.
            # In-flight requests will finish (their cost is already incurred)
            # but no new ones will be considered. --max-cost 0 disables.
            if args.max_cost and total_cost >= args.max_cost:
                if not aborted:
                    print(f"\n  ✋  HARD CEILING REACHED: spent ${total_cost:.2f} >= ${args.max_cost:.2f}", flush=True)
                    print(f"      Cancelling remaining work. Run with --resume --max-cost <higher> to continue.\n", flush=True)
                    aborted = True
                for f in futures:
                    f.cancel()
                continue

            try:
                res = fut.result()
            except Exception as e:
                print(f"  ✗ {rid}: {type(e).__name__}: {e}", file=sys.stderr)
                continue

            with save_lock:
                entry = existing["rules"].get(rid) or {
                    "rule_id": rid,
                    "file": str(path.relative_to(ROOT)),
                    "name": doc.get("name"),
                    "structural_issues": [],
                    "semantic_issues": [],
                }
                entry["semantic_issues"] = res["semantic_issues"]
                entry["per_language_scores"] = res["per_language_scores"]
                entry["overall_query_score"] = res["overall_query_score"]
                entry["semantic_audited_at"] = datetime.now(timezone.utc).isoformat()
                entry["semantic_model"] = f"agents + {CROSS_MODEL}"
                # Record actual cost per rule so future estimates can use real data,
                # not hand-waving. agents_cost_usd already uses correct cache pricing.
                entry["semantic_cost"] = {
                    "agents_usd": round(res["agents_cost_usd"], 6),
                    "cross_usd": round(res["cross_cost_usd"], 6),
                    "total_usd": round(res["agents_cost_usd"] + res["cross_cost_usd"], 6),
                    "agents_input_tokens": res["agents_input_tokens"],
                    "agents_output_tokens": res["agents_output_tokens"],
                    "cross_input_tokens": res["cross_input_tokens"],
                    "cross_output_tokens": res["cross_output_tokens"],
                }
                existing["rules"][rid] = entry
                save(existing)

            cost = res["agents_cost_usd"] + res["cross_cost_usd"]
            total_cost += cost
            total_findings += len(res["semantic_issues"])
            done += 1

            n_crit = sum(1 for f in res["semantic_issues"] if f.get("severity") == "critical")
            n_maj = sum(1 for f in res["semantic_issues"] if f.get("severity") == "major")
            marker = "✗" if n_crit else ("!" if n_maj else "·")
            score = res["overall_query_score"]
            print(f"  {marker} {rid:<22} q-score:{score:>3}  {len(res['semantic_issues'])} findings  "
                  f"({n_crit}c/{n_maj}m)  ${cost:.4f}", flush=True)

    elapsed = time.time() - started
    print(f"\n  Done: {done}/{len(rules)} rules audited in {elapsed:.1f}s")
    print(f"  Total findings: {total_findings}")
    print(f"  Actual cost:    ${total_cost:.4f}")
    print(f"  Report:         {OUT_PATH.relative_to(ROOT)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
