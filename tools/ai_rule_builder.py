"""Phase 4 — AI rule builder.

Generates a full TDL rule (metadata + all 10 SIEM queries) from a natural-language
prompt using Claude Sonnet 4.6. Per-Generate spend ~$0.03–0.05 estimated, $0.10
hard-bounded by max_tokens.

Cost model (Sonnet 4.6, non-batch):
    $3.00 / MTok input
    $15.00 / MTok output

Usage from server:
    result = generate_rule(prompt, technique_id="T1078", platforms=["Windows"])
    # result = {"rule": {...}, "usage": {"input_tokens": ..., "output_tokens": ..., "cost_usd": ...}}

Reads ANTHROPIC_API_KEY from env. Never logs or returns the key.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

MODEL = os.environ.get("AI_BUILDER_MODEL", "claude-sonnet-4-6")
MAX_OUTPUT_TOKENS = 4000
INPUT_PRICE_PER_MTOK = 3.00
OUTPUT_PRICE_PER_MTOK = 15.00

QUERY_KEYS = ["spl", "kql", "aql", "yara_l", "esql", "leql",
              "crowdstrike", "xql", "lucene", "sumo"]

VALID_TACTICS = {
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Command and Control", "Collection", "Exfiltration", "Impact",
}
VALID_SEVERITY = {"Critical", "High", "Medium", "Low"}
VALID_FIDELITY = {"High", "Medium", "Low"}

SYSTEM_PROMPT = """You are a senior detection engineer authoring rules for the TDL Playbook library.

Output a single TDL detection rule as a strict JSON object. Do not include any prose, markdown fences, or commentary — only the JSON.

Required keys:
- name: short imperative title (≤80 chars)
- description: 1–2 sentences on what this detects
- tactic: one of: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Command and Control, Collection, Exfiltration, Impact
- tactic_id: matching MITRE TA00xx code
- technique_id: MITRE T-code (e.g. T1078, T1059.001)
- technique_name: matching technique name
- platform: list of platforms (Windows, Linux, macOS, AWS, Azure, GCP, Okta, Microsoft 365, Network, Kubernetes, SaaS)
- data_sources: list of strings (log sources / event types)
- severity: Critical | High | Medium | Low
- fidelity: High | Medium | Low
- risk_score: integer 1–100
- pseudo_logic: plain-English description of the detection logic, including thresholds and exclusions
- queries: object with these 10 keys, each containing a runnable query for that SIEM:
    spl (Splunk), kql (Microsoft Sentinel/Defender), aql (IBM QRadar),
    yara_l (Chronicle), esql (Elastic), leql (Rapid7),
    crowdstrike (Falcon LogScale), xql (Palo XSIAM), lucene (generic), sumo (Sumo Logic)
- false_positives: list of strings
- triage_steps: list of 4–6 imperative analyst steps
- tuning_guidance: 1–2 sentences on tuning
- tags: list of short kebab-case tags
- test_method: one of: Atomic, Caldera, Manual, none

Quality bar:
- Queries must be syntactically valid for their respective SIEM.
- Use realistic field names from the data_sources you list.
- Pseudo_logic must match the queries (same thresholds, same exclusions).
- Severity/fidelity must match the realistic detection profile.
"""


def _user_prompt(prompt: str, technique_id: str | None, platforms: list[str] | None,
                 primary_siem: str | None) -> str:
    parts = [f"Detection request: {prompt.strip()}"]
    if technique_id:
        parts.append(f"\nTarget MITRE technique: {technique_id}")
    if platforms:
        parts.append(f"\nTarget platforms: {', '.join(platforms)}")
    if primary_siem:
        parts.append(f"\nThe analyst's primary SIEM is {primary_siem} — make that query especially strong.")
    parts.append("\nReturn the rule as a single JSON object, nothing else.")
    return "".join(parts)


def estimate_cost(input_tokens: int, output_tokens: int) -> float:
    return (
        (input_tokens / 1_000_000) * INPUT_PRICE_PER_MTOK
        + (output_tokens / 1_000_000) * OUTPUT_PRICE_PER_MTOK
    )


def max_call_cost() -> float:
    """Hard upper bound for one generate call.

    Assumes worst-case ~3000 tokens input (system + context) and the full
    MAX_OUTPUT_TOKENS output ceiling.
    """
    return estimate_cost(3000, MAX_OUTPUT_TOKENS)


def _parse_rule_json(text: str) -> dict:
    s = text.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", s, re.DOTALL)
        if m:
            return json.loads(m.group(0))
        raise


def _validate_rule(rule: dict) -> None:
    required = ["name", "description", "tactic", "technique_id", "technique_name",
                "platform", "data_sources", "severity", "fidelity", "risk_score",
                "pseudo_logic", "queries"]
    missing = [k for k in required if not rule.get(k)]
    if missing:
        raise ValueError(f"generated rule missing required fields: {missing}")
    if rule["tactic"] not in VALID_TACTICS:
        raise ValueError(f"invalid tactic: {rule['tactic']!r}")
    if rule["severity"] not in VALID_SEVERITY:
        raise ValueError(f"invalid severity: {rule['severity']!r}")
    if rule["fidelity"] not in VALID_FIDELITY:
        raise ValueError(f"invalid fidelity: {rule['fidelity']!r}")
    queries = rule.get("queries") or {}
    if not isinstance(queries, dict):
        raise ValueError("queries must be an object")
    missing_q = [k for k in QUERY_KEYS if not queries.get(k)]
    if missing_q:
        raise ValueError(f"generated rule missing SIEM queries: {missing_q}")


def generate_rule(
    prompt: str,
    *,
    technique_id: str | None = None,
    platforms: list[str] | None = None,
    primary_siem: str | None = None,
) -> dict:
    """Call Claude to generate a TDL rule. Returns {"rule": dict, "usage": dict}.

    Raises RuntimeError if ANTHROPIC_API_KEY is unset.
    Raises ValueError if the model returns an invalid/incomplete rule.
    """
    if not (prompt or "").strip():
        raise ValueError("prompt is required")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY is not set")

    try:
        from anthropic import Anthropic
    except ImportError:
        raise RuntimeError("anthropic SDK not installed — `pip install anthropic`")

    client = Anthropic()
    user = _user_prompt(prompt, technique_id, platforms, primary_siem)

    resp = client.messages.create(
        model=MODEL,
        max_tokens=MAX_OUTPUT_TOKENS,
        system=[{
            "type": "text",
            "text": SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{"role": "user", "content": user}],
    )

    text_parts = [b.text for b in resp.content if getattr(b, "type", None) == "text"]
    raw = "".join(text_parts)
    rule = _parse_rule_json(raw)
    _validate_rule(rule)

    usage = resp.usage
    input_tok = (getattr(usage, "input_tokens", 0) or 0) + \
                (getattr(usage, "cache_creation_input_tokens", 0) or 0) + \
                (getattr(usage, "cache_read_input_tokens", 0) or 0)
    output_tok = getattr(usage, "output_tokens", 0) or 0
    cost = estimate_cost(input_tok, output_tok)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rule.setdefault("created", today)
    rule.setdefault("last_modified", today)
    rule.setdefault("author", "AI")
    rule.setdefault("lifecycle", "Proposed")
    rule.setdefault("test_method", rule.get("test_method") or "none")
    rule.setdefault("tags", rule.get("tags") or [])

    return {
        "rule": rule,
        "usage": {
            "model": MODEL,
            "input_tokens": input_tok,
            "output_tokens": output_tok,
            "cost_usd": round(cost, 6),
        },
    }
