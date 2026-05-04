"""Phase 4 — AI rule builder.

Generates a full TDL rule (metadata + all 10 SIEM queries) from a natural-language
prompt using Claude Sonnet 4.6.

Uses Anthropic tool use with a strict JSON schema for the rule shape, which
guarantees the model returns valid JSON matching the schema (no fragile parsing).

Reads ANTHROPIC_API_KEY from env. Never logs or returns the key.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

MODEL = os.environ.get("AI_BUILDER_MODEL", "claude-sonnet-4-6")
MAX_OUTPUT_TOKENS = 8000
INPUT_PRICE_PER_MTOK = 3.00
OUTPUT_PRICE_PER_MTOK = 15.00

QUERY_KEYS = ["spl", "kql", "aql", "yara_l", "esql", "leql",
              "crowdstrike", "xql", "lucene", "sumo"]

VALID_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Command and Control", "Collection", "Exfiltration", "Impact",
]
VALID_PLATFORMS = [
    "Windows", "Linux", "macOS", "AWS", "Azure", "GCP",
    "Okta", "Microsoft 365", "Network", "Kubernetes", "SaaS",
]
VALID_SEVERITY = ["Critical", "High", "Medium", "Low"]
VALID_FIDELITY = ["High", "Medium", "Low"]
VALID_TEST_METHOD = ["Atomic", "Caldera", "Manual", "none"]

SYSTEM_PROMPT = """You are a senior detection engineer authoring rules for the TDL Playbook library.

When the user describes a detection they want, call the `save_detection_rule` tool exactly once with a complete rule.

Quality bar:
- Every SIEM query must be syntactically valid for that platform.
- Use realistic field names from the data_sources you list.
- pseudo_logic must match the queries (same thresholds, same exclusions).
- Severity / fidelity must reflect the realistic detection profile.
- Triage steps should be 4–6 imperative analyst actions, ordered by what an analyst would actually do.
"""


RULE_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Short imperative title (≤80 chars)"},
        "description": {"type": "string", "description": "1–2 sentences describing what this detects"},
        "tactic": {"type": "string", "enum": VALID_TACTICS},
        "tactic_id": {"type": "string", "description": "MITRE TA00xx code matching the tactic"},
        "technique_id": {"type": "string", "description": "MITRE T-code, e.g. T1078 or T1059.001"},
        "technique_name": {"type": "string"},
        "platform": {
            "type": "array",
            "items": {"type": "string", "enum": VALID_PLATFORMS},
            "minItems": 1,
        },
        "data_sources": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        },
        "severity": {"type": "string", "enum": VALID_SEVERITY},
        "fidelity": {"type": "string", "enum": VALID_FIDELITY},
        "risk_score": {"type": "integer", "minimum": 1, "maximum": 100},
        "pseudo_logic": {"type": "string", "description": "Plain-English detection logic with thresholds and exclusions"},
        "queries": {
            "type": "object",
            "properties": {
                "spl":         {"type": "string", "description": "Splunk SPL"},
                "kql":         {"type": "string", "description": "Microsoft Sentinel/Defender KQL"},
                "aql":         {"type": "string", "description": "IBM QRadar AQL"},
                "yara_l":      {"type": "string", "description": "Chronicle YARA-L"},
                "esql":        {"type": "string", "description": "Elastic ES|QL"},
                "leql":        {"type": "string", "description": "Rapid7 LEQL"},
                "crowdstrike": {"type": "string", "description": "CrowdStrike Falcon LogScale"},
                "xql":         {"type": "string", "description": "Palo Alto XSIAM XQL"},
                "lucene":      {"type": "string", "description": "Generic Lucene"},
                "sumo":        {"type": "string", "description": "Sumo Logic"},
            },
            "required": QUERY_KEYS,
        },
        "false_positives": {"type": "array", "items": {"type": "string"}},
        "triage_steps": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 4,
            "maxItems": 6,
        },
        "tuning_guidance": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "test_method": {"type": "string", "enum": VALID_TEST_METHOD},
    },
    "required": [
        "name", "description", "tactic", "tactic_id",
        "technique_id", "technique_name", "platform", "data_sources",
        "severity", "fidelity", "risk_score", "pseudo_logic",
        "queries", "false_positives", "triage_steps",
        "tuning_guidance", "tags", "test_method",
    ],
}


def _user_prompt(prompt: str, technique_id: str | None, platforms: list[str] | None,
                 primary_siem: str | None) -> str:
    parts = [f"Detection request: {prompt.strip()}"]
    if technique_id:
        parts.append(f"\nTarget MITRE technique: {technique_id}")
    if platforms:
        parts.append(f"\nTarget platforms: {', '.join(platforms)}")
    if primary_siem:
        parts.append(f"\nPrimary SIEM: {primary_siem} — make that query especially strong.")
    return "".join(parts)


def estimate_cost(input_tokens: int, output_tokens: int) -> float:
    return (
        (input_tokens / 1_000_000) * INPUT_PRICE_PER_MTOK
        + (output_tokens / 1_000_000) * OUTPUT_PRICE_PER_MTOK
    )


def max_call_cost() -> float:
    """Upper bound for one generate call: ~3000 input + max_tokens output."""
    return estimate_cost(3000, MAX_OUTPUT_TOKENS)


def generate_rule(
    prompt: str,
    *,
    technique_id: str | None = None,
    platforms: list[str] | None = None,
    primary_siem: str | None = None,
) -> dict:
    """Call Claude with tool use and return {"rule": dict, "usage": dict}.

    The schema-driven tool guarantees the model emits valid JSON matching
    the rule shape — no string parsing required.
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
        tools=[{
            "name": "save_detection_rule",
            "description": "Save a complete TDL detection rule to the library.",
            "input_schema": RULE_TOOL_SCHEMA,
        }],
        tool_choice={"type": "tool", "name": "save_detection_rule"},
        messages=[{"role": "user", "content": user}],
    )

    rule = None
    for block in resp.content:
        if getattr(block, "type", None) == "tool_use" and block.name == "save_detection_rule":
            rule = dict(block.input)
            break
    if rule is None:
        raise ValueError("model did not return a save_detection_rule tool call")

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

    return {
        "rule": rule,
        "usage": {
            "model": MODEL,
            "input_tokens": input_tok,
            "output_tokens": output_tok,
            "cost_usd": round(cost, 6),
        },
    }
