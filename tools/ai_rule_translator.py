"""Phase 5 — translate a source rule (Sigma YAML or SIEM-dialect query) into a complete TDL rule.

Reuses the strict tool-use schema from `ai_rule_builder.py` so the model
returns valid JSON matching the TDL rule shape — no fragile parsing.

Two source-type families:
- 'sigma' — structured Sigma rule (logsource + detection blocks)
- one of the 10 SIEM dialects — raw query string in that dialect
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from tools.ai_rule_builder import (
    MODEL,
    MAX_OUTPUT_TOKENS,
    QUERY_KEYS,
    RULE_TOOL_SCHEMA,
    estimate_cost,
)

# 10 SIEM dialects we support as source formats — must match QUERY_KEYS.
DIALECT_LABELS = {
    "spl":         "Splunk SPL",
    "kql":         "Microsoft Sentinel/Defender KQL",
    "aql":         "IBM QRadar AQL",
    "yara_l":      "Chronicle YARA-L",
    "esql":        "Elastic ES|QL",
    "leql":        "Rapid7 LEQL",
    "crowdstrike": "CrowdStrike Falcon LogScale",
    "xql":         "Palo Alto XSIAM XQL",
    "lucene":      "Generic Lucene",
    "sumo":        "Sumo Logic",
}

SIGMA_SYSTEM_PROMPT = """You are a senior detection engineer importing community Sigma rules into the TDL Playbook library.

The user will provide a Sigma rule (YAML, structured with title/description/logsource/detection blocks). Call the `save_detection_rule` tool exactly once with a complete TDL rule that preserves the original Sigma rule's detection intent.

Mapping guidance:
- Sigma `title` → TDL `name`
- Sigma `description` → TDL `description`
- Sigma `tags` (e.g. `attack.execution`, `attack.t1059.001`) → derive `tactic`, `tactic_id`, `technique_id`, `technique_name`
- Sigma `logsource.product`/`category` → TDL `platform` and `data_sources`
- Sigma `level` (low/medium/high/critical) → TDL `severity`
- Sigma `falsepositives` → TDL `false_positives`
- Sigma `detection` block → derive `pseudo_logic` AND generate ALL 10 SIEM queries that implement the same logic

You MUST generate all 10 SIEM queries (spl, kql, aql, yara_l, esql, leql, crowdstrike, xql, lucene, sumo). Use realistic field names per platform. Triage steps should be 4–6 ordered analyst actions.
"""

DIALECT_SYSTEM_PROMPT = """You are a senior detection engineer importing existing detection queries into the TDL Playbook library.

The user will provide a SIEM detection query in a specific dialect (e.g. Splunk SPL, KQL). Call the `save_detection_rule` tool exactly once with a complete TDL rule that:

1. Preserves the original detection intent — the same query in the original dialect must appear in the `queries` object under its dialect key.
2. Generates the OTHER 9 SIEM queries equivalent to the source. Use realistic field names per platform.
3. Infers all the metadata (name, description, tactic, technique, severity, fidelity, platform, data_sources, pseudo_logic, triage_steps) from the query's content. If the query is ambiguous, pick reasonable defaults that match the technique you infer.
"""


def _user_prompt_sigma(sigma_rule: dict) -> str:
    payload = json.dumps(sigma_rule, default=str, indent=2)
    return f"Sigma rule to import:\n```yaml\n{payload}\n```"


def _user_prompt_dialect(query: str, dialect: str) -> str:
    label = DIALECT_LABELS.get(dialect, dialect)
    return f"Source dialect: {label} ({dialect})\n\nSource query:\n```\n{query}\n```"


def translate_sigma_rule(sigma_rule: dict) -> dict:
    """Sigma → TDL rule. Returns {"rule": dict, "usage": dict}."""
    return _call_translator(SIGMA_SYSTEM_PROMPT, _user_prompt_sigma(sigma_rule))


def translate_dialect_query(query: str, dialect: str) -> dict:
    """SIEM-dialect query → TDL rule. Returns {"rule": dict, "usage": dict}."""
    if dialect not in QUERY_KEYS:
        raise ValueError(f"unsupported dialect: {dialect!r}; must be one of {QUERY_KEYS}")
    return _call_translator(DIALECT_SYSTEM_PROMPT, _user_prompt_dialect(query, dialect))


def _call_translator(system_prompt: str, user_msg: str) -> dict:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    try:
        from anthropic import Anthropic
    except ImportError:
        raise RuntimeError("anthropic SDK not installed — `pip install anthropic`")

    client = Anthropic()
    resp = client.messages.create(
        model=MODEL,
        max_tokens=MAX_OUTPUT_TOKENS,
        system=[{
            "type": "text",
            "text": system_prompt,
            "cache_control": {"type": "ephemeral"},
        }],
        tools=[{
            "name": "save_detection_rule",
            "description": "Save a complete TDL detection rule to the library.",
            "input_schema": RULE_TOOL_SCHEMA,
        }],
        tool_choice={"type": "tool", "name": "save_detection_rule"},
        messages=[{"role": "user", "content": user_msg}],
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
    rule.setdefault("author", "AI (imported)")
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
