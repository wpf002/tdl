"""BaseQueryAgent — shared machinery for the 10 SIEM-language specialist agents.

Each subclass declares its language identity and four prompt fragments
(syntax rules, field conventions, best practices, example queries). The base
class assembles those into a language-specific system prompt and exposes three
Claude-backed methods:

    generate_query(pseudo_logic, tactic, technique, platform, data_sources) -> str
    validate_query(query, pseudo_logic) -> {valid, issues, score, usage}
    improve_query(existing_query, pseudo_logic, instruction) -> str

Every Claude call returns its token usage so the orchestrator can attribute
cost per language. Reads ANTHROPIC_API_KEY from env; never logs it.
"""

from __future__ import annotations

import os

# The spec pins the specialist agents to Sonnet 4.5; override via env if needed.
AGENT_MODEL = os.environ.get("AGENT_MODEL", "claude-sonnet-4-5")

# Per-MTok pricing. Picked by model family substring so AGENT_MODEL changes
# automatically reprice. Override via AGENT_INPUT_PRICE / AGENT_OUTPUT_PRICE
# env vars for one-off models.
_PRICES = {
    "haiku":  (1.00, 5.00),    # Claude Haiku 4.5
    "sonnet": (3.00, 15.00),   # Claude Sonnet 4.5 / 4.6
    "opus":   (15.00, 75.00),  # Claude Opus 4.x
}
_family = next((k for k in _PRICES if k in AGENT_MODEL.lower()), "sonnet")
INPUT_PRICE_PER_MTOK = float(os.environ.get("AGENT_INPUT_PRICE", _PRICES[_family][0]))
OUTPUT_PRICE_PER_MTOK = float(os.environ.get("AGENT_OUTPUT_PRICE", _PRICES[_family][1]))

GENERATE_MAX_TOKENS = 1500
VALIDATE_MAX_TOKENS = 1200
IMPROVE_MAX_TOKENS = 1500


def estimate_cost(input_tokens: int, output_tokens: int) -> float:
    """Plain estimate when token-bucket breakdown isn't available."""
    return (
        (input_tokens / 1_000_000) * INPUT_PRICE_PER_MTOK
        + (output_tokens / 1_000_000) * OUTPUT_PRICE_PER_MTOK
    )


def actual_cost(base_in: int, cache_create: int, cache_read: int, output_tok: int) -> float:
    """Real Anthropic billing: cache creation = 1.25x base, cache read = 0.10x base."""
    return (
        (base_in / 1_000_000) * INPUT_PRICE_PER_MTOK
        + (cache_create / 1_000_000) * INPUT_PRICE_PER_MTOK * 1.25
        + (cache_read / 1_000_000) * INPUT_PRICE_PER_MTOK * 0.10
        + (output_tok / 1_000_000) * OUTPUT_PRICE_PER_MTOK
    )


def _usage_dict(resp, language_key: str) -> dict:
    u = resp.usage
    base_in = getattr(u, "input_tokens", 0) or 0
    cache_create = getattr(u, "cache_creation_input_tokens", 0) or 0
    cache_read = getattr(u, "cache_read_input_tokens", 0) or 0
    output_tok = getattr(u, "output_tokens", 0) or 0
    return {
        "language": language_key,
        "model": AGENT_MODEL,
        "input_tokens": base_in + cache_create + cache_read,
        "base_input_tokens": base_in,
        "cache_creation_input_tokens": cache_create,
        "cache_read_input_tokens": cache_read,
        "output_tokens": output_tok,
        "cost_usd": round(actual_cost(base_in, cache_create, cache_read, output_tok), 6),
    }


class BaseQueryAgent:
    """One specialist per query language. Subclasses set the class attributes below."""

    # ── language identity (set by each subclass) ──
    LANGUAGE_KEY: str = ""        # e.g. "spl" — matches QUERY_KEYS
    LANGUAGE_NAME: str = ""       # e.g. "Splunk SPL"
    SIEM_NAME: str = ""           # e.g. "Splunk"
    DOCS_URL: str = ""

    # ── prompt fragments (set by each subclass) ──
    SYNTAX_RULES: str = ""        # operators, pipeline syntax, gotchas
    FIELD_CONVENTIONS: str = ""   # common table/index + field names
    BEST_PRACTICES: str = ""
    EXAMPLES: str = ""            # 3–5 example queries for detection patterns

    # convenience read-only properties (spec asks for properties)
    @property
    def language_key(self) -> str:
        return self.LANGUAGE_KEY

    @property
    def language_name(self) -> str:
        return self.LANGUAGE_NAME

    @property
    def siem_name(self) -> str:
        return self.SIEM_NAME

    @property
    def docs_url(self) -> str:
        return self.DOCS_URL

    # ── system prompt assembly ──
    def system_prompt(self) -> str:
        return f"""You are a world-class detection engineer who specializes EXCLUSIVELY in \
{self.LANGUAGE_NAME} for {self.SIEM_NAME}. You know this one query language deeply and write \
production-grade, syntactically valid queries every time. You never emit syntax from any other \
query language.

Reference docs: {self.DOCS_URL}

SYNTAX RULES
{self.SYNTAX_RULES.strip()}

FIELD & TABLE CONVENTIONS
{self.FIELD_CONVENTIONS.strip()}

BEST PRACTICES
{self.BEST_PRACTICES.strip()}

EXAMPLE QUERIES (study these patterns)
{self.EXAMPLES.strip()}
"""

    # ── Claude client ──
    @staticmethod
    def _client():
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        try:
            from anthropic import Anthropic
        except ImportError:
            raise RuntimeError("anthropic SDK not installed — `pip install anthropic`")
        # SDK does exponential backoff with jitter and honors Retry-After on 429s.
        # Default 2 retries (~1.5s worst case) keeps the user-facing /generate
        # endpoint responsive. The audit pipeline opts into AGENT_MAX_RETRIES=6
        # so long batch runs ride out a 429 storm instead of dropping calls.
        return Anthropic(max_retries=int(os.environ.get("AGENT_MAX_RETRIES", "2")))

    def _system_blocks(self):
        # Cache the (large, static per-language) system prompt across calls.
        return [{
            "type": "text",
            "text": self.system_prompt(),
            "cache_control": {"type": "ephemeral"},
        }]

    @staticmethod
    def _text(resp) -> str:
        parts = [b.text for b in resp.content if getattr(b, "type", None) == "text"]
        return "".join(parts).strip()

    @staticmethod
    def _strip_fence(text: str) -> str:
        """Drop a leading/trailing ``` fence if the model wrapped the query."""
        t = text.strip()
        if t.startswith("```"):
            lines = t.splitlines()
            # remove opening fence (optionally with a language tag) and closing fence
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            t = "\n".join(lines).strip()
        return t

    # ── public methods ──
    def generate_query(self, pseudo_logic, tactic, technique, platform, data_sources) -> dict:
        """Generate a single query in this agent's language.

        Returns {"query": str, "usage": {...}}.
        """
        plats = ", ".join(platform) if isinstance(platform, list) else (platform or "any")
        srcs = ", ".join(data_sources) if isinstance(data_sources, list) else (data_sources or "any")
        user = f"""Write ONE {self.LANGUAGE_NAME} query that implements this detection.

MITRE tactic: {tactic or "n/a"}
MITRE technique: {technique or "n/a"}
Target platform(s): {plats}
Available data sources: {srcs}

Detection logic (pseudo-code — match its thresholds, time windows, and exclusions exactly):
{pseudo_logic}

Return ONLY the raw {self.LANGUAGE_NAME} query — no prose, no markdown fences, no explanation."""

        client = self._client()
        resp = client.messages.create(
            model=AGENT_MODEL,
            max_tokens=GENERATE_MAX_TOKENS,
            system=self._system_blocks(),
            messages=[{"role": "user", "content": user}],
        )
        return {
            "query": self._strip_fence(self._text(resp)),
            "usage": _usage_dict(resp, self.LANGUAGE_KEY),
        }

    def validate_query(self, query, pseudo_logic) -> dict:
        """Validate a query against the pseudo-logic.

        Returns {"valid": bool, "issues": [str], "score": int, "usage": {...}}.
        """
        if not (query or "").strip():
            return {
                "valid": False,
                "issues": ["No query present for this language."],
                "score": 0,
                "usage": {"language": self.LANGUAGE_KEY, "model": AGENT_MODEL,
                          "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
            }

        tool = {
            "name": "report_validation",
            "description": f"Report the validation result for a {self.LANGUAGE_NAME} query.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "valid": {"type": "boolean",
                              "description": "True if the query is syntactically valid and faithful to the logic."},
                    "issues": {"type": "array", "items": {"type": "string"},
                               "description": "Specific problems: syntax errors, wrong fields, logic mismatches. Empty if none."},
                    "score": {"type": "integer", "minimum": 0, "maximum": 100,
                              "description": "Quality 0-100: syntax correctness, field accuracy, fidelity to the logic."},
                },
                "required": ["valid", "issues", "score"],
            },
        }
        user = f"""Validate this {self.LANGUAGE_NAME} query for {self.SIEM_NAME}.

Check: (1) syntax is valid for {self.LANGUAGE_NAME}, (2) field/table names are real and correct \
for {self.SIEM_NAME}, (3) the query faithfully implements the intended detection logic below \
(same thresholds, windows, exclusions).

Intended detection logic:
{pseudo_logic or "(none provided — judge syntax and internal consistency only)"}

Query to validate:
{query}

Call report_validation exactly once."""

        client = self._client()
        resp = client.messages.create(
            model=AGENT_MODEL,
            max_tokens=VALIDATE_MAX_TOKENS,
            system=self._system_blocks(),
            tools=[tool],
            tool_choice={"type": "tool", "name": "report_validation"},
            messages=[{"role": "user", "content": user}],
        )
        result = None
        for block in resp.content:
            if getattr(block, "type", None) == "tool_use" and block.name == "report_validation":
                result = dict(block.input)
                break
        if result is None:
            result = {"valid": False, "issues": ["validator did not return a result"], "score": 0}

        return {
            "valid": bool(result.get("valid")),
            "issues": list(result.get("issues") or []),
            "score": int(result.get("score") or 0),
            "usage": _usage_dict(resp, self.LANGUAGE_KEY),
        }

    def improve_query(self, existing_query, pseudo_logic, instruction) -> dict:
        """Rewrite an existing query per an instruction. Returns {"query", "usage"}."""
        user = f"""Improve this {self.LANGUAGE_NAME} query.

Instruction: {instruction}

Intended detection logic (keep faithful unless the instruction says otherwise):
{pseudo_logic or "(none provided)"}

Current query:
{existing_query or "(none — write it from scratch)"}

Return ONLY the improved raw {self.LANGUAGE_NAME} query — no prose, no markdown fences."""

        client = self._client()
        resp = client.messages.create(
            model=AGENT_MODEL,
            max_tokens=IMPROVE_MAX_TOKENS,
            system=self._system_blocks(),
            messages=[{"role": "user", "content": user}],
        )
        return {
            "query": self._strip_fence(self._text(resp)),
            "usage": _usage_dict(resp, self.LANGUAGE_KEY),
        }
