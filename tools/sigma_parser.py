"""Parse one or more Sigma rules from raw YAML text.

Sigma supports multi-document YAML (each doc separated by `---`), so a single
file can hold many rules. We use safe_load_all to handle both single and multi.
"""

from __future__ import annotations

import yaml


REQUIRED_SIGMA_KEYS = ("title", "detection")


def parse_sigma(content: str) -> list[dict]:
    """Return a list of Sigma rule dicts parsed from raw YAML text.

    Filters out anything that doesn't look like a Sigma rule (missing title or
    detection block). Doesn't validate beyond that — the translator will reject
    nonsense at the LLM step.

    Raises ValueError for genuine YAML parse errors.
    """
    if not (content or "").strip():
        return []

    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        raise ValueError(f"Sigma YAML parse error: {e}") from e

    rules = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        if all(doc.get(k) for k in REQUIRED_SIGMA_KEYS):
            rules.append(doc)
    return rules


def parse_dialect_queries(content: str) -> list[str]:
    """Split a SIEM-dialect blob into individual query strings.

    Convention: queries separated by a line containing only `---` (matches
    Sigma's multi-doc separator, easy for users to copy from existing files).
    Single-query input (no `---`) returns a one-element list.
    """
    if not (content or "").strip():
        return []
    chunks = []
    cur = []
    for line in content.splitlines():
        if line.strip() == "---":
            if cur:
                q = "\n".join(cur).strip()
                if q:
                    chunks.append(q)
                cur = []
        else:
            cur.append(line)
    if cur:
        q = "\n".join(cur).strip()
        if q:
            chunks.append(q)
    return chunks
