#!/usr/bin/env python3
"""Regenerate the 9 non-SPL SIEM dialects for every rule, credit-optimized.

Optimizations:
  * Message Batches API — 50% off standard token pricing for this bulk job.
  * Prompt caching — each language's large system prompt is sent with
    cache_control and the requests are ordered per-language so it's a cache hit
    (0.1x input) across that language's 821 requests instead of re-billed.

Regenerates KQL/AQL/YARA-L/ES|QL/LEQL/CrowdStrike/XQL/Lucene/Sumo (SPL is already
done) → exports/regen_dialects.json {rule_id: {lang: query}}.

    ANTHROPIC_API_KEY=... python -m tools.regen_dialects_batch [--max-cost 70] [--limit N]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
OUT = ROOT / "exports" / "regen_dialects.json"
LANGS = ["kql", "aql", "yara_l", "esql", "leql", "crowdstrike", "xql", "lucene", "sumo"]
MAX_TOKENS = 1500
# Sonnet 4.5 per-MTok, then 0.5x for batch.
IN_PRICE, OUT_PRICE = 3.00, 15.00


def load_rules(limit=None):
    out = []
    for p in sorted(RULES_DIR.rglob("*.yaml")):
        try:
            d = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(d, dict) and d.get("rule_id"):
            out.append(d)
    return out[:limit] if limit else out


def user_prompt(agent, rule):
    plat = rule.get("platform")
    ds = rule.get("data_sources")
    plats = ", ".join(plat) if isinstance(plat, list) else (plat or "any")
    srcs = ", ".join(ds) if isinstance(ds, list) else (ds or "any")
    return (f"Write ONE {agent.LANGUAGE_NAME} query that implements this detection.\n\n"
            f"MITRE tactic: {rule.get('tactic') or 'n/a'}\n"
            f"MITRE technique: {rule.get('technique_id') or 'n/a'}\n"
            f"Target platform(s): {plats}\n"
            f"Available data sources: {srcs}\n\n"
            f"Detection logic (pseudo-code — match its thresholds, time windows, and exclusions exactly):\n"
            f"{rule.get('pseudo_logic') or ''}\n\n"
            f"Return ONLY the raw {agent.LANGUAGE_NAME} query — no prose, no markdown fences, no explanation.")


def strip_fence(t):
    t = (t or "").strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines).strip()
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-cost", type=float, default=70.0)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--poll", type=int, default=30, help="seconds between status polls")
    args = ap.parse_args()

    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY not set")
    from anthropic import Anthropic
    from tools.agents import get_agent, AGENTS
    from tools.agents.base_agent import AGENT_MODEL
    client = Anthropic()

    rules = load_rules(args.limit)
    agents = {l: get_agent(l) for l in LANGS}

    # Rough pre-flight estimate (batch = 0.5x; caching makes this conservative).
    n = len(rules) * len(LANGS)
    est = n * ((2500 * IN_PRICE + 350 * OUT_PRICE) / 1_000_000) * 0.5
    print(f"Rules: {len(rules)} × {len(LANGS)} dialects = {n} requests")
    print(f"Model: {AGENT_MODEL}  ·  Batch (50% off) + prompt caching")
    print(f"Rough estimate: ~${est:.2f}  (hard cap ${args.max_cost:.2f})")
    if est > args.max_cost:
        sys.exit(f"Estimate ${est:.2f} exceeds cap ${args.max_cost:.2f} — aborting.")

    # Build requests ordered per-language (keeps each system prompt a cache hit).
    requests = []
    for lang in LANGS:
        a = agents[lang]
        sys_blocks = [{"type": "text", "text": a.system_prompt(), "cache_control": {"type": "ephemeral"}}]
        for r in rules:
            requests.append({
                "custom_id": f"{r['rule_id']}__{lang}",
                "params": {
                    "model": AGENT_MODEL, "max_tokens": MAX_TOKENS,
                    "system": sys_blocks,
                    "messages": [{"role": "user", "content": user_prompt(a, r)}],
                },
            })

    print(f"\nSubmitting batch of {len(requests)} requests …")
    batch = client.beta.messages.batches.create(requests=requests)
    bid = batch.id
    print(f"Batch {bid} submitted. Polling every {args.poll}s (Anthropic SLA 24h; usually much faster).")

    while True:
        b = client.beta.messages.batches.retrieve(bid)
        rc = b.request_counts
        print(f"  [{b.processing_status}] done={rc.succeeded} err={rc.errored} proc={rc.processing}", flush=True)
        if b.processing_status == "ended":
            break
        time.sleep(args.poll)

    out = {}
    if OUT.exists():
        try:
            out = json.loads(OUT.read_text())
        except json.JSONDecodeError:
            out = {}
    tin = tout = 0
    ok = err = 0
    for res in client.beta.messages.batches.results(bid):
        rid, lang = res.custom_id.rsplit("__", 1)
        if res.result.type != "succeeded":
            err += 1
            continue
        msg = res.result.message
        text = "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
        out.setdefault(rid, {})[lang] = strip_fence(text)
        u = msg.usage
        tin += (getattr(u, "input_tokens", 0) or 0) + (getattr(u, "cache_read_input_tokens", 0) or 0) + (getattr(u, "cache_creation_input_tokens", 0) or 0)
        tout += getattr(u, "output_tokens", 0) or 0
        ok += 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2))
    # Approx cost (batch 0.5x; cache reads already fold into a lower effective rate).
    cost = ((tin * IN_PRICE + tout * OUT_PRICE) / 1_000_000) * 0.5
    print(f"\nDone: {ok} queries generated, {err} errored.")
    print(f"Tokens: {tin:,} in / {tout:,} out  ·  approx cost ${cost:.2f} (batch 50% off)")
    print(f"Report: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
