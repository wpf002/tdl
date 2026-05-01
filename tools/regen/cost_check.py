#!/usr/bin/env python3
"""Count exact tokens for regen_requests.jsonl and price the batch."""
from __future__ import annotations
import json, os, sys, statistics
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from anthropic import Anthropic

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / ".regen-validation"
REGEN_REQ = WORK / "regen_requests.jsonl"
REGEN_SAMPLE_DIR = WORK / "regen"
AUDIT_RESULTS = WORK / "audit_results"

client = Anthropic()


def count_one(req: dict) -> tuple[int, int]:
    """Return (system_tokens, user_tokens) for a single request."""
    p = req["params"]
    sys_text = p["system"][0]["text"]
    user_msg = p["messages"][0]["content"]
    sys_resp = client.messages.count_tokens(
        model=p["model"],
        system=sys_text,
        messages=[{"role": "user", "content": "x"}],
    )
    full_resp = client.messages.count_tokens(
        model=p["model"],
        system=sys_text,
        messages=[{"role": "user", "content": user_msg}],
    )
    return sys_resp.input_tokens, full_resp.input_tokens - sys_resp.input_tokens


def main():
    reqs = [json.loads(l) for l in REGEN_REQ.read_text().splitlines() if l]
    print(f"requests: {len(reqs)}")

    # System prompt is identical across all requests — count once
    p0 = reqs[0]["params"]
    sys_text = p0["system"][0]["text"]
    model = p0["model"]
    max_tokens = p0["max_tokens"]
    print(f"model: {model}")
    print(f"max_tokens per request: {max_tokens}")

    sys_resp = client.messages.count_tokens(
        model=model,
        system=sys_text,
        messages=[{"role": "user", "content": "x"}],
    )
    # Subtract the trivial "x" user message + overhead
    overhead = client.messages.count_tokens(
        model=model,
        messages=[{"role": "user", "content": "x"}],
    ).input_tokens
    sys_tokens = sys_resp.input_tokens - overhead
    print(f"system prompt tokens (one-time cache write): {sys_tokens}")

    # Count user payload tokens for each of the 714 requests
    def user_tok(req):
        msg = req["params"]["messages"][0]["content"]
        return client.messages.count_tokens(
            model=model,
            messages=[{"role": "user", "content": msg}],
        ).input_tokens - overhead  # subtract trivial overhead so we get pure content tokens

    user_tokens = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(user_tok, r): i for i, r in enumerate(reqs)}
        for i, fut in enumerate(as_completed(futures)):
            user_tokens.append(fut.result())
            if (i + 1) % 100 == 0:
                print(f"  counted {i+1}/{len(reqs)}", file=sys.stderr)

    total_user = sum(user_tokens)
    print(f"user payload tokens (sum across {len(reqs)} requests): {total_user:,}")
    print(f"  per-request: min={min(user_tokens)} median={int(statistics.median(user_tokens))} "
          f"max={max(user_tokens)} mean={int(statistics.mean(user_tokens))}")

    # Output token estimate from existing regen samples (same prompt, same model)
    sample_outputs = []
    for f in sorted(REGEN_SAMPLE_DIR.glob("TDL-*.json")):
        text = f.read_text()
        n = client.messages.count_tokens(
            model=model,
            messages=[{"role": "user", "content": text}],
        ).input_tokens - overhead
        sample_outputs.append(n)
    if sample_outputs:
        print(f"\nregen output samples (n={len(sample_outputs)}): "
              f"min={min(sample_outputs)} median={int(statistics.median(sample_outputs))} "
              f"max={max(sample_outputs)} mean={int(statistics.mean(sample_outputs))}")
        est_out_per = int(statistics.mean(sample_outputs))
    else:
        est_out_per = max_tokens
    est_total_out = est_out_per * len(reqs)
    ceiling_out = max_tokens * len(reqs)

    # Sonnet 4.6 pricing (verify before spending — see https://www.anthropic.com/pricing)
    # Base: $3 / MTok input, $15 / MTok output
    # Cache write: 1.25x = $3.75 / MTok input
    # Cache read: 0.1x = $0.30 / MTok input
    # Batch API: 50% off all rates
    P_INPUT = 1.50      # batch, uncached input
    P_CACHE_WRITE = 1.875  # batch, cache write
    P_CACHE_READ = 0.15    # batch, cache read
    P_OUTPUT = 7.50     # batch, output

    n_req = len(reqs)
    sys_writes = sys_tokens          # cached once
    sys_reads = sys_tokens * (n_req - 1)
    cost_sys_write = (sys_writes / 1_000_000) * P_CACHE_WRITE
    cost_sys_read = (sys_reads / 1_000_000) * P_CACHE_READ
    cost_user_in = (total_user / 1_000_000) * P_INPUT
    cost_out_est = (est_total_out / 1_000_000) * P_OUTPUT
    cost_out_max = (ceiling_out / 1_000_000) * P_OUTPUT

    total_in = cost_sys_write + cost_sys_read + cost_user_in
    print(f"\n--- cost breakdown (Sonnet 4.6, Batch API 50% off) ---")
    print(f"system cache write : {sys_writes:>10,} tok × $1.875/MTok = ${cost_sys_write:>7.4f}")
    print(f"system cache reads : {sys_reads:>10,} tok × $0.15/MTok  = ${cost_sys_read:>7.4f}")
    print(f"user input         : {total_user:>10,} tok × $1.50/MTok  = ${cost_user_in:>7.4f}")
    print(f"input subtotal     :                                       ${total_in:>7.4f}")
    print()
    print(f"output (estimated) : {est_total_out:>10,} tok × $7.50/MTok  = ${cost_out_est:>7.4f}  (based on {len(sample_outputs)} prior samples)")
    print(f"output (CEILING)   : {ceiling_out:>10,} tok × $7.50/MTok  = ${cost_out_max:>7.4f}  (max_tokens × {n_req})")
    print()
    print(f"TOTAL (estimated)  : ${total_in + cost_out_est:>7.2f}")
    print(f"TOTAL (CEILING)    : ${total_in + cost_out_max:>7.2f}  ← absolute upper bound")
    print()
    print("Caveats:")
    print(" - Output ceiling assumes every response uses the full max_tokens=4096. Real output is almost always lower.")
    print(" - Assumes prompt caching works in batch (it does per Anthropic docs).")
    print(" - If Sonnet 4.6 prices have changed since Jan 2026, recompute with: rate × tokens / 1e6.")


if __name__ == "__main__":
    main()
