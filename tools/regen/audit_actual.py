#!/usr/bin/env python3
"""Pull actual usage from the completed audit batch as a pricing reality-check."""
from anthropic import Anthropic
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
batch_id = (ROOT / ".regen-validation" / "audit_batch_id.txt").read_text().strip()
client = Anthropic()

tot_in = tot_out = tot_cw = tot_cr = 0
n = 0
for entry in client.messages.batches.results(batch_id):
    if entry.result.type != "succeeded":
        continue
    u = entry.result.message.usage
    tot_in += u.input_tokens
    tot_out += u.output_tokens
    tot_cw += getattr(u, "cache_creation_input_tokens", 0) or 0
    tot_cr += getattr(u, "cache_read_input_tokens", 0) or 0
    n += 1

print(f"audit batch: {n} succeeded results")
print(f"  raw input tokens (uncached) : {tot_in:,}")
print(f"  cache write tokens          : {tot_cw:,}")
print(f"  cache read tokens           : {tot_cr:,}")
print(f"  output tokens               : {tot_out:,}")
print()
# Sonnet 4.6 batch pricing
P_IN, P_CW, P_CR, P_OUT = 1.50, 1.875, 0.15, 7.50
cost = (tot_in/1e6)*P_IN + (tot_cw/1e6)*P_CW + (tot_cr/1e6)*P_CR + (tot_out/1e6)*P_OUT
print(f"computed cost @ Sonnet 4.6 batch pricing : ${cost:.2f}")
print(f"(if this matches the $17 charge, our pricing assumptions are correct)")
