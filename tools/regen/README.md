# Audit + regenerate SIEM queries via Anthropic Batch API

Cost-efficient replacement for running rule audits inside Claude Code.
Uses the **Message Batches API** (50% off) with **prompt caching** on the
audit/regen system prompts (~90% off the cached portion). Total run cost
for ~715 rules: roughly **$15–20**, vs the Max-plan burn of doing it
interactively.

## Why this is separate from the Max plan

- The Max plan you use in Claude Code resets monthly on your billing
  anniversary. Running 715 LLM calls inside the chat session burns through
  it fast.
- The Anthropic API is billed **separately** at console.anthropic.com
  with prepaid credits. You'll need an API account with credit on it.
  This pipeline uses that credit pool, leaving your Max plan untouched.
- If you don't want to top up the API account, see the
  "Max-plan-only fallback" section at the bottom.

## One-time setup

```bash
pip install anthropic pyyaml
export ANTHROPIC_API_KEY=sk-ant-...   # from console.anthropic.com
```

## Run the pipeline

Each step is independent and re-runnable. Outputs live in
`.regen-validation/` (gitignored).

```bash
# 1. Audit phase — score every rule's 10 queries against pseudo_logic.
python3 tools/regen/batch.py audit-extract       # builds audit_requests.jsonl (715)
python3 tools/regen/batch.py audit-submit        # submits batch; saves audit_batch_id.txt
python3 tools/regen/batch.py audit-fetch         # polls every 30s, downloads results
python3 tools/regen/batch.py audit-summary       # prints scores; writes audit_summary.json

# 2. Regen phase — only for rules the audit flagged as "regenerate".
python3 tools/regen/batch.py regen-extract       # builds regen_requests.jsonl
python3 tools/regen/batch.py regen-submit        # submits batch
python3 tools/regen/batch.py regen-fetch         # polls + downloads new query JSON

# 3. Apply — write new queries back to rules/<tactic>/TDL-*.yaml
python3 tools/regen/batch.py apply
```

After step 3, run your existing validators:

```bash
python3 tools/recommend.py            # or whatever your rule QA pipeline is
git diff rules/                       # eyeball a few before committing
```

## What each step writes

```
.regen-validation/
├── audit_requests.jsonl     (input: 715 batch requests)
├── audit_batch_id.txt       (Anthropic batch handle)
├── audit_results/           (one TDL-*.json per rule)
├── audit_summary.json       (rolled-up scores, list of rules to regen)
├── regen_requests.jsonl     (input: only flagged rules)
├── regen_batch_id.txt
└── regen_results/           (one TDL-*.json per regenerated rule)
```

## Cost shape (Sonnet 4.6 batch + caching)

Numbers are approximate. Sonnet 4.6 batch pricing: input $1.50/M, output
$7.50/M; cached read $0.30/M.

| Phase | Rules | Input/req | Output/req | Cost |
|---|---|---|---|---|
| Audit | 715 | ~3K cached + ~2K fresh | ~500 | ~$5–8 |
| Regen | ~half | ~3K cached + ~1K fresh | ~3K | ~$8–12 |

Use `REGEN_MODEL=claude-haiku-4-5-20251001` to drop costs ~3× more if the
audit accuracy is acceptable on Haiku. Test on a 10-rule sample first.

## Tuning knobs

- **Different model**: `REGEN_MODEL=claude-haiku-4-5-20251001 python3 tools/regen/batch.py …`
- **Subset of rules**: edit `iter_rules()` filter, or hand-edit
  `audit_requests.jsonl` before submit.
- **Re-audit only**: re-run from `audit-extract`. Old `audit_results/`
  is overwritten by new batch results.
- **Resume after a crash**: every step is idempotent. The `_batch_id.txt`
  file is the handle; `*-fetch` re-uses it.

## Max-plan-only fallback (no API account)

If you'd rather not fund an API account, you can run the audit *inside*
Claude Code more cheaply than last time by:

1. **Don't fan out 715 subagents.** Each subagent inherits parent
   context. Instead, run the audit as a single deterministic loop:
   write a Python script that reads each rule and calls a Claude Code
   subagent **per chunk of 50 rules**, returning a JSON array. ~14
   subagent calls instead of 715.
2. **Use Sonnet, not Opus.** Inside Claude Code, run `/model sonnet`
   before starting. The audit doesn't need Opus.
3. **Clear context between chunks.** Use `/clear` after each
   50-rule chunk completes; don't carry context across.
4. **Skip the regen step.** `tools/regen_queries.py` already produces
   queries deterministically from rule metadata. The audit's job is
   to tell you *which* rules' deterministic output is wrong; for
   those, hand-edit the rule's `pseudo_logic` or the family classifier
   in `tools/regen_queries.py`, then re-run the deterministic
   regenerator.

The Batch API path is still 5–10× cheaper end-to-end. The fallback
exists so you can make progress even if the API account isn't funded.
