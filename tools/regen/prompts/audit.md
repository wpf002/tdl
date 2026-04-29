# Audit prompt — score 10 SIEM queries against pseudo_logic

You are auditing detection queries to measure how completely each one implements the rule's `pseudo_logic` (the canonical English detection intent).

## Inputs you will receive
- `rule_id`, `name`
- `pseudo_logic` (source of truth — the detection intent)
- `data_sources`, `platform`, `severity` (context)
- 10 dialect queries: `spl`, `kql`, `aql`, `yara_l`, `esql`, `leql`, `crowdstrike`, `xql`, `lucene`, `sumo`

## Scoring rubric (0–10 per dialect)

Score each query on whether it captures the pseudo_logic, NOT on style preference.

- **10** — Every filter condition, threshold, time window, distinct/grouping field, and negative condition is present. Idiomatic dialect syntax. Correct telemetry source.
- **8–9** — All major conditions captured. Minor imperfection: one secondary filter missing, slightly imperfect dialect syntax, or threshold/window expressed indirectly.
- **6–7** — Captures most filters and the right telemetry, but missing one non-trivial filter OR threshold/window OR grouping field.
- **4–5** — Targets the right telemetry but only one or two filter conditions; missing several conditions, threshold, or window. Would generate excessive noise as written.
- **2–3** — Wrong field names, wrong telemetry source, OR generic stub that filters on nothing meaningful (e.g., `event_id:* AND log_type:"security"`).
- **0–1** — Completely wrong telemetry (e.g., SharePoint rule querying Sysmon process events), empty, or placeholder.

## Hard rules for scoring

1. **Telemetry mismatch is severe.** A SharePoint rule must hit O365/cloud-audit telemetry. A firewall rule must hit network telemetry. A Windows auth rule must hit Windows security log. If the query targets the wrong telemetry, max score is 2 regardless of how clever the rest of the query is.

2. **Single-filter on multi-condition rules is a fail.** If pseudo_logic has 5 `Where` clauses and the query only filters on 1, max score is 4.

3. **Missing threshold = fail when pseudo_logic specifies one.** If pseudo_logic says "7 events" or "≥10" and the query has no `count >= N` / `having` / `condition` block, max score is 5.

4. **Missing time window = fail when pseudo_logic specifies one.** If pseudo_logic says "within 1 minute" and the query has no `bin _time span=1m` / `bin(TimeGenerated, …)` / `BUCKET` / `match … over Nm`, max score is 6.

5. **Negative conditions count.** "NOT ending with `$`", "NOT in [list]", "is NOT 'krbtgt'" must each appear. Each missing negative drops 1 point.

## Output

Return JSON only — no prose, no markdown fences:

```json
{
  "rule_id": "TDL-XX-000000",
  "scores": {
    "spl":         { "score": 0, "missing": ["..."] },
    "kql":         { "score": 0, "missing": ["..."] },
    "aql":         { "score": 0, "missing": ["..."] },
    "yara_l":      { "score": 0, "missing": ["..."] },
    "esql":        { "score": 0, "missing": ["..."] },
    "leql":        { "score": 0, "missing": ["..."] },
    "crowdstrike": { "score": 0, "missing": ["..."] },
    "xql":         { "score": 0, "missing": ["..."] },
    "lucene":      { "score": 0, "missing": ["..."] },
    "sumo":        { "score": 0, "missing": ["..."] }
  },
  "min_score": 0,
  "max_score": 0,
  "mean_score": 0,
  "recommendation": "regenerate"
}
```

`recommendation`:
- `"regenerate"` if `min_score < 5`
- `"tune"` if `min_score` is 5–7
- `"ok"` if `min_score >= 8`

`missing` is a short list of specific items the query failed to capture (e.g., `"Failure_Code filter not included"`, `"threshold of 7 not expressed"`, `"wrong telemetry — SharePoint rule on Sysmon"`). Empty list `[]` if the query is complete.
