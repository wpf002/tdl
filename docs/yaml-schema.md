# TDL Rule YAML — Schema, Portability, and Sigma Interop

This is the canonical reference for the TDL rule format and how it maps onto
Sigma (the cross-vendor portability layer). The authoritative machine schema
lives at [schemas/rule.schema.json](../schemas/rule.schema.json); this
document is the human-readable companion.

## TL;DR — can this YAML plug into any environment?

**Yes, via Sigma.** Native TDL YAML requires the TDL toolchain (the rule
library, the agent system, the UI, the exporter). But every TDL rule converts
losslessly into Sigma YAML via `tools/sigma_gen.py`, and every Sigma rule
imports into TDL via the Sigma importer (the same parser the
`POST /api/rules/import` endpoint uses). Sigma is the portability layer:

```
                ┌──────────────┐         ┌──────────────┐
   Splunk SPL ◀─┤  TDL YAML    │ ───────▶│  Sigma YAML  │──▶ MS Sentinel
   QRadar AQL ◀─┤  (canonical) │ ◀───────│              │──▶ Elastic ESQL
   Chronicle  ◀─│              │         │              │──▶ Chronicle UDM
                └──────┬───────┘         └──────────────┘
                       │  multi-language
                       │  query bundle
                       ▼
                  10 SIEM dialects
```

If you only need a rule to live inside the TDL Playbook, use TDL YAML — it
carries the richer metadata (pseudo_logic, triage_steps, requirements,
per-language queries). If you need it to deploy into a vendor SIEM you don't
own, convert to Sigma and let the Sigma backends do the heavy lifting.

## The TDL rule schema

Every rule is a single YAML document with these fields. See the JSON Schema
for exact types and enums.

### Required

| Field | Type | Notes |
| --- | --- | --- |
| `rule_id` | string | Unique ID, e.g. `TDL-CA-000123`. Pattern-validated by tactic prefix. |
| `name` | string | Short imperative title (≥ 5 chars). |
| `tactic` | enum | MITRE ATT&CK tactic. |
| `technique_id` | string | MITRE technique/sub-technique, e.g. `T1003.001`. |
| `technique_name` | string | Human-readable technique name. |
| `platform` | string[] | Target platforms (Windows, Linux, macOS, AWS, Azure, GCP, Okta, Microsoft 365, Network, SaaS, Kubernetes). |
| `data_sources` | string[] | Log sources the rule reads from. |
| `severity` | enum | Low \| Medium \| High \| Critical. |
| `fidelity` | enum | Low \| Medium \| High — expected signal-to-noise. |
| `lifecycle` | enum | Proposed \| Tested \| Deployed \| Tuned \| Retired. |
| `queries` | object | At least one of the per-language query strings. |
| `false_positives` | string[] | Known benign triggers. |
| `author` | string | |
| `created` | string (date) | YYYY-MM-DD. |

### Optional but recommended

| Field | Type | Notes |
| --- | --- | --- |
| `description` | string | What the rule detects. |
| `pseudo_logic` | string | Source-of-truth detection logic in plain English. Used by the agent system to (re)generate queries. |
| `risk_score` | int 1–100 | Risk weighting. |
| `tactic_id` | string | MITRE tactic code, e.g. `TA0006`. |
| `triage_steps` | string[] | Ordered analyst playbook for an alert. |
| `requirements` | object | Log sources + event IDs the rule needs to fire (`{log_sources: [{source, events: [{id, name, required}]}]}`). Drives the granular MITRE matrix dimming and onboarding event-ID checklists. |
| `tuning_guidance` | string | How to tune for a given environment. |
| `tuning_period` | string | Recommended baseline window. |
| `suppression` | object | `{window, fields[]}` for alert dedupe. |
| `tags` | string[] | Free-form labels. |
| `references` | string[] | External URLs / citations. |
| `test_method` | enum | historical \| synthetic \| purple_team \| none. |
| `simulation_id` | string | Linked simulation, e.g. `SIM-001`. |
| `related_rules` | string[] | Complementary `rule_id`s. |
| `last_modified` | string (date) | |
| `v4_id` | string\|int | Legacy ID for migration. |

### `queries` keys

Each value is a query string for that SIEM. `queries` must have at least one
populated entry; in practice TDL rules ship all 10 plus an optional `sigma`.

| Key | Vendor / language |
| --- | --- |
| `spl` | Splunk — SPL |
| `kql` | Microsoft Sentinel / Defender — KQL |
| `aql` | IBM QRadar — AQL |
| `yara_l` | Google Chronicle — YARA-L 2.0 |
| `esql` | Elastic Security — ES\|QL |
| `leql` | Rapid7 InsightIDR — LEQL |
| `crowdstrike` | CrowdStrike Falcon LogScale — CQL |
| `xql` | Palo Alto XSIAM — XQL |
| `lucene` | OpenSearch / Graylog / Exabeam — Lucene |
| `sumo` | Sumo Logic Search |
| `sigma` | Vendor-neutral Sigma YAML (compile target) |

## TDL ↔ Sigma field mapping

`tools/sigma_gen.py` performs this mapping in both directions.

| Sigma field | TDL field | Notes |
| --- | --- | --- |
| `title` | `name` | |
| `id` | `rule_id` | TDL ID is also written into Sigma `id`. |
| `status` | `lifecycle` | `Deployed/Tuned → stable`, `Tested → test`, `Proposed → experimental`. |
| `description` | `description` | |
| `references` | `references` | |
| `author` | `author` | |
| `date` | `created` | |
| `modified` | `last_modified` | |
| `tags` | `tactic` + `technique_id` + custom `tags` | TDL emits `attack.<tactic>`, `attack.t<id>`, `detection.<tag>`. |
| `logsource` | `data_sources` + `platform` | Heuristic mapping in `sigma_gen.infer_logsource()`. |
| `detection` | `pseudo_logic` + `queries` | TDL → Sigma builds `detection` from `pseudo_logic`; Sigma → TDL retains the original Sigma detection block and adds it as a query. |
| `falsepositives` | `false_positives` | |
| `level` | `severity` | `Critical → critical`, `High → high`, etc. |
| `custom.v4_id` | `v4_id` | Round-trips legacy IDs. |

### TDL-specific (no Sigma equivalent)

These fields live only in TDL because Sigma's schema is intentionally minimal:

- `pseudo_logic` (source-of-truth detection logic)
- The full `queries` object with all 10 per-language strings
- `requirements` (log-source + event-ID dependencies)
- `triage_steps`, `tuning_guidance`, `tuning_period`, `suppression`
- `test_method`, `simulation_id`, `related_rules`
- `risk_score`, `fidelity`

When converting TDL → Sigma these are dropped (Sigma will compile from the
`detection` block). When importing Sigma → TDL these arrive empty and the
agent system can populate them on demand.

## Conversion paths

### TDL → Sigma

```
python3 -m tools.sigma_gen --rules rules/ --output sigma/
```

Or per-rule via the export modal: choose **Sigma YAML (zip)** as the format
in the UI. The generated `.yml` files validate against the Sigma schema.

### Sigma → TDL

Use the in-app import flow (`POST /api/rules/import` with `source_type:
"sigma"`) or call the parser directly:

```python
from tools.sigma_parser import parse_sigma
rules = parse_sigma(open("rule.yml").read())
```

The translator (`tools/ai_rule_translator.py`) populates the missing TDL-only
fields with Claude — pseudo_logic, the 9 sibling-language queries, triage
steps — so the imported rule is first-class in the library.

## Portability matrix

| Source format | Destination | Path | Lossy? |
| --- | --- | --- | --- |
| TDL YAML | TDL Playbook | direct | no |
| TDL YAML | Sigma YAML | `tools/sigma_gen.to_sigma()` | yes (TDL-specific fields dropped) |
| TDL YAML | Splunk SPL | `queries.spl` | no — query is native |
| TDL YAML | Sentinel KQL | `queries.kql` | no |
| TDL YAML | Chronicle YARA-L | `queries.yara_l` | no |
| TDL YAML | QRadar AQL | `queries.aql` | no |
| TDL YAML | Elastic ES\|QL | `queries.esql` | no |
| TDL YAML | Rapid7 LEQL | `queries.leql` | no |
| TDL YAML | CrowdStrike LogScale | `queries.crowdstrike` | no |
| TDL YAML | XSIAM XQL | `queries.xql` | no |
| TDL YAML | OpenSearch / Graylog Lucene | `queries.lucene` | no |
| TDL YAML | Sumo Logic | `queries.sumo` | no |
| Sigma YAML | TDL YAML | `tools/sigma_parser.parse_sigma()` + translator | enriched, not lossy |
| Sigma YAML | Any vendor | Sigma backends (pysigma + plugins) | per vendor |

## See also

- [`schemas/rule.schema.json`](../schemas/rule.schema.json) — the JSON Schema
- [`tools/sigma_gen.py`](../tools/sigma_gen.py) — TDL → Sigma converter
- [`tools/sigma_parser.py`](../tools/sigma_parser.py) — Sigma → TDL parser
- [`tools/agents/`](../tools/agents/) — per-language specialist agents that
  generate, validate, and improve the per-language queries
