# detections.ai vs. TDL Playbook — Honest Competitive Analysis

_Last updated: May 2026. Based on public information about detections.ai
(built by System Two Security, funded by SentinelOne's S Ventures). Their
product surface changes; treat this as a point-in-time snapshot._

## TL;DR

| Aspect | detections.ai | TDL Playbook |
| --- | --- | --- |
| Audience | Detection engineers + SOC analysts at enterprises | Detection engineers + SOC teams of any size |
| Distribution | Hosted SaaS (closed beta historically) | Self-hosted open library + UI |
| Pricing | Not publicly listed — enterprise / private beta | Free / OSS |
| Detection generation | GenAI from threat intel; minutes vs. days | GenAI from natural-language prompt; 10 specialist agents in parallel |
| Cross-platform translation | Yes — rule in one SIEM → another | Yes — TDL ↔ Sigma, 10 dialect importers, 10 dialect outputs per rule |
| Community / sharing | Public ratings, private trust circles (ISACs, F500) | None yet — single-tenant per deploy |
| Drift / schema awareness | Yes — flags outdated logic when log schemas change | Not yet — on the roadmap |
| SIEM coverage (named) | Splunk, Sentinel, CrowdStrike NG-SIEM, "others" | Splunk SPL, Sentinel KQL, QRadar AQL, Chronicle YARA-L, Elastic ES\|QL, Rapid7 LEQL, CrowdStrike LogScale, XSIAM XQL, Lucene, Sumo Logic, Sigma |
| Rule lifecycle / triage metadata | Implied | First-class — `pseudo_logic`, `triage_steps`, `requirements`, `tuning_guidance`, `lifecycle` |
| Coverage view | Not advertised | MITRE matrix tile per technique, dimmed by deployed log sources + event IDs |
| Onboarding to org's environment | Implied | Per-event-ID inventory checklist + matrix that re-dims live |
| Portability of exports | Cross-SIEM translation | Sigma YAML + zips of TDL/Sigma + per-language JSON |

## What detections.ai does well that TDL Playbook does not (yet)

1. **Community-driven detection ecosystem.** They aggregate rules from
   open-source repos, vendors, and individual researchers, with a community
   rating loop ("vetted and improved by a broad community of practitioners").
   TDL Playbook is currently single-org. There's no shared library, no public
   ratings, no upvote/downvote on rules. _Roadmap implication: add a public
   `/library` mirror and a rating store keyed by rule_id._
2. **Private trust circles** (e.g. ISACs, Fortune 500 sharing groups). They
   support scoped sharing between named orgs. TDL has no inter-org concept.
3. **Schema-drift detection.** They flag rules whose log schemas have
   changed under them and propose fixes. TDL's 10 specialist agents *can*
   validate and improve rules, but there's no scheduled drift sweep yet.
4. **Marketing / distribution.** SentinelOne S Ventures funding,
   9,000+ users / 1,500 orgs onboarded early, name recognition at major
   conferences. TDL is a single OSS repo.
5. **Hosted product.** Zero ops — they run it for you. TDL requires running
   the Flask backend, Postgres, and the React UI yourself.

## What TDL Playbook does well

1. **Transparency.** The library, the schema, the agents, the prompts, and
   the conversion pipelines are all in the repo. You can read exactly how
   any query gets generated and tune it.
2. **Breadth of native query languages.** 10 SIEM dialects ship with every
   rule — not "translation on demand", but pre-generated and validatable in
   parallel by 10 specialist agents (Sonnet 4.5, one per language).
3. **Coverage-as-data.** MITRE matrix with per-technique tile counts that
   dim against your deployed log sources, and now against your collected
   event IDs (e.g. uncheck 4769 → all Kerberoasting rules dim immediately).
4. **Rich rule metadata that drives triage.** Every rule carries
   `pseudo_logic` (source of truth used by the agents to regenerate
   queries), `triage_steps`, `false_positives`, `tuning_guidance`,
   `requirements` (log_source → event_ids), `lifecycle`, `risk_score`. Most
   competitor rules are just a query string.
5. **Free and self-hostable.** No procurement loop. Run it on your laptop
   for $0 plus whatever the Anthropic agent calls cost you (capped per day).
6. **Sigma portability layer.** TDL → Sigma → any vendor backend.
   Documented in [docs/yaml-schema.md](./yaml-schema.md).
7. **Selective export.** Pick scope (current view / selected / all / custom)
   × format (PDF / CSV / JSON / Sigma / YAML) × which query languages to
   include. Useful for moving subsets of the library into existing pipelines.

## Honest gaps to close

Based on the gaps above and the validation list in this prompt, the
following UI / product improvements ship in this commit:

- **Rule quality score** — a 0–100 badge on each rule row (has
  pseudo_logic? has all 10 queries? has requirements? has triage steps?).
  Visible in the list, full breakdown in detail. Surfaces the most-curated
  rules and the ones that need work.
- **Better search** — name, description, pseudo_logic, technique_id, and
  tags simultaneously; matched text highlighted; Cmd/Ctrl+K opens search
  from anywhere.
- **Related rules** — in the rule detail pane, the top 5 sibling rules
  in the same tactic/technique sorted by risk_score.
- **Copy for primary language** — a one-click "Copy SPL" (or your org's
  language) above the query tab strip so analysts don't have to find the
  tab first.
- **Dark / light mode toggle** in the topbar (persisted to localStorage).
- **Live rule count badge** on the Detection Rules sidebar entry —
  reflects active filters in real time.

What's *not* in this commit and remains a real gap vs. detections.ai:

- A public detection library / ratings store.
- Cross-org sharing or trust circles.
- A scheduled drift checker. (The pieces exist — the 10 specialist agents'
  `validate_query` does this on demand — but there's no cron yet.)

## Sources

- [SentinelOne S Ventures investment in detections.ai](https://www.sentinelone.com/s-ventures/blog/s-ventures-investment-in-detections-ai/)
- [System Two Security — CB Insights profile](https://www.cbinsights.com/company/system-two-security)
- [detections.ai (redirects to systemtwosecurity.com)](https://systemtwosecurity.com/)
- [The AI-Powered Detection Engineer — Jack Naglieri, Detection at Scale](https://www.detectionatscale.com/p/the-ai-powered-detection-engineer)
