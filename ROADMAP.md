# TDL Playbook — Roadmap

Living document. Move items between sections as work progresses; delete what's
done, edit freely. Last updated: 2026-05-04.

---

## Now (in-flight)

- **SaaS productization track.** Six-phase plan to take TDL Playbook from
  static rule library to multi-tenant SaaS. Phases 1, 2, 3, 3.5, 4 shipped;
  Phase 5 in build, Phase 6 deferred.

---

## Next — SaaS productization (sequenced, gated)

Each phase is a separate commit; each one ends in an explicit checkpoint
before the next begins. Phases 4–6 also have cost gates.

- [x] **Phase 1 — PostgreSQL data layer.** SQLAlchemy models, idempotent
      migration, YAML→Postgres seeder that skips `is_custom=true` rules so user
      edits survive re-seed. `tools/db.py`, `tools/migrate.py`, `tools/seed_db.py`.
      `./run prod` migrates + seeds before booting.
- [x] **Phase 2 — Coverage report export.** PDF (reportlab), CSV, JSON
      endpoints; Export dropdown in Dashboard. No DB writes, no LLM. Free.
- [x] **Phase 3 — Rule editor.** `PUT /api/rules/<id>`, soft `DELETE` (sets
      `lifecycle=Retired`), `POST /duplicate`. Inline edit in the rule detail
      pane. Adds `tools/dump_db.py` so audit/regen tooling keeps working
      against YAML round-tripped from Postgres. Free.
- [x] **Phase 3.5 — Org profile in Postgres + settings page.** Promote the
      onboarding profile (org name, primary SIEM, deployed log sources) from
      browser localStorage to a Postgres `org_profile` table keyed off Clerk
      user id. Adds a Settings nav entry; migrates existing localStorage
      profiles on first authenticated load. No LLM. Free.
      Prerequisite for Phase 4 (per-org AI spend caps need a real org row)
      and Phase 6 (Stripe tier needs to attach to an org).
- [ ] **Phase 4 — AI rule builder. ⚠ COST GATE.** Sonnet 4.5 generates a full
      TDL rule + all 10 SIEM queries from a prompt. Per-Generate spend ~$0.03–
      0.05. Adds `ai_usage` table for actual-spend telemetry. Soft per-org
      daily cap. **Requires explicit cost-analysis approval before first call.**
- [ ] **Phase 5 — Rule import (Sigma + SPL). ⚠ COST GATE.** Upload Sigma YAML
      or SPL; per-rule Claude call (~$0.02–0.04) translates each into TDL
      format with all 10 SIEM queries. Two modes in one phase: sync (≤50 rules
      per upload, immediate results) and batch (>50 rules, Anthropic Batch API
      for 50% off, results pulled when ready). Reuses `ai_usage` table and
      daily cap from Phase 4. **Requires approval.**
- [ ] **Phase 6 — Stripe paywall.** *(deferred — revisit once the app is
      fully built out and there's a paying-customer rationale)* Free / Pro /
      Team tiers, real-money cost gate, live-card validation gating.

---

## Next — Library hygiene (independent of SaaS track)

### Library hygiene

- [ ] **Backfill `pseudo_logic` on the 106 rules missing it** (821 total − 715
      with). Or document why specific rules are intentionally excluded.
- [ ] **README accuracy pass**:
  - Hero line says "700 detection rules" — actual is 821
  - Hero line says "9 SIEM platforms" — actual is 10 (Sumo Logic added in
    `fa12da7`); the table lower down is already correct

### Tooling

- [ ] **CI check that Sigma export stays in sync** — `npm run sigma` regenerates
      `sigma/` but nothing prevents drift. Either commit the regenerated files
      and verify in CI, or generate on-demand and stop committing.
- [ ] **Per-rule unit tests for `tools/regen_queries.py`** — currently only
      integration-level coverage. A few golden-file tests would catch
      regressions when the family classifier changes.

---

## Later (bigger bets, not committed)

- **Log-source toggles in Recommendations view** — `profiles/default.yaml` is
  a hypothetical environment for the recommender. Once Phase 3.5 lands, the
  user's deployed log sources will live in Postgres; this item is the
  Recommendations-side surface that reads from the org profile so the view
  reflects *their* stack, not the default.
- **Coverage diff view** — given two profiles (or two points in time), show
  which rules light up / go dark. Useful for "what would deploying X log
  source actually buy us?"

---

## Done (recent, for context)

- PostgreSQL data layer — SQLAlchemy models, idempotent migration + YAML seed,
  `./run prod` boots `migrate → seed → server` (Phase 1 of the SaaS track)
- Clerk auth on the hosted Railway instance — `0e75564`
- Batch API audit/regen pipeline (`tools/regen/batch.py`) — `a84f1cb`
- Regenerated all 10 SIEM queries from `data_sources` + `pseudo_logic` — `b27fab9`
- Backfilled `risk_score` on 121 rules + Kill Chain phase filter — `d6bf6f0`
- Responsive mobile layout — `f369c42`
- Triage steps + dashboard click-to-filter + matrix tile expand — `4722edf`
- Sumo Logic as 10th SIEM + aligned technique counters — `fa12da7`
