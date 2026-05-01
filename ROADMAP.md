# TDL Playbook — Roadmap

Living document. Move items between sections as work progresses; delete what's
done, edit freely. Last updated: 2026-04-30.

---

## Now (in-flight)

- **SIEM-query audit** — Batch `msgbatch_01FDEGAN3kfKzebipgmH4hbN` submitted
  2026-04-30. Scores all 715 rules' 10 queries against `pseudo_logic`.
  - [ ] `audit-fetch` once Anthropic finishes processing
  - [ ] Review `audit_summary.json`, pick scope for regen
  - [ ] `regen-extract` / `regen-submit` / `regen-fetch` / `apply` for flagged rules
  - [ ] `git diff rules/` review + commit

---

## Next (near-term cleanup)

### Library hygiene
- [ ] **Backfill `pseudo_logic` on the 106 rules missing it** (821 total − 715
      with). Without it they're invisible to the audit pipeline and the regen
      tooling can't reason about them. Alternative: document why specific rules
      are intentionally excluded.
- [ ] **README accuracy pass**:
  - Hero line says "700 detection rules" — actual is 821
  - Hero line says "9 SIEM platforms" — actual is 10 (Sumo Logic added in
    `fa12da7`); the table lower down is already correct
- [ ] **Audit-driven `pseudo_logic` cleanup** — for rules where the audit flags
      queries as wrong, the fix often belongs in `pseudo_logic` (or in
      `tools/regen_queries.py`'s family classifier), not in the queries
      themselves. Decide a policy: regen blindly, or fix upstream first.

### Tooling
- [ ] **CI check that Sigma export stays in sync** — `npm run sigma` regenerates
      `sigma/` but nothing prevents drift. Either commit the regenerated files
      and verify in CI, or generate on-demand and stop committing.
- [ ] **Per-rule unit tests for `tools/regen_queries.py`** — currently only
      integration-level coverage. A few golden-file tests would catch
      regressions when the family classifier changes.

---

## Later (bigger bets, not committed)

- **User-editable profile in the UI** — `profiles/default.yaml` is a
  hypothetical environment for the recommender. Letting a user toggle
  `log_sources[].deployed` in-browser would make the Recommendations view
  reflect *their* stack, not the default. Persistence: localStorage first,
  account/server-side only if needed.
- **Coverage diff view** — given two profiles (or two points in time), show
  which rules light up / go dark. Useful for "what would deploying X log
  source actually buy us?"
- **Rule provenance** — surface which audit run a rule's queries came from
  (model, batch ID, date) so we can re-audit selectively when the model
  improves.
- **Auth on the hosted Railway instance** — currently public. If the library
  ever contains anything sensitive (custom rules, environment-specific
  pseudo-logic), add a gate.

---

## Done (recent, for context)

- Batch API audit/regen pipeline (`tools/regen/batch.py`) — `a84f1cb`
- Regenerated all 10 SIEM queries from `data_sources` + `pseudo_logic` — `b27fab9`
- Backfilled `risk_score` on 121 rules + Kill Chain phase filter — `d6bf6f0`
- Responsive mobile layout — `f369c42`
- Triage steps + dashboard click-to-filter + matrix tile expand — `4722edf`
- Sumo Logic as 10th SIEM + aligned technique counters — `fa12da7`
