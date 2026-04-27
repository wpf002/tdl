# TDL Playbook

Threat Detection Library — 700 ATT&CK-mapped detection rules with native query implementations
for 9 SIEM platforms (SPL, KQL, AQL, YARA-L, ES|QL, LEQL, CrowdStrike, XQL, Lucene), a validation
pipeline, Sigma export, attack chain correlation, log source recommendation engine, and a
React/Vite dashboard backed by a Flask API.

## Quick start

```bash
./run            # boots backend (:8787) + Vite dev server (:5173)
# or
npm run app      # same thing via npm
```

Open `http://localhost:5173` — the sidebar's **Data source** indicator should read `● live API`,
confirming the frontend is fetching from the running backend.

```bash
./run prod       # builds the UI and serves everything from Flask on :8787
npm run test:app # full integration test (backend + UI build)
```

## Architecture

```text
ui/  (React + Vite, port 5173)  ──fetch /api/*──▶  tools/server.py  (Flask, port 8787)
                                                          │
                                                          ├─ rules/*.yaml          (canonical detection rules)
                                                          ├─ chains/*.yaml         (attack chain definitions)
                                                          ├─ profiles, log-sources (recommendation engine)
                                                          └─ tools/{chain_eval,recommend,coverage}.py|js
```

In dev mode Vite proxies `/api/*` → `http://localhost:8787`. In prod mode Flask serves
`ui/dist/` plus the API on the same origin. If the backend is unreachable the frontend falls
back to the bundled `ui/src/data/rules.json` so the UI never goes blank.

## API endpoints

| Method | Path                          | Purpose                                                |
|--------|-------------------------------|--------------------------------------------------------|
| GET    | `/api/health`                 | Health probe — `{status, rules}`                       |
| GET    | `/api/stats`                  | Dashboard counts by tactic / severity / lifecycle      |
| GET    | `/api/rules`                  | All rules; filters: `tactic, severity, lifecycle, q`   |
| GET    | `/api/rules/<rule_id>`        | Single rule (add `?full=1` to read raw YAML)           |
| GET    | `/api/tactics`                | Per-tactic counts and technique sets                   |
| GET    | `/api/coverage`               | ATT&CK coverage report                                 |
| GET    | `/api/chains`                 | Attack chain coverage (`?refresh=1` to recompute)      |
| GET    | `/api/recommendations`        | Log-source recommendations (`?refresh=1` to recompute) |

## Pipeline

```bash
npm install            # Node deps for validator/indexer/exporter
npm run validate       # AJV schema validation across rules/
npm run index          # build exports/rule_index.json
npm run coverage       # ATT&CK coverage report
npm run chains         # evaluate chains/attack_chains.yaml
npm run sigma          # generate sigma/ rules
npm run all            # full pipeline
```

## UI

```bash
npm run ui:data    # regenerate rules.json from YAML library
npm run ui:dev     # Vite dev server only → http://localhost:5173
npm run ui:build   # production build → ui/dist/
npm run api        # Flask API only → http://localhost:8787
```

## Testing

```bash
npm run test:app   # boots backend, hits every /api/* endpoint, builds UI
node tools/validator.js          # schema validation, 700/700 expected
python3 tools/chain_eval.py      # 5/5 chains expected active
python3 tools/sigma_compile_test.py  # pySigma compile sanity check
```
