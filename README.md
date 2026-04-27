# TDL Playbook

Threat Detection Library — 700 ATT&CK-mapped detection rules with native query implementations
for 9 SIEM platforms (SPL, KQL, AQL, YARA-L, ES|QL, LEQL, CrowdStrike, XQL, Lucene), a validation
pipeline, Sigma export, attack chain correlation, log source recommendation engine, and a
React/Vite dashboard.

## Pipeline

```bash
npm install            # Node deps for the validator/indexer/exporter
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
npm run ui:dev     # development server → http://localhost:5173
npm run ui:build   # production build → ui/dist/
```
