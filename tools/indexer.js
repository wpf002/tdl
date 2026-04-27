#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { glob } from 'glob';
import yaml from 'js-yaml';
import chalk from 'chalk';

const ROOT = process.cwd();
const OUT_DIR = path.join(ROOT, 'exports');

function bump(map, key) {
  if (!key) return;
  map[key] = (map[key] || 0) + 1;
}

function main() {
  const files = glob.sync('rules/**/*.yaml', { cwd: ROOT, absolute: true });
  const rules = [];
  for (const f of files) {
    try {
      const doc = yaml.load(fs.readFileSync(f, 'utf8'));
      if (!doc || !doc.rule_id) continue;
      rules.push({
        rule_id: doc.rule_id,
        name: doc.name,
        tactic: doc.tactic,
        technique_id: doc.technique_id,
        technique_name: doc.technique_name,
        platform: doc.platform || [],
        data_sources: doc.data_sources || [],
        severity: doc.severity,
        fidelity: doc.fidelity,
        lifecycle: doc.lifecycle,
        risk_score: doc.risk_score ?? null,
        query_formats: Object.keys(doc.queries || {}),
        path: path.relative(ROOT, f)
      });
    } catch (e) {
      console.error(chalk.yellow(`  ! skip ${path.relative(ROOT, f)}: ${e.message}`));
    }
  }

  const stats = {
    by_tactic: {},
    by_severity: {},
    by_lifecycle: {},
    by_fidelity: {},
    by_query_format: {},
    by_platform: {}
  };
  for (const r of rules) {
    bump(stats.by_tactic, r.tactic);
    bump(stats.by_severity, r.severity);
    bump(stats.by_lifecycle, r.lifecycle);
    bump(stats.by_fidelity, r.fidelity);
    for (const fmt of r.query_formats) bump(stats.by_query_format, fmt);
    for (const p of r.platform) bump(stats.by_platform, p);
  }

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const outPath = path.join(OUT_DIR, 'rule_index.json');
  fs.writeFileSync(outPath, JSON.stringify({
    total_rules: rules.length,
    stats,
    rules,
    generated_at: new Date().toISOString()
  }, null, 2));

  console.log(chalk.bold('\n  TDL Playbook — Rule Indexer\n'));
  console.log(`  Total rules: ${rules.length}`);
  console.log(`  Tactics:     ${Object.keys(stats.by_tactic).length}`);
  console.log(`  Lifecycles:  ${JSON.stringify(stats.by_lifecycle)}`);
  console.log(`  Index:       ${path.relative(ROOT, outPath)}\n`);
}

main();
