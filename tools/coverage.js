#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { glob } from 'glob';
import yaml from 'js-yaml';
import chalk from 'chalk';

const ROOT = process.cwd();
const MATRIX_DIR = path.join(ROOT, 'matrix');

const TACTIC_ORDER = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact'
];

function main() {
  const files = glob.sync('rules/**/*.yaml', { cwd: ROOT, absolute: true });
  const byTactic = {};
  const byTechnique = {};

  for (const f of files) {
    let doc;
    try { doc = yaml.load(fs.readFileSync(f, 'utf8')); } catch { continue; }
    if (!doc || !doc.rule_id) continue;

    const tactic = doc.tactic || 'Unknown';
    byTactic[tactic] = byTactic[tactic] || { total: 0, deployed: 0, proposed: 0, techniques: new Set() };
    byTactic[tactic].total++;
    if (doc.lifecycle === 'Deployed') byTactic[tactic].deployed++;
    if (doc.lifecycle === 'Proposed') byTactic[tactic].proposed++;
    if (doc.technique_id) byTactic[tactic].techniques.add(doc.technique_id);

    const tech = doc.technique_id || 'unknown';
    byTechnique[tech] = byTechnique[tech] || {
      technique_id: tech,
      technique_name: doc.technique_name || '',
      tactic,
      rule_count: 0,
      rules: []
    };
    byTechnique[tech].rule_count++;
    byTechnique[tech].rules.push(doc.rule_id);
  }

  const tacticReport = {};
  for (const [t, v] of Object.entries(byTactic)) {
    tacticReport[t] = {
      total: v.total,
      deployed: v.deployed,
      proposed: v.proposed,
      unique_techniques: v.techniques.size
    };
  }

  const report = {
    summary: {
      total_rules: files.length,
      total_techniques: Object.keys(byTechnique).length,
      tactics_covered: Object.keys(byTactic).length
    },
    by_tactic: tacticReport,
    by_technique: Object.values(byTechnique).sort((a, b) => b.rule_count - a.rule_count),
    generated_at: new Date().toISOString()
  };

  fs.mkdirSync(MATRIX_DIR, { recursive: true });
  const outPath = path.join(MATRIX_DIR, 'coverage_report.json');
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2));

  console.log(chalk.bold('\n  TDL Playbook — Coverage Report\n'));
  console.log(`  Total rules:       ${files.length}`);
  console.log(`  Unique techniques: ${Object.keys(byTechnique).length}`);
  console.log(`  Tactics covered:   ${Object.keys(byTactic).length}\n`);
  for (const t of TACTIC_ORDER) {
    const v = tacticReport[t];
    if (!v) continue;
    console.log(`    ${t.padEnd(22)} rules=${String(v.total).padStart(4)}  deployed=${String(v.deployed).padStart(4)}  techniques=${v.unique_techniques}`);
  }
  console.log(`\n  Report: ${path.relative(ROOT, outPath)}\n`);
}

main();
