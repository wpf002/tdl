#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { glob } from 'glob';
import yaml from 'js-yaml';
import chalk from 'chalk';

const ROOT = process.cwd();
const OUT_DIR = path.join(ROOT, 'exports');

function readJSON(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}

function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const files = glob.sync('rules/**/*.yaml', { cwd: ROOT, absolute: true });
  const rules = [];
  for (const f of files) {
    try {
      const doc = yaml.load(fs.readFileSync(f, 'utf8'));
      if (doc && doc.rule_id) rules.push(doc);
    } catch {}
  }

  const ruleIndex = readJSON(path.join(OUT_DIR, 'rule_index.json'));
  const chainCov  = readJSON(path.join(OUT_DIR, 'chain_coverage.json'));
  const coverage  = readJSON(path.join(ROOT, 'matrix', 'coverage_report.json'));

  const sigmaCount = glob.sync('sigma/**/*.yml', { cwd: ROOT }).length;

  const pack = {
    name: 'tdl-playbook',
    version: '2.0.0',
    generated_at: new Date().toISOString(),
    summary: {
      total_rules: rules.length,
      sigma_rules: sigmaCount,
      tactics_covered: coverage?.summary?.tactics_covered ?? null,
      unique_techniques: coverage?.summary?.total_techniques ?? null,
      attack_chains: Array.isArray(chainCov) ? chainCov.length : null,
      active_chains: Array.isArray(chainCov) ? chainCov.filter(c => c.active).length : null
    },
    has_index: !!ruleIndex,
    has_coverage: !!coverage,
    has_chain_coverage: !!chainCov
  };

  const outPath = path.join(OUT_DIR, 'canonical_pack.json');
  fs.writeFileSync(outPath, JSON.stringify(pack, null, 2));

  console.log(chalk.bold('\n  TDL Playbook — Canonical Exporter\n'));
  console.log(`  Rules:        ${rules.length}`);
  console.log(`  Sigma rules:  ${sigmaCount}`);
  if (chainCov) console.log(`  Chains:       ${pack.summary.active_chains}/${pack.summary.attack_chains} active`);
  console.log(`  Pack:         ${path.relative(ROOT, outPath)}\n`);
}

main();
