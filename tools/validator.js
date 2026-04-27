#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { glob } from 'glob';
import yaml from 'js-yaml';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import chalk from 'chalk';

const ROOT = process.cwd();
const RULES_DIR = process.env.RULES_DIR || path.join(ROOT, 'rules');
const SCHEMA_PATH = path.join(ROOT, 'schemas', 'rule.schema.json');
const OUT_DIR = path.join(ROOT, 'exports');

function loadSchema() {
  const raw = fs.readFileSync(SCHEMA_PATH, 'utf8');
  return JSON.parse(raw);
}

function loadRuleFiles() {
  return glob.sync('rules/**/*.yaml', { cwd: ROOT, absolute: true });
}

function main() {
  const schema = loadSchema();
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  const validate = ajv.compile(schema);

  const files = loadRuleFiles();
  let pass = 0, fail = 0;
  const failures = [];

  for (const f of files) {
    const text = fs.readFileSync(f, 'utf8');
    let doc;
    try {
      doc = yaml.load(text);
    } catch (e) {
      failures.push({ file: path.relative(ROOT, f), errors: [`YAML parse error: ${e.message}`] });
      fail++;
      continue;
    }
    const ok = validate(doc);
    if (ok) {
      pass++;
    } else {
      fail++;
      failures.push({
        file: path.relative(ROOT, f),
        errors: (validate.errors || []).map(e => `${e.instancePath || '/'} ${e.message}`)
      });
    }
  }

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outPath = path.join(OUT_DIR, `validation_${stamp}.json`);
  fs.writeFileSync(outPath, JSON.stringify({
    total: files.length,
    pass,
    fail,
    failures,
    generated_at: new Date().toISOString()
  }, null, 2));

  console.log(chalk.bold('\n  TDL Playbook — Rule Validator\n'));
  console.log(`  Total rules:  ${files.length}`);
  console.log(`  ${chalk.green(`Pass: ${pass}`)}`);
  console.log(`  ${fail ? chalk.red(`Fail: ${fail}`) : `Fail: ${fail}`}`);
  console.log(`  Report:       ${path.relative(ROOT, outPath)}\n`);

  if (fail > 0) {
    for (const f of failures.slice(0, 10)) {
      console.log(chalk.red(`  ✗ ${f.file}`));
      for (const e of f.errors.slice(0, 3)) console.log(`     - ${e}`);
    }
    if (failures.length > 10) console.log(`  … and ${failures.length - 10} more`);
    process.exit(1);
  }
}

main();
