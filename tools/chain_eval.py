#!/usr/bin/env python3
"""
TDE Playbook — Chain Evaluator
Validates that all rules referenced in attack chains exist in the rule library,
computes chain coverage, and outputs a chain coverage report.

Usage:
  python3 tools/chain_eval.py
  python3 tools/chain_eval.py --output exports/chain_coverage.json
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("pip install pyyaml"); sys.exit(1)


def load_rules(rules_dir: str) -> dict:
    """Returns dict: rule_id → rule metadata."""
    rules = {}
    for f in Path(rules_dir).rglob("*.yaml"):
        content = f.read_text()
        for doc in content.split("\n---\n"):
            doc = doc.strip()
            if not doc:
                continue
            try:
                rule = yaml.safe_load(doc)
                if rule and "rule_id" in rule:
                    rules[rule["rule_id"]] = rule
            except Exception:
                pass
    return rules


def load_chains(chains_path: str) -> list:
    with open(chains_path) as f:
        data = yaml.safe_load(f)
    return data.get("chains", [])


def evaluate_chains(chains: list, rules: dict) -> list:
    results = []
    for chain in chains:
        chain_id = chain["chain_id"]
        chain_rules = chain.get("rules", [])
        required_rules = [r for r in chain_rules if r.get("required", False)]

        present = []
        missing = []
        for cr in chain_rules:
            rid = cr["rule_id"]
            if rid in rules:
                rule = rules[rid]
                present.append({
                    "rule_id":   rid,
                    "name":      rule.get("name", ""),
                    "severity":  rule.get("severity", ""),
                    "lifecycle": rule.get("lifecycle", ""),
                    "step":      cr.get("step", 0),
                    "label":     cr.get("label", ""),
                    "required":  cr.get("required", False),
                })
            else:
                missing.append({
                    "rule_id": rid,
                    "label":   cr.get("label", ""),
                    "required":cr.get("required", False),
                })

        required_present = all(
            r["rule_id"] in rules for r in required_rules
        )
        coverage_pct = round(len(present) / len(chain_rules) * 100) if chain_rules else 0

        results.append({
            "chain_id":         chain_id,
            "name":             chain["name"],
            "threat_profile":   chain.get("threat_actor_profile", ""),
            "severity":         chain["severity"],
            "window":           chain.get("window", ""),
            "total_rules":      len(chain_rules),
            "present_count":    len(present),
            "missing_count":    len(missing),
            "coverage_pct":     coverage_pct,
            "required_met":     required_present,
            "active":           required_present and coverage_pct >= 50,
            "present_rules":    present,
            "missing_rules":    missing,
            "has_spl":          bool(chain.get("detection_spl")),
            "has_kql":          bool(chain.get("detection_kql")),
        })

    return results


def print_chain_report(results: list):
    BOLD = "\033[1m"; W = "\033[0m"
    G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; B = "\033[94m"

    print(f"\n{BOLD}{'═'*70}{W}")
    print(f"{BOLD}  TDE PLAYBOOK — ATTACK CHAIN COVERAGE{W}")
    print(f"{BOLD}{'═'*70}{W}\n")

    active   = [r for r in results if r["active"]]
    inactive = [r for r in results if not r["active"]]
    print(f"  Total chains defined:  {len(results)}")
    print(f"  {G}Active (fully covered): {len(active)}{W}")
    print(f"  {Y}Partial coverage:       {len(inactive)}{W}\n")

    for r in results:
        status_color = G if r["active"] else Y if r["coverage_pct"] >= 50 else R
        status = "ACTIVE  " if r["active"] else "PARTIAL " if r["coverage_pct"] >= 50 else "MISSING "
        print(f"  {status_color}{status}{W} {BOLD}{r['chain_id']}{W} — {r['name']}")
        print(f"           Threat: {r['threat_profile']}")
        print(f"           Coverage: {r['coverage_pct']}%  ({r['present_count']}/{r['total_rules']} rules)")
        print(f"           Window: {r['window']}  |  Severity: {r['severity']}")
        print(f"           SPL: {'✓' if r['has_spl'] else '✗'}  KQL: {'✓' if r['has_kql'] else '✗'}")

        if r["present_rules"]:
            print(f"           {G}Present rules:{W}")
            for pr in r["present_rules"]:
                req = " [REQUIRED]" if pr["required"] else ""
                print(f"             Step {pr['step']}: {pr['rule_id']} — {pr['label']}{req}")

        if r["missing_rules"]:
            print(f"           {R}Missing rules:{W}")
            for mr in r["missing_rules"]:
                req = " [REQUIRED — chain inactive]" if mr["required"] else ""
                print(f"             ✗ {mr['rule_id']} — {mr['label']}{req}")
        print()


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules",  default="rules")
    parser.add_argument("--chains", default="chains/attack_chains.yaml")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    rules   = load_rules(args.rules)
    chains  = load_chains(args.chains)
    results = evaluate_chains(chains, rules)
    print_chain_report(results)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"  Chain coverage report: {args.output}\n")


if __name__ == "__main__":
    main()
