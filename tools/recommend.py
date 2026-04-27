#!/usr/bin/env python3
"""
TDL Playbook — Rule Recommendation Engine
Scores every rule against your environment profile and outputs a prioritized
deployment plan, coverage gaps, and log source ROI analysis.

Usage:
  python3 tools/recommend.py --profile profiles/default.yaml
  python3 tools/recommend.py --profile profiles/default.yaml --siem splunk --output exports/recommendations.json
  python3 tools/recommend.py --profile profiles/default.yaml --top 50 --lifecycle Deployed
"""

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("pip install pyyaml")
    sys.exit(1)

# ── Constants ────────────────────────────────────────────────────────────────

SEVERITY_SCORE = {"Critical": 100, "High": 75, "Medium": 50, "Low": 25}
FIDELITY_SCORE = {"High": 30, "Medium": 15, "Low": 5}
LIFECYCLE_SCORE = {"Deployed": 20, "Tested": 15, "Proposed": 5, "Tuned": 20, "Retired": -100}
TACTIC_PRIORITY = {
    "Credential Access":   10,
    "Lateral Movement":    10,
    "Impact":              10,
    "Defense Evasion":     9,
    "Privilege Escalation":9,
    "Execution":           8,
    "Persistence":         8,
    "Command and Control": 7,
    "Exfiltration":        7,
    "Discovery":           6,
    "Collection":          6,
    "Initial Access":      5,
    "Reconnaissance":      3,
    "Resource Development":3,
}

LOG_SOURCE_MATCH_TERMS = {
    "windows_security_events": [
        "windows security", "windows active directory", "windows os",
        "windows operating system", "wineventlog", "active directory",
        "windows ad", "security event", "event id", "eventcode",
    ],
    "sysmon": ["sysmon", "microsoft-windows-sysmon"],
    "firewall": ["firewall", "palo alto", "cisco asa", "fortinet", "checkpoint", "netflow"],
    "edr": ["crowdstrike", "sentinelone", "carbon black", "cylance", "defender",
            "cortex", "edr", "endpoint detection", "antivirus", "av"],
    "dns": ["dns", "domain name system", "dns server"],
    "identity_provider": ["azure ad", "entra", "okta", "ping identity", "idp",
                          "azure sign", "identity provider"],
    "proxy_web_gateway": ["proxy", "zscaler", "bluecoat", "netskope", "web gateway",
                          "forward proxy", "squid"],
    "email_security": ["proofpoint", "mimecast", "email security", "o365 atp",
                       "defender for o365", "email server"],
    "cloud_infrastructure": ["aws", "cloudtrail", "azure activity", "gcp audit",
                             "cloud infrastructure", "amazon", "azure monitor"],
    "m365_audit": ["office 365", "microsoft 365", "sharepoint", "exchange",
                   "teams", "m365", "o365", "unified audit"],
    "linux_os": ["linux", "syslog", "auditd", "linux operating"],
    "vpn": ["vpn", "remote access", "anyconnect", "globalprotect", "pulse"],
    "dlp": ["dlp", "data loss", "varonis", "digital guardian"],
    "waf": ["waf", "web application firewall", "f5", "imperva", "akamai"],
    "saas_productivity": ["slack", "salesforce", "google workspace", "box", "dropbox",
                          "github", "snowflake", "saas"],
    "kubernetes": ["kubernetes", "k8s", "docker", "eks", "aks", "gke", "container"],
    "mfa": ["mfa", "duo", "rsa securid", "authenticator", "multi-factor"],
}

QUERY_FORMAT = {
    "splunk": "spl",
    "sentinel": "kql",
    "elastic": "eql",
    "chronicle": "yara_l",
}


# ── Loaders ──────────────────────────────────────────────────────────────────

def load_profile(path: str) -> dict:
    with open(path) as f:
        raw = yaml.safe_load(f)
    return raw.get("profile", raw)


def load_catalog(catalog_path: str) -> dict:
    """Returns dict keyed by log_source id."""
    with open(catalog_path) as f:
        raw = yaml.safe_load(f)
    return {ls["id"]: ls for ls in raw.get("log_sources", [])}


def load_rules(rules_dir: str) -> list:
    rules = []
    for f in sorted(Path(rules_dir).rglob("*.yaml")):
        content = f.read_text()
        for doc in content.split("\n---\n"):
            doc = doc.strip()
            if not doc:
                continue
            try:
                rule = yaml.safe_load(doc)
                if rule and "rule_id" in rule:
                    rule["_file"] = str(f)
                    rules.append(rule)
            except Exception:
                pass
    return rules


# ── Matching ─────────────────────────────────────────────────────────────────

def get_deployed_ids(profile: dict) -> set:
    return {
        ls["id"]
        for ls in profile.get("log_sources", [])
        if ls.get("deployed", False)
    }


def get_planned_ids(profile: dict) -> set:
    return {
        ls["id"]
        for ls in profile.get("log_sources", [])
        if ls.get("planned", False) and not ls.get("deployed", False)
    }


def rule_data_source_coverage(rule: dict, deployed_ids: set) -> tuple:
    """
    Returns (coverage_ratio, matched_sources, missing_sources).
    coverage_ratio: 0.0 – 1.0
    """
    rule_sources_raw = rule.get("data_sources", [])
    if not rule_sources_raw:
        return (0.5, [], [])  # no data source info → neutral score

    rule_sources = [str(s).lower() for s in rule_sources_raw]
    matched = []
    missing = []

    for rs in rule_sources:
        found = False
        for src_id, terms in LOG_SOURCE_MATCH_TERMS.items():
            if any(t in rs for t in terms):
                if src_id in deployed_ids:
                    matched.append(src_id)
                    found = True
                    break
                else:
                    missing.append(src_id)
                    found = True
                    break
        if not found:
            # Unrecognized source — don't penalize
            matched.append("unknown")

    total = len(matched) + len(missing_unique := list(dict.fromkeys(missing)))
    if total == 0:
        return (0.5, matched, missing_unique)

    ratio = len(matched) / total
    return (ratio, matched, missing_unique)


def score_rule(rule: dict, deployed_ids: set, profile: dict) -> dict:
    """Compute a deployment priority score for a rule given the profile."""
    sev = rule.get("severity", "Medium")
    fid = rule.get("fidelity", "Medium")
    lc = rule.get("lifecycle", "Proposed")
    tactic = rule.get("tactic", "")

    # Base score components
    sev_pts = SEVERITY_SCORE.get(sev, 25)
    fid_pts = FIDELITY_SCORE.get(fid, 15)
    lc_pts  = LIFECYCLE_SCORE.get(lc, 5)
    tac_pts = TACTIC_PRIORITY.get(tactic, 5) * 3

    # Coverage: how many required data sources do we have?
    coverage_ratio, matched, missing = rule_data_source_coverage(rule, deployed_ids)
    coverage_pts = int(coverage_ratio * 40)

    # Query format availability
    queries = rule.get("queries", {})
    preferred_siem = profile.get("siem", [{}])[0].get("platform", "splunk")
    fmt = QUERY_FORMAT.get(preferred_siem, "spl")
    has_query = 40 if queries.get(fmt) else (20 if queries else 0)

    total = sev_pts + fid_pts + lc_pts + tac_pts + coverage_pts + has_query

    return {
        "rule_id":        rule.get("rule_id", ""),
        "name":           rule.get("name", ""),
        "tactic":         tactic,
        "technique_id":   rule.get("technique_id", ""),
        "severity":       sev,
        "fidelity":       fid,
        "lifecycle":      lc,
        "score":          total,
        "coverage_ratio": round(coverage_ratio, 2),
        "matched_sources": list(dict.fromkeys(matched)),
        "missing_sources": list(dict.fromkeys(missing)),
        "deployable":     coverage_ratio >= 0.5,
        "has_query":      bool(queries.get(fmt)),
        "query_format":   fmt,
        "source":         "TDL",
    }


# ── ROI Analysis ─────────────────────────────────────────────────────────────

def log_source_roi(rules: list, deployed_ids: set, catalog: dict) -> list:
    """
    For each un-deployed log source, count how many rules it would unlock.
    Returns sorted list of (source_id, rules_unlocked, tactics_covered, criticality).
    """
    undeployed_sources = [
        src_id for src_id in LOG_SOURCE_MATCH_TERMS.keys()
        if src_id not in deployed_ids
    ]

    roi = []
    for src_id in undeployed_sources:
        terms = LOG_SOURCE_MATCH_TERMS[src_id]
        unlocked_rules = []
        tactics = set()

        for rule in rules:
            rule_sources = [str(s).lower() for s in rule.get("data_sources", [])]
            if any(any(t in rs for t in terms) for rs in rule_sources):
                unlocked_rules.append(rule.get("rule_id", ""))
                tactics.add(rule.get("tactic", "Unknown"))

        if unlocked_rules:
            cat_info = catalog.get(src_id, {})
            roi.append({
                "log_source_id":   src_id,
                "log_source_name": cat_info.get("name", src_id),
                "criticality":     cat_info.get("criticality", "Unknown"),
                "tier":            cat_info.get("tier", 3),
                "deployment":      cat_info.get("deployment", "Unknown"),
                "cost":            cat_info.get("cost", "Unknown"),
                "rules_unlocked":  len(unlocked_rules),
                "tactics_covered": sorted(list(tactics)),
                "sample_rules":    unlocked_rules[:5],
            })

    return sorted(roi, key=lambda x: (-x["rules_unlocked"], x["tier"]))


# ── Coverage Gap Analysis ─────────────────────────────────────────────────────

ATTACK_COVERAGE_MAP = {
    "Execution":          ["T1059", "T1053", "T1218", "T1047", "T1204"],
    "Persistence":        ["T1547", "T1543", "T1546", "T1574", "T1078"],
    "Privilege Escalation":["T1134", "T1548", "T1055", "T1068"],
    "Defense Evasion":    ["T1070", "T1036", "T1027", "T1562", "T1140"],
    "Credential Access":  ["T1003", "T1558", "T1110", "T1555"],
    "Discovery":          ["T1046", "T1087", "T1082", "T1135"],
    "Lateral Movement":   ["T1550", "T1021", "T1563"],
    "Command and Control":["T1071", "T1095", "T1105", "T1090"],
    "Collection":         ["T1560", "T1074", "T1056"],
    "Exfiltration":       ["T1041", "T1048", "T1567"],
    "Impact":             ["T1486", "T1490", "T1531", "T1529"],
    "Initial Access":     ["T1566", "T1078", "T1133"],
}


def coverage_gap_analysis(scored_rules: list) -> dict:
    """Identify ATT&CK technique coverage gaps across deployable rules."""
    covered_techniques = set()
    for r in scored_rules:
        if r["deployable"]:
            tid = r.get("technique_id", "")
            if tid:
                covered_techniques.add(tid[:5])  # T1059 from T1059.001

    gaps = {}
    for tactic, techniques in ATTACK_COVERAGE_MAP.items():
        tactic_gaps = [t for t in techniques if t not in covered_techniques]
        gaps[tactic] = {
            "total":   len(techniques),
            "covered": len(techniques) - len(tactic_gaps),
            "gaps":    tactic_gaps,
            "pct":     round((len(techniques) - len(tactic_gaps)) / len(techniques) * 100),
        }
    return gaps


# ── Report ────────────────────────────────────────────────────────────────────

def print_report(profile: dict, scored: list, roi: list, gaps: dict,
                 top_n: int, catalog: dict):
    deployable  = [r for r in scored if r["deployable"]]
    undeployable = [r for r in scored if not r["deployable"]]
    critical    = [r for r in deployable if r["severity"] == "Critical"]
    high        = [r for r in deployable if r["severity"] == "High"]

    W = "\033[0m"
    R = "\033[91m"
    Y = "\033[93m"
    G = "\033[92m"
    B = "\033[94m"
    BOLD = "\033[1m"

    print(f"\n{BOLD}{'═'*72}{W}")
    print(f"{BOLD}  TDL PLAYBOOK — RECOMMENDATION ENGINE{W}")
    print(f"{BOLD}{'═'*72}{W}\n")
    print(f"  Profile:  {profile.get('name', 'Unknown')}")
    print(f"  Industry: {profile.get('industry', 'N/A')}")
    siems = [s.get("platform", "?") for s in profile.get("siem", [])]
    print(f"  SIEM(s):  {', '.join(siems)}")
    deployed_count = sum(1 for ls in profile.get("log_sources", []) if ls.get("deployed"))
    print(f"  Log Sources Deployed: {deployed_count}")
    print()

    # Summary
    print(f"{BOLD}  DEPLOYMENT SUMMARY{W}")
    print(f"  {'─'*40}")
    print(f"  Total rules evaluated:    {len(scored)}")
    print(f"  {G}Deployable now:           {len(deployable)}{W}")
    print(f"  {Y}Needs additional sources: {len(undeployable)}{W}")
    print(f"  {R}Critical severity rules:  {len(critical)}{W}")
    print(f"  High severity rules:       {len(high)}")
    print()

    # Top N deployable rules
    print(f"{BOLD}  TOP {top_n} PRIORITY RULES (deploy these first){W}")
    print(f"  {'─'*68}")
    header = f"  {'#':>3}  {'Rule ID':<22} {'Sev':>8}  {'Fidelity':>8}  {'Score':>5}  {'Tactic':<25}"
    print(header)
    print(f"  {'─'*68}")
    for i, r in enumerate(deployable[:top_n], 1):
        sev_color = R if r["severity"] == "Critical" else Y if r["severity"] == "High" else W
        print(
            f"  {i:>3}.  {r['rule_id']:<22} "
            f"{sev_color}{r['severity']:>8}{W}  "
            f"{r['fidelity']:>8}  "
            f"{r['score']:>5}  "
            f"{r['tactic']:<25}"
        )
    print()

    # ATT&CK Coverage
    print(f"{BOLD}  ATT&CK COVERAGE WITH CURRENT LOG SOURCES{W}")
    print(f"  {'─'*58}")
    for tactic, data in gaps.items():
        pct = data["pct"]
        bar_len = 28
        filled = round(pct / 100 * bar_len)
        bar = G + "█" * filled + W + "░" * (bar_len - filled)
        color = G if pct >= 70 else Y if pct >= 40 else R
        print(f"  {tactic:<28} {bar} {color}{pct:>3}%{W} ({data['covered']}/{data['total']})")
    print()

    # Log source ROI
    print(f"{BOLD}  LOG SOURCE ROI — ADD THESE TO UNLOCK MORE RULES{W}")
    print(f"  {'─'*68}")
    print(f"  {'Log Source':<35} {'Rules':>6}  {'Tier':>5}  {'Deploy':>8}  {'Cost':>6}")
    print(f"  {'─'*68}")
    for item in roi[:8]:
        crit_color = R if item["criticality"] == "Critical" else Y if item["criticality"] == "High" else W
        print(
            f"  {item['log_source_name']:<35} "
            f"{crit_color}{item['rules_unlocked']:>6}{W}  "
            f"{'T'+str(item['tier']):>5}  "
            f"{item['deployment']:>8}  "
            f"{item['cost']:>6}"
        )
    print()

    # Log source criticality summary
    print(f"{BOLD}  LOG SOURCE CRITICALITY ASSESSMENT{W}")
    print(f"  {'─'*58}")
    for ls in profile.get("log_sources", []):
        ls_id = ls.get("id", "")
        cat_info = catalog.get(ls_id, {})
        deployed = ls.get("deployed", False)
        criticality = cat_info.get("criticality", "Unknown")
        tier = cat_info.get("tier", "?")
        status_color = G if deployed else Y if ls.get("planned") else R
        status = "DEPLOYED" if deployed else ("PLANNED" if ls.get("planned") else "MISSING ")
        crit_color = R if criticality == "Critical" else Y if criticality == "High" else W
        tier_str = f"T{tier}"
        print(
            f"  {status_color}{status}{W}  "
            f"{crit_color}{criticality:<10}{W}  "
            f"{tier_str}  {cat_info.get('name', ls_id)}"
        )
    print()


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile",  default="profiles/default.yaml")
    parser.add_argument("--rules",    default="rules")
    parser.add_argument("--catalog",  default="log-sources/catalog.yaml")
    parser.add_argument("--top",      default=30, type=int)
    parser.add_argument("--output",   default=None)
    parser.add_argument("--lifecycle",default=None, help="Filter: Deployed|Proposed|Tested")
    parser.add_argument("--siem",     default=None, help="Override SIEM platform from profile")
    args = parser.parse_args()

    profile = load_profile(args.profile)
    catalog = load_catalog(args.catalog)
    rules   = load_rules(args.rules)

    if args.siem:
        profile.setdefault("siem", [{}])
        profile["siem"][0]["platform"] = args.siem

    deployed_ids = get_deployed_ids(profile)
    planned_ids  = get_planned_ids(profile)

    # Score all rules
    scored = [score_rule(r, deployed_ids, profile) for r in rules]

    # Filter by lifecycle if requested
    if args.lifecycle:
        scored = [r for r in scored if r["lifecycle"] == args.lifecycle]

    # Sort by score desc
    scored.sort(key=lambda x: -x["score"])

    # Log source ROI
    roi = log_source_roi(rules, deployed_ids, catalog)

    # Coverage gaps
    gaps = coverage_gap_analysis(scored)

    # Print report
    print_report(profile, scored, roi, gaps, args.top, catalog)

    # JSON output
    if args.output:
        out = {
            "profile":            profile.get("name"),
            "generated":          str(__import__("datetime").date.today()),
            "total_rules":        len(scored),
            "deployable_count":   sum(1 for r in scored if r["deployable"]),
            "top_rules":          scored[:args.top],
            "log_source_roi":     roi,
            "coverage_gaps":      gaps,
            "all_scored":         scored,
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(out, f, indent=2)
        print(f"  Full report: {args.output}\n")


if __name__ == "__main__":
    main()
