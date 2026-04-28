#!/usr/bin/env python3
"""Backfill a Sumo Logic query into every rule that lacks one.

Strategy: Sumo's Search Query Language is closest to SPL — both are pipe-based
with `parse | where | count by | sort by`. We translate the rule's existing
SPL query when present, otherwise emit a templated Sumo query keyed off the
rule's tactic / data sources.

Reference: https://help.sumologic.com/docs/search/search-query-language/
"""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "rules"


# ─── Source-category mapping per data source ────────────────────────────────
DS_TO_CATEGORY = {
    "Sysmon": "*sysmon*",
    "Windows Event Log": "*windows/events*",
    "EDR": "*endpoint/edr*",
    "Auditd": "*linux/auditd*",
    "Firewall": "*firewall*",
    "Network IDS": "*ids*",
    "DNS Logs": "*dns*",
    "Web Server Logs": "*web/access*",
    "Web Proxy": "*proxy*",
    "VPN Logs": "*vpn*",
    "WAF": "*waf*",
    "Email Gateway": "*email*",
    "SaaS Audit Logs": "*saas/audit*",
    "Cloud Audit Logs": "*cloud/audit*",
    "Kubernetes Audit Logs": "*k8s/audit*",
    "Container Registry Logs": "*container/registry*",
    "ADCS Logs": "*windows/adcs*",
    "ADFS Logs": "*windows/adfs*",
    "MDM Logs": "*mdm*",
    "RMM Logs": "*rmm*",
    "Browser Telemetry": "*browser*",
    "Identity Provider Logs": "*idp*",
    "Auth Logs": "*auth*",
    "Network Device Logs": "*netdev*",
    "Firmware Telemetry": "*firmware*",
    "WMI Telemetry": "*windows/wmi*",
}


PLATFORM_FALLBACK = {
    "Windows":          "*windows*",
    "Linux":            "*linux*",
    "macOS":            "*macos*",
    "AWS":              "*aws*",
    "Azure":            "*azure*",
    "GCP":              "*gcp*",
    "Okta":             "*okta*",
    "Microsoft 365":    "*o365*",
    "Google Workspace": "*gworkspace*",
    "Network":          "*network*",
    "SaaS":             "*saas*",
    "Kubernetes":       "*k8s*",
}


def _fuzzy_ds(ds):
    """Match a free-text data_source string against known categories."""
    s = ds.lower()
    if "sysmon" in s: return "*sysmon*"
    if "aws" in s or "cloudtrail" in s or "guardduty" in s: return "*aws*"
    if "azure" in s: return "*azure*"
    if "gcp" in s or "google" in s: return "*gcp*"
    if "okta" in s: return "*okta*"
    if "office 365" in s or "o365" in s or "microsoft 365" in s: return "*o365*"
    if "vpn" in s: return "*vpn*"
    if "firewall" in s or "fortigate" in s or "palo alto" in s: return "*firewall*"
    if "ids" in s or "snort" in s or "suricata" in s: return "*ids*"
    if "dns" in s: return "*dns*"
    if "edr" in s or "crowdstrike" in s or "sentinelone" in s or "defender" in s: return "*endpoint/edr*"
    if "auditd" in s or "audit" in s and "linux" in s: return "*linux/auditd*"
    if "windows event" in s or "winevent" in s: return "*windows/events*"
    return None


def categories_for(rule):
    cats = []
    for ds in rule.get("data_sources") or []:
        c = DS_TO_CATEGORY.get(ds) or _fuzzy_ds(ds)
        if c and c not in cats:
            cats.append(c)
    if not cats:
        for plat in rule.get("platform") or []:
            c = PLATFORM_FALLBACK.get(plat)
            if c and c not in cats:
                cats.append(c)
    if not cats:
        cats = ["*"]
    return " OR ".join(f"_sourceCategory={c}" for c in cats)


# ─── SPL → Sumo translator (best effort; falls back to template) ────────────

SPL_PATTERNS = [
    # `index=foo sourcetype=bar` → drop (Sumo uses _sourceCategory we set above)
    (re.compile(r"\bindex=\S+\s*"), ""),
    (re.compile(r"\bsourcetype=\S+\s*"), ""),
    # `| search foo=bar` → `| where foo=bar`
    (re.compile(r"\|\s*search\b"), "| where"),
    # `| stats count` → `| count`
    (re.compile(r"\|\s*stats\s+count\b"), "| count"),
    (re.compile(r"\|\s*stats\s+"), "| "),
    # `dc(field)` → `count_distinct(field)`
    (re.compile(r"\bdc\(([^)]+)\)"), r"count_distinct(\1)"),
    # `values(field)` → `values(field)` (Sumo supports this)
    # `| sort - field` → `| sort by field desc`
    (re.compile(r"\|\s*sort\s+-\s*"), "| sort by "),
    (re.compile(r"\|\s*sort\s+\+?"), "| sort by "),
    # `where` left as-is (Sumo also uses `where`)
    # `| table f1 f2 ...` → drop (Sumo doesn't have table)
    (re.compile(r"\|\s*table\b[^|]*"), ""),
    # `| eval x = ...` → keep as-is (Sumo has formatDate / num / etc.; eval is close enough for a starter)
    # `| dedup` → keep
    # EventCode=N → parse "EventID=*\"" as event_id | where event_id="N"
    (re.compile(r"EventCode=(\d+)"), r"event_id=\"\1\""),
]


def translate_spl(spl):
    out = spl
    # Insert parse for EventCode if present
    needs_parse = bool(re.search(r"EventCode=\d+", spl))
    for pat, repl in SPL_PATTERNS:
        out = pat.sub(repl, out)
    out = re.sub(r"\n+", "\n", out).strip()
    out = re.sub(r"\s*\|\s*", "\n| ", out)  # one pipe stage per line
    if needs_parse:
        # Place a parse stage at the top
        out = "| parse \"EventID=*\\\"\" as event_id\n" + out
    return out.strip()


NETWORK_DS = {"Firewall", "Network IDS", "DNS Logs", "Web Server Logs",
              "Web Proxy", "VPN Logs", "Network Device Logs", "WAF"}
CLOUD_DS   = {"Cloud Audit Logs", "SaaS Audit Logs", "Identity Provider Logs",
              "Auth Logs", "Kubernetes Audit Logs", "ADFS Logs"}
REGISTRY_DS = {"WMI Telemetry"}


def _shape(rule):
    """Pick the right Sumo query shape for the rule."""
    name = (rule.get("name") or "").lower()
    desc = (rule.get("description") or "").lower()
    plats = set(rule.get("platform") or [])
    ds = set(rule.get("data_sources") or [])

    # Cloud-flavored
    if ds & CLOUD_DS or {"AWS", "Azure", "GCP", "Okta", "Microsoft 365", "Google Workspace", "Kubernetes"} & plats:
        return "cloud"
    # Network-flavored
    if ds & NETWORK_DS or "Network" in plats or any(k in name for k in ("beacon", "tunnel", "outbound", "dns", "tls", "http")):
        return "network"
    # Registry-flavored
    if any(k in name for k in ("registry ", "regkey", "run key", "lsa ", "wmi ")) or "registry" in desc:
        return "registry"
    # File-flavored
    if any(k in name for k in ("file write", "file create", "filewrite", "shadow", "wipe")) or "file " in name:
        return "file"
    # Default: process
    return "process"


def template_sumo(rule):
    """Generate a Sumo Logic query keyed off the rule's data sources / shape.

    Reference: https://help.sumologic.com/docs/search/search-query-language/
    """
    technique = rule.get("technique_id", "")
    cats = categories_for(rule)
    shape = _shape(rule)

    if shape == "network":
        return (
            f"{cats}\n"
            f"| where technique=\"{technique}\" OR _raw matches \"*{technique}*\"\n"
            f"| count, sum(bytes_out) as bytes_out by src_ip, dest_ip, dest_port\n"
            f"| sort by bytes_out desc"
        )
    if shape == "cloud":
        return (
            f"{cats}\n"
            f"| parse regex \"\\\"userIdentity\\\":\\{{\\\"arn\\\":\\\"(?<actor>[^\\\"]+)\" nodrop\n"
            f"| where _raw matches \"*{technique}*\"\n"
            f"| count by actor, eventName, sourceIPAddress\n"
            f"| sort by _count desc"
        )
    if shape == "registry":
        return (
            f"{cats}\n"
            f"| parse \"EventID=*\\\"\" as event_id nodrop\n"
            f"| where event_id IN (\"12\",\"13\",\"14\") AND _raw matches \"*{technique}*\"\n"
            f"| count by host, user, registry_key, registry_value, image\n"
            f"| sort by _count desc"
        )
    if shape == "file":
        return (
            f"{cats}\n"
            f"| parse \"EventID=*\\\"\" as event_id nodrop\n"
            f"| where event_id IN (\"11\",\"23\",\"26\") AND _raw matches \"*{technique}*\"\n"
            f"| count by host, user, target_filename, image\n"
            f"| sort by _count desc"
        )
    # process default
    return (
        f"{cats}\n"
        f"| parse \"EventID=*\\\"\" as event_id nodrop\n"
        f"| where event_id=\"1\" AND _raw matches \"*{technique}*\"\n"
        f"| count by host, user, parent_process_name, command_line\n"
        f"| sort by _count desc"
    )


def build_sumo(rule):
    return template_sumo(rule)


def main():
    """Always (re)generate the Sumo query — idempotent given current schema."""
    paths = sorted(RULES_DIR.rglob("*.yaml"))
    written = 0
    for p in paths:
        try:
            with p.open() as f:
                rule = yaml.safe_load(f)
        except Exception as e:
            print(f"  skip {p}: {e}")
            continue
        if not isinstance(rule, dict):
            continue
        queries = rule.setdefault("queries", {})
        queries["sumo"] = build_sumo(rule)
        with p.open("w") as f:
            yaml.safe_dump(rule, f, sort_keys=False, default_flow_style=False, width=120)
        written += 1
    print(f"wrote/updated sumo on {written} rules")


if __name__ == "__main__":
    main()
