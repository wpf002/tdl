#!/usr/bin/env python3
"""Regenerate every rule's 10 SIEM query languages from its actual metadata.

Why this exists
---------------
The previous generator (`tools/siem_expand.py`) was a keyword-pattern matcher
that only recognized ~6 rule names (kerberoast, lsass, log clear, …). Every
other rule fell through to a generic template that ignored the rule's actual
data sources and pseudo_logic, producing queries like `index=windows | table
_time…` for SharePoint rules and `event_simpleName=ProcessRollup2` for
firewall rules.

This tool does the right thing:
  1. Classify each rule into a query family (auth / cloud / network /
     process / registry / file) from its data_sources, platform, and
     pseudo_logic — not its name.
  2. Derive a hint (event, field, command-pattern) from data_sources +
     pseudo_logic so the per-dialect filter actually filters on what the
     rule says to detect (event IDs, ports, operation names, process
     names, etc.).
  3. Render all 10 dialects via tools/gen/query_templates.render() so
     the telemetry source (index/table/dataset/event_simpleName/…) is
     correct for the family.

Usage:
    python3 tools/regen_queries.py            # regenerate all rules
    python3 tools/regen_queries.py --rule TDL-AUTH-000001
    python3 tools/regen_queries.py --dry-run  # show first 5 rules, no writes
"""

import argparse
import re
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from gen.query_templates import render  # noqa: E402

RULES_DIR = ROOT / "rules"


class BlockStr(str):
    """Strings emitted as YAML literal blocks (preserves newlines)."""


def _block_str_rep(d, data):
    return d.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(BlockStr, _block_str_rep)


# ── 1. Family classifier ────────────────────────────────────────────────────

CLOUD_TOKENS = (
    "cloudtrail", "guardduty", " aws", "aws ", "azure", "gcp",
    "google cloud", "okta", "duo", "slack", "salesforce", "github",
    "google workspace", "sharepoint", "office 365", "o365", "m365",
    "kubernetes", "k8s", "aws elb", "aws config", "aws vpc", "box ",
    "onedrive", "email security", "mimecast", "proofpoint", "abnormal",
    "sso", "saml", "ssh certificate authority", "atlassian", "jira",
    "zoom", "service cloud", "workday",
)
NETWORK_TOKENS = (
    "firewall", "forward proxy", "proxy", "intrusion detection",
    "intrusion prevention", "ids/ips", "ids ", "waf",
    "web application firewall", "dns", "netflow", "vpn",
    "network traffic", "network device", "ndr", "zeek", "suricata",
)
AUTH_EVENT_RE = re.compile(
    r"\b(528|529|540|4624|4625|4634|4648|4672|4768|4769|4771|4776|"
    r"4798|4799|4964|5140|5145)\b"
)
PROCESS_TOKENS = (
    "sysmon", "edr", "powershell", "process create", "process launch",
    "windows operating system",  # most Windows rules without explicit auth events
)


def classify_family(rule):
    """Return one of: auth | cloud | network | process | registry | file."""
    ds_text = " ".join((s or "").lower() for s in (rule.get("data_sources") or []))
    plat_text = " ".join((s or "").lower() for s in (rule.get("platform") or []))
    pseudo = (rule.get("pseudo_logic") or "").lower()
    name = (rule.get("name") or "").lower()
    blob = " ".join([ds_text, plat_text, pseudo, name])

    # Cloud / SaaS / IdP — covers AWS, Azure, GCP, Okta, M365, SharePoint, Slack,
    # Salesforce, GitHub, K8s, etc.
    if any(t in blob for t in CLOUD_TOKENS):
        return "cloud"

    # Network telemetry — firewall, proxy, DNS, IDS, WAF, NDR
    if any(t in blob for t in NETWORK_TOKENS):
        return "network"

    # Windows / on-prem authentication. Keyed on the canonical Windows event IDs
    # so we catch rules that mention 4625 in pseudo_logic but list "Windows
    # Operating System" as the only data source.
    if AUTH_EVENT_RE.search(ds_text + " " + pseudo):
        return "auth"
    if "active directory" in ds_text or "kerberos" in name + " " + pseudo:
        return "auth"
    if "windows security event log" in ds_text:
        return "auth"

    # Registry — sysmon 12/13/14
    if "registry" in pseudo or "reg.exe" in pseudo or "regedit" in pseudo:
        return "registry"

    # File events — sysmon 11/23/26 + ransomware-style
    if any(k in pseudo for k in (
        "file create", "file write", "file delete", "file modify",
        "file rename", "encrypt", "shadow copy",
    )):
        return "file"

    # Endpoint / process activity (Sysmon, EDR, 4688)
    if any(t in blob for t in PROCESS_TOKENS) or "4688" in pseudo:
        return "process"

    # Default — most uncategorized rules involve process activity
    return "process"


# ── 2. Hint derivation (event, field, regex) ────────────────────────────────

# Maps a family to the event hint that selects it via _resolve(). We pick the
# canonical event for each family so the right templates are returned.
FAMILY_TO_EVENT = {
    "auth":     "UserLogon",
    "cloud":    "ConsoleLogin",
    "network":  "NetworkConnect",
    "registry": "RegistryEvent",
    "file":     "FileCreate",
    "process":  "ProcessCreate",
}


def _extract_event_ids(rule, max_n=6):
    """Collect Windows event IDs referenced anywhere in the rule's data."""
    text = (
        " ".join(str(s) for s in (rule.get("data_sources") or []))
        + " " + str(rule.get("pseudo_logic") or "")
    )
    ids = re.findall(r"\b(\d{3,4})\b", text)
    # Filter to the Windows audit / sysmon range
    keep = []
    for x in ids:
        n = int(x)
        if 100 <= n <= 9999 and (n in (104, 1102) or 1 <= n <= 26 or 4000 <= n <= 5999 or n == 7045):
            if x not in keep:
                keep.append(x)
        if len(keep) >= max_n:
            break
    return keep


def _extract_ports(text):
    """Pull explicit port lists out of pseudo_logic.

    Handles 'port is in [6667, 6668]', 'port 22', 'destination port 443'.
    """
    # Bracketed list — common in TDL pseudo_logic: 'Port is in [6667, 6668, 6669]'
    m = re.search(r"port[s]?\b.{0,30}?\[\s*(\d{2,5}(?:\s*,\s*\d{2,5})*)\s*\]", text, re.I)
    if m:
        return [p.strip() for p in m.group(1).split(",") if p.strip().isdigit()][:8]
    # Single 'port 22' / 'destination port 443'
    m = re.search(r"\bport[s]?\s+(?:is\s+)?(\d{2,5})\b", text, re.I)
    if m:
        return [m.group(1)]
    return []


PROTOCOL_RE = re.compile(
    r"\b(IRC|HTTPS?|DNS|SSH|FTPS?|SMB|SMTP|RDP|ICMP|TLS|LDAP|TELNET|SNMP|VNC|TOR)\b",
    re.I,
)


def _extract_operation(text):
    """Pull a quoted operation/event name out of pseudo_logic."""
    m = re.search(r"operation\s+(?:is\s+)?[\"']([A-Za-z][\w\-\.]+)[\"']", text, re.I)
    if m:
        return m.group(1)
    m = re.search(r"event\s*name\s+(?:is\s+)?[\"']([A-Za-z][\w\-\.]+)[\"']", text, re.I)
    if m:
        return m.group(1)
    return None


def _extract_processes(text):
    """Pull process names like vssadmin.exe, powershell.exe out of text."""
    return list(dict.fromkeys(re.findall(r"\b([\w\-]{2,32}\.exe)\b", text, re.I)))[:6]


def _extract_quoted(text):
    """Pull single/double-quoted string literals out of text."""
    return re.findall(r"[\"']([^\"']{2,60})[\"']", text)


def derive_hint(rule, family):
    """Return a hint dict {event, field, command} for render()."""
    pseudo = rule.get("pseudo_logic") or ""
    name = rule.get("name") or ""
    description = rule.get("description") or ""
    technique_id = (rule.get("technique_id") or "").split(".")[0]
    blob = " ".join([pseudo, name, description])

    event = FAMILY_TO_EVENT[family]

    # Per-family: pick the strongest field/regex available.
    if family == "auth":
        eids = _extract_event_ids(rule)
        if eids:
            return {
                "event": event,
                "field": "event_id",
                "command": "|".join(eids),
                "values": eids,
            }
        default_eids = ["4624", "4625", "4768", "4769", "4776"]
        return {"event": event, "field": "event_id",
                "command": "|".join(default_eids), "values": default_eids}

    if family == "network":
        ports = _extract_ports(blob)
        if ports:
            return {
                "event": event,
                "field": "destination_port",
                "command": "|".join(ports),
                "values": ports,
            }
        # Quoted application name: 'Where the Application is "IRC"'
        m = re.search(r"\bapplication\b[^\"'\n]{0,40}[\"']([A-Za-z][\w\-]{1,20})[\"']", blob, re.I)
        if m:
            return {"event": event, "field": "application", "command": m.group(1)}
        # Bare protocol keyword anywhere in blob
        m = PROTOCOL_RE.search(blob)
        if m:
            return {"event": event, "field": "network.protocol", "command": m.group(1).lower()}
        return {"event": event, "field": "network.protocol", "command": "tcp"}

    if family == "cloud":
        op = _extract_operation(blob)
        if op:
            return {"event": event, "field": "eventName", "command": op}
        # Try to match well-known cloud API names from rule name (PutBucketAcl, etc.)
        m = re.search(r"\b([A-Z][a-z]+[A-Z]\w+)\b", name)
        if m:
            return {"event": event, "field": "eventName", "command": m.group(1)}
        return {"event": event, "field": "eventName", "command": ".+"}

    if family == "registry":
        keys = _extract_quoted(blob)
        for k in keys:
            if "\\" in k or "HKEY" in k.upper() or "Run" in k:
                return {"event": event, "field": "registry_key", "command": k}
        return {"event": event, "field": "registry_key", "command": ".+"}

    if family == "file":
        procs = _extract_processes(blob)
        if procs:
            return {
                "event": event,
                "field": "process_name",
                "command": "|".join(re.escape(p) for p in procs),
            }
        keys = _extract_quoted(blob)
        for k in keys:
            if "." in k:
                return {"event": event, "field": "file_name", "command": k}
        return {"event": event, "field": "file_name", "command": ".+"}

    # process family
    procs = _extract_processes(blob)
    if procs:
        return {
            "event": event,
            "field": "process_name",
            "command": "|".join(re.escape(p) for p in procs),
            "values": procs,
        }
    eids = _extract_event_ids(rule)
    if eids:
        return {"event": event, "field": "event_id",
                "command": "|".join(eids), "values": eids}
    return {"event": event, "field": "process_name", "command": ".+"}


# ── 3. Driver ────────────────────────────────────────────────────────────────

QUERY_KEYS = ("spl", "kql", "aql", "yara_l", "esql", "leql",
              "crowdstrike", "xql", "lucene", "sumo")


def regen_rule_queries(rule):
    """Return a fresh `queries` dict with all 10 dialects."""
    family = classify_family(rule)
    hint = derive_hint(rule, family)
    out = render(
        rule_id=rule.get("rule_id", "TDL-X-000000"),
        technique_id=rule.get("technique_id") or "T1078",
        tactic_id=rule.get("tactic_id") or "TA0001",
        name=rule.get("name") or "Detection",
        severity=rule.get("severity") or "Medium",
        hint=hint,
    )
    # Render all 10 keys; if a dialect missed, fall back to a comment.
    queries = {}
    for k in QUERY_KEYS:
        v = out.get(k)
        if v and v.strip():
            queries[k] = BlockStr(v.strip() + "\n")
        else:
            queries[k] = BlockStr(f"# {k.upper()}: tune from pseudo_logic\n")
    return queries, family, hint


def load_yaml_text(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def write_yaml(rule, path):
    rule["last_modified"] = date.today().isoformat()
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(rule, f, default_flow_style=False, allow_unicode=True,
                  sort_keys=False, width=120)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rule", help="Only process a single rule_id (e.g. TDL-AUTH-000001)")
    p.add_argument("--dry-run", action="store_true", help="Print first 5 rules' output, write nothing")
    p.add_argument("--limit", type=int, default=None, help="Only process N rules")
    args = p.parse_args()

    paths = sorted(RULES_DIR.rglob("*.yaml"))
    n_processed = 0
    n_written = 0
    family_counts = {}

    for path in paths:
        try:
            rule = load_yaml_text(path)
        except Exception as e:
            print(f"  ! parse error {path}: {e}")
            continue
        if not isinstance(rule, dict) or "rule_id" not in rule:
            continue
        if args.rule and rule["rule_id"] != args.rule:
            continue

        queries, family, hint = regen_rule_queries(rule)
        family_counts[family] = family_counts.get(family, 0) + 1
        n_processed += 1

        if args.dry_run:
            if n_processed <= 5:
                print("=" * 72)
                print(f"{rule['rule_id']} · {rule.get('name')}")
                print(f"  family={family}  hint={hint}")
                print(f"  data_sources={rule.get('data_sources')}")
                for k in ("spl", "kql", "crowdstrike"):
                    print(f"\n  --- [{k}] ---")
                    print("  " + str(queries[k]).rstrip().replace("\n", "\n  "))
            continue

        rule["queries"] = {k: queries[k] for k in QUERY_KEYS}
        write_yaml(rule, path)
        n_written += 1

        if args.limit and n_written >= args.limit:
            break

    print(f"\nProcessed: {n_processed}")
    print(f"Written:   {n_written}")
    print(f"Family distribution:")
    for fam, n in sorted(family_counts.items(), key=lambda x: -x[1]):
        print(f"  {fam:<10} {n}")


if __name__ == "__main__":
    main()
