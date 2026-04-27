#!/usr/bin/env python3
"""
TDE Playbook — Sigma Generator
Converts TDE/TDL rules into valid Sigma rule format.
Sigma is the canonical vendor-neutral format — SPL/KQL are compiled outputs.

Usage:
  python3 tools/sigma_gen.py                    # all rules
  python3 tools/sigma_gen.py --tactic credential-access
  python3 tools/sigma_gen.py --rule-id TDE-CA-001
  python3 tools/sigma_gen.py --lifecycle Deployed

Output: sigma/<tactic>/<rule_id>.yml
"""

import argparse
import re
import sys
from pathlib import Path
from datetime import date

try:
    import yaml
except ImportError:
    print("pip install pyyaml"); sys.exit(1)

# ── Sigma field mappings ─────────────────────────────────────────────────────

LOGSOURCE_MAP = {
    # Windows endpoint
    "windows_process":   {"category": "process_creation",     "product": "windows"},
    "windows_registry":  {"category": "registry_set",         "product": "windows"},
    "windows_network":   {"category": "network_connection",   "product": "windows"},
    "windows_file":      {"category": "file_event",           "product": "windows"},
    "windows_security":  {"service":  "security",             "product": "windows"},
    "windows_system":    {"service":  "system",               "product": "windows"},
    "windows_sysmon":    {"service":  "sysmon",               "product": "windows"},
    "windows_powershell":{"category": "ps_script",            "product": "windows"},
    # Network
    "firewall":          {"category": "firewall",             "product": None},
    "proxy":             {"category": "proxy",                "product": None},
    "dns":               {"category": "dns",                  "product": None},
    # Cloud
    "aws":               {"service":  "cloudtrail",           "product": "aws"},
    "azure":             {"service":  "activitylogs",         "product": "azure"},
    "azure_ad":          {"service":  "signinlogs",           "product": "azure"},
    "m365":              {"service":  "office365",            "product": "m365"},
    "okta":              {"service":  "okta",                 "product": "okta"},
    # Linux
    "linux":             {"service":  "syslog",               "product": "linux"},
    "linux_auth":        {"service":  "auth",                 "product": "linux"},
}

SEVERITY_MAP = {
    "Critical": "critical",
    "High":     "high",
    "Medium":   "medium",
    "Low":      "low",
}

TACTIC_MAP = {
    "Initial Access":        "initial-access",
    "Execution":             "execution",
    "Persistence":           "persistence",
    "Privilege Escalation":  "privilege-escalation",
    "Defense Evasion":       "defense-evasion",
    "Credential Access":     "credential-access",
    "Discovery":             "discovery",
    "Lateral Movement":      "lateral-movement",
    "Command and Control":   "command-and-control",
    "Collection":            "collection",
    "Exfiltration":          "exfiltration",
    "Impact":                "impact",
    "Reconnaissance":        "reconnaissance",
    "Resource Development":  "resource-development",
}


# ── Log source inference ─────────────────────────────────────────────────────

def infer_logsource(rule: dict) -> dict:
    """Determine Sigma logsource from rule metadata."""
    ds_str = " ".join(str(s).lower() for s in rule.get("data_sources", []))
    log_src = str(rule.get("log_source", "")).lower()
    platforms = [p.lower() for p in rule.get("platform", [])]
    name_l = rule.get("name", "").lower()

    combined = ds_str + " " + log_src

    # Sysmon
    if "sysmon" in combined:
        eid_match = re.search(r'\b(EventCode|Event ID)[:\s]+(\d+)', combined, re.I)
        if eid_match:
            eid = int(eid_match.group(2))
            cat_map = {1:"process_creation",2:"file_change",3:"network_connection",
                       7:"image_load",8:"create_remote_thread",10:"process_access",
                       11:"file_event",13:"registry_set",19:"wmi_event",
                       20:"wmi_event",21:"wmi_event"}
            cat = cat_map.get(eid, "process_creation")
            return {"category": cat, "product": "windows"}
        return {"service": "sysmon", "product": "windows"}

    # Windows Security events
    if any(x in combined for x in ["windows security", "eventcode=4", "event id: 4", "wineventlog:security"]):
        return {"service": "security", "product": "windows"}

    # Windows System events
    if "wineventlog:system" in combined or "event id: 7045" in combined:
        return {"service": "system", "product": "windows"}

    # PowerShell
    if "powershell" in combined:
        return {"category": "ps_script", "product": "windows"}

    # Network/Firewall
    if any(x in combined for x in ["firewall", "palo alto", "cisco", "checkpoint"]):
        return {"category": "firewall"}

    # Proxy
    if any(x in combined for x in ["proxy", "zscaler", "bluecoat", "netskope"]):
        return {"category": "proxy"}

    # DNS
    if "dns" in combined:
        return {"category": "dns"}

    # Azure AD / Entra
    if any(x in combined for x in ["azure ad", "entra", "azure sign"]):
        return {"service": "signinlogs", "product": "azure"}

    # O365 / M365
    if any(x in combined for x in ["office 365", "o365", "sharepoint", "exchange", "m365"]):
        return {"service": "office365", "product": "m365"}

    # AWS
    if any(x in combined for x in ["aws", "cloudtrail"]):
        return {"service": "cloudtrail", "product": "aws"}

    # Okta
    if "okta" in combined:
        return {"service": "okta", "product": "okta"}

    # Linux
    if "linux" in combined or "linux" in platforms:
        return {"service": "syslog", "product": "linux"}

    # Generic Windows fallback
    if "windows" in platforms:
        return {"service": "security", "product": "windows"}

    return {"category": "generic"}


# ── Detection block generation ───────────────────────────────────────────────

def build_detection_from_pseudo(rule: dict) -> dict:
    """
    Build a Sigma detection block from pseudo_logic or rule name patterns.
    Returns a dict suitable for the 'detection:' section.
    """
    name_l = rule.get("name", "").lower()
    pseudo = str(rule.get("pseudo_logic", "") or "").lower()
    eids = re.findall(r'\b(\d{4,5})\b',
                      " ".join(str(s) for s in rule.get("data_sources", [])) + pseudo)
    eids = list(dict.fromkeys(eids))[:6]

    # Build selection criteria from name patterns
    selection = {}

    # Windows event IDs
    if eids:
        selection["EventID"] = [int(e) for e in eids]

    # Pattern-specific conditions
    if "password spray" in name_l or "password guessing" in name_l:
        selection["Keywords"] = ["0xC000006A", "0xC0000064", "0xC000006D"]

    elif "kerberoast" in name_l:
        selection["TicketEncryptionType"] = ["0x17", "0x18"]
        if "EventID" not in selection:
            selection["EventID"] = [4769]

    elif "encoded command" in name_l or "encoded" in name_l and "powershell" in name_l:
        selection["CommandLine|contains"] = ["-EncodedCommand", "-enc ", "-e "]

    elif "mshta" in name_l:
        selection["Image|endswith"] = "\\mshta.exe"
        selection["CommandLine|contains"] = ["http://", "https://", "javascript:", "vbscript:"]

    elif "regsvr32" in name_l and ("remote" in name_l or "scriptlet" in name_l):
        selection["Image|endswith"] = "\\regsvr32.exe"
        selection["CommandLine|contains"] = ["scrobj.dll", "http://", "https://"]

    elif "wscript" in name_l or "cscript" in name_l:
        selection["Image|endswith|any"] = ["\\wscript.exe", "\\cscript.exe"]
        selection["CommandLine|contains"] = ["http://", "https://", "\\\\"]

    elif "shadow copy" in name_l or "vss" in name_l or "vssadmin" in name_l:
        selection["Image|endswith|any"] = ["\\vssadmin.exe", "\\wmic.exe", "\\wbadmin.exe"]
        selection["CommandLine|contains|any"] = ["delete", "shadowcopy"]

    elif "event log" in name_l and "clear" in name_l:
        if "EventID" not in selection:
            selection["EventID"] = [1102, 104]

    elif "lsass" in name_l:
        selection["TargetImage|endswith"] = "\\lsass.exe"
        selection["GrantedAccess|contains|any"] = ["0x1010", "0x1410", "0x1fffff", "0x1438"]

    elif "dcsync" in name_l:
        selection["ObjectClass"] = "domainDNS"
        selection["Properties|contains|any"] = [
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2",
        ]

    elif "masquerad" in name_l:
        selection["Image|contains|any"] = ["\\temp\\", "\\appdata\\"]
        selection["Image|endswith|any"] = [
            "\\svchost.exe", "\\lsass.exe", "\\csrss.exe",
            "\\wininit.exe", "\\smss.exe",
        ]

    elif "wmi" in name_l and "subscription" in name_l:
        selection["EventID"] = [19, 20, 21]

    elif "lateral" in name_l or "psexec" in name_l:
        selection["EventID"] = [7045]
        selection["ServiceName|contains"] = "PSEXESVC"

    elif any(x in name_l for x in ["ransomware", "encrypt"]):
        selection["CommandLine|contains|any"] = [
            "delete shadows", "shadowcopy delete", "resize shadowstorage"
        ]

    elif any(x in name_l for x in ["beaconing", "beacon"]):
        selection["Initiated"] = "true"
        selection["DestinationPort|contains|any"] = ["80", "443", "8080", "8443"]

    # Generic fallback
    if not selection:
        selection["Keywords"] = [rule.get("name", "detection")]

    # Build filter
    filter_block = None
    if any(x in name_l for x in ["lsass", "injection", "remote thread"]):
        filter_block = {
            "Image|startswith|any": [
                "C:\\Windows\\System32\\",
                "C:\\Windows\\SysWOW64\\",
            ]
        }

    detection = {"selection": selection}
    if filter_block:
        detection["filter"] = filter_block
        detection["condition"] = "selection and not filter"
    else:
        detection["condition"] = "selection"

    return detection


# ── Main rule builder ─────────────────────────────────────────────────────────

def to_sigma(rule: dict) -> dict:
    """Convert a TDE/TDL rule dict into a Sigma rule dict."""
    rule_id   = rule.get("rule_id", "")
    tactic    = rule.get("tactic", "")
    tech_id   = rule.get("technique_id", "")

    # Tags
    tags = []
    tactic_slug = TACTIC_MAP.get(tactic, "")
    if tactic_slug:
        tags.append(f"attack.{tactic_slug}")
    if tech_id:
        tid_clean = tech_id.lower().replace(".", "_")
        tags.append(f"attack.{tid_clean}")
    for t in rule.get("tags", []):
        if t and t not in ["low","medium","high","critical"]:
            tags.append(f"detection.{t}")

    sigma = {
        "title":       rule.get("name", ""),
        "id":          rule_id,
        "status":      {"Deployed":"stable","Tested":"test","Proposed":"experimental",
                        "Tuned":"stable"}.get(rule.get("lifecycle","Proposed"), "experimental"),
        "description": str(rule.get("description", "")).strip(),
        "references":  rule.get("references", []),
        "author":      rule.get("author", "TDE"),
        "date":        str(rule.get("created", date.today())),
        "modified":    str(rule.get("last_modified", date.today())),
        "tags":        tags,
        "logsource":   infer_logsource(rule),
        "detection":   build_detection_from_pseudo(rule),
        "falsepositives": rule.get("false_positives", ["Unknown"]),
        "level":       SEVERITY_MAP.get(rule.get("severity", "Medium"), "medium"),
    }

    # Add v4_id as custom field if present
    if rule.get("v4_id"):
        sigma["custom"] = {"v4_id": rule["v4_id"]}

    return sigma


def sigma_to_yaml(sigma_dict: dict) -> str:
    """Serialize Sigma rule to YAML string with Sigma-compatible formatting."""
    # Sigma uses specific field ordering
    ordered = {}
    for key in ["title","id","status","description","references","author",
                "date","modified","tags","logsource","detection",
                "falsepositives","level","custom"]:
        if key in sigma_dict:
            ordered[key] = sigma_dict[key]

    return yaml.dump(ordered, default_flow_style=False, allow_unicode=True,
                     sort_keys=False, width=100)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules",     default="rules")
    parser.add_argument("--output",    default="sigma")
    parser.add_argument("--tactic",    default=None)
    parser.add_argument("--rule-id",   default=None)
    parser.add_argument("--lifecycle", default=None)
    args = parser.parse_args()

    rules = []
    for f in sorted(Path(args.rules).rglob("*.yaml")):
        content = f.read_text()
        for doc in content.split("\n---\n"):
            doc = doc.strip()
            if not doc:
                continue
            try:
                rule = yaml.safe_load(doc)
                if rule and "rule_id" in rule:
                    rules.append(rule)
            except Exception:
                pass

    # Filters
    if args.tactic:
        rules = [r for r in rules
                 if TACTIC_MAP.get(r.get("tactic",""),"") == args.tactic
                 or r.get("tactic","").lower().replace(" ","-") == args.tactic]
    if args.rule_id:
        rules = [r for r in rules if r.get("rule_id") == args.rule_id]
    if args.lifecycle:
        rules = [r for r in rules if r.get("lifecycle") == args.lifecycle]

    print(f"\n  TDE Playbook — Sigma Generator")
    print(f"  Converting {len(rules)} rules...\n")

    converted = 0
    errors = []

    for rule in rules:
        try:
            sigma = to_sigma(rule)
            tactic_slug = TACTIC_MAP.get(rule.get("tactic",""), "uncategorized")
            out_dir = Path(args.output) / tactic_slug
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f"{rule['rule_id']}.yml"
            with open(out_file, "w") as f:
                f.write(sigma_to_yaml(sigma))
            converted += 1
        except Exception as e:
            errors.append(f"  {rule.get('rule_id','?')}: {e}")

    print(f"  ✅ Generated {converted} Sigma rules → {args.output}/")
    if errors:
        print(f"  ❌ {len(errors)} errors:")
        for e in errors[:5]:
            print(e)

    # Count by tactic
    by_tactic = {}
    for f in Path(args.output).rglob("*.yml"):
        tactic = f.parent.name
        by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
    print(f"\n  Sigma rules by tactic:")
    for t, c in sorted(by_tactic.items(), key=lambda x: -x[1]):
        print(f"    {t:<35} {c}")
    print()


if __name__ == "__main__":
    main()
