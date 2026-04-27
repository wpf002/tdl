#!/usr/bin/env python3
"""
TDL Playbook — Multi-SIEM Query Generator
Generates native query language implementations for all major SIEMs.

Supported platforms (v3):
  spl         Splunk Enterprise Security
  kql         Microsoft Sentinel
  aql         IBM QRadar / Palo Alto SIEM
  yara_l      Google Chronicle / Google SecOps
  esql        Elastic Security ES-QL / EQL
  leql        Rapid7 InsightIDR
  crowdstrike CrowdStrike Falcon NG-SIEM
  xql         Palo Alto XSIAM
  lucene      Exabeam / Graylog / OpenSearch

Usage:
  python3 tools/siem_expand.py                    # enrich all rules
  python3 tools/siem_expand.py --rule TDL-CA-001  # single rule
  python3 tools/siem_expand.py --platform aql     # only add AQL
  python3 tools/siem_expand.py --stats            # show coverage stats only
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


class BlockStr(str): pass
def block_str_rep(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
yaml.add_representer(BlockStr, block_str_rep)


# ── Field name mappings across SIEMs ─────────────────────────────────────────
# Each SIEM normalizes field names differently.

FIELD_MAP = {
    # canonical → { siem: field_name }
    "src_ip":       {"aql":"sourceip",   "yara_l":"principal.ip",    "esql":"source.ip",       "leql":"source_ip",      "crowdstrike":"RemoteIP",          "xql":"src_ip",     "lucene":"src_ip"},
    "dest_ip":      {"aql":"destinationip","yara_l":"target.ip",      "esql":"destination.ip",  "leql":"destination_ip", "crowdstrike":"LocalIP",           "xql":"dst_ip",     "lucene":"dst_ip"},
    "user":         {"aql":"username",   "yara_l":"principal.user.userid","esql":"user.name",  "leql":"username",       "crowdstrike":"UserName",          "xql":"actor_effective_username","lucene":"user.name"},
    "host":         {"aql":"hostname",   "yara_l":"principal.hostname","esql":"host.name",      "leql":"hostname",       "crowdstrike":"ComputerName",       "xql":"hostname",   "lucene":"host.name"},
    "process":      {"aql":"filename",   "yara_l":"principal.process.file.full_path","esql":"process.name","leql":"process","crowdstrike":"FileName",    "xql":"process_name","lucene":"process.name"},
    "cmdline":      {"aql":"commandtext","yara_l":"target.process.command_line","esql":"process.command_line","leql":"command","crowdstrike":"CommandLine","xql":"cmd","lucene":"process.command_line"},
    "event_id":     {"aql":"eventid",    "yara_l":"metadata.event_type","esql":"winlog.event_id","leql":"event_id",     "crowdstrike":"EventCode",         "xql":"action_evtlog_event_id","lucene":"event_id"},
}


# ── Helper utilities ──────────────────────────────────────────────────────────

def extract_event_ids(rule: dict) -> list:
    text = " ".join(str(s) for s in rule.get("data_sources", [])) + " " + str(rule.get("pseudo_logic", ""))
    return list(dict.fromkeys(re.findall(r'\b(4\d{3}|7045|1102|104)\b', text)))[:6]

def extract_threshold(rule: dict) -> int:
    logic = str(rule.get("pseudo_logic", "")).strip()
    m = re.search(r'^(\d+)\s+\w', logic)
    return max(int(m.group(1)), 1) if m else 1

def extract_window(rule: dict) -> dict:
    logic = str(rule.get("pseudo_logic", ""))
    m = re.search(r'(\d+)\s*(minute|min|hour|second)', logic, re.I)
    if m:
        n, unit = int(m.group(1)), m.group(2).lower()
        if 'hour' in unit: return {"secs": n*3600, "spl": f"{n}h", "kql": f"{n}h", "aql": f"{n*3600}", "esql": f"{n}h"}
        if 'second' in unit: return {"secs": n, "spl": f"{n}s", "kql": f"{n}s", "aql": str(n), "esql": f"{n}s"}
        return {"secs": n*60, "spl": f"{n}m", "kql": f"{n}m", "aql": str(n*60), "esql": f"{n}m"}
    return {"secs": 300, "spl": "5m", "kql": "5m", "aql": "300", "esql": "5m"}

def get_log_src(rule: dict) -> str:
    return " ".join(str(s) for s in rule.get("data_sources", [])).lower() + " " + " ".join(rule.get("platform", [])).lower()

def is_windows(rule: dict) -> bool:
    return "windows" in " ".join(rule.get("platform", [])).lower()

def is_network(rule: dict) -> bool:
    src = get_log_src(rule)
    return any(x in src for x in ["firewall","proxy","network","dns","netflow"])

def is_cloud(rule: dict) -> bool:
    src = get_log_src(rule)
    return any(x in src for x in ["aws","azure","gcp","okta","office 365","m365","sharepoint"])


# ── AQL (IBM QRadar / Palo Alto SIEM) ────────────────────────────────────────
# SQL-like syntax: SELECT ... FROM events/flows WHERE ... GROUP BY ... ORDER BY ...

def build_aql(rule: dict) -> str:
    name_l = rule.get("name", "").lower()
    eids = extract_event_ids(rule)
    thresh = extract_threshold(rule)
    window = extract_window(rule)
    src = get_log_src(rule)

    # Base table selection
    if is_network(rule):
        table = "flows"
        fields = "sourceip, destinationip, destinationport, SUM(flowCount) AS total_flows"
        group_by = "GROUP BY sourceip, destinationip, destinationport"
    else:
        table = "events"
        fields = "LOGSOURCENAME(logsourceid) AS log_source, username, hostname, QIDNAME(qid) AS event_name, eventcount"
        group_by = "GROUP BY username, hostname, QIDNAME(qid)"

    where_parts = []

    if eids:
        if len(eids) == 1:
            where_parts.append(f"eventid = {eids[0]}")
        else:
            where_parts.append(f"eventid IN ({', '.join(eids)})")

    # Pattern-specific logic
    if "password spray" in name_l or "brute force" in name_l:
        t = max(thresh, 10)
        return f"""SELECT username, sourceip, COUNT(*) AS failure_count, UNIQUECOUNT(username) AS unique_accounts
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Windows%'
  AND eventid IN (4625, 529, 4776)
  AND INOFFSET(starttime, LAST {window['aql']} SECONDS)
GROUP BY sourceip
HAVING unique_accounts >= 10 AND (failure_count / unique_accounts) <= 3
ORDER BY failure_count DESC
START '{str(date.today())} 00:00:00'"""

    elif "kerberoast" in name_l:
        return f"""SELECT username AS requesting_user, QIDNAME(qid) AS event_name,
       hostname AS destination, UNIQUECOUNT(hostname) AS unique_spns
FROM events
WHERE eventid = 4769
  AND LOGSOURCETYPENAME(devicetype) ILIKE '%Windows%'
  AND "Ticket Encryption Type" IN ('0x17', '0x18')
  AND username NOT LIKE '%$'
  AND INOFFSET(starttime, LAST {window['aql']} SECONDS)
GROUP BY username
HAVING unique_spns >= 5
ORDER BY unique_spns DESC"""

    elif "lsass" in name_l:
        return f"""SELECT sourceaddress AS source_host, username, QIDNAME(qid) AS event_name,
       "Process Name" AS accessing_process, "Granted Access" AS access_mask
FROM events
WHERE eventid = 10
  AND "Target Image" ILIKE '%lsass.exe%'
  AND "Granted Access" IN ('0x1010','0x1410','0x1fffff','0x147a')
  AND "Source Image" NOT ILIKE '%\\Windows\\System32\\%'
  AND INOFFSET(starttime, LAST 3600 SECONDS)
ORDER BY starttime DESC"""

    elif "dcsync" in name_l:
        return f"""SELECT username AS subject_user, hostname AS dc_name, QIDNAME(qid) AS event_name,
       "Object Properties" AS properties
FROM events
WHERE eventid = 4662
  AND "Object Properties" ILIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%'
     OR "Object Properties" ILIKE '%1131f6ab-9c07-11d1-f79f-00c04fc2dcd2%'
  AND username NOT LIKE '%$'
  AND INOFFSET(starttime, LAST 86400 SECONDS)
ORDER BY starttime DESC"""

    elif "log" in name_l and "clear" in name_l:
        return f"""SELECT username, hostname, QIDNAME(qid) AS event_name, eventid
FROM events
WHERE eventid IN (1102, 104)
  AND INOFFSET(starttime, LAST 86400 SECONDS)
ORDER BY starttime DESC"""

    elif "shadow copy" in name_l or "vss" in name_l:
        return f"""SELECT username, hostname, "Process Name" AS process, "Command Line" AS cmdline
FROM events
WHERE ("Process Name" ILIKE '%vssadmin.exe%' AND "Command Line" ILIKE '%delete%')
   OR ("Process Name" ILIKE '%wmic.exe%' AND "Command Line" ILIKE '%shadowcopy%delete%')
  AND INOFFSET(starttime, LAST 86400 SECONDS)
ORDER BY starttime DESC"""

    elif "port scan" in name_l or "smb scan" in name_l:
        return f"""SELECT sourceip, COUNT(DISTINCT destinationport) AS unique_ports,
       COUNT(DISTINCT destinationip) AS unique_hosts, COUNT(*) AS total_conns
FROM flows
WHERE INOFFSET(starttime, LAST 300 SECONDS)
GROUP BY sourceip
HAVING unique_ports >= 20 OR unique_hosts >= 30
ORDER BY unique_ports DESC"""

    # Generic pattern with where conditions
    if where_parts:
        where_clause = " AND ".join(where_parts)
        agg = f"COUNT(*) AS event_count" if thresh > 1 else "eventcount"
        having = f"HAVING event_count >= {thresh}" if thresh > 1 else ""
        return f"""SELECT {fields}
FROM {table}
WHERE {where_clause}
  AND INOFFSET(starttime, LAST {window['aql']} SECONDS)
{group_by}
{having}
ORDER BY starttime DESC""".strip()

    return f"""SELECT {fields}
FROM {table}
WHERE INOFFSET(starttime, LAST {window['aql']} SECONDS)
{group_by}
ORDER BY starttime DESC"""


# ── YARA-L 2.0 (Google Chronicle / SecOps) ────────────────────────────────────
# Declarative rule format with events block, match block, condition block

def build_yara_l(rule: dict) -> str:
    name_l = rule.get("name", "").lower()
    rule_id = rule.get("rule_id", "RULE_001").replace("-","_").lower()
    tech_id = rule.get("technique_id", "T1078").replace(".", "_").lower()
    tactic = rule.get("tactic", "").lower().replace(" ", "_")
    eids = extract_event_ids(rule)
    thresh = extract_threshold(rule)
    window = extract_window(rule)
    sev = rule.get("severity", "Medium").upper()

    # YARA-L uses a specific structure
    if "password spray" in name_l or "brute force" in name_l:
        return f"""rule {rule_id} {{
  meta:
    author = "TDL"
    description = "{rule.get('name','')}"
    severity = "{sev}"
    tactic = "TA0006"
    technique = "{rule.get('technique_id','T1110')}"

  events:
    $login.metadata.event_type = "USER_LOGIN"
    $login.metadata.product_name = "Windows"
    $login.security_result.action = "BLOCK"
    $login.principal.ip = $src_ip
    $login.target.user.userid = $user

  match:
    $src_ip over {window['spl']}

  condition:
    #login > 10 and
    #user > 8

  outcome:
    $risk_score = max(50)
}}"""

    elif "kerberoast" in name_l:
        return f"""rule {rule_id} {{
  meta:
    author = "TDL"
    description = "{rule.get('name','')}"
    severity = "{sev}"
    tactic = "TA0006"
    technique = "T1558.003"

  events:
    $kerberos.metadata.event_type = "USER_RESOURCE_ACCESS"
    $kerberos.metadata.product_event_type = "4769"
    $kerberos.additional.fields["TicketEncryptionType"] = /0x17|0x18/
    $kerberos.principal.user.userid != /\$$/
    $kerberos.target.resource.name != "krbtgt"
    $kerberos.principal.user.userid = $user
    $kerberos.target.resource.name = $spn

  match:
    $user over 10m

  condition:
    #spn >= 5

  outcome:
    $risk_score = max(75)
}}"""

    elif "lsass" in name_l:
        return f"""rule {rule_id} {{
  meta:
    author = "TDL"
    description = "{rule.get('name','')}"
    severity = "{sev}"
    tactic = "TA0006"
    technique = "T1003.001"

  events:
    $proc_access.metadata.event_type = "PROCESS_OPEN"
    $proc_access.target.process.file.full_path = /lsass\.exe$/
    $proc_access.additional.fields["GrantedAccess"] = /0x1010|0x1410|0x1fffff/
    $proc_access.principal.process.file.full_path != /Windows\\\\System32/
    $proc_access.principal.hostname = $host

  match:
    $host over 5m

  condition:
    #proc_access >= 1

  outcome:
    $risk_score = max(95)
}}"""

    elif "log" in name_l and "clear" in name_l:
        return f"""rule {rule_id} {{
  meta:
    author = "TDL"
    description = "{rule.get('name','')}"
    severity = "{sev}"
    tactic = "TA0005"
    technique = "T1070.001"

  events:
    $log_clear.metadata.event_type = "SYSTEM_AUDIT_LOG_WIPE"
    ($log_clear.metadata.product_event_type = "1102" or
     $log_clear.metadata.product_event_type = "104")
    $log_clear.principal.hostname = $host

  match:
    $host over 24h

  condition:
    #log_clear >= 1

  outcome:
    $risk_score = max(90)
}}"""

    elif "shadow copy" in name_l or "vss" in name_l:
        return f"""rule {rule_id} {{
  meta:
    author = "TDL"
    description = "{rule.get('name','')}"
    severity = "CRITICAL"
    tactic = "TA0040"
    technique = "T1490"

  events:
    $proc.metadata.event_type = "PROCESS_LAUNCH"
    ($proc.target.process.file.full_path = /vssadmin\.exe$/
     and $proc.target.process.command_line = /delete/i)
    or
    ($proc.target.process.file.full_path = /wmic\.exe$/
     and $proc.target.process.command_line = /shadowcopy.*delete/i)
    $proc.principal.hostname = $host

  match:
    $host over 1h

  condition:
    #proc >= 1

  outcome:
    $risk_score = max(100)
}}"""

    elif "beaconing" in name_l or "beacon" in name_l:
        return f"""rule {rule_id} {{
  meta:
    author = "TDL"
    description = "{rule.get('name','')}"
    severity = "{sev}"
    tactic = "TA0011"
    technique = "T1071.001"

  events:
    $network.metadata.event_type = "NETWORK_CONNECTION"
    $network.security_result.action = "ALLOW"
    $network.principal.ip = $src_ip
    $network.target.hostname = $dest_host
    $network.network.sent_bytes < 5000

  match:
    $src_ip, $dest_host over 1h

  condition:
    #network >= 10 and
    math.stddev(timestamp.seconds, $network) < 300

  outcome:
    $risk_score = max(75)
}}"""

    # Generic rule
    eid_filter = ""
    if eids:
        eid_filter = f'\n    $event.metadata.product_event_type = "{eids[0]}"'

    return f"""rule {rule_id} {{
  meta:
    author = "TDL"
    description = "{rule.get('name','')}"
    severity = "{sev}"
    tactic = "{rule.get('tactic_id','TA0001')}"
    technique = "{rule.get('technique_id','T1078')}"

  events:
    $event.metadata.event_type = "GENERIC_EVENT"{eid_filter}
    $event.principal.hostname = $host
    $event.principal.user.userid = $user

  match:
    $host over {window['spl']}

  condition:
    #event >= {max(thresh, 1)}

  outcome:
    $risk_score = max(50)
}}"""


# ── ES-QL (Elastic Security) ─────────────────────────────────────────────────
# Pipe-based query language, similar to SPL but with different syntax

def build_esql(rule: dict) -> str:
    name_l = rule.get("name", "").lower()
    eids = extract_event_ids(rule)
    thresh = extract_threshold(rule)
    window = extract_window(rule)
    src = get_log_src(rule)

    if "azure" in src or "office 365" in src or "m365" in src:
        index = "logs-azure*,logs-o365*"
    elif "aws" in src or "cloudtrail" in src:
        index = "logs-aws.cloudtrail*"
    elif any(x in src for x in ["firewall","network","proxy"]):
        index = "logs-network*,logs-firewall*"
    elif "linux" in src:
        index = "logs-system.syslog*,logs-auditd*"
    else:
        index = "logs-windows.sysmon_operational*,logs-system.security*"

    if "password spray" in name_l or "brute force" in name_l:
        t = max(thresh, 10)
        return f"""FROM {index}
| WHERE @timestamp > NOW() - 1 day
| WHERE event.code IN ("4625", "529")
| STATS failure_count = COUNT(*), unique_accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName) BY source.ip, @timestamp = BUCKET(@timestamp, {window['esql']})
| WHERE unique_accounts >= 10
| EVAL ratio = failure_count / unique_accounts
| WHERE ratio <= 3
| SORT failure_count DESC"""

    elif "kerberoast" in name_l:
        return f"""FROM {index}
| WHERE @timestamp > NOW() - 1 day
| WHERE event.code == "4769"
| WHERE winlog.event_data.TicketEncryptionType IN ("0x17", "0x18")
| WHERE NOT winlog.event_data.ServiceName LIKE "*$"
| WHERE winlog.event_data.ServiceName != "krbtgt"
| STATS unique_spns = COUNT_DISTINCT(winlog.event_data.ServiceName), spns = VALUES(winlog.event_data.ServiceName) BY winlog.event_data.SubjectUserName, source.ip, @timestamp = BUCKET(@timestamp, 10 minutes)
| WHERE unique_spns >= 5
| SORT unique_spns DESC"""

    elif "lsass" in name_l:
        return f"""FROM logs-windows.sysmon_operational*
| WHERE @timestamp > NOW() - 1 day
| WHERE event.code == "10"
| WHERE winlog.event_data.TargetImage LIKE "*\\\\lsass.exe"
| WHERE winlog.event_data.GrantedAccess IN ("0x1010","0x1410","0x1fffff","0x147a")
| WHERE NOT winlog.event_data.SourceImage LIKE "*\\\\Windows\\\\System32\\\\*"
| KEEP host.name, winlog.event_data.SourceImage, winlog.event_data.GrantedAccess, winlog.event_data.CallTrace, @timestamp
| SORT @timestamp DESC"""

    elif "log" in name_l and "clear" in name_l:
        return f"""FROM logs-system.security*,logs-system.system*
| WHERE @timestamp > NOW() - 1 day
| WHERE event.code IN ("1102", "104")
| KEEP host.name, winlog.event_data.SubjectUserName, event.code, @timestamp
| SORT @timestamp DESC"""

    elif "shadow copy" in name_l or "vss" in name_l:
        return f"""FROM logs-windows.sysmon_operational*,logs-system.security*
| WHERE @timestamp > NOW() - 1 day
| WHERE event.code == "4688"
| WHERE (process.name LIKE "*vssadmin.exe" AND process.command_line LIKE "*delete*")
     OR (process.name LIKE "*wmic.exe" AND process.command_line RLIKE "(?i)shadowcopy.*delete")
| KEEP host.name, user.name, process.name, process.command_line, @timestamp
| SORT @timestamp DESC"""

    elif "port scan" in name_l or "smb scan" in name_l:
        return f"""FROM logs-network*,logs-firewall*
| WHERE @timestamp > NOW() - 1 hour
| STATS unique_ports = COUNT_DISTINCT(destination.port), unique_hosts = COUNT_DISTINCT(destination.ip), total = COUNT(*) BY source.ip, @timestamp = BUCKET(@timestamp, 5 minutes)
| WHERE unique_ports >= 20 OR unique_hosts >= 30
| SORT unique_ports DESC"""

    elif "beaconing" in name_l:
        return f"""FROM logs-network*,logs-proxy*
| WHERE @timestamp > NOW() - 1 day
| WHERE event.type == "allowed"
| STATS request_count = COUNT(*), avg_bytes = AVG(destination.bytes), std_time = STD_DEV(TO_LONG(@timestamp)) BY source.ip, destination.domain, @timestamp = BUCKET(@timestamp, 1 hour)
| WHERE request_count >= 10 AND avg_bytes < 5000
| SORT request_count DESC"""

    # Generic with event IDs
    if eids and not is_network(rule):
        eid_filter = f'\n| WHERE event.code IN ({", ".join(repr(e) for e in eids)})'
        return f"""FROM {index}
| WHERE @timestamp > NOW() - 1 day{eid_filter}
| STATS event_count = COUNT(*) BY host.name, user.name, event.code, @timestamp = BUCKET(@timestamp, {window['esql']})
| WHERE event_count >= {max(thresh,1)}
| SORT event_count DESC"""

    return f"""FROM {index}
| WHERE @timestamp > NOW() - 1 day
| STATS event_count = COUNT(*) BY host.name, user.name, @timestamp = BUCKET(@timestamp, {window['esql']})
| WHERE event_count >= {max(thresh,1)}
| SORT @timestamp DESC"""


# ── LEQL (Rapid7 InsightIDR) ─────────────────────────────────────────────────
# SQL-style: where(), groupby(), calculate()

def build_leql(rule: dict) -> str:
    name_l = rule.get("name", "").lower()
    eids = extract_event_ids(rule)
    thresh = extract_threshold(rule)
    window = extract_window(rule)

    if "password spray" in name_l or "brute force" in name_l:
        t = max(thresh, 10)
        return f"""where(event_id IN [4625, 529] AND logset = "Active Directory")
groupby(source_ip)
calculate(unique_count:destination_account AS unique_accounts)
calculate(count AS total_failures)
having(unique_accounts >= 10)
having(total_failures / unique_accounts <= 3)"""

    elif "kerberoast" in name_l:
        return f"""where(event_id = 4769 AND ticket_encryption_type IN ["0x17", "0x18"]
  AND NOT destination_account ENDS WITH "$"
  AND NOT destination_account = "krbtgt")
groupby(source_account, source_ip)
calculate(unique_count:destination_account AS spn_count)
having(spn_count >= 5)"""

    elif "lsass" in name_l:
        return f"""where(source_name = "Microsoft-Windows-Sysmon"
  AND event_id = 10
  AND target_image CONTAINS "lsass.exe"
  AND granted_access IN ["0x1010","0x1410","0x1fffff"]
  AND NOT source_image CONTAINS "Windows\\System32")
calculate(count AS total)
having(total >= 1)"""

    elif "log" in name_l and "clear" in name_l:
        return f"""where(event_id IN [1102, 104])
groupby(hostname)
calculate(count AS clear_count)"""

    elif "shadow copy" in name_l or "vss" in name_l:
        return f"""where((process CONTAINS "vssadmin.exe" AND command CONTAINS "delete")
  OR (process CONTAINS "wmic.exe" AND command CONTAINS "shadowcopy"))
groupby(hostname, username)
calculate(count AS vss_deletions)"""

    elif "port scan" in name_l or "network scan" in name_l:
        return f"""where(logset = "Firewall Activity")
groupby(source_ip)
calculate(unique_count:destination_port AS unique_ports)
calculate(unique_count:destination_ip AS unique_hosts)
having(unique_ports >= 20 OR unique_hosts >= 30)"""

    elif eids:
        eid_str = ", ".join(eids)
        base = f"where(event_id IN [{eid_str}])"
        if thresh > 1:
            return f"""{base}
groupby(source_ip, username, hostname)
calculate(count AS event_count)
having(event_count >= {thresh})"""
        return f"""{base}
groupby(hostname, username)
calculate(count AS event_count)"""

    return f"""where(logset = "Endpoint Activity")
groupby(hostname, username)
calculate(count AS event_count)
having(event_count >= {max(thresh,1)})"""


# ── CrowdStrike Falcon NG-SIEM (Event Search / CQL) ──────────────────────────

def build_crowdstrike(rule: dict) -> str:
    name_l = rule.get("name", "").lower()
    eids = extract_event_ids(rule)
    thresh = extract_threshold(rule)
    window = extract_window(rule)

    if "password spray" in name_l or "brute force" in name_l:
        t = max(thresh, 10)
        return f"""event_simpleName=UserLogonFailed2
| stats count(TargetUserName) as failures, dc(TargetUserName) as unique_accounts by RemoteIP
| where unique_accounts >= 10 AND failures/unique_accounts <= 3
| sort -unique_accounts"""

    elif "kerberoast" in name_l:
        return f"""event_simpleName=KerberosServiceTicketGrantedFailed OR event_simpleName=KerberosServiceTicketGranted
| where TicketEncryptionType IN ("0x17", "0x18") AND ServiceName != "krbtgt" AND ServiceName!="*$"
| stats dc(ServiceName) as spn_count, values(ServiceName) as spns by aid, UserName
| where spn_count >= 5"""

    elif "lsass" in name_l:
        return f"""event_simpleName=ProcessRollup2
| where TargetProcessName MATCHES "(?i)lsass.exe"
| where DesiredAccess IN ("0x1010","0x1410","0x1fffff")
| where FileName NOT MATCHES "(?i)C:\\\\Windows\\\\System32"
| table ComputerName, FileName, TargetProcessName, DesiredAccess, CommandLine, ContextTimeStamp"""

    elif "log" in name_l and "clear" in name_l:
        return f"""event_simpleName=SecurityLogCleared OR event_simpleName=EventLogCleared
| table ComputerName, UserName, EventCode, ContextTimeStamp
| sort -ContextTimeStamp"""

    elif "shadow copy" in name_l or "vss" in name_l:
        return f"""event_simpleName=ProcessRollup2
| where (FileName MATCHES "(?i)vssadmin.exe" AND CommandLine MATCHES "(?i)delete")
    OR (FileName MATCHES "(?i)wmic.exe" AND CommandLine MATCHES "(?i)shadowcopy.*delete")
| table ComputerName, UserName, FileName, CommandLine, ContextTimeStamp"""

    elif "lateral movement" in name_l or "pass-the-hash" in name_l or "psexec" in name_l:
        return f"""event_simpleName=UserLogon
| where LogonType = 3 AND AuthenticationPackage = "NTLM" AND UserName!="*$"
| stats dc(RemoteIP) as src_count by UserName, aid
| where src_count >= 3"""

    elif "ransomware" in name_l or "mass file" in name_l:
        return f"""event_simpleName=BootstrapProcess OR event_simpleName=SuspiciousFilesWithOperation
| where FileOperation IN ("WRITE","RENAME","DELETE")
| stats count(FileName) as file_count, dc(FileExtension) as ext_count by ComputerName, FileName_parent
| where file_count >= 50 AND ext_count >= 3
| sort -file_count"""

    elif eids:
        eid_str = " OR ".join(f"EventCode={e}" for e in eids[:4])
        base = f"""event_simpleName=SecurityEvent
| where {eid_str}"""
        if thresh > 1:
            return f"""{base}
| stats count as events by ComputerName, UserName
| where events >= {thresh}"""
        return f"""{base}
| table ComputerName, UserName, CommandLine, ContextTimeStamp"""

    return f"""event_simpleName=ProcessRollup2
| stats count as proc_count by ComputerName, FileName
| where proc_count >= {max(thresh,1)}
| sort -proc_count"""


# ── Palo Alto XSIAM XQL ────────────────────────────────────────────────────────
# XQL: dataset-based with filter, fields, aggregate

def build_xql(rule: dict) -> str:
    name_l = rule.get("name", "").lower()
    eids = extract_event_ids(rule)
    thresh = extract_threshold(rule)
    window = extract_window(rule)
    src = get_log_src(rule)

    if is_network(rule):
        dataset = "xdr_data"
        ds_filter = 'event_type = "NETWORK"'
    elif "aws" in src or "azure" in src:
        dataset = "cloud_audit_log"
        ds_filter = 'event_type = "CLOUD"'
    else:
        dataset = "xdr_data"
        ds_filter = 'event_type = "PROCESS"'

    if "password spray" in name_l or "brute force" in name_l:
        t = max(thresh, 10)
        return f"""dataset = {dataset}
| filter {ds_filter} and action_evtlog_event_id = 4625
| filter _time > to_timestamp(now() - 86400, "epoch")
| comp count() as failure_count, dc(actor_effective_username) as unique_accounts by src_ip
| filter unique_accounts >= 10
| fields src_ip, failure_count, unique_accounts"""

    elif "kerberoast" in name_l:
        return f"""dataset = {dataset}
| filter event_type = "NETWORK" and actor_process_image_name contains "lsass.exe"
| filter action_evtlog_event_id = 4769
| filter actor_process_command_line contains "0x17" or actor_process_command_line contains "0x18"
| comp dc(action_network_remote_port) as spn_count by actor_effective_username, src_ip
| filter spn_count >= 5"""

    elif "lsass" in name_l:
        return f"""dataset = {dataset}
| filter event_type = "INJECTION"
| filter action_remote_process_image_path contains "lsass.exe"
| filter actor_process_image_path not contains "C:\\Windows\\System32"
| fields hostname, actor_process_image_name, action_remote_process_image_path, actor_effective_username, _time
| sort desc _time"""

    elif "log" in name_l and "clear" in name_l:
        return f"""dataset = {dataset}
| filter action_evtlog_event_id in (1102, 104)
| fields hostname, actor_effective_username, action_evtlog_event_id, _time
| sort desc _time"""

    elif "shadow copy" in name_l or "vss" in name_l:
        return f"""dataset = {dataset}
| filter event_type = "PROCESS"
| filter (action_process_image_name ~= "vssadmin.exe" and action_process_command_line contains "delete")
       or (action_process_image_name ~= "wmic.exe" and action_process_command_line ~= "(?i)shadowcopy.*delete")
| fields hostname, actor_effective_username, action_process_image_name, action_process_command_line, _time"""

    elif eids:
        eid_filter = f"and action_evtlog_event_id in ({', '.join(eids[:4])})"
    else:
        eid_filter = ""

    if thresh > 1:
        return f"""dataset = {dataset}
| filter {ds_filter} {eid_filter}
| filter _time > to_timestamp(now() - 86400, "epoch")
| comp count() as event_count by hostname, actor_effective_username
| filter event_count >= {thresh}
| fields hostname, actor_effective_username, event_count"""

    return f"""dataset = {dataset}
| filter {ds_filter} {eid_filter}
| filter _time > to_timestamp(now() - 86400, "epoch")
| fields hostname, actor_effective_username, action_process_image_name, action_process_command_line, _time
| sort desc _time"""


# ── Lucene DSL (Exabeam / Graylog / OpenSearch) ────────────────────────────────

def build_lucene(rule: dict) -> str:
    name_l = rule.get("name", "").lower()
    eids = extract_event_ids(rule)
    thresh = extract_threshold(rule)

    if "password spray" in name_l or "brute force" in name_l:
        return """event_id:(4625 OR 529) AND log_source_type:"Windows Security"
AND NOT user_name:("ANONYMOUS LOGON" OR "*$")"""

    elif "kerberoast" in name_l:
        return """event_id:4769 AND ticket_encryption_type:(0x17 OR 0x18)
AND NOT service_name:krbtgt AND NOT service_name:*$"""

    elif "lsass" in name_l:
        return """event_id:10 AND target_image:*lsass.exe
AND granted_access:(0x1010 OR 0x1410 OR 0x1fffff)
AND NOT source_image:*Windows\\System32*"""

    elif "log" in name_l and "clear" in name_l:
        return "event_id:(1102 OR 104)"

    elif "shadow copy" in name_l or "vss" in name_l:
        return """(process:vssadmin.exe AND command_line:*delete*)
OR (process:wmic.exe AND command_line:*shadowcopy*delete*)"""

    elif "port scan" in name_l:
        return """log_type:"firewall" AND NOT destination_ip:"10.0.0.0/8"
AND NOT destination_ip:"172.16.0.0/12"
AND NOT destination_ip:"192.168.0.0/16" """

    elif "ransomware" in name_l or "mass file" in name_l:
        return """source_name:Microsoft-Windows-Sysmon AND event_id:11
AND NOT file_extension:(tmp OR log OR ini)"""

    elif eids:
        eid_part = " OR ".join(eids)
        return f"event_id:({eid_part})"

    return """event_id:* AND log_type:"security" """


# ── Main enrichment loop ──────────────────────────────────────────────────────

BUILDERS = {
    "aql":         build_aql,
    "yara_l":      build_yara_l,
    "esql":        build_esql,
    "leql":        build_leql,
    "crowdstrike": build_crowdstrike,
    "xql":         build_xql,
    "lucene":      build_lucene,
}


def load_rules(rules_dir: str) -> list:
    result = []
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
                    result.append(rule)
            except Exception:
                pass
    return result


def save_rule(rule: dict):
    filepath = rule.pop("_file")
    rule["last_modified"] = str(date.today())
    with open(filepath, "w") as f:
        yaml.dump(rule, f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=120)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules",    default="rules")
    parser.add_argument("--rule",     default=None, help="Single rule ID to process")
    parser.add_argument("--platform", default=None, help="Only generate this platform: aql|yara_l|esql|leql|crowdstrike|xql|lucene")
    parser.add_argument("--stats",    action="store_true")
    parser.add_argument("--force",    action="store_true", help="Overwrite existing queries")
    args = parser.parse_args()

    rules = load_rules(args.rules)

    if args.rule:
        rules = [r for r in rules if r.get("rule_id") == args.rule]
        if not rules:
            print(f"Rule {args.rule} not found"); return

    platforms = [args.platform] if args.platform else list(BUILDERS.keys())

    if args.stats:
        print(f"\n{'SIEM Platform':<20} {'Coverage':>10}  {'%':>5}")
        print("-"*40)
        total = len(rules)
        for plat in ["spl","kql","aql","yara_l","esql","leql","crowdstrike","xql","lucene"]:
            have = sum(1 for r in rules if r.get("queries",{}).get(plat))
            pct = round(have/total*100) if total else 0
            bar = "█" * (pct//5) + "░" * (20-pct//5)
            print(f"  {plat:<18} {have:>8}/{total}  {bar} {pct}%")
        return

    enriched = 0
    print(f"\n  TDL Playbook — Multi-SIEM Query Generator")
    print(f"  Enriching {len(rules)} rules with: {', '.join(platforms)}\n")

    for rule in rules:
        changed = False
        queries = rule.setdefault("queries", {})

        for plat in platforms:
            if not args.force and queries.get(plat):
                continue
            try:
                q = BUILDERS[plat](rule)
                if q:
                    queries[plat] = BlockStr(q.strip())
                    changed = True
            except Exception as e:
                pass

        if changed:
            rule["queries"] = queries
            save_rule(rule)
            enriched += 1

    print(f"  ✅ Enriched {enriched} rules")
    print(f"\n  Run --stats to see updated coverage\n")


if __name__ == "__main__":
    main()
