#!/usr/bin/env python3
"""Canonical event catalog for every log source, and rule→requirements mapping.

The heuristic requirements backfill only knew Windows + Sysmon numeric event IDs
and dumped them all under a rule's first data_source — so EDR/IdP/DNS/M365/etc.
showed Sysmon events or nothing. This module gives each log source its OWN real
events (the "unique events per log source"), and attributes a rule's events to
the *correct* source by keyword.

Shape per source: {canonical_id: {"source": <display string that matchLogSourceId
maps back to this id>, "events": [{"id","name","keywords":[...]}]}}.

Event ids are numeric for Windows/Sysmon and short slugs (operations / table /
event-type names) for the rest — the UI treats id as an opaque string.
"""

from __future__ import annotations

import re

# Keyword → canonical log-source id. Matched with word boundaries against a
# rule's data_sources + platform + pseudo_logic. Ambiguous short substrings
# (ids/ips/root/box/ping…) are deliberately avoided to prevent false matches
# (e.g. "Event IDs:" must not match a firewall).
LOG_SOURCE_KEYWORDS = {
    "sysmon": ["sysmon"],
    "windows_security_events": ["windows security", "wineventlog", "security event",
                                 "windows event", "active directory", "windows operating system",
                                 "domain controller", "windows"],
    "edr": ["edr", "crowdstrike", "sentinelone", "defender for endpoint", "mde",
            "endpoint detection", "carbon black", "cortex xdr", "falcon"],
    "dns": ["dns"],
    "firewall": ["firewall", "palo alto", "fortinet", "pfsense", "network perimeter",
                 "intrusion detection", "intrusion prevention", "ids/ips", "netflow"],
    "identity_provider": ["okta", "azure ad", "entra", "identity provider", "idp",
                          "onelogin", "saml", "single sign-on", "sso"],
    "proxy": ["proxy", "web gateway", "swg", "zscaler", "squid"],
    "email_security": ["email", "proofpoint", "mimecast", "defender for office", "exchange online protection"],
    "cloud": ["cloudtrail", "aws", "azure activity", "azure audit", "gcp audit",
              "cloud audit", "cloud infrastructure", "guardduty"],
    "m365": ["microsoft 365", "m365", "office 365", "o365", "unified audit", "exchange online", "sharepoint"],
    "linux": ["linux", "auditd", "syslog", "/var/log"],
    "vpn": ["vpn", "remote access", "anyconnect", "globalprotect"],
    "dlp": ["dlp", "data loss"],
    "waf": ["waf", "web application firewall", "modsecurity"],
    "saas": ["saas", "salesforce", "slack", "github", "google workspace", "workday"],
    "kubernetes": ["kubernetes", "k8s", "container", "eks", "gke", "aks"],
    "mfa": ["multi-factor", "multifactor", "okta verify", "authenticator app"],
}


def _kw_hit(kw: str, text: str) -> bool:
    """Word-boundary keyword match (so 'ids' doesn't match 'Event IDs')."""
    return re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", text) is not None

# The unique events for each log source. `keywords` decide whether a given rule
# references that event.
LOG_SOURCE_EVENTS = {
    "windows_security_events": {"source": "Windows Security Event Log", "events": [
        {"id": "4624", "name": "Successful logon", "keywords": ["logon", "4624", "sign-in", "authenticat"]},
        {"id": "4625", "name": "Failed logon", "keywords": ["failed logon", "4625", "failed auth", "brute"]},
        {"id": "4634", "name": "Logoff", "keywords": ["logoff", "4634"]},
        {"id": "4648", "name": "Explicit credential use", "keywords": ["explicit cred", "runas", "4648"]},
        {"id": "4672", "name": "Special privileges assigned", "keywords": ["special privilege", "4672", "admin logon"]},
        {"id": "4688", "name": "Process creation", "keywords": ["process creation", "process create", "4688", "command line"]},
        {"id": "4697", "name": "Service installed", "keywords": ["service install", "4697", "7045", "new service"]},
        {"id": "4698", "name": "Scheduled task created", "keywords": ["scheduled task", "4698", "schtasks"]},
        {"id": "4720", "name": "User account created", "keywords": ["account created", "4720", "user created"]},
        {"id": "4728", "name": "Member added to group", "keywords": ["added to group", "4728", "4732", "group member", "privileged group"]},
        {"id": "4738", "name": "User account changed", "keywords": ["account changed", "4738", "account modif"]},
        {"id": "4740", "name": "Account lockout", "keywords": ["lockout", "locked out", "4740"]},
        {"id": "4768", "name": "Kerberos TGT requested", "keywords": ["kerberos", "tgt", "4768", "asrep"]},
        {"id": "4769", "name": "Kerberos service ticket", "keywords": ["kerberoast", "service ticket", "4769", "spn"]},
        {"id": "4776", "name": "NTLM authentication", "keywords": ["ntlm", "4776"]},
        {"id": "1102", "name": "Security log cleared", "keywords": ["log cleared", "1102", "clear log", "wevtutil"]},
        {"id": "4104", "name": "PowerShell script block", "keywords": ["powershell", "script block", "4104", "4103"]},
        {"id": "5140", "name": "Network share accessed", "keywords": ["network share", "5140", "5145", "admin share"]},
    ]},
    "sysmon": {"source": "Sysmon", "events": [
        {"id": "1", "name": "Process creation", "keywords": ["process creation", "process create", "command line", "parent process"]},
        {"id": "2", "name": "File creation time changed", "keywords": ["timestomp", "file creation time"]},
        {"id": "3", "name": "Network connection", "keywords": ["network connection", "outbound", "c2", "beacon"]},
        {"id": "7", "name": "Image/DLL loaded", "keywords": ["image load", "dll load", "module load", "unsigned dll"]},
        {"id": "8", "name": "CreateRemoteThread", "keywords": ["remote thread", "injection", "createremotethread"]},
        {"id": "10", "name": "Process access (LSASS)", "keywords": ["lsass", "process access", "credential dump", "minidump"]},
        {"id": "11", "name": "File created", "keywords": ["file create", "dropped file", "file written"]},
        {"id": "12", "name": "Registry key/value", "keywords": ["registry", "run key", "regedit", "reg add"]},
        {"id": "13", "name": "Registry value set", "keywords": ["registry value", "reg set", "persistence key"]},
        {"id": "22", "name": "DNS query", "keywords": ["dns query", "dns request", "domain resolution"]},
    ]},
    "edr": {"source": "EDR (CrowdStrike / SentinelOne / Defender for Endpoint)", "events": [
        {"id": "process_exec", "name": "Process execution (DeviceProcessEvents / ProcessRollup2)", "keywords": ["process", "exec", "command line", "spawn", "child process"]},
        {"id": "network_conn", "name": "Network connection (DeviceNetworkEvents)", "keywords": ["network connection", "outbound", "c2", "beacon", "connect"]},
        {"id": "file_event", "name": "File create/modify (DeviceFileEvents)", "keywords": ["file", "dropped", "ransomware", "encrypt"]},
        {"id": "registry_event", "name": "Registry modification (DeviceRegistryEvents)", "keywords": ["registry", "run key", "persistence"]},
        {"id": "image_load", "name": "Module load (DeviceImageLoadEvents)", "keywords": ["image load", "dll", "module load"]},
        {"id": "logon_event", "name": "Logon (DeviceLogonEvents)", "keywords": ["logon", "sign-in", "authenticat"]},
        {"id": "edr_alert", "name": "EDR detection / alert (AlertEvidence)", "keywords": ["detection", "alert", "quarantine", "block"]},
    ]},
    "dns": {"source": "DNS Logs", "events": [
        {"id": "query", "name": "DNS query", "keywords": ["dns query", "domain", "resolution", "lookup", "query"]},
        {"id": "response", "name": "DNS response", "keywords": ["dns response", "answer", "resolved"]},
        {"id": "nxdomain", "name": "NXDOMAIN response", "keywords": ["nxdomain", "non-existent", "dga"]},
        {"id": "txt_query", "name": "TXT / large record query", "keywords": ["txt record", "dns tunnel", "exfil", "base64"]},
        {"id": "sinkhole", "name": "Sinkholed / blocklisted domain", "keywords": ["sinkhole", "blocklist", "malicious domain", "c2 domain"]},
    ]},
    "firewall": {"source": "Firewall / Network Perimeter Logs", "events": [
        {"id": "allow", "name": "Connection allowed", "keywords": ["allow", "permit", "accepted"]},
        {"id": "deny", "name": "Connection denied/blocked", "keywords": ["deny", "block", "drop", "reject"]},
        {"id": "threat", "name": "IPS / threat signature match", "keywords": ["threat", "signature", "ips", "exploit", "intrusion"]},
        {"id": "scan", "name": "Port scan / recon", "keywords": ["port scan", "scan", "sweep", "recon"]},
        {"id": "egress", "name": "Suspicious outbound / egress", "keywords": ["outbound", "egress", "exfil", "data transfer", "beacon"]},
    ]},
    "identity_provider": {"source": "Identity Provider (Okta / Azure AD)", "events": [
        {"id": "signin", "name": "Interactive sign-in", "keywords": ["sign-in", "signin", "logon", "authenticat", "login"]},
        {"id": "signin_fail", "name": "Failed sign-in", "keywords": ["failed sign", "failed login", "brute", "password spray"]},
        {"id": "mfa_challenge", "name": "MFA challenge", "keywords": ["mfa", "multi-factor", "verify", "push"]},
        {"id": "conditional_access", "name": "Conditional access / sign-on policy", "keywords": ["conditional access", "sign-on policy", "policy evaluate"]},
        {"id": "admin_action", "name": "Admin / directory change", "keywords": ["admin", "role assign", "directory", "privileged"]},
        {"id": "account_lock", "name": "Account locked / suspended", "keywords": ["lock", "suspend", "disabled"]},
        {"id": "oauth_consent", "name": "OAuth app consent grant", "keywords": ["oauth", "consent", "app registration", "grant"]},
        {"id": "factor_change", "name": "MFA factor added/removed", "keywords": ["factor", "enroll", "reset mfa", "register device"]},
    ]},
    "m365": {"source": "Microsoft 365 Unified Audit Log", "events": [
        {"id": "UserLoggedIn", "name": "User logged in", "keywords": ["logged in", "sign-in", "login", "userloggedin"]},
        {"id": "MailItemsAccessed", "name": "Mail items accessed", "keywords": ["mail access", "mailitemsaccessed", "mailbox access"]},
        {"id": "Set-InboxRule", "name": "Inbox rule created/modified", "keywords": ["inbox rule", "forwarding", "set-inboxrule", "new-inboxrule", "redirect"]},
        {"id": "Add-MailboxPermission", "name": "Mailbox permission added", "keywords": ["mailbox permission", "delegate", "add-mailboxpermission"]},
        {"id": "FileDownloaded", "name": "File downloaded", "keywords": ["file download", "filedownloaded", "download"]},
        {"id": "SharingInvitationCreated", "name": "External sharing invitation", "keywords": ["sharing", "external share", "sharinginvitation", "anonymous link"]},
        {"id": "Send", "name": "Message sent", "keywords": ["message sent", "send as", "sendas", "sendonbehalf"]},
        {"id": "SearchQueryPerformed", "name": "eDiscovery / content search", "keywords": ["ediscovery", "content search", "compliance search"]},
    ]},
    "cloud": {"source": "Cloud Infrastructure (AWS CloudTrail / Azure / GCP Audit)", "events": [
        {"id": "ConsoleLogin", "name": "Console login", "keywords": ["console login", "sign-in", "root login", "consolelogin"]},
        {"id": "CreateUser", "name": "IAM user/role created", "keywords": ["create user", "createuser", "iam", "createrole", "new principal"]},
        {"id": "CreateAccessKey", "name": "Access key created", "keywords": ["access key", "createaccesskey", "api key"]},
        {"id": "PutBucketPolicy", "name": "Bucket/storage policy change", "keywords": ["bucket", "s3", "putbucket", "public access", "storage acl"]},
        {"id": "AuthorizeSecurityGroupIngress", "name": "Security group / firewall change", "keywords": ["security group", "ingress", "0.0.0.0", "nsg", "firewall rule"]},
        {"id": "AssumeRole", "name": "Role assumption", "keywords": ["assume role", "assumerole", "sts", "privilege escal"]},
        {"id": "GetSecretValue", "name": "Secret / key accessed", "keywords": ["secret", "getsecretvalue", "kms", "key vault", "parameter store"]},
        {"id": "DeleteTrail", "name": "Logging/trail disabled", "keywords": ["deletetrail", "stoplogging", "disable logging", "cloudtrail delete"]},
    ]},
    "proxy": {"source": "Web Proxy / Secure Web Gateway", "events": [
        {"id": "request", "name": "Web request", "keywords": ["http request", "url", "web request", "user-agent"]},
        {"id": "block", "name": "URL / category blocked", "keywords": ["blocked", "category", "denied", "policy block"]},
        {"id": "malware", "name": "Malware download blocked", "keywords": ["malware", "download", "payload", "executable"]},
        {"id": "cnc", "name": "C2 / callback detected", "keywords": ["c2", "command and control", "callback", "beacon", "newly registered"]},
        {"id": "upload", "name": "Large upload / exfil", "keywords": ["upload", "exfil", "data transfer", "paste site"]},
    ]},
    "email_security": {"source": "Email Security Gateway", "events": [
        {"id": "phish", "name": "Phishing detected", "keywords": ["phish", "spoof", "suspicious sender"]},
        {"id": "malware_attach", "name": "Malicious attachment", "keywords": ["attachment", "malware", "macro", "payload"]},
        {"id": "url_click", "name": "Malicious URL click", "keywords": ["url click", "link", "rewritten url", "safe links"]},
        {"id": "impersonation", "name": "Impersonation / BEC", "keywords": ["impersonation", "bec", "display name", "ceo fraud"]},
        {"id": "quarantine", "name": "Message quarantined", "keywords": ["quarantine", "blocked message"]},
    ]},
    "linux": {"source": "Linux OS Logs (syslog / auditd)", "events": [
        {"id": "execve", "name": "Process execution (EXECVE)", "keywords": ["execve", "process", "command", "bash", "/bin/"]},
        {"id": "user_login", "name": "User login (sshd / USER_LOGIN)", "keywords": ["ssh", "login", "sshd", "logon", "accepted password"]},
        {"id": "sudo", "name": "Privilege escalation (sudo / USER_CMD)", "keywords": ["sudo", "privilege", "su ", "root", "visudo"]},
        {"id": "cred_change", "name": "Credential/account change", "keywords": ["passwd", "useradd", "account", "shadow", "adduser"]},
        {"id": "cron", "name": "Scheduled task (cron)", "keywords": ["cron", "crontab", "scheduled", "systemd timer"]},
        {"id": "syscall", "name": "Audit syscall (auditd)", "keywords": ["syscall", "auditd", "audit rule", "ptrace"]},
    ]},
    "vpn": {"source": "VPN / Remote Access Logs", "events": [
        {"id": "connect", "name": "VPN session established", "keywords": ["vpn connect", "session start", "tunnel", "connected"]},
        {"id": "disconnect", "name": "VPN session ended", "keywords": ["disconnect", "session end"]},
        {"id": "auth_fail", "name": "VPN authentication failure", "keywords": ["auth fail", "failed", "denied", "brute"]},
        {"id": "impossible_travel", "name": "Impossible travel / geo anomaly", "keywords": ["impossible travel", "geo", "distant", "anomalous location"]},
    ]},
    "dlp": {"source": "Data Loss Prevention (DLP)", "events": [
        {"id": "policy_match", "name": "DLP policy match", "keywords": ["policy match", "sensitive", "pii", "violation"]},
        {"id": "block", "name": "Transfer blocked", "keywords": ["blocked", "prevented", "denied transfer"]},
        {"id": "exfil_alert", "name": "Exfiltration alert", "keywords": ["exfil", "large transfer", "usb", "upload", "external"]},
    ]},
    "waf": {"source": "Web Application Firewall (WAF)", "events": [
        {"id": "block", "name": "Request blocked", "keywords": ["blocked", "denied", "403"]},
        {"id": "sqli", "name": "SQL injection attempt", "keywords": ["sql injection", "sqli", "union select"]},
        {"id": "xss", "name": "Cross-site scripting attempt", "keywords": ["xss", "cross-site", "<script"]},
        {"id": "rce", "name": "RCE / path traversal attempt", "keywords": ["traversal", "rce", "command injection", "../", "log4j"]},
        {"id": "rate_limit", "name": "Rate limit / bot", "keywords": ["rate limit", "bot", "flood", "credential stuffing"]},
    ]},
    "saas": {"source": "SaaS / Productivity Apps", "events": [
        {"id": "login", "name": "App login", "keywords": ["login", "sign-in", "authenticat"]},
        {"id": "file_download", "name": "Bulk file download/export", "keywords": ["download", "export", "bulk"]},
        {"id": "external_share", "name": "External share / public link", "keywords": ["external share", "public link", "shared with"]},
        {"id": "oauth_grant", "name": "Third-party OAuth grant", "keywords": ["oauth", "third-party", "app grant", "token"]},
        {"id": "admin_change", "name": "Admin/setting change", "keywords": ["admin", "setting", "permission change", "role"]},
    ]},
    "kubernetes": {"source": "Kubernetes / Container Audit Logs", "events": [
        {"id": "create", "name": "Resource created", "keywords": ["create", "deploy", "apply", "new pod"]},
        {"id": "delete", "name": "Resource deleted", "keywords": ["delete", "remove", "events deleted"]},
        {"id": "exec", "name": "Pod exec / attach", "keywords": ["exec", "attach", "kubectl exec", "shell"]},
        {"id": "secret_access", "name": "Secret accessed", "keywords": ["secret", "configmap", "credential"]},
        {"id": "rbac_change", "name": "RBAC / role binding change", "keywords": ["rbac", "clusterrole", "rolebinding", "privilege"]},
        {"id": "priv_container", "name": "Privileged / hostPath container", "keywords": ["privileged", "hostpath", "escape", "capabilities"]},
    ]},
    "mfa": {"source": "MFA / Authentication App Logs", "events": [
        {"id": "challenge", "name": "MFA challenge issued", "keywords": ["challenge", "push", "prompt", "verify"]},
        {"id": "denied", "name": "MFA denied by user", "keywords": ["denied", "rejected"]},
        {"id": "fatigue", "name": "MFA fatigue (repeated prompts)", "keywords": ["fatigue", "repeated", "bombing", "spam"]},
        {"id": "enroll", "name": "New factor enrolled", "keywords": ["enroll", "register", "new device", "add factor"]},
    ]},
}

_NUMERIC_SOURCES = ("windows_security_events", "sysmon")


def canonical_sources_for_rule(rule: dict) -> list[str]:
    """Which canonical log sources this rule maps to. Matches the declared
    data_sources + platform + pseudo_logic only (not the noisier name/triage/
    description), with word boundaries, to keep attribution precise."""
    text = " ".join([
        " ".join(str(x) for x in (rule.get("data_sources") or [])),
        " ".join(str(x) for x in (rule.get("platform") or [])),
        rule.get("pseudo_logic") or "",
    ]).lower()
    hits = [cid for cid, kws in LOG_SOURCE_KEYWORDS.items()
            if any(_kw_hit(k, text) for k in kws)]
    return hits


def build_requirements(rule: dict) -> dict | None:
    """Deterministic per-source requirements using each source's real events."""
    logic = ((rule.get("pseudo_logic") or "") + " " + " ".join(
        (rule.get("queries") or {}).values() if isinstance(rule.get("queries"), dict) else [])).lower()
    blob = (logic + " " + (rule.get("name") or "") + " " + (rule.get("description") or "")).lower()
    ids_in_logic = set(re.findall(r"\b(\d{1,5})\b", logic))

    sources = canonical_sources_for_rule(rule)
    if not sources:
        return None

    log_sources = []
    for cid in sources:
        cat = LOG_SOURCE_EVENTS.get(cid)
        if not cat:
            continue
        events = []
        for ev in cat["events"]:
            if cid in _NUMERIC_SOURCES:
                # Attribute a numeric event only if the rule's logic references its id.
                referenced = ev["id"] in ids_in_logic
                required = referenced
                match = referenced or any(k in blob for k in ev["keywords"])
            else:
                in_logic = any(k in logic for k in ev["keywords"])
                match = in_logic or any(k in blob for k in ev["keywords"])
                required = in_logic
            if match:
                events.append({"id": ev["id"], "name": ev["name"], "required": required})
        # If the rule maps to this source but referenced no specific event, show the
        # source's first two events as "used" (optional) so the source isn't blank.
        if not events:
            events = [{"id": e["id"], "name": e["name"], "required": False} for e in cat["events"][:2]]
        log_sources.append({"source": cat["source"], "events": events})

    return {"log_sources": log_sources} if log_sources else None
