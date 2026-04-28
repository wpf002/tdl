"""Per-tactic analyst triage playbooks.

Each tactic has a 6-step ordered playbook. The placeholder {tech_focus} gets
filled with technique-specific phrasing (process tree / network destination /
auth source / cloud actor) chosen at generation time.
"""

# Phrasing keyed off the rule's primary "shape" (process / network / cloud /
# registry / file) — used as the {tech_focus} substitution.
SHAPE_FOCUS = {
    "process": "the parent → child process tree, command line arguments, and code-signing status",
    "network": "the destination domain/IP, ASN, port, and TLS / HTTP fingerprints",
    "cloud":   "the calling identity (ARN / UPN), source IP, user agent, and the resource being acted on",
    "registry":"the registry hive, key path, value name, and writing process",
    "file":    "the file path, file hash, parent process, and any prior network/email delivery",
    "auth":    "the source IP, geo / ASN, authentication method, and prior sign-in pattern for the user",
}


# 6-step playbook per tactic. {tech_focus} appears once per playbook.
TACTIC_PLAYBOOK = {
    "Initial Access": [
        "Confirm the alert metadata: timestamp, target host/identity, source (IP, sender, URL), and the matched IOC.",
        "Examine {tech_focus} to assess whether the entry vector is consistent with this technique.",
        "Cross-reference with email gateway, web proxy, and EDR telemetry in the 30 minutes around the alert for related delivery activity.",
        "Pivot on the user / host: look for follow-on execution, persistence, or credential-access events in the next 24h.",
        "Decide TP / FP / dual-use: confirm the user did not request the activity (sanctioned vendor onboarding, marketing campaign, pen test).",
        "If TP: isolate the host, reset the user's credentials and tokens, capture forensic artifacts, and open an incident ticket referencing this rule_id.",
    ],
    "Execution": [
        "Confirm the alert metadata: timestamp, host, user, and the executing process.",
        "Inspect {tech_focus} — pay attention to short-lived processes, encoded arguments, and unusual parents (Office, browser, services).",
        "Pull EDR process tree for the alert PID; check the parent / grandparent and any child processes spawned within 5 minutes.",
        "Compare against the host's baseline: is the binary / interpreter normally invoked here, by this user, at this time?",
        "Decide TP / FP: TP if the execution chain has no business justification; FP if it traces to a packaging script, software install, or scheduled job.",
        "If TP: contain the host, kill the offending process, snapshot memory if possible, and escalate to IR with the process tree attached.",
    ],
    "Persistence": [
        "Confirm the alert metadata: timestamp, host, user, and the persistence artifact (registry path / scheduled task / service / config).",
        "Inspect {tech_focus} — verify the persistence target points to an unusual location or unsigned binary.",
        "Determine when the artifact was created and which process/account performed the write — pivot on that process for the original attack chain.",
        "Look for prior child-process activity from the persistence target: did anything actually launch from it?",
        "Decide TP / FP: FP for sanctioned management software (RMM, vendor agents, custom installers) — verify against the asset register.",
        "If TP: remove the persistence artifact, isolate the host, hunt for the same artifact across the fleet, and rotate any credentials touched by the persistent process.",
    ],
    "Privilege Escalation": [
        "Confirm the alert metadata: timestamp, host, source user, and (if visible) the resulting privileged context.",
        "Inspect {tech_focus} — verify the privilege gain was not part of an approved elevation flow (UAC consent, sudo, PAM ticket).",
        "Pull preceding 1h of activity for the source user: was there earlier credential-access / discovery / exploit telemetry?",
        "Validate token / session changes: new SeImpersonate-style privileges, new IAM role assumption, or a SYSTEM-level child process from a user-level parent.",
        "Decide TP / FP: TP if there's no change-management correlation and no parent admin process; FP if it's a documented elevation by IT.",
        "If TP: contain the host, revoke the elevated session, sweep for other escalations using the same primitive, and notify identity / IR teams.",
    ],
    "Defense Evasion": [
        "Confirm the alert metadata: timestamp, host, user, and the evasion artifact (process / DLL / log clear / service stop).",
        "Inspect {tech_focus} — distinguish administrative tooling from adversary tradecraft (LOLBins, signed binary proxies, masquerading paths).",
        "Pull surrounding security-tool telemetry: EDR sensor health, AV scan history, log channel state to see what was suppressed.",
        "Look for adjacent stages: a successful evasion typically wraps an execution / persistence / cred-access action in the same minute.",
        "Decide TP / FP: FP if patch / debugging / IT-troubleshooting context fully accounts for it; TP if it's unattended and pairs with other malicious telemetry.",
        "If TP: restore the disabled defenses, capture artifacts before evidence rolls out of retention, isolate the host, and escalate to IR.",
    ],
    "Credential Access": [
        "Confirm the alert metadata: timestamp, target host (LSASS / DC / KDC) or identity provider, and the source process / actor.",
        "Inspect {tech_focus} — verify the read / dump / brute-force pattern is consistent with this technique.",
        "Pull preceding execution / discovery telemetry: many credential-access actions follow process-injection or LSASS tooling.",
        "Compute the blast radius: which accounts could have been exposed (enumerate cached credentials, recent session tokens, kerberos tickets).",
        "Decide TP / FP: FP for sanctioned IR / pen-test / DSC tooling; TP for unattended dumping or anomalous Kerberos behavior.",
        "If TP: rotate all potentially exposed credentials and tickets, invalidate sessions, isolate the host, and consider golden-ticket / krbtgt rotation if scope warrants.",
    ],
    "Discovery": [
        "Confirm the alert metadata: timestamp, host, user, and the enumeration command(s) observed.",
        "Inspect {tech_focus} — determine whether the enumeration is targeted (specific user / share / OU) or scattered (broad, scripted).",
        "Compare against the user's role: is this discovery activity normal for an admin, engineer, or pen-tester? Discovery from a finance or HR identity is high-signal.",
        "Pull adjacent execution / lateral-movement / cred-access telemetry — discovery often precedes the next stage by minutes.",
        "Decide TP / FP: FP for sanctioned pen-test, asset inventory, or admin troubleshooting; TP if the user is unexpected and adjacent telemetry is suspicious.",
        "If TP: review what was learned (groups, hosts, paths), constrain the user's privileges, and watch for the next-stage activity that the recon was likely setting up.",
    ],
    "Lateral Movement": [
        "Confirm the alert metadata: timestamp, source host, target host, and the protocol / credential used.",
        "Inspect {tech_focus} — confirm the cross-host action (SMB write, WinRM exec, RDP session, kubectl exec) and the auth context.",
        "Pull a graph of the source identity's recent host touches — adversaries hop quickly across multiple endpoints.",
        "Validate against change tickets and admin patterns: is this admin-bastion traffic or worker-to-worker movement that has no business justification?",
        "Decide TP / FP: FP for sanctioned admin / vulnerability-scan / RMM activity; TP for movement that crosses security zones or uses an unusual identity.",
        "If TP: isolate both source and target, rotate the moving identity's credentials, and walk forward from the target host to find subsequent stages.",
    ],
    "Collection": [
        "Confirm the alert metadata: timestamp, host, user, and the data being read (paths, mailbox, share, repository).",
        "Inspect {tech_focus} — determine the collection scope (single file, recursive walk, mailbox export).",
        "Compare against business need: does this user have a legitimate reason to read this data set in this way?",
        "Pull staging telemetry: archive creation, large temp folders, encrypted blobs in unusual locations within the next 30 minutes.",
        "Decide TP / FP: FP for sanctioned migration / backup / DLP testing; TP if collection volume is anomalous and lacks a ticket.",
        "If TP: determine sensitivity of accessed data, preserve audit logs, prepare for possible DLP / privacy notification, and escalate accordingly.",
    ],
    "Command and Control": [
        "Confirm the alert metadata: timestamp, source host, destination domain/IP, and the cadence pattern detected.",
        "Inspect {tech_focus} — verify beaconing characteristics (interval, jitter, request size, server response code).",
        "Pull WHOIS / TLS / passive-DNS context on the destination — newly registered or low-reputation infrastructure raises confidence.",
        "Identify the originating process and trace it back to its install / launch event (initial access / persistence stage).",
        "Decide TP / FP: FP for sanctioned OOB management agents (allowlist them); TP for unattended periodic egress to new infrastructure.",
        "If TP: block the destination at egress, isolate the host, capture network PCAP / memory while session is live, and escalate to IR.",
    ],
    "Exfiltration": [
        "Confirm the alert metadata: timestamp, source host, destination, total bytes transferred, and the protocol used.",
        "Inspect {tech_focus} — quantify the data volume vs the host's baseline outbound profile.",
        "Pivot to preceding collection / staging activity: archives, mailbox dumps, database extracts in the prior 24h on the same host.",
        "Identify what was likely exfiltrated (path patterns, file types, classification labels) and the user/process that produced it.",
        "Decide TP / FP: FP for sanctioned cloud backup / vendor data sharing on a known channel; TP for unattended bulk transfers to new endpoints.",
        "If TP: block the destination, isolate the host, preserve network and DLP evidence, and trigger your data-incident process (legal / privacy / customer notification as applicable).",
    ],
    "Impact": [
        "Confirm the alert metadata: timestamp, host(s) affected, scope of impact (count of files / accounts / services).",
        "Inspect {tech_focus} — characterize the destructive action (encrypt, delete, lockout, disable, reboot).",
        "Determine spread: is this a single host or a coordinated multi-host event? Pull file / service telemetry across the fleet.",
        "Trigger your major-incident bridge if scope is multi-host or business-critical — early activation buys time.",
        "Decide TP / FP: FP only if a sanctioned destructive action (DR test, decommission) is documented; default to TP at this severity.",
        "If TP: execute your IR runbook — isolate, preserve evidence, restore from backup if appropriate, hunt for adversary persistence to prevent recurrence.",
    ],
}


def shape_for(rule):
    """Return the focus key for {tech_focus} substitution."""
    name = (rule.get("name") or "").lower()
    desc = (rule.get("description") or "").lower()
    plats = set(rule.get("platform") or [])
    ds = set(rule.get("data_sources") or [])

    if "Network" in plats or any(k in name for k in ("beacon", "tunnel", "outbound", "dns", "tls", "http", "exfil", "c2", "lateral")):
        return "network"
    if {"AWS","Azure","GCP","Okta","Microsoft 365","Google Workspace","Kubernetes"} & plats or any(k in name.lower() for k in ("oauth", "iam", "console", "saml")):
        return "cloud"
    if any(k in name for k in ("registry", "regkey", "run key", "lsa ", "wmi sub")):
        return "registry"
    if any(k in name for k in ("file ", "shadow", "wipe", "encrypted", "archive")):
        return "file"
    if any(k in name for k in ("login", "logon", "auth", "kerber", "mfa", "spray", "brute")):
        return "auth"
    return "process"


def steps_for(rule):
    """Return the 6-step playbook for this rule's tactic + shape."""
    tactic = rule.get("tactic")
    base = TACTIC_PLAYBOOK.get(tactic)
    if not base:
        # Generic fallback for unmapped tactics
        base = TACTIC_PLAYBOOK["Execution"]
    focus = SHAPE_FOCUS[shape_for(rule)]
    return [step.replace("{tech_focus}", focus) for step in base]
