"""Knowledge base of detection intent per ATT&CK technique.

One entry per technique_id. The generator pulls a per-(tactic, technique)
detection from these entries. Each entry provides:
  name           — canonical MITRE technique name
  platforms      — list[str] from the schema's enum
  data_sources   — list[str], free text, populates the recommend engine
  severity       — Low | Medium | High | Critical
  fidelity       — Low | Medium | High
  tags           — list[str] (lower-case)
  intents        — dict keyed by tactic name, each with
      title  : rule name suffix (e.g. "Suspicious Process Discovery via tasklist")
      pseudo : pseudo_logic source-of-truth (1-3 lines)
      hint   : short detection hint used to template SIEM queries
                fields:
                  event   : log event name (e.g. "ProcessCreate")
                  command : sample CLI/regex (e.g. "tasklist")
                  field   : primary field to alert on (e.g. "process.command_line")

Falls back to a generic skeleton if intents lacks the tactic.
"""

# Tactic ID lookup
TACTIC_IDS = {
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}

# Tactic → folder name
TACTIC_FOLDER = {
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
}

# Tactic → rule_id prefix
TACTIC_PREFIX = {
    "Initial Access": "AUTH",
    "Execution": "EXE",
    "Persistence": "PER",
    "Privilege Escalation": "PE",
    "Defense Evasion": "DE",
    "Credential Access": "CA",
    "Discovery": "DIS",
    "Lateral Movement": "LM",
    "Collection": "COL",
    "Command and Control": "C2",
    "Exfiltration": "EXF",
    "Impact": "IMP",
}


# ============================================================================
# Technique knowledge base
# ============================================================================
#
# Format note: each `intents` entry lists per-tactic context. Where a technique
# applies to only one tactic, the intent is also used as a generic fallback.
# `hint` keys feed the per-SIEM query templates in query_templates.py.

TECHNIQUES = {
    # ─── Initial Access ─────────────────────────────────────────────────
    "T1091": {
        "name": "Replication Through Removable Media",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Windows Event Log", "Sysmon", "EDR"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["removable-media", "usb", "autorun"],
        "intents": {
            "Initial Access": {
                "title": "Executable Launched from Removable USB Volume",
                "pseudo": "Process started from a path on a removable drive (DriveType=2). Adversaries copy implants to USB and rely on autorun or user click for first execution.",
                "hint": {"event": "ProcessCreate", "command": "removable", "field": "process.parent.path"},
            },
            "Lateral Movement": {
                "title": "Lateral Spread via Removable Media Write+Execute",
                "pseudo": "Same host writes an executable to a removable volume then a different host executes it within 24h. Suggests USB-borne worm spread.",
                "hint": {"event": "FileCreate", "command": "removable", "field": "file.path"},
            },
        },
    },
    "T1199": {
        "name": "Trusted Relationship",
        "platforms": ["AWS", "Azure", "GCP", "Okta", "SaaS"],
        "data_sources": ["Cloud Audit Logs", "SaaS Audit Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["third-party", "supply-chain", "federated"],
        "intents": {
            "Initial Access": {
                "title": "Federated Trust Login from Third-Party Tenant",
                "pseudo": "Successful console/API login originates from an external IdP or partner tenant outside the approved trust list. Adversaries pivot through compromised MSPs and partners.",
                "hint": {"event": "ConsoleLogin", "command": "trust", "field": "userIdentity.principalId"},
            },
        },
    },

    # ─── Execution ──────────────────────────────────────────────────────
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "EDR", "Auditd"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["scripting", "interpreter", "powershell", "bash"],
        "intents": {
            "Execution": {
                "title": "Encoded PowerShell Command Execution",
                "pseudo": "powershell.exe spawned with -EncodedCommand or -enc flag. Encoded payloads are a classic obfuscation pattern.",
                "hint": {"event": "ProcessCreate", "command": "powershell -enc", "field": "process.command_line"},
            },
        },
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["EDR", "Sysmon"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["exploit", "client-side", "office", "browser"],
        "intents": {
            "Execution": {
                "title": "Office Application Spawning Suspicious Child Process",
                "pseudo": "winword.exe / excel.exe / powerpnt.exe parents cmd.exe, powershell.exe, wscript, mshta, rundll32 or regsvr32. Common post-exploit payload pivot from a malicious document.",
                "hint": {"event": "ProcessCreate", "command": "office-child", "field": "process.parent.name"},
            },
        },
    },
    "T1559": {
        "name": "Inter-Process Communication",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "Medium",
        "fidelity": "Low",
        "tags": ["ipc", "com", "dde"],
        "intents": {
            "Execution": {
                "title": "DDE/COM Object Invoked from Office Application",
                "pseudo": "Office process invokes COM scripting (MSScriptControl) or DDEAUTO. Legacy OLE/DDE abuse for code execution.",
                "hint": {"event": "ProcessCreate", "command": "dde", "field": "process.command_line"},
            },
        },
    },
    "T1106": {
        "name": "Native API",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["EDR", "Sysmon"],
        "severity": "Medium",
        "fidelity": "Low",
        "tags": ["native-api", "syscall"],
        "intents": {
            "Execution": {
                "title": "Direct Syscall via Unbacked Memory Region",
                "pseudo": "Process makes NT* syscalls from an unbacked / RX private memory region. Indicates syscall stub injection or direct system call evasion.",
                "hint": {"event": "ImageLoad", "command": "ntdll", "field": "process.thread.start_address"},
            },
        },
    },
    "T1648": {
        "name": "Serverless Execution",
        "platforms": ["AWS", "Azure", "GCP"],
        "data_sources": ["Cloud Audit Logs"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["serverless", "lambda", "function"],
        "intents": {
            "Execution": {
                "title": "Suspicious Lambda/Function Created with Admin Role",
                "pseudo": "New serverless function created with privileged role (IAM admin / contributor) by a non-CI/CD identity. Adversaries weaponize serverless to persist with cloud creds.",
                "hint": {"event": "CreateFunction", "command": "lambda", "field": "userIdentity.arn"},
            },
        },
    },
    "T1129": {
        "name": "Shared Modules",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "Medium",
        "fidelity": "Low",
        "tags": ["dll", "loadlibrary", "module"],
        "intents": {
            "Execution": {
                "title": "DLL Loaded from User-Writable Path",
                "pseudo": "Process loads a DLL from %TEMP%, %APPDATA% or other user-writable directory. Adversaries side-load malicious DLLs from those paths.",
                "hint": {"event": "ImageLoad", "command": "user-writable", "field": "file.path"},
            },
        },
    },
    "T1072": {
        "name": "Software Deployment Tools",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["EDR", "MDM Logs", "RMM Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["sccm", "intune", "rmm", "deployment"],
        "intents": {
            "Execution": {
                "title": "RMM Agent Spawning Interactive Shell",
                "pseudo": "ConnectWise / Kaseya / NinjaOne / TeamViewer agent process spawns cmd, powershell or pwsh. Outside known patch workflows this signals abused deployment tooling.",
                "hint": {"event": "ProcessCreate", "command": "rmm-shell", "field": "process.parent.name"},
            },
            "Lateral Movement": {
                "title": "Mass Software Push from RMM Console",
                "pseudo": "Single RMM/SCCM identity initiates software install or script execution against ≥10 distinct endpoints in 30m. Anomalous fan-out from deployment tooling.",
                "hint": {"event": "Deploy", "command": "fanout", "field": "actor.user.name"},
            },
        },
    },
    "T1204": {
        "name": "User Execution",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["EDR", "Sysmon", "Email Gateway"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["phishing", "user-action", "lure"],
        "intents": {
            "Execution": {
                "title": "User-Executed Script From Recently-Downloaded Archive",
                "pseudo": "User runs .lnk, .iso, .img, .vhd or scripted file extracted from an archive received in the last 24h. Standard click-to-run lure flow.",
                "hint": {"event": "ProcessCreate", "command": "lnk-iso", "field": "process.executable"},
            },
        },
    },

    # ─── Persistence ────────────────────────────────────────────────────
    "T1197": {
        "name": "BITS Jobs",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon", "Windows Event Log"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["bits", "bitsadmin", "transfer"],
        "intents": {
            "Persistence": {
                "title": "BITS Job with SetNotifyCmdLine Configured",
                "pseudo": "BITS job created with a notify command — BITS will execute the command when the transfer completes. Classic stealth persistence/launch primitive.",
                "hint": {"event": "BitsClient", "command": "bitsadmin", "field": "process.command_line"},
            },
            "Defense Evasion": {
                "title": "BITS Used to Download Executable from Unusual Host",
                "pseudo": "bitsadmin or BITS-via-PowerShell downloads .exe / .dll / .bin from a host outside your software-delivery allowlist. Living-off-the-land transfer.",
                "hint": {"event": "BitsClient", "command": "bitsadmin", "field": "url.full"},
            },
        },
    },
    "T1176": {
        "name": "Browser Extensions",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["EDR", "Browser Telemetry"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["browser", "extension", "addon"],
        "intents": {
            "Persistence": {
                "title": "New Browser Extension Installed Outside Managed Channel",
                "pseudo": "Chrome/Edge/Firefox extension installed via developer-mode load or sideload, not from the managed extension policy. Persistence + credential-theft vector.",
                "hint": {"event": "FileCreate", "command": "extension", "field": "file.path"},
            },
        },
    },
    "T1525": {
        "name": "Implant Internal Image",
        "platforms": ["AWS", "Azure", "GCP", "Kubernetes"],
        "data_sources": ["Cloud Audit Logs", "Container Registry Logs"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["container", "image", "registry"],
        "intents": {
            "Persistence": {
                "title": "Container Image Pushed to Production Registry by Unusual Identity",
                "pseudo": "Push to internal/prod container registry from an identity outside the CI/CD service-account allowlist. Adversaries plant backdoored images for later pulls.",
                "hint": {"event": "PushImage", "command": "registry", "field": "userIdentity.arn"},
            },
        },
    },
    "T1556": {
        "name": "Modify Authentication Process",
        "platforms": ["Windows", "Linux", "macOS", "Azure", "AWS"],
        "data_sources": ["Windows Event Log", "Sysmon", "Auditd", "Cloud Audit Logs"],
        "severity": "Critical",
        "fidelity": "Medium",
        "tags": ["auth", "lsass", "pam", "ssp"],
        "intents": {
            "Persistence": {
                "title": "LSA Security Package or Authentication Package Registered",
                "pseudo": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa Security Packages / Authentication Packages key written. Adversaries register a malicious SSP DLL for credential capture and persistence.",
                "hint": {"event": "RegistryEvent", "command": "lsa-package", "field": "registry.path"},
            },
            "Defense Evasion": {
                "title": "PAM Module File Modified Outside Patch Window",
                "pseudo": "Write to /lib/security/pam_*.so or /etc/pam.d/* outside an approved package install. Backdoors authentication on Linux.",
                "hint": {"event": "FileModify", "command": "pam", "field": "file.path"},
            },
            "Credential Access": {
                "title": "Domain Authentication Policy Modified to Disable Strong Auth",
                "pseudo": "Domain GPO or Azure AD Conditional Access policy modified to remove MFA/strong-auth for privileged users. Lowers the bar for credential abuse.",
                "hint": {"event": "PolicyChange", "command": "auth-weaken", "field": "policy.name"},
            },
        },
    },
    "T1137": {
        "name": "Office Application Startup",
        "platforms": ["Windows", "macOS"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["office", "template", "addin", "macro"],
        "intents": {
            "Persistence": {
                "title": "Office Application Loading Template or Add-in from User Path",
                "pseudo": "Office app loads a .dotm/.xlam/.ppam/.wll/.xll from %APPDATA% or %TEMP%. Common Office persistence (Outlook Home Page, template injection, COM addins).",
                "hint": {"event": "FileCreate", "command": "office-addin", "field": "file.path"},
            },
        },
    },
    "T1542": {
        "name": "Pre-OS Boot",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["EDR", "Firmware Telemetry"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["bootkit", "uefi", "mbr"],
        "intents": {
            "Persistence": {
                "title": "Direct Write to MBR/VBR or EFI System Partition",
                "pseudo": "Process opens \\\\.\\PhysicalDrive0 with write access or modifies files on the EFI System Partition outside an approved firmware update. Bootkit/UEFI implant.",
                "hint": {"event": "FileWrite", "command": "boot-sector", "field": "file.path"},
            },
            "Defense Evasion": {
                "title": "Boot Configuration Data (BCD) Modified to Disable Integrity",
                "pseudo": "bcdedit invoked with testsigning, nointegritychecks, disable_integrity_checks or similar flags. Disables driver-signing enforcement to load unsigned drivers.",
                "hint": {"event": "ProcessCreate", "command": "bcdedit", "field": "process.command_line"},
            },
        },
    },
    "T1205": {
        "name": "Traffic Signaling",
        "platforms": ["Windows", "Linux", "Network"],
        "data_sources": ["Firewall", "Network IDS", "Sysmon"],
        "severity": "Medium",
        "fidelity": "Low",
        "tags": ["port-knock", "magic-packet", "wol"],
        "intents": {
            "Persistence": {
                "title": "Inbound Connection Following Unusual UDP Knock Sequence",
                "pseudo": "Sequence of small UDP packets to closed ports immediately followed by a TCP connection from the same source to a high port. Classic port-knock backdoor activation.",
                "hint": {"event": "NetworkConnect", "command": "knock", "field": "source.ip"},
            },
            "Defense Evasion": {
                "title": "Wake-on-LAN / Magic-Packet from External Source",
                "pseudo": "WoL magic packet (UDP/9 or UDP/7 with FFFFFFFFFFFF + 16x MAC) received from a non-internal subnet. Stealth wake-up signaling.",
                "hint": {"event": "NetworkConnect", "command": "wol", "field": "destination.port"},
            },
            "Command and Control": {
                "title": "Beacon Activated by ICMP Trigger Pattern",
                "pseudo": "ICMP echo with anomalous payload size or pattern preceding a sudden outbound TCP/443 burst from the receiving host. Trigger-then-beacon C2.",
                "hint": {"event": "NetworkConnect", "command": "icmp-trigger", "field": "network.protocol"},
            },
        },
    },
    "T1078": {
        "name": "Valid Accounts",
        "platforms": ["Windows", "Linux", "macOS", "AWS", "Azure", "Okta", "Microsoft 365"],
        "data_sources": ["Auth Logs", "Cloud Audit Logs", "Identity Provider Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["valid-accounts", "credential-abuse", "anomaly"],
        "intents": {
            "Persistence": {
                "title": "Dormant Account Reactivated and Used Within 1 Hour",
                "pseudo": "Account with no auth in ≥90 days reactivated and immediately used to authenticate. Adversaries revive forgotten accounts as quiet persistence.",
                "hint": {"event": "Login", "command": "dormant", "field": "user.name"},
            },
            "Privilege Escalation": {
                "title": "Standard User Granted Privileged Role Without Ticket",
                "pseudo": "User added to Domain Admins / Global Admins / EC2 admin / IAM admin role outside an approved change-management ticket window.",
                "hint": {"event": "RoleAssignment", "command": "priv-grant", "field": "target.user.name"},
            },
            "Defense Evasion": {
                "title": "Service Account Used Interactively During Off-Hours",
                "pseudo": "Logon type 2 / 10 (interactive / RDP) using a service account outside business hours. Service accounts should not log in interactively.",
                "hint": {"event": "Login", "command": "svc-interactive", "field": "user.name"},
            },
        },
    },

    # ─── Privilege Escalation ───────────────────────────────────────────
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Sysmon", "EDR", "Windows Event Log"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["autostart", "run-key", "registry"],
        "intents": {
            "Privilege Escalation": {
                "title": "Run Key Modified Pointing to User-Writable Path",
                "pseudo": "HKLM\\...\\Run or HKCU\\...\\Run value set to an executable in %TEMP%/%APPDATA%/Public. Re-launches malicious binary at boot/logon with that user's context.",
                "hint": {"event": "RegistryEvent", "command": "run-key", "field": "registry.path"},
            },
        },
    },
    "T1037": {
        "name": "Boot or Logon Initialization Scripts",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Sysmon", "EDR", "Auditd"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["logon-script", "rc-script"],
        "intents": {
            "Privilege Escalation": {
                "title": "Logon Script (UserInitMprLogonScript) Created or Modified",
                "pseudo": "HKCU\\Environment\\UserInitMprLogonScript value created/modified, or /etc/rc.local / /etc/profile.d/* written. Runs at next logon under target's context.",
                "hint": {"event": "RegistryEvent", "command": "logon-script", "field": "registry.path"},
            },
        },
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Sysmon", "EDR", "Auditd"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["service", "launchd", "systemd"],
        "intents": {
            "Privilege Escalation": {
                "title": "New Windows Service Created With Binary in User Path",
                "pseudo": "sc create / New-Service / direct registry create under HKLM\\SYSTEM\\CurrentControlSet\\Services with ImagePath in %TEMP%/%APPDATA%. Service runs as SYSTEM at next start.",
                "hint": {"event": "ProcessCreate", "command": "sc-create", "field": "process.command_line"},
            },
        },
    },
    "T1546": {
        "name": "Event Triggered Execution",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Sysmon", "EDR", "WMI Telemetry"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["wmi", "trigger", "subscription"],
        "intents": {
            "Privilege Escalation": {
                "title": "WMI Permanent Event Subscription Created",
                "pseudo": "Creation of __EventFilter / __EventConsumer / __FilterToConsumerBinding in root\\subscription. Classic stealth WMI persistence + privesc.",
                "hint": {"event": "WmiEvent", "command": "wmi-sub", "field": "wmi.namespace"},
            },
        },
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["EDR", "Sysmon", "Auditd"],
        "severity": "Critical",
        "fidelity": "Medium",
        "tags": ["exploit", "kernel", "cve", "privesc"],
        "intents": {
            "Privilege Escalation": {
                "title": "Unprivileged Process Spawning Elevated Child via Known LPE Pattern",
                "pseudo": "Non-admin process spawns a SYSTEM/root child without UAC consent prompt; or kernel module load with no preceding signed-driver event. Indicates LPE exploit.",
                "hint": {"event": "ProcessCreate", "command": "elevation", "field": "process.user.id"},
            },
        },
    },
    "T1574": {
        "name": "Hijack Execution Flow",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["dll-hijack", "search-order", "side-load"],
        "intents": {
            "Privilege Escalation": {
                "title": "Trusted Binary Loading DLL from Application Directory",
                "pseudo": "Microsoft-signed binary loads an unsigned DLL from its application directory or %APPDATA%. Side-load / search-order hijack pattern.",
                "hint": {"event": "ImageLoad", "command": "dll-side-load", "field": "file.path"},
            },
            "Defense Evasion": {
                "title": "DLL Search Order Hijack via Phantom DLL in PATH Directory",
                "pseudo": "Process loads a DLL from a writable PATH directory before the system32 copy. Phantom-DLL hijack.",
                "hint": {"event": "ImageLoad", "command": "phantom-dll", "field": "file.path"},
            },
        },
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "Windows Event Log", "Auditd"],
        "severity": "Medium",
        "fidelity": "High",
        "tags": ["schtasks", "cron", "at"],
        "intents": {
            "Persistence": {
                "title": "Scheduled Task Created Running From User-Writable Path",
                "pseudo": "schtasks /create or New-ScheduledTask with action pointing to %TEMP%/%APPDATA%/%PUBLIC%. Common malware persistence.",
                "hint": {"event": "ProcessCreate", "command": "schtasks", "field": "process.command_line"},
            },
            "Privilege Escalation": {
                "title": "Scheduled Task Configured to Run as SYSTEM",
                "pseudo": "schtasks /create /ru SYSTEM, or task XML RunLevel=HighestAvailable with UserId=NT AUTHORITY\\SYSTEM. Scheduled escalation primitive.",
                "hint": {"event": "ProcessCreate", "command": "schtasks-system", "field": "process.command_line"},
            },
        },
    },

    # ─── Defense Evasion ────────────────────────────────────────────────
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "EDR", "Auditd"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["uac-bypass", "sudo", "setuid"],
        "intents": {
            "Defense Evasion": {
                "title": "UAC Auto-Elevate Bypass via fodhelper / computerdefaults",
                "pseudo": "fodhelper.exe or computerdefaults.exe spawned with HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command precondition set. Classic auto-elevate UAC bypass.",
                "hint": {"event": "ProcessCreate", "command": "uac-bypass", "field": "process.executable"},
            },
        },
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["token", "impersonation", "seimpersonate"],
        "intents": {
            "Defense Evasion": {
                "title": "Process Acquired SeImpersonate-Style Privileged Token",
                "pseudo": "Sysmon EID 1 or EDR token-grant event showing a non-service process acquiring SeAssignPrimaryTokenPrivilege or SeImpersonatePrivilege. Token-theft / Potato-style abuse.",
                "hint": {"event": "ProcessAccess", "command": "token-impersonate", "field": "process.token.privileges"},
            },
        },
    },
    "T1610": {
        "name": "Deploy Container",
        "platforms": ["Kubernetes", "AWS", "Azure", "GCP"],
        "data_sources": ["Cloud Audit Logs", "Kubernetes Audit Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["container", "k8s", "ecs"],
        "intents": {
            "Defense Evasion": {
                "title": "Privileged Pod Created With Host Mounts",
                "pseudo": "create pod with privileged: true OR hostPID/hostNetwork: true OR hostPath volume mounting / and /etc. Container escape / host evasion primitive.",
                "hint": {"event": "CreatePod", "command": "privileged-pod", "field": "pod.spec.containers"},
            },
            "Execution": {
                "title": "Pod Executes Unusual Image From Public Registry",
                "pseudo": "Pod with image from public registry (docker.io/<rand>, ghcr.io/<rand>) deployed in production namespace. Unsanctioned image execution.",
                "hint": {"event": "CreatePod", "command": "public-image", "field": "pod.spec.containers"},
            },
        },
    },
    "T1006": {
        "name": "Direct Volume Access",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["volume", "raw-disk", "ntds"],
        "intents": {
            "Defense Evasion": {
                "title": "Raw Volume Open via \\\\\\\\.\\\\C: Handle",
                "pseudo": "Process opens \\\\.\\C: or \\\\.\\PhysicalDrive0 with FILE_READ_DATA — bypasses NTFS ACLs to read NTDS.dit, registry hives, locked files.",
                "hint": {"event": "FileAccess", "command": "raw-volume", "field": "file.name"},
            },
        },
    },
    "T1484": {
        "name": "Domain Policy Modification",
        "platforms": ["Windows", "Azure"],
        "data_sources": ["Windows Event Log", "Azure AD Audit Logs"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["gpo", "azuread", "trust"],
        "intents": {
            "Defense Evasion": {
                "title": "Group Policy Object Modified to Drop Scheduled Task",
                "pseudo": "GPO XML modified to add ScheduledTasks / Files / RegistrySettings preference targeting workstations. Domain-wide stealth deployment.",
                "hint": {"event": "GpoChange", "command": "gpo-task", "field": "gpo.name"},
            },
            "Privilege Escalation": {
                "title": "Federation Trust Added or Modified in AAD",
                "pseudo": "Set-MsolDomainFederationSettings / Set-DomainFederationSettings / new federation realm added. Golden-SAML precursor.",
                "hint": {"event": "AAD", "command": "fed-trust", "field": "operationName"},
            },
        },
    },
    "T1480": {
        "name": "Execution Guardrails",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["EDR", "Sysmon"],
        "severity": "Medium",
        "fidelity": "Low",
        "tags": ["guardrail", "environment-keying"],
        "intents": {
            "Defense Evasion": {
                "title": "Process Reads Domain Membership / Geo Before Execution",
                "pseudo": "Short-lived process queries GetComputerNameEx, NetWkstaGetInfo, GetUserGeoID and exits with no further activity. Likely environment-keyed payload bailing on a non-target host.",
                "hint": {"event": "ProcessCreate", "command": "guardrail", "field": "process.command_line"},
            },
        },
    },
    "T1211": {
        "name": "Exploitation for Defense Evasion",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["EDR", "Sysmon"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["exploit", "evasion", "av-bypass"],
        "intents": {
            "Defense Evasion": {
                "title": "Suspicious Crash in Security Product Process",
                "pseudo": "AV/EDR process crash (MsMpEng.exe, sentinel*.exe, Csagent.exe) followed within 5m by new process creation that the dead product would normally block.",
                "hint": {"event": "ProcessTerminate", "command": "av-crash", "field": "process.name"},
            },
        },
    },
    "T1562": {
        "name": "Impair Defenses",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "EDR", "Auditd"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["av-disable", "log-disable"],
        "intents": {
            "Defense Evasion": {
                "title": "Defender / EDR Service Stop or Tamper Attempt",
                "pseudo": "sc stop / Set-MpPreference -Disable* / Stop-Service against Defender, Sentinel, Crowdstrike, Carbon Black, Falcon. Or wevtutil cl / auditpol /clear.",
                "hint": {"event": "ProcessCreate", "command": "av-disable", "field": "process.command_line"},
            },
        },
    },
    "T1202": {
        "name": "Indirect Command Execution",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["lolbin", "indirect"],
        "intents": {
            "Defense Evasion": {
                "title": "Command Execution via pcalua / forfiles / cmstp",
                "pseudo": "pcalua.exe, forfiles.exe, or cmstp.exe spawning interactive shells or unusual children. Indirect-execution lolbins commonly used to bypass parent-process detections.",
                "hint": {"event": "ProcessCreate", "command": "lolbin-indirect", "field": "process.executable"},
            },
        },
    },
    "T1112": {
        "name": "Modify Registry",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon", "Windows Event Log"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["registry", "reg.exe"],
        "intents": {
            "Defense Evasion": {
                "title": "Registry Modification Disabling Security Telemetry",
                "pseudo": "Writes to HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\* (DisableAntiSpyware), DisableTaskMgr, DisableRegistryTools, or HideAdminAccount.",
                "hint": {"event": "RegistryEvent", "command": "reg-tamper", "field": "registry.path"},
            },
        },
    },
    "T1601": {
        "name": "Modify System Image",
        "platforms": ["Network"],
        "data_sources": ["Network Device Logs"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["network", "ios", "firmware"],
        "intents": {
            "Defense Evasion": {
                "title": "Network Device Firmware/Image Replaced from Untrusted Source",
                "pseudo": "Cisco/Juniper/Arista config event: copy tftp://… running-config or boot system flash:<unknown>. Image swap on network gear.",
                "hint": {"event": "NetdevConfig", "command": "fw-replace", "field": "device.config"},
            },
        },
    },
    "T1599": {
        "name": "Network Boundary Bridging",
        "platforms": ["Network"],
        "data_sources": ["Firewall", "Network IDS"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["network", "boundary"],
        "intents": {
            "Defense Evasion": {
                "title": "Asymmetric Traffic Across Trust Boundary",
                "pseudo": "TCP sessions where reply path differs from request path crossing a security boundary, or NAT'd flows bypassing the egress firewall. Indicates rogue route/bridge.",
                "hint": {"event": "NetworkFlow", "command": "asymmetric", "field": "network.path"},
            },
        },
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["obfuscation", "encoded"],
        "intents": {
            "Defense Evasion": {
                "title": "High-Entropy Command Line in Interpreter Process",
                "pseudo": "PowerShell/cmd/bash command line with Shannon entropy > 5.5 and length > 200. Indicates encoded/obfuscated payload.",
                "hint": {"event": "ProcessCreate", "command": "high-entropy", "field": "process.command_line"},
            },
        },
    },
    "T1055": {
        "name": "Process Injection",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "Critical",
        "fidelity": "Medium",
        "tags": ["injection", "createremotethread", "ptrace"],
        "intents": {
            "Defense Evasion": {
                "title": "CreateRemoteThread Into Cross-Process Address Space",
                "pseudo": "Sysmon EID 8 (CreateRemoteThread) where source ≠ target and target is one of lsass/explorer/winlogon/svchost. Classic injection for evasion.",
                "hint": {"event": "CreateRemoteThread", "command": "remote-thread", "field": "process.target"},
            },
            "Privilege Escalation": {
                "title": "Injection Into SYSTEM-Owned Process from Medium Integrity",
                "pseudo": "Cross-process WriteProcessMemory or thread creation where target process runs as SYSTEM and source runs as Medium IL. Privilege jump via injection.",
                "hint": {"event": "ProcessAccess", "command": "inject-privesc", "field": "process.target.user"},
            },
        },
    },
    "T1620": {
        "name": "Reflective Code Loading",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["EDR", "Sysmon"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["reflective", "in-memory", "rwx"],
        "intents": {
            "Defense Evasion": {
                "title": "Code Execution from Unbacked RWX Memory",
                "pseudo": "EDR event showing thread start address inside RWX private memory (no backing image). Reflective DLL / shellcode loader signal.",
                "hint": {"event": "ImageLoad", "command": "rwx-thread", "field": "process.thread.start_address"},
            },
        },
    },
    "T1207": {
        "name": "Rogue Domain Controller",
        "platforms": ["Windows"],
        "data_sources": ["Windows Event Log"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["dcshadow", "rogue-dc"],
        "intents": {
            "Defense Evasion": {
                "title": "DCShadow Replication from Non-DC Source",
                "pseudo": "EID 4928/4929 replication source from a host not in the DC OU, or DRSReplicaAdd from an unfamiliar SPN. DCShadow pattern.",
                "hint": {"event": "DirectoryReplication", "command": "dcshadow", "field": "source.host"},
            },
        },
    },
    "T1014": {
        "name": "Rootkit",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["EDR", "Auditd"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["rootkit", "kernel", "lkm"],
        "intents": {
            "Defense Evasion": {
                "title": "Unsigned Kernel Driver Load",
                "pseudo": "DriverLoad event for a driver not in the Microsoft / vendor-trusted publisher allowlist; or insmod / modprobe of an LKM outside package management.",
                "hint": {"event": "DriverLoad", "command": "unsigned-driver", "field": "file.signature"},
            },
        },
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["lolbin", "rundll32", "regsvr32"],
        "intents": {
            "Defense Evasion": {
                "title": "rundll32/regsvr32 Loading Remote Resource",
                "pseudo": "rundll32.exe or regsvr32.exe with command line containing http://, https:// or \\\\unc-path. Squiblydoo / signed-binary proxy execution.",
                "hint": {"event": "ProcessCreate", "command": "rundll-remote", "field": "process.command_line"},
            },
        },
    },
    "T1216": {
        "name": "System Script Proxy Execution",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["lolbin", "scripts"],
        "intents": {
            "Defense Evasion": {
                "title": "Signed Script (PubPrn / SyncAppvPublishingServer) Used as Proxy",
                "pseudo": "Microsoft-signed script (PubPrn.vbs, SyncAppvPublishingServer.vbs) invoked with a URL or unusual argument. Signed-script proxy execution.",
                "hint": {"event": "ProcessCreate", "command": "signed-script-proxy", "field": "process.command_line"},
            },
        },
    },
    "T1221": {
        "name": "Template Injection",
        "platforms": ["Windows"],
        "data_sources": ["EDR", "Sysmon"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["office", "remote-template"],
        "intents": {
            "Defense Evasion": {
                "title": "Office Document Fetching Remote Template URL",
                "pseudo": "winword.exe / excel.exe child connection to http(s):// retrieving .dotm or .xltm. Remote-template injection delivery.",
                "hint": {"event": "NetworkConnect", "command": "remote-template", "field": "url.full"},
            },
        },
    },
    "T1127": {
        "name": "Trusted Developer Utilities Proxy Execution",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["lolbin", "msbuild", "devtools"],
        "intents": {
            "Defense Evasion": {
                "title": "MSBuild / InstallUtil Executing User-Authored XML Project",
                "pseudo": "msbuild.exe or installutil.exe with argument pointing to an .xml/.csproj/.dll in %TEMP%/%APPDATA%. Inline-task code execution.",
                "hint": {"event": "ProcessCreate", "command": "msbuild-inline", "field": "process.command_line"},
            },
        },
    },
    "T1535": {
        "name": "Unused/Unsupported Cloud Regions",
        "platforms": ["AWS", "Azure", "GCP"],
        "data_sources": ["Cloud Audit Logs"],
        "severity": "Medium",
        "fidelity": "High",
        "tags": ["cloud", "region", "shadow-it"],
        "intents": {
            "Defense Evasion": {
                "title": "Resource Created in Non-Approved Cloud Region",
                "pseudo": "RunInstances / VM create / ComputeEngine.insert in a region outside the approved-region allowlist. Adversaries use exotic regions to evade region-scoped detections.",
                "hint": {"event": "RunInstances", "command": "off-region", "field": "awsRegion"},
            },
        },
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "platforms": ["Windows", "Linux", "AWS", "Azure"],
        "data_sources": ["Auth Logs", "Cloud Audit Logs"],
        "severity": "Critical",
        "fidelity": "Medium",
        "tags": ["pth", "ptt", "session-token"],
        "intents": {
            "Lateral Movement": {
                "title": "NTLM Authentication With Type-3 Hash But No Interactive Logon",
                "pseudo": "EID 4624 logon type 3 from non-DC source against admin shares with NTLM and no preceding interactive logon for the user. Pass-the-Hash pattern.",
                "hint": {"event": "Logon", "command": "pth", "field": "logon.authentication_package"},
            },
        },
    },
    "T1497": {
        "name": "Virtualization/Sandbox Evasion",
        "platforms": ["Windows", "macOS"],
        "data_sources": ["EDR"],
        "severity": "Medium",
        "fidelity": "Low",
        "tags": ["sandbox-evasion", "anti-vm"],
        "intents": {
            "Defense Evasion": {
                "title": "Process Reads VM/Sandbox Indicators Then Exits Quickly",
                "pseudo": "Process reads HKLM\\SYSTEM\\HardwareConfig\\* (BIOS strings), checks WMI Win32_BIOS / Manufacturer, or scans for VBOX/VMware drivers and exits within 5s.",
                "hint": {"event": "RegistryEvent", "command": "vm-check", "field": "registry.path"},
            },
        },
    },
    "T1220": {
        "name": "XSL Script Processing",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["lolbin", "wmic", "xsl"],
        "intents": {
            "Defense Evasion": {
                "title": "wmic format:xsl Loading Remote XSL",
                "pseudo": "wmic.exe with /format:\"http(s)://\" or any .xsl path outside system32. Squiblytwo XSL-based proxy execution.",
                "hint": {"event": "ProcessCreate", "command": "wmic-xsl", "field": "process.command_line"},
            },
        },
    },

    # ─── Credential Access ──────────────────────────────────────────────
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "platforms": ["Windows", "Network"],
        "data_sources": ["Network IDS", "Sysmon"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["aitm", "llmnr", "responder"],
        "intents": {
            "Credential Access": {
                "title": "LLMNR/NBT-NS Poisoning Indicator",
                "pseudo": "Workstation answering LLMNR (UDP/5355) or NBT-NS (UDP/137) name queries it didn't originate, with rapid SMB/HTTP authentication afterward. Responder/Inveigh.",
                "hint": {"event": "NetworkConnect", "command": "llmnr-poison", "field": "destination.port"},
            },
            "Collection": {
                "title": "ARP Reply Storm to Default Gateway MAC",
                "pseudo": "Single host emitting >100 unsolicited ARP replies per minute claiming gateway IP. ARP-spoof MITM precursor for collection.",
                "hint": {"event": "Arp", "command": "arp-storm", "field": "source.mac"},
            },
        },
    },
    "T1212": {
        "name": "Exploitation for Credential Access",
        "platforms": ["Windows"],
        "data_sources": ["EDR", "Windows Event Log"],
        "severity": "Critical",
        "fidelity": "Medium",
        "tags": ["zerologon", "petitpotam", "exploit"],
        "intents": {
            "Credential Access": {
                "title": "Anonymous NetrServerPasswordSet2 to Domain Controller",
                "pseudo": "Successful NetrServerPasswordSet2 / NetrServerAuthenticate3 from anonymous session against a DC. Zerologon (CVE-2020-1472) signature.",
                "hint": {"event": "RpcCall", "command": "zerologon", "field": "rpc.opnum"},
            },
        },
    },
    "T1187": {
        "name": "Forced Authentication",
        "platforms": ["Windows"],
        "data_sources": ["Network IDS", "Windows Event Log"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["smb", "unc", "ntlm-relay"],
        "intents": {
            "Credential Access": {
                "title": "SMB Connection Following SCF/HTML UNC Trigger",
                "pseudo": "Client SMB connection to external IP within 2s of opening a file or browsing a path. Forced-auth via SCF / .url / HTML img src=\\\\evil.",
                "hint": {"event": "NetworkConnect", "command": "smb-external", "field": "destination.ip"},
            },
        },
    },
    "T1606": {
        "name": "Forge Web Credentials",
        "platforms": ["Azure", "AWS", "Windows"],
        "data_sources": ["Cloud Audit Logs", "ADFS Logs"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["golden-saml", "jwt", "forge"],
        "intents": {
            "Credential Access": {
                "title": "SAML Token Issued With Impossible Lifetime",
                "pseudo": "ADFS / Azure AD token with NotOnOrAfter > 24h, or SignatureCertificate fingerprint not in the published cert set. Golden-SAML forging signal.",
                "hint": {"event": "TokenIssue", "command": "saml-forge", "field": "token.lifetime"},
            },
        },
    },
    "T1111": {
        "name": "Multi-Factor Authentication Interception",
        "platforms": ["Windows", "Network"],
        "data_sources": ["Auth Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["mfa", "intercept"],
        "intents": {
            "Credential Access": {
                "title": "MFA Code Replayed From Multiple Source IPs",
                "pseudo": "Same TOTP / push code accepted from ≥2 distinct source IPs within 90s for the same user. MFA proxy / interception.",
                "hint": {"event": "MfaSuccess", "command": "mfa-replay", "field": "user.name"},
            },
        },
    },
    "T1621": {
        "name": "MFA Request Generation",
        "platforms": ["Okta", "Microsoft 365", "Azure"],
        "data_sources": ["Identity Provider Logs"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["mfa-fatigue", "push-bombing"],
        "intents": {
            "Credential Access": {
                "title": "Repeated MFA Push Denials Followed by Approval",
                "pseudo": "≥5 MFA push denials for the same user in 10m, then a single approval. MFA-fatigue / push-bombing pattern.",
                "hint": {"event": "MfaPush", "command": "push-bombing", "field": "user.name"},
            },
        },
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "EDR", "Auditd"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["lsass", "ntds", "shadowcopy"],
        "intents": {
            "Credential Access": {
                "title": "Process Opening LSASS With PROCESS_VM_READ Access",
                "pseudo": "Sysmon EID 10 ProcessAccess targeting lsass.exe with GrantedAccess containing 0x1000 / 0x40 / 0x1410. Mimikatz / handle-clone style dumping.",
                "hint": {"event": "ProcessAccess", "command": "lsass-read", "field": "process.target.name"},
            },
        },
    },
    "T1649": {
        "name": "Steal or Forge Authentication Certificates",
        "platforms": ["Windows"],
        "data_sources": ["Windows Event Log", "ADCS Logs"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["adcs", "esc1-esc8", "certificate"],
        "intents": {
            "Credential Access": {
                "title": "ADCS Certificate Issued With SAN Override",
                "pseudo": "EID 4886/4887 with explicit SubjectAltName UPN that does not match the requesting account. ADCS ESC1/ESC6 abuse.",
                "hint": {"event": "AdcsIssue", "command": "esc1", "field": "certificate.san"},
            },
        },
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["EDR"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["cookie", "session", "browser"],
        "intents": {
            "Credential Access": {
                "title": "Non-Browser Process Reading Browser Cookie Database",
                "pseudo": "Read of Chrome/Edge \"Network\\Cookies\" SQLite, Firefox cookies.sqlite, or Safari Cookies.binarycookies by a process other than the browser itself.",
                "hint": {"event": "FileAccess", "command": "cookie-steal", "field": "file.path"},
            },
        },
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "platforms": ["Windows", "Linux", "macOS", "AWS", "Azure"],
        "data_sources": ["EDR", "Sysmon", "Auditd"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["credential-files", "registry", "instance-metadata"],
        "intents": {
            "Credential Access": {
                "title": "Recursive Search for Credential Strings in User Profile",
                "pseudo": "findstr / grep / Select-String over ≥20 files searching for password/secret/key/credential within 60s. Mass credential harvest.",
                "hint": {"event": "ProcessCreate", "command": "cred-search", "field": "process.command_line"},
            },
        },
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["EDR", "Sysmon"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["password-manager", "vaultcli", "keychain"],
        "intents": {
            "Credential Access": {
                "title": "Access to Browser/OS Password Store Database",
                "pseudo": "Read of Chrome \"Login Data\", Firefox logins.json, /Library/Keychains/login.keychain, or HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Credentials by a non-browser, non-keyring process.",
                "hint": {"event": "FileAccess", "command": "pw-store", "field": "file.path"},
            },
        },
    },

    # ─── Discovery ──────────────────────────────────────────────────────
    "T1010": {
        "name": "Application Window Discovery",
        "platforms": ["Windows", "macOS"],
        "data_sources": ["EDR"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["window", "enum"],
        "intents": {
            "Discovery": {
                "title": "Process Enumerating Foreground Windows via EnumWindows",
                "pseudo": "Short-lived process calling EnumWindows / GetForegroundWindow / GetWindowText >50 times within 10s. Common screen-aware malware staging.",
                "hint": {"event": "ApiCall", "command": "enum-windows", "field": "api.function"},
            },
        },
    },
    "T1217": {
        "name": "Browser Information Discovery",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["EDR", "Sysmon"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["browser", "history", "bookmarks"],
        "intents": {
            "Discovery": {
                "title": "Non-Browser Process Reading Browser History DB",
                "pseudo": "Read of Chrome \"History\", Firefox places.sqlite or Safari History.db by a process that is not the browser itself.",
                "hint": {"event": "FileAccess", "command": "browser-history", "field": "file.path"},
            },
        },
    },
    "T1580": {
        "name": "Cloud Infrastructure Discovery",
        "platforms": ["AWS", "Azure", "GCP"],
        "data_sources": ["Cloud Audit Logs"],
        "severity": "Low",
        "fidelity": "Medium",
        "tags": ["cloud", "enum", "iam"],
        "intents": {
            "Discovery": {
                "title": "Burst of Describe* / List* Calls From Single Identity",
                "pseudo": "≥30 distinct Describe*/Get*/List* API calls from one identity within 5m and never seen before from that identity. Cloud-recon burst.",
                "hint": {"event": "DescribeAll", "command": "cloud-recon", "field": "userIdentity.arn"},
            },
        },
    },
    "T1526": {
        "name": "Cloud Service Discovery",
        "platforms": ["AWS", "Azure", "GCP", "SaaS"],
        "data_sources": ["Cloud Audit Logs"],
        "severity": "Low",
        "fidelity": "Medium",
        "tags": ["cloud-service", "enum"],
        "intents": {
            "Discovery": {
                "title": "Wide-Scope ListServices / GetServices Without Prior Use",
                "pseudo": "Identity invokes service-enumeration APIs (resourcegroups.ListResources, billing.GetCostAndUsage) for the first time. New tenants of a compromised role.",
                "hint": {"event": "ListServices", "command": "svc-enum", "field": "userIdentity.arn"},
            },
        },
    },
    "T1619": {
        "name": "Cloud Storage Object Discovery",
        "platforms": ["AWS", "Azure", "GCP"],
        "data_sources": ["Cloud Audit Logs"],
        "severity": "Low",
        "fidelity": "Medium",
        "tags": ["s3", "blob", "bucket"],
        "intents": {
            "Discovery": {
                "title": "Mass ListObjects Across Many Buckets",
                "pseudo": "ListObjects/ListBlobs against ≥10 distinct buckets/containers from the same identity in 10m. Bucket-walking pre-exfil.",
                "hint": {"event": "ListObjects", "command": "bucket-walk", "field": "userIdentity.arn"},
            },
        },
    },
    "T1613": {
        "name": "Container and Resource Discovery",
        "platforms": ["Kubernetes"],
        "data_sources": ["Kubernetes Audit Logs"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["k8s", "kubectl", "enum"],
        "intents": {
            "Discovery": {
                "title": "Kubectl get all from Inside a Pod",
                "pseudo": "kubectl get all / kubectl get pods --all-namespaces issued from an in-cluster service account that does not normally enumerate.",
                "hint": {"event": "K8sApi", "command": "k8s-enum", "field": "objectRef.resource"},
            },
        },
    },
    "T1622": {
        "name": "Debugger Evasion",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["EDR"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["anti-debug"],
        "intents": {
            "Discovery": {
                "title": "Process Calls IsDebuggerPresent / CheckRemoteDebuggerPresent",
                "pseudo": "Non-debugger process invokes IsDebuggerPresent, CheckRemoteDebuggerPresent or NtQueryInformationProcess (ProcessDebugPort).",
                "hint": {"event": "ApiCall", "command": "anti-debug", "field": "api.function"},
            },
        },
    },
    "T1652": {
        "name": "Device Driver Discovery",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["driver", "enum"],
        "intents": {
            "Discovery": {
                "title": "driverquery.exe Executed by Non-Admin Context",
                "pseudo": "driverquery.exe / sc.exe query type=driver / fltmc.exe filters from a user-context process. Pre-rootkit reconnaissance.",
                "hint": {"event": "ProcessCreate", "command": "driverquery", "field": "process.executable"},
            },
        },
    },
    "T1482": {
        "name": "Domain Trust Discovery",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["domain", "trust", "ad"],
        "intents": {
            "Discovery": {
                "title": "nltest /domain_trusts or Get-ADTrust Executed",
                "pseudo": "nltest.exe /domain_trusts / /trusted_domains, or Get-ADTrust PowerShell cmdlet from non-admin context.",
                "hint": {"event": "ProcessCreate", "command": "trust-enum", "field": "process.command_line"},
            },
        },
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "Auditd"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["dir-enum"],
        "intents": {
            "Discovery": {
                "title": "Recursive Directory Walk of User Profile by Unusual Process",
                "pseudo": "Process enumerates ≥1000 paths under %USERPROFILE% / /home/* in 60s. Pre-staging or cred-harvest recon.",
                "hint": {"event": "FileAccess", "command": "dir-walk", "field": "process.executable"},
            },
        },
    },
    "T1615": {
        "name": "Group Policy Discovery",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["gpo", "enum"],
        "intents": {
            "Discovery": {
                "title": "gpresult / Get-GPO Discovery from Workstation",
                "pseudo": "gpresult.exe /h or Get-GPO / Get-GPOReport invoked outside admin desktops. Pre-attack GPO reconnaissance.",
                "hint": {"event": "ProcessCreate", "command": "gpresult", "field": "process.command_line"},
            },
        },
    },
    "T1654": {
        "name": "Log Enumeration",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Auditd"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["log-enum", "wevtutil"],
        "intents": {
            "Discovery": {
                "title": "wevtutil el or Get-WinEvent Enumerating All Logs",
                "pseudo": "wevtutil el / Get-WinEvent -ListLog * / journalctl --list-boots invoked from non-admin / non-engineer context.",
                "hint": {"event": "ProcessCreate", "command": "log-enum", "field": "process.command_line"},
            },
        },
    },
    "T1046": {
        "name": "Network Service Discovery",
        "platforms": ["Network", "Windows", "Linux"],
        "data_sources": ["Firewall", "Sysmon"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["scan", "nmap"],
        "intents": {
            "Discovery": {
                "title": "Internal Host Scanning Many Ports/Hosts",
                "pseudo": "Single internal source touching ≥50 distinct ports across ≥10 distinct destinations within 5m. Internal port scan.",
                "hint": {"event": "NetworkConnect", "command": "internal-scan", "field": "source.ip"},
            },
        },
    },
    "T1135": {
        "name": "Network Share Discovery",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Windows Event Log"],
        "severity": "Low",
        "fidelity": "Medium",
        "tags": ["share-enum"],
        "intents": {
            "Discovery": {
                "title": "net view / net share Burst Across Multiple Hosts",
                "pseudo": "net view \\\\<host> issued against ≥10 distinct hosts in 5m, or smbclient -L mass-enumeration on Linux.",
                "hint": {"event": "ProcessCreate", "command": "share-enum", "field": "process.command_line"},
            },
        },
    },
    "T1040": {
        "name": "Network Sniffing",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["EDR", "Sysmon", "Auditd"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["sniffer", "tcpdump", "pcap"],
        "intents": {
            "Discovery": {
                "title": "Packet Capture Tool Execution",
                "pseudo": "tcpdump / tshark / windump / pktmon / dumpcap launched outside known network-engineering context.",
                "hint": {"event": "ProcessCreate", "command": "pcap", "field": "process.executable"},
            },
            "Credential Access": {
                "title": "Promiscuous Mode Enabled on Network Interface",
                "pseudo": "Auditd PROMISC event or Windows event indicating NIC entered promiscuous mode by a non-monitoring process.",
                "hint": {"event": "Promiscuous", "command": "promisc", "field": "interface.mode"},
            },
        },
    },
    "T1201": {
        "name": "Password Policy Discovery",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Auditd"],
        "severity": "Low",
        "fidelity": "Medium",
        "tags": ["enum", "password-policy"],
        "intents": {
            "Discovery": {
                "title": "net accounts / Get-ADDefaultDomainPasswordPolicy Executed",
                "pseudo": "net accounts /domain, Get-ADDefaultDomainPasswordPolicy or chage -l / pwpolicy from a workstation. Pre-spray reconnaissance.",
                "hint": {"event": "ProcessCreate", "command": "pwpolicy", "field": "process.command_line"},
            },
        },
    },
    "T1120": {
        "name": "Peripheral Device Discovery",
        "platforms": ["Windows", "macOS"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["devices", "enum"],
        "intents": {
            "Discovery": {
                "title": "WMI Enumeration of Win32_USBHub / Win32_PnPEntity",
                "pseudo": "Get-WmiObject / Get-CimInstance over Win32_USBHub, Win32_PnPEntity, Win32_LogicalDisk from non-IT context.",
                "hint": {"event": "WmiEvent", "command": "device-enum", "field": "wmi.query"},
            },
        },
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "platforms": ["Windows", "Linux", "AWS", "Azure"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Medium",
        "tags": ["groups", "enum"],
        "intents": {
            "Discovery": {
                "title": "Domain Admin Group Enumeration via net group",
                "pseudo": "net group \"Domain Admins\" /domain, Get-ADGroupMember \"Domain Admins\", or aws iam list-groups by an unprivileged identity.",
                "hint": {"event": "ProcessCreate", "command": "group-enum", "field": "process.command_line"},
            },
        },
    },
    "T1057": {
        "name": "Process Discovery",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "Auditd"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["process", "enum"],
        "intents": {
            "Discovery": {
                "title": "tasklist / ps Enumerating EDR & AV Processes",
                "pseudo": "tasklist /v or ps -ef | grep with patterns for sentinel*, csagent, MsMpEng, falcon, defender, carbonblack — survey for security tools.",
                "hint": {"event": "ProcessCreate", "command": "process-enum", "field": "process.command_line"},
            },
        },
    },
    "T1012": {
        "name": "Query Registry",
        "platforms": ["Windows"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Medium",
        "tags": ["registry", "enum"],
        "intents": {
            "Discovery": {
                "title": "reg query of Sensitive Registry Hives",
                "pseudo": "reg.exe query against HKLM\\SAM, HKLM\\SECURITY, HKLM\\System\\CurrentControlSet\\Control\\Lsa, or HKLM\\Software\\Microsoft\\Windows Defender.",
                "hint": {"event": "ProcessCreate", "command": "reg-query", "field": "process.command_line"},
            },
        },
    },
    "T1018": {
        "name": "Remote System Discovery",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["enum", "remote"],
        "intents": {
            "Discovery": {
                "title": "Mass Reverse-DNS / arp -a Enumeration",
                "pseudo": "Process emitting >50 PTR DNS queries in 30s, or arp -a / nbtstat -A across a /24. Network mapping.",
                "hint": {"event": "Dns", "command": "ptr-burst", "field": "dns.question.type"},
            },
        },
    },
    "T1518": {
        "name": "Software Discovery",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["software-enum", "av-check"],
        "intents": {
            "Discovery": {
                "title": "wmic product where / dpkg -l for Security Software",
                "pseudo": "wmic.exe product where, Get-ItemProperty Uninstall, dpkg -l, or rpm -qa filtered for AV/EDR vendor names.",
                "hint": {"event": "ProcessCreate", "command": "sw-enum", "field": "process.command_line"},
            },
        },
    },
    "T1082": {
        "name": "System Information Discovery",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["enum"],
        "intents": {
            "Discovery": {
                "title": "systeminfo / hostnamectl / uname Burst",
                "pseudo": "Multiple system-info commands (systeminfo, hostnamectl, uname -a, ver, whoami) within 60s on a single host.",
                "hint": {"event": "ProcessCreate", "command": "sysinfo", "field": "process.command_line"},
            },
        },
    },
    "T1614": {
        "name": "System Location Discovery",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["geo", "locale"],
        "intents": {
            "Discovery": {
                "title": "GetUserGeoID / locale Probe in Short-Lived Process",
                "pseudo": "Process queries GetUserGeoID, GetSystemDefaultLCID, or HKCU\\Control Panel\\International and exits within 10s. Geo-keyed payload.",
                "hint": {"event": "ApiCall", "command": "geo-probe", "field": "api.function"},
            },
        },
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["ipconfig", "ifconfig"],
        "intents": {
            "Discovery": {
                "title": "ipconfig / route / arp -a Burst",
                "pseudo": "ipconfig /all, route print, arp -a, ifconfig, ip addr issued sequentially within 30s. Network-config recon.",
                "hint": {"event": "ProcessCreate", "command": "netconfig", "field": "process.command_line"},
            },
        },
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["netstat", "enum"],
        "intents": {
            "Discovery": {
                "title": "netstat / ss Enumerated Repeatedly in Short Window",
                "pseudo": "netstat -ano / ss -tulnp / lsof -i invoked ≥3 times within 60s. Active-connection survey.",
                "hint": {"event": "ProcessCreate", "command": "netstat", "field": "process.command_line"},
            },
        },
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["whoami", "enum"],
        "intents": {
            "Discovery": {
                "title": "whoami /all Followed Quickly by Discovery Tooling",
                "pseudo": "whoami /all, id, query user, quser, w issued within 30s of new logon — typical first-step recon.",
                "hint": {"event": "ProcessCreate", "command": "whoami", "field": "process.command_line"},
            },
        },
    },
    "T1007": {
        "name": "System Service Discovery",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["services", "enum"],
        "intents": {
            "Discovery": {
                "title": "sc query / Get-Service Burst",
                "pseudo": "sc.exe query, Get-Service, systemctl list-units invoked from non-admin context with no preceding service interaction.",
                "hint": {"event": "ProcessCreate", "command": "svc-enum", "field": "process.command_line"},
            },
        },
    },
    "T1124": {
        "name": "System Time Discovery",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon"],
        "severity": "Low",
        "fidelity": "Low",
        "tags": ["time", "enum"],
        "intents": {
            "Discovery": {
                "title": "net time / w32tm Probed by Unusual Process",
                "pseudo": "net time \\\\<host>, w32tm /query /status, or date / hwclock from a non-admin user-context process.",
                "hint": {"event": "ProcessCreate", "command": "time-probe", "field": "process.command_line"},
            },
        },
    },
    "T1087": {
        "name": "Account Discovery",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Windows Event Log"],
        "severity": "Low",
        "fidelity": "Medium",
        "tags": ["account-enum"],
        "intents": {
            "Discovery": {
                "title": "net user / Get-ADUser Burst",
                "pseudo": "net user /domain, Get-ADUser -Filter *, dsquery user from a non-admin desktop. Domain account harvest.",
                "hint": {"event": "ProcessCreate", "command": "user-enum", "field": "process.command_line"},
            },
        },
    },

    # ─── Lateral Movement ───────────────────────────────────────────────
    "T1210": {
        "name": "Exploitation of Remote Services",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Network IDS", "Windows Event Log"],
        "severity": "Critical",
        "fidelity": "Medium",
        "tags": ["exploit", "smb", "wmi"],
        "intents": {
            "Lateral Movement": {
                "title": "Anomalous SMB Pipe Opens to Remote Hosts",
                "pseudo": "Single source opens \\PIPE\\srvsvc, \\PIPE\\samr, \\PIPE\\netlogon to ≥3 distinct remote hosts within 5m without preceding admin auth. EternalBlue / Zerologon-style probing.",
                "hint": {"event": "NetworkConnect", "command": "smb-pipe-fanout", "field": "destination.ip"},
            },
        },
    },
    "T1534": {
        "name": "Internal Spearphishing",
        "platforms": ["Microsoft 365", "Google Workspace"],
        "data_sources": ["Email Gateway", "SaaS Audit Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["phishing", "internal", "email"],
        "intents": {
            "Lateral Movement": {
                "title": "Single Internal Sender Mailing ≥20 Internal Recipients With Link",
                "pseudo": "Internal account sends ≥20 messages with a clickable URL to internal recipients within 30m, especially after a recent password reset or new-device sign-in. Account-takeover-driven internal phish.",
                "hint": {"event": "EmailSent", "command": "internal-phish", "field": "email.from.user"},
            },
        },
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Network IDS"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["smb", "scp", "tool-transfer"],
        "intents": {
            "Lateral Movement": {
                "title": "Executable Written via SMB to Admin$ Share",
                "pseudo": "FileCreate of .exe/.dll/.bin under \\\\<host>\\ADMIN$ or \\\\<host>\\C$\\Windows\\* by a remote logon session. Classic lateral payload drop.",
                "hint": {"event": "FileCreate", "command": "admin-share-write", "field": "file.path"},
            },
        },
    },
    "T1563": {
        "name": "Remote Service Session Hijacking",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Windows Event Log", "Auditd"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["rdp-hijack", "ssh-hijack"],
        "intents": {
            "Lateral Movement": {
                "title": "tscon Used to Hijack Disconnected RDP Session",
                "pseudo": "tscon.exe invoked targeting another user's session ID without /password. Free-RDP-session takeover when invoker is SYSTEM.",
                "hint": {"event": "ProcessCreate", "command": "tscon", "field": "process.command_line"},
            },
        },
    },
    "T1021": {
        "name": "Remote Services",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Windows Event Log", "Auditd"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["rdp", "winrm", "ssh"],
        "intents": {
            "Lateral Movement": {
                "title": "WinRM / WMI Remote Execution from Non-Admin Workstation",
                "pseudo": "wsmprovhost.exe / WmiPrvSE.exe spawning cmd/powershell with NetworkLogon initiated by a workstation that is not in the IT admin OU.",
                "hint": {"event": "ProcessCreate", "command": "winrm-exec", "field": "process.parent.name"},
            },
        },
    },
    "T1080": {
        "name": "Taint Shared Content",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Auditd"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["share", "taint"],
        "intents": {
            "Lateral Movement": {
                "title": "Executable Written to Departmental Network Share",
                "pseudo": "New .exe / .lnk / .scr written to a departmental file share (Finance, HR) by a non-admin user. Worm-like content tainting.",
                "hint": {"event": "FileCreate", "command": "share-taint", "field": "file.path"},
            },
        },
    },

    # ─── Collection ─────────────────────────────────────────────────────
    "T1560": {
        "name": "Archive Collected Data",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["archive", "rar", "7z", "zip"],
        "intents": {
            "Collection": {
                "title": "Archive Tool Producing Password-Protected Volume",
                "pseudo": "rar.exe / 7z.exe / zip with -p (password) or -hp (header encrypt) writing >50MB output. Pre-exfil staging.",
                "hint": {"event": "ProcessCreate", "command": "archive-pw", "field": "process.command_line"},
            },
        },
    },
    "T1123": {
        "name": "Audio Capture",
        "platforms": ["Windows", "macOS"],
        "data_sources": ["EDR"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["mic", "audio"],
        "intents": {
            "Collection": {
                "title": "Non-Conferencing Process Activating Microphone",
                "pseudo": "Audio device opened via WASAPI / CoreAudio by a process not in the conferencing/recording allowlist (Teams, Zoom, OBS, Audacity).",
                "hint": {"event": "DeviceAccess", "command": "mic-on", "field": "device.type"},
            },
        },
    },
    "T1119": {
        "name": "Automated Collection",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["scripted", "harvest"],
        "intents": {
            "Collection": {
                "title": "Scripted File Globbing of User Documents",
                "pseudo": "PowerShell / bash recursively globbing *.doc*, *.xls*, *.pdf, *.txt, *.kdbx under user profiles, then copying to a staging dir.",
                "hint": {"event": "ProcessCreate", "command": "doc-harvest", "field": "process.command_line"},
            },
        },
    },
    "T1185": {
        "name": "Browser Session Hijacking",
        "platforms": ["Windows", "macOS"],
        "data_sources": ["EDR"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["browser", "session", "hijack"],
        "intents": {
            "Collection": {
                "title": "Process Attaching to Browser via Debug/Inspector Port",
                "pseudo": "Connection to chrome --remote-debugging-port (9222) or msedge --remote-debugging-pipe by a non-developer process.",
                "hint": {"event": "NetworkConnect", "command": "browser-debug", "field": "destination.port"},
            },
        },
    },
    "T1115": {
        "name": "Clipboard Data",
        "platforms": ["Windows", "macOS"],
        "data_sources": ["EDR"],
        "severity": "Medium",
        "fidelity": "High",
        "tags": ["clipboard"],
        "intents": {
            "Collection": {
                "title": "Repeated Clipboard Reads From Non-UI Process",
                "pseudo": "GetClipboardData / NSPasteboard reads ≥10 times in 60s by a process with no UI. Crypto-clipper / password-grab.",
                "hint": {"event": "ApiCall", "command": "clipboard-poll", "field": "api.function"},
            },
        },
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "platforms": ["AWS", "Azure", "GCP"],
        "data_sources": ["Cloud Audit Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["s3", "blob", "exfil-precursor"],
        "intents": {
            "Collection": {
                "title": "Bulk GetObject from Sensitive Bucket",
                "pseudo": "≥1000 GetObject calls in 5m from one identity against a tagged-sensitive bucket, or from a region the identity has never used.",
                "hint": {"event": "GetObject", "command": "bulk-get", "field": "userIdentity.arn"},
            },
        },
    },
    "T1602": {
        "name": "Data from Configuration Repository",
        "platforms": ["Network"],
        "data_sources": ["Network Device Logs"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["snmp", "tftp", "config"],
        "intents": {
            "Collection": {
                "title": "TFTP Transfer of running-config or startup-config",
                "pseudo": "Network device emits copy running-config tftp:// to a non-management IP, or SNMP bulk-walk against private OIDs from outside management subnet.",
                "hint": {"event": "NetdevConfig", "command": "config-pull", "field": "device.config"},
            },
        },
    },
    "T1213": {
        "name": "Data from Information Repositories",
        "platforms": ["SaaS"],
        "data_sources": ["SaaS Audit Logs"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["confluence", "sharepoint", "wiki"],
        "intents": {
            "Collection": {
                "title": "Bulk Wiki/Confluence Page Reads by Single User",
                "pseudo": "≥100 distinct page views or downloads in 10m from one user in Confluence/SharePoint/Notion. Aggressive doc harvest.",
                "hint": {"event": "PageView", "command": "wiki-burst", "field": "user.name"},
            },
        },
    },
    "T1005": {
        "name": "Data from Local System",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["local-files", "harvest"],
        "intents": {
            "Collection": {
                "title": "Sensitive Directory Read by Unusual Process",
                "pseudo": "Process not in user-shell allowlist reads ≥50 files under Desktop, Documents, Downloads in 60s.",
                "hint": {"event": "FileAccess", "command": "user-doc-read", "field": "file.path"},
            },
        },
    },
    "T1039": {
        "name": "Data from Network Shared Drive",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Windows Event Log"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["smb", "share-read"],
        "intents": {
            "Collection": {
                "title": "Burst Reads from Departmental Share by Single User",
                "pseudo": "EID 5145 share access ≥500 unique files within 10m from one user against HR/Finance/Legal share.",
                "hint": {"event": "ShareAccess", "command": "share-bulk-read", "field": "user.name"},
            },
        },
    },
    "T1025": {
        "name": "Data from Removable Media",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "Auditd"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["usb", "removable"],
        "intents": {
            "Collection": {
                "title": "Mass File Read from Removable Volume",
                "pseudo": "≥100 file reads from a DriveType=2 (removable) volume by user-shell process in 5m.",
                "hint": {"event": "FileAccess", "command": "usb-read", "field": "file.path"},
            },
        },
    },
    "T1074": {
        "name": "Data Staged",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "Medium",
        "fidelity": "High",
        "tags": ["staging", "archive"],
        "intents": {
            "Collection": {
                "title": "Single Folder Growing >100MB With Archive Files in 30m",
                "pseudo": "Directory under %TEMP%, %APPDATA%, /tmp accumulates >100MB of .rar/.zip/.7z/.tar.gz in 30m. Pre-exfil staging.",
                "hint": {"event": "FileCreate", "command": "stage-grow", "field": "file.path"},
            },
        },
    },
    "T1114": {
        "name": "Email Collection",
        "platforms": ["Microsoft 365", "Google Workspace"],
        "data_sources": ["SaaS Audit Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["email", "mailbox"],
        "intents": {
            "Collection": {
                "title": "Mailbox Auto-Forward Rule Created to External Domain",
                "pseudo": "New-InboxRule / message-rule creation with ForwardTo / RedirectTo to a non-corporate domain. Classic mailbox theft pattern.",
                "hint": {"event": "InboxRule", "command": "auto-forward", "field": "rule.action"},
            },
        },
    },
    "T1056": {
        "name": "Input Capture",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["EDR"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["keylogger", "hook"],
        "intents": {
            "Collection": {
                "title": "SetWindowsHookEx WH_KEYBOARD_LL Installed",
                "pseudo": "EDR signal of low-level keyboard hook from a non-input-tooling process. Classic user-mode keylogger primitive.",
                "hint": {"event": "ApiCall", "command": "keyhook", "field": "api.function"},
            },
        },
    },
    "T1113": {
        "name": "Screen Capture",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["EDR"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["screenshot", "spying"],
        "intents": {
            "Collection": {
                "title": "Repeated BitBlt / CGWindowListCreateImage Calls",
                "pseudo": "Process invokes BitBlt / PrintWindow / CGWindowListCreateImage ≥10 times within 60s. Periodic screen capture.",
                "hint": {"event": "ApiCall", "command": "screen-cap", "field": "api.function"},
            },
        },
    },
    "T1125": {
        "name": "Video Capture",
        "platforms": ["Windows", "macOS"],
        "data_sources": ["EDR"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["webcam", "video"],
        "intents": {
            "Collection": {
                "title": "Camera Device Activated by Non-Conferencing Process",
                "pseudo": "Webcam opened via Media Foundation / AVFoundation by a process not in the conferencing/streaming allowlist (Teams, Zoom, OBS).",
                "hint": {"event": "DeviceAccess", "command": "cam-on", "field": "device.type"},
            },
        },
    },

    # ─── Command and Control ────────────────────────────────────────────
    "T1071": {
        "name": "Application Layer Protocol",
        "platforms": ["Network"],
        "data_sources": ["Firewall", "Network IDS", "DNS Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["c2", "http", "dns"],
        "intents": {
            "Command and Control": {
                "title": "Periodic POST Beacon to Newly Registered Domain",
                "pseudo": "HTTP POST every 60s ±10s to a domain registered <30 days ago, with response sizes 0–512 bytes. Beaconing to staged C2.",
                "hint": {"event": "Http", "command": "beacon-post", "field": "url.domain"},
            },
        },
    },
    "T1092": {
        "name": "Communication Through Removable Media",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Auditd"],
        "severity": "Medium",
        "fidelity": "High",
        "tags": ["air-gap", "usb-c2"],
        "intents": {
            "Command and Control": {
                "title": "Hidden File Polled on Removable Volume",
                "pseudo": "Repeated reads of a hidden file on a DriveType=2 volume by a long-running process. Air-gap C2 via shared USB.",
                "hint": {"event": "FileAccess", "command": "usb-poll", "field": "file.path"},
            },
        },
    },
    "T1659": {
        "name": "Content Injection",
        "platforms": ["Network"],
        "data_sources": ["Network IDS"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["mitm", "inject"],
        "intents": {
            "Command and Control": {
                "title": "HTTP Response Body Modified Mid-Path",
                "pseudo": "TLS-stripped or plaintext HTTP response with size mismatch vs. server-declared Content-Length, or known-good page hash mismatch from gateway.",
                "hint": {"event": "Http", "command": "content-mismatch", "field": "http.response.body.bytes"},
            },
        },
    },
    "T1132": {
        "name": "Data Encoding",
        "platforms": ["Network"],
        "data_sources": ["Network IDS"],
        "severity": "Medium",
        "fidelity": "Low",
        "tags": ["base64", "encoded-c2"],
        "intents": {
            "Command and Control": {
                "title": "High-Entropy Base64 Body in Outbound HTTP",
                "pseudo": "HTTP body with Shannon entropy > 5.0 and length > 256 sent to non-cdn destinations. Encoded C2 traffic.",
                "hint": {"event": "Http", "command": "b64-body", "field": "http.request.body"},
            },
        },
    },
    "T1001": {
        "name": "Data Obfuscation",
        "platforms": ["Network"],
        "data_sources": ["Network IDS"],
        "severity": "Medium",
        "fidelity": "Low",
        "tags": ["obfuscation"],
        "intents": {
            "Command and Control": {
                "title": "TLS JA3 Fingerprint Anomalous for Process",
                "pseudo": "Outbound TLS connection with JA3 / JA3S not seen before for the originating process binary. Custom-stack C2.",
                "hint": {"event": "Tls", "command": "ja3-anomaly", "field": "tls.client.ja3"},
            },
        },
    },
    "T1568": {
        "name": "Dynamic Resolution",
        "platforms": ["Network"],
        "data_sources": ["DNS Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["dga", "fast-flux"],
        "intents": {
            "Command and Control": {
                "title": "DNS Query to Algorithmically-Generated Domain",
                "pseudo": "DNS query to a high-entropy domain (>4.0 entropy, length 12–24, no dictionary words). DGA candidate.",
                "hint": {"event": "Dns", "command": "dga", "field": "dns.question.name"},
            },
        },
    },
    "T1573": {
        "name": "Encrypted Channel",
        "platforms": ["Network"],
        "data_sources": ["Network IDS"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["tls", "encrypted-c2"],
        "intents": {
            "Command and Control": {
                "title": "Self-Signed TLS Certificate on Outbound Beacon",
                "pseudo": "Outbound TLS to non-cdn IP with self-signed cert and unusual subject, repeated session every 30–120s.",
                "hint": {"event": "Tls", "command": "self-signed", "field": "tls.server.certificate.subject"},
            },
        },
    },
    "T1008": {
        "name": "Fallback Channels",
        "platforms": ["Network"],
        "data_sources": ["Network IDS"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["fallback", "c2"],
        "intents": {
            "Command and Control": {
                "title": "Process Switching Between Multiple Outbound Endpoints",
                "pseudo": "Single process initiates outbound to ≥3 distinct unrelated domains within 5m using identical request cadence.",
                "hint": {"event": "NetworkConnect", "command": "fallback", "field": "destination.domain"},
            },
        },
    },
    "T1665": {
        "name": "Hide Infrastructure",
        "platforms": ["Network"],
        "data_sources": ["DNS Logs"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["fast-flux", "domain-fronting"],
        "intents": {
            "Command and Control": {
                "title": "TLS SNI Disagrees With HTTP Host Header",
                "pseudo": "TLS SNI = popular CDN (cloudfront, akamai), HTTP Host header = unrelated domain. Domain-fronting indicator.",
                "hint": {"event": "Http", "command": "domain-front", "field": "tls.client.server_name"},
            },
        },
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Auditd"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["download", "tool"],
        "intents": {
            "Command and Control": {
                "title": "Living-Off-the-Land Binary Downloading From Internet",
                "pseudo": "certutil.exe -urlcache -f, bitsadmin /transfer, curl, wget, Invoke-WebRequest fetching from internet to %TEMP%/%APPDATA%.",
                "hint": {"event": "ProcessCreate", "command": "lolbin-download", "field": "process.command_line"},
            },
        },
    },
    "T1104": {
        "name": "Multi-Stage Channels",
        "platforms": ["Network"],
        "data_sources": ["Network IDS"],
        "severity": "Medium",
        "fidelity": "Low",
        "tags": ["multi-stage"],
        "intents": {
            "Command and Control": {
                "title": "Two-Domain Beacon Pattern (Stage1 → Stage2)",
                "pseudo": "Outbound to one domain, then within 5m a second outbound to a different domain with markedly different cadence/cert fingerprint, from same process.",
                "hint": {"event": "NetworkConnect", "command": "multi-stage", "field": "destination.domain"},
            },
        },
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "platforms": ["Network"],
        "data_sources": ["Firewall", "Network IDS"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["icmp-c2", "raw-tcp"],
        "intents": {
            "Command and Control": {
                "title": "Sustained ICMP With Large Payload",
                "pseudo": "ICMP echo with payload > 64 bytes sustained for >10m to single external IP. ICMP tunnel.",
                "hint": {"event": "Icmp", "command": "icmp-tunnel", "field": "icmp.payload.size"},
            },
        },
    },
    "T1571": {
        "name": "Non-Standard Port",
        "platforms": ["Network"],
        "data_sources": ["Firewall"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["non-standard-port"],
        "intents": {
            "Command and Control": {
                "title": "HTTP/TLS on Unexpected Port",
                "pseudo": "TLS handshake or HTTP traffic on port not in [80,443,8080,8443] going to external IP from a workstation.",
                "hint": {"event": "Tls", "command": "weird-port", "field": "destination.port"},
            },
        },
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "platforms": ["Network"],
        "data_sources": ["DNS Logs", "Firewall"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["tunnel", "dns-tunnel", "ssh-tunnel"],
        "intents": {
            "Command and Control": {
                "title": "DNS Tunnel Indicator (High TXT Record Volume)",
                "pseudo": "Single client emits ≥50 DNS TXT queries to one zone in 5m, with average label length > 30. DNS tunneling.",
                "hint": {"event": "Dns", "command": "dns-txt-burst", "field": "dns.question.type"},
            },
        },
    },
    "T1090": {
        "name": "Proxy",
        "platforms": ["Network"],
        "data_sources": ["Firewall"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["proxy", "tor", "socks"],
        "intents": {
            "Command and Control": {
                "title": "Outbound Connection to Tor Entry Node",
                "pseudo": "Connection from internal source to a known Tor relay IP (TorDNSEL feed) on port 443/9001. Anonymizing-proxy C2.",
                "hint": {"event": "NetworkConnect", "command": "tor", "field": "destination.ip"},
            },
        },
    },
    "T1219": {
        "name": "Remote Access Software",
        "platforms": ["Windows", "macOS"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["rmm", "remote-access"],
        "intents": {
            "Command and Control": {
                "title": "Unsanctioned Remote-Access Tool Execution",
                "pseudo": "Process names matching anydesk, teamviewer, splashtop, screenconnect, atera, ngrok, gotomypc on a host where those products are not deployed by IT.",
                "hint": {"event": "ProcessCreate", "command": "rmm-rogue", "field": "process.name"},
            },
        },
    },
    "T1102": {
        "name": "Web Service",
        "platforms": ["Network"],
        "data_sources": ["DNS Logs", "Firewall"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["paste", "github", "social"],
        "intents": {
            "Command and Control": {
                "title": "Programmatic Access to Public Paste/Drive Service",
                "pseudo": "Non-browser process connecting to pastebin.com, raw.githubusercontent.com, hastebin, paste.ee, or telegram-bot API. Web-service C2.",
                "hint": {"event": "Http", "command": "paste-c2", "field": "url.domain"},
            },
        },
    },

    # ─── Exfiltration ───────────────────────────────────────────────────
    "T1020": {
        "name": "Automated Exfiltration",
        "platforms": ["Network"],
        "data_sources": ["Firewall", "EDR"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["scripted-exfil"],
        "intents": {
            "Exfiltration": {
                "title": "Scheduled Outbound Burst Following Local Archive Creation",
                "pseudo": "Within 30m of an archive .rar/.zip creation in %TEMP%, the same host emits >100MB outbound to a single external destination.",
                "hint": {"event": "NetworkConnect", "command": "auto-exfil", "field": "network.bytes_sent"},
            },
        },
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "platforms": ["Network"],
        "data_sources": ["Firewall", "Network IDS"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["exfil-c2"],
        "intents": {
            "Exfiltration": {
                "title": "Outbound Volume Spike on Existing C2 Beacon",
                "pseudo": "Established outbound session previously beaconing <1MB/h suddenly transfers >50MB in 10m. Exfil over C2.",
                "hint": {"event": "NetworkConnect", "command": "c2-bulk", "field": "network.bytes_sent"},
            },
        },
    },
    "T1011": {
        "name": "Exfiltration Over Other Network Medium",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["EDR"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["bluetooth", "wifi-exfil"],
        "intents": {
            "Exfiltration": {
                "title": "Large File Transfer Over Bluetooth OBEX",
                "pseudo": "Bluetooth OBEX FTP/OPP transfer >10MB to a non-paired device, or rogue Wi-Fi tether process active during file write.",
                "hint": {"event": "DeviceTransfer", "command": "bt-exfil", "field": "device.protocol"},
            },
        },
    },
    "T1052": {
        "name": "Exfiltration Over Physical Medium",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Auditd"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["usb-exfil"],
        "intents": {
            "Exfiltration": {
                "title": "Large Write to Removable Volume in Short Window",
                "pseudo": ">100MB total bytes written by single process to a DriveType=2 volume within 5m.",
                "hint": {"event": "FileWrite", "command": "usb-exfil", "field": "file.path"},
            },
        },
    },
    "T1029": {
        "name": "Scheduled Transfer",
        "platforms": ["Network"],
        "data_sources": ["Firewall"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["schedule", "exfil"],
        "intents": {
            "Exfiltration": {
                "title": "Periodic Off-Hours Outbound Bulk Transfer",
                "pseudo": "Outbound transfer >25MB to same external destination at consistent intervals (±10m) between 0100–0500 local. Scheduled exfil.",
                "hint": {"event": "NetworkConnect", "command": "off-hours-bulk", "field": "destination.ip"},
            },
        },
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "platforms": ["Network"],
        "data_sources": ["DNS Logs", "Firewall"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["dns-exfil", "ftp"],
        "intents": {
            "Exfiltration": {
                "title": "Large DNS TXT/NULL Query Burst to Single Zone",
                "pseudo": "Sustained DNS queries with high label entropy and total payload > 5MB to a single zone in 30m.",
                "hint": {"event": "Dns", "command": "dns-exfil", "field": "dns.question.name"},
            },
        },
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "platforms": ["Network"],
        "data_sources": ["Firewall", "Web Proxy"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["dropbox", "cloud-exfil"],
        "intents": {
            "Exfiltration": {
                "title": "Bulk Upload to Personal Cloud Storage",
                "pseudo": ">25MB POST/PUT to dropbox.com, drive.google.com, mega.nz, transfer.sh, file.io from a workstation outside of approved cloud-backup tools.",
                "hint": {"event": "Http", "command": "cloud-upload", "field": "url.domain"},
            },
        },
    },

    # ─── Impact ─────────────────────────────────────────────────────────
    "T1531": {
        "name": "Account Access Removal",
        "platforms": ["Windows", "Linux", "AWS", "Azure"],
        "data_sources": ["Auth Logs", "Cloud Audit Logs"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["account-lockout", "denial"],
        "intents": {
            "Impact": {
                "title": "Mass Password Reset / Account Disable Within 10m",
                "pseudo": "≥10 password resets / Disable-ADAccount / aws iam delete-login-profile within 10m by single identity.",
                "hint": {"event": "PasswordReset", "command": "mass-disable", "field": "actor.user.name"},
            },
        },
    },
    "T1485": {
        "name": "Data Destruction",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Auditd"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["wiper", "delete"],
        "intents": {
            "Impact": {
                "title": "Mass File Deletion or Overwrite of User Data",
                "pseudo": "Single process deleting/overwriting ≥500 files under user profiles or shared drives in 5m. Wiper / sabotage.",
                "hint": {"event": "FileDelete", "command": "mass-delete", "field": "process.executable"},
            },
        },
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["ransomware", "encrypt"],
        "intents": {
            "Impact": {
                "title": "Mass Rename With Ransom Extension and Note Drop",
                "pseudo": "≥100 files renamed to add an extension that matches no known software, in same directory tree as a new README/HOW_TO_RECOVER file. Ransomware.",
                "hint": {"event": "FileRename", "command": "ransom-rename", "field": "file.extension"},
            },
        },
    },
    "T1565": {
        "name": "Data Manipulation",
        "platforms": ["Windows", "Linux", "AWS"],
        "data_sources": ["Auditd", "Sysmon", "Cloud Audit Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["manipulation", "integrity"],
        "intents": {
            "Impact": {
                "title": "Modification of Financial / Audit Records by Non-App Identity",
                "pseudo": "UPDATE/DELETE on financial or audit tables by a database account outside the application service account allowlist.",
                "hint": {"event": "DbWrite", "command": "data-tamper", "field": "db.user"},
            },
        },
    },
    "T1491": {
        "name": "Defacement",
        "platforms": ["Network"],
        "data_sources": ["Web Server Logs"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["website", "deface"],
        "intents": {
            "Impact": {
                "title": "Modification of Public Web Root by Non-Deployment Identity",
                "pseudo": "Write to index.html, default.aspx, or other web-root entry file by a process not in the deployment-pipeline allowlist.",
                "hint": {"event": "FileWrite", "command": "deface", "field": "file.path"},
            },
        },
    },
    "T1561": {
        "name": "Disk Wipe",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "EDR"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["wiper", "raw-disk"],
        "intents": {
            "Impact": {
                "title": "Direct Write to Physical Drive or Partition Boot Sector",
                "pseudo": "Process opens \\\\.\\PhysicalDrive0 / /dev/sda with write and writes ≥1MB. Boot-sector wipe.",
                "hint": {"event": "FileWrite", "command": "disk-wipe", "field": "file.name"},
            },
        },
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["EDR"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["dos", "endpoint"],
        "intents": {
            "Impact": {
                "title": "Process Forking Storm Saturating CPU",
                "pseudo": "Single parent spawning >500 children in 60s, or fork-bomb pattern from a non-build process. Endpoint DoS.",
                "hint": {"event": "ProcessCreate", "command": "fork-storm", "field": "process.parent.pid"},
            },
        },
    },
    "T1495": {
        "name": "Firmware Corruption",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["EDR", "Firmware Telemetry"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["firmware", "uefi"],
        "intents": {
            "Impact": {
                "title": "BIOS/UEFI Flash Operation From User Context",
                "pseudo": "Direct invocation of fwupdmgr, afuwin.exe, AFU /B, or write to \\Device\\NTPNP_PCI* with FW update IOCTL outside vendor management agent.",
                "hint": {"event": "ProcessCreate", "command": "firmware-flash", "field": "process.command_line"},
            },
        },
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Windows Event Log"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["vss", "shadow-copy", "recovery"],
        "intents": {
            "Impact": {
                "title": "Shadow Copies Deleted via vssadmin or wmic",
                "pseudo": "vssadmin delete shadows /all, wmic shadowcopy delete, or wbadmin delete catalog. Pre-ransomware recovery sabotage.",
                "hint": {"event": "ProcessCreate", "command": "vss-delete", "field": "process.command_line"},
            },
        },
    },
    "T1498": {
        "name": "Network Denial of Service",
        "platforms": ["Network"],
        "data_sources": ["Firewall"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["ddos", "flood"],
        "intents": {
            "Impact": {
                "title": "Internal Host Generating SYN Flood to External Target",
                "pseudo": "Single internal host emitting >5000 SYN packets/s to a single external IP. Likely participant in DDoS or local abuse.",
                "hint": {"event": "NetworkFlow", "command": "syn-flood", "field": "source.ip"},
            },
        },
    },
    "T1496": {
        "name": "Resource Hijacking",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["EDR"],
        "severity": "Medium",
        "fidelity": "High",
        "tags": ["cryptomining", "xmrig"],
        "intents": {
            "Impact": {
                "title": "Process With Cryptominer Pool Connection",
                "pseudo": "Outbound TCP to known Stratum / cryptopool hostnames or ports (3333, 4444, 5555, 7777, stratum+tcp://) from a workstation.",
                "hint": {"event": "NetworkConnect", "command": "cryptomine", "field": "destination.port"},
            },
        },
    },
    "T1489": {
        "name": "Service Stop",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["service-stop", "ransomware-prep"],
        "intents": {
            "Impact": {
                "title": "Mass Service Stop Targeting Backup/Database Services",
                "pseudo": "≥3 of (Veeam, MSSQL, Exchange, Backup Exec, VMware Tools) services stopped within 5m. Pre-ransomware service kill.",
                "hint": {"event": "ProcessCreate", "command": "svc-kill", "field": "process.command_line"},
            },
        },
    },
    "T1529": {
        "name": "System Shutdown/Reboot",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Windows Event Log"],
        "severity": "Medium",
        "fidelity": "High",
        "tags": ["shutdown", "reboot"],
        "intents": {
            "Impact": {
                "title": "Forced Shutdown Issued From User Process",
                "pseudo": "shutdown /r /f /t 0, shutdown -r now, or systemctl poweroff issued by non-admin user-context process outside change windows.",
                "hint": {"event": "ProcessCreate", "command": "shutdown", "field": "process.command_line"},
            },
        },
    },
    "T1098": {
        "name": "Account Manipulation",
        "platforms": ["Windows", "Azure", "AWS"],
        "data_sources": ["Auth Logs", "Cloud Audit Logs"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["account-modify"],
        "intents": {
            "Persistence": {
                "title": "Privilege Added to Existing Account (Non-Standard Path)",
                "pseudo": "Add-ADGroupMember Domain Admins, aws iam attach-user-policy AdministratorAccess, or AAD role assignment outside change ticket.",
                "hint": {"event": "GroupAddMember", "command": "priv-add", "field": "group.name"},
            },
        },
    },
    "T1136": {
        "name": "Create Account",
        "platforms": ["Windows", "AWS", "Azure"],
        "data_sources": ["Auth Logs", "Cloud Audit Logs"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["new-account"],
        "intents": {
            "Persistence": {
                "title": "Local Admin Account Created on Workstation",
                "pseudo": "net user /add followed by net localgroup Administrators /add on workstation outside IT-onboarding workflow.",
                "hint": {"event": "ProcessCreate", "command": "useradd-admin", "field": "process.command_line"},
            },
        },
    },
    "T1505": {
        "name": "Server Software Component",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Sysmon", "Web Server Logs"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["webshell", "iis-module", "sql-proc"],
        "intents": {
            "Persistence": {
                "title": "Web Shell Indicator: Webserver Spawning Shell",
                "pseudo": "w3wp.exe / httpd / nginx spawning cmd.exe / powershell.exe / bash. Web-shell command execution.",
                "hint": {"event": "ProcessCreate", "command": "webshell", "field": "process.parent.name"},
            },
        },
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "platforms": ["Network", "Linux"],
        "data_sources": ["Web Server Logs", "WAF"],
        "severity": "Critical",
        "fidelity": "Medium",
        "tags": ["exploit", "rce", "log4shell"],
        "intents": {
            "Initial Access": {
                "title": "Suspicious Payload in HTTP Header / URL Reaching App",
                "pseudo": "Inbound HTTP with ${jndi:, /etc/passwd, ../../, <?php, base64_decode in URI/header reaching internet-facing app and producing 200/500.",
                "hint": {"event": "Http", "command": "exploit-payload", "field": "url.full"},
            },
        },
    },
    "T1566": {
        "name": "Phishing",
        "platforms": ["Microsoft 365", "Google Workspace"],
        "data_sources": ["Email Gateway"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["phishing", "lure"],
        "intents": {
            "Initial Access": {
                "title": "Mail With Lookalike Sender Domain Delivered",
                "pseudo": "Inbound email with display-name spoofing internal user but sender domain ≠ corporate domain, containing URL or attachment.",
                "hint": {"event": "EmailReceived", "command": "lookalike", "field": "email.from.address"},
            },
        },
    },
    "T1189": {
        "name": "Drive-by Compromise",
        "platforms": ["Network"],
        "data_sources": ["Web Proxy", "EDR"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["drive-by", "browser"],
        "intents": {
            "Initial Access": {
                "title": "Browser Spawning Suspicious Child Following Suspicious Domain Visit",
                "pseudo": "chrome.exe / firefox.exe spawns powershell.exe / cmd.exe / cscript.exe within 60s of navigating to a newly-registered domain.",
                "hint": {"event": "ProcessCreate", "command": "drive-by-spawn", "field": "process.parent.name"},
            },
        },
    },
    "T1133": {
        "name": "External Remote Services",
        "platforms": ["Network"],
        "data_sources": ["VPN Logs", "Firewall"],
        "severity": "High",
        "fidelity": "Medium",
        "tags": ["vpn", "rdp-external"],
        "intents": {
            "Initial Access": {
                "title": "VPN/RDP Auth From Country Not Used Before by User",
                "pseudo": "VPN concentrator or external RDP gateway login from a country ASN not previously associated with the user identity.",
                "hint": {"event": "Login", "command": "geo-novel", "field": "source.country"},
            },
            "Persistence": {
                "title": "External Remote Service Account Used After 60d Inactivity",
                "pseudo": "VPN/Citrix/SSH login from an account dormant ≥60 days, immediately followed by interactive activity.",
                "hint": {"event": "Login", "command": "dormant-vpn", "field": "user.name"},
            },
        },
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["EDR", "Sysmon"],
        "severity": "Critical",
        "fidelity": "Medium",
        "tags": ["supply-chain", "package"],
        "intents": {
            "Initial Access": {
                "title": "Signed Update Process Spawning Anomalous Child",
                "pseudo": "Vendor signed updater (TeamsUpdate, GoogleUpdate, MsiInstaller) spawning unrelated cmd/powershell with network egress within 60s.",
                "hint": {"event": "ProcessCreate", "command": "updater-anomaly", "field": "process.parent.name"},
            },
        },
    },
    "T1200": {
        "name": "Hardware Additions",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["EDR", "Auditd"],
        "severity": "Medium",
        "fidelity": "Medium",
        "tags": ["hid", "rubber-ducky"],
        "intents": {
            "Initial Access": {
                "title": "Unknown HID Device Enumerated as Keyboard",
                "pseudo": "USB device class HID/Keyboard enumerated with VID/PID outside the hardware-asset register, especially attached briefly (<60s).",
                "hint": {"event": "DeviceConnect", "command": "rogue-hid", "field": "device.product_id"},
            },
        },
    },
    "T1110": {
        "name": "Brute Force",
        "platforms": ["Windows", "Linux", "Okta"],
        "data_sources": ["Auth Logs"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["brute-force", "spray"],
        "intents": {
            "Credential Access": {
                "title": "Password Spray: One Password, Many Users",
                "pseudo": "Single source IP attempting auth against ≥20 distinct users with ≤5 password attempts per user in 10m. Spray pattern.",
                "hint": {"event": "Login", "command": "password-spray", "field": "source.ip"},
            },
        },
    },
    "T1558": {
        "name": "Steal or Forge Kerberos Tickets",
        "platforms": ["Windows"],
        "data_sources": ["Windows Event Log"],
        "severity": "Critical",
        "fidelity": "High",
        "tags": ["kerberos", "kerberoast", "asreproast"],
        "intents": {
            "Credential Access": {
                "title": "Kerberoasting: Multiple SPN TGS Requests by Single User",
                "pseudo": "EID 4769 with encryption type 0x17 (RC4) for ≥5 distinct service SPNs by single account in 5m. Kerberoasting.",
                "hint": {"event": "TgsRequest", "command": "kerberoast", "field": "user.name"},
            },
        },
    },
    "T1528": {
        "name": "Steal Application Access Token",
        "platforms": ["Microsoft 365", "Azure", "AWS"],
        "data_sources": ["Cloud Audit Logs"],
        "severity": "High",
        "fidelity": "High",
        "tags": ["oauth", "token-steal"],
        "intents": {
            "Credential Access": {
                "title": "OAuth App Granted High-Risk Permissions by Standard User",
                "pseudo": "Consent grant to an external OAuth application requesting Mail.ReadWrite, Files.ReadWrite.All, or User.ReadWrite.All by non-admin user.",
                "hint": {"event": "OAuthConsent", "command": "oauth-grant", "field": "consent.scope"},
            },
        },
    },
}
