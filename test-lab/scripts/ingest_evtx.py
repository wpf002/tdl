#!/usr/bin/env python3
"""Convert Windows .evtx files to JSON and ship them to the lab's Splunk via HEC.

Splunk on Linux/Docker can't read the Windows binary .evtx format directly, so we
parse each record to XML (python-evtx), flatten System + EventData into fields,
and POST to the HTTP Event Collector with a Windows-style sourcetype so TDL's SPL
queries (sourcetype="WinEventLog:Security", EventCode/event_id, …) can match.

Setup:
    pip install python-evtx requests
Usage:
    python ingest_evtx.py /path/to/sample.evtx [more.evtx ...]
    python ingest_evtx.py samples/**/*.evtx      # shell-expanded glob
Env (defaults target this repo's docker-compose):
    SPLUNK_HEC_URL   (default https://localhost:8088/services/collector/event)
    SPLUNK_HEC_TOKEN (default tdl-hec-token-0000000000)
    SPLUNK_INDEX     (default main)
"""
from __future__ import annotations

import os
import sys
import json
import glob
from datetime import datetime, timezone

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from Evtx.Evtx import Evtx
    import xmltodict
except ImportError:
    sys.exit("Missing deps. Run:  pip install python-evtx requests xmltodict")

HEC_URL = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "tdl-hec-token-0000000000")
INDEX = os.environ.get("SPLUNK_INDEX", "main")
BATCH = 200


def _channel_to_sourcetype(channel: str) -> str:
    """Map the EVTX Channel to the sourcetype TDL's SPL expects."""
    ch = channel or "Security"
    if "Sysmon" in ch:
        return "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    if "PowerShell" in ch:
        return "WinEventLog:Microsoft-Windows-PowerShell/Operational"
    return f"WinEventLog:{ch}"


def record_to_event(xml: str) -> dict | None:
    """Flatten one EVTX record's XML into a Splunk-friendly dict."""
    try:
        doc = xmltodict.parse(xml)["Event"]
    except Exception:
        return None
    system = doc.get("System", {}) or {}
    eid = system.get("EventID")
    if isinstance(eid, dict):  # <EventID Qualifiers="...">4688</EventID>
        eid = eid.get("#text")
    channel = system.get("Channel", "Security")
    computer = system.get("Computer", "unknown")
    tc = (system.get("TimeCreated") or {}).get("@SystemTime")

    out = {
        # Provide every field name TDL rules reference across dialects.
        "EventCode": eid, "EventID": eid, "event_id": eid,
        "Channel": channel, "Computer": computer, "ComputerName": computer,
        "host": computer,
    }
    # Flatten <EventData><Data Name="X">v</Data></EventData> into top-level fields.
    data = (doc.get("EventData") or {}).get("Data")
    if isinstance(data, dict):
        data = [data]
    for d in data or []:
        if isinstance(d, dict) and "@Name" in d:
            out[d["@Name"]] = d.get("#text")
    return {"sourcetype": _channel_to_sourcetype(channel), "time": tc, "event": out}


def _epoch(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def ship(batch: list[dict], source: str) -> int:
    if not batch:
        return 0
    body = ""
    for rec in batch:
        payload = {"index": INDEX, "sourcetype": rec["sourcetype"], "source": source,
                   "event": rec["event"]}
        t = _epoch(rec.get("time"))
        if t:
            payload["time"] = t
        body += json.dumps(payload) + "\n"
    r = requests.post(HEC_URL, headers={"Authorization": f"Splunk {HEC_TOKEN}"},
                      data=body, verify=False, timeout=60)
    if r.status_code >= 300:
        raise SystemExit(f"HEC error {r.status_code}: {r.text[:200]}")
    return len(batch)


def main(paths: list[str]) -> int:
    files = []
    for p in paths:
        files.extend(glob.glob(p, recursive=True) if any(c in p for c in "*?[") else [p])
    if not files:
        sys.exit("No .evtx files given.")
    total = 0
    for path in files:
        src = os.path.basename(path)
        sent, batch = 0, []
        try:
            with Evtx(path) as ev:
                for rec in ev.records():
                    e = record_to_event(rec.xml())
                    if not e:
                        continue
                    batch.append(e)
                    if len(batch) >= BATCH:
                        sent += ship(batch, src); batch = []
                sent += ship(batch, src)
        except Exception as e:
            print(f"  ! {src}: {type(e).__name__}: {e}", file=sys.stderr)
            continue
        total += sent
        print(f"  ✓ {src}: {sent} events → Splunk (index={INDEX})")
    print(f"\nDone: {total} events ingested. Search in Splunk:  index={INDEX}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    raise SystemExit(main(sys.argv[1:]))
