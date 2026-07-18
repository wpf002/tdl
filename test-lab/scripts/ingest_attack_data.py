#!/usr/bin/env python3
"""Ingest splunk/attack_data real-attack datasets, re-tagged to the sourcetypes
TDL rules query, so the regenerated SPL can be validated against REAL attacks
(complete scenarios) rather than thin synthetic samples.

Download datasets first (Git LFS content via the media endpoint), e.g.:
    curl -sL https://media.githubusercontent.com/media/splunk/attack_data/master/<path> -o file

    pip install requests
    python ingest_attack_data.py samples/attack_real/*.log samples/attack_real/*.json
"""
import os
import sys
import json
import glob

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEC_URL = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "tdl-hec-token-0000000000")

# filename substring → the TDL sourcetype the rules expect
ST_MAP = [
    ("cloudtrail", "aws:cloudtrail"), ("okta", "OktaIM2:log"),
    ("suricata", "ids"), ("zeek", "firewall"), ("kubernetes", "kubernetes"),
    ("gws", "gsuite"), ("gcp", "gcp:audit"), ("azure", "azure:aad:signin"),
    ("o365", "m365"), ("gsuite", "gsuite"),
]


def sourcetype_for(fn):
    fnl = fn.lower()
    for k, st in ST_MAP:
        if k in fnl:
            return st
    return "attack_data"


def records(path):
    txt = open(path, encoding="utf-8", errors="replace").read().strip()
    if not txt:
        return
    try:
        obj = json.loads(txt)                      # whole-file JSON?
        if isinstance(obj, list):
            yield from obj; return
        if isinstance(obj, dict):
            if isinstance(obj.get("Records"), list):
                yield from obj["Records"]; return
            yield obj; return
    except json.JSONDecodeError:
        pass
    for line in txt.splitlines():                  # NDJSON
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def normalize(e, st):
    """Lift nested fields into the flat names TDL rules filter on."""
    if st == "ids" and isinstance(e.get("alert"), dict):
        e.setdefault("signature", e["alert"].get("signature"))
        e.setdefault("category", e["alert"].get("category"))
        e.setdefault("severity", e["alert"].get("severity"))
    if "dest_port" in e:
        e.setdefault("destination_port", e["dest_port"])
    return e


def main(paths):
    files = []
    for p in paths:
        files.extend(glob.glob(p) if any(c in p for c in "*?[") else [p])
    total = 0
    override = os.environ.get("ST_OVERRIDE")  # force a sourcetype for all files
    for path in files:
        st = override or sourcetype_for(os.path.basename(path))
        evs = [normalize(e, st) for e in records(path) if isinstance(e, dict)]
        if not evs:
            print(f"  · {os.path.basename(path)}: no records"); continue
        body = "".join(json.dumps({"index": "main", "sourcetype": st,
                                   "source": "attack_data:" + os.path.basename(path),
                                   "event": e}) + "\n" for e in evs)
        r = requests.post(HEC_URL, headers={"Authorization": f"Splunk {HEC_TOKEN}"},
                          data=body, verify=False, timeout=60)
        ok = r.status_code < 300
        total += len(evs) if ok else 0
        print(f"  {'✓' if ok else '!'} {os.path.basename(path):34} -> {st:16} {len(evs)} events (HEC {r.status_code})")
    print(f"\n{total} real-attack events ingested.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
