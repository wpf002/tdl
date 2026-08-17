#!/usr/bin/env python3
"""Create empty stub lookups in the lab Splunk for every lookup TDL rules
reference (customer_default_accounts.csv, domain_controllers.csv, threat_intel_*,
authorized_* …). These are org-specific lists a real SOC would populate; the lab
has none, so lookup-referencing queries error. Empty stubs make the subsearches
resolve to 0 rows (exclusions become no-ops) so the queries RUN.

Idempotent; re-run after `docker compose down -v`. Lookups live in the persistent
etc volume otherwise.

    python create_stub_lookups.py
"""
import os
import re
import glob
import tempfile
import subprocess
from pathlib import Path

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules"
CONTAINER = os.environ.get("SPLUNK_CONTAINER", "tdl-splunk")
REST = os.environ.get("SPLUNK_URL", "https://localhost:8089")
AUTH = (os.environ.get("SPLUNK_USER", "admin"), os.environ.get("SPLUNK_PASSWORD", "tdl-splunk-lab"))

LOOKUP_RE = re.compile(r'\b(?:input)?lookup\s+(?:local=(?:true|false)\s+)?([A-Za-z0-9_]+(?:\.csv)?)', re.I)
SKIP = {"local", "append", "output", "outputnew", "update"}


def main():
    names = set()
    for p in glob.glob(str(RULES / "**/*.yaml"), recursive=True):
        import yaml
        try:
            d = yaml.safe_load(open(p, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        spl = (d.get("queries") or {}).get("spl") or ""
        for m in LOOKUP_RE.finditer(spl):
            n = m.group(1)
            if n.lower() not in SKIP:
                names.add(n)

    tmp = Path(tempfile.mkdtemp())
    (tmp / "lookups").mkdir()
    defs = []
    for n in sorted(names):
        base = n[:-4] if n.lower().endswith(".csv") else n
        (tmp / "lookups" / f"{base}.csv").write_text("dummy_field\n")   # header only = 0 rows
        defs.append(f"[{base}]\nfilename = {base}.csv\n")
        defs.append(f"[{base}.csv]\nfilename = {base}.csv\n")
    (tmp / "transforms.conf").write_text("\n".join(defs))

    app = "/opt/splunk/etc/apps/search"
    subprocess.run(f"docker exec {CONTAINER} mkdir -p {app}/lookups {app}/local", shell=True)
    subprocess.run(f"docker cp {tmp}/lookups/. {CONTAINER}:{app}/lookups/", shell=True)
    subprocess.run(f"docker cp {tmp}/transforms.conf {CONTAINER}:{app}/local/transforms.conf", shell=True)
    r = requests.post(f"{REST}/servicesNS/nobody/search/data/transforms/lookups/_reload",
                      auth=AUTH, verify=False)
    print(f"{len(names)} lookups → stub CSVs created, transforms reloaded (HTTP {r.status_code})")


if __name__ == "__main__":
    main()
