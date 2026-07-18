# TDL Test Lab — validate rules against real logs

A free, local **Splunk** instance for testing TDL's detection rules against
**real Windows logs** — EVTX attack samples and Atomic Red Team telemetry —
instead of only eyeballing SPL. Running rules against real data surfaces the
field-name and logic mismatches that a static check can't.

Everything runs on your machine via Docker. No cloud, no cost.

## 1. Start Splunk

```bash
cd test-lab
cp .env.example .env         # optional: change the password / HEC token
docker compose up -d
```

First boot takes ~1–2 min (a few minutes on Apple Silicon — the official Splunk
image is amd64 and runs under emulation). Then:

- Web UI: <http://localhost:8000>  (login `admin` / the `SPLUNK_PASSWORD` in `.env`)
- Uses Splunk's **free 60-day Enterprise trial** (full features). It reverts to
  the free 500 MB/day tier after 60 days; run `scripts/enable-remote-login.sh`
  then so the rule runner (REST) keeps working.

Install the host-side Python tooling once:

```bash
pip install -r requirements.txt
```

## 2. Smoke-test the loop (no download)

```bash
python scripts/send_sample_events.py        # ships ~5 synthetic Windows events
python scripts/run_rule.py TDL-CA-000019    # Kerberoasting rule → should show hits
```

## 3. Load real Windows attack logs (EVTX)

Splunk-on-Linux can't read the Windows binary `.evtx` format, so the ingester
converts each record to JSON and ships it via HEC with a Windows sourcetype.

```bash
./scripts/fetch_samples.sh                                   # EVTX-ATTACK-SAMPLES (ATT&CK-mapped)
python scripts/ingest_evtx.py "samples/EVTX-ATTACK-SAMPLES/**/*.evtx"
```

`fetch_samples.sh "Credential Access"` grabs a single tactic folder if you don't
want the whole set.

## 3b. Load the other log sources (cloud / network / endpoint / IdP)

EVTX samples are Windows-only. To make the *whole* library testable, load
representative events for the other sourcetypes TDL rules query
(aws:cloudtrail, azure:auditlogs, gcp:audit, Sysmon, firewall, ids, Okta, …):

```bash
python scripts/load_sources.py
```

## 3c. Field normalization

Real EVTX carries raw field names (Image, CommandLine, SubjectUserName…) while
TDL's SPL uses process_name/command_line/user. `splunk-config/props.conf` adds
the search-time aliases a real Splunk gets from the Windows TA. It's applied when
the container is created; to (re)apply to a running container:

```bash
docker cp splunk-config/props.conf tdl-splunk:/opt/splunk/etc/system/local/props.conf
curl -sk -u admin:$SPLUNK_PASSWORD -X POST https://localhost:8089/services/admin/conf-props/_reload
```

## 4. Run TDL rules against the data

```bash
python scripts/run_rule.py TDL-CA-000019       # one rule
python scripts/run_rule.py --tactic credential-access
python scripts/run_rule.py --all --limit 100   # coverage summary: how many fire
```

Output marks each rule ✓ fired / · no-hit / ⚠ errored — a fast way to find rules
whose SPL doesn't actually match real data (wrong fields, wrong sourcetype, etc.).

## 5. Atomic Red Team (fresh telemetry)

Atomic Red Team runs the actual attack techniques and is **Windows/PowerShell**,
so it needs a Windows host (a VM or spare box) — it can't run on macOS directly.
The lab receives that host's logs via a Splunk **Universal Forwarder**:

1. On the Windows host, install the Splunk Universal Forwarder.
2. Copy `atomic-red-team/splunk-uf/inputs.conf` and `outputs.conf` into
   `%SPLUNK_HOME%\etc\system\local\` (set `<MAC-IP>` in `outputs.conf` to the IP
   of the machine running this compose).
3. On the lab Splunk, enable receiving on 9997 (already exposed):
   `docker exec -u splunk tdl-splunk /opt/splunk/bin/splunk enable listen 9997 -auth admin:<password>`
4. Install Sysmon (with a good config, e.g. SwiftOnSecurity/olafhartong) on the host.
5. Run atomics:
   ```powershell
   Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser
   Invoke-AtomicTest T1558.003   # Kerberoasting, matches TDL-CA-000019
   ```
6. Back on your Mac: `python scripts/run_rule.py TDL-CA-000019`.

## Files

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Splunk (Web 8000, HEC 8088, REST 8089, receiving 9997) |
| `scripts/send_sample_events.py` | Ship synthetic events (quick smoke test) |
| `scripts/fetch_samples.sh` | Download EVTX-ATTACK-SAMPLES |
| `scripts/ingest_evtx.py` | EVTX → JSON → Splunk HEC |
| `scripts/run_rule.py` | Run TDL SPL rules via REST, report hits |
| `scripts/load_sources.py` | Load cloud/network/endpoint/IdP sample events |
| `scripts/run_rule.py` | `--workers` parallel, `--all/--tactic/--limit`, index-normalized |
| `splunk-config/props.conf` | Windows-TA-style field aliases (raw EVTX → TDL field names) |
| `scripts/enable-remote-login.sh` | Re-enable REST login after the trial → Free reversion |
| `atomic-red-team/splunk-uf/` | Universal Forwarder configs for a Windows ART host |

## Open a rule's logs from the app

The Detection Rules page has an **"Open in Splunk"** link on each rule's SPL tab.
It opens this Splunk instance in a new tab, searching the rule's **base events**
(the raw logs it matches, before aggregation) with the index normalized to the
lab data. Defaults to `http://localhost:8000`; override in the browser console:
`localStorage.setItem('tdl_splunk_url', 'http://your-splunk:8000')`.

## Stop / reset

```bash
docker compose stop          # pause
docker compose down          # remove container (keeps indexed data)
docker compose down -v       # remove everything incl. indexed data
```
