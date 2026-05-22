"""Splunk SPL specialist agent."""

from tools.agents.base_agent import BaseQueryAgent


class SPLAgent(BaseQueryAgent):
    LANGUAGE_KEY = "spl"
    LANGUAGE_NAME = "Splunk SPL"
    SIEM_NAME = "Splunk"
    DOCS_URL = "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference"

    SYNTAX_RULES = """
- Search starts with terms/`index=`/`source=`, then pipes (`|`) into transforming commands.
- Core commands: `search`, `where`, `eval`, `stats`, `tstats`, `bucket`/`bin`, `dedup`,
  `table`, `rename`, `rex`, `lookup`, `join`, `transaction`, `streamstats`, `eventstats`.
- `stats` aggregations: count, dc (distinct count), values, sum, avg, min, max, latest, earliest.
  Group with `by`. Window/time-bucketing via `bin _time span=5m` before `stats ... by _time`.
- Comparison in `where`/`eval`: `=`, `!=`, `<`, `>`, AND, OR, NOT, `IN(...)`, `like()`, `match()`.
- Time defaults come from the time picker; you can use `earliest=-15m latest=now` inline.
- String fields are case-insensitive in search terms but case-sensitive in `eval`/`where`.
"""

    FIELD_CONVENTIONS = """
- Windows event logs: `index=windows` or `index=wineventlog`, sourcetype `WinEventLog:Security`.
  Field for the event ID is `EventCode` (NOT EventID). Other fields: ComputerName, Account_Name,
  Image, ParentImage, CommandLine, TargetUserName, Logon_Type.
- Sysmon: sourcetype `WinEventLog:Microsoft-Windows-Sysmon/Operational`, EventCode 1 (proc create),
  3 (network), 7 (image load), 8 (CreateRemoteThread), 10 (process access — LSASS).
- Linux: `index=linux` / sourcetype `linux_secure`, `syslog`.
- Cloud/CIM: prefer Common Information Model fields (action, user, src, dest, process_name).
- `_time` is the canonical timestamp; `host`, `source`, `sourcetype` are metadata fields.
"""

    BEST_PRACTICES = """
- Filter as early as possible (index, sourcetype, EventCode) before piping to stats.
- Use `tstats` against accelerated data models for performance when possible.
- Prefer `stats` over `transaction` for grouping; cheaper and scales.
- Always project final fields with `table` or `fields` so the result is analyst-readable.
- Encode thresholds with `where count >= N`; encode time windows with `bin _time span=...`.
"""

    EXAMPLES = """
1) Brute force — many failed logons per account in 10m:
   index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
   | bin _time span=10m
   | stats count by _time, Account_Name, ComputerName
   | where count >= 10

2) LSASS process access (credential dumping, Sysmon EID 10):
   index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
   TargetImage="*\\\\lsass.exe"
   | stats count values(SourceImage) as accessing_process by ComputerName, SourceUser
   | where count > 0

3) Suspicious PowerShell encoded command (Sysmon EID 1):
   index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
   Image="*\\\\powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*")
   | table _time, ComputerName, User, ParentImage, CommandLine

4) New service installed (EID 7045):
   index=wineventlog sourcetype=WinEventLog:System EventCode=7045
   | table _time, ComputerName, Service_Name, Service_File_Name, Service_Start_Type

5) Rare process by host (baseline via eventstats):
   index=wineventlog EventCode=1
   | eventstats dc(ComputerName) as host_count by Image
   | where host_count <= 2
   | table _time, ComputerName, Image, CommandLine
"""
