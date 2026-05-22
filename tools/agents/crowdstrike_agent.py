"""CrowdStrike Falcon LogScale (CQL) specialist agent."""

from tools.agents.base_agent import BaseQueryAgent


class CrowdStrikeAgent(BaseQueryAgent):
    LANGUAGE_KEY = "crowdstrike"
    LANGUAGE_NAME = "CrowdStrike Falcon LogScale"
    SIEM_NAME = "CrowdStrike Falcon"
    DOCS_URL = "https://library.humio.com/falcon-logscale/docs-search-cql.html"

    SYNTAX_RULES = """
- LogScale CQL (formerly Humio) is a pipeline language: filters and functions joined by `|`.
- Filtering: bare `field=value`, `field="quoted"`, `/regex/` , `!=`, comparison `>`/`<`,
  and free-text. Combine with `and`, `or`, `not`, parentheses.
- Functions are prefixed and piped: `| groupBy([field], function=count())`,
  `| count()`, `| timeChart()`, `| table([f1,f2])`, `| sort()`, `| head()`, `| tail()`.
- Aggregations: count(), count(field, distinct=true), sum(field), avg(field), max(), min().
- `groupBy([a,b], function=count(as=cnt))` then `| cnt >= 10` to threshold.
- Regex extraction: `| regex("(?<x>...)", field=...)`. Wildcards in match: `field=*lsass.exe`.
- Time is set by the search range; functions like `timeChart(span=10m)` bucket within it.
"""

    FIELD_CONVENTIONS = """
- Falcon telemetry uses event_simpleName / event_platform plus raw fields. Common fields:
  event_simpleName (e.g. ProcessRollup2, NetworkConnectIP4, EndOfProcess),
  ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, SHA256HashData,
  TargetProcessId, RemoteAddressIP4.
- When ingesting Windows event logs, the event id field is `EventCode` (Windows-style),
  or `event.code` depending on the parser; ProcessRollup2 is the EDR process-creation event.
- LSASS access surfaces via the ProcessRollup2/CredentialDump-related events referencing
  lsass.exe in TargetFileName/CommandLine.
- @timestamp / @timestamp.nanos hold event time; #repo and #type tag the data source.
"""

    BEST_PRACTICES = """
- Filter on event_simpleName (or #type) first to scope to the right telemetry, then narrow.
- Use `groupBy([...], function=count(as=cnt))` then `| cnt >= N` for burst thresholds.
- Prefer wildcard `field=*lsass.exe` or `/regex/` over broad free-text search.
- End with `| table([...])` to produce an analyst-readable result set.
- Use distinct counts via `count(field, distinct=true, as=...)`.
"""

    EXAMPLES = """
1) Brute force — failed logons per account (Windows event log in LogScale):
   EventCode=4625
   | groupBy([TargetUserName, ComputerName], function=count(as=attempts))
   | attempts >= 10

2) LSASS access (EDR / Sysmon EID 10):
   (event_simpleName=ProcessRollup2 OR EventCode=10) CommandLine=*lsass.exe
   | groupBy([ComputerName, ParentBaseFileName], function=count(as=hits))
   | table([ComputerName, ParentBaseFileName, hits])

3) Encoded PowerShell:
   event_simpleName=ProcessRollup2 FileName=powershell.exe
   (CommandLine=*-enc* OR CommandLine=*-EncodedCommand*)
   | table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])

4) New service installed (event 7045):
   EventCode=7045
   | table([@timestamp, ComputerName, ServiceName, ImagePath])

5) Rare binary by host count:
   event_simpleName=ProcessRollup2
   | groupBy([FileName], function=count(ComputerName, distinct=true, as=hosts))
   | hosts <= 2
"""
