"""Sumo Logic Search query specialist agent."""

from tools.agents.base_agent import BaseQueryAgent


class SumoAgent(BaseQueryAgent):
    LANGUAGE_KEY = "sumo"
    LANGUAGE_NAME = "Sumo Logic Search"
    SIEM_NAME = "Sumo Logic"
    DOCS_URL = "https://help.sumologic.com/docs/search/search-query-language/"

    SYNTAX_RULES = """
- A Sumo query is keyword/scope terms followed by pipes (`|`) into operators.
- Scope first with metadata: `_sourceCategory=...`, `_source=...`, `_collector=...`.
- Parse before you reference fields: `parse "...*..." as field`, `json field "..." as x`,
  `parse regex "(?<name>...)"`, or use the FER (field extraction rules).
- Operators: `where`, `count by`, `count_distinct(...)`, `sum`, `avg`, `min`, `max`,
  `timeslice 10m`, `fields`, `dedup`, `sort by`, `limit`, `if(...)`.
- Aggregate with `| count by user` (or `count as cnt by user`) then `| where cnt >= 10`.
- Comparison: =, !=, <, >, AND, OR, NOT, matches, in. Substring via `*term*` keyword or `matches`.
- `timeslice` buckets the search time range; the range itself is set in the UI/API.
"""

    FIELD_CONVENTIONS = """
- Data is segmented by `_sourceCategory` (e.g. `OS/Windows`, `Labs/Windows/Security`).
- Windows event logs are typically JSON; extract with `json field "_raw" "EventID" as event_id`
  or reference parsed fields: EventID, Computer, TargetUserName, Process, CommandLine,
  ParentProcessName, ServiceName.
- Common parsed fields after extraction: event_id, host/Computer, user/TargetUserName,
  src_ip, dest_ip, process_name, command_line.
- Windows event id is `EventID` once parsed from the JSON payload.
- `_messageTime` / `_receiptTime` hold timestamps; `_sourceHost` is the sending host.
"""

    BEST_PRACTICES = """
- Always scope with `_sourceCategory=...` first to cut the data volume before parsing.
- Parse only the fields you need; reference them after the parse stage.
- Use `timeslice` + `count by` for windowed bursts, then `where` for the threshold.
- Prefer extracted/typed fields over raw keyword matches for precision.
- End with `fields` to keep the result readable.
"""

    EXAMPLES = """
1) Brute force — failed logons per account:
   _sourceCategory=*Windows*Security* "4625"
   | json field=_raw "EventID" as event_id
   | json field=_raw "TargetUserName" as target_user
   | where event_id = "4625"
   | timeslice 10m
   | count as attempts by _timeslice, target_user
   | where attempts >= 10

2) LSASS access (Sysmon EID 10):
   _sourceCategory=*Sysmon* "10"
   | json field=_raw "EventID" as event_id
   | json field=_raw "TargetImage" as target_image
   | json field=_raw "SourceImage" as source_image
   | where event_id = "10" and target_image matches "*lsass.exe"
   | count by source_image, _sourceHost

3) Encoded PowerShell:
   _sourceCategory=*Windows* "powershell"
   | json field=_raw "CommandLine" as cmd
   | where cmd matches "*-enc*" or cmd matches "*-EncodedCommand*"
   | fields _messageTime, _sourceHost, cmd

4) New service installed (event 7045):
   _sourceCategory=*Windows*System* "7045"
   | json field=_raw "EventID" as event_id
   | json field=_raw "ServiceName" as service
   | where event_id = "7045"
   | count by _sourceHost, service

5) Rare process by host count:
   _sourceCategory=*Windows* "4688"
   | json field=_raw "NewProcessName" as process_name
   | count_distinct(_sourceHost) as hosts by process_name
   | where hosts <= 2
"""
