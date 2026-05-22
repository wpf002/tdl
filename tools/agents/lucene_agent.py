"""Generic Lucene query-string specialist agent (OpenSearch / Graylog / Exabeam)."""

from tools.agents.base_agent import BaseQueryAgent


class LuceneAgent(BaseQueryAgent):
    LANGUAGE_KEY = "lucene"
    LANGUAGE_NAME = "Generic Lucene"
    SIEM_NAME = "OpenSearch / Graylog / Exabeam"
    DOCS_URL = "https://opensearch.org/docs/latest/query-dsl/full-text/query-string/"

    SYNTAX_RULES = """
- Lucene query-string syntax filters documents; it does NOT aggregate (no pipes, no stats).
- Field match: `field:value`. Phrase: `field:"two words"`. Wildcards: `*` and `?`
  (`field:*lsass.exe`). Regex between slashes: `field:/powershell\\.exe/`.
- Boolean operators: AND, OR, NOT (uppercase), and `+` (must) / `-` (must not).
- Grouping with parentheses: `field:(4625 OR 4624)`.
- Ranges: `field:[1 TO 100]`, `field:{0 TO *}`. Existence: `_exists_:field`.
- No time window inside the query string — the time range is set by the dashboard/API.
- Aggregation/thresholds are done outside the query string (e.g. OpenSearch aggs, Graylog
  alert conditions). Keep the query string a precise filter.
"""

    FIELD_CONVENTIONS = """
- Field names follow the index mapping; ECS is common in OpenSearch/Graylog deployments:
  event.code (Windows event id), winlog.event_id, process.name, process.command_line,
  process.parent.name, host.name, user.name, source.ip, destination.ip, destination.port.
- Some Graylog/Exabeam pipelines keep vendor-native keys: EventID, EventCode, TargetImage,
  SourceImage, ServiceName, CommandLine — match the mapping you actually have.
- Nested/text fields may need `.keyword` suffix for exact match in OpenSearch.
- Windows event id is `event.code` (ECS) or `EventID`/`EventCode` (native), as a string.
"""

    BEST_PRACTICES = """
- Be precise: prefer exact `field:value` over bare keyword search to limit false matches.
- Use parentheses to make boolean intent explicit; uppercase AND/OR/NOT.
- Escape special characters (`: \\ / ( ) [ ]`) with a backslash when matching literals.
- Remember thresholds/grouping live in the surrounding alert config, not the query string.
- Use wildcards sparingly (leading wildcards are expensive) and anchor with field names.
"""

    EXAMPLES = """
1) Failed logons (filter; threshold set by alert condition):
   event.code:4625

2) LSASS access (Sysmon EID 10):
   winlog.event_id:10 AND winlog.event_data.TargetImage:*lsass.exe

3) Encoded PowerShell:
   process.name:powershell.exe AND (process.command_line:*-enc* OR process.command_line:*-EncodedCommand*)

4) New service installed (event 7045):
   event.code:7045

5) Outbound connections to a suspicious port range, excluding internal dest:
   destination.port:[1024 TO 65535] AND NOT destination.ip:10.0.0.0/8
"""
