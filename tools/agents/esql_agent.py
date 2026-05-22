"""Elastic ES|QL specialist agent."""

from tools.agents.base_agent import BaseQueryAgent


class ESQLAgent(BaseQueryAgent):
    LANGUAGE_KEY = "esql"
    LANGUAGE_NAME = "Elastic ES|QL"
    SIEM_NAME = "Elastic Security"
    DOCS_URL = "https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html"

    SYNTAX_RULES = """
- A query starts with a source command `FROM <index-pattern>` and pipes (`|`) into commands.
- Commands: WHERE, EVAL, STATS ... BY, KEEP, DROP, RENAME, SORT, LIMIT, DISSECT, GROK, ENRICH.
- STATS aggregations: COUNT(), COUNT_DISTINCT(), SUM(), AVG(), MIN(), MAX(), VALUES().
  Group with BY. Time-bucket with `STATS ... BY bucket = BUCKET(@timestamp, 10 minute)`.
- Comparison/functions: ==, !=, <, >, AND, OR, NOT, IN (...), LIKE \"*x*\", RLIKE \"regex\",
  STARTS_WITH(), TO_LOWER(), CASE().
- Filter time with `WHERE @timestamp > NOW() - 1 hour`.
- KEEP selects the output columns (like project). String matches are case-sensitive.
"""

    FIELD_CONVENTIONS = """
- Uses Elastic Common Schema (ECS) over data streams / index patterns:
  `logs-windows.sysmon_operational*`, `logs-system.security*`, `logs-endpoint.events.process*`,
  `winlogbeat-*`, `.alerts-security.alerts-*`.
- Windows event id is `winlog.event_id` (or `event.code`). Process fields:
  process.name, process.command_line, process.executable, process.parent.name.
- Host/user: host.name, user.name, source.ip, destination.ip, destination.port.
- Sysmon process-access (EID 10) appears in `logs-windows.sysmon_operational*` with
  winlog.event_data.TargetImage / SourceImage.
- @timestamp is the canonical event time.
"""

    BEST_PRACTICES = """
- Choose the narrowest index pattern in FROM, then WHERE on event id / timestamp first.
- Use ECS field names; avoid raw winlog.event_data unless ECS lacks the field.
- Express thresholds with `STATS c = COUNT(*) BY ... | WHERE c >= N`.
- KEEP only the columns analysts need at the end.
- Use BUCKET() for time-windowed aggregation rather than manual date math.
"""

    EXAMPLES = """
1) Brute force — failed logons per user:
   FROM logs-system.security*
   | WHERE @timestamp > NOW() - 1 hour AND event.code == "4625"
   | STATS attempts = COUNT(*) BY user.name, host.name, win = BUCKET(@timestamp, 10 minute)
   | WHERE attempts >= 10

2) LSASS access (Sysmon EID 10):
   FROM logs-windows.sysmon_operational*
   | WHERE winlog.event_id == 10 AND TO_LOWER(winlog.event_data.TargetImage) LIKE "*lsass.exe"
   | STATS hits = COUNT(*) BY host.name, winlog.event_data.SourceImage, user.name
   | WHERE hits > 0

3) Encoded PowerShell:
   FROM logs-endpoint.events.process*
   | WHERE process.name == "powershell.exe"
     AND (process.command_line LIKE "*-enc*" OR process.command_line LIKE "*-EncodedCommand*")
   | KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line

4) New service installed (event 7045):
   FROM logs-system.system*
   | WHERE event.code == "7045"
   | KEEP @timestamp, host.name, winlog.event_data.ServiceName, winlog.event_data.ImagePath

5) Rare parent-child process pair:
   FROM logs-endpoint.events.process*
   | STATS hosts = COUNT_DISTINCT(host.name) BY process.parent.name, process.name
   | WHERE hosts <= 2
"""
