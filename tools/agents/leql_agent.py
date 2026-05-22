"""Rapid7 InsightIDR LEQL (Log Entry Query Language) specialist agent."""

from tools.agents.base_agent import BaseQueryAgent


class LEQLAgent(BaseQueryAgent):
    LANGUAGE_KEY = "leql"
    LANGUAGE_NAME = "Rapid7 InsightIDR LEQL"
    SIEM_NAME = "Rapid7 InsightIDR"
    DOCS_URL = "https://docs.rapid7.com/insightidr/log-search/"

    SYNTAX_RULES = """
- LEQL has two parts: an optional `where(...)` filter and an optional `groupby(...)`/`calculate(...)`.
- Basic: `where(field=value)` ; combine with AND / OR / NOT and parentheses.
- Operators: =, !=, <, >, >=, <=, IN [a, b], CONTAINS, STARTS-WITH, ENDS-WITH, ICONTAINS,
  and `=/regex/` for regex matching.
- Aggregation: `groupby(field)` then `calculate(count)`, `calculate(unique:field)`,
  `calculate(average:field)`. Thresholds are applied client-side / via alert conditions.
- Keyword search (no field) matches the raw log line; field search uses `field=...`.
- Loose vs strict: `where(field=value)` is loose; `where(field=/^value$/)` for exact regex.
"""

    FIELD_CONVENTIONS = """
- InsightIDR normalizes logs into JSON keys queried with dotted/keypath notation.
- Common keys: source_json.EventID, source_json.EventCode, user, account, source_user,
  destination_user, hostname, asset, source_address, destination_address, process_name,
  parent_process_name, process_cmd_line.
- For raw Windows event logs the event id is typically `source_json.EventID`.
- Authentication log set fields: result (e.g. FAILED_BAD_PASSWORD), user, account, source_asset.
- Use the keypath that matches the log set you are searching (Authentication, Endpoint, etc.).
"""

    BEST_PRACTICES = """
- Scope the search to the right log set, then filter with `where(...)` on indexed keys first.
- Use ICONTAINS / case-insensitive regex for command-line substring matches.
- Use `groupby(...)` + `calculate(count)` to surface bursts; alert thresholds gate the count.
- Prefer explicit field keypaths over bare keyword search for precision.
- Quote string values when they contain spaces or special characters.
"""

    EXAMPLES = """
1) Brute force — failed logons grouped by user:
   where(source_json.EventID=4625) groupby(source_json.TargetUserName) calculate(count)

2) LSASS access (Sysmon EID 10):
   where(source_json.EventID=10 AND source_json.TargetImage ICONTAINS "lsass.exe")
   groupby(source_json.SourceImage, asset) calculate(count)

3) Encoded PowerShell:
   where(process_name ICONTAINS "powershell.exe" AND
         (process_cmd_line ICONTAINS "-enc" OR process_cmd_line ICONTAINS "-encodedcommand"))

4) New service installed (event 7045):
   where(source_json.EventID=7045)
   groupby(asset, source_json.ServiceName) calculate(count)

5) Failed authentications by source asset:
   where(result=FAILED_BAD_PASSWORD) groupby(source_asset, user) calculate(count)
"""
