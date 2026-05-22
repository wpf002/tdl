"""IBM QRadar AQL (Ariel Query Language) specialist agent."""

from tools.agents.base_agent import BaseQueryAgent


class AQLAgent(BaseQueryAgent):
    LANGUAGE_KEY = "aql"
    LANGUAGE_NAME = "IBM QRadar AQL"
    SIEM_NAME = "IBM QRadar"
    DOCS_URL = "https://www.ibm.com/docs/en/qradar-on-cloud?topic=reference-ariel-query-language"

    SYNTAX_RULES = """
- AQL is SQL-like: `SELECT <fields> FROM events|flows WHERE <conds> GROUP BY ... ORDER BY ... LAST <time>`.
- Source is `events` or `flows` (not arbitrary table names).
- Functions: COUNT(), UNIQUECOUNT(), SUM(), MAX(), MIN(), AVG(), FIRST(), LAST().
- Time window uses the `LAST` clause: `LAST 1 HOURS`, `LAST 24 HOURS`, `LAST 10 MINUTES`,
  or `START` / `STOP` with epoch-millisecond timestamps.
- Custom/extracted properties are referenced in double quotes: "Username", "Process Name".
- String matching: `=`, `LIKE '%foo%'`, `ILIKE`, `MATCHES` (regex), `IN (...)`.
- HAVING applies thresholds to aggregates: `GROUP BY username HAVING COUNT(*) > 10`.
"""

    FIELD_CONVENTIONS = """
- Normalized event fields: qid, eventcount, sourceip, destinationip, sourceport, destinationport,
  username, eventtime (epoch ms), category, qidname(qid), categoryname(category),
  logsourceid, LOGSOURCENAME(logsourceid).
- Windows event id is the custom property "EventID" (referenced in quotes). Common Windows
  custom properties: "Process Name", "Process CommandLine", "Parent Process Name",
  "Target Username", "Logon Type", "Service Name".
- Use functions like LOGSOURCENAME(logsourceid) and CATEGORYNAME(category) for readable output.
- DSM-extracted properties depend on the log source; reference them by their exact display name.
"""

    BEST_PRACTICES = """
- Always include a `LAST <time>` (or START/STOP) clause — unbounded queries are rejected/slow.
- Filter on indexed normalized fields (sourceip, username, logsourceid) before custom properties.
- Use UNIQUECOUNT() for distinct counts; COUNT(*) for total events.
- Apply thresholds with HAVING on the grouped aggregate.
- Quote custom property names exactly as defined in QRadar, including spaces.
"""

    EXAMPLES = """
1) Brute force — failed logons per user in last hour:
   SELECT username, sourceip, COUNT(*) AS attempts
   FROM events
   WHERE "EventID" = '4625'
   GROUP BY username, sourceip
   HAVING attempts >= 10
   LAST 1 HOURS

2) LSASS access (Sysmon EID 10):
   SELECT "Process Name" AS source_process, "Target Username", sourceip, COUNT(*) AS hits
   FROM events
   WHERE "EventID" = '10' AND "TargetImage" ILIKE '%lsass.exe%'
   GROUP BY "Process Name", "Target Username", sourceip
   LAST 1 HOURS

3) Encoded PowerShell:
   SELECT eventtime, username, "Process CommandLine", "Parent Process Name"
   FROM events
   WHERE "Process Name" ILIKE '%powershell.exe%'
     AND ("Process CommandLine" ILIKE '%-enc%' OR "Process CommandLine" ILIKE '%-EncodedCommand%')
   LAST 1 HOURS

4) New service installed (EventID 7045):
   SELECT eventtime, LOGSOURCENAME(logsourceid) AS host, "Service Name", "Service File Name"
   FROM events
   WHERE "EventID" = '7045'
   LAST 24 HOURS

5) Outbound beaconing — many flows to one dest:
   SELECT sourceip, destinationip, UNIQUECOUNT(destinationport) AS ports, COUNT(*) AS flows
   FROM flows
   GROUP BY sourceip, destinationip
   HAVING flows > 100
   LAST 1 HOURS
"""
