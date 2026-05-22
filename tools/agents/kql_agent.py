"""Microsoft Sentinel / Defender KQL specialist agent."""

from tools.agents.base_agent import BaseQueryAgent


class KQLAgent(BaseQueryAgent):
    LANGUAGE_KEY = "kql"
    LANGUAGE_NAME = "Microsoft Sentinel KQL"
    SIEM_NAME = "Microsoft Sentinel / Defender"
    DOCS_URL = "https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/"

    SYNTAX_RULES = """
- A query starts with a table name and pipes (`|`) into operators. Tables are case-sensitive.
- Operators: `where`, `project`, `extend`, `summarize`, `join kind=inner`, `union`, `sort by`,
  `top N by`, `distinct`, `count`, `mv-expand`, `parse`, `make-set`, `make-list`.
- `summarize` aggregations: count(), dcount(), sum(), avg(), min(), max(), arg_max(), make_set().
  Group with `by`. Time-bin with `bin(TimeGenerated, 10m)`.
- Comparison: `==`, `!=`, `<`, `>`, `and`, `or`, `in (...)`, `has`, `contains`, `startswith`,
  `endswith`, `matches regex`. Prefer `has`/`==` over `contains` for performance.
- Filter time with `where TimeGenerated > ago(1h)`.
- String comparisons are case-sensitive by default; append `=~` or use `tolower()` for case-insensitive.
"""

    FIELD_CONVENTIONS = """
- Windows security events: table `SecurityEvent`. The event id field is `EventID` (NOT EventCode).
  Fields: Computer, Account, TargetAccount, SubjectUserName, LogonType, Process, CommandLine.
- Microsoft Defender for Endpoint (advanced hunting): `DeviceProcessEvents`
  (FileName, ProcessCommandLine, InitiatingProcessFileName, DeviceName, AccountName),
  `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceFileEvents`, `DeviceImageLoadEvents`.
- Azure AD / Entra sign-ins: `SigninLogs`, `AuditLogs`. Office: `OfficeActivity`.
- Sysmon via SecurityEvent or `Event` table when ingested; EventID 10 = process access.
- `TimeGenerated` is the canonical timestamp on Sentinel tables.
"""

    BEST_PRACTICES = """
- Put the most selective `where` (table-scoped time + EventID) first to prune rows early.
- Use `has` for tokenized substring matches; reserve `contains` for non-tokenized needs.
- Project only the columns analysts need at the end with `project`.
- Express thresholds with `summarize count() by ... | where count_ >= N`.
- For Defender, prefer the Device* tables over raw Event tables.
"""

    EXAMPLES = """
1) Brute force — failed logons per account (Sentinel):
   SecurityEvent
   | where TimeGenerated > ago(1h) and EventID == 4625
   | summarize attempts = count() by bin(TimeGenerated, 10m), TargetAccount, Computer
   | where attempts >= 10

2) LSASS access (Defender advanced hunting):
   DeviceProcessEvents
   | where TimeGenerated > ago(1h)
   | where FileName !in~ ("MsMpEng.exe","csrss.exe")
   | join kind=inner (DeviceImageLoadEvents | where FileName =~ "lsass.exe") on DeviceId
   | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine

3) Encoded PowerShell (Defender):
   DeviceProcessEvents
   | where FileName =~ "powershell.exe"
   | where ProcessCommandLine has_any ("-enc","-EncodedCommand")
   | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine

4) New service installed (Sentinel, EventID 7045):
   SecurityEvent
   | where EventID == 7045
   | project TimeGenerated, Computer, ServiceName = Service, ServiceFileName = FileName

5) Impossible travel sign-ins (Entra):
   SigninLogs
   | where TimeGenerated > ago(24h) and ResultType == 0
   | summarize cities = make_set(LocationDetails.city) by UserPrincipalName
   | where array_length(cities) >= 3
"""
