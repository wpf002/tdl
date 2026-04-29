# Canonical regeneration prompt

You are rewriting the SIEM detection queries for a TDL rule. The goal is queries that **actually implement the rule's pseudo_logic** — not generic templates.

## Inputs you will receive
- The rule's `pseudo_logic` (free text describing the detection)
- The rule's `data_sources`, `platform`, `technique_id`, `severity`, `name`, `description`

## What to produce
A JSON object with these 10 keys, each value a single string containing the complete query:

```
{ "spl": "...", "kql": "...", "aql": "...", "yara_l": "...",
  "esql": "...", "leql": "...", "crowdstrike": "...",
  "xql": "...", "lucene": "...", "sumo": "..." }
```

## Hard requirements

1. **Every condition in pseudo_logic must appear in every query**, mapped to that dialect's idiomatic field name. If pseudo_logic says `Failure Code is "0x0" AND Ticket Encryption in [0x17, 0x18]`, every query must filter on both.

2. **Threshold logic must be expressed**, not dropped. `7 events` → `count >= 7`. `unique service names` → `dc(field) >= 7` / `count_distinct` / `dcount`. `From the same Source Username` → group by that user field.

3. **Time window must be expressed**. `Within 1 minute` → `bin _time span=1m` (SPL), `bin(TimeGenerated, 1m)` (KQL), `BUCKET(@timestamp, 1 minute)` (ES|QL), etc.

4. **Telemetry source must match data_sources / platform.** SharePoint → O365/Cloud audit tables. Firewall → network event tables. Windows Security → SecurityEvent / WinEventLog:Security. AWS CloudTrail → AWSCloudTrail / aws.cloudtrail. Don't put a SharePoint rule on Sysmon.

5. **Use the dialect's correct field names.** Examples:
   - SPL Windows: `EventCode`, `Account_Name`, `IpAddress`, `LogonType`, `Service_Name`, `Ticket_Encryption_Type`, `Failure_Code`
   - KQL `SecurityEvent`: `EventID`, `Account`, `IpAddress`, `LogonType`, `ServiceName`, `Status`, `TicketEncryptionType`
   - KQL `OfficeActivity`: `Operation`, `OfficeWorkload`, `UserId`, `ClientIP`
   - ES|QL Windows: `event.code`, `winlog.event_data.SubjectUserName`, `winlog.event_data.ServiceName`
   - CrowdStrike: `event_simpleName`, `UserName`, `ComputerName`, `ServiceName`, `TicketEncryptionType`
   - YARA-L: `metadata.event_type`, `metadata.product_event_type`, `principal.user.userid`, `target.resource.name`
   - LEQL: `logset`, `event_id`, `source_account`, `service_name`, `destination_account`
   - XQL: `dataset = xdr_data`, `event_type`, `action_evtlog_event_id`, `actor_effective_username`
   - Lucene: ECS field names — `event.code`, `user.name`, `event.action`, `destination.port`
   - Sumo: `_sourceCategory`, `parse "Field=*\""` patterns; field names match the parsed parse expressions

6. **Negative conditions** (`NOT ending with "$"`) must be expressed:
   - SPL: `NOT match(field, "\$$")` or `NOT field="*$"`
   - KQL: `field !endswith "$"`
   - LEQL: `NOT field ENDS WITH "$"`
   - ES|QL: `NOT field LIKE "%$"`
   - CrowdStrike: `NOT match(field, "\$$")`
   - XQL: `not field ~= "\\$$"`
   - Lucene: `NOT field:*$`
   - Sumo: `!(field matches "*$")`

7. **Output JSON only** — no prose, no markdown fences, no explanation. The string values are the raw query bodies.

8. **Preserve newlines** inside query strings using `\n`.

## Style
- Use multi-line queries with pipe-per-line in pipe-based dialects (SPL, KQL, ES|QL, CrowdStrike, XQL).
- AQL is SQL-style — use `WHERE … AND … AND …`, `GROUP BY`, `HAVING`, `LAST <n> MINUTES/HOURS/DAYS`.
- YARA-L is declarative — `events:` block with all conditions, `match:` block with grouping, `condition:` block with threshold.
- Lucene is single-line bool query — combine all conditions with `AND` / `OR` and parentheses. Aggregations are out of scope (handled at the visualization layer).

## Sanity checks before emitting
- Did I capture every `Where …` clause from pseudo_logic? If pseudo_logic has 7 conditions, every query needs 7 filters.
- Did I capture the threshold (`N events`, `unique X`)?
- Did I capture the time window?
- Did I use the right table / index / dataset for the data_source?
