"""Palo Alto Cortex XSIAM / XDR XQL specialist agent."""

from tools.agents.base_agent import BaseQueryAgent


class XQLAgent(BaseQueryAgent):
    LANGUAGE_KEY = "xql"
    LANGUAGE_NAME = "Palo Alto XSIAM XQL"
    SIEM_NAME = "Palo Alto Cortex XSIAM"
    DOCS_URL = "https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-XQL-Language-Reference"

    SYNTAX_RULES = """
- XQL is a pipeline language beginning with a `dataset = <name>` (or `preset = ...`) stage,
  then stages joined by `|`.
- Stages: `filter`, `fields`, `alter`, `comp` (compute/aggregate), `dedup`, `sort`, `limit`,
  `join`, `arrayexpand`, `bin`.
- Aggregation uses `comp`: `comp count() as cnt by user`, `comp count_distinct(...) `,
  `comp sum(...)`, `comp avg(...)`. Threshold afterwards with `filter cnt >= 10`.
- Comparison/functions: =, !=, <, >, and, or, not, in (...), contains, ~= (regex),
  lowercase(), incidr(...).
- Time is set by the query time range UI; `bin _time span=10m` buckets within it.
- `fields` projects columns; `alter` creates derived fields.
"""

    FIELD_CONVENTIONS = """
- Datasets: `xdr_data` (endpoint EDR), `panw_ngfw_traffic_raw`, `cloud_audit_logs`,
  and per-vendor raw datasets. Endpoint preset: `preset = xdr_data`.
- Endpoint fields (xdr_data): event_type, event_sub_type, action_process_image_name,
  action_process_image_command_line, actor_process_image_name, agent_hostname,
  action_remote_ip, action_remote_port, actor_effective_username.
- Windows event log id field is `action_evtlog_event_id`; message in action_evtlog_message.
- LSASS access appears in event_type ENUM.EVENT_TYPE_PROCESS with target image lsass.exe, or
  via the dedicated injection/access events.
- `_time` is the canonical event timestamp.
"""

    BEST_PRACTICES = """
- Start from the most specific dataset/preset, then `filter` on event_type and ids early.
- Use `comp ... by ...` then `filter` for thresholds; use `bin _time span=` for windows.
- Prefer `=` / `in (...)` over `contains`; use `~=` regex for command-line patterns.
- Project the analyst-relevant columns with `fields` at the end.
- Reference enum values fully, e.g. event_type = ENUM.EVENT_TYPE_PROCESS.
"""

    EXAMPLES = """
1) Brute force — failed logons per user:
   dataset = xdr_data
   | filter action_evtlog_event_id = 4625
   | bin _time span=10m
   | comp count() as attempts by _time, action_evtlog_event_data_TargetUserName, agent_hostname
   | filter attempts >= 10

2) LSASS access (Sysmon EID 10):
   dataset = xdr_data
   | filter action_evtlog_event_id = 10 and lowercase(action_process_image_name) contains "lsass.exe"
   | comp count() as hits by agent_hostname, actor_process_image_name
   | filter hits > 0

3) Encoded PowerShell:
   dataset = xdr_data
   | filter actor_process_image_name = "powershell.exe"
     and (action_process_image_command_line contains "-enc"
          or action_process_image_command_line contains "-EncodedCommand")
   | fields _time, agent_hostname, actor_effective_username, action_process_image_command_line

4) New service installed (event 7045):
   dataset = xdr_data
   | filter action_evtlog_event_id = 7045
   | fields _time, agent_hostname, action_evtlog_event_data_ServiceName

5) Rare process by host count:
   dataset = xdr_data
   | filter event_type = ENUM.EVENT_TYPE_PROCESS
   | comp count_distinct(agent_hostname) as hosts by action_process_image_name
   | filter hosts <= 2
"""
