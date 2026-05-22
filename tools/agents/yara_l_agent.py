"""Google Chronicle YARA-L 2.0 specialist agent."""

from tools.agents.base_agent import BaseQueryAgent


class YaraLAgent(BaseQueryAgent):
    LANGUAGE_KEY = "yara_l"
    LANGUAGE_NAME = "Google Chronicle YARA-L 2.0"
    SIEM_NAME = "Google Chronicle"
    DOCS_URL = "https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview"

    SYNTAX_RULES = """
- A rule has the form:
    rule <name> {
      meta: ...
      events: ...      // event predicates over UDM, variables prefixed with $
      match: ...       // grouping fields over a time window
      outcome: ...     // optional risk_score / aggregations
      condition: ...   // references events/match; uses #count and $vars
    }
- Events bind UDM fields to placeholders, e.g. $e.metadata.event_type = "PROCESS_LAUNCH".
- `match:` lists grouping fields `over` a duration: `$host over 10m`.
- `condition:` uses `#e >= 10` (count of matched events), logical and/or/not, and event vars.
- Join events by sharing a placeholder, e.g. `$e1.principal.hostname = $host`.
- Strings use `=`, `!=`, regex via `re.regex($field, \"pattern\")`, `net.ip_in_range_cidr(...)`.
"""

    FIELD_CONVENTIONS = """
- Everything is UDM (Unified Data Model). Key paths:
  metadata.event_type (PROCESS_LAUNCH, NETWORK_CONNECTION, USER_LOGIN, REGISTRY_MODIFICATION,
  SYSTEM_AUDIT_LOG_WIPE), metadata.product_event_type (raw vendor code, e.g. \"4625\").
- Process: principal.process.command_line, principal.process.file.full_path,
  target.process.file.full_path, principal.process.parent_process.file.full_path.
- Host/user: principal.hostname, principal.user.userid, target.user.userid.
- Network: target.ip, target.port, network.direction.
- Security result: security_result.action, security_result.summary.
- Windows event id maps to metadata.product_event_type as a string.
"""

    BEST_PRACTICES = """
- Always declare a `match:` window so the condition aggregates over a bounded period.
- Use metadata.event_type for portable matching; product_event_type for vendor-specific ids.
- Encode thresholds in `condition:` with `#var >= N`.
- Add an `outcome:` block with $risk_score for triage prioritization when relevant.
- Use re.regex() for substring/pattern matching rather than chained ORs.
"""

    EXAMPLES = """
1) Brute force — failed logons per host:
   rule failed_logon_burst {
     meta:
       author = "TDL"
     events:
       $e.metadata.event_type = "USER_LOGIN"
       $e.security_result.action = "BLOCK"
       $e.metadata.product_event_type = "4625"
       $e.target.user.userid = $user
       $e.principal.hostname = $host
     match:
       $host, $user over 10m
     condition:
       #e >= 10
   }

2) LSASS access (credential dumping):
   rule lsass_access {
     events:
       $e.metadata.event_type = "PROCESS_OPEN"
       re.regex($e.target.process.file.full_path, `(?i)\\\\lsass\\.exe$`)
       $e.principal.hostname = $host
     match:
       $host over 5m
     condition:
       $e
   }

3) Encoded PowerShell:
   rule encoded_powershell {
     events:
       $e.metadata.event_type = "PROCESS_LAUNCH"
       re.regex($e.principal.process.file.full_path, `(?i)powershell\\.exe$`)
       re.regex($e.principal.process.command_line, `(?i)-enc(odedcommand)?`)
     match:
       $e.principal.hostname over 5m
     condition:
       $e
   }

4) Security log cleared:
   rule security_log_cleared {
     events:
       $e.metadata.event_type = "SYSTEM_AUDIT_LOG_WIPE"
       $e.principal.hostname = $host
     match:
       $host over 1h
     condition:
       $e
   }
"""
