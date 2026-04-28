"""SIEM query templates — turns a (technique_id, intent.hint) pair into the
nine query languages the schema supports.

Each template is intentionally a *starting point* — Proposed-lifecycle rules
land in the library so analysts can tune them. The shape mirrors patterns
already in rules/ (process, network, registry, file, cloud-audit).
"""

from textwrap import dedent

# Each template family maps a `hint.command` keyword to per-SIEM bodies.
# A few generic families cover most techniques; specific commands fall back to
# a `process_generic` / `cloud_generic` shape using the supplied field.

PROCESS_FAMILY = {
    "spl": dedent("""\
        index=endpoint sourcetype=Sysmon EventCode=1
        | search {filter}
        | stats count, values(host) as hosts, values(user) as users by process_name, parent_process_name, command_line
        | where count >= 1
        | sort - count"""),
    "kql": dedent("""\
        DeviceProcessEvents
        | where TimeGenerated > ago(1d)
        | where {filter_kql}
        | summarize Count=count() by DeviceName, AccountName, FileName, InitiatingProcessFileName, ProcessCommandLine
        | order by Count desc"""),
    "aql": dedent("""\
        SELECT DEVICETIME, sourceip, "Process Name", "Parent Process Name", "Process CommandLine"
        FROM events
        WHERE LOGSOURCETYPENAME(devicetype) = 'Microsoft Windows Sysmon'
          AND "EventID" = '1'
          AND {filter_aql}
        LAST 24 HOURS"""),
    "yara_l": dedent("""\
        rule {rule_yid} {{
          meta:
            author = \"TDL\"
            description = \"{name}\"
            severity = \"{severity_upper}\"
            tactic = \"{tactic_id}\"
            technique = \"{technique_id}\"
          events:
            $e.metadata.event_type = \"PROCESS_LAUNCH\"
            {yara_match}
            $host = $e.principal.hostname
          match:
            $host over 30m
          condition:
            $e
        }}"""),
    "esql": dedent("""\
        FROM logs-endpoint*,logs-windows*
        | WHERE @timestamp > NOW() - 1 hour
        | WHERE event.category == \"process\" AND {filter_esql}
        | STATS count = COUNT(*) BY host.name, user.name, process.name, process.parent.name, process.command_line
        | SORT count DESC"""),
    "leql": dedent("""\
        where(logset = \"Endpoint Activity\" AND {filter_leql})
        groupby(asset, process_name, parent_process_name)
        calculate(count)"""),
    "crowdstrike": dedent("""\
        event_simpleName=ProcessRollup2 {filter_cs}
        | stats count as occurrences by ComputerName, UserName, FileName, ParentBaseFileName, CommandLine
        | sort -occurrences"""),
    "xql": dedent("""\
        dataset = xdr_data
        | filter event_type = ENUM.PROCESS AND {filter_xql}
        | comp count() as occurrences by agent_hostname, actor_effective_username, action_process_image_name, causality_actor_process_image_name, action_process_image_command_line
        | sort desc occurrences"""),
    "lucene": "event.category:\"process\" AND {filter_lucene}",
}

NETWORK_FAMILY = {
    "spl": dedent("""\
        index=network sourcetype=firewall OR sourcetype=ids
        | search {filter}
        | stats count, dc(dest_ip) as unique_dests, sum(bytes_out) as bytes_out by src_ip, dest_ip, dest_port
        | where count >= 1
        | sort - bytes_out"""),
    "kql": dedent("""\
        union (DeviceNetworkEvents), (CommonSecurityLog | extend SourceIP=tostring(SourceIP), DestinationIP=tostring(DestinationIP))
        | where TimeGenerated > ago(1d)
        | where {filter_kql}
        | summarize Count=count(), Bytes=sum(coalesce(SentBytes, 0)) by SourceIP, DestinationIP, DestinationPort
        | order by Bytes desc"""),
    "aql": dedent("""\
        SELECT sourceip, destinationip, destinationport, SUM(eventcount) as connections, SUM(bytessrc) as bytes_out
        FROM flows
        WHERE {filter_aql}
        GROUP BY sourceip, destinationip, destinationport
        LAST 1 HOURS"""),
    "yara_l": dedent("""\
        rule {rule_yid} {{
          meta:
            author = \"TDL\"
            description = \"{name}\"
            severity = \"{severity_upper}\"
            tactic = \"{tactic_id}\"
            technique = \"{technique_id}\"
          events:
            $e.metadata.event_type = \"NETWORK_CONNECTION\"
            {yara_match}
            $src = $e.principal.ip
          match:
            $src over 10m
          condition:
            $e
        }}"""),
    "esql": dedent("""\
        FROM logs-network*,logs-endpoint*
        | WHERE @timestamp > NOW() - 1 hour
        | WHERE event.category == \"network\" AND {filter_esql}
        | STATS bytes_out = SUM(network.bytes), conns = COUNT(*) BY source.ip, destination.ip, destination.port
        | SORT bytes_out DESC"""),
    "leql": dedent("""\
        where(logset = \"Network Activity\" AND {filter_leql})
        groupby(source_ip, destination_ip, destination_port)
        calculate(count, sum(bytes_out))"""),
    "crowdstrike": dedent("""\
        event_simpleName IN (NetworkConnectIP4, NetworkConnectIP6, DnsRequest) {filter_cs}
        | stats count as conns, sum(BytesSent) as bytes_out by ComputerName, RemoteAddressIP4, RemotePort
        | sort -bytes_out"""),
    "xql": dedent("""\
        dataset = xdr_data
        | filter event_type = ENUM.NETWORK AND {filter_xql}
        | comp count() as conns, sum(action_total_bytes) as bytes_out by agent_hostname, action_remote_ip, action_remote_port
        | sort desc bytes_out"""),
    "lucene": "event.category:\"network\" AND {filter_lucene}",
}

REGISTRY_FAMILY = {
    "spl": dedent("""\
        index=endpoint sourcetype=Sysmon (EventCode=12 OR EventCode=13 OR EventCode=14)
        | search {filter}
        | stats count, values(host) as hosts by user, target_object, details, image
        | sort - count"""),
    "kql": dedent("""\
        DeviceRegistryEvents
        | where TimeGenerated > ago(1d)
        | where {filter_kql}
        | summarize Count=count() by DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
        | order by Count desc"""),
    "aql": dedent("""\
        SELECT DEVICETIME, sourceip, "Registry Key", "Registry Value Name", "Registry Value Data", "Process Name"
        FROM events
        WHERE LOGSOURCETYPENAME(devicetype) = 'Microsoft Windows Sysmon'
          AND "EventID" IN ('12','13','14')
          AND {filter_aql}
        LAST 24 HOURS"""),
    "yara_l": dedent("""\
        rule {rule_yid} {{
          meta:
            author = \"TDL\"
            description = \"{name}\"
            severity = \"{severity_upper}\"
            tactic = \"{tactic_id}\"
            technique = \"{technique_id}\"
          events:
            $e.metadata.event_type = \"REGISTRY_MODIFICATION\"
            {yara_match}
            $host = $e.principal.hostname
          match:
            $host over 30m
          condition:
            $e
        }}"""),
    "esql": dedent("""\
        FROM logs-endpoint*
        | WHERE @timestamp > NOW() - 1 hour
        | WHERE event.category == \"registry\" AND {filter_esql}
        | STATS count = COUNT(*) BY host.name, user.name, registry.path, registry.value, process.name
        | SORT count DESC"""),
    "leql": dedent("""\
        where(logset = \"Endpoint Activity\" AND log_type = \"registry\" AND {filter_leql})
        groupby(asset, registry_key, registry_value)
        calculate(count)"""),
    "crowdstrike": dedent("""\
        event_simpleName IN (RegSystemConfigValueUpdate, RegGenericValueUpdate) {filter_cs}
        | stats count as changes by ComputerName, UserName, RegObjectName, RegStringValue
        | sort -changes"""),
    "xql": dedent("""\
        dataset = xdr_data
        | filter event_type = ENUM.REGISTRY AND {filter_xql}
        | comp count() as changes by agent_hostname, actor_effective_username, action_registry_key_name, action_registry_value_name
        | sort desc changes"""),
    "lucene": "event.category:\"registry\" AND {filter_lucene}",
}

FILE_FAMILY = {
    "spl": dedent("""\
        index=endpoint sourcetype=Sysmon (EventCode=11 OR EventCode=23 OR EventCode=26)
        | search {filter}
        | stats count, values(host) as hosts by user, image, target_filename
        | where count >= 1
        | sort - count"""),
    "kql": dedent("""\
        DeviceFileEvents
        | where TimeGenerated > ago(1d)
        | where {filter_kql}
        | summarize Count=count() by DeviceName, InitiatingProcessFileName, FolderPath, FileName
        | order by Count desc"""),
    "aql": dedent("""\
        SELECT DEVICETIME, sourceip, "File Path", "Process Name"
        FROM events
        WHERE LOGSOURCETYPENAME(devicetype) = 'Microsoft Windows Sysmon'
          AND "EventID" IN ('11','23','26')
          AND {filter_aql}
        LAST 24 HOURS"""),
    "yara_l": dedent("""\
        rule {rule_yid} {{
          meta:
            author = \"TDL\"
            description = \"{name}\"
            severity = \"{severity_upper}\"
            tactic = \"{tactic_id}\"
            technique = \"{technique_id}\"
          events:
            $e.metadata.event_type = \"FILE_CREATION\"
            {yara_match}
            $host = $e.principal.hostname
          match:
            $host over 30m
          condition:
            $e
        }}"""),
    "esql": dedent("""\
        FROM logs-endpoint*
        | WHERE @timestamp > NOW() - 1 hour
        | WHERE event.category == \"file\" AND {filter_esql}
        | STATS count = COUNT(*) BY host.name, user.name, file.path, process.name
        | SORT count DESC"""),
    "leql": dedent("""\
        where(logset = \"Endpoint Activity\" AND log_type = \"file\" AND {filter_leql})
        groupby(asset, file_path, process_name)
        calculate(count)"""),
    "crowdstrike": dedent("""\
        event_simpleName IN (FileWritten, NewExecutableWritten) {filter_cs}
        | stats count as writes by ComputerName, UserName, FileName, ImageFileName
        | sort -writes"""),
    "xql": dedent("""\
        dataset = xdr_data
        | filter event_type = ENUM.FILE AND {filter_xql}
        | comp count() as writes by agent_hostname, actor_effective_username, action_file_name, action_file_path
        | sort desc writes"""),
    "lucene": "event.category:\"file\" AND {filter_lucene}",
}

CLOUD_FAMILY = {
    "spl": dedent("""\
        index=cloud (sourcetype=aws:cloudtrail OR sourcetype=azure:auditlogs OR sourcetype=gcp:audit)
        | search {filter}
        | stats count, values(sourceIPAddress) as src_ips by userIdentity.arn, eventName, resources{{}}.ARN
        | where count >= 1
        | sort - count"""),
    "kql": dedent("""\
        union AWSCloudTrail, AzureActivity, AuditLogs
        | where TimeGenerated > ago(1d)
        | where {filter_kql}
        | summarize Count=count() by Identity, EventName=coalesce(EventName, OperationName), Resource=tostring(coalesce(ResourceId, ResourceProvider))
        | order by Count desc"""),
    "aql": dedent("""\
        SELECT DEVICETIME, "User Identity", "Event Name", "Source IP Address"
        FROM events
        WHERE LOGSOURCETYPENAME(devicetype) IN ('AWS CloudTrail','Azure Audit','GCP Cloud Audit')
          AND {filter_aql}
        LAST 24 HOURS"""),
    "yara_l": dedent("""\
        rule {rule_yid} {{
          meta:
            author = \"TDL\"
            description = \"{name}\"
            severity = \"{severity_upper}\"
            tactic = \"{tactic_id}\"
            technique = \"{technique_id}\"
          events:
            $e.metadata.event_type = \"USER_RESOURCE_ACCESS\"
            {yara_match}
            $actor = $e.principal.user.userid
          match:
            $actor over 30m
          condition:
            $e
        }}"""),
    "esql": dedent("""\
        FROM logs-aws*,logs-azure*,logs-gcp*
        | WHERE @timestamp > NOW() - 1 hour
        | WHERE {filter_esql}
        | STATS count = COUNT(*) BY user.name, event.action, cloud.account.id
        | SORT count DESC"""),
    "leql": dedent("""\
        where(logset IN [\"AWS CloudTrail\", \"Azure Audit\", \"GCP Audit\"] AND {filter_leql})
        groupby(actor, event_name)
        calculate(count)"""),
    "crowdstrike": dedent("""\
        event_simpleName=CloudOcsfApiActivity {filter_cs}
        | stats count as calls by Actor, ApiName, SourceIPAddress
        | sort -calls"""),
    "xql": dedent("""\
        dataset = cloud_audit_logs
        | filter {filter_xql}
        | comp count() as calls by actor_effective_username, action_evtlog_event_name, action_remote_ip
        | sort desc calls"""),
    "lucene": "event.dataset:(\"aws.cloudtrail\" OR \"azure.audit\" OR \"gcp.audit\") AND {filter_lucene}",
}


# ----------------------------------------------------------------------
# Per-(technique_id, command) filter snippets
#
# Each snippet returns a dict with the per-SIEM filter literal. Most filters
# are deliberately small — they're starting points the analyst will tune.
# ----------------------------------------------------------------------

def _basic_filter(field, equals=None, regex=None):
    """Generate a uniform per-language filter snippet."""
    if equals is not None:
        v = equals
        return {
            "filter": f"{field}=\"{v}\"",
            "filter_kql": f"{field} =~ \"{v}\"",
            "filter_aql": f"\"{field}\" = '{v}'",
            "filter_esql": f"{field} == \"{v}\"",
            "filter_leql": f"{field}=\"{v}\"",
            "filter_cs": f"AND {field}=\"{v}\"",
            "filter_xql": f"{field} = \"{v}\"",
            "filter_lucene": f"{field}:\"{v}\"",
            "yara_match": f"$e.{field} = \"{v}\"",
        }
    if regex is not None:
        v = regex
        return {
            "filter": f"{field}=\"*{v}*\"",
            "filter_kql": f"{field} matches regex \"{v}\"",
            "filter_aql": f"\"{field}\" LIKE '%{v}%'",
            "filter_esql": f"{field} LIKE \"%{v}%\"",
            "filter_leql": f"{field}=/{v}/",
            "filter_cs": f"AND {field}=*{v}*",
            "filter_xql": f"{field} ~= \"{v}\"",
            "filter_lucene": f"{field}:*{v}*",
            "yara_match": f"$e.{field} = /{v}/",
        }
    return {k: "*" for k in ("filter", "filter_kql", "filter_aql", "filter_esql", "filter_leql", "filter_cs", "filter_xql", "filter_lucene", "yara_match")}


# Map (technique_id, command) → (family, filter_snippet)
# `family` is one of the *_FAMILY dicts above.

def _resolve(technique_id, hint):
    """Pick the right family + filter snippet for a given hint."""
    field = hint.get("field", "process.command_line")
    cmd = hint.get("command", "")
    event = hint.get("event", "ProcessCreate")

    # Cloud-flavored techniques
    if event in ("ConsoleLogin", "CreateFunction", "PushImage", "RunInstances",
                 "DescribeAll", "ListServices", "ListObjects", "GetObject",
                 "RoleAssignment", "AAD", "OAuthConsent", "PasswordReset",
                 "K8sApi", "CreatePod", "GroupAddMember", "TokenIssue", "MfaPush", "MfaSuccess"):
        return CLOUD_FAMILY, _basic_filter(field, regex=cmd)

    # Network-flavored
    if event in ("NetworkConnect", "Tls", "Http", "Dns", "Icmp", "Arp",
                 "Promiscuous", "EmailReceived", "EmailSent", "Login",
                 "BitsClient", "NetdevConfig", "ShareAccess", "PageView",
                 "InboxRule", "DbWrite", "AdcsIssue", "TgsRequest", "RpcCall",
                 "DirectoryReplication", "DeviceTransfer", "DeviceConnect",
                 "DeviceAccess", "GpoChange", "Deploy", "PolicyChange",
                 "WmiEvent"):
        return NETWORK_FAMILY, _basic_filter(field, regex=cmd)

    # Registry-flavored
    if event in ("RegistryEvent",):
        return REGISTRY_FAMILY, _basic_filter(field, regex=cmd)

    # File-flavored
    if event in ("FileCreate", "FileWrite", "FileModify", "FileAccess",
                 "FileDelete", "FileRename"):
        return FILE_FAMILY, _basic_filter(field, regex=cmd)

    # Default: process
    return PROCESS_FAMILY, _basic_filter(field, regex=cmd)


def render(rule_id, technique_id, tactic_id, name, severity, hint):
    """Render the queries dict for a rule.

    Returns dict[str, str] with keys spl, kql, aql, yara_l, esql, leql,
    crowdstrike, xql, lucene.
    """
    family, snippet = _resolve(technique_id, hint)
    rule_yid = "tdl_" + rule_id.lower().replace("-", "_")
    severity_upper = severity.upper()

    ctx = {
        "rule_yid": rule_yid,
        "name": name.replace("\"", "'"),
        "severity_upper": severity_upper,
        "tactic_id": tactic_id,
        "technique_id": technique_id,
        **snippet,
    }

    out = {}
    for key, tmpl in family.items():
        try:
            out[key] = tmpl.format(**ctx)
        except (KeyError, IndexError):
            # Fallback to a bare reference if a templating placeholder is
            # missing for an unusual hint shape.
            out[key] = f"# Detection placeholder for {technique_id}: tune from pseudo_logic"
    return out
