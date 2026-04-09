# KQL — Azure Workbook Dashboard Queries

Queries used in Azure Monitor Workbooks. All are interactive and support
time range parameters where noted.

---

## Workbook 1: Security Posture Dashboard

### Secure Score Trend
**Data source:** Azure Resource Graph  
**Visualization:** Line chart | X: timeGenerated | Y: score

```kql
securityresources
| where type == 'microsoft.security/securescores'
| extend score = properties.score.current
| project subscriptionId, score, timeGenerated = todatetime(properties.displayName)
```

### Open Recommendations by Severity
**Data source:** Azure Resource Graph  
**Visualization:** Bar chart

```kql
securityresources
| where type == 'microsoft.security/assessments'
| where properties.status.code == 'Unhealthy'
| summarize Count = count() by Severity = tostring(properties.metadata.severity)
| order by Count desc
```

### Unpatched Servers Table
**Visualization:** Grid | Color threshold: red > 5 missing patches

```kql
Update
| where Classification in ('Critical Updates', 'Security Updates')
    and UpdateState == 'Needed'
| summarize MissingPatches = count() by Computer, OSType
| order by MissingPatches desc
```

---

## Workbook 2: Failed Login Heatmap
**Parameter:** `{TimeRange}` — Time range picker, default Last 7 days

### Failures by Hour (Heatmap)
**Visualization:** Heatmap | X: HourOfDay | Y: Computer | Value: Failures | Color: Red scale

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated {TimeRange}
| extend HourOfDay = datetime_part('hour', TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated) / 1d
| summarize Failures = count() by HourOfDay, Computer
| order by HourOfDay asc
```

### Top Targeted Accounts
**Visualization:** Grid with Failures column as bar visualization

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated {TimeRange}
| summarize Failures = count() by Account, Computer
| top 10 by Failures
```

---

## Workbook 3: SQL Availability Group Health

### AG Failover Events (Last 30 Days)
**Visualization:** Table | Sorted by TimeGenerated desc

```kql
Event
| where EventLog == 'Application'
    and Source == 'MSSQLSERVER'
| where EventID in (1480, 35264, 35265, 35267, 35268)
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
```

### Last Backup per Database
**Note:** Requires `SQLBackupLog_CL` custom table populated by Automation runbook  
**Visualization:** Grid | Color threshold: HoursSinceBackup > 25 = Red

```kql
SQLBackupLog_CL
| summarize LastBackup = max(BackupEnd_t) by DatabaseName_s, ServerName_s
| extend HoursSinceBackup = datetime_diff('hour', now(), LastBackup)
| order by HoursSinceBackup desc
```

### SQL Drive Free Space Trend
**Visualization:** Line chart — one line per Computer + Drive

```kql
Perf
| where ObjectName == 'LogicalDisk'
    and CounterName == '% Free Space'
| where InstanceName in ('D:', 'L:', 'T:')
| where Computer contains 'SQL'
| summarize AvgFree = avg(CounterValue) by Computer, InstanceName, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

---

## Workbook 4: Arc Server Fleet Health

### Heartbeat Status Table
**Visualization:** Grid | Status column: green = Online, red = OFFLINE

```kql
Heartbeat
| summarize LastHeartbeat = max(TimeGenerated),
            AgentVersion = max(AgentVersion),
            OSType = max(OSType) by Computer
| extend MinutesSinceHeartbeat = datetime_diff('minute', now(), LastHeartbeat)
| extend Status = iff(MinutesSinceHeartbeat < 6, 'Online', 'OFFLINE')
| order by Status asc
```

### Recent Security Alerts by Server (Last 7 Days)
**Visualization:** Heatmap or stacked bar

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize AlertCount = count() by CompromisedEntity, AlertSeverity
| order by AlertCount desc
```

### Patch Compliance Summary
**Visualization:** Bar chart grouped by Computer

```kql
Update
| where UpdateState == 'Needed'
| summarize Missing = count() by Computer, Classification
| where Classification in ('Critical Updates', 'Security Updates')
```
