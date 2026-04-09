# KQL — Azure Arc Server Alerting

All queries target a Log Analytics Workspace with AMA/DCR collecting
Windows Performance Counters, Event Logs, and Heartbeat data from Arc-connected servers.

---

## CPU Alert
**Alert name:** `Alert-ArcServer-HighCPU`  
**Severity:** 2 (Warning)  
**Evaluate:** Every 5 min | Lookback: 15 min | Threshold: > 90%

```kql
Perf
| where ObjectName in ("Processor Information", "Processor")
| where CounterName == "% Processor Time"
| where InstanceName == "_Total"
| summarize AvgCPU = avg(CounterValue) by _ResourceId, Computer, bin(TimeGenerated, 5m)
```

---

## Memory Alert
**Alert name:** `Alert-ArcServer-LowMemory`  
**Severity:** 2 (Warning)  
**Evaluate:** Every 5 min | Lookback: 15 min | Threshold: < 90%

```kql
Perf
| where ObjectName == "Memory"
| where CounterName == "% Committed Bytes In Use"
| summarize AvgCommittedPct = avg(CounterValue) by _ResourceId, Computer, bin(TimeGenerated, 5m)
```

---

## Disk Space Alert
**Alert name:** `Alert-ArcServer-LowDiskSpace`  
**Severity:** 1 (Critical)  
**Evaluate:** Every 15 min | Lookback: 30 min | Threshold: > 90% used

```kql
InsightsMetrics
| where Origin == "vm.azm.ms"
| where Namespace == "LogicalDisk"
| where Name == "FreeSpacePercentage"
| extend Disk = tostring(todynamic(Tags)["vm.azm.ms/mountId"])
| where isnotempty(Disk)
| extend Host = tostring(split(Computer, ".")[0])
| extend Resource = strcat(Host, " | ", Disk)
| extend UsedPct = 100.0 - todouble(Val)
| project _ResourceId, TimeGenerated, Resource, UsedPct
```

---

## Heartbeat Loss Alert (Critical)
**Alert name:** `Alert-ArcServer-HeartbeatLoss`  
**Severity:** 1 (Critical)  
**Evaluate:** Every 5 min | Threshold: > 0 results  
**Note:** Missing heartbeat may indicate outage, network issue, or agent tampering. Correlate with security events.

```kql
Heartbeat
| summarize LastHeartbeat = max(TimeGenerated) by Computer
| where LastHeartbeat < ago(5m)
```

---

## Failed Login — Brute Force (Event ID 4625)
**Alert name:** `Alert-ArcServer-BruteForce`  
**Severity:** 1 (Critical)  
**Threshold:** > 10 failures per computer/account in 15 min

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by Computer, Account, bin(TimeGenerated, 15m)
| where FailedLogins > 10
```

---

## Privilege Escalation (Event ID 4672)
**Alert name:** `Alert-ArcServer-PrivilegeUse`  
**Severity:** 2 (Warning)

```kql
SecurityEvent
| where EventID == 4672
| where SubjectUserName !endswith '$'
| summarize count() by Computer, SubjectUserName, bin(TimeGenerated, 1h)
```

---

## Service Crash (Event ID 7034 / 7036)
**Alert name:** `Alert-ArcServer-ServiceCrash`  
**Severity:** 2 (Warning)

```kql
Event
| where EventLog == 'System'
    and EventID in (7034, 7036)
| where RenderedDescription contains 'terminated unexpectedly'
```

---

## Update Manager — Critical Patch Missing
**Alert name:** `Alert-ArcServer-CriticalPatchMissing`  
**Severity:** 1 (Critical)  
**Data source:** Azure Resource Graph (PatchAssessmentResources)

```kql
PatchAssessmentResources
| where type == 'microsoft.compute/virtualmachines/patchassessmentresults'
| where properties.availablePatchCountByClassification.critical > 0
```
