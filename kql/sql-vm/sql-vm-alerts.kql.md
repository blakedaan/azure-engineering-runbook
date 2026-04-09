# KQL — SQL Server VM Alerting

Queries for SQL VMs in Azure with the SQL IaaS Extension installed.
Log sources: Windows Application/Security Event Log, Perf counters, Azure Backup signals.

---

## Availability Group — Replica Disconnect
**Alert name:** `Alert-SQLVM-AGReplicaDisconnect`  
**Severity:** 1 (Critical)  
**Evaluate:** Every 5 min  
**Event IDs:** 35264, 35265, 35267, 35268

```kql
Event
| where EventLog == 'Application'
    and Source == 'MSSQLSERVER'
| where EventID in (35264, 35265, 35267, 35268)
| project TimeGenerated, Computer, RenderedDescription
```

---

## Availability Group — Failover Detection
**Alert name:** `Alert-SQLVM-AGFailover`  
**Severity:** 1 (Critical)  
**Note:** Event 1480 fires on the new primary after failover. Alert the entire on-call team immediately.

```kql
Event
| where EventLog == 'Application'
    and Source == 'MSSQLSERVER'
| where EventID == 1480
| project TimeGenerated, Computer, RenderedDescription
```

---

## SA Account Login Alert
**Alert name:** `Alert-SQLVM-SALogin`  
**Severity:** 1 (Critical)  
**Note:** SA account should be disabled. Any SA login is a red flag — investigate immediately.

```kql
Event
| where EventLog == 'Application'
    and Source == 'MSSQLSERVER'
| where RenderedDescription contains 'Login succeeded'
    and RenderedDescription contains "'sa'"
```

---

## SQL Login Brute Force (Failed Logins)
**Alert name:** `Alert-SQLVM-SQLLoginBrute`  
**Severity:** 1 (Critical)  
**Threshold:** > 5 failures per account in 10 min  
**Prerequisite:** SQL Server audit must be enabled and writing to Windows Security Log

```kql
SecurityEvent
| where EventID == 4625
    and ProcessName contains 'sqlservr'
| summarize Failures = count() by Computer, Account, bin(TimeGenerated, 10m)
| where Failures > 5
```

---

## SQL Drive Low Disk Space
**Alert name:** `Alert-SQLVM-SQLDriveLow`  
**Severity:** 1 (Critical) at < 20% | Severity 0 (P1) at < 10%  
**Drives monitored:** D:\ (data), L:\ (logs), T:\ (TempDB)

```kql
Perf
| where ObjectName == 'LogicalDisk'
    and CounterName == '% Free Space'
| where InstanceName in ('D:', 'L:', 'T:')
| summarize AvgFree = avg(CounterValue) by Computer, InstanceName, bin(TimeGenerated, 10m)
| where AvgFree < 20
```

---

## TempDB / Log File Free Space (Custom Log Table)
**Alert name:** `Alert-SQLVM-TempDBLow`  
**Severity:** 1 (Critical)  
**Note:** Requires Azure Automation runbook to populate `SQLFileSpace_CL` custom log table via HTTP Data Collector API.

```kql
SQLFileSpace_CL
| where FreeMB_d < 1024
| project TimeGenerated, ServerName_s, DBName_s, FileName_s, FreeMB_d
| order by FreeMB_d asc
```

---

## SQL IaaS Extension Unhealthy
**Alert name:** `Alert-SQLVM-IaaSExtensionUnhealthy`  
**Severity:** 2 (Warning)  
**Data source:** Azure Resource Graph

```kql
resources
| where type == 'microsoft.sqlvirtualmachine/sqlvirtualmachines'
| where properties.provisioningState != 'Succeeded'
```

---

## SQL Audit — Failed / Suspicious Operations (Log Analytics)
**Alert name:** `Alert-SQLVM-SuspiciousAuditEvent`  
**Severity:** 2 (Warning)  
**Prerequisite:** SQL Server Audit enabled with destination = Log Analytics Workspace

```kql
AzureDiagnostics
| where Category == 'SQLSecurityAuditEvents'
| where action_name_s in ('INSERT', 'UPDATE', 'DELETE', 'SELECT')
| where succeeded_s == 'False'
| project TimeGenerated, server_instance_name_s, database_name_s,
          client_ip_s, action_name_s, statement_s
```
