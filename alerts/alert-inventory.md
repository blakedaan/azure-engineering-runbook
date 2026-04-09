# Alert Inventory

Complete reference of all alert rules defined in this runbook.
Use this as a checklist during deployment and as a source-of-truth for naming conventions.

---

## Arc Server Alerts (Runbook 1)

| Alert Name | Severity | Evaluate | Lookback | Threshold | Notes |
|---|---|---|---|---|---|
| `Alert-ArcServer-HighCPU` | 2 — Warning | 5 min | 15 min | AvgCPU > 90% | |
| `Alert-ArcServer-LowMemory` | 2 — Warning | 5 min | 15 min | AvgMemMB < 512 | |
| `Alert-ArcServer-LowDiskSpace` | 1 — Critical | 15 min | 30 min | AvgFree < 15% | |
| `Alert-ArcServer-HeartbeatLoss` | 1 — Critical | 5 min | — | > 0 results | Possible security incident |
| `Alert-ArcServer-BruteForce` | 1 — Critical | 15 min | 15 min | > 10 failures | Event ID 4625 |
| `Alert-ArcServer-PrivilegeUse` | 2 — Warning | 1 hr | 1 hr | Any occurrence | Event ID 4672 |
| `Alert-ArcServer-ServiceCrash` | 2 — Warning | — | — | Any occurrence | Event ID 7034/7036 |
| `Alert-ArcServer-CriticalPatchMissing` | 1 — Critical | Daily | — | critical > 0 | Resource Graph |

---

## SQL VM Alerts (Runbook 2)

| Alert Name | Severity | Evaluate | Lookback | Threshold | Notes |
|---|---|---|---|---|---|
| `Alert-SQLVM-AGReplicaDisconnect` | 1 — Critical | 5 min | 5 min | > 0 results | Event IDs 35264–35268 |
| `Alert-SQLVM-AGFailover` | 1 — Critical | 5 min | 5 min | > 0 results | Event ID 1480 — alert full on-call |
| `Alert-SQLVM-SALogin` | 1 — Critical | — | — | Any occurrence | SA account should be disabled |
| `Alert-SQLVM-SQLLoginBrute` | 1 — Critical | 10 min | 10 min | > 5 failures | Requires SQL audit enabled |
| `Alert-SQLVM-BackupFailed` | 1 — Critical | — | — | Job status = Failed | Via Recovery Services Vault |
| `Alert-SQLVM-SQLDriveLow` | 1 — Critical | 10 min | 10 min | < 20% free | D:\, L:\, T:\ drives |
| `Alert-SQLVM-SQLDriveCritical` | 0 — P1 | 10 min | 10 min | < 10% free | Second rule, higher urgency |
| `Alert-SQLVM-TempDBLow` | 1 — Critical | — | — | FreeMB < 1024 | Custom log table required |
| `Alert-SQLVM-IaaSExtensionUnhealthy` | 2 — Warning | — | — | provisioningState != Succeeded | Resource Graph |
| `Alert-SQLVM-SuspiciousAuditEvent` | 2 — Warning | — | — | Failed ops | Requires SQL Audit → Log Analytics |

---

## Sentinel Custom Rules (Runbook 3)

| Rule Name | Severity | Run Frequency | Lookback | MITRE Tactic | MITRE Technique |
|---|---|---|---|---|---|
| `CUSTOM - Failed Login Spike On-Prem Servers` | High | 5 min | 15 min | Credential Access | T1110 — Brute Force |
| `CUSTOM - New Local Admin Added` | High | — | — | Privilege Escalation | T1069 — Local Groups |
| `CUSTOM - After Hours Login` | Medium | 30 min | 1 hr | Initial Access | T1078 — Valid Accounts |
| `CUSTOM - RDP from Public IP` | High | — | — | Lateral Movement | T1021.001 — RDP |
| `CUSTOM - Privileged AAD Role Assigned` | High | — | — | Privilege Escalation | T1078.004 — Cloud Accounts |
| `CUSTOM - JIT Access Request Logged` | Informational | — | — | — | Audit trail only |

---

## Naming Convention

```
Alert-{Scope}-{Description}
CUSTOM - {Description}
```

- **Scope:** `ArcServer`, `SQLVM`, `Sentinel`
- **Severity:** 0 = P1/Emergency, 1 = Critical, 2 = Warning, 3 = Informational
- **Sentinel rules** use `CUSTOM -` prefix to distinguish from built-in templates

---

## Action Groups

| Action Group | Display Name | Linked Alerts |
|---|---|---|
| `AG-DBA-Alerts` | DBA Alerts | All Arc + SQL VM alerts |
| *(Sentinel uses Automation Rules for incident routing)* | | |
