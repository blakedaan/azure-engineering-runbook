# KQL — Microsoft Sentinel Custom Analytics Rules

Custom scheduled query rules for Microsoft Sentinel.
All rules include MITRE ATT&CK mapping where applicable.

---

## Failed Login Spike — On-Prem Servers
**Rule name:** `CUSTOM - Failed Login Spike On-Prem Servers`  
**Severity:** High  
**Run:** Every 5 min | Lookback: 15 min | Threshold: > 0 results  
**MITRE:** Credential Access > Brute Force (T1110)

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(15m)
| summarize FailureCount = count() by Computer, Account, IpAddress
| where FailureCount > 10
| extend AlertDetail = strcat('Account: ', Account, ' on ', Computer,
    ' --- ', tostring(FailureCount), ' failures from ', IpAddress)
```

---

## New Local Admin Account Added
**Rule name:** `CUSTOM - New Local Admin Added`  
**Severity:** High  
**MITRE:** Privilege Escalation > Local Groups (T1069)

```kql
SecurityEvent
| where EventID == 4732
| where TargetUserName == 'Administrators'
| project TimeGenerated, Computer, SubjectUserName, MemberName
```

---

## Login Outside Business Hours
**Rule name:** `CUSTOM - After Hours Login`  
**Severity:** Medium  
**Run:** Every 30 min | Lookback: 1 hour  
**Logon Types:** 2 (Interactive), 10 (RemoteInteractive)

```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (2, 10)
| extend HourOfDay = datetime_part('hour', TimeGenerated)
| where HourOfDay < 6 or HourOfDay > 20
| where AccountType == 'User'
| where Account !endswith '$'
```

---

## Inbound RDP from Public IP
**Rule name:** `CUSTOM - RDP from Public IP`  
**Severity:** High  
**Prerequisite:** NSG Flow Logs must be enabled (NSG > Diagnostic settings > Flow logs)

```kql
AzureNetworkAnalytics_CL
| where SubType_s == 'FlowLog'
| where DestPort_d == 3389
    and FlowDirection_s == 'I'
    and FlowStatus_s == 'A'
| where isnotempty(SrcIP_s)
| where SrcIP_s !startswith '10.'
    and SrcIP_s !startswith '192.168.'
| project TimeGenerated, SrcIP_s, DestIP_s, DestPort_d, VM_s
```

---

## Privileged AAD Role Assignment
**Rule name:** `CUSTOM - Privileged AAD Role Assigned`  
**Severity:** High  
**Data connector:** Azure Active Directory (Audit Logs)

```kql
AuditLogs
| where OperationName == 'Add member to role'
| where Result == 'success'
| extend RoleName = tostring(TargetResources[0].displayName)
| where RoleName in ('Global Administrator', 'Privileged Role Administrator', 'Security Administrator')
| project TimeGenerated, InitiatedBy, RoleName, TargetResources
```

---

## JIT VM Access Request (Audit Trail)
**Rule name:** `CUSTOM - JIT Access Request Logged`  
**Severity:** Informational  
**Note:** Good audit trail for all JIT access — log every open-port request.

```kql
AzureActivity
| where OperationNameValue == 'Microsoft.Security/locations/jitNetworkAccessPolicies/initiate/action'
| project TimeGenerated, Caller, ResourceGroup, Properties
```
