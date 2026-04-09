# Runbook 3: Security Alerts & Microsoft Sentinel

**Purpose:** Enable Defender for Cloud, onboard Sentinel, configure security alert rules  
**Estimated Time:** 4–6 hours initial setup  
**Permissions Required:** Security Admin, Microsoft Sentinel Contributor, Log Analytics Contributor

---

## Phase 1: Enable Microsoft Defender for Cloud

### 1.1 — Enable Defender Plans
1. Azure Portal > Microsoft Defender for Cloud > Environment Settings
2. Select your Subscription
3. Enable:
   - **Defender for Servers (Plan 2)** — covers Arc-connected servers; includes 500 MB/day free log ingestion, endpoint protection assessment, and file integrity monitoring
   - **Defender for SQL on Azure VMs** — SQL on IaaS VMs
   - **Defender for SQL on machines** — Arc-connected on-prem SQL

### 1.2 — Configure Auto-Provisioning
1. Defender for Cloud > Environment Settings > Auto provisioning
2. Enable:
   - Azure Monitor Agent (AMA)
   - Vulnerability assessment (Microsoft Defender Vulnerability Management)
   - Guest configuration agent

### 1.3 — Secure Score Quick Wins
Priority recommendations to address first:
- Enable MFA for accounts with owner permissions
- Enable TDE on SQL databases
- Restrict RDP access (JIT or NSG rules)
- Apply missing system updates

---

## Phase 2: Enable Microsoft Sentinel

### 2.1 — Add Sentinel to Workspace
1. Microsoft Sentinel > Create
2. Select your existing Log Analytics Workspace
3. Click **Add Microsoft Sentinel** (~2–3 min deployment)

### 2.2 — Connect Data Connectors
| Connector | Notes |
|---|---|
| Microsoft Defender for Cloud | Streams all Defender alerts into Sentinel |
| Azure Active Directory | Sign-in logs, audit logs — requires Global Admin or Security Admin consent |
| Azure Activity | Subscription-level operations |
| Security Events via AMA | Windows Security Event Log — requires DCR |
| Microsoft Defender for SQL | SQL threat alerts |

### 2.3 — Enable Built-in Analytics Rules
Sentinel > Analytics > Rule templates > Filter: Data sources = Security Events

Enable:
- Brute force attack against a Cloud PC (Event 4625)
- Failed login attempts to Azure Portal
- Suspicious number of resource creation or deployment activities
- Rare subscription-level operations in Azure
- Anomalous sign-in activity *(requires UEBA enabled)*

---

## Phase 3: Custom KQL Security Rules

See [`/kql/sentinel/sentinel-custom-rules.kql.md`](../kql/sentinel/sentinel-custom-rules.kql.md) for all query definitions.

| Rule | Severity | MITRE |
|---|---|---|
| Failed Login Spike On-Prem Servers | High | T1110 |
| New Local Admin Added | High | T1069 |
| After Hours Login | Medium | T1078 |
| RDP from Public IP | High | T1021.001 |
| Privileged AAD Role Assigned | High | T1078.004 |
| JIT Access Request Logged | Info | — |

---

## Phase 4: Incidents & Automation

### 4.1 — Enable UEBA
Sentinel > Settings > Entity behavior > Enable  
Data sources: Azure Active Directory, Security Events

### 4.2 — Automation Rule: Auto-Triage SQL Incidents
- Trigger: When incident is created
- Condition: Incident title contains 'SQL'
- Actions: Assign owner, Change status to Active

---

## Validation Checklist

- [ ] Defender for Cloud shows active plans for Servers and SQL
- [ ] Sentinel workspace has data flowing (check ingestion graphs)
- [ ] At least 4 data connectors connected and flowing
- [ ] 3+ built-in analytics rules enabled
- [ ] 5 custom KQL rules created and enabled
- [ ] UEBA enabled and active
- [ ] Incident automation rule configured
