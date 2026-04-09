# Azure Engineering Runbook — Operations & Security

> **Environment:** Azure Hybrid (Arc-connected on-prem + Azure SQL VMs)  
> **Stack:** Azure Arc · SQL Server · Microsoft Sentinel · Defender for Cloud · Azure Automation  
> **Author:** Blake Daniels  
> **Last Updated:** April 2026

---

## Repository Structure

```
azure-engineering-runbook/
├── kql/
│   ├── arc-servers/        # Performance & availability alerts for Arc-connected servers
│   ├── sql-vm/             # SQL Server VM alerting queries
│   ├── sentinel/           # Custom Sentinel analytics rules (security)
│   └── workbooks/          # Dashboard queries for Azure Workbooks
├── scripts/
│   ├── powershell/         # Azure Automation runbook scripts
│   ├── bicep/              # IaC templates for SQL VM deployment
│   └── automation/         # Hybrid Worker & index maintenance scripts
├── alerts/                 # Alert rule reference (names, severities, MITRE mappings)
└── docs/                   # Runbook documentation and setup guides
```

---

## Runbooks Covered

| # | Runbook | Description |
|---|---------|-------------|
| 1 | [Arc Server Alerting](docs/runbook-1-arc-alerting.md) | CPU, memory, disk, heartbeat, and Windows event alerts for Arc servers |
| 2 | [SQL Server VM Alerting](docs/runbook-2-sql-alerting.md) | AG health, backup failures, login auditing, disk space for SQL VMs |
| 3 | [Sentinel & Defender](docs/runbook-3-sentinel.md) | Defender for Cloud, Sentinel onboarding, custom KQL security rules |
| 4 | [Workbooks & Dashboards](docs/runbook-4-workbooks.md) | Security posture, failed login heatmap, AG health, Arc fleet dashboards |
| 5 | [Automation & Security Projects](docs/runbook-5-automation.md) | JIT, Azure Policy, Key Vault, SQL Audit, tagging, Bicep IaC, Hybrid Worker |

---

## Quick Reference — Alert Names

See [`alerts/alert-inventory.md`](alerts/alert-inventory.md) for the full list of alert names, severities, and MITRE mappings.

---

## Security Notice

All queries, scripts, and templates in this repo have been sanitized.  
**Never commit:** tenant IDs, subscription IDs, resource names, passwords, connection strings, or any environment-specific identifiers.  
Use placeholders like `YOUR_SUBSCRIPTION_ID`, `YOUR_RG`, `YOUR_WORKSPACE_ID` throughout.

---

## Prerequisites

- Azure Arc agent installed on target servers
- Log Analytics Workspace provisioned
- Azure Monitor Agent (AMA) deployed via DCR
- Defender for Cloud enabled (Servers Plan 2 + Defender for SQL)
- Microsoft Sentinel added to Log Analytics Workspace
- Azure Automation Account with Hybrid Worker Group (for on-prem runbooks)
