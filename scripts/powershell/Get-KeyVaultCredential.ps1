<#
.SYNOPSIS
    Retrieves credentials from Azure Key Vault using Managed Identity.
    Use this pattern in all Automation runbooks — never hardcode credentials.

.DESCRIPTION
    Azure Automation runbook helper for securely retrieving secrets from
    Key Vault via the Automation Account's System-Assigned Managed Identity.

.PREREQUISITES
    - Automation Account with System-Assigned Managed Identity enabled
    - Managed Identity granted 'Key Vault Secrets User' role on the Key Vault
    - Key Vault name stored as an Automation Variable: 'KeyVaultName'

.NOTES
    Key Vault: kv-dba-prod (replace with YOUR_KEYVAULT_NAME)
    Secrets expected:
      - sql-svc-account-password
      - ag-monitoring-sql-password
      - automation-sql-connection-string
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SqlInstance,

    [Parameter(Mandatory = $false)]
    [string]$Database = 'master'
)

# ── Connect via Managed Identity (no stored credentials needed) ──────────────
Connect-AzAccount -Identity

# ── Retrieve Key Vault name from Automation Variable ────────────────────────
$kvName = Get-AutomationVariable -Name 'KeyVaultName'

# ── Retrieve secret from Key Vault ──────────────────────────────────────────
$sqlPassword = Get-AzKeyVaultSecret `
    -VaultName $kvName `
    -Name 'sql-svc-account-password' `
    -AsPlainText

# ── Build credential object ──────────────────────────────────────────────────
$securePassword = ConvertTo-SecureString $sqlPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential('svc_automation', $securePassword)

# ── Example: run a query against the SQL instance ───────────────────────────
try {
    $result = Invoke-Sqlcmd `
        -ServerInstance $SqlInstance `
        -Database $Database `
        -Query "SELECT @@SERVERNAME AS ServerName, GETDATE() AS CheckTime" `
        -Credential $credential `
        -TrustServerCertificate

    Write-Output "Connected to: $($result.ServerName) at $($result.CheckTime)"
}
catch {
    Write-Error "Failed to connect to $SqlInstance. Error: $_"
    throw
}
