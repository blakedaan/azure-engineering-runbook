<#
.SYNOPSIS
    Runs SQL Server index maintenance on Arc-connected on-premises instances
    via Azure Automation Hybrid Runbook Worker.

.DESCRIPTION
    Invokes Ola Hallengren's IndexOptimize stored procedure (or equivalent)
    against a target SQL instance. Credentials are retrieved from Key Vault
    via Managed Identity — no hardcoded passwords.

.PREREQUISITES
    - Hybrid Runbook Worker installed on Arc-connected SQL server
    - Hybrid Worker Group: HybridGroup-OnPremSQL
    - Ola Hallengren's maintenance solution deployed on target instance
    - Key Vault secret: sql-svc-account-password
    - Automation Variable: KeyVaultName

.SCHEDULE
    Weekly — Saturday 02:00 AM
    Run on: Hybrid Worker Group 'HybridGroup-OnPremSQL'

.PARAMETER SqlInstance
    SQL Server instance name (e.g., SQLSERVER01 or SQLSERVER01\INSTANCE)

.PARAMETER Database
    Target database or 'ALL_DATABASES' (default). Passed to IndexOptimize.

.PARAMETER FragmentationLow
    Minimum fragmentation % to trigger REORGANIZE (default: 5)

.PARAMETER FragmentationMedium
    Minimum fragmentation % to trigger REBUILD (default: 30)
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SqlInstance,

    [Parameter(Mandatory = $false)]
    [string]$Database = 'ALL_DATABASES',

    [Parameter(Mandatory = $false)]
    [int]$FragmentationLow = 5,

    [Parameter(Mandatory = $false)]
    [int]$FragmentationMedium = 30
)

# ── Connect via Managed Identity ─────────────────────────────────────────────
Connect-AzAccount -Identity

# ── Retrieve credentials from Key Vault ──────────────────────────────────────
$kvName    = Get-AutomationVariable -Name 'KeyVaultName'
$sqlPass   = Get-AzKeyVaultSecret -VaultName $kvName -Name 'sql-svc-account-password' -AsPlainText
$sqlUser   = 'svc_automation'

# ── Run IndexOptimize ─────────────────────────────────────────────────────────
Write-Output "Starting index maintenance on $SqlInstance — Database: $Database"
Write-Output "Fragmentation thresholds: Low=$FragmentationLow% | Medium=$FragmentationMedium%"

try {
    $query = @"
EXEC dbo.IndexOptimize
    @Databases = '$Database',
    @FragmentationLow = NULL,
    @FragmentationMedium = 'INDEX_REORGANIZE',
    @FragmentationHigh = 'INDEX_REBUILD_ONLINE,INDEX_REBUILD_OFFLINE',
    @FragmentationLevel1 = $FragmentationLow,
    @FragmentationLevel2 = $FragmentationMedium,
    @UpdateStatistics = 'ALL',
    @OnlyModifiedStatistics = 'Y',
    @LogToTable = 'Y'
"@

    Invoke-Sqlcmd `
        -ServerInstance $SqlInstance `
        -Database 'master' `
        -Query $query `
        -Username $sqlUser `
        -Password $sqlPass `
        -QueryTimeout 7200 `
        -TrustServerCertificate

    Write-Output "Index maintenance completed successfully on $SqlInstance"
}
catch {
    Write-Error "Index maintenance failed on $SqlInstance. Error: $_"
    throw
}
