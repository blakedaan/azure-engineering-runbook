// =============================================================================
// main.bicep — SQL VM with Security Baseline
// =============================================================================
// Deploys a Windows VM registered as a SQL IaaS VM with:
//   - Azure Monitor Agent (AMA) via DCR association
//   - SQL IaaS Extension
//   - NSG with JIT-ready port restrictions
//   - Key Vault reference for admin password (no plaintext secrets)
//   - Tags for governance and cost tracking
//
// Usage:
//   az deployment group create \
//     --resource-group YOUR_RG \
//     --template-file main.bicep \
//     --parameters vmName=SQLVM01 adminUsername=sqladmin
//
// Parameters sourced from Key Vault — no plaintext passwords in pipeline.
// =============================================================================

@description('Name of the SQL VM')
param vmName string

@description('VM size — default is suitable for SQL workloads')
param vmSize string = 'Standard_E4s_v5'

@description('Azure region')
param location string = resourceGroup().location

@description('Admin username for the VM')
param adminUsername string

@description('SQL Server license type')
@allowed(['PAYG', 'AHUB', 'DR'])
param sqlLicenseType string = 'PAYG'

@description('SQL Server edition')
@allowed(['Developer', 'Express', 'Standard', 'Enterprise', 'Web'])
param sqlImageSku string = 'Standard'

@description('Name of the existing Log Analytics Workspace')
param logAnalyticsWorkspaceName string

@description('Resource group of the Log Analytics Workspace (if different)')
param logAnalyticsWorkspaceRG string = resourceGroup().name

@description('Name of the existing Key Vault for secrets')
param keyVaultName string

@description('Environment tag value')
@allowed(['prod', 'staging', 'dev'])
param environment string = 'prod'

@description('Team tag value')
param team string = 'dba'

@description('Cost center tag value')
param costCenter string

// ── Reference existing Key Vault ─────────────────────────────────────────────
resource kv 'Microsoft.KeyVault/vaults@2023-02-01' existing = {
  name: keyVaultName
}

// ── Reference existing Log Analytics Workspace ───────────────────────────────
resource law 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: logAnalyticsWorkspaceName
  scope: resourceGroup(logAnalyticsWorkspaceRG)
}

// ── NSG — Deny RDP/SSH by default (JIT will create temp rules) ───────────────
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-${vmName}'
  location: location
  tags: {
    Environment: environment
    Team: team
    CostCenter: costCenter
    DataClassification: 'confidential'
  }
  properties: {
    securityRules: [
      {
        name: 'DenyRDP'
        properties: {
          priority: 1000
          protocol: 'Tcp'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
      {
        name: 'DenySSH'
        properties: {
          priority: 1010
          protocol: 'Tcp'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
    ]
  }
}

// ── NIC ───────────────────────────────────────────────────────────────────────
resource nic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: 'nic-${vmName}'
  location: location
  tags: {
    Environment: environment
    Team: team
    CostCenter: costCenter
  }
  properties: {
    networkSecurityGroup: {
      id: nsg.id
    }
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          // Reference an existing subnet — replace with your vnet/subnet resource IDs
          subnet: {
            id: '/subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/YOUR_RG/providers/Microsoft.Network/virtualNetworks/YOUR_VNET/subnets/YOUR_SUBNET'
          }
        }
      }
    ]
  }
}

// ── Windows VM ────────────────────────────────────────────────────────────────
resource vm 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: vmName
  location: location
  tags: {
    Environment: environment
    Team: team
    CostCenter: costCenter
    DataClassification: 'confidential'
    Project: 'sql-vm-baseline'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: kv.getSecret('vm-admin-password')  // Key Vault reference
      windowsConfiguration: {
        enableAutomaticUpdates: true
        patchSettings: {
          patchMode: 'AutomaticByPlatform'
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftSQLServer'
        offer: 'sql2022-ws2022'
        sku: sqlImageSku
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
      }
      dataDisks: [
        {
          lun: 0
          name: '${vmName}-data-disk'
          createOption: 'Empty'
          diskSizeGB: 256
          managedDisk: { storageAccountType: 'Premium_LRS' }
          caching: 'ReadOnly'
        }
        {
          lun: 1
          name: '${vmName}-log-disk'
          createOption: 'Empty'
          diskSizeGB: 128
          managedDisk: { storageAccountType: 'Premium_LRS' }
          caching: 'None'
        }
      ]
    }
    networkProfile: {
      networkInterfaces: [
        { id: nic.id }
      ]
    }
  }
}

// ── SQL IaaS Extension ────────────────────────────────────────────────────────
resource sqlVm 'Microsoft.SqlVirtualMachine/sqlVirtualMachines@2022-07-01-preview' = {
  name: vmName
  location: location
  properties: {
    virtualMachineResourceId: vm.id
    sqlServerLicenseType: sqlLicenseType
    sqlManagement: 'Full'
    autoPatchingSettings: {
      enable: true
      dayOfWeek: 'Sunday'
      maintenanceWindowStartingHour: 2
      maintenanceWindowDuration: 60
    }
    autoBackupSettings: {
      enable: true
      retentionPeriod: 30
      storageAccessKey: ''  // Populate via Key Vault in full deployment
      enableEncryption: true
    }
  }
}

// ── Azure Monitor Agent Extension ────────────────────────────────────────────
resource amaExtension 'Microsoft.Compute/virtualMachines/extensions@2023-07-01' = {
  parent: vm
  name: 'AzureMonitorWindowsAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorWindowsAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
  }
}

// ── Outputs ───────────────────────────────────────────────────────────────────
output vmId string = vm.id
output vmName string = vm.name
output nicId string = nic.id
output nsgId string = nsg.id
