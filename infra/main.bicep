@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Environment name, for example dev, test, or prod.')
param environmentName string = 'dev'

@description('Container image for the AIOps agent API.')
param containerImage string

@description('Azure OpenAI endpoint. Leave empty to use deterministic local analysis.')
param azureOpenAIEndpoint string = ''

@description('Azure OpenAI deployment name. Leave empty to use deterministic local analysis.')
param azureOpenAIDeployment string = ''

@description('Comma-separated subscription IDs monitored by the agent.')
param monitoredSubscriptionIds string = ''

@description('Optional Log Analytics workspace ID used for incident context queries.')
param logAnalyticsWorkspaceId string = ''

@description('Optional comma-separated subscription=workspace mapping for estates with one workspace per subscription.')
param logAnalyticsWorkspaceMap string = ''

@description('Whether the agent should execute live Azure read integrations. Keep false during first deployment.')
param enableLiveAzureIntegrations bool = false

var prefix = 'aiops-${environmentName}'

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-id'
  location: location
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${prefix}-law'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${prefix}-appi'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: take(replace('${prefix}st${uniqueString(resourceGroup().id)}', '-', ''), 24)
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

resource serviceBus 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: '${prefix}-sb-${uniqueString(resourceGroup().id)}'
  location: location
  sku: {
    name: 'Standard'
    tier: 'Standard'
  }
}

resource alertQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: serviceBus
  name: 'alerts'
  properties: {
    lockDuration: 'PT1M'
    maxDeliveryCount: 10
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${prefix}-kv-${uniqueString(resourceGroup().id)}'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
  }
}

resource containerEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${prefix}-cae'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: workspace.properties.customerId
        sharedKey: workspace.listKeys().primarySharedKey
      }
    }
  }
}

resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${prefix}-api'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto'
      }
    }
    template: {
      containers: [
        {
          name: 'api'
          image: containerImage
          env: [
            {
              name: 'AIOPS_ENVIRONMENT'
              value: environmentName
            }
            {
              name: 'AIOPS_EXECUTION_MODE'
              value: 'mock'
            }
            {
              name: 'AIOPS_STATE_FILE'
              value: '/tmp/aiops-state.json'
            }
            {
              name: 'AIOPS_AZURE_SUBSCRIPTION_IDS'
              value: monitoredSubscriptionIds
            }
            {
              name: 'AIOPS_LOG_ANALYTICS_WORKSPACE_ID'
              value: empty(logAnalyticsWorkspaceId) ? workspace.properties.customerId : logAnalyticsWorkspaceId
            }
            {
              name: 'AIOPS_LOG_ANALYTICS_WORKSPACE_MAP'
              value: logAnalyticsWorkspaceMap
            }
            {
              name: 'AIOPS_LOG_QUERY_TIMESPAN_MINUTES'
              value: '60'
            }
            {
              name: 'AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS'
              value: string(enableLiveAzureIntegrations)
            }
            {
              name: 'AIOPS_AZURE_OPENAI_ENDPOINT'
              value: azureOpenAIEndpoint
            }
            {
              name: 'AIOPS_AZURE_OPENAI_DEPLOYMENT'
              value: azureOpenAIDeployment
            }
            {
              name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
              value: appInsights.properties.ConnectionString
            }
          ]
          resources: {
            cpu: 0.5
            memory: '1Gi'
          }
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 5
        rules: [
          {
            name: 'http-concurrency'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

output containerAppUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}'
output managedIdentityPrincipalId string = identity.properties.principalId
output logAnalyticsWorkspaceResourceId string = workspace.id
output serviceBusQueueName string = alertQueue.name
output keyVaultName string = keyVault.name
