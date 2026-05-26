# Azure OpenAI Integration

The agent can use Azure OpenAI to improve incident summaries, blast-radius assessment, and likely-cause ranking. Remediation actions still come from the approval-gated catalog, so the model cannot directly execute arbitrary changes.

## Local `.env`

For local testing with an API key:

```env
AIOPS_AZURE_OPENAI_ENDPOINT=https://<resource-name>.openai.azure.com/
AIOPS_AZURE_OPENAI_DEPLOYMENT=<deployment-name>
AIOPS_AZURE_OPENAI_API_VERSION=v1
AIOPS_AZURE_OPENAI_AUTH_MODE=api_key
AIOPS_AZURE_OPENAI_API_KEY=<azure-openai-key>
```

The deployment value must be your Azure OpenAI deployment name, not only the base model name.

## Managed Identity

For Azure Container Apps, prefer managed identity:

```env
AIOPS_AZURE_OPENAI_ENDPOINT=https://<resource-name>.openai.azure.com/
AIOPS_AZURE_OPENAI_DEPLOYMENT=<deployment-name>
AIOPS_AZURE_OPENAI_API_VERSION=v1
AIOPS_AZURE_OPENAI_AUTH_MODE=managed_identity
```

Grant the Container App managed identity access to the Azure OpenAI resource, typically with the **Cognitive Services OpenAI User** role.

## Testing

Check configuration:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/integrations/azure-openai/status
```

Run a smoke test:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"prompt":"Confirm Azure OpenAI connectivity for the AIOps agent."}' `
  -Uri http://127.0.0.1:8000/integrations/azure-openai/test
```

Then ingest or poll an alert. If Azure OpenAI is configured, incident context will include model metadata with `provider=azure_openai`; otherwise the deterministic analyzer remains active.

## Analyze Log Analytics Rows

Use this when you want Azure OpenAI to analyze the result of a KQL query directly:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"query":"AzureActivity | where TimeGenerated > ago(1h) | take 20","max_rows":20}' `
  -Uri http://127.0.0.1:8000/integrations/log-analytics/analyze
```

If you use per-subscription workspace mapping, include `subscription_id`:

```json
{
  "subscription_id": "<subscription-id>",
  "query": "AzureActivity | where TimeGenerated > ago(1h) | take 20",
  "max_rows": 20
}
```

For incident creation instead of direct summarization, use `/integrations/log-analytics/poll-alerts`. That endpoint expects or creates rows with `TimeGenerated`, `Severity`, `RuleName`, `ResourceId`, and `Description`.

For workspaces where `AzureMetrics` has useful data, start with a compact aggregation instead of sending raw rows:

```kusto
AzureMetrics
| where TimeGenerated > ago(24h)
| summarize
    Samples=count(),
    AvgAverage=avg(Average),
    MaxMaximum=max(Maximum),
    LastSeen=max(TimeGenerated)
    by ResourceId, MetricName, UnitName
| order by Samples desc
| take 20
```

That same query is saved in `samples/kql/azuremetrics-operational-summary.kql`.

If `query_status` is `ok` but `analysis_status` is `empty`, reduce `max_rows`, summarize the KQL first, or use a deployment with enough output token capacity. The service now reports `analysis_status=empty` rather than returning a successful response with a blank `analysis` field.
