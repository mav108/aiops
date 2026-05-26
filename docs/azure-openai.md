# Azure OpenAI Integration

The agent can use Azure OpenAI to improve incident summaries, blast-radius assessment, and likely-cause ranking. Remediation actions still come from the approval-gated catalog, so the model cannot directly execute arbitrary changes.

## Local `.env`

For local testing with an API key:

```env
AIOPS_AZURE_OPENAI_ENDPOINT=https://<resource-name>.openai.azure.com/
AIOPS_AZURE_OPENAI_DEPLOYMENT=<deployment-name>
AIOPS_AZURE_OPENAI_API_VERSION=2024-02-15-preview
AIOPS_AZURE_OPENAI_AUTH_MODE=api_key
AIOPS_AZURE_OPENAI_API_KEY=<azure-openai-key>
```

The deployment value must be your Azure OpenAI deployment name, not only the base model name.

## Managed Identity

For Azure Container Apps, prefer managed identity:

```env
AIOPS_AZURE_OPENAI_ENDPOINT=https://<resource-name>.openai.azure.com/
AIOPS_AZURE_OPENAI_DEPLOYMENT=<deployment-name>
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
