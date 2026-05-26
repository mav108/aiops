# Azure AIOps Agent

Azure-native AIOps MVP for VMs and VM Scale Sets. The agent ingests Azure Monitor alerts, enriches them with Azure context, proposes AI-assisted remediation, and executes only after human approval.

## What Is Included

- FastAPI control plane with approval-gated remediation.
- Deterministic local analyzer with optional Azure OpenAI recommendations.
- Azure adapter boundaries for Monitor/Log Analytics, Resource Graph, Advisor, Compute, Automation, and Sentinel enrichment.
- Bicep infrastructure scaffold for Azure Container Apps, managed identity, Log Analytics, Application Insights, Service Bus, Storage, and Key Vault.
- Architecture and remediation catalog docs.
- Unit and contract tests with sample Azure Monitor payloads.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
copy .env.example .env
uvicorn aiops_agent.app:create_app --factory --reload
```

Open `http://127.0.0.1:8000/docs` for the API.

Post the sample alert:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -InFile .\samples\azure-monitor-vmss-high-cpu.json `
  -Uri http://127.0.0.1:8000/alerts/azure-monitor
```

Approve an incident:

```powershell
Invoke-RestMethod `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"approver":"operator@example.com","comment":"Approved from local test"}' `
  -Uri http://127.0.0.1:8000/incidents/<incident-id>/approve
```

## Safety Model

The default execution mode is `mock`, so remediation calls are simulated. Set `AIOPS_EXECUTION_MODE=live` only after configuring managed identity/RBAC and reviewing `docs/remediation-catalog.md`.

Actions must be approved, allowlisted, and non-destructive before they execute.

## Tests

```powershell
pytest
```

## Azure Deployment

The infrastructure scaffold is in `infra/main.bicep`.

```powershell
az deployment group create `
  --resource-group <rg> `
  --template-file infra/main.bicep `
  --parameters containerImage=<registry>/aiops-agent:latest
```

