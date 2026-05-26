# Azure AIOps Agent Architecture

## Overview

The Azure AIOps Agent is a human-approved operations assistant for Azure VMs and VM Scale Sets. It receives Azure Monitor alerts, enriches incidents with Azure telemetry and inventory context, generates a diagnosis and remediation proposal, then waits for an operator to approve or reject the proposed action.

```text
Azure Monitor Action Group
        |
        v
FastAPI /alerts/azure-monitor
        |
        v
Alert Processor -> Context Collector -> Analyzer
        |              |                  |
        |              |                  +--> Azure OpenAI or deterministic fallback
        |              +--> Log Analytics, Resource Graph, Advisor, Sentinel extension
        v
Incident Store + Audit Trail
        |
        v
Approval API/UI -> Remediation Executor -> Azure Compute / Automation / Monitor
```

## Runtime Components

- FastAPI control plane exposes alert intake, incident review, approval, rejection, action lookup, and a minimal operator UI.
- Alert processor normalizes Azure Monitor common alert schema payloads and correlates repeated alerts into existing open incidents when the rule and target resource match.
- Enterprise integrations support Azure Monitor webhook push, Log Analytics KQL pull, and Resource Graph discovery for existing VM, VMSS, and AKS resources.
- Context collector creates a single incident context bundle from Azure resource metadata, Log Analytics query plans, Advisor categories, Sentinel/Defender extension points, and monitoring recommendations.
- Analyzer uses Azure OpenAI when configured and falls back to deterministic VM/VMSS heuristics when local or offline.
- Remediation executor enforces approval, allowlists, destructive-action blocking, execution mode, and audit logging.
- JSON state store is used for the MVP. Production should replace it with Cosmos DB or another transactional store.

## Security Model

- Default execution mode is `mock`; no Azure mutation happens unless `AIOPS_EXECUTION_MODE=live`.
- Every remediation action must be explicitly approved before execution.
- Action type must be present in `AIOPS_REMEDIATION_ALLOWLIST`.
- Destructive actions are blocked unless their action type is also present in `AIOPS_DESTRUCTIVE_ACTION_ALLOWLIST`.
- Azure deployment uses managed identity. Avoid static secrets for Azure APIs where possible.
- Azure OpenAI can be deployed with private networking and keyless identity in enterprise environments.
- Prompts, recommendations, approvals, execution outcomes, and guardrail blocks are written to the audit log.

## RBAC

Start with read-only identity permissions for analysis:

- Reader on monitored subscriptions or resource groups.
- Log Analytics Reader on the workspace.
- Resource Graph read access through Azure Resource Manager.
- Advisor recommendation read access.
- Microsoft Sentinel Reader when security enrichment is enabled.

Add mutation permissions only for approved remediation types:

- `Microsoft.Compute/virtualMachines/restart/action` for VM restart.
- `Microsoft.Compute/virtualMachineScaleSets/write` for VMSS capacity changes.
- Automation job/webhook permissions for runbook remediation.
- Azure Monitor write permissions for autoscale rule changes.

## Network Model

The MVP can run with public Container Apps ingress for Azure Monitor webhooks. Enterprise deployment should add:

- Private endpoints for Azure OpenAI, Key Vault, Storage, and state store.
- Ingress restrictions or API gateway validation for action group calls.
- Egress controls for live remediation APIs.
- Separate dev, test, and prod environments.

## Enterprise Rollout

1. Start in mock mode and ingest non-production alerts.
2. Validate recommendations, noisy-alert handling, and runbook catalog coverage.
3. Enable live execution only for one low-risk action type at a time.
4. Add Service Bus between alert intake and processing for resiliency.
5. Replace JSON state with Cosmos DB and add retention policies.
6. Integrate Teams/ServiceNow/Jira/PagerDuty for approval and post-incident workflows.
7. Add SLO/error-budget, deployment-change, CMDB ownership, and FinOps signals to context collection.
