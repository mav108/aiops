# Enterprise Azure Integration

## Integration Modes

Use both push and pull in enterprise environments:

- Push: Azure Monitor Action Groups send common alert schema webhooks to `/alerts/azure-monitor`.
- Pull: the agent queries Log Analytics with KQL through `/integrations/log-analytics/query` and can synthesize incidents from `/integrations/log-analytics/poll-alerts`.
- Discovery: the agent queries Azure Resource Graph through `/integrations/resource-graph/discover` to inventory existing VM, VMSS, and AKS resources across configured subscriptions.

## Existing Infrastructure Onboarding

1. Assign the agent managed identity read access to the existing subscriptions or management-group scoped resource groups.
2. Add `AIOPS_AZURE_SUBSCRIPTION_IDS` with comma-separated subscription IDs.
3. Add `AIOPS_LOG_ANALYTICS_WORKSPACE_ID` for the central workspace or pass a workspace ID per request.
4. Keep `AIOPS_EXECUTION_MODE=mock` until approvals, RBAC, and runbooks have been validated.
5. Enable `AIOPS_ENABLE_LIVE_AZURE_INTEGRATIONS=true` to allow live Resource Graph and Log Analytics reads.

## Azure Monitor Action Group

Create or update an existing Action Group and add a webhook receiver:

- URI: `https://<agent-host>/alerts/azure-monitor`
- Common alert schema: enabled
- Authentication: place the agent behind API Management, Container Apps auth, private ingress, or a signed gateway pattern for production.

This is the preferred path for alert ingestion because Azure Monitor sends the alert immediately and preserves alert metadata.

## Log Analytics Pull

Use pull mode when alerts are represented as KQL signals, when historical replay is needed, or while onboarding existing workspaces. The default query detects:

- Failed AzureActivity records.
- Windows error/warning events.
- Perf CPU samples above 90 percent.

Enterprise teams should replace the default query with workspace-specific KQL for VM, VMSS, AKS, Application Insights, Sentinel, and platform logs.

## Resource Graph Discovery

The discovery endpoint starts with:

- `microsoft.compute/virtualmachines`
- `microsoft.compute/virtualmachinescalesets`
- `microsoft.containerservice/managedclusters`

Pass additional resource types for App Service, databases, networking, or storage as the estate expands.

## Recommended RBAC

Read-only onboarding:

- Reader on target subscriptions/resource groups.
- Log Analytics Reader on the workspace.
- Microsoft Sentinel Reader where security enrichment is enabled.

Live remediation:

- Add narrowly scoped Compute, Monitor, and Automation permissions only for approved action types.
- Prefer runbook-specific permissions over broad Contributor.
