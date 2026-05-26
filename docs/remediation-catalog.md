# Remediation Catalog

## Policy

All remediation is approval-gated in v1. The agent may propose actions, but it cannot execute them until an operator approves the incident. Destructive actions remain blocked unless explicitly allowlisted.

## Action Types

| Action | Risk | Default | Prerequisites | Rollback |
| --- | --- | --- | --- | --- |
| `restart_vm` | Medium | Allowlisted | VM target ID, health check, Compute restart RBAC | Start VM, restore service, or recover from backup |
| `resize_vmss` | Medium | Allowlisted | VMSS target ID, current capacity check, Compute write RBAC | Reduce capacity to previous value |
| `run_automation_webhook` | Medium | Allowlisted | Approved runbook, webhook URL, payload validation | Run paired rollback runbook or restore from snapshot/backup |
| `adjust_autoscale_rule` | Medium | Allowlisted | Azure Monitor autoscale write RBAC, change ticket | Restore previous autoscale profile |
| `create_ticket` | Low | Allowlisted | ITSM connector configuration | Close or update ticket |
| `manual_action_required` | Low/High | Allowlisted | Human owner assignment | No automated change |

## Guardrails

- Never execute an action in `proposed` state.
- Block any action not present in `AIOPS_REMEDIATION_ALLOWLIST`.
- Block `destructive` risk unless `AIOPS_DESTRUCTIVE_ACTION_ALLOWLIST` includes the action type.
- Record approver, timestamp, affected resources, required permissions, rollback notes, and execution output.
- Prefer scale-out, ticket creation, and manual escalation over restart or cleanup when confidence is low.

## Initial Detection Playbooks

- VMSS high CPU: recommend one-instance scale-out and predictive autoscale review.
- Disk pressure: recommend approved cleanup runbook or manual capacity expansion.
- Availability/heartbeat loss: recommend VM restart only after health confirmation.
- Security alert: require SOC investigation and Sentinel/Defender/UEBA enrichment before remediation.
- Unknown anomaly: collect Log Analytics, Advisor, Resource Graph, and recent-change context before automation.

