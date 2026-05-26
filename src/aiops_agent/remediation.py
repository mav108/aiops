from aiops_agent.azure_clients import AzureRemediationClient
from aiops_agent.config import Settings
from aiops_agent.models import (
    ActionExecutionResult,
    ActionStatus,
    AuditEvent,
    IncidentStatus,
    RemediationAction,
    RiskLevel,
    utcnow,
)
from aiops_agent.state import JsonStateStore


class RemediationExecutor:
    def __init__(self, settings: Settings, store: JsonStateStore, azure_client: AzureRemediationClient):
        self.settings = settings
        self.store = store
        self.azure_client = azure_client

    def approve_incident(
        self, incident_id: str, approver: str, comment: str | None = None
    ) -> list[ActionExecutionResult]:
        incident = self.store.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident {incident_id} was not found.")

        results: list[ActionExecutionResult] = []
        for action in self.store.list_actions_for_incident(incident_id):
            if action.status != ActionStatus.PROPOSED:
                continue
            action.status = ActionStatus.APPROVED
            action.approved_by = approver
            action.approved_at = utcnow()
            self.store.upsert_action(action)
            self.store.add_audit_event(
                AuditEvent(
                    incident_id=incident_id,
                    action_id=action.id,
                    event_type="action.approved",
                    actor=approver,
                    message=comment or "Action approved.",
                )
            )
            results.append(self.execute_approved_action(action))

        refreshed_actions = self.store.list_actions_for_incident(incident_id)
        if refreshed_actions and all(
            action.status in {ActionStatus.SUCCEEDED, ActionStatus.BLOCKED} for action in refreshed_actions
        ):
            incident.status = IncidentStatus.REMEDIATED
            self.store.upsert_incident(incident)
        return results

    def reject_incident(self, incident_id: str, rejected_by: str, reason: str):
        incident = self.store.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident {incident_id} was not found.")
        incident.status = IncidentStatus.REJECTED
        self.store.upsert_incident(incident)
        for action in self.store.list_actions_for_incident(incident_id):
            if action.status == ActionStatus.PROPOSED:
                action.status = ActionStatus.REJECTED
                self.store.upsert_action(action)
        self.store.add_audit_event(
            AuditEvent(
                incident_id=incident_id,
                event_type="incident.rejected",
                actor=rejected_by,
                message=reason,
            )
        )
        return incident

    def execute_approved_action(self, action: RemediationAction) -> ActionExecutionResult:
        if action.status != ActionStatus.APPROVED:
            return self._block(action, "Action must be approved before execution.")

        guardrail_failure = self._guardrail_failure(action)
        if guardrail_failure:
            return self._block(action, guardrail_failure)

        action.status = ActionStatus.EXECUTING
        self.store.upsert_action(action)
        try:
            if self.settings.execution_mode == "mock":
                output = f"Mock execution completed for {action.type.value}."
            else:
                output = self.azure_client.execute_live(action)
            action.status = ActionStatus.SUCCEEDED
            action.executed_at = utcnow()
            action.execution_output = output
            self.store.upsert_action(action)
            self.store.add_audit_event(
                AuditEvent(
                    incident_id=action.incident_id,
                    action_id=action.id,
                    event_type="action.succeeded",
                    message=output,
                    metadata={"execution_mode": self.settings.execution_mode},
                )
            )
            return ActionExecutionResult(action_id=action.id, status=action.status, output=output)
        except Exception as exc:
            action.status = ActionStatus.FAILED
            action.executed_at = utcnow()
            action.execution_output = str(exc)
            self.store.upsert_action(action)
            self.store.add_audit_event(
                AuditEvent(
                    incident_id=action.incident_id,
                    action_id=action.id,
                    event_type="action.failed",
                    message=str(exc),
                )
            )
            return ActionExecutionResult(action_id=action.id, status=action.status, output=str(exc))

    def _guardrail_failure(self, action: RemediationAction) -> str | None:
        if action.type.value not in self.settings.remediation_allowlist_set:
            return f"Action type {action.type.value} is not in the remediation allowlist."
        if (
            action.risk == RiskLevel.DESTRUCTIVE
            and action.type.value not in self.settings.destructive_action_allowlist_set
        ):
            return "Destructive actions are blocked unless explicitly allowlisted."
        return None

    def _block(self, action: RemediationAction, reason: str) -> ActionExecutionResult:
        action.status = ActionStatus.BLOCKED
        action.executed_at = utcnow()
        action.execution_output = reason
        self.store.upsert_action(action)
        self.store.add_audit_event(
            AuditEvent(
                incident_id=action.incident_id,
                action_id=action.id,
                event_type="action.blocked",
                message=reason,
            )
        )
        return ActionExecutionResult(action_id=action.id, status=action.status, output=reason)

