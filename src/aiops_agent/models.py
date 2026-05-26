from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


class IncidentStatus(str, Enum):
    OPEN = "open"
    REMEDIATED = "remediated"
    REJECTED = "rejected"
    FAILED = "failed"


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


class ActionType(str, Enum):
    RESTART_VM = "restart_vm"
    RESIZE_VMSS = "resize_vmss"
    RUN_AUTOMATION_WEBHOOK = "run_automation_webhook"
    ADJUST_AUTOSCALE_RULE = "adjust_autoscale_rule"
    CREATE_TICKET = "create_ticket"
    MANUAL_ACTION_REQUIRED = "manual_action_required"


class NormalizedAlert(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    rule_name: str
    severity: str
    signal_type: str | None = None
    monitor_condition: str | None = None
    monitoring_service: str | None = None
    fired_at: datetime = Field(default_factory=utcnow)
    description: str | None = None
    resource_ids: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    @property
    def primary_resource_id(self) -> str | None:
        return self.resource_ids[0] if self.resource_ids else None

    @property
    def is_security_alert(self) -> bool:
        haystack = " ".join(
            [
                self.rule_name,
                self.signal_type or "",
                self.monitoring_service or "",
                self.description or "",
            ]
        ).lower()
        return any(token in haystack for token in ["sentinel", "defender", "security", "threat"])


class RemediationAction(BaseModel):
    id: str = Field(default_factory=lambda: new_id("act"))
    incident_id: str
    type: ActionType
    status: ActionStatus = ActionStatus.PROPOSED
    risk: RiskLevel
    description: str
    affected_resources: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    rollback: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    proposed_at: datetime = Field(default_factory=utcnow)
    approved_by: str | None = None
    approved_at: datetime | None = None
    executed_at: datetime | None = None
    execution_output: str | None = None


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: new_id("inc"))
    title: str
    status: IncidentStatus = IncidentStatus.OPEN
    severity: str
    source: str = "azure-monitor"
    alert_rule: str
    resource_ids: list[str] = Field(default_factory=list)
    summary: str
    blast_radius: str
    likely_causes: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    action_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    tags: dict[str, str] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: new_id("aud"))
    incident_id: str | None = None
    action_id: str | None = None
    event_type: str
    actor: str = "system"
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class IncidentRecommendation(BaseModel):
    summary: str
    blast_radius: str
    likely_causes: list[str]
    actions: list[RemediationAction]
    model_metadata: dict[str, Any] = Field(default_factory=dict)


class ApproveRequest(BaseModel):
    approver: str
    comment: str | None = None


class RejectRequest(BaseModel):
    rejected_by: str
    reason: str


class AlertIngestResponse(BaseModel):
    incident_id: str
    action_ids: list[str]
    status: IncidentStatus


class ActionExecutionResult(BaseModel):
    action_id: str
    status: ActionStatus
    output: str


class IntegrationStatus(BaseModel):
    mode: str
    live_azure_integrations_enabled: bool
    subscriptions_configured: int
    log_analytics_configured: bool
    azure_openai_configured: bool
    supported_ingestion_modes: list[str]
    supported_resource_types: list[str]


class LogAnalyticsQueryRequest(BaseModel):
    query: str
    workspace_id: str | None = None
    timespan_minutes: int | None = None


class LogAnalyticsQueryResponse(BaseModel):
    status: str
    workspace_id: str | None
    columns: list[str] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    message: str | None = None


class ResourceDiscoveryRequest(BaseModel):
    subscriptions: list[str] | None = None
    resource_types: list[str] = Field(
        default_factory=lambda: [
            "microsoft.compute/virtualmachines",
            "microsoft.compute/virtualmachinescalesets",
            "microsoft.containerservice/managedclusters",
        ]
    )
    limit: int = 100


class ResourceDiscoveryResponse(BaseModel):
    status: str
    subscriptions: list[str]
    query: str
    resources: list[dict[str, Any]] = Field(default_factory=list)
    message: str | None = None


class AlertPollRequest(BaseModel):
    query: str | None = None
    workspace_id: str | None = None
    timespan_minutes: int | None = None
    max_alerts: int = 50
