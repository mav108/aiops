import json
from typing import Any

from aiops_agent.config import Settings
from aiops_agent.models import (
    ActionType,
    IncidentRecommendation,
    NormalizedAlert,
    RemediationAction,
    RiskLevel,
)


class AIOpsAnalyzer:
    def recommend(self, alert: NormalizedAlert, context: dict[str, Any], incident_id: str) -> IncidentRecommendation:
        raise NotImplementedError


class DeterministicAnalyzer(AIOpsAnalyzer):
    """Local fallback analyzer that keeps the MVP useful without model access."""

    def recommend(self, alert: NormalizedAlert, context: dict[str, Any], incident_id: str) -> IncidentRecommendation:
        resource_text = " ".join(alert.resource_ids).lower()
        signal_text = " ".join(
            [
                alert.rule_name,
                alert.description or "",
                json.dumps(alert.context, default=str),
            ]
        ).lower()

        if alert.is_security_alert:
            action = RemediationAction(
                incident_id=incident_id,
                type=ActionType.MANUAL_ACTION_REQUIRED,
                risk=RiskLevel.HIGH,
                description="Escalate to security operations and enrich with Sentinel/Defender entity context.",
                affected_resources=alert.resource_ids,
                required_permissions=["Microsoft.SecurityInsights/incidents/read"],
                rollback="No automated change is performed.",
                metadata={"reason": "security_alert"},
            )
            return IncidentRecommendation(
                summary="Security-related alert requires investigation before automated remediation.",
                blast_radius=_blast_radius(alert),
                likely_causes=["Suspicious user/entity behavior", "Defender or Sentinel detection", "Policy drift"],
                actions=[action],
                model_metadata={"provider": "deterministic"},
            )

        if "virtualmachinescalesets" in resource_text and any(
            token in signal_text for token in ["cpu", "processor", "capacity", "scale"]
        ):
            action = RemediationAction(
                incident_id=incident_id,
                type=ActionType.RESIZE_VMSS,
                risk=RiskLevel.MEDIUM,
                description="Increase VM Scale Set capacity by one instance and review predictive autoscale.",
                affected_resources=alert.resource_ids,
                required_permissions=["Microsoft.Compute/virtualMachineScaleSets/write"],
                rollback="Reduce VMSS capacity to the previous value after load normalizes.",
                metadata={"desired_capacity": "current+1", "predictive_autoscale_review": True},
            )
            return IncidentRecommendation(
                summary="VMSS capacity pressure is likely causing elevated CPU or degraded performance.",
                blast_radius=_blast_radius(alert),
                likely_causes=[
                    "Cyclical demand exceeded current VMSS capacity",
                    "Autoscale threshold too conservative",
                    "Recent deployment increased CPU cost",
                ],
                actions=[action],
                model_metadata={"provider": "deterministic"},
            )

        if any(token in signal_text for token in ["disk", "space", "volume"]):
            action = RemediationAction(
                incident_id=incident_id,
                type=ActionType.RUN_AUTOMATION_WEBHOOK,
                risk=RiskLevel.MEDIUM,
                description="Run the approved disk cleanup Automation runbook if configured.",
                affected_resources=alert.resource_ids,
                required_permissions=["Microsoft.Automation/automationAccounts/jobs/write"],
                rollback="Restore from backup or snapshot if cleanup removes required artifacts.",
                metadata={"runbook": "disk-cleanup"},
            )
            return IncidentRecommendation(
                summary="Disk pressure detected; cleanup or capacity expansion is likely required.",
                blast_radius=_blast_radius(alert),
                likely_causes=["Log growth", "Temporary file accumulation", "Application data growth"],
                actions=[action],
                model_metadata={"provider": "deterministic"},
            )

        if any(token in signal_text for token in ["heartbeat", "availability", "down", "unhealthy"]):
            action = RemediationAction(
                incident_id=incident_id,
                type=ActionType.RESTART_VM,
                risk=RiskLevel.MEDIUM,
                description="Restart the affected VM after approval if health checks confirm service loss.",
                affected_resources=alert.resource_ids,
                required_permissions=["Microsoft.Compute/virtualMachines/restart/action"],
                rollback="Start the VM and restore service from backup if restart does not recover it.",
                metadata={"requires_health_check": True},
            )
            return IncidentRecommendation(
                summary="Availability signal suggests the VM or service may be unhealthy.",
                blast_radius=_blast_radius(alert),
                likely_causes=["Guest OS hang", "Service crash", "Host maintenance or network issue"],
                actions=[action],
                model_metadata={"provider": "deterministic"},
            )

        action = RemediationAction(
            incident_id=incident_id,
            type=ActionType.MANUAL_ACTION_REQUIRED,
            risk=RiskLevel.LOW,
            description="Collect additional metrics, logs, Advisor recommendations, and recent changes.",
            affected_resources=alert.resource_ids,
            required_permissions=["Microsoft.Insights/*/read"],
            rollback="No automated change is performed.",
            metadata={"reason": "insufficient_confidence"},
        )
        return IncidentRecommendation(
            summary="The alert needs additional context before an automated remediation can be selected.",
            blast_radius=_blast_radius(alert),
            likely_causes=["Unknown workload change", "Metric anomaly", "Configuration drift"],
            actions=[action],
            model_metadata={"provider": "deterministic"},
        )


class AzureOpenAIAnalyzer(AIOpsAnalyzer):
    def __init__(self, settings: Settings, fallback: AIOpsAnalyzer | None = None):
        self.settings = settings
        self.fallback = fallback or DeterministicAnalyzer()

    def recommend(self, alert: NormalizedAlert, context: dict[str, Any], incident_id: str) -> IncidentRecommendation:
        if not self.settings.azure_openai_enabled:
            return self.fallback.recommend(alert, context, incident_id)
        try:
            from openai import AzureOpenAI

            client_kwargs: dict[str, Any] = {
                "azure_endpoint": self.settings.azure_openai_endpoint,
                "api_version": self.settings.azure_openai_api_version,
            }
            if self.settings.azure_openai_api_key:
                client_kwargs["api_key"] = self.settings.azure_openai_api_key

            client = AzureOpenAI(**client_kwargs)
            response = client.chat.completions.create(
                model=self.settings.azure_openai_deployment,
                temperature=0.1,
                response_format={"type": "json_object"},
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an Azure AIOps incident analyst. Return JSON with summary, "
                            "blast_radius, likely_causes, and one safe recommended_action. Never "
                            "recommend destructive remediation."
                        ),
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            {"alert": alert.model_dump(mode="json"), "context": context},
                            default=str,
                        ),
                    },
                ],
            )
            content = response.choices[0].message.content or "{}"
            ai_payload = json.loads(content)
            base = self.fallback.recommend(alert, context, incident_id)
            base.summary = ai_payload.get("summary") or base.summary
            base.blast_radius = ai_payload.get("blast_radius") or base.blast_radius
            base.likely_causes = ai_payload.get("likely_causes") or base.likely_causes
            base.model_metadata = {"provider": "azure_openai", "fallback_actions": True}
            return base
        except Exception as exc:
            recommendation = self.fallback.recommend(alert, context, incident_id)
            recommendation.model_metadata = {
                "provider": "deterministic",
                "azure_openai_error": str(exc),
            }
            return recommendation


def build_analyzer(settings: Settings) -> AIOpsAnalyzer:
    return AzureOpenAIAnalyzer(settings)


def _blast_radius(alert: NormalizedAlert) -> str:
    if not alert.resource_ids:
        return "Unknown; alert did not include target resource IDs."
    if len(alert.resource_ids) == 1:
        return f"Limited to {alert.resource_ids[0]} unless dependent services are affected."
    return f"Potentially affects {len(alert.resource_ids)} Azure resources and their dependencies."

