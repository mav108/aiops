from typing import Any

import httpx

from aiops_agent.config import Settings
from aiops_agent.models import ActionType, NormalizedAlert, RemediationAction


class AzureContextCollector:
    """Collects Azure context when configuration is available.

    The MVP returns structured placeholders for missing configuration so incident
    analysis remains useful during local development and tests.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    def collect(self, alert: NormalizedAlert) -> dict[str, Any]:
        return {
            "resource_inventory": self._resource_inventory(alert),
            "recent_logs": self._recent_logs(alert),
            "advisor_recommendations": self._advisor_recommendations(alert),
            "security_context": self._security_context(alert),
            "monitoring_recommendations": self._monitoring_recommendations(alert),
        }

    def _resource_inventory(self, alert: NormalizedAlert) -> dict[str, Any]:
        resources = []
        for resource_id in alert.resource_ids:
            parsed = parse_resource_id(resource_id)
            resources.append(
                {
                    "id": resource_id,
                    "subscription_id": parsed.get("subscriptions"),
                    "resource_group": parsed.get("resourceGroups"),
                    "provider": parsed.get("providers"),
                    "resource_type": parsed.get("type_path"),
                    "name": parsed.get("name"),
                }
            )
        return {
            "status": "configured" if self.settings.subscription_id_list else "not_configured",
            "resources": resources,
        }

    def _recent_logs(self, alert: NormalizedAlert) -> dict[str, Any]:
        if not self.settings.log_analytics_workspace_id:
            return {
                "status": "not_configured",
                "queries": [
                    "Perf | where CounterName in ('% Processor Time', 'Available MBytes')",
                    "Event | where EventLevelName in ('Error', 'Warning')",
                    "AzureActivity | where ActivityStatusValue != 'Success'",
                ],
            }
        return {
            "status": "configured",
            "workspace_id": self.settings.log_analytics_workspace_id,
            "note": "Live Log Analytics query execution is isolated behind this adapter.",
        }

    def _advisor_recommendations(self, alert: NormalizedAlert) -> dict[str, Any]:
        return {
            "status": "extension_point",
            "categories": ["HighAvailability", "Security", "Performance", "Cost"],
            "resource_ids": alert.resource_ids,
        }

    def _security_context(self, alert: NormalizedAlert) -> dict[str, Any]:
        return {
            "status": "extension_point",
            "sentinel_ueba_relevant": alert.is_security_alert,
            "signals": ["Sentinel incidents", "Defender alerts", "UEBA entity anomalies"],
        }

    def _monitoring_recommendations(self, alert: NormalizedAlert) -> dict[str, Any]:
        return {
            "dynamic_thresholds": [
                "Use Azure Monitor dynamic thresholds for recurring noisy CPU, memory, disk, and availability signals."
            ],
            "predictive_scaling": [
                "Use VMSS predictive autoscale for cyclical CPU-bound workloads with enough history."
            ],
        }


class AzureRemediationClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def execute_live(self, action: RemediationAction) -> str:
        if action.type == ActionType.RUN_AUTOMATION_WEBHOOK:
            return self._run_automation_webhook(action)
        if action.type == ActionType.RESTART_VM:
            return self._restart_vm(action)
        if action.type == ActionType.RESIZE_VMSS:
            return self._resize_vmss(action)
        if action.type == ActionType.ADJUST_AUTOSCALE_RULE:
            return "Autoscale adjustment is prepared; apply the generated rule through Azure Monitor change control."
        if action.type == ActionType.CREATE_TICKET:
            return "Ticket connector is not configured; recorded ticket creation request."
        if action.type == ActionType.MANUAL_ACTION_REQUIRED:
            return "Manual action recorded; no Azure mutation executed."
        raise ValueError(f"Unsupported action type: {action.type}")

    def _run_automation_webhook(self, action: RemediationAction) -> str:
        webhook_url = action.metadata.get("webhook_url") or self.settings.automation_webhook_url
        if not webhook_url:
            raise ValueError("Automation webhook URL is not configured.")
        response = httpx.post(webhook_url, json=action.metadata.get("payload", {}), timeout=30)
        response.raise_for_status()
        return f"Automation webhook accepted with HTTP {response.status_code}."

    def _restart_vm(self, action: RemediationAction) -> str:
        target = action.affected_resources[0] if action.affected_resources else None
        if not target:
            raise ValueError("restart_vm action requires an affected VM resource id.")
        parsed = parse_resource_id(target)
        return (
            "Live VM restart adapter reached. Configure azure-mgmt-compute call for "
            f"{parsed.get('resourceGroups')}/{parsed.get('name')} after RBAC validation."
        )

    def _resize_vmss(self, action: RemediationAction) -> str:
        target = action.affected_resources[0] if action.affected_resources else None
        if not target:
            raise ValueError("resize_vmss action requires an affected VMSS resource id.")
        desired_capacity = action.metadata.get("desired_capacity", "current+1")
        return f"Live VMSS resize adapter reached for {target}; desired capacity {desired_capacity}."


def parse_resource_id(resource_id: str) -> dict[str, str]:
    parts = [part for part in resource_id.strip("/").split("/") if part]
    parsed: dict[str, str] = {}
    for index, part in enumerate(parts):
        if part in {"subscriptions", "resourceGroups", "providers"} and index + 1 < len(parts):
            parsed[part] = parts[index + 1]

    if "providers" in parsed:
        provider_index = parts.index("providers")
        provider_parts = parts[provider_index + 2 :]
        if len(provider_parts) >= 2:
            parsed["type_path"] = "/".join(provider_parts[0::2])
            parsed["name"] = provider_parts[-1]
    return parsed

