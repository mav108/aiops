from typing import Any

from aiops_agent.alert_parser import parse_azure_monitor_alert
from aiops_agent.analyzer import AIOpsAnalyzer
from aiops_agent.azure_clients import AzureContextCollector
from aiops_agent.models import AlertIngestResponse, AuditEvent, Incident, IncidentStatus
from aiops_agent.state import JsonStateStore


class AlertProcessor:
    def __init__(self, store: JsonStateStore, context_collector: AzureContextCollector, analyzer: AIOpsAnalyzer):
        self.store = store
        self.context_collector = context_collector
        self.analyzer = analyzer

    def ingest_azure_monitor_alert(self, payload: dict[str, Any]) -> AlertIngestResponse:
        return self.ingest_normalized_alert_payload(payload, source="azure-monitor")

    def ingest_log_analytics_signal(self, row: dict[str, Any]) -> AlertIngestResponse:
        payload = {
            "data": {
                "essentials": {
                    "alertId": f"log-analytics:{row.get('TimeGenerated')}:{row.get('RuleName')}",
                    "alertRule": row.get("RuleName") or "Log Analytics signal",
                    "severity": row.get("Severity") or "Sev3",
                    "signalType": "Log",
                    "monitorCondition": "Fired",
                    "monitoringService": "Log Analytics",
                    "alertTargetIDs": [row.get("ResourceId")] if row.get("ResourceId") else [],
                    "firedDateTime": row.get("TimeGenerated"),
                    "description": row.get("Description"),
                },
                "alertContext": {"sourceRow": row},
            }
        }
        return self.ingest_normalized_alert_payload(payload, source="log-analytics")

    def ingest_normalized_alert_payload(
        self, payload: dict[str, Any], source: str
    ) -> AlertIngestResponse:
        alert = parse_azure_monitor_alert(payload)
        incident = self._find_open_related_incident(alert.rule_name, alert.resource_ids)

        if incident is None:
            incident = Incident(
                title=f"{alert.severity}: {alert.rule_name}",
                severity=alert.severity,
                source=source,
                alert_rule=alert.rule_name,
                resource_ids=alert.resource_ids,
                summary="Incident created; analysis pending.",
                blast_radius="Unknown until context collection completes.",
                context={"alerts": [alert.model_dump(mode="json")]},
                tags={"monitoring_service": alert.monitoring_service or "unknown"},
            )
        else:
            incident.context.setdefault("alerts", []).append(alert.model_dump(mode="json"))

        azure_context = self.context_collector.collect(alert)
        incident.context["azure"] = azure_context
        recommendation = self.analyzer.recommend(alert, azure_context, incident.id)
        incident.summary = recommendation.summary
        incident.blast_radius = recommendation.blast_radius
        incident.likely_causes = recommendation.likely_causes
        incident.context["model_metadata"] = recommendation.model_metadata

        self.store.upsert_incident(incident)
        action_ids: list[str] = []
        for action in recommendation.actions:
            action.incident_id = incident.id
            self.store.upsert_action(action)
            action_ids.append(action.id)

        incident.action_ids = sorted(set(incident.action_ids + action_ids))
        self.store.upsert_incident(incident)
        self.store.add_audit_event(
            AuditEvent(
                incident_id=incident.id,
                event_type="incident.ingested",
                message=f"Ingested {source} alert {alert.id}.",
                metadata={"alert_rule": alert.rule_name, "action_ids": action_ids},
            )
        )
        return AlertIngestResponse(
            incident_id=incident.id,
            action_ids=action_ids,
            status=incident.status,
        )

    def _find_open_related_incident(self, rule_name: str, resource_ids: list[str]) -> Incident | None:
        resource_set = set(resource_ids)
        for incident in self.store.list_incidents():
            if incident.status != IncidentStatus.OPEN:
                continue
            if incident.alert_rule != rule_name:
                continue
            if resource_set.intersection(incident.resource_ids):
                return incident
        return None
