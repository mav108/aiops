import json
from pathlib import Path
from threading import RLock

from pydantic import BaseModel, Field

from aiops_agent.models import AuditEvent, Incident, RemediationAction, utcnow


class StateSnapshot(BaseModel):
    incidents: dict[str, Incident] = Field(default_factory=dict)
    actions: dict[str, RemediationAction] = Field(default_factory=dict)
    audit_events: dict[str, AuditEvent] = Field(default_factory=dict)


class JsonStateStore:
    """Small durable store for the MVP.

    Production deployments should replace this with Cosmos DB or another
    transactional store, but the interface keeps the domain services stable.
    """

    def __init__(self, path: Path):
        self.path = path
        self._lock = RLock()
        self._state = self._load()

    def list_incidents(self) -> list[Incident]:
        with self._lock:
            return sorted(self._state.incidents.values(), key=lambda item: item.created_at, reverse=True)

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            return self._state.incidents.get(incident_id)

    def upsert_incident(self, incident: Incident) -> Incident:
        with self._lock:
            incident.updated_at = utcnow()
            self._state.incidents[incident.id] = incident
            self._save()
            return incident

    def list_actions_for_incident(self, incident_id: str) -> list[RemediationAction]:
        with self._lock:
            return [
                action
                for action in self._state.actions.values()
                if action.incident_id == incident_id
            ]

    def get_action(self, action_id: str) -> RemediationAction | None:
        with self._lock:
            return self._state.actions.get(action_id)

    def upsert_action(self, action: RemediationAction) -> RemediationAction:
        with self._lock:
            self._state.actions[action.id] = action
            self._save()
            return action

    def add_audit_event(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            self._state.audit_events[event.id] = event
            self._save()
            return event

    def list_audit_events(self, incident_id: str | None = None) -> list[AuditEvent]:
        with self._lock:
            events = self._state.audit_events.values()
            if incident_id:
                events = [event for event in events if event.incident_id == incident_id]
            return sorted(events, key=lambda item: item.created_at)

    def _load(self) -> StateSnapshot:
        if not self.path.exists():
            return StateSnapshot()
        with self.path.open("r", encoding="utf-8") as handle:
            return StateSnapshot.model_validate(json.load(handle))

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(self._state.model_dump(mode="json"), handle, indent=2)

