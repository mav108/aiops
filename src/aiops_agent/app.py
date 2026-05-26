from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from aiops_agent.analyzer import build_analyzer
from aiops_agent.azure_clients import AzureContextCollector, AzureRemediationClient
from aiops_agent.config import Settings, get_settings
from aiops_agent.models import (
    AlertIngestResponse,
    ApproveRequest,
    AuditEvent,
    Incident,
    RejectRequest,
    RemediationAction,
)
from aiops_agent.remediation import RemediationExecutor
from aiops_agent.state import JsonStateStore
from aiops_agent.workflow import AlertProcessor


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    store = JsonStateStore(settings.state_file)
    context_collector = AzureContextCollector(settings)
    analyzer = build_analyzer(settings)
    processor = AlertProcessor(store, context_collector, analyzer)
    executor = RemediationExecutor(settings, store, AzureRemediationClient(settings))

    app = FastAPI(title=settings.app_name, version="0.1.0")
    app.state.settings = settings
    app.state.store = store
    app.state.processor = processor
    app.state.executor = executor

    @app.get("/")
    def root() -> dict[str, Any]:
        return {
            "name": settings.app_name,
            "environment": settings.environment,
            "execution_mode": settings.execution_mode,
            "docs": "/docs",
            "ui": "/ui",
        }

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/alerts/azure-monitor", response_model=AlertIngestResponse)
    def ingest_azure_monitor_alert(payload: dict[str, Any]) -> AlertIngestResponse:
        return processor.ingest_azure_monitor_alert(payload)

    @app.get("/incidents", response_model=list[Incident])
    def list_incidents() -> list[Incident]:
        return store.list_incidents()

    @app.get("/incidents/{incident_id}", response_model=Incident)
    def get_incident(incident_id: str) -> Incident:
        incident = store.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident

    @app.get("/incidents/{incident_id}/actions", response_model=list[RemediationAction])
    def list_incident_actions(incident_id: str) -> list[RemediationAction]:
        if not store.get_incident(incident_id):
            raise HTTPException(status_code=404, detail="Incident not found")
        return store.list_actions_for_incident(incident_id)

    @app.get("/incidents/{incident_id}/audit", response_model=list[AuditEvent])
    def list_incident_audit(incident_id: str) -> list[AuditEvent]:
        if not store.get_incident(incident_id):
            raise HTTPException(status_code=404, detail="Incident not found")
        return store.list_audit_events(incident_id)

    @app.post("/incidents/{incident_id}/approve")
    def approve_incident(incident_id: str, request: ApproveRequest):
        try:
            return executor.approve_incident(incident_id, request.approver, request.comment)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/incidents/{incident_id}/reject", response_model=Incident)
    def reject_incident(incident_id: str, request: RejectRequest) -> Incident:
        try:
            return executor.reject_incident(incident_id, request.rejected_by, request.reason)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/actions/{action_id}", response_model=RemediationAction)
    def get_action(action_id: str) -> RemediationAction:
        action = store.get_action(action_id)
        if not action:
            raise HTTPException(status_code=404, detail="Action not found")
        return action

    @app.get("/ui", response_class=HTMLResponse)
    def ui() -> str:
        return _approval_ui()

    return app


def _approval_ui() -> str:
    return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Azure AIOps Agent</title>
  <style>
    :root { font-family: Segoe UI, system-ui, sans-serif; color: #172033; background: #f6f8fb; }
    body { margin: 0; }
    header { background: #12395f; color: white; padding: 18px 24px; }
    main { max-width: 1160px; margin: 0 auto; padding: 24px; }
    table { width: 100%; border-collapse: collapse; background: white; border: 1px solid #d9e1ec; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid #e6edf5; vertical-align: top; }
    th { background: #edf3f8; font-size: 13px; text-transform: uppercase; }
    button { border: 0; border-radius: 6px; padding: 8px 12px; cursor: pointer; }
    .approve { background: #127a5b; color: white; }
    .reject { background: #a83232; color: white; }
    .muted { color: #5d6b7a; }
    .actions { display: flex; gap: 8px; }
  </style>
</head>
<body>
  <header><h1>Azure AIOps Agent</h1></header>
  <main>
    <table>
      <thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Summary</th><th>Actions</th></tr></thead>
      <tbody id="incidents"></tbody>
    </table>
  </main>
  <script>
    async function load() {
      const rows = document.getElementById('incidents');
      const incidents = await fetch('/incidents').then(r => r.json());
      rows.innerHTML = incidents.map(i => `
        <tr>
          <td><strong>${i.title}</strong><br><span class="muted">${i.id}</span></td>
          <td>${i.severity}</td>
          <td>${i.status}</td>
          <td>${i.summary}</td>
          <td class="actions">
            <button class="approve" onclick="approve('${i.id}')">Approve</button>
            <button class="reject" onclick="rejectIncident('${i.id}')">Reject</button>
          </td>
        </tr>`).join('');
    }
    async function approve(id) {
      const approver = prompt('Approver email');
      if (!approver) return;
      await fetch(`/incidents/${id}/approve`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({approver, comment: 'Approved from UI'})
      });
      load();
    }
    async function rejectIncident(id) {
      const rejected_by = prompt('Reviewer email');
      const reason = prompt('Reason');
      if (!rejected_by || !reason) return;
      await fetch(`/incidents/${id}/reject`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({rejected_by, reason})
      });
      load();
    }
    load();
  </script>
</body>
</html>
"""

