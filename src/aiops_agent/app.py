import html
import sys
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from aiops_agent.analyzer import build_analyzer
from aiops_agent.auth import (
    SESSION_USER_KEY,
    auth_status,
    build_user_profile,
    configure_auth,
    microsoft_logout_url,
    require_user,
    session_user,
)
from aiops_agent.azure_clients import (
    AzureContextCollector,
    AzureEnterpriseIntegrationClient,
    AzureRemediationClient,
)
from aiops_agent.config import Settings, get_settings
from aiops_agent.models import (
    AlertPollRequest,
    AlertIngestResponse,
    ApproveRequest,
    AuthStatus,
    AuditEvent,
    Incident,
    IntegrationStatus,
    LogAnalyticsQueryRequest,
    LogAnalyticsQueryResponse,
    RejectRequest,
    RemediationAction,
    ResourceDiscoveryRequest,
    ResourceDiscoveryResponse,
    UserProfile,
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
    integrations = AzureEnterpriseIntegrationClient(settings)

    app = FastAPI(title=settings.app_name, version="0.1.0")
    oauth = configure_auth(app, settings)
    app.state.settings = settings
    app.state.store = store
    app.state.processor = processor
    app.state.executor = executor
    app.state.integrations = integrations

    def current_user(request: Request) -> UserProfile:
        return require_user(request, settings)

    @app.get("/")
    def root() -> dict[str, Any]:
        return {
            "name": settings.app_name,
            "environment": settings.environment,
            "runtime": {
                "language": "python",
                "python_version": sys.version.split()[0],
                "framework": "fastapi",
            },
            "execution_mode": settings.execution_mode,
            "auth": auth_status(settings).model_dump(mode="json"),
            "azure_integrations": integrations.status().model_dump(mode="json"),
            "docs": "/docs",
            "openapi": "/openapi.json",
            "ui": "/ui",
            "endpoints": {
                "health": "GET /healthz",
                "azure_monitor_webhook": "POST /alerts/azure-monitor",
                "integration_status": "GET /integrations/status",
                "log_analytics_query": "POST /integrations/log-analytics/query",
                "log_analytics_poll_alerts": "POST /integrations/log-analytics/poll-alerts",
                "resource_graph_discovery": "POST /integrations/resource-graph/discover",
                "incidents": "GET /incidents",
                "approval": "POST /incidents/{incident_id}/approve",
                "rejection": "POST /incidents/{incident_id}/reject",
                "profile": "GET /me",
                "profile_json": "GET /api/me",
            },
        }

    @app.get("/auth/status", response_model=AuthStatus)
    def get_auth_status() -> AuthStatus:
        return auth_status(settings)

    @app.get("/auth/login")
    async def auth_login(request: Request):
        if not settings.auth_enabled:
            return RedirectResponse(url="/")
        if not settings.auth_configured:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Microsoft login is enabled but AIOPS_AUTH_CLIENT_ID and "
                    "AIOPS_AUTH_CLIENT_SECRET are not configured."
                ),
            )
        redirect_uri = request.url_for("auth_callback")
        return await oauth.microsoft.authorize_redirect(request, redirect_uri)

    @app.get("/auth/callback")
    async def auth_callback(request: Request):
        if not settings.auth_configured:
            raise HTTPException(status_code=500, detail="Microsoft login is not configured.")
        token = await oauth.microsoft.authorize_access_token(request)
        claims = dict(token.get("userinfo") or {})
        profile = build_user_profile(claims)
        request.session[SESSION_USER_KEY] = profile.model_dump(mode="json")
        return RedirectResponse(url="/ui")

    @app.get("/auth/logout")
    def auth_logout(request: Request):
        request.session.clear()
        if settings.auth_enabled:
            return RedirectResponse(url=microsoft_logout_url(settings))
        return RedirectResponse(url="/")

    @app.get("/api/me", response_model=UserProfile)
    def me_json(request: Request) -> UserProfile:
        if not settings.auth_enabled:
            return current_user(request)
        user = session_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="Not signed in.")
        return user

    @app.get("/me", response_class=HTMLResponse, response_model=None)
    def me(request: Request):
        if not settings.auth_enabled:
            return _profile_ui(current_user(request), auth_enabled=False)
        user = session_user(request)
        return _profile_ui(user, auth_enabled=True)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/alerts/azure-monitor", response_model=AlertIngestResponse)
    def ingest_azure_monitor_alert(payload: dict[str, Any]) -> AlertIngestResponse:
        return processor.ingest_azure_monitor_alert(payload)

    @app.get("/integrations/status", response_model=IntegrationStatus)
    def integration_status(_user: UserProfile = Depends(current_user)) -> IntegrationStatus:
        return integrations.status()

    @app.post("/integrations/log-analytics/query", response_model=LogAnalyticsQueryResponse)
    def query_log_analytics(
        request: LogAnalyticsQueryRequest,
        _user: UserProfile = Depends(current_user),
    ) -> LogAnalyticsQueryResponse:
        return integrations.query_log_analytics(request)

    @app.post("/integrations/log-analytics/poll-alerts", response_model=list[AlertIngestResponse])
    def poll_log_analytics_alerts(
        request: AlertPollRequest,
        _user: UserProfile = Depends(current_user),
    ) -> list[AlertIngestResponse]:
        query_result = integrations.poll_workspace_alert_signals(request)
        if query_result.status in {"error", "not_configured"}:
            raise HTTPException(status_code=400, detail=query_result.message)
        responses = []
        for row in query_result.rows:
            if "ResourceId" in row or "RuleName" in row:
                responses.append(processor.ingest_log_analytics_signal(row))
        return responses

    @app.post("/integrations/resource-graph/discover", response_model=ResourceDiscoveryResponse)
    def discover_resources(
        request: ResourceDiscoveryRequest,
        _user: UserProfile = Depends(current_user),
    ) -> ResourceDiscoveryResponse:
        return integrations.discover_resources(request)

    @app.get("/incidents", response_model=list[Incident])
    def list_incidents(_user: UserProfile = Depends(current_user)) -> list[Incident]:
        return store.list_incidents()

    @app.get("/incidents/{incident_id}", response_model=Incident)
    def get_incident(
        incident_id: str,
        _user: UserProfile = Depends(current_user),
    ) -> Incident:
        incident = store.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident

    @app.get("/incidents/{incident_id}/actions", response_model=list[RemediationAction])
    def list_incident_actions(
        incident_id: str,
        _user: UserProfile = Depends(current_user),
    ) -> list[RemediationAction]:
        if not store.get_incident(incident_id):
            raise HTTPException(status_code=404, detail="Incident not found")
        return store.list_actions_for_incident(incident_id)

    @app.get("/incidents/{incident_id}/audit", response_model=list[AuditEvent])
    def list_incident_audit(
        incident_id: str,
        _user: UserProfile = Depends(current_user),
    ) -> list[AuditEvent]:
        if not store.get_incident(incident_id):
            raise HTTPException(status_code=404, detail="Incident not found")
        return store.list_audit_events(incident_id)

    @app.post("/incidents/{incident_id}/approve")
    def approve_incident(
        incident_id: str,
        request: ApproveRequest,
        _user: UserProfile = Depends(current_user),
    ):
        try:
            return executor.approve_incident(incident_id, request.approver, request.comment)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/incidents/{incident_id}/reject", response_model=Incident)
    def reject_incident(
        incident_id: str,
        request: RejectRequest,
        _user: UserProfile = Depends(current_user),
    ) -> Incident:
        try:
            return executor.reject_incident(incident_id, request.rejected_by, request.reason)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/actions/{action_id}", response_model=RemediationAction)
    def get_action(
        action_id: str,
        _user: UserProfile = Depends(current_user),
    ) -> RemediationAction:
        action = store.get_action(action_id)
        if not action:
            raise HTTPException(status_code=404, detail="Action not found")
        return action

    @app.get("/ui", response_class=HTMLResponse, response_model=None)
    def ui(request: Request):
        if settings.auth_enabled and not session_user(request):
            return RedirectResponse(url="/auth/login")
        return _approval_ui()

    return app


def _profile_ui(user: UserProfile | None, auth_enabled: bool) -> str:
    if user is None:
        return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Profile - Azure AIOps Agent</title>
  <style>
    :root { font-family: Segoe UI, system-ui, sans-serif; color: #172033; background: #f6f8fb; }
    body { margin: 0; }
    header { background: #12395f; color: white; padding: 18px 24px; display: flex; justify-content: space-between; align-items: center; gap: 16px; }
    header h1 { font-size: 20px; margin: 0; }
    main { max-width: 920px; margin: 0 auto; padding: 28px 24px; }
    .panel { background: white; border: 1px solid #d9e1ec; border-radius: 8px; padding: 24px; }
    .actions { display: flex; gap: 10px; margin-top: 18px; flex-wrap: wrap; }
    a.button { background: #1267a8; color: white; text-decoration: none; border-radius: 6px; padding: 10px 14px; font-weight: 600; }
    a.secondary { color: #17466d; text-decoration: none; font-weight: 600; }
  </style>
</head>
<body>
  <header><h1>Azure AIOps Agent</h1><a class="secondary" style="color:white" href="/docs">API Docs</a></header>
  <main>
    <section class="panel">
      <h2>Not Signed In</h2>
      <p>Sign in with Microsoft to view your profile and access operator actions.</p>
      <div class="actions">
        <a class="button" href="/auth/login">Sign In</a>
        <a class="secondary" href="/">Service Status</a>
      </div>
    </section>
  </main>
</body>
</html>
"""

    name = _escape(user.name or user.username or "Operator")
    username = _escape(user.username or "")
    email = _escape(user.email or "")
    object_id = _escape(user.object_id or "")
    tenant_id = _escape(user.tenant_id or "")
    initials = _initials(user.name or user.username or "Operator")
    auth_mode = "Microsoft Entra ID" if auth_enabled else "Local development"
    sign_out = '<a class="button danger" href="/auth/logout">Sign Out</a>' if auth_enabled else ""

    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Profile - Azure AIOps Agent</title>
  <style>
    :root {{ font-family: Segoe UI, system-ui, sans-serif; color: #172033; background: #f6f8fb; }}
    body {{ margin: 0; }}
    header {{ background: #12395f; color: white; padding: 18px 24px; display: flex; justify-content: space-between; align-items: center; gap: 16px; }}
    header h1 {{ font-size: 20px; margin: 0; }}
    nav {{ display: flex; gap: 14px; flex-wrap: wrap; }}
    nav a {{ color: white; text-decoration: none; font-weight: 600; }}
    main {{ max-width: 1080px; margin: 0 auto; padding: 28px 24px; }}
    .summary {{ display: grid; grid-template-columns: auto 1fr; gap: 18px; align-items: center; background: white; border: 1px solid #d9e1ec; border-radius: 8px; padding: 24px; }}
    .avatar {{ width: 76px; height: 76px; border-radius: 50%; background: #1267a8; color: white; display: grid; place-items: center; font-size: 26px; font-weight: 700; }}
    h2 {{ margin: 0 0 6px; font-size: 24px; }}
    .muted {{ color: #5d6b7a; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-top: 18px; }}
    .field {{ background: white; border: 1px solid #d9e1ec; border-radius: 8px; padding: 16px; min-width: 0; }}
    .label {{ color: #5d6b7a; font-size: 12px; text-transform: uppercase; font-weight: 700; margin-bottom: 8px; }}
    .value {{ overflow-wrap: anywhere; font-size: 15px; }}
    .actions {{ display: flex; gap: 10px; margin-top: 18px; flex-wrap: wrap; }}
    a.button {{ background: #1267a8; color: white; text-decoration: none; border-radius: 6px; padding: 10px 14px; font-weight: 600; }}
    a.button.secondary {{ background: #eef4f8; color: #17466d; }}
    a.button.danger {{ background: #a83232; }}
  </style>
</head>
<body>
  <header>
    <h1>Azure AIOps Agent</h1>
    <nav>
      <a href="/ui">Incidents</a>
      <a href="/docs">API Docs</a>
      <a href="/api/me">JSON</a>
    </nav>
  </header>
  <main>
    <section class="summary">
      <div class="avatar">{initials}</div>
      <div>
        <h2>{name}</h2>
        <div class="muted">{email or username}</div>
        <div class="actions">
          <a class="button" href="/ui">Open Incidents</a>
          <a class="button secondary" href="/">Service Status</a>
          {sign_out}
        </div>
      </div>
    </section>
    <section class="grid" aria-label="Profile details">
      <div class="field"><div class="label">Authentication</div><div class="value">{auth_mode}</div></div>
      <div class="field"><div class="label">Username</div><div class="value">{username or "Not provided"}</div></div>
      <div class="field"><div class="label">Email</div><div class="value">{email or "Not provided"}</div></div>
      <div class="field"><div class="label">Tenant ID</div><div class="value">{tenant_id or "Not provided"}</div></div>
      <div class="field"><div class="label">Object ID</div><div class="value">{object_id or "Not provided"}</div></div>
      <div class="field"><div class="label">Session</div><div class="value">Browser session active</div></div>
    </section>
  </main>
</body>
</html>
"""


def _escape(value: str) -> str:
    return html.escape(value, quote=True)


def _initials(value: str) -> str:
    parts = [part for part in value.replace("@", " ").replace(".", " ").split() if part]
    letters = "".join(part[0] for part in parts[:2]).upper()
    return html.escape(letters or "OP", quote=True)


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
