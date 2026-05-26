# Microsoft Login

The agent supports optional Microsoft Entra ID login for operator routes. Local development can keep auth disabled; enterprise testing can enable auth and use individual browser sessions.

Microsoft Entra ID uses `https://login.microsoftonline.com/<tenant>` as the authority host for OAuth/OIDC. The user-facing route in this app is `/auth/login`.

## App Registration

Create a Microsoft Entra app registration for a web application:

- Redirect URI: `http://127.0.0.1:8000/auth/callback` for local testing.
- Redirect URI: `https://<deployed-host>/auth/callback` for Azure deployment.
- Client secret: create one and store it securely.
- Supported account types: choose single tenant for internal enterprise use, or organizations for multi-tenant work/school accounts.

## Local `.env`

```env
AIOPS_AUTH_ENABLED=true
AIOPS_AUTH_TENANT_ID=<tenant-id-or-organizations>
AIOPS_AUTH_CLIENT_ID=<app-client-id>
AIOPS_AUTH_CLIENT_SECRET=<app-client-secret>
AIOPS_AUTH_SESSION_SECRET=<long-random-string>
AIOPS_AUTH_SCOPES=openid profile email
AIOPS_AUTH_POST_LOGOUT_REDIRECT_URI=http://127.0.0.1:8000/
```

Start the app from the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn aiops_agent.app:create_app --factory --host 127.0.0.1 --port 8000
```

Open:

- `http://127.0.0.1:8000/auth/login`
- `http://127.0.0.1:8000/me`
- `http://127.0.0.1:8000/ui`

## Protected Routes

When auth is enabled, the operator and integration routes require a signed-in session:

- `/integrations/status`
- `/integrations/log-analytics/query`
- `/integrations/log-analytics/poll-alerts`
- `/integrations/resource-graph/discover`
- `/incidents`
- `/incidents/{incident_id}`
- `/incidents/{incident_id}/approve`
- `/incidents/{incident_id}/reject`
- `/actions/{action_id}`
- `/ui`

The Azure Monitor webhook route remains open by default because Azure Monitor Action Groups are service-to-service calls, not browser sessions. Put the deployed endpoint behind API Management, private ingress, network restrictions, or signed webhook validation before production exposure.
