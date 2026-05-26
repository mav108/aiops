from typing import Any
from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException, Request, status
from starlette.middleware.sessions import SessionMiddleware

from aiops_agent.config import Settings
from aiops_agent.models import AuthStatus, UserProfile

SESSION_USER_KEY = "user"


def configure_auth(app, settings: Settings) -> OAuth:
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.auth_session_secret,
        same_site="lax",
        https_only=False,
    )

    oauth = OAuth()
    if settings.auth_enabled and settings.auth_client_id and settings.auth_client_secret:
        oauth.register(
            name="microsoft",
            client_id=settings.auth_client_id,
            client_secret=settings.auth_client_secret,
            server_metadata_url=settings.auth_metadata_url,
            client_kwargs={"scope": settings.auth_scopes},
        )
    app.state.oauth = oauth
    return oauth


def auth_status(settings: Settings) -> AuthStatus:
    return AuthStatus(
        enabled=settings.auth_enabled,
        configured=settings.auth_configured,
        authority=settings.auth_authority,
        login_url="/auth/login",
        logout_url="/auth/logout",
        profile_url="/me",
    )


def require_user(request: Request, settings: Settings) -> UserProfile:
    if not settings.auth_enabled:
        return UserProfile(
            authenticated=False,
            name="Local operator",
            username="local",
            email=None,
            claims={"auth_mode": "disabled"},
        )

    user = request.session.get(SESSION_USER_KEY)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Microsoft login required. Visit /auth/login first.",
        )
    return UserProfile.model_validate(user)


def session_user(request: Request) -> UserProfile | None:
    user = request.session.get(SESSION_USER_KEY)
    return UserProfile.model_validate(user) if user else None


def build_user_profile(claims: dict[str, Any]) -> UserProfile:
    return UserProfile(
        authenticated=True,
        name=claims.get("name"),
        username=claims.get("preferred_username") or claims.get("upn"),
        email=claims.get("email") or claims.get("preferred_username"),
        object_id=claims.get("oid") or claims.get("sub"),
        tenant_id=claims.get("tid"),
        claims=claims,
    )


def microsoft_logout_url(settings: Settings) -> str:
    query = urlencode({"post_logout_redirect_uri": settings.auth_post_logout_redirect_uri})
    return f"{settings.auth_authority}/oauth2/v2.0/logout?{query}"
