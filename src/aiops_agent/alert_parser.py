from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from aiops_agent.models import NormalizedAlert


def parse_azure_monitor_alert(payload: dict[str, Any]) -> NormalizedAlert:
    """Normalize Azure Monitor common alert schema payloads.

    The parser is intentionally tolerant because action groups can include custom
    properties and service-specific alertContext shapes.
    """

    data = payload.get("data", payload)
    essentials = data.get("essentials", {})
    context = data.get("alertContext", {})

    target_ids = essentials.get("alertTargetIDs") or essentials.get("alertTargetIds") or []
    if isinstance(target_ids, str):
        target_ids = [target_ids]

    fired_at = _parse_datetime(essentials.get("firedDateTime"))

    return NormalizedAlert(
        id=essentials.get("alertId") or essentials.get("originAlertId") or f"alert-{uuid4().hex}",
        rule_name=essentials.get("alertRule") or essentials.get("alertRuleName") or "Unknown alert",
        severity=essentials.get("severity") or "Sev3",
        signal_type=essentials.get("signalType"),
        monitor_condition=essentials.get("monitorCondition"),
        monitoring_service=essentials.get("monitoringService"),
        fired_at=fired_at,
        description=essentials.get("description"),
        resource_ids=list(target_ids),
        context=context,
        raw_payload=payload,
    )


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)

