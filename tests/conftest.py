from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from aiops_agent.app import create_app
from aiops_agent.config import Settings


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:
    settings = Settings(
        state_file=tmp_path / "state.json",
        execution_mode="mock",
        auth_enabled=False,
        log_analytics_workspace_id=None,
        log_analytics_workspace_map="",
        enable_live_azure_integrations=False,
    )
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def sample_alert() -> dict:
    return {
        "schemaId": "azureMonitorCommonAlertSchema",
        "data": {
            "essentials": {
                "alertId": "sample-alert",
                "alertRule": "vmss-prod-cpu-dynamic-threshold",
                "severity": "Sev2",
                "signalType": "Metric",
                "monitorCondition": "Fired",
                "monitoringService": "Platform",
                "alertTargetIDs": [
                    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-web"
                ],
                "firedDateTime": "2026-05-26T13:30:00Z",
                "description": "CPU percentage breached dynamic threshold.",
            },
            "alertContext": {"condition": {"metricName": "Percentage CPU"}},
        },
    }
