from aiops_agent.azure_clients import (
    AzureEnterpriseIntegrationClient,
    build_default_alert_signal_query,
    build_resource_discovery_query,
)
from aiops_agent.config import Settings
from aiops_agent.models import AlertPollRequest, LogAnalyticsQueryRequest, ResourceDiscoveryRequest


def test_integration_status_reports_enterprise_modes(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_subscription_ids="sub-a,sub-b",
        log_analytics_workspace_id="workspace-1",
    )
    client = AzureEnterpriseIntegrationClient(settings)

    status = client.status()

    assert status.subscriptions_configured == 2
    assert status.log_analytics_configured is True
    assert "Azure Monitor Action Group webhook" in status.supported_ingestion_modes
    assert "Microsoft.ContainerService/managedClusters" in status.supported_resource_types


def test_log_analytics_query_is_configuration_only_until_live_enabled(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        log_analytics_workspace_id="workspace-1",
        enable_live_azure_integrations=False,
    )
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.query_log_analytics(LogAnalyticsQueryRequest(query="AzureActivity | take 1"))

    assert response.status == "configuration_only"
    assert response.workspace_id == "workspace-1"
    assert response.rows == [{"query": "AzureActivity | take 1"}]


def test_resource_discovery_query_includes_vmss_and_aks():
    query = build_resource_discovery_query(
        [
            "microsoft.compute/virtualmachinescalesets",
            "microsoft.containerservice/managedclusters",
        ],
        25,
    )

    assert "microsoft.compute/virtualmachinescalesets" in query
    assert "microsoft.containerservice/managedclusters" in query
    assert "limit 25" in query


def test_poll_alerts_requires_workspace_configuration(tmp_path):
    settings = Settings(state_file=tmp_path / "state.json")
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.poll_workspace_alert_signals(AlertPollRequest())

    assert response.status == "not_configured"


def test_default_alert_signal_query_is_enterprise_kql():
    query = build_default_alert_signal_query(10)

    assert "AzureActivity" in query
    assert "Event" in query
    assert "Perf" in query
    assert "take 10" in query


def test_discover_resources_is_configuration_only_with_subscriptions(tmp_path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        azure_subscription_ids="sub-a",
        enable_live_azure_integrations=False,
    )
    client = AzureEnterpriseIntegrationClient(settings)

    response = client.discover_resources(ResourceDiscoveryRequest(limit=5))

    assert response.status == "configuration_only"
    assert response.subscriptions == ["sub-a"]
    assert "Resources" in response.query

