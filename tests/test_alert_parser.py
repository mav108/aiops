from datetime import datetime, timezone

from aiops_agent.alert_parser import parse_azure_monitor_alert


def test_parse_common_alert_schema(sample_alert):
    alert = parse_azure_monitor_alert(sample_alert)

    assert alert.id == "sample-alert"
    assert alert.rule_name == "vmss-prod-cpu-dynamic-threshold"
    assert alert.severity == "Sev2"
    assert alert.resource_ids == [
        "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-web"
    ]


def test_parse_log_analytics_datetime_object(sample_alert):
    fired_at = datetime(2026, 5, 27, 10, 30, tzinfo=timezone.utc)
    sample_alert["data"]["essentials"]["firedDateTime"] = fired_at

    alert = parse_azure_monitor_alert(sample_alert)

    assert alert.fired_at == fired_at
