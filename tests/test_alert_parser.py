from aiops_agent.alert_parser import parse_azure_monitor_alert


def test_parse_common_alert_schema(sample_alert):
    alert = parse_azure_monitor_alert(sample_alert)

    assert alert.id == "sample-alert"
    assert alert.rule_name == "vmss-prod-cpu-dynamic-threshold"
    assert alert.severity == "Sev2"
    assert alert.resource_ids == [
        "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-web"
    ]

