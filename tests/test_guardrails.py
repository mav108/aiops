from aiops_agent.azure_clients import AzureRemediationClient
from aiops_agent.config import Settings
from aiops_agent.models import ActionStatus, ActionType, RemediationAction, RiskLevel
from aiops_agent.remediation import RemediationExecutor
from aiops_agent.state import JsonStateStore


def test_unapproved_action_is_blocked(tmp_path):
    settings = Settings(state_file=tmp_path / "state.json", execution_mode="mock")
    store = JsonStateStore(settings.state_file)
    executor = RemediationExecutor(settings, store, AzureRemediationClient(settings))
    action = RemediationAction(
        incident_id="inc_test",
        type=ActionType.RESTART_VM,
        risk=RiskLevel.MEDIUM,
        description="Restart VM",
        affected_resources=["/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"],
        required_permissions=["Microsoft.Compute/virtualMachines/restart/action"],
        rollback="Start VM if needed.",
    )

    result = executor.execute_approved_action(action)

    assert result.status == ActionStatus.BLOCKED
    assert "approved" in result.output


def test_destructive_action_is_blocked_without_explicit_allowlist(tmp_path):
    settings = Settings(state_file=tmp_path / "state.json", execution_mode="mock")
    store = JsonStateStore(settings.state_file)
    executor = RemediationExecutor(settings, store, AzureRemediationClient(settings))
    action = RemediationAction(
        incident_id="inc_test",
        type=ActionType.RESTART_VM,
        status=ActionStatus.APPROVED,
        risk=RiskLevel.DESTRUCTIVE,
        description="Dangerous restart",
        affected_resources=["/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"],
        required_permissions=["Microsoft.Compute/virtualMachines/restart/action"],
        rollback="Restore from backup.",
    )

    result = executor.execute_approved_action(action)

    assert result.status == ActionStatus.BLOCKED
    assert "Destructive" in result.output

