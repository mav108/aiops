from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="AIOPS_", env_file=".env", extra="ignore")

    app_name: str = "Azure AIOps Agent"
    environment: str = "local"
    state_file: Path = Path(".data/aiops-state.json")
    execution_mode: Literal["mock", "live"] = "mock"
    remediation_allowlist: str = (
        "restart_vm,resize_vmss,run_automation_webhook,adjust_autoscale_rule,"
        "create_ticket,manual_action_required"
    )
    destructive_action_allowlist: str = ""

    azure_subscription_ids: str = ""
    log_analytics_workspace_id: str | None = None
    automation_webhook_url: str | None = None

    azure_openai_endpoint: str | None = None
    azure_openai_deployment: str | None = None
    azure_openai_api_version: str = "2024-02-15-preview"
    azure_openai_api_key: str | None = None

    @field_validator("remediation_allowlist", "destructive_action_allowlist")
    @classmethod
    def normalize_csv(cls, value: str) -> str:
        return ",".join(part.strip() for part in value.split(",") if part.strip())

    @property
    def subscription_id_list(self) -> list[str]:
        return [part.strip() for part in self.azure_subscription_ids.split(",") if part.strip()]

    @property
    def remediation_allowlist_set(self) -> set[str]:
        return {part.strip() for part in self.remediation_allowlist.split(",") if part.strip()}

    @property
    def destructive_action_allowlist_set(self) -> set[str]:
        return {part.strip() for part in self.destructive_action_allowlist.split(",") if part.strip()}

    @property
    def azure_openai_enabled(self) -> bool:
        return bool(self.azure_openai_endpoint and self.azure_openai_deployment)


@lru_cache
def get_settings() -> Settings:
    return Settings()
