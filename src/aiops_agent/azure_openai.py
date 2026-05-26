from typing import Any

from aiops_agent.config import Settings
import json

from aiops_agent.models import (
    AzureOpenAIStatus,
    AzureOpenAITestResponse,
    LogAnalyticsAnalyzeResponse,
    LogAnalyticsQueryResponse,
)


class AzureOpenAIService:
    def __init__(self, settings: Settings):
        self.settings = settings

    def status(self) -> AzureOpenAIStatus:
        endpoint_configured = bool(self.settings.azure_openai_endpoint)
        deployment_configured = bool(self.settings.azure_openai_deployment)
        api_key_configured = bool(self.settings.azure_openai_api_key)
        configured = self.settings.azure_openai_configured

        message = "Azure OpenAI is configured."
        if not endpoint_configured:
            message = "Set AIOPS_AZURE_OPENAI_ENDPOINT."
        elif not deployment_configured:
            message = "Set AIOPS_AZURE_OPENAI_DEPLOYMENT to your Azure deployment name."
        elif self.settings.azure_openai_auth_mode == "api_key" and not api_key_configured:
            message = "Set AIOPS_AZURE_OPENAI_API_KEY or use managed_identity auth mode."

        return AzureOpenAIStatus(
            enabled=configured,
            configured=configured,
            endpoint_configured=endpoint_configured,
            deployment_configured=deployment_configured,
            api_version=self.settings.azure_openai_api_version,
            auth_mode=self.settings.azure_openai_auth_mode,
            api_key_configured=api_key_configured,
            deployment=self.settings.azure_openai_deployment,
            message=message,
        )

    def client(self):
        if not self.settings.azure_openai_configured:
            raise ValueError(self.status().message)

        if self.settings.azure_openai_api_version.lower() == "v1":
            return self._v1_client()

        from openai import AzureOpenAI

        client_kwargs: dict[str, Any] = {
            "azure_endpoint": self.settings.azure_openai_endpoint,
            "api_version": self.settings.azure_openai_api_version,
        }

        if self.settings.azure_openai_auth_mode == "api_key":
            client_kwargs["api_key"] = self.settings.azure_openai_api_key
        else:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider

            token_provider = get_bearer_token_provider(
                DefaultAzureCredential(),
                "https://cognitiveservices.azure.com/.default",
            )
            client_kwargs["azure_ad_token_provider"] = token_provider

        return AzureOpenAI(**client_kwargs)

    def _v1_client(self):
        from openai import OpenAI

        endpoint = (self.settings.azure_openai_endpoint or "").rstrip("/")
        client_kwargs: dict[str, Any] = {
            "base_url": f"{endpoint}/openai/v1/",
        }

        if self.settings.azure_openai_auth_mode == "api_key":
            client_kwargs["api_key"] = self.settings.azure_openai_api_key
        else:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider

            token_provider = get_bearer_token_provider(
                DefaultAzureCredential(),
                "https://cognitiveservices.azure.com/.default",
            )
            client_kwargs["api_key"] = token_provider

        return OpenAI(**client_kwargs)

    def test_chat(self, prompt: str) -> AzureOpenAITestResponse:
        status = self.status()
        if not status.configured:
            return AzureOpenAITestResponse(
                status="not_configured",
                provider="azure_openai",
                deployment=status.deployment,
                message=status.message,
            )

        try:
            response = self.client().chat.completions.create(
                model=self.settings.azure_openai_deployment,
                max_completion_tokens=80,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a connectivity test for an Azure AIOps agent.",
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            return AzureOpenAITestResponse(
                status="ok",
                provider="azure_openai",
                deployment=self.settings.azure_openai_deployment,
                output=response.choices[0].message.content,
            )
        except Exception as exc:
            return AzureOpenAITestResponse(
                status="error",
                provider="azure_openai",
                deployment=self.settings.azure_openai_deployment,
                message=str(exc),
            )

    def analyze_log_rows(
        self,
        query_result: LogAnalyticsQueryResponse,
        prompt: str,
        max_rows: int,
    ) -> LogAnalyticsAnalyzeResponse:
        rows = query_result.rows[:max_rows]
        if query_result.status not in {"ok", "partial"}:
            return LogAnalyticsAnalyzeResponse(
                query_status=query_result.status,
                analysis_status="skipped",
                workspace_id=query_result.workspace_id,
                row_count=len(query_result.rows),
                columns=query_result.columns,
                message=query_result.message or "Log Analytics query did not return analyzable rows.",
            )
        if not rows:
            return LogAnalyticsAnalyzeResponse(
                query_status=query_result.status,
                analysis_status="no_rows",
                workspace_id=query_result.workspace_id,
                row_count=0,
                columns=query_result.columns,
                message="Log Analytics query returned no rows.",
            )

        status = self.status()
        if not status.configured:
            return LogAnalyticsAnalyzeResponse(
                query_status=query_result.status,
                analysis_status="not_configured",
                workspace_id=query_result.workspace_id,
                row_count=len(query_result.rows),
                columns=query_result.columns,
                message=status.message,
            )

        try:
            response = self.client().chat.completions.create(
                model=self.settings.azure_openai_deployment,
                max_completion_tokens=700,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an Azure AIOps analyst. Summarize Log Analytics rows, "
                            "identify likely operational causes, call out risk, and recommend "
                            "approval-gated next steps. Do not invent facts not present in the rows."
                        ),
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "instruction": prompt,
                                "columns": query_result.columns,
                                "rows": rows,
                            },
                            default=str,
                        ),
                    },
                ],
            )
            return LogAnalyticsAnalyzeResponse(
                query_status=query_result.status,
                analysis_status="ok",
                workspace_id=query_result.workspace_id,
                row_count=len(query_result.rows),
                columns=query_result.columns,
                analysis=response.choices[0].message.content,
            )
        except Exception as exc:
            return LogAnalyticsAnalyzeResponse(
                query_status=query_result.status,
                analysis_status="error",
                workspace_id=query_result.workspace_id,
                row_count=len(query_result.rows),
                columns=query_result.columns,
                message=str(exc),
            )
