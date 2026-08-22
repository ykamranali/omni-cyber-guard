"""
Language-model transport for the security engineer.

The important behaviour in this module is what happens when no model is
reachable. The previous implementation defaulted to `http://localhost:11434`,
and when nothing answered there it returned the connection exception as the
assistant's reply — which the UI rendered in the same panel, in the same
typeface, as analysis. An operator skimming the page saw text where analysis
should be.

So: configuration is explicit and off by default, `status()` reports precisely
what is missing and how to supply it, and a transport failure raises
`ProviderUnavailable` rather than producing content. Nothing in this module can
return a string that reaches the operator as an answer.

Two wire formats are supported, both of which carry native tool-calling:

  openai_compatible   POST {base}/chat/completions   (OpenAI, vLLM, LiteLLM,
                      llama.cpp server, Together, Groq, Azure OpenAI …)
  ollama              POST {base}/api/chat           (Ollama ≥ 0.3)

Adding a third means implementing `chat()` and `status()`; nothing else in the
agent knows which transport is in use.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

import requests

from app.core.config import settings

logger = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = ("openai_compatible", "ollama")


class ProviderUnavailable(RuntimeError):
    """The model could not be reached or returned something unusable."""


@dataclass(frozen=True)
class ProviderStatus:
    """
    Whether the assistant can run, and if not, exactly what to do about it.

    The five fields after `configured` exist so the API can answer the
    operator's real question — "what do I have to set up?" — without them
    having to read the source.
    """
    configured: bool
    provider: str = ""
    endpoint: str = ""
    model: str = ""
    missing: list[str] = field(default_factory=list)
    why_required: str = ""
    how_to_enable: str = ""
    implemented_in: str = "backend/app/agents/provider.py"

    def as_dict(self) -> dict:
        return {
            "configured": self.configured,
            "provider": self.provider,
            "endpoint": self.endpoint,
            "model": self.model,
            "missing": list(self.missing),
            "why_required": self.why_required,
            "how_to_enable": self.how_to_enable,
            "implemented_in": self.implemented_in,
        }


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class LLMReply:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMProvider(Protocol):
    name: str
    model: str

    def status(self) -> ProviderStatus: ...

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMReply: ...


WHY_REQUIRED = (
    "The security engineer summarises findings that already exist in your "
    "database. It needs a language model to do the summarising. Retrieval, "
    "grounding checks and action gating are implemented and require no external "
    "service, but without a model there is nothing to phrase the answer."
)

HOW_TO_ENABLE = (
    "Set these in the backend environment and restart the API:\n"
    "  AGENT_LLM_PROVIDER=ollama            # or openai_compatible\n"
    "  AGENT_LLM_BASE_URL=http://ollama:11434\n"
    "  AGENT_LLM_MODEL=llama3.1             # must support tool calling\n"
    "  AGENT_LLM_API_KEY=...                # openai_compatible only\n"
    "The model must support tool calling; the agent has no free-text fallback "
    "and will not answer from an unstructured prompt."
)


def _parse_arguments(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        raise ProviderUnavailable(
            "The model returned tool arguments that are not valid JSON. The "
            "configured model may not support tool calling."
        )
    return parsed if isinstance(parsed, dict) else {}


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(self) -> None:
        self.base_url = settings.AGENT_LLM_BASE_URL.rstrip("/")
        self.model = settings.AGENT_LLM_MODEL
        self.api_key = settings.AGENT_LLM_API_KEY

    def status(self) -> ProviderStatus:
        missing = []
        if not self.base_url:
            missing.append("AGENT_LLM_BASE_URL")
        if not self.model:
            missing.append("AGENT_LLM_MODEL")
        return ProviderStatus(
            configured=not missing,
            provider=self.name,
            endpoint=f"{self.base_url}/chat/completions" if self.base_url else "",
            model=self.model,
            missing=missing,
            why_required=WHY_REQUIRED if missing else "",
            how_to_enable=HOW_TO_ENABLE if missing else "",
        )

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMReply:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                json=payload, headers=headers,
                timeout=settings.AGENT_LLM_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            body = response.json()
        except requests.RequestException as exc:
            raise ProviderUnavailable(f"{self.base_url} did not answer: {exc}") from exc
        except ValueError as exc:
            raise ProviderUnavailable(f"{self.base_url} returned a non-JSON body.") from exc

        try:
            message = body["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderUnavailable(
                "The response did not contain a chat completion."
            ) from exc

        calls = [
            ToolCall(
                id=str(call.get("id") or f"call_{index}"),
                name=str(call.get("function", {}).get("name", "")),
                arguments=_parse_arguments(call.get("function", {}).get("arguments")),
            )
            for index, call in enumerate(message.get("tool_calls") or [])
        ]
        return LLMReply(content=message.get("content") or "", tool_calls=calls)


class OllamaProvider:
    name = "ollama"

    def __init__(self) -> None:
        self.base_url = settings.AGENT_LLM_BASE_URL.rstrip("/")
        self.model = settings.AGENT_LLM_MODEL

    def status(self) -> ProviderStatus:
        missing = []
        if not self.base_url:
            missing.append("AGENT_LLM_BASE_URL")
        if not self.model:
            missing.append("AGENT_LLM_MODEL")
        return ProviderStatus(
            configured=not missing,
            provider=self.name,
            endpoint=f"{self.base_url}/api/chat" if self.base_url else "",
            model=self.model,
            missing=missing,
            why_required=WHY_REQUIRED if missing else "",
            how_to_enable=HOW_TO_ENABLE if missing else "",
        )

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMReply:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0},
        }
        if tools:
            payload["tools"] = tools

        try:
            response = requests.post(
                f"{self.base_url}/api/chat", json=payload,
                timeout=settings.AGENT_LLM_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            body = response.json()
        except requests.RequestException as exc:
            raise ProviderUnavailable(f"{self.base_url} did not answer: {exc}") from exc
        except ValueError as exc:
            raise ProviderUnavailable(f"{self.base_url} returned a non-JSON body.") from exc

        message = body.get("message")
        if not isinstance(message, dict):
            raise ProviderUnavailable("The response did not contain a chat message.")

        calls = [
            ToolCall(
                id=f"call_{index}",
                name=str(call.get("function", {}).get("name", "")),
                arguments=_parse_arguments(call.get("function", {}).get("arguments")),
            )
            for index, call in enumerate(message.get("tool_calls") or [])
        ]
        return LLMReply(content=message.get("content") or "", tool_calls=calls)


class UnconfiguredProvider:
    """
    Stands in when no provider is selected.

    It answers `status()` honestly and raises on `chat()`. It never returns
    text, because text from here would be indistinguishable from analysis.
    """
    name = "none"
    model = ""

    def status(self) -> ProviderStatus:
        return ProviderStatus(
            configured=False,
            provider="",
            missing=["AGENT_LLM_PROVIDER", "AGENT_LLM_BASE_URL", "AGENT_LLM_MODEL"],
            why_required=WHY_REQUIRED,
            how_to_enable=HOW_TO_ENABLE,
        )

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMReply:
        raise ProviderUnavailable(
            "No language model is configured for the security engineer."
        )


def get_provider() -> LLMProvider:
    choice = (settings.AGENT_LLM_PROVIDER or "").strip().lower()
    if choice == "openai_compatible":
        return OpenAICompatibleProvider()
    if choice == "ollama":
        return OllamaProvider()
    if choice:
        logger.warning(
            "AGENT_LLM_PROVIDER=%r is not one of %s; the security engineer stays disabled.",
            choice, ", ".join(SUPPORTED_PROVIDERS),
        )
    return UnconfiguredProvider()
