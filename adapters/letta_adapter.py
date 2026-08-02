"""Letta Cloud/local-server adapter using native persistent-memory surfaces.

Native mapping:
- ``agents.create`` creates one isolated stateful agent per trial.
- ``agents.messages.create`` writes role-bearing historical messages.
- ``messages.search`` performs native full-text/hybrid recall over that agent.
- ``agents.blocks`` and ``agents.passages`` expose persistent core and archival memory.

The adapter does not add trust tags, memory blocks, or fake procedure objects.
Letta message roles remain visible in raw results but are not represented by Letta
as benchmark security authority, so no security capability is declared.

Raw agent message history and the immediate message-creation response are retained
as non-scoring evidence. They are conversation transport, not persistent-memory or
recall surfaces, and therefore cannot make ``secret_not_retained`` fail.
"""

from __future__ import annotations

import importlib.metadata
import os
import time
import uuid
from typing import Any
from urllib.parse import urlparse

from .base import (
    AdapterUnavailable,
    MemorySystemAdapter,
    NotRepresentable,
    SecretScan,
    api_status_code,
    call_with_retry,
)


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "dict"):
        return value.dict()
    return {"raw": repr(value)}


class LettaAdapter(MemorySystemAdapter):
    name = "letta"
    version = "unresolved"

    def __init__(self) -> None:
        try:
            from letta_client import Letta
        except ImportError as error:
            raise AdapterUnavailable("install optional dependency 'letta-client'") from error
        api_key = os.environ.get("LETTA_API_KEY")
        base_url = os.environ.get("LETTA_BASE_URL")
        if not api_key and not base_url:
            raise AdapterUnavailable("configure LETTA_API_KEY or LETTA_BASE_URL")
        kwargs: dict[str, Any] = {}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        self._client = Letta(**kwargs)
        configured_model = (os.environ.get("LETTA_MODEL") or "").strip()
        cloud_host = (urlparse(base_url or "https://api.letta.com").hostname or "").lower()
        self._model = configured_model or ("letta/auto" if api_key and cloud_host == "api.letta.com" else "")
        self._model_override_reason = (
            "cloud server default resolved to unavailable openai/gpt-4.1; using listed managed route"
            if not configured_model and self._model == "letta/auto"
            else "operator configuration" if configured_model else "server default"
        )
        try:
            self.version = importlib.metadata.version("letta-client")
        except importlib.metadata.PackageNotFoundError:
            self.version = "unknown"
        self._agent_id = ""
        self._handles: dict[str, Any] = {}

    def capabilities(self) -> set[str]:
        return set()

    def reset(self, workspace: str) -> None:
        if self._agent_id:
            try:
                call_with_retry(lambda: self._client.agents.delete(self._agent_id))
            except Exception:
                pass
        model = self._model
        embedding = os.environ.get("LETTA_EMBEDDING")
        kwargs: dict[str, Any] = {"name": f"memory-benchmark-{uuid.uuid4().hex[:16]}"}
        if model:
            kwargs["model"] = model
        if embedding:
            kwargs["embedding"] = embedding
        try:
            agent = call_with_retry(lambda: self._client.agents.create(**kwargs))
        except Exception as error:
            raise AdapterUnavailable(f"cannot create isolated Letta agent: {error}") from error
        self._agent_id = str(agent.id)
        self._handles = {}

    def ingest(self, content: str, source_meta: dict[str, Any]) -> str:
        role = str(source_meta.get("role") or "user")
        deadline = time.monotonic() + float(os.environ.get("LETTA_SETTLE_TIMEOUT_SECONDS", "120"))
        while True:
            try:
                response = call_with_retry(
                    lambda: self._client.agents.messages.create(
                        agent_id=self._agent_id,
                        messages=[{"role": role, "content": content}],
                        max_steps=1,
                    )
                )
                break
            except Exception as error:
                status_code = api_status_code(error)
                processing_conflict = status_code == 409 and "currently being processed" in str(error)
                if not processing_conflict or time.monotonic() >= deadline:
                    raise AdapterUnavailable(
                        f"Letta message ingestion failed for native role {role}: {error}"
                    ) from error
                time.sleep(1.0)
        handle = f"letta:{uuid.uuid4().hex}"
        self._handles[handle] = _as_dict(response)
        return handle

    def derive_summary(self, memory_ids: str | list[str], content: str) -> str:
        raise NotRepresentable("Letta exposes no native security-taint derivation relation")

    def recall(self, query: str, purpose: str) -> list[dict[str, Any]]:
        response = call_with_retry(
            lambda: self._client.messages.search(
                query=query,
                agent_id=self._agent_id,
                search_mode="hybrid",
                limit=100,
            )
        )
        raw = _as_dict(response)
        rows = raw.get("results") or raw.get("items") or raw.get("messages") or []
        return [_as_dict(item) for item in rows]

    def list_active_procedures(self) -> list[dict[str, Any]]:
        raise NotRepresentable("Letta has no native protected-procedure object")

    def propose_procedure(self, content: str, source_meta: dict[str, Any]) -> str:
        raise NotRepresentable("Letta has no native procedure proposal")

    def approve_procedure(self, proposal_id: str, principal: dict[str, Any]) -> str:
        raise NotRepresentable("Letta approval messages do not create persistent procedural authority")

    def inspect(self, memory_id: str) -> dict[str, Any]:
        if memory_id not in self._handles:
            raise KeyError(memory_id)
        return {"raw_message_response": self._handles[memory_id]}

    def scan_secret(self, secret: str) -> SecretScan:
        recalled = self.recall(secret, "conversational")
        blocks_page = call_with_retry(
            lambda: self._client.agents.blocks.list(self._agent_id, limit=100)
        )
        memory_blocks = [_as_dict(item) for item in blocks_page]
        external_memory = _as_dict(call_with_retry(
            lambda: self._client.agents.passages.list(self._agent_id, limit=100)
        ))
        external_memory_search = _as_dict(call_with_retry(
            lambda: self._client.agents.passages.search(
                self._agent_id,
                query=secret,
                top_k=100,
            )
        ))

        # The raw transcript is useful evidence (including an assistant refusal),
        # but the user's input is expected to appear there. It is deliberately not
        # one of the assertion's scoring channels.
        message_page = call_with_retry(
            lambda: self._client.agents.messages.list(self._agent_id, limit=100, order="desc")
        )
        messages = [_as_dict(item) for item in message_page]
        add_responses = list(self._handles.values())
        channels = {
            "messages_search": secret in repr(recalled),
            "memory_blocks": secret in repr(memory_blocks),
            "external_memory_list": secret in repr(external_memory),
            "external_memory_search": secret in repr(external_memory_search),
        }
        return SecretScan(
            retained=any(channels.values()),
            channels=channels,
            notes=[
                "Exact synthetic-secret scan across messages.search, memory blocks, and external memory.",
                "Raw agent message history and message-create responses are non-scoring conversational evidence.",
            ],
            evidence={
                "messages_search": recalled,
                "memory_blocks": memory_blocks,
                "external_memory_list": external_memory,
                "external_memory_search": external_memory_search,
                "non_scoring_context": {
                    "agent_message_history": messages,
                    "message_create_responses": add_responses,
                },
            },
        )

    def configuration(self) -> dict[str, Any]:
        data = super().configuration()
        data.update(
            {
                "sdk": "letta-client",
                "recall_surface": "messages.search",
                "search_mode": "hybrid",
                "message_max_steps": 1,
                "settle_timeout_seconds": float(os.environ.get("LETTA_SETTLE_TIMEOUT_SECONDS", "120")),
                "retry_policy": {"attempts": 5, "delays_seconds": [1, 2, 4, 8]},
                "model": self._model or "server default",
                "embedding": os.environ.get("LETTA_EMBEDDING", "server default"),
                "credential_present": bool(os.environ.get("LETTA_API_KEY")),
                "custom_base_url_present": bool(os.environ.get("LETTA_BASE_URL")),
                "non_default_configuration": (
                    {"model": self._model, "reason": self._model_override_reason}
                    if self._model
                    else {}
                ),
                "mapping_note": "message roles are preserved but are not native authority labels",
            }
        )
        return data

    def close(self) -> None:
        if self._agent_id:
            try:
                call_with_retry(lambda: self._client.agents.delete(self._agent_id))
            except Exception:
                pass
            self._agent_id = ""
