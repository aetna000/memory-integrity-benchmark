"""Zep Cloud v3 adapter using threads, messages, and graph search.

Native mapping:
- ``thread.create`` creates a per-trial thread bound to a per-trial user.
- ``thread.add_messages`` ingests user/assistant roles.
- ``graph.search(..., scope='episodes')`` recalls ingested episodes.

Zep episode provenance is retained as raw output, but this adapter does not call
it a security trust/taint marker. No benchmark capability is declared unless the
public model directly represents the corresponding enforcement concept.
"""

from __future__ import annotations

import importlib.metadata
import os
import time
import uuid
from typing import Any

from .base import AdapterUnavailable, MemorySystemAdapter, NotRepresentable, call_with_retry


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "dict"):
        return value.dict()
    return {"raw": repr(value)}


class ZepAdapter(MemorySystemAdapter):
    name = "zep"
    version = "unresolved"

    def __init__(self) -> None:
        try:
            from zep_cloud.client import Zep
            from zep_cloud.types import Message
        except ImportError as error:
            raise AdapterUnavailable("install optional dependency 'zep-cloud'") from error
        if not os.environ.get("ZEP_API_KEY"):
            raise AdapterUnavailable("ZEP_API_KEY is not configured")
        try:
            self.version = importlib.metadata.version("zep-cloud")
        except importlib.metadata.PackageNotFoundError:
            self.version = "unknown"
        self._client = Zep(api_key=os.environ["ZEP_API_KEY"])
        self._message_type = Message
        self._user_id = ""
        self._thread_id = ""
        self._handles: dict[str, Any] = {}
        self._pending_episode_uuids: list[str] = []

    def capabilities(self) -> set[str]:
        return set()

    def reset(self, workspace: str) -> None:
        self._delete_user(self._user_id)
        suffix = uuid.uuid5(uuid.NAMESPACE_URL, workspace).hex
        self._user_id = f"memory-benchmark-user-{suffix}"
        self._thread_id = f"memory-benchmark-thread-{suffix}"
        self._handles = {}
        self._pending_episode_uuids = []
        try:
            call_with_retry(lambda: self._client.user.add(user_id=self._user_id))
        except Exception as error:
            try:
                call_with_retry(lambda: self._client.user.get(self._user_id))
            except Exception:
                raise AdapterUnavailable(f"cannot create isolated Zep user: {error}") from error
        try:
            call_with_retry(
                lambda: self._client.thread.create(thread_id=self._thread_id, user_id=self._user_id)
            )
        except Exception as error:
            # Deterministic retry of a previously interrupted trial may encounter
            # an already-created thread. Confirm it exists; otherwise surface ERROR.
            try:
                call_with_retry(lambda: self._client.thread.get(self._thread_id))
            except Exception:
                raise AdapterUnavailable(f"cannot create isolated Zep thread: {error}") from error

    def ingest(self, content: str, source_meta: dict[str, Any]) -> str:
        role = str(source_meta.get("role") or "user")
        name = str(source_meta.get("principal") or ("benchmark-agent" if role == "assistant" else "benchmark-user"))
        response = call_with_retry(
            lambda: self._client.thread.add_messages(
                self._thread_id,
                messages=[self._message_type(name=name, role=role, content=content)],
            )
        )
        handle = f"zep:{uuid.uuid4().hex}"
        raw = _as_dict(response)
        self._handles[handle] = raw
        message_uuids = [str(item) for item in raw.get("message_uuids") or [] if item]
        if not message_uuids:
            raise AdapterUnavailable("Zep add_messages returned no message UUID for ingestion polling")
        self._pending_episode_uuids.extend(message_uuids)
        return handle

    def derive_summary(self, memory_ids: str | list[str], content: str) -> str:
        raise NotRepresentable("Zep exposes graph provenance, not a native security-taint derivation")

    def settle(self) -> None:
        # Zep graph ingestion is asynchronous. Poll the native thread once per
        # interval and match the returned message UUIDs. This avoids multiplying
        # API traffic by the seven repeated messages in attack F.
        deadline = time.monotonic() + float(os.environ.get("ZEP_SETTLE_TIMEOUT_SECONDS", "300"))
        if not self._pending_episode_uuids:
            return
        pending = set(self._pending_episode_uuids)
        while time.monotonic() < deadline:
            thread = call_with_retry(
                lambda: self._client.thread.get(
                    self._thread_id, lastn=max(1, len(self._pending_episode_uuids))
                )
            )
            raw = _as_dict(thread)
            for message in raw.get("messages") or []:
                item = _as_dict(message)
                message_uuid = str(item.get("uuid") or item.get("uuid_") or "")
                if message_uuid in pending and bool(item.get("processed")):
                    pending.remove(message_uuid)
            if not pending:
                self._pending_episode_uuids = []
                return
            time.sleep(float(os.environ.get("ZEP_SETTLE_POLL_SECONDS", "10")))
        raise AdapterUnavailable("Zep ingestion did not settle before the configured timeout")

    def recall(self, query: str, purpose: str) -> list[dict[str, Any]]:
        response = call_with_retry(
            lambda: self._client.graph.search(
                user_id=self._user_id, query=query, scope="episodes"
            )
        )
        raw = _as_dict(response)
        rows = raw.get("results") or raw.get("episodes") or []
        return [_as_dict(item) for item in rows]

    def list_active_procedures(self) -> list[dict[str, Any]]:
        raise NotRepresentable("Zep has no native protected-procedure object")

    def propose_procedure(self, content: str, source_meta: dict[str, Any]) -> str:
        raise NotRepresentable("Zep has no native procedure proposal")

    def approve_procedure(self, proposal_id: str, principal: dict[str, Any]) -> str:
        raise NotRepresentable("Zep has no native procedural authority witness")

    def inspect(self, memory_id: str) -> dict[str, Any]:
        if memory_id not in self._handles:
            raise KeyError(memory_id)
        return {"raw_add_response": self._handles[memory_id]}

    def configuration(self) -> dict[str, Any]:
        data = super().configuration()
        data.update(
            {
                "sdk": "zep-cloud",
                "search_scope": "episodes",
                "settle_timeout_seconds": float(os.environ.get("ZEP_SETTLE_TIMEOUT_SECONDS", "300")),
                "settle_poll_seconds": float(os.environ.get("ZEP_SETTLE_POLL_SECONDS", "10")),
                "credential_present": bool(os.environ.get("ZEP_API_KEY")),
                "retry_policy": {
                    "attempts": 5,
                    "delays_seconds": [1, 2, 4, 8],
                    "honors_numeric_retry_after": True,
                    "retry_after_cap_seconds": 120,
                },
                "non_default_configuration": {},
                "mapping_note": "episode/message provenance is raw evidence, not a security trust marker",
            }
        )
        return data

    def _delete_user(self, user_id: str) -> None:
        if not user_id:
            return
        try:
            call_with_retry(lambda: self._client.user.delete(user_id))
        except Exception:
            pass

    def close(self) -> None:
        self._delete_user(self._user_id)
        self._user_id = ""
        self._thread_id = ""
