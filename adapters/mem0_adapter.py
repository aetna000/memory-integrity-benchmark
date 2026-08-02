"""Mem0 Platform adapter using documented default memory operations.

Native mapping:
- ``MemoryClient.add(messages=..., user_id=...)`` ingests role-bearing messages
  with the documented default ``infer=True``.
- ``MemoryClient.search(query=..., filters={"user_id": ...})`` is recall.
- ``MemoryClient.get`` exposes raw memory metadata for inspection.

The benchmark writes correlation fields into Mem0 metadata but never interprets
them as native trust or taint. Mem0's public memory model does not expose the
benchmark's procedural-authority, derivation-taint, purpose-scope, or secret-deny
concepts, so those capabilities are deliberately undeclared.
"""

from __future__ import annotations

import importlib.metadata
import os
import uuid
from typing import Any

from .base import AdapterUnavailable, MemorySystemAdapter, NotRepresentable, SecretScan, call_with_retry


class Mem0Adapter(MemorySystemAdapter):
    name = "mem0"
    version = "unresolved"

    def __init__(self) -> None:
        try:
            from mem0 import MemoryClient
        except ImportError as error:
            raise AdapterUnavailable("install optional dependency 'mem0ai'") from error
        if not os.environ.get("MEM0_API_KEY"):
            raise AdapterUnavailable("MEM0_API_KEY is not configured")
        try:
            self.version = importlib.metadata.version("mem0ai")
        except importlib.metadata.PackageNotFoundError:
            self.version = "unknown"
        self._client = MemoryClient(api_key=os.environ["MEM0_API_KEY"])
        self._workspace = ""
        self._handles: dict[str, Any] = {}

    def capabilities(self) -> set[str]:
        return set()

    def reset(self, workspace: str) -> None:
        self._delete_workspace(self._workspace)
        self._workspace = f"memory-benchmark:{workspace}"
        self._handles = {}
        self._delete_workspace(self._workspace)

    def _delete_workspace(self, workspace: str) -> None:
        if not workspace:
            return
        try:
            call_with_retry(lambda: self._client.delete_all(user_id=workspace))
        except Exception:
            # A brand-new, seed-derived user id is already isolated. Some plans
            # reject delete_all before any memories exist.
            pass

    def ingest(self, content: str, source_meta: dict[str, Any]) -> str:
        role = str(source_meta.get("role") or "user")
        metadata = {
            "benchmark_event_id": str(source_meta.get("event_id") or uuid.uuid4().hex),
            "benchmark_channel": str(source_meta.get("channel") or "benchmark"),
        }
        response = call_with_retry(
            lambda: self._client.add(
                messages=[{"role": role, "content": content}],
                user_id=self._workspace,
                metadata=metadata,
                infer=True,
            )
        )
        handle = f"mem0:{uuid.uuid4().hex}"
        self._handles[handle] = response
        return handle

    def derive_summary(self, memory_ids: str | list[str], content: str) -> str:
        raise NotRepresentable("Mem0 exposes no native security-taint derivation relation")

    def recall(self, query: str, purpose: str) -> list[dict[str, Any]]:
        response = call_with_retry(
            lambda: self._client.search(query=query, filters={"user_id": self._workspace})
        )
        if isinstance(response, dict):
            rows = response.get("results") or response.get("memories") or []
        else:
            rows = response or []
        return [dict(item) if isinstance(item, dict) else {"raw": repr(item)} for item in rows]

    def list_active_procedures(self) -> list[dict[str, Any]]:
        raise NotRepresentable("Mem0 has no native protected-procedure object")

    def propose_procedure(self, content: str, source_meta: dict[str, Any]) -> str:
        raise NotRepresentable("Mem0 has no native procedure proposal")

    def approve_procedure(self, proposal_id: str, principal: dict[str, Any]) -> str:
        raise NotRepresentable("Mem0 has no native procedural authority witness")

    def inspect(self, memory_id: str) -> dict[str, Any]:
        raw = self._handles.get(memory_id)
        if raw is None:
            raise KeyError(memory_id)
        ids: list[str] = []
        rows = raw.get("results", []) if isinstance(raw, dict) else raw if isinstance(raw, list) else []
        for row in rows:
            if isinstance(row, dict) and row.get("id"):
                ids.append(str(row["id"]))
        details = []
        for item_id in ids:
            try:
                details.append(call_with_retry(lambda item_id=item_id: self._client.get(item_id)))
            except Exception as error:
                details.append({"id": item_id, "inspection_error": repr(error)})
        return {"raw_add_response": raw, "raw_memories": details, "native_memory_ids": ids}

    def scan_secret(self, secret: str) -> SecretScan:
        recalled = self.recall(secret, "conversational")
        all_memories = call_with_retry(
            lambda: self._client.get_all(filters={"user_id": self._workspace})
        )
        add_responses = list(self._handles.values())
        channels = {
            "search": secret in repr(recalled),
            "get_all": secret in repr(all_memories),
        }
        return SecretScan(
            retained=any(channels.values()),
            channels=channels,
            notes=[
                "Exact synthetic-secret scan across search and persistent get_all results.",
                "The immediate add response is non-scoring ingestion evidence.",
            ],
            evidence={
                "search": recalled,
                "get_all": all_memories,
                "non_scoring_context": {"add_responses": add_responses},
            },
        )

    def configuration(self) -> dict[str, Any]:
        data = super().configuration()
        data.update(
            {
                "sdk": "mem0ai",
                "api": "MemoryClient",
                "infer": True,
                "non_default_configuration": {},
                "credential_present": bool(os.environ.get("MEM0_API_KEY")),
                "retry_policy": {"attempts": 5, "delays_seconds": [1, 2, 4, 8]},
                "mapping_note": "benchmark metadata is correlation-only, not a trust marker",
            }
        )
        return data

    def close(self) -> None:
        self._delete_workspace(self._workspace)
        self._workspace = ""
