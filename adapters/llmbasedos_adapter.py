"""LLMBASEDOS v0.4-rc1 adapter.

Native mapping:
- ``MemoryKernelStore.ingest`` stores observations with source/evidence class.
- ``parent_memory_ids`` and ``transformer_version`` are native derivation fields.
- ``MemoryKernelStore.query(..., purpose=...)`` supplies purpose-scoped recall.
- ``propose_procedure`` / ``approve_procedure`` implement approval witnesses.
- secret checks use the Kernel deny path and scan recall, embedding targets,
  audit output, and accessible SQLite/WAL/SHM bytes.

The adapter imports an archive of exact commit
``54a1dda4c896c2e7697c4849e1025d726bb29519``. It never imports the repository's
working tree.
"""

from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable, MemorySystemAdapter, SecretScan


PINNED_COMMIT = "54a1dda4c896c2e7697c4849e1025d726bb29519"
PINNED_TAG = "v0.4-rc1"


class LLMBASEDOSAdapter(MemorySystemAdapter):
    name = "llmbasedos"
    version = f"{PINNED_TAG}@{PINNED_COMMIT}"

    def __init__(self, repository: str | Path | None = None):
        configured_repository = (
            repository
            or os.environ.get("LLMBASEDOS_REPOSITORY")
            or "../llmbasedos"
        )
        self.repository = Path(configured_repository).expanduser().resolve()
        self._archive_root: Path | None = None
        self._archive_temp: tempfile.TemporaryDirectory[str] | None = None
        self._trial_temp: tempfile.TemporaryDirectory[str] | None = None
        self._store: Any = None
        self._workspace = ""
        self._sentinel = "benchmark-sentinel"
        self._handles: dict[str, dict[str, Any]] = {}
        self._load_pinned_store()

    def _git(self, *args: str) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(self.repository), *args],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise AdapterUnavailable(f"cannot inspect pinned LLMBASEDOS source: {error}") from error
        return result.stdout.strip()

    def _load_pinned_store(self) -> None:
        resolved = self._git("rev-parse", f"{PINNED_TAG}^{{commit}}")
        if resolved != PINNED_COMMIT:
            raise AdapterUnavailable(
                f"{PINNED_TAG} resolves to {resolved}, expected {PINNED_COMMIT}"
            )
        self._archive_temp = tempfile.TemporaryDirectory(prefix="memory-bench-llmbasedos-")
        self._archive_root = Path(self._archive_temp.name)
        archive = subprocess.run(
            ["git", "-C", str(self.repository), "archive", "--format=tar", PINNED_COMMIT],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        extract = subprocess.run(
            ["tar", "-xf", "-", "-C", str(self._archive_root)],
            input=archive,
            check=True,
        )
        if extract.returncode:
            raise AdapterUnavailable("failed to extract pinned LLMBASEDOS archive")
        sys.path.insert(0, str(self._archive_root))
        try:
            # A long-lived Python process may already have imported the dirty
            # working tree. Remove that namespace before importing the archive.
            for name in list(sys.modules):
                if name == "llmbasedos_src" or name.startswith("llmbasedos_src."):
                    del sys.modules[name]
            module = importlib.import_module("llmbasedos_src.arcs.memory_kernel.store")
            module_path = Path(module.__file__ or "").resolve()
            if not module_path.is_relative_to(self._archive_root.resolve()):
                raise AdapterUnavailable(
                    f"pinned module resolved outside archive: {module_path}"
                )
            self._store_class = module.MemoryKernelStore
        except Exception as error:
            raise AdapterUnavailable(f"cannot import pinned Memory Kernel: {error}") from error

    def capabilities(self) -> set[str]:
        return self.assert_capabilities(
            {
                "source_trust",
                "derivation_tracking",
                "procedural_memory",
                "authority_gating",
                "purpose_scoped_recall",
                "secret_blocking",
            }
        )

    def reset(self, workspace: str) -> None:
        if self._trial_temp:
            self._trial_temp.cleanup()
        self._trial_temp = tempfile.TemporaryDirectory(prefix="memory-bench-trial-")
        database = Path(self._trial_temp.name) / "memory.sqlite3"
        self._store = self._store_class(database, integrity_mode="enforce")
        self._workspace = workspace
        self._handles = {}

    def _idempotency(self, label: str) -> str:
        return f"harness:{label}:{uuid.uuid4().hex}"

    @staticmethod
    def _source_fields(source_meta: dict[str, Any]) -> tuple[str, str, str, str]:
        role = str(source_meta.get("role") or "user")
        trusted = bool(source_meta.get("trusted", False))
        if trusted:
            return "authoritative", "human_confirmed", "user_explicit", "knowledge.confirmed"
        if role == "assistant":
            return "agent_generated", "agent_output", "system_observation", "agent.output"
        return "external_untrusted", "observed", "system_observation", "observation.chat"

    def ingest(self, content: str, source_meta: dict[str, Any]) -> str:
        if self._store is None:
            raise AdapterUnavailable("reset() must be called before ingest()")
        source_class, evidence, source_kind, category = self._source_fields(source_meta)
        memory_type = str(source_meta.get("memory_type") or "episodic")
        value: dict[str, Any] = {
            "kind": str(source_meta.get("kind") or "benchmark.observation"),
            "text": content,
        }
        if isinstance(source_meta.get("value"), dict):
            value.update(source_meta["value"])
        result = self._store.ingest(
            self._workspace,
            self._sentinel,
            {
                "memory_type": memory_type,
                "category": str(source_meta.get("category") or category),
                "summary": content,
                "value": value,
                "source": {
                    "kind": source_kind,
                    "event_id": str(source_meta.get("event_id") or uuid.uuid4().hex),
                    "user_id": str(source_meta.get("principal") or "unknown"),
                    "channel": str(source_meta.get("channel") or "benchmark"),
                },
                "evidence_class": evidence,
                "source_class": source_class,
                "sensitivity": str(source_meta.get("sensitivity") or "public"),
            },
            idempotency_key=self._idempotency("ingest"),
            principal_id=str(source_meta.get("principal") or "unknown"),
        )
        handle = f"handle:{uuid.uuid4().hex}"
        self._handles[handle] = {"kind": "ingest", "result": result}
        return handle

    def _native_memory(self, handle: str) -> dict[str, Any]:
        entry = self._handles.get(handle)
        if not entry:
            raise KeyError(handle)
        result = entry.get("result") or {}
        memory = result.get("memory") or entry.get("memory")
        if not isinstance(memory, dict):
            raise KeyError(f"{handle} has no stored memory")
        return memory

    def derive_summary(self, memory_ids: str | list[str], content: str) -> str:
        parents = [memory_ids] if isinstance(memory_ids, str) else list(memory_ids)
        native_parents = [self._native_memory(item)["memory_id"] for item in parents]
        result = self._store.ingest(
            self._workspace,
            self._sentinel,
            {
                "memory_type": "semantic",
                "category": "knowledge.summary",
                "summary": content,
                "value": {"kind": "benchmark.summary", "text": content},
                "source": {"kind": "inference", "event_id": uuid.uuid4().hex},
                "evidence_class": "derived",
                "source_class": "agent_generated",
                "parent_memory_ids": native_parents,
                "transformer_version": "memory-integrity-benchmark-v1",
                "sensitivity": "public",
            },
            idempotency_key=self._idempotency("derive"),
        )
        handle = f"handle:{uuid.uuid4().hex}"
        self._handles[handle] = {"kind": "derivation", "result": result}
        return handle

    def recall(self, query: str, purpose: str) -> list[dict[str, Any]]:
        purpose_map = {
            "factual_recall": "factual_recall",
            "conversational": "conversational_continuity",
            "procedure_execution": "procedure_execution",
        }
        rows = self._store.query(
            self._workspace,
            self._sentinel,
            query,
            purpose=purpose_map[purpose],
            include_agent_output=True,
            include_value=True,
            authority_scopes=["procedure"] if purpose == "procedure_execution" else [],
        )
        return [dict(item) for item in rows]

    def list_active_procedures(self) -> list[dict[str, Any]]:
        return self.recall("procedure policy instruction publication invoice sponsor", "procedure_execution")

    def propose_procedure(self, content: str, source_meta: dict[str, Any]) -> str:
        source_meta = dict(source_meta)
        source_meta.setdefault("memory_type", "episodic")
        handle = self.ingest(content, source_meta)
        result = self._handles[handle]["result"]
        proposal = result.get("procedure_proposal") or {}
        if not proposal.get("proposal_id"):
            memory = self._native_memory(handle)
            proposal = self._store.propose_procedure(
                self._workspace,
                self._sentinel,
                {"summary": content, "value": {"text": content}},
                [memory["memory_id"]],
                principal_id=str(source_meta.get("principal") or "unknown"),
                idempotency_key=self._idempotency("proposal"),
            )
        proposal_handle = f"proposal:{uuid.uuid4().hex}"
        self._handles[proposal_handle] = {
            "kind": "proposal",
            "proposal": proposal,
            "source_handle": handle,
        }
        return proposal_handle

    def approve_procedure(self, proposal_id: str, principal: dict[str, Any]) -> str:
        entry = self._handles.get(proposal_id)
        if not entry or entry.get("kind") != "proposal":
            raise KeyError(proposal_id)
        proposal = entry["proposal"]
        content = dict(principal.get("approved_content") or {})
        content.setdefault("summary", str(proposal.get("requested_content", {}).get("summary") or "Approved procedure"))
        content.setdefault("value", {"approved": True})
        content.setdefault("key", f"benchmark.procedure.{uuid.uuid4().hex[:12]}")
        result = self._store.approve_procedure(
            self._workspace,
            proposal["proposal_id"],
            principal_id=str(principal.get("id") or "unknown"),
            authority_scopes=list(principal.get("scopes") or []),
            reason=str(principal.get("reason") or "Benchmark approval"),
            idempotency_key=self._idempotency("approval"),
            approved_content=content,
            approval_expires_at=principal.get("expires_at"),
        )
        handle = f"approval:{uuid.uuid4().hex}"
        self._handles[handle] = {"kind": "approval", "result": result}
        return handle

    def record_outcome(self, memory_id: str, outcome: dict[str, Any]) -> dict[str, Any]:
        memory = self._native_memory(memory_id)
        result = self._store.record_feedback(
            self._workspace,
            memory["memory_id"],
            str(outcome.get("kind") or "helpful"),
            self._idempotency("outcome"),
            contribution=float(outcome.get("contribution", 1.0)),
            outcome_id=str(outcome.get("outcome_id") or uuid.uuid4().hex),
        )
        self._handles[memory_id]["result"] = {"memory": result}
        return dict(result)

    def inspect(self, memory_id: str) -> dict[str, Any]:
        entry = self._handles.get(memory_id)
        if not entry:
            raise KeyError(memory_id)
        if entry.get("kind") == "approval":
            result = entry.get("result") or {}
            return {
                "raw": result,
                "approval_status": result.get("status"),
                "approval_event_id": result.get("approval_event_id"),
                "active": result.get("status") == "approved",
                "memory_id": (result.get("memory") or {}).get("memory_id"),
            }
        if entry.get("kind") == "proposal":
            return {"raw": entry["proposal"], **entry["proposal"]}
        result = entry.get("result") or {}
        if result.get("status") == "blocked":
            return {
                "raw": result,
                "stored": False,
                "status": result.get("status"),
                "taint_markers": list(result.get("reason_codes") or []),
            }
        memory = self._native_memory(memory_id)
        return {
            "raw": memory,
            "stored": True,
            "memory_id": memory.get("memory_id"),
            "source_trust": memory.get("source_class"),
            "taint_markers": list(memory.get("taint_labels") or []),
            "parent_memory_ids": list(memory.get("parent_memory_ids") or []),
            "authority": {
                "protected": bool(memory.get("protected")),
                "approval_event_id": memory.get("approval_event_id"),
                "object_kind": memory.get("object_kind"),
            },
            "seen_count": int((memory.get("metrics") or {}).get("seen_count") or 0),
            "utility_score": float((memory.get("metrics") or {}).get("utility_score") or 0.0),
        }

    def scan_secret(self, secret: str) -> SecretScan:
        recalled = self.recall(secret, "conversational")
        targets = self._store.list_embedding_targets(
            self._workspace, self._sentinel, "benchmark-secret-probe"
        )
        audits = self._store.list_audit_events(
            self._workspace, event_types=["secret_ingestion_blocked"]
        )
        channels = {
            "memory_recall": secret in json.dumps(recalled, ensure_ascii=False),
            "embedding_targets": secret in json.dumps(targets, ensure_ascii=False),
            "audit_events": secret in json.dumps(audits, ensure_ascii=False),
            "local_storage_files": False,
        }
        if self._store.path:
            needle = secret.encode("utf-8")
            for candidate in (
                Path(self._store.path),
                Path(f"{self._store.path}-wal"),
                Path(f"{self._store.path}-shm"),
            ):
                if candidate.exists() and needle in candidate.read_bytes():
                    channels["local_storage_files"] = True
        return SecretScan(
            retained=any(channels.values()),
            channels=channels,
            notes=["Scanned every target surface exposed by the pinned local adapter."],
        )

    def configuration(self) -> dict[str, Any]:
        data = super().configuration()
        data.update(
            {
                "target_commit": PINNED_COMMIT,
                "target_tag": PINNED_TAG,
                "integrity_mode": "enforce",
                "source_loading": "git archive of target commit; working tree excluded",
            }
        )
        return data

    def close(self) -> None:
        if self._trial_temp:
            self._trial_temp.cleanup()
            self._trial_temp = None
        if self._archive_root and str(self._archive_root) in sys.path:
            sys.path.remove(str(self._archive_root))
        if self._archive_temp:
            self._archive_temp.cleanup()
            self._archive_temp = None
