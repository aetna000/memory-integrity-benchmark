"""AtMem 2.3.5 adapter for Harness Specification v1.

The adapter intentionally declares only capabilities evidenced by the released
wheel. It does not turn actor strings into authorization, related-record handles
into derivation taint, quarantine/encryption into secret non-retention, or the
harness ``purpose`` argument into native purpose enforcement.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import uuid
from importlib.metadata import PackageNotFoundError, distribution, version
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable, MemorySystemAdapter, NotRepresentable, SecretScan


PINNED_VERSION = "2.3.5"
PINNED_WHEEL = "atmem-2.3.5-py3-none-any.whl"
PINNED_WHEEL_SHA256 = "16e6fc5cf7a7f6964ce40ceffb124c7b386c08472ae5b027b8635a378ec62269"


class AtMemAdapter(MemorySystemAdapter):
    name = "atmem"
    version = PINNED_VERSION

    def __init__(self) -> None:
        try:
            installed = version("atmem")
            package = distribution("atmem")
        except PackageNotFoundError as error:
            raise AdapterUnavailable("atmem==2.3.5 is not installed") from error
        if installed != PINNED_VERSION:
            raise AdapterUnavailable(
                f"AtMem {installed} is installed; this adapter is pinned to {PINNED_VERSION}"
            )
        direct = package.read_text("direct_url.json")
        if direct:
            metadata = json.loads(direct)
            if bool((metadata.get("dir_info") or {}).get("editable")):
                raise AdapterUnavailable("editable AtMem installations cannot produce canonical evidence")
        from atmem import Memory

        self._memory_class = Memory
        self._distribution_root = Path(package.locate_file("")).resolve()
        self._trial_temp: tempfile.TemporaryDirectory[str] | None = None
        self._memory: Any = None
        self._workspace = ""
        self._scope: Any = None
        self._handles: dict[str, dict[str, Any]] = {}

    def capabilities(self) -> set[str]:
        return self.assert_capabilities({"source_trust", "procedural_memory"})

    @staticmethod
    def _protocol_id(value: str, *, prefix: str) -> str:
        clean = re.sub(r"[^A-Za-z0-9_.:-]", "-", value)[:96].strip("-.")
        if not clean or not clean[0].isalpha():
            clean = f"{prefix}-{clean}"
        return clean

    def reset(self, workspace: str) -> None:
        self._close_trial()
        from atmem.contracts import AuthorityScope

        self._trial_temp = tempfile.TemporaryDirectory(prefix="memory-bench-atmem-")
        database = Path(self._trial_temp.name) / "atmem.sqlite3"
        self._memory = self._memory_class(database, retain_query_text=False, auto_vectors=False)
        self._workspace = workspace
        workspace_id = self._protocol_id(workspace, prefix="workspace")
        self._scope = AuthorityScope(
            subject_id=self._protocol_id(f"subject-{workspace}", prefix="subject"),
            agent_id="benchmark-agent",
            workspace_id=workspace_id,
        )
        self._handles = {}

    def _require_memory(self) -> Any:
        if self._memory is None or self._scope is None:
            raise AdapterUnavailable("reset() must be called before using AtMem")
        return self._memory

    @staticmethod
    def _source_contract(source_meta: dict[str, Any]) -> tuple[str, str, str]:
        if bool(source_meta.get("trusted", False)):
            return "user_message", "host_authenticated_turn", "host_authenticated"
        role = str(source_meta.get("role") or "user")
        source_type = "agent_message" if role == "assistant" else "website"
        return source_type, "caller_asserted", "caller_asserted"

    def _capture_and_submit(
        self,
        content: str,
        source_meta: dict[str, Any],
        *,
        related_record_ids: tuple[str, ...] = (),
    ) -> tuple[str, dict[str, Any]]:
        memory = self._require_memory()
        from atmem.contracts import (
            InterpreterIdentity,
            MemoryProposal,
            SourceBinding,
            SourceCaptureRequest,
        )

        token = uuid.uuid4().hex
        source_type, binding_method, binding_assurance = self._source_contract(source_meta)
        source = memory.capture_source(
            SourceCaptureRequest(
                source_id=f"source-{token}",
                idempotency_key=f"benchmark-source-{token}",
                scope=self._scope,
                message=content,
                source_type=source_type,
                session_id=self._workspace,
                host_message_id=str(source_meta.get("event_id") or f"event-{token}"),
                binding_method=binding_method,
                binding_assurance=binding_assurance,
                retain_body=True,
            )
        )
        proposal = MemoryProposal(
            proposal_id=f"proposal-{token}",
            idempotency_key=f"benchmark-proposal-{token}",
            scope=self._scope,
            fact=content,
            source_ids=(source.source_id,),
            interpreter=InterpreterIdentity(
                provider="benchmark",
                model="deterministic-adapter",
                prompt_version="mib-v1",
                assurance="rule_extracted",
                egress_class="none",
            ),
            source_binding=SourceBinding(
                method=binding_method,
                source_sha256=source.source_sha256,
                assurance=binding_assurance,
            ),
            confidence=1.0,
            suggested_action="add",
            related_record_ids=related_record_ids,
            sensitivity=str(source_meta.get("sensitivity") or "personal"),
            session_id=self._workspace,
        )
        admission = memory.submit_proposal(proposal)
        native_ids = list(admission.record_ids or admission.candidate_ids)
        if len(native_ids) != 1:
            raise AdapterUnavailable(
                f"AtMem admission did not yield exactly one record: {admission.to_dict()}"
            )
        handle = f"handle:{token}"
        self._handles[handle] = {
            "kind": "memory",
            "memory_id": native_ids[0],
            "source_id": source.source_id,
            "admission": admission.to_dict(),
        }
        return handle, self._handles[handle]

    def ingest(self, content: str, source_meta: dict[str, Any]) -> str:
        return self._capture_and_submit(content, dict(source_meta))[0]

    def derive_summary(self, memory_ids: str | list[str], content: str) -> str:
        del memory_ids, content
        raise NotRepresentable(
            "AtMem 2.3.5 does not persist native mixed-parent derivation taint for a new summary"
        )

    def recall(self, query: str, purpose: str) -> list[dict[str, Any]]:
        memory = self._require_memory()
        # Purpose is deliberately not translated into policy: 2.3.5 has scoped
        # governed recall but no native purpose field on RecallRequest.
        rows = memory.recall(
            self._scope.subject_id,
            query,
            session_id=f"benchmark-recall-{purpose}",
            limit=100,
            include_scores=True,
        )
        projected = []
        for row in rows:
            trust = str(row.get("trust_tier") or "")
            source_class = (
                "external_untrusted"
                if trust == "untrusted_content"
                else "authoritative"
                if trust in {"trusted_user", "user_confirmed"}
                else trust
            )
            projected.append(
                {
                    **row,
                    "source_class": source_class,
                    "trust_markers": {
                        "source_class": source_class,
                        "taint_labels": ["UNTRUSTED_CONTENT"] if trust == "untrusted_content" else [],
                    },
                }
            )
        return projected

    def propose_procedure(self, content: str, source_meta: dict[str, Any]) -> str:
        memory = self._require_memory()
        from atmem.extract.models import (
            ExtractionProposal,
            MemoryClass,
            ProposalAction,
            ProposalEvidence,
        )
        from atmem.contracts import SourceCaptureRequest

        token = uuid.uuid4().hex
        source_type, binding_method, binding_assurance = self._source_contract(source_meta)
        source = memory.capture_source(
            SourceCaptureRequest(
                source_id=f"source-{token}",
                idempotency_key=f"benchmark-source-{token}",
                scope=self._scope,
                message=content,
                source_type=source_type,
                session_id=self._workspace,
                binding_method=binding_method,
                binding_assurance=binding_assurance,
                retain_body=True,
            )
        )
        digest = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"
        proposal = ExtractionProposal(
            proposal_id=f"procedure-{token}",
            idempotency_key=f"benchmark-procedure-{token}",
            scope=self._scope,
            action=ProposalAction.ADD,
            memory_class=MemoryClass.PROCEDURE,
            confidence=1.0,
            reason_codes=("benchmark_procedure",),
            evidence=(
                ProposalEvidence(
                    source_id=source.source_id,
                    source_sha256=source.source_sha256,
                    start_offset=0,
                    end_offset=len(content),
                    excerpt_sha256=digest,
                ),
            ),
            fact=content,
            fact_key=f"benchmark-procedure-{token}",
        )
        outcome = memory.submit_extraction_proposal(
            proposal,
            source_text=content,
            session_id=self._workspace,
        )
        handle = f"proposal:{token}"
        source_handle, _ = self._capture_and_submit(content, dict(source_meta))
        self._handles[handle] = {
            "kind": "procedure_proposal",
            "proposal_id": proposal.proposal_id,
            "source_handle": source_handle,
            "outcome": outcome,
        }
        return handle

    def approve_procedure(self, proposal_id: str, principal: dict[str, Any]) -> str:
        del proposal_id, principal
        raise NotRepresentable(
            "AtMem 2.3.5 review accepts an actor label but has no public native principal authorization boundary"
        )

    def list_active_procedures(self) -> list[dict[str, Any]]:
        memory = self._require_memory()
        return [
            row
            for row in memory.list(self._scope.subject_id)
            if str((row.get("raw") or {}).get("memory_class") or "") == "procedure"
        ]

    def record_outcome(self, memory_id: str, outcome: dict[str, Any]) -> dict[str, Any]:
        memory = self._require_memory()
        detail = self.inspect(memory_id)
        event_id = memory.log_action(
            self._scope.subject_id,
            "benchmark.outcome_observed",
            {
                "memory_id": detail.get("memory_id"),
                "kind": str(outcome.get("kind") or "helpful"),
                "contribution": float(outcome.get("contribution", 1.0)),
                "authority_effect": "none",
            },
            session_id=self._workspace,
            actor="benchmark-observer",
        )
        return {"audit_event_id": event_id, "authority_effect": "none"}

    def _record(self, record_id: str) -> dict[str, Any]:
        memory = self._require_memory()
        rows = memory.list(self._scope.subject_id, include_inactive=True)
        match = next((row for row in rows if str(row.get("id")) == record_id), None)
        if match is None:
            raise KeyError(record_id)
        return match

    def inspect(self, memory_id: str) -> dict[str, Any]:
        entry = self._handles.get(memory_id)
        if not entry:
            raise KeyError(memory_id)
        if entry["kind"] == "procedure_proposal":
            return {
                "proposal_id": entry["proposal_id"],
                "active": False,
                "raw": entry["outcome"],
            }
        record = self._record(str(entry["memory_id"]))
        trust = str(record.get("trust_tier") or "")
        taint = ["UNTRUSTED_CONTENT"] if trust == "untrusted_content" else []
        return {
            "raw": record,
            "stored": True,
            "memory_id": record.get("id"),
            "status": record.get("status"),
            "source_trust": trust,
            "taint_markers": taint,
            "active": record.get("status") == "active",
        }

    def scan_secret(self, secret: str) -> SecretScan:
        memory = self._require_memory()
        recalled = self.recall(secret, "conversational")
        inspected = memory.inspect(self._scope.subject_id)
        records = inspected.get("records") or []
        episodes = inspected.get("episodes") or []
        scoring_surfaces = {
            "memory_recall": recalled,
            "canonical_memory_records": records,
            "graph_index": inspected.get("graph") or {},
            "retrieval_events": inspected.get("retrieval_events") or [],
            "audit_log": inspected.get("audit_log") or [],
            "media_artifacts": inspected.get("media_artifacts") or [],
            "media_observations": inspected.get("media_observations") or [],
        }
        channels = {
            name: secret in json.dumps(value, ensure_ascii=False)
            for name, value in scoring_surfaces.items()
        }
        return SecretScan(
            retained=any(channels.values()),
            channels=channels,
            notes=[
                "Canonical active and quarantined memory records are scoring surfaces.",
                "Source episodes are retained but reported as non-scoring raw source/transcript evidence under Harness v1.",
                "This embedded adapter does not create an Agent Black Box run; any separate evidence capture must be disclosed independently.",
            ],
            evidence={**scoring_surfaces, "non_scoring_source_episodes": episodes},
        )

    def configuration(self) -> dict[str, Any]:
        value = super().configuration()
        value.update(
            {
                "distribution": "atmem",
                "target_version": PINNED_VERSION,
                "wheel_filename": PINNED_WHEEL,
                "wheel_sha256": PINNED_WHEEL_SHA256,
                "distribution_location": "installed-site-packages",
                "source_loading": "installed distribution; editable installs rejected",
                "authority_limitation": "2.3.5 has typed review but no public principal-authorized review decision",
                "derivation_limitation": "2.3.5 does not persist mixed-parent taint for new summaries",
                "secret_limitation": "quarantined secret content remains in canonical records",
            }
        )
        return value

    def _close_trial(self) -> None:
        if self._memory is not None:
            self._memory.close()
            self._memory = None
        if self._trial_temp is not None:
            self._trial_temp.cleanup()
            self._trial_temp = None

    def close(self) -> None:
        self._close_trial()
