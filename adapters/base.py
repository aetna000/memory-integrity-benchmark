"""Adapter contract and shared result types.

Adapters expose native concepts only. Correlation metadata used by the harness is
never interpreted as a trust, taint, or authority signal unless the target system
itself gives that field security semantics.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import time
from typing import Any, ClassVar


CAPABILITIES = frozenset(
    {
        "source_trust",
        "derivation_tracking",
        "procedural_memory",
        "authority_gating",
        "purpose_scoped_recall",
        "secret_blocking",
    }
)


class BenchmarkAdapterError(RuntimeError):
    """Base class for adapter errors that must never be counted as a failure."""


class NotRepresentable(BenchmarkAdapterError):
    """The target system has no native concept for the requested operation."""


class NotSupported(BenchmarkAdapterError):
    """The concept exists, but the public API cannot perform or inspect it."""


class AdapterUnavailable(BenchmarkAdapterError):
    """The SDK, credentials, service, or pinned source tree is unavailable."""


RETRYABLE_STATUS_CODES = frozenset({408, 425, 429, 500, 502, 503, 504})


def api_status_code(error: BaseException) -> int | None:
    direct = getattr(error, "status_code", None)
    if isinstance(direct, int):
        return direct
    response = getattr(error, "response", None)
    response_code = getattr(response, "status_code", None)
    return response_code if isinstance(response_code, int) else None


def retryable_api_error(error: BaseException) -> bool:
    status = api_status_code(error)
    if status in RETRYABLE_STATUS_CODES or (status is not None and 500 <= status <= 599):
        return True
    name = type(error).__name__.lower()
    rendered = str(error).lower()
    return any(
        marker in name or marker in rendered
        for marker in ("timeout", "timed out", "connectionerror", "connecterror", "networkerror")
    )


def retry_after_seconds(error: BaseException) -> float | None:
    """Return a bounded numeric Retry-After delay exposed by an SDK error."""
    headers = getattr(error, "headers", None)
    if not isinstance(headers, dict):
        response = getattr(error, "response", None)
        headers = getattr(response, "headers", None)
    if not headers:
        return None
    value = next(
        (item for key, item in headers.items() if str(key).lower() == "retry-after"),
        None,
    )
    try:
        return max(0.0, min(120.0, float(value)))
    except (TypeError, ValueError):
        return None


def call_with_retry(
    operation: Any,
    *,
    attempts: int = 5,
    base_delay_seconds: float = 1.0,
    extra_retryable: Any | None = None,
) -> Any:
    """Retry only transient transport/rate/server errors, then re-raise raw error."""
    if attempts < 1:
        raise ValueError("attempts must be positive")
    for attempt in range(1, attempts + 1):
        try:
            return operation()
        except Exception as error:
            retryable = retryable_api_error(error) or bool(
                extra_retryable and extra_retryable(error)
            )
            if not retryable or attempt == attempts:
                raise
            exponential_delay = min(8.0, base_delay_seconds * (2 ** (attempt - 1)))
            time.sleep(max(exponential_delay, retry_after_seconds(error) or 0.0))
    raise AssertionError("unreachable retry state")


@dataclass(frozen=True)
class SecretScan:
    retained: bool
    channels: dict[str, bool]
    notes: list[str]
    evidence: dict[str, Any] = field(default_factory=dict)


class MemorySystemAdapter(ABC):
    """Abstract native-memory interface used by attack definitions."""

    name: ClassVar[str]
    version: ClassVar[str]

    @abstractmethod
    def capabilities(self) -> set[str]:
        """Return only capabilities the target system natively represents."""

    @abstractmethod
    def reset(self, workspace: str) -> None:
        """Create or clear an isolated trial workspace."""

    @abstractmethod
    def ingest(self, content: str, source_meta: dict[str, Any]) -> str:
        """Store one observation and return an adapter-local memory handle."""

    @abstractmethod
    def derive_summary(self, memory_ids: str | list[str], content: str) -> str:
        """Create a native derivation from one or more stored memories."""

    @abstractmethod
    def recall(self, query: str, purpose: str) -> list[dict[str, Any]]:
        """Recall through the target's public API."""

    @abstractmethod
    def list_active_procedures(self) -> list[dict[str, Any]]:
        """Return natively active procedures."""

    @abstractmethod
    def propose_procedure(self, content: str, source_meta: dict[str, Any]) -> str:
        """Create a native procedure proposal."""

    @abstractmethod
    def approve_procedure(self, proposal_id: str, principal: dict[str, Any]) -> str:
        """Approve a proposal using native authority semantics."""

    @abstractmethod
    def inspect(self, memory_id: str) -> dict[str, Any]:
        """Return raw metadata exactly as the public/native system exposes it."""

    def record_outcome(self, memory_id: str, outcome: dict[str, Any]) -> dict[str, Any]:
        raise NotRepresentable(f"{self.name} has no native outcome-credit operation")

    def scan_secret(self, secret: str) -> SecretScan:
        """Scan every store surface exposed to the adapter."""
        recalled = self.recall(secret, "conversational")
        rendered = repr(recalled)
        return SecretScan(
            retained=secret in rendered,
            channels={"public_recall_api": secret in rendered},
            notes=["Only the public recall API is exposed to this adapter."],
            evidence={"public_recall_api": recalled},
        )

    def settle(self) -> None:
        """Wait for documented asynchronous ingestion, when required."""

    def close(self) -> None:
        """Release local resources."""

    def configuration(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "capabilities": sorted(self.capabilities()),
        }

    @staticmethod
    def assert_capabilities(values: set[str]) -> set[str]:
        unknown = values - CAPABILITIES
        if unknown:
            raise ValueError(f"unknown capabilities: {sorted(unknown)}")
        return values
