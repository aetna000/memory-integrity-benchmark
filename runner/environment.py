"""Local credential loading without secret disclosure."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"
KNOWN_ENV_KEYS = (
    "MEM0_API_KEY",
    "ZEP_API_KEY",
    "LETTA_API_KEY",
    "LETTA_BASE_URL",
    "LETTA_MODEL",
    "LETTA_EMBEDDING",
)


def load_benchmark_environment(path: Path = ENV_PATH) -> bool:
    """Load the ignored local file without overriding explicit process values."""
    if not path.is_file():
        return False
    load_dotenv(dotenv_path=path, override=False)
    # Some SDKs turn an empty environment value into an invalid Authorization
    # header. Treat blank dotenv placeholders as genuinely absent.
    for key in KNOWN_ENV_KEYS:
        if key in os.environ and not os.environ[key].strip():
            del os.environ[key]
    return True


def credential_status() -> dict[str, dict[str, Any]]:
    """Return presence booleans only; never return credential values."""
    mem0 = bool((os.environ.get("MEM0_API_KEY") or "").strip())
    zep = bool((os.environ.get("ZEP_API_KEY") or "").strip())
    letta_key = bool((os.environ.get("LETTA_API_KEY") or "").strip())
    letta_base = (os.environ.get("LETTA_BASE_URL") or "").strip()
    letta_url = bool(letta_base)
    letta_host = (urlparse(letta_base).hostname or "").lower()
    letta_cloud_requires_key = letta_host == "api.letta.com"
    letta_configured = letta_key or (letta_url and not letta_cloud_requires_key)
    return {
        "mem0": {
            "configured": mem0,
            "requirements": "MEM0_API_KEY",
            "credential_present": mem0,
        },
        "zep": {
            "configured": zep,
            "requirements": "ZEP_API_KEY",
            "credential_present": zep,
        },
        "letta": {
            "configured": letta_configured,
            "requirements": "LETTA_API_KEY for Letta Cloud, or a custom self-hosted LETTA_BASE_URL",
            "credential_present": letta_key,
            "custom_base_url_present": letta_url,
            "cloud_endpoint_requires_key": letta_cloud_requires_key,
        },
    }
