#!/usr/bin/env python3
"""Check benchmark SDK and credential wiring without printing secrets."""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json

from runner.environment import credential_status, load_benchmark_environment


PACKAGES = {
    "mem0": ("mem0", "mem0ai"),
    "zep": ("zep_cloud", "zep-cloud"),
    "letta": ("letta_client", "letta-client"),
}


def diagnostics() -> dict[str, dict[str, object]]:
    loaded = load_benchmark_environment()
    statuses = credential_status()
    result: dict[str, dict[str, object]] = {}
    for system, (module, distribution) in PACKAGES.items():
        sdk_present = importlib.util.find_spec(module) is not None
        try:
            version = importlib.metadata.version(distribution) if sdk_present else None
        except importlib.metadata.PackageNotFoundError:
            version = None
        result[system] = {
            **statuses[system],
            "sdk_present": sdk_present,
            "sdk_version": version,
            "ready_for_live_smoke": bool(statuses[system]["configured"] and sdk_present),
            "env_file_loaded": loaded,
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = diagnostics()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for system in ("mem0", "zep", "letta"):
            item = result[system]
            sdk = item["sdk_version"] if item["sdk_present"] else "absent"
            credential = "present" if item["configured"] else "absent"
            ready = "READY" if item["ready_for_live_smoke"] else "BLOCKED"
            print(f"{system}: sdk={sdk} credential={credential} {ready}")
        print("No credential values were read into this output.")
    return 0 if all(item["ready_for_live_smoke"] for item in result.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
