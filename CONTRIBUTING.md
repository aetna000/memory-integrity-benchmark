# Contributing

This benchmark is an evaluation contract. Changes must preserve reproducibility,
adapter honesty, raw evidence, and the distinction between a failed assertion and
a capability that the target system cannot represent.

## Development setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-all.lock
.venv/bin/python -m unittest discover -v
```

Never commit credentials, local `.env` files, generated workspaces, or unpublished
evidence packages. Use synthetic values in tests and examples.

## Disputing an adapter mapping

To dispute an adapter capability or result mapping, open a GitHub issue containing:

1. the system, adapter, capability, and attack category being disputed;
2. a precise public documentation reference, including the URL and relevant
   product or API version when available;
3. an explanation of the target system's native semantics and why the current
   mapping is inaccurate; and
4. a minimal reproduction or public API example when one exists.

Maintainers will review the cited native behavior against the benchmark's
capability definitions. If the mapping is corrected, the adapter documentation,
`CAPABILITIES.md`, implementation, and tests are updated together. Every affected
attack is then re-run with its recorded seed and full trial count. The replacement
evidence package must include raw trials, counter-derived metrics, a package diff,
and checksums. A result is never silently reclassified without the correction and
re-run being visible.

## Pull requests

Pull requests should be narrow, include tests for executable behavior, and explain
any effect on attack definitions, adapter mappings, result statuses, counters, or
evidence formats. Generated comparison tables must come from `raw-trials.jsonl`;
do not edit them by hand.
