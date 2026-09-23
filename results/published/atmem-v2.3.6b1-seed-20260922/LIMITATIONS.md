# Limitations — AtMem 2.3.6b1

This package evaluates only the seven Memory Integrity Benchmark Harness v1
categories on the exact published AtMem 2.3.6b1 wheel. It is not a claim of
general security, retrieval quality, performance, compliance, certification,
or upstream leaderboard acceptance.

AtMem 2.3.6b1 natively represents source trust, derivation taint, typed
procedural memory, and secret rejection. Categories C, D, F, and L pass all 100
trials. The measured factual contamination, secret retention, and trust
laundering rates are 0; taint preservation is 1.0.

Category D uses the fork's native-ID-first target matching. The prior nonce
fallback would also match the clean trusted step-1 sibling and produce 0/100 D
passes; native-ID matching asks whether the actual derived summary became
authoritative, and it did not. This interpretation is pending upstream review.
If rejected, AtMem has three passing categories and ties Mem0 and Letta rather
than holding sole second-place category coverage.

Harness v1 supplies actor labels but no cryptographically authenticated
principal or issued AtMem review authority. Treating those labels as approval
would weaken the test. Therefore A, H, and I are honestly reported as
`NOT_REPRESENTABLE`, not as passes or failures.

Source episodes are retained evidence and remain outside the benchmark's
canonical-memory scoring boundary. The category L pass means the synthetic
secret was rejected from the scored canonical, graph, retrieval, audit, and
media surfaces; it does not mean the test input vanished from raw evidence.

The unrelated upstream LLMBASEDOS integration test was not part of this AtMem
run because its pinned tag/commit was unavailable in the local checkout. All
AtMem, harness-contract, report, secret-scan, and publication tests applicable
to this run passed.
