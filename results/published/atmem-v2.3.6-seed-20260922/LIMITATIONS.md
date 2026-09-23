# Limitations — AtMem 2.3.6

This package evaluates only the seven Memory Integrity Benchmark Harness v1
categories on the exact published AtMem 2.3.6 wheel. It is not a claim of
general security, retrieval quality, performance, compliance, certification,
or upstream leaderboard acceptance.

AtMem 2.3.6 natively represents source trust, derivation taint, typed
procedural memory, and secret rejection. Categories C, D, F, and L pass all 100
trials. The measured factual contamination, secret retention, and trust
laundering rates are 0; taint preservation is 1.0.

This is not first place in the current comparison. LLMBASEDOS reports seven
passing categories, while AtMem reports four passes and three
`NOT_REPRESENTABLE` categories. Unlike AtMem's published wheel, the LLMBASEDOS
target is not publicly rerunnable from its source today, so that comparison is
inspectable but not independently reproducible. If the Category D
interpretation below is accepted upstream, AtMem has the second-highest passing
category count in the published table. If it is rejected, AtMem has three
passing categories and ties Mem0 and Letta on category coverage.

Category D uses the fork's native-ID-first target matching. The prior nonce
fallback would also match the clean trusted step-1 sibling and produce 0/100 D
passes; native-ID matching asks whether the actual derived summary became
authoritative, and it did not. This interpretation is pending upstream review.

Harness v1 supplies actor labels but no cryptographically authenticated
principal or issued AtMem review authority. Treating those labels as approval
would weaken the test. Therefore A, H, and I are honestly reported as
`NOT_REPRESENTABLE`, not as passes or failures.

Source episodes are retained evidence and remain outside the benchmark's
canonical-memory scoring boundary. The category L pass means the synthetic
secret was rejected from the scored canonical, graph, retrieval, audit, and
media surfaces; it does not mean the test input vanished from raw evidence.

The unrelated upstream LLMBASEDOS integration test was not part of this AtMem
run because its pinned source checkout was unavailable locally. All 41 AtMem,
harness-contract, report, secret-scan, and publication tests applicable to this
run passed.
