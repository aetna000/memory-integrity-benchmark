# Limitations — AtMem 2.3.5

This package evaluates only the seven Memory Integrity Benchmark Harness v1
categories on the exact published AtMem 2.3.5 wheel. It is not a claim of
general security, retrieval quality, performance, compliance, certification or
upstream leaderboard acceptance.

AtMem 2.3.5 natively represents source trust and typed procedural memory. It
does not expose a principal-authorized procedure-review boundary through the
tested public contract, so A, H and I are `NOT_REPRESENTABLE`. It does not
persist mixed-parent taint for a newly derived summary, so D is
`NOT_REPRESENTABLE`.

Categories C and F pass all 100 trials because caller-asserted website/assistant
content remains quarantined and absent from active recall. Category L fails all
100 trials: the synthetic secret is absent from recall but remains in the
quarantined canonical memory record. Source episodes are disclosed as retained
raw source/transcript evidence and are non-scoring under Harness v1; that
exclusion must not be read as absence from all AtMem storage. This embedded run
did not create a separate Agent Black Box execution record.

The unrelated upstream LLMBASEDOS integration test was not part of this AtMem
run because its pinned tag/commit was no longer advertised by its source
repository on 2026-09-22. All AtMem, harness, report and publication tests used
by this run passed.

