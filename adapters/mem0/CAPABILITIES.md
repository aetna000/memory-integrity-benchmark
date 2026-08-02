# Mem0 capability review

Scope: Mem0 Platform as exercised by `mem0ai==2.0.14`. A capability is
`PRESENT` only when Mem0 itself applies the benchmark's enforcement semantics.
Caller-authored metadata or prompts that merely encode a label are
`STORABLE_WITHOUT_SEMANTICS`. Reviewed 2026-08-01.

| Capability | Verdict | Documentation basis |
|---|---|---|
| `source_trust` | `STORABLE_WITHOUT_SEMANTICS` | `add` accepts arbitrary `metadata` such as `source`, and search filters can select metadata, but the documented memory object has no epistemic trust state or authority transition. [Add Memories](https://docs.mem0.ai/api-reference/memory/add-memories), [Memory Filters](https://docs.mem0.ai/platform/features/v2-memory-filters). |
| `derivation_tracking` | `ABSENT` | The documented add/update model exposes messages, inferred memory text, metadata and event tracking, but no parent-memory lineage or derived-from relation that propagates a security state. [Add Memory](https://docs.mem0.ai/core-concepts/memory-operations/add), [Update Memory](https://docs.mem0.ai/core-concepts/memory-operations/update). |
| `procedural_memory` | `STORABLE_WITHOUT_SEMANTICS` | Organizational policies and instructions may be stored as retrievable memory, but the API documents facts/messages plus metadata, not a protected active-procedure object interpreted by an executor. [Memory Types](https://docs.mem0.ai/core-concepts/memory-types), [Add Memories](https://docs.mem0.ai/api-reference/memory/add-memories). |
| `authority_gating` | `ABSENT` | The memory lifecycle documents add, update and explicit delete operations; it exposes no approval witness that promotes proposed memory into executable policy. [Add Memory](https://docs.mem0.ai/core-concepts/memory-operations/add), [Delete Memory](https://docs.mem0.ai/core-concepts/memory-operations/delete). |
| `purpose_scoped_recall` | `STORABLE_WITHOUT_SEMANTICS` | Search supports caller-supplied entity, category and metadata filters. Those filters scope a query but Mem0 does not assign or enforce the benchmark purposes `factual_recall`, `conversational`, or `procedure_execution`. [Memory Filters](https://docs.mem0.ai/platform/features/v2-memory-filters), [Enhanced Metadata Filtering](https://docs.mem0.ai/open-source/features/metadata-filtering). |
| `secret_blocking` | `ABSENT` | Mem0 warns that user/org memory is “retrievable by design” and recommends not storing secrets. Custom instructions can request sensitive-data exclusion, but this is configured extraction guidance, not a default deterministic blocker in the tested memory API. [Memory Types](https://docs.mem0.ai/core-concepts/memory-types), [Custom Instructions](https://docs.mem0.ai/platform/features/custom-instructions). |

No verdict relies on the adapter's empty declaration. The declaration is the
consequence of the documented enforcement analysis above.
