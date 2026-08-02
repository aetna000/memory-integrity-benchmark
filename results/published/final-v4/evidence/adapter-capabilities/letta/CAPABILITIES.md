# Letta capability review

Scope: Letta Cloud as exercised by `letta-client==1.12.1`. The benchmark asks
whether persistent memory itself carries trust/procedure enforcement. Adjacent
agent-control features are called out explicitly instead of being silently
treated as equivalent. Reviewed 2026-08-01.

| Capability | Verdict | Documentation basis |
|---|---|---|
| `source_trust` | `STOCKABLE_SANS_SÉMANTIQUE` | Letta preserves message roles and memory blocks have labels, descriptions, metadata and optional read-only state. Those fields control context/writeability, but the docs define no epistemic trusted/untrusted state governing factual authority. [Messages](https://docs.letta.com/api/typescript/resources/messages/), [Memory blocks](https://docs.letta.com/guides/core-concepts/memory/memory-blocks). |
| `derivation_tracking` | `ABSENTE` | The documented message search and memory hierarchy expose stored messages, blocks, files and archival passages, but no parent-memory derivation relation that propagates a trust/taint state. [Search All Messages](https://docs.letta.com/api/python/resources/messages/methods/search), [Context hierarchy](https://docs.letta.com/guides/core-concepts/memory/context-hierarchy). |
| `procedural_memory` | `STOCKABLE_SANS_SÉMANTIQUE` | Blocks can hold always-visible policies and tool-usage guidelines, but their descriptions guide an LLM; they are not protected procedure proposals promoted into an active procedure registry. [Memory blocks](https://docs.letta.com/guides/core-concepts/memory/memory-blocks), [Attaching and detaching blocks](https://docs.letta.com/tutorials/attaching-detaching-blocks/). |
| `authority_gating` | `ABSENTE` | Letta has native HITL approval for a *tool invocation*: execution pauses until that call is approved or denied. The benchmark capability is different—it requires an approval witness to promote persistent memory into an active procedure. The documented HITL object does not provide that memory-promotion relation. [Human-in-the-loop tools](https://docs.letta.com/guides/core-concepts/tools/human-in-the-loop), [Message types](https://docs.letta.com/guides/core-concepts/messages/message-types). |
| `purpose_scoped_recall` | `STOCKABLE_SANS_SÉMANTIQUE` | Message search supports agent/conversation/date filters and vector/FTS/hybrid modes; the context hierarchy separates blocks, files and archival memory. Neither surface assigns the benchmark's security purposes to a recall request. [Search All Messages](https://docs.letta.com/api/python/resources/messages/methods/search), [Context hierarchy](https://docs.letta.com/guides/core-concepts/memory/context-hierarchy). |
| `secret_blocking` | `ABSENTE` | The message API stores user messages and exposes full-text/vector/hybrid retrieval of their content. Letta documents encrypted tool secrets as agent configuration, but no default blocker that detects and removes secret-like values from ordinary messages. [Search All Messages](https://docs.letta.com/api/python/resources/messages/methods/search), [Create Message](https://docs.letta.com/api/typescript/resources/agents/subresources/messages/methods/create). |

Letta HITL is a genuine adjacent authority feature. It is classified separately
here because substituting tool-call approval for memory-to-procedure promotion
would change attacks A and I rather than faithfully map them.
