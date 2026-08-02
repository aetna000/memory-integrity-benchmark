# Zep capability review

Scope: Zep Cloud v3 as exercised by `zep-cloud==3.25.0`. Verdicts concern the
benchmark's epistemic/procedural enforcement semantics, not Zep's retrieval
quality or API-key access control. Reviewed 2026-08-01.

| Capability | Verdict | Documentation basis |
|---|---|---|
| `source_trust` | `STOCKABLE_SANS_SÉMANTIQUE` | Episodes accept source descriptions, roles and metadata. Projected metadata can drive filters and source-based ABAC, but that enforcement decides which API key may read an object—not whether its content has factual authority. [Adding Episodes](https://help.getzep.com/graphiti/core-concepts/adding-episodes), [Episode metadata projection](https://help.getzep.com/v3/episode-metadata-projection). |
| `derivation_tracking` | `STOCKABLE_SANS_SÉMANTIQUE` | Zep natively associates derived facts/entities/observations with source episodes and projects episode metadata. This is real provenance, but the documented consumers are retrieval, filtering, ABAC and deletion integrity; no trust/taint lattice constrains factual authority, so D remains non-representable in the benchmark sense. [Episode metadata projection](https://help.getzep.com/v3/episode-metadata-projection), [Episodes](https://help.getzep.com/episodes). |
| `procedural_memory` | `STOCKABLE_SANS_SÉMANTIQUE` | Messages and JSON/text episodes can store instructions verbatim, and relevant episodes may enter a context block, but Zep documents no protected active-procedure object or procedure executor. [Episodes](https://help.getzep.com/episodes), [Batch ingestion](https://help.getzep.com/adding-batch-data). |
| `authority_gating` | `ABSENTE` | Source-based ABAC gates read access to graph artifacts; it is not an approval event that promotes a proposed procedure. The documented thread/graph ingestion and search APIs expose no such promotion witness. [Episode metadata projection](https://help.getzep.com/v3/episode-metadata-projection), [Searching the Graph](https://help.getzep.com/searching-the-graph). |
| `purpose_scoped_recall` | `STOCKABLE_SANS_SÉMANTIQUE` | Graph search has native scopes (`nodes`, `edges`, `episodes`) and metadata filters, but no enforcement meaning for the benchmark purposes `factual_recall`, `conversational`, or `procedure_execution`; a caller could only encode them as metadata/filter policy. [Searching the Graph](https://help.getzep.com/searching-the-graph). |
| `secret_blocking` | `ABSENTE` | Zep documents that episodes store the supplied raw artifact verbatim and make it retrievable; no default secret-deny/redaction stage is documented for thread messages or episodes. [Episodes](https://help.getzep.com/episodes). |

Zep provenance is therefore acknowledged rather than erased: it is valuable
native lineage for retrieval, but it is not the security-taint enforcement that
category D asks the system to represent.
