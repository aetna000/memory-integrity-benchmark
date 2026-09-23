# AtMem 2.3.6b1 capability review

Target artifact: `atmem-2.3.6b1-py3-none-any.whl`, installed from the canonical
[PyPI wheel](https://files.pythonhosted.org/packages/ee/c6/a2da1fa9e11ca5b04d4c3e0a46287b849fd24229c15c2320711d6e4149f6/atmem-2.3.6b1-py3-none-any.whl)
with SHA-256
`0d68baba36f2ae301cfa9fb407963e650d814c97958ebc618dd390208b25d063`.
The adapter, frozen configuration, and environment lock require this exact
artifact before canonical evidence can be generated.

| Capability | Decision | Native evidence | Enforcement and limitation |
|---|---|---|---|
| `source_trust` | `PRESENT` | [`SourceCaptureRequest` and `Memory.submit_proposal`](https://github.com/aetna000/atmem/blob/v2.3.6b1/atmem/memory.py) persist source type, binding assurance, trust tier and lifecycle. | Authenticated user or agent sources may be active; caller-asserted sources are quarantined and excluded from recall. |
| `derivation_tracking` | `PRESENT` | [`MemoryProposal.related_record_ids`](https://github.com/aetna000/atmem/blob/v2.3.6b1/atmem/contracts/models.py) resolves canonical parents and persists their native taint/trust/lifecycle on the derived record. | Direct parents only. Any tainted, untrusted or inactive parent forces quarantine. |
| `procedural_memory` | `PRESENT` | [`MemoryClass.PROCEDURE`](https://github.com/aetna000/atmem/blob/v2.3.6b1/atmem/extract/models.py) persists on typed extraction proposals and approved records. | Procedures enter review; this does not imply that benchmark principal labels carry approval authority. |
| `authority_gating` | `NOT_REPRESENTABLE` | [`ReviewAuthorization`](https://github.com/aetna000/atmem/blob/v2.3.6b1/atmem/extract/review.py) is instance-issued, exact-scope and single-use. | Harness v1 passes only caller-controlled principal labels. The adapter cannot convert those labels into native authority without manufacturing trust, so category I remains not representable. |
| `purpose_scoped_recall` | `ABSENT` | [`RecallRequest`](https://github.com/aetna000/atmem/blob/v2.3.6b1/atmem/contracts/models.py) has authority scope but no purpose field. | The adapter ignores the harness purpose argument rather than inventing enforcement. |
| `secret_blocking` | `PRESENT` | [Both semantic proposal paths](https://github.com/aetna000/atmem/blob/v2.3.6b1/atmem/memory.py) reject secrets before canonical persistence and sanitize rejected proposal/audit surfaces. | Source episodes remain disclosed non-scoring transcript evidence under Harness v1; canonical, proposal, graph, recall and audit scoring surfaces retain only digests/placeholders. |

The adapter declares `source_trust`, `derivation_tracking`,
`procedural_memory`, and `secret_blocking`. Harness correlation handles,
principal dictionaries and adapter projections never grant authority or create
taint.
