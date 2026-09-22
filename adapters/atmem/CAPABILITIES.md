# AtMem 2.3.5 capability review

Target artifact: `atmem-2.3.5-py3-none-any.whl`, SHA-256
`16e6fc5cf7a7f6964ce40ceffb124c7b386c08472ae5b027b8635a378ec62269`.
The decisions below were falsified against a clean Python 3.11 installation.

| Capability | Decision | Native evidence | Enforcement and limitation |
|---|---|---|---|
| `source_trust` | `PRESENT` | [`SourceCaptureRequest`, `Memory.submit_proposal`](https://github.com/aetna000/atmem/blob/v2.3.5/atmem/memory.py) persist source type, binding assurance, trust tier and lifecycle. | Authenticated user sources can be active; website/agent/caller-asserted sources are quarantined and excluded from recall. |
| `derivation_tracking` | `STORABLE_WITHOUT_SEMANTICS` | [`MemoryProposal.related_record_ids`](https://github.com/aetna000/atmem/blob/v2.3.5/atmem/contracts/models.py) can name related records. | A new summary does not persist mixed-parent lineage/taint on its canonical record in 2.3.5; category D is not representable. |
| `procedural_memory` | `PRESENT` | [`MemoryClass.PROCEDURE`](https://github.com/aetna000/atmem/blob/v2.3.5/atmem/extract/models.py) persists on typed extraction proposals and approved records. | Typed proposals enter pending review. This does not imply that approval authority is present. |
| `authority_gating` | `ABSENT` | [`ReviewService.decide`](https://github.com/aetna000/atmem/blob/v2.3.5/atmem/extract/review.py) records an `actor` string. | The public 2.3.5 review method does not authenticate/authorize that actor; benchmark principal metadata must not be trusted. A/H/I are not representable. |
| `purpose_scoped_recall` | `ABSENT` | [`RecallRequest`](https://github.com/aetna000/atmem/blob/v2.3.5/atmem/contracts/models.py) has authority scope but no purpose field. | The adapter ignores the harness purpose argument rather than inventing enforcement. |
| `secret_blocking` | `ABSENT` | [`Memory.inspect`](https://github.com/aetna000/atmem/blob/v2.3.5/atmem/memory.py) exposes quarantined canonical records to an authorized inspector. | Secret text is withheld from active recall but retained in quarantined memory/source evidence, so category L evaluates empirically and is expected to fail. Encryption is not non-retention. |

The adapter therefore declares only `source_trust` and `procedural_memory`.
Harness correlation handles and adapter projections never grant authority.

