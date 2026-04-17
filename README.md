# GERA Framework

**Governed Enterprise Reconciliation Architecture**

[![arXiv](https://img.shields.io/badge/arXiv-2604.15108-b31b1b.svg)](https://arxiv.org/abs/2604.15108)
[![DOI](https://img.shields.io/badge/DOI-10.48550%2FarXiv.2604.15108-blue.svg)](https://doi.org/10.48550/arXiv.2604.15108)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

**Companion code / reference implementation** for the arXiv preprint *"Data Engineering Patterns for Cross-System Reconciliation in Regulated Enterprises: Architecture, Anomaly Detection, and Governance"* ([arXiv:2604.15108](https://arxiv.org/abs/2604.15108)).

This repository makes the four-layer architecture described in the paper concrete enough to read, run, and adapt — it is **not a drop-in production library**. Each layer is implemented as a small, dependency-light Python module with BigQuery and Athena/Glue SQL DDL and Terraform modules for AWS Lake Formation and GCP BigQuery row-level security. The goal is to show *how the paper's patterns fit together*, not to replace an enterprise data platform.

**Cloud-agnostic** by design — matching SQL DDL and Terraform modules are provided for both **AWS** (Lake Formation + Glue + S3) and **GCP** (BigQuery + Cloud IAM).

```
┌─────────────────────────────────────────────────────────────┐
│                    GERA Framework                           │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: NIST CSF 2.0 Security Controls                    │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────────┐  │
│  │ ABAC / RLS  │ │ Policy-as-   │ │ Compliance           │  │
│  │ (Terraform) │ │ Code (TF)    │ │ Mapping              │  │
│  └─────────────┘ └──────────────┘ └──────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Governed Semantic Standardization                 │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────────┐  │
│  │ Semantic    │ │ Audit Logger │ │ Hash-Chain           │  │
│  │ Registry    │ │ (Append-Only)│ │ Verification         │  │
│  └─────────────┘ └──────────────┘ └──────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Multi-Layer Statistical Validation                │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────────┐  │
│  │ Z-Score Gate│ │ Recon Checks │ │ Reasonableness       │  │
│  │ (2.5σ/4.0σ) │ │ (Count/Amt)  │ │ (Period Variance)    │  │
│  └─────────────┘ └──────────────┘ └──────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Deterministic Cross-System Reconciliation         │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────────┐  │
│  │ Key Matcher │ │ Exception    │ │ FIFO Queue           │  │
│  │ (Composite) │ │ Router       │ │ (SLA Tracking)       │  │
│  └─────────────┘ └──────────────┘ └──────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Why GERA?

Financial enterprises operating under SOX Section 404, PCAOB standards, and NIST CSF 2.0 need **auditable, repeatable reconciliation** across disparate systems. This repository demonstrates, in working code:

- **Deterministic matching** with composite keys, normalization, and conflict detection
- **Statistical anomaly detection** using (modified) Z-Score gates with configurable thresholds and a MAD option robust to baseline contamination
- **Governed semantic definitions** with versioned metric registries (copy-on-write / copy-on-read)
- **Tamper-evident audit logging** with SHA-256 hash chaining (7-year SOX retention), surviving retention purge via a chain anchor
- **Policy-as-Code security** via Terraform templates for **BigQuery RLS (GCP)** and **Lake Formation RLS (AWS)**, plus ABAC roles
- **Dual-cloud reference DDL** (`sql/bigquery/` and `sql/athena/`) aligned with the Terraform modules so row-level security policies attach to real, documented table schemas

## Paper ↔ Repository Mapping

The paper's four-layer architecture maps 1:1 onto the repository. Use this table when cross-referencing sections of the paper to code:

| Paper section / layer                                  | Repository module(s)                                  | Key classes / DDL                                   |
| ------------------------------------------------------ | ----------------------------------------------------- | --------------------------------------------------- |
| Layer 1 — Deterministic Cross-System Reconciliation    | `gera/reconciliation/`                                | `DeterministicMatcher`, `ExceptionRouter`, `GERAException` |
| Layer 2 — Multi-Layer Statistical Validation           | `gera/validation/`                                    | `ZScoreGate` (with MAD option), `ReconciliationCheck` |
| Layer 3 — Governed Semantic Standardization            | `gera/governance/`                                    | `SemanticRegistry`, `AuditLogger` (hash-chained)    |
| Layer 4 — NIST CSF 2.0 Security Controls               | `gera/nist/`, `terraform/`                            | `CSF2ControlMapper`, `terraform/bigquery_rls/`, `terraform/lakeformation_rls/` |
| Warehouse DDL for all four layers                      | `sql/bigquery/`, `sql/athena/`                        | `audit_log`, `semantic_registry`, `reconciliation_results`, `exceptions_queue`, `zscore_anomalies` (+ companion views) |

## Scope Boundaries

Consistent with §5 of the paper, the companion code is deliberately narrow. The following are out of scope for this repository and should not be interpreted as production-ready features:

- **Persistence.** The Python runtime is in-memory only. `AuditLogger`, `SemanticRegistry`, and `ExceptionRouter` do not ship with a persistent backend. The provided SQL DDL is the intended sink for long-term storage; wiring the Python layer to it is a deployment exercise.
- **Thresholds and SLAs are illustrative.** Default Z-Score thresholds (2.5σ / 4.0σ), exception SLAs (4 h / 24 h / 72 h), and retention (2,555 days for SOX) are reasonable starting points, not calibrated recommendations. Tune to your own data distribution and regulatory regime.
- **No streaming / CDC.** The framework is batch-oriented. A streaming adaptation (Kinesis, Pub/Sub, Kafka) is discussed in the paper but not implemented here.
- **No IAM / identity integration.** The ABAC and RLS Terraform modules presume your organization already federates identity (Cloud IAM / IAM Identity Center). They do not provision identity providers, groups, or user records.
- **Not certified.** The NIST CSF 2.0 control mapping in `gera/nist/` and the SOX / PCAOB alignment documented in the Regulatory Alignment section are engineering-level mappings. They are evidence that the patterns exist in the code, not a substitute for an independent audit or attestation.
- **No model-based anomaly detection.** Layer 2 is statistical (Z-Score / MAD). ML-based anomaly models (isolation forests, autoencoders, sequence models) are intentionally excluded — they raise explainability burdens that sit outside the paper's scope.
- **No entity resolution / fuzzy matching.** Layer 1 is key-based with configurable normalization. Probabilistic or ML-based entity resolution is a separate problem space.
- **Demo-grade benchmarks.** The performance numbers below come from a dual-core sandbox and are published as a reproducibility artifact, not as the paper's empirical claims (see §4 of the paper for the methodological discussion).

## Quick Start

```python
from gera.reconciliation import DeterministicMatcher
from gera.validation import ZScoreGate, ReconciliationCheck
from gera.governance import AuditLogger

# Match records across systems
matcher = DeterministicMatcher(key_fields=["txn_id"], value_fields=["amount"])
report = matcher.match(source_records, target_records)

# Statistical anomaly detection
gate = ZScoreGate(sigma_threshold=2.5, block_threshold=4.0)
result = gate.validate(amounts, historical_baseline)

# Tamper-evident audit logging
logger = AuditLogger(retention_days=2555)  # ~7 years for SOX
logger.log_gate_decision("reconciliation", result.gate_decision.value)
assert logger.verify_chain()  # Verify no tampering
```

## Modules

| Module | Layer | Description |
|--------|-------|-------------|
| `gera.reconciliation` | 1 | Deterministic key matching + FIFO exception routing |
| `gera.validation` | 2 | Z-Score anomaly detection + reconciliation checks |
| `gera.governance` | 3 | Semantic registry + append-only audit logging |
| `gera.nist` | 4 | NIST CSF 2.0 control mapping + compliance reports |
| `sql/bigquery/` | All | GCP BigQuery DDL for audit log, semantic registry, reconciliation results, exceptions queue, Z-score baseline |
| `sql/athena/` | All | AWS Athena / Glue DDL (same schema, AWS-native types and partitioning) |
| `terraform/bigquery_rls/` | 4 | GCP BigQuery row-level security + ABAC via Cloud IAM groups |
| `terraform/lakeformation_rls/` | 4 | AWS Lake Formation data cells filters + ABAC via IAM groups |
| `terraform/abac/`, `terraform/audit_logging/` | 4 | Shared ABAC roles and append-only audit sink templates |

## Regulatory Alignment

| Regulation | GERA Feature |
|-----------|-------------|
| SOX Section 404 | Hash-chained audit trail, 7-year retention |
| PCAOB AS 2201 | Deterministic reconciliation + statistical validation |
| NIST CSF 2.0 GV.OC | Sensitivity classification in SemanticRegistry |
| NIST CSF 2.0 PR.AA | Terraform ABAC + BigQuery Row-Level Security (GCP) + Lake Formation Data Cells Filters (AWS) |
| NIST CSF 2.0 DE.CM | Real-time gate decisions + exception routing |

## Installation

```bash
pip install -e .
```

## Running Tests

```bash
pytest tests/ -v
```

Tests are split into unit (`tests/test_reconciliation.py`, `tests/test_zscore_gate.py`)
and integration (`tests/test_integration.py`). Integration tests exercise all four
layers end-to-end under clean, mismatched, anomalous, and tampered scenarios.

## Examples

| Script | Scenario |
|--------|----------|
| `examples/basic_reconciliation.py` | Two-source reconciliation with all four layers |
| `examples/multi_source_reconciliation.py` | Three-way GL ⇄ Processor ⇄ Warehouse reconciliation with classified exceptions |

Run from the project root:

```bash
python examples/basic_reconciliation.py
python examples/multi_source_reconciliation.py
```

## Performance (supplemental repository artifact)

> **Not a paper result.** The numbers below are produced by this
> repository's benchmark harness on a sandbox VM as a reproducibility
> aid for readers who want to sanity-check the asymptotic behaviour of
> each layer. They are *not* the paper's empirical claims — the paper's
> quantitative discussion is in §4 and is based on the design, not on
> the sandbox timings.

```bash
python -m benchmarks.benchmark_reconciliation
python -m benchmarks.benchmark_reconciliation --scales 10000 100000 --json
```

Representative results on a dual-core x86_64 sandbox (Python 3.10, NumPy 2.2):

| Operation | n = 1,000 | n = 10,000 | Throughput |
|-----------|-----------|------------|------------|
| `DeterministicMatcher.match` | 2.1 ms | 29.2 ms | ≈ 340K rec/s |
| `ZScoreGate.validate` | 2.6 ms | 24.3 ms | ≈ 410K rec/s |
| `ReconciliationCheck.run_all` | 0.05 ms | 0.32 ms | ≈ 30M rec/s |
| `AuditLogger.log` (append) | 14 ms | 160 ms | ≈ 63K events/s |
| `AuditLogger.verify_chain` | 9 ms | 86 ms | ≈ 115K events/s |
| `ExceptionRouter.route` | 1.7 ms | 17.6 ms | ≈ 570K rec/s |
| `SemanticRegistry.register` | 2.1 ms | 21.3 ms | ≈ 470K rec/s |

The intent of the table is to demonstrate that every measured operation
is **linear in record count** — there are no hidden quadratic scans in
the hot path. Absolute numbers vary with hardware; the benchmark
harness is included so readers can re-run it against their own
environment.

## Publication

Qiu, Z. (2026). *Data Engineering Patterns for Cross-System Reconciliation in Regulated Enterprises: Architecture, Anomaly Detection, and Governance.* arXiv:2604.15108 [cs.DB; cs.CY]. DOI: [10.48550/arXiv.2604.15108](https://doi.org/10.48550/arXiv.2604.15108). <https://arxiv.org/abs/2604.15108>

Submitted 16 April 2026. 13 pages, 3 figures, 1 table. ACM classes: H.2.7, H.2.8, K.6.5.

## Citation

If you use this software or reference this architecture in academic work, please cite the paper:

```bibtex
@article{qiu2026gera,
  title   = {Data Engineering Patterns for Cross-System Reconciliation in Regulated Enterprises:
             Architecture, Anomaly Detection, and Governance},
  author  = {Qiu, Zhijun},
  journal = {arXiv preprint arXiv:2604.15108},
  year    = {2026},
  month   = apr,
  doi     = {10.48550/arXiv.2604.15108},
  url     = {https://arxiv.org/abs/2604.15108},
  archivePrefix = {arXiv},
  eprint  = {2604.15108},
  primaryClass  = {cs.DB}
}
```

A machine-readable [`CITATION.cff`](CITATION.cff) is also provided; GitHub will surface it automatically via the **"Cite this repository"** button in the sidebar.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Author

**Zhijun Qiu** — [GitHub](https://github.com/andersonqiu)
