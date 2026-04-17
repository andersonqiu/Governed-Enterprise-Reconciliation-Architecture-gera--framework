-- GERA Framework — BigQuery DDL
-- Table: reconciliation_results
-- Layers: 1 (Deterministic Reconciliation) + 2 (Statistical Validation)
-- Python counterpart: gera.reconciliation.deterministic_matcher.MatchResult
--                     + gera.validation.zscore_gate.GateDecision
--
-- Per-record reconciliation outcome. Row-level security is attached to this
-- table by terraform/bigquery_rls/rls_policies.tf — keep the sensitivity_level
-- column and its value set (PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED) in
-- sync with the filter_predicate expressions there.
--
-- Schema matches google_bigquery_table.reconciliation_results in
-- terraform/bigquery_rls/main.tf — when you change one, change the other.
--
-- NIST CSF 2.0 controls: PR.AA-01, PR.DS-01, DE.CM-01.

CREATE TABLE IF NOT EXISTS `${project}.${dataset}.reconciliation_results` (
  record_id         STRING    NOT NULL OPTIONS(description="Unique identifier for the reconciliation record"),
  source_system     STRING    NOT NULL OPTIONS(description="Originating system (e.g. ERP, CRM, Billing)"),
  target_system     STRING    NOT NULL OPTIONS(description="Destination system reconciled against"),
  match_status      STRING    NOT NULL OPTIONS(description="Enum: MATCHED | UNMATCHED_SOURCE | UNMATCHED_TARGET | CONFLICT"),
  amount_difference FLOAT64            OPTIONS(description="Source minus target, in the reconciliation currency; NULL if non-monetary"),
  gate_decision     STRING    NOT NULL OPTIONS(description="Enum: PASS | FLAG | BLOCK — Z-score gate verdict for this record"),
  z_score           FLOAT64            OPTIONS(description="Z-score against historical baseline; NULL if not evaluated"),
  sensitivity_level STRING    NOT NULL OPTIONS(description="Enum: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED — drives row-level security"),
  created_at        TIMESTAMP NOT NULL OPTIONS(description="UTC timestamp when this reconciliation row was produced"),

  PRIMARY KEY (record_id) NOT ENFORCED
)
PARTITION BY DATE(created_at)
CLUSTER BY sensitivity_level, match_status
OPTIONS(
  description = "GERA Layer 1 + Layer 2 per-record reconciliation outcome with sensitivity classification",
  labels      = [("framework", "gera"), ("layer", "1"), ("regulation", "sox")]
);

-- User attribute table — referenced by ABAC row-access policies.
-- Matches google_bigquery_table.user_attributes in terraform/bigquery_rls/main.tf.
CREATE TABLE IF NOT EXISTS `${project}.${dataset}.user_attributes` (
  user_email            STRING NOT NULL OPTIONS(description="User's federated identity email"),
  role                  STRING NOT NULL OPTIONS(description="Role: analyst | finance_lead | data_engineer | auditor"),
  department            STRING NOT NULL OPTIONS(description="Department / business unit"),
  sensitivity_clearance STRING NOT NULL OPTIONS(description="Max clearance: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED"),
  nist_label            STRING          OPTIONS(description="NIST SP 800-53 clearance label, optional"),

  PRIMARY KEY (user_email) NOT ENFORCED
)
OPTIONS(
  description = "ABAC user-attribute directory used by row-access policies in terraform/bigquery_rls/",
  labels      = [("framework", "gera"), ("layer", "4")]
);
