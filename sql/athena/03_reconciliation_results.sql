-- GERA Framework — Athena / Glue DDL
-- Table: reconciliation_results
-- Layers: 1 (Deterministic Reconciliation) + 2 (Statistical Validation)
-- Python counterpart: gera.reconciliation.deterministic_matcher.MatchResult
--                     + gera.validation.zscore_gate.GateDecision
--
-- Row-level security is attached to this table by
-- terraform/lakeformation_rls/rls_policies.tf. Keep sensitivity_level in sync
-- with the four data cells filters (rls_public, rls_internal, rls_confidential,
-- rls_restricted) defined there.
--
-- Schema matches aws_glue_catalog_table.reconciliation_results in
-- terraform/lakeformation_rls/main.tf — change them together.
--
-- NIST CSF 2.0 controls: PR.AA-01, PR.DS-01, DE.CM-01.

CREATE EXTERNAL TABLE IF NOT EXISTS `${database}`.`reconciliation_results` (
  record_id         STRING    COMMENT 'Unique identifier for the reconciliation record',
  source_system     STRING    COMMENT 'Originating system',
  target_system     STRING    COMMENT 'Destination system',
  match_status      STRING    COMMENT 'Enum: MATCHED | UNMATCHED_SOURCE | UNMATCHED_TARGET | CONFLICT',
  amount_difference DOUBLE    COMMENT 'Source minus target; NULL if non-monetary',
  gate_decision     STRING    COMMENT 'Enum: PASS | FLAG | BLOCK',
  z_score           DOUBLE    COMMENT 'Z-score against historical baseline; NULL if not evaluated',
  sensitivity_level STRING    COMMENT 'Enum: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED — drives row-level security',
  created_at        TIMESTAMP COMMENT 'UTC timestamp when this row was produced'
)
PARTITIONED BY (
  created_date STRING COMMENT 'YYYY-MM-DD partition key derived from created_at'
)
STORED AS PARQUET
LOCATION 's3://${bucket}/reconciliation_results/'
TBLPROPERTIES (
  'classification'                       = 'parquet',
  'parquet.compression'                  = 'SNAPPY',
  'projection.enabled'                   = 'true',
  'projection.created_date.type'         = 'date',
  'projection.created_date.format'       = 'yyyy-MM-dd',
  'projection.created_date.range'        = '2025-01-01,NOW',
  'projection.created_date.interval'     = '1',
  'projection.created_date.interval.unit' = 'DAYS',
  'storage.location.template'            = 's3://${bucket}/reconciliation_results/created_date=${created_date}/',
  'framework'                            = 'gera',
  'layer'                                = '1',
  'regulation'                           = 'sox'
);

-- User attribute table — referenced by ABAC Lake Formation policies.
-- Matches aws_glue_catalog_table.user_attributes in
-- terraform/lakeformation_rls/main.tf.
--
-- Note on the principal column: AWS IAM identifies principals by ARN, while
-- GCP federates identity by email. This table uses `user_arn` to stay native
-- to AWS; the equivalent GCP column is `user_email` in sql/bigquery/03.
CREATE EXTERNAL TABLE IF NOT EXISTS `${database}`.`user_attributes` (
  user_arn              STRING COMMENT 'IAM principal ARN — equivalent to BigQuery user_email',
  role                  STRING COMMENT 'Role: analyst | finance_lead | data_engineer | auditor',
  department            STRING COMMENT 'Department / business unit',
  sensitivity_clearance STRING COMMENT 'Max clearance: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED',
  nist_label            STRING COMMENT 'NIST SP 800-53 clearance label, optional'
)
STORED AS PARQUET
LOCATION 's3://${bucket}/user_attributes/'
TBLPROPERTIES (
  'classification'      = 'parquet',
  'parquet.compression' = 'SNAPPY',
  'framework'           = 'gera',
  'layer'               = '4'
);
