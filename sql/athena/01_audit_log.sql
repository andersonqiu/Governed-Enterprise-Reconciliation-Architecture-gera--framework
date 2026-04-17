-- GERA Framework — Athena / Glue DDL
-- Table: audit_log
-- Layer: 3 (Governed Semantic Standardization)
-- Python counterpart: gera.governance.audit_logger.AuditEvent
--
-- Append-only external table over S3-parquet with SHA-256 hash chaining.
-- Integrity verification is performed by sql/athena/views/v_audit_chain_verification.sql.
--
-- Retention: 2555 days (~7 years) is enforced outside this DDL by an S3
-- lifecycle rule on the audit_log/ prefix — Glue / Athena has no
-- partition_expiration_days equivalent.
--
-- Partitioning: event_date is a derived column produced by the pipeline so we
-- can use Athena partition projection (no MSCK REPAIR required).
--
-- NIST CSF 2.0 controls: GV.OC-03, DE.CM-01, DE.AE-03, RS.MA-01.

CREATE EXTERNAL TABLE IF NOT EXISTS `${database}`.`audit_log` (
  event_id       STRING COMMENT 'Unique, monotonically-increasing event identifier (e.g. AUD-00000001)',
  event_type     STRING COMMENT 'Enum: GATE_DECISION | RECONCILIATION | ACCESS | CONFIGURATION_CHANGE | DATA_MODIFICATION',
  `timestamp`    TIMESTAMP COMMENT 'UTC event timestamp',
  actor          STRING COMMENT 'Principal that triggered the event',
  action         STRING COMMENT 'Short action verb',
  resource       STRING COMMENT 'Resource acted on',
  details        STRING COMMENT 'JSON-serialized structured payload — parse with Athena json_extract_* functions',
  previous_hash  STRING COMMENT 'SHA-256 hex digest of the preceding event (all zeros for genesis)',
  event_hash     STRING COMMENT 'SHA-256 hex digest of this event'
)
PARTITIONED BY (
  event_date STRING COMMENT 'YYYY-MM-DD partition key derived from timestamp'
)
STORED AS PARQUET
LOCATION 's3://${bucket}/audit_log/'
TBLPROPERTIES (
  'classification'                       = 'parquet',
  'parquet.compression'                  = 'SNAPPY',
  -- Partition projection avoids MSCK REPAIR TABLE.
  'projection.enabled'                   = 'true',
  'projection.event_date.type'           = 'date',
  'projection.event_date.format'         = 'yyyy-MM-dd',
  'projection.event_date.range'          = '2025-01-01,NOW',
  'projection.event_date.interval'       = '1',
  'projection.event_date.interval.unit'  = 'DAYS',
  'storage.location.template'            = 's3://${bucket}/audit_log/event_date=${event_date}/',
  'framework'                            = 'gera',
  'layer'                                = '3',
  'regulation'                           = 'sox',
  'retention.enforcement'                = 's3_lifecycle_2555d'
);

-- NOTE: writes to this table must be append-only. Lake Formation permissions
-- should grant INSERT only to the pipeline role; DELETE should not be granted
-- to any principal. 7-year retention is enforced by an S3 lifecycle rule on
-- the audit_log/ prefix (configure outside this DDL, e.g. via Terraform).
