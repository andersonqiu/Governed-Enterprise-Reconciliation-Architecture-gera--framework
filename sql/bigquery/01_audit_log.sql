-- GERA Framework — BigQuery DDL
-- Table: audit_log
-- Layer: 3 (Governed Semantic Standardization)
-- Python counterpart: gera.governance.audit_logger.AuditEvent
--
-- Append-only audit table with SHA-256 hash chaining. Every row carries the
-- hash of the previous event, forming a tamper-evident chain. Integrity
-- verification is performed by sql/bigquery/views/v_audit_chain_verification.sql.
--
-- Retention: 2555 days (~7 years) — aligns with SOX Section 404 record retention
-- requirements. BigQuery partition expiration deletes partitions older than this
-- automatically.
--
-- NIST CSF 2.0 controls: GV.OC-03, DE.CM-01, DE.AE-03, RS.MA-01.

CREATE TABLE IF NOT EXISTS `${project}.${dataset}.audit_log` (
  -- Identity
  event_id       STRING    NOT NULL OPTIONS(description="Unique, monotonically-increasing event identifier (e.g. AUD-00000001)"),
  event_type     STRING    NOT NULL OPTIONS(description="Enum: GATE_DECISION | RECONCILIATION | ACCESS | CONFIGURATION_CHANGE | DATA_MODIFICATION"),

  -- When / who / what
  `timestamp`    TIMESTAMP NOT NULL OPTIONS(description="UTC event timestamp"),
  actor          STRING    NOT NULL OPTIONS(description="Principal that triggered the event (service account, user, or pipeline role)"),
  action         STRING    NOT NULL OPTIONS(description="Short action verb (e.g. gate_block, chain_verify, schema_change)"),
  resource       STRING    NOT NULL OPTIONS(description="Resource acted on (table name, pipeline stage, metric name, etc.)"),
  details        JSON               OPTIONS(description="Arbitrary structured payload — action-specific context, kept as JSON for schema evolution"),

  -- Hash chain
  previous_hash  STRING    NOT NULL OPTIONS(description="SHA-256 hex digest of the preceding event (all zeros for the genesis event)"),
  event_hash     STRING    NOT NULL OPTIONS(description="SHA-256 hex digest of this event's canonical serialization — used to link the next event"),

  PRIMARY KEY (event_id) NOT ENFORCED
)
PARTITION BY DATE(`timestamp`)
CLUSTER BY event_type, actor
OPTIONS(
  description               = "GERA append-only audit log with SHA-256 hash chaining (SOX / NIST CSF 2.0 DE.AE-03)",
  partition_expiration_days = 2555,  -- ~7 years, matches AuditLogger(retention_days=2555)
  labels                    = [("framework", "gera"), ("layer", "3"), ("regulation", "sox"), ("pii", "none")]
);

-- Note: INSERTs should be append-only. No UPDATE or DELETE grants should be
-- issued for this table in production (except for partition-expiration-driven
-- deletes by BigQuery itself). The pipeline service account should hold
-- bigquery.tables.updateData only; a separate "auditor" role has read access.
