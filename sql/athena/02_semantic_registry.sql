-- GERA Framework — Athena / Glue DDL
-- Table: semantic_registry
-- Layer: 3 (Governed Semantic Standardization)
-- Python counterpart: gera.governance.semantic_registry.MetricDefinition
--
-- Versioned metric definitions with lineage and SLA metadata. One row per
-- (metric_name, version) pair. The pipeline writes a new version on every
-- update so historical re-runs and audit reproductions remain possible.
--
-- Partitioning: registry is small (hundreds to thousands of rows) — no
-- partitioning, but we cluster physical files by writing one Parquet file
-- per sensitivity level to help predicate pushdown.
--
-- NIST CSF 2.0 controls: GV.OC-01, GV.OC-03, GV.RM-01.

CREATE EXTERNAL TABLE IF NOT EXISTS `${database}`.`semantic_registry` (
  name              STRING        COMMENT 'Metric identifier',
  version           INT           COMMENT 'Monotonically increasing version; first registration = 1',
  description       STRING        COMMENT 'Human-readable metric description',
  formula           STRING        COMMENT 'Deterministic formula or SQL expression',
  owner             STRING        COMMENT 'Business owner (email, team alias, or steward)',
  sensitivity       STRING        COMMENT 'Enum: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED',
  source_system     STRING        COMMENT 'Primary upstream system of record',
  refresh_frequency STRING        COMMENT 'Cadence: realtime | hourly | daily | weekly | monthly',
  sla_hours         DOUBLE        COMMENT 'Max allowed freshness in hours',
  lineage           ARRAY<STRING> COMMENT 'Ordered list of upstream table / metric references',
  created_at        TIMESTAMP     COMMENT 'UTC timestamp of first registration for this (name, version)',
  updated_at        TIMESTAMP     COMMENT 'UTC timestamp of the last field change'
)
STORED AS PARQUET
LOCATION 's3://${bucket}/semantic_registry/'
TBLPROPERTIES (
  'classification'      = 'parquet',
  'parquet.compression' = 'SNAPPY',
  'framework'           = 'gera',
  'layer'               = '3',
  'regulation'          = 'sox'
);

-- Latest-version view — mirrors the BigQuery v_semantic_registry_latest view.
CREATE OR REPLACE VIEW `${database}`.`v_semantic_registry_latest` AS
SELECT *
FROM (
  SELECT
    sr.*,
    ROW_NUMBER() OVER (PARTITION BY name ORDER BY version DESC) AS rn
  FROM `${database}`.`semantic_registry` AS sr
)
WHERE rn = 1;
