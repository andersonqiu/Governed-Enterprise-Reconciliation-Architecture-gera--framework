-- GERA Framework — BigQuery DDL
-- Table: semantic_registry
-- Layer: 3 (Governed Semantic Standardization)
-- Python counterpart: gera.governance.semantic_registry.MetricDefinition
--
-- Versioned metric definitions with lineage and SLA metadata. Each row is one
-- (metric_name, version) pair. Application code reads the latest version via
-- the companion view and writes a new version on every update, so older
-- definitions remain queryable for historical re-runs and audit reproducibility.
--
-- NIST CSF 2.0 controls: GV.OC-01, GV.OC-03, GV.RM-01.

CREATE TABLE IF NOT EXISTS `${project}.${dataset}.semantic_registry` (
  name              STRING         NOT NULL OPTIONS(description="Metric identifier (e.g. net_revenue, daily_auth_failures)"),
  version           INT64          NOT NULL OPTIONS(description="Monotonically increasing version; first registration = 1"),
  description       STRING         NOT NULL OPTIONS(description="Human-readable metric description"),
  formula           STRING         NOT NULL OPTIONS(description="Deterministic formula or SQL expression used to compute the metric"),
  owner             STRING         NOT NULL OPTIONS(description="Business owner (email, team alias, or steward identifier)"),
  sensitivity       STRING         NOT NULL OPTIONS(description="Enum: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED — NIST CSF 2.0 GV.OC classification"),
  source_system     STRING                  OPTIONS(description="Primary upstream system of record"),
  refresh_frequency STRING                  OPTIONS(description="Cadence: realtime | hourly | daily | weekly | monthly"),
  sla_hours         FLOAT64                 OPTIONS(description="Maximum allowed freshness in hours before the metric is considered stale"),
  lineage           ARRAY<STRING>           OPTIONS(description="Ordered list of upstream table / metric references"),
  created_at        TIMESTAMP      NOT NULL OPTIONS(description="UTC timestamp of first registration for this (name, version)"),
  updated_at        TIMESTAMP      NOT NULL OPTIONS(description="UTC timestamp of the last field change"),

  PRIMARY KEY (name, version) NOT ENFORCED
)
CLUSTER BY sensitivity, name
OPTIONS(
  description = "GERA semantic registry — versioned metric definitions with lineage, owner, and SLA",
  labels      = [("framework", "gera"), ("layer", "3"), ("regulation", "sox")]
);

-- Latest-version view for easy consumer-side queries.
CREATE OR REPLACE VIEW `${project}.${dataset}.v_semantic_registry_latest` AS
SELECT * EXCEPT(rn)
FROM (
  SELECT
    *,
    ROW_NUMBER() OVER (PARTITION BY name ORDER BY version DESC) AS rn
  FROM `${project}.${dataset}.semantic_registry`
)
WHERE rn = 1;
