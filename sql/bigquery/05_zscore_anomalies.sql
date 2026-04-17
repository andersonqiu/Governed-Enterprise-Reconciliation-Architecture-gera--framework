-- GERA Framework — BigQuery DDL
-- Table: zscore_anomalies
-- Layer: 2 (Multi-Layer Statistical Validation)
-- Python counterpart: gera.validation.zscore_gate.Anomaly
--
-- Persistent record of individual Z-score anomaly decisions. Each row is the
-- output of ZScoreGate.validate() for one (record_id, segment) pair. Used for:
--   * reconciling "why did this value get blocked" in the audit trail
--   * computing rolling anomaly rates per segment for Reasonableness Layer
--   * back-testing sigma thresholds on historical data
--
-- NIST CSF 2.0 controls: DE.CM-01, DE.AE-02.

CREATE TABLE IF NOT EXISTS `${project}.${dataset}.zscore_anomalies` (
  record_id      STRING    NOT NULL OPTIONS(description="Record identifier (same space as reconciliation_results.record_id)"),
  value          FLOAT64   NOT NULL OPTIONS(description="Observed value under evaluation"),
  z_score        FLOAT64   NOT NULL OPTIONS(description="Z-score against baseline; sign preserved"),
  decision       STRING    NOT NULL OPTIONS(description="Enum: PASS | FLAG | BLOCK"),
  baseline_mean  FLOAT64   NOT NULL OPTIONS(description="Mean of the historical baseline window"),
  baseline_std   FLOAT64   NOT NULL OPTIONS(description="Standard deviation of the historical baseline window"),
  segment        STRING             OPTIONS(description="Optional segment key (e.g. merchant_id, region) — NULL means the global segment"),
  `timestamp`    TIMESTAMP          OPTIONS(description="UTC timestamp of the observation; falls back to ingestion time if not provided"),

  ingested_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP()
                                 OPTIONS(description="UTC timestamp this row was written to BigQuery"),

  PRIMARY KEY (record_id, segment) NOT ENFORCED
)
PARTITION BY DATE(IFNULL(`timestamp`, ingested_at))
CLUSTER BY decision, segment
OPTIONS(
  description = "GERA Layer 2 per-record Z-score anomaly decisions",
  labels      = [("framework", "gera"), ("layer", "2")]
);

-- Convenience view: % FLAG + % BLOCK per segment per day — drives Layer 2
-- batch-rate gating and alerting.
CREATE OR REPLACE VIEW `${project}.${dataset}.v_zscore_daily_rates` AS
SELECT
  DATE(IFNULL(`timestamp`, ingested_at)) AS observation_date,
  IFNULL(segment, 'GLOBAL')              AS segment,
  COUNT(*)                               AS total_records,
  COUNTIF(decision = 'PASS')             AS passed,
  COUNTIF(decision = 'FLAG')             AS flagged,
  COUNTIF(decision = 'BLOCK')            AS blocked,
  SAFE_DIVIDE(COUNTIF(decision = 'FLAG'),  COUNT(*)) AS flag_rate,
  SAFE_DIVIDE(COUNTIF(decision = 'BLOCK'), COUNT(*)) AS block_rate
FROM `${project}.${dataset}.zscore_anomalies`
GROUP BY observation_date, segment;
