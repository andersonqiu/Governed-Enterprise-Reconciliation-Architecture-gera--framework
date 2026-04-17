-- GERA Framework — Athena / Glue DDL
-- Table: zscore_anomalies
-- Layer: 2 (Multi-Layer Statistical Validation)
-- Python counterpart: gera.validation.zscore_gate.Anomaly
--
-- Persistent record of individual Z-score anomaly decisions.
--
-- NIST CSF 2.0 controls: DE.CM-01, DE.AE-02.

CREATE EXTERNAL TABLE IF NOT EXISTS `${database}`.`zscore_anomalies` (
  record_id     STRING    COMMENT 'Record identifier (same space as reconciliation_results.record_id)',
  value         DOUBLE    COMMENT 'Observed value under evaluation',
  z_score       DOUBLE    COMMENT 'Z-score against baseline; sign preserved',
  decision      STRING    COMMENT 'Enum: PASS | FLAG | BLOCK',
  baseline_mean DOUBLE    COMMENT 'Mean of the historical baseline window',
  baseline_std  DOUBLE    COMMENT 'Standard deviation of the historical baseline window',
  segment       STRING    COMMENT 'Optional segment key; NULL means global segment',
  `timestamp`   TIMESTAMP COMMENT 'UTC observation timestamp; falls back to ingestion time',
  ingested_at   TIMESTAMP COMMENT 'UTC write time'
)
PARTITIONED BY (
  observation_date STRING COMMENT 'YYYY-MM-DD partition key (date of timestamp or ingested_at)'
)
STORED AS PARQUET
LOCATION 's3://${bucket}/zscore_anomalies/'
TBLPROPERTIES (
  'classification'                          = 'parquet',
  'parquet.compression'                     = 'SNAPPY',
  'projection.enabled'                      = 'true',
  'projection.observation_date.type'        = 'date',
  'projection.observation_date.format'      = 'yyyy-MM-dd',
  'projection.observation_date.range'       = '2025-01-01,NOW',
  'projection.observation_date.interval'    = '1',
  'projection.observation_date.interval.unit' = 'DAYS',
  'storage.location.template'               = 's3://${bucket}/zscore_anomalies/observation_date=${observation_date}/',
  'framework'                               = 'gera',
  'layer'                                   = '2'
);

-- Daily rate view — mirrors BigQuery v_zscore_daily_rates.
CREATE OR REPLACE VIEW `${database}`.`v_zscore_daily_rates` AS
SELECT
  observation_date,
  COALESCE(segment, 'GLOBAL')                                                AS segment,
  COUNT(*)                                                                   AS total_records,
  COUNT_IF(decision = 'PASS')                                                AS passed,
  COUNT_IF(decision = 'FLAG')                                                AS flagged,
  COUNT_IF(decision = 'BLOCK')                                               AS blocked,
  TRY(CAST(COUNT_IF(decision = 'FLAG')  AS DOUBLE) / NULLIF(COUNT(*), 0))    AS flag_rate,
  TRY(CAST(COUNT_IF(decision = 'BLOCK') AS DOUBLE) / NULLIF(COUNT(*), 0))    AS block_rate
FROM `${database}`.`zscore_anomalies`
GROUP BY observation_date, COALESCE(segment, 'GLOBAL');
