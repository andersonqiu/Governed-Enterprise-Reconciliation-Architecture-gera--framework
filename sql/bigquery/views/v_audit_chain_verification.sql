-- GERA Framework — BigQuery view
-- View: v_audit_chain_verification
-- Python counterpart: gera.governance.audit_logger.AuditLogger.verify_chain()
--
-- Re-implements hash-chain integrity verification in pure SQL so an auditor
-- can check the chain without running Python. The view yields one row per
-- audit event with a boolean `is_linked` flag: TRUE when this event's
-- previous_hash equals the prior event's event_hash (ordered by event_id).
-- The genesis event links to '0' * 64 by convention.
--
-- Usage:
--   -- Is the whole chain intact?
--   SELECT COUNTIF(NOT is_linked) = 0 AS chain_is_valid
--   FROM `${project}.${dataset}.v_audit_chain_verification`;
--
--   -- Which events are broken?
--   SELECT event_id, event_type, previous_hash, expected_previous_hash
--   FROM `${project}.${dataset}.v_audit_chain_verification`
--   WHERE NOT is_linked
--   ORDER BY event_id;

CREATE OR REPLACE VIEW `${project}.${dataset}.v_audit_chain_verification` AS
SELECT
  event_id,
  event_type,
  `timestamp`,
  actor,
  action,
  resource,
  previous_hash,
  event_hash,
  -- The hash this event claims to chain to — NULL on the genesis event.
  LAG(event_hash) OVER (ORDER BY event_id) AS expected_previous_hash,
  -- Chain integrity check: genesis event is linked if previous_hash is all zeros;
  -- non-genesis events are linked if previous_hash = previous row's event_hash.
  CASE
    WHEN LAG(event_hash) OVER (ORDER BY event_id) IS NULL
      THEN previous_hash = REPEAT('0', 64)
    ELSE previous_hash = LAG(event_hash) OVER (ORDER BY event_id)
  END AS is_linked
FROM `${project}.${dataset}.audit_log`;
