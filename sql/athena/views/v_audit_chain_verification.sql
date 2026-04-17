-- GERA Framework — Athena view
-- View: v_audit_chain_verification
-- Python counterpart: gera.governance.audit_logger.AuditLogger.verify_chain()
--
-- Re-implements hash-chain integrity verification in pure SQL (Athena /
-- Presto dialect) so an auditor can check the chain without running Python.
-- One row per audit event; is_linked = TRUE when this event's previous_hash
-- equals the prior event's event_hash ordered by event_id. The genesis
-- event links to 64 zeros by convention.
--
-- Usage:
--   -- Is the whole chain intact?
--   SELECT COUNT_IF(NOT is_linked) = 0 AS chain_is_valid
--   FROM `${database}`.`v_audit_chain_verification`;
--
--   -- Which events are broken?
--   SELECT event_id, event_type, previous_hash, expected_previous_hash
--   FROM `${database}`.`v_audit_chain_verification`
--   WHERE NOT is_linked
--   ORDER BY event_id;

CREATE OR REPLACE VIEW `${database}`.`v_audit_chain_verification` AS
SELECT
  event_id,
  event_type,
  `timestamp`,
  actor,
  action,
  resource,
  previous_hash,
  event_hash,
  LAG(event_hash) OVER (ORDER BY event_id) AS expected_previous_hash,
  CASE
    WHEN LAG(event_hash) OVER (ORDER BY event_id) IS NULL
      THEN previous_hash = lpad('', 64, '0')
    ELSE previous_hash = LAG(event_hash) OVER (ORDER BY event_id)
  END AS is_linked
FROM `${database}`.`audit_log`;
