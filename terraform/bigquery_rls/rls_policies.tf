# GERA Framework — BigQuery Row-Level Security Policies
#
# Applies four row access policies to the reconciliation_results table,
# one per sensitivity tier. Each policy restricts which rows a group can
# read based on the sensitivity_level column.
#
# Clearance hierarchy (cumulative — higher clearance includes lower tiers):
#
#   PUBLIC      → gera-analysts, gera-finance-leads, gera-data-engineers, gera-auditors
#   INTERNAL    → gera-analysts, gera-finance-leads, gera-data-engineers, gera-auditors
#   CONFIDENTIAL→ gera-finance-leads, gera-data-engineers, gera-auditors
#   RESTRICTED  → gera-auditors only (no row filter — sees everything)
#
# How it works:
#   BigQuery evaluates ALL row access policies that match the querying user.
#   A row is visible if ANY matching policy allows it. The grantees list in
#   each policy uses the Cloud Identity group emails defined in groups.tf.
#
# NIST CSF 2.0 Control: PR.AA-01 (Identities and credentials are managed),
#                        PR.DS-01 (Data-at-rest is protected)
#
# Alternative: SESSION_USER() subquery approach
#   Instead of per-tier policies, a single policy can dynamically resolve
#   clearance from the user_attributes lookup table:
#
#     filter_predicate = <<-EOT
#       sensitivity_level IN (
#         SELECT CASE sensitivity_clearance
#           WHEN 'RESTRICTED'    THEN sensitivity_level  -- all tiers
#           WHEN 'CONFIDENTIAL'  THEN sensitivity_level
#           WHEN 'INTERNAL'      THEN sensitivity_level
#           ELSE NULL
#         END
#         FROM `${var.project_id}.${var.dataset_id}.user_attributes`
#         WHERE user_email = SESSION_USER()
#           AND sensitivity_level IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')
#       )
#     EOT
#
#   The per-policy approach below is simpler to audit and easier to test
#   individually, which is preferable in regulated environments.

# ---------------------------------------------------------------------------
# Policy 1 — PUBLIC rows
# Grantees: all four groups
# Visible rows: sensitivity_level = 'PUBLIC'
# ---------------------------------------------------------------------------

resource "google_bigquery_row_access_policy" "rls_public" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  table_id   = google_bigquery_table.reconciliation_results.table_id
  policy_id  = "rls_public"

  # All four groups can see PUBLIC rows.
  grantees = [
    "group:${google_cloud_identity_group.gera_analysts.group_key[0].id}",
    "group:${google_cloud_identity_group.gera_finance_leads.group_key[0].id}",
    "group:${google_cloud_identity_group.gera_data_engineers.group_key[0].id}",
    "group:${google_cloud_identity_group.gera_auditors.group_key[0].id}",
  ]

  filter_predicate = "sensitivity_level = 'PUBLIC'"
}

# ---------------------------------------------------------------------------
# Policy 2 — INTERNAL rows
# Grantees: all four groups (analysts have clearance for INTERNAL and below)
# Visible rows: sensitivity_level = 'INTERNAL'
#
# Combined with rls_public, analysts see: PUBLIC + INTERNAL rows.
# ---------------------------------------------------------------------------

resource "google_bigquery_row_access_policy" "rls_internal" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  table_id   = google_bigquery_table.reconciliation_results.table_id
  policy_id  = "rls_internal"

  grantees = [
    "group:${google_cloud_identity_group.gera_analysts.group_key[0].id}",
    "group:${google_cloud_identity_group.gera_finance_leads.group_key[0].id}",
    "group:${google_cloud_identity_group.gera_data_engineers.group_key[0].id}",
    "group:${google_cloud_identity_group.gera_auditors.group_key[0].id}",
  ]

  filter_predicate = "sensitivity_level = 'INTERNAL'"
}

# ---------------------------------------------------------------------------
# Policy 3 — CONFIDENTIAL rows
# Grantees: finance-leads, data-engineers, auditors (analysts excluded)
# Visible rows: sensitivity_level = 'CONFIDENTIAL'
#
# Combined with policies 1 & 2, finance-leads and data-engineers see:
# PUBLIC + INTERNAL + CONFIDENTIAL rows.
# ---------------------------------------------------------------------------

resource "google_bigquery_row_access_policy" "rls_confidential" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  table_id   = google_bigquery_table.reconciliation_results.table_id
  policy_id  = "rls_confidential"

  grantees = [
    "group:${google_cloud_identity_group.gera_finance_leads.group_key[0].id}",
    "group:${google_cloud_identity_group.gera_data_engineers.group_key[0].id}",
    "group:${google_cloud_identity_group.gera_auditors.group_key[0].id}",
  ]

  filter_predicate = "sensitivity_level = 'CONFIDENTIAL'"
}

# ---------------------------------------------------------------------------
# Policy 4 — RESTRICTED rows
# Grantees: auditors only
# Filter: TRUE (no filter — auditors see all rows including RESTRICTED)
#
# The TRUE predicate is equivalent to no row filter. BigQuery's union
# semantics mean auditors will see every row across all sensitivity tiers
# because at least one matching policy allows each row.
# ---------------------------------------------------------------------------

resource "google_bigquery_row_access_policy" "rls_restricted" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  table_id   = google_bigquery_table.reconciliation_results.table_id
  policy_id  = "rls_restricted"

  grantees = [
    "group:${google_cloud_identity_group.gera_auditors.group_key[0].id}",
    # The pipeline service account needs unrestricted read-back after writes.
    # Defined in iam.tf; Terraform resolves cross-file references within a module.
    "serviceAccount:${google_service_account.gera_pipeline.email}",
  ]

  filter_predicate = "TRUE"
}
