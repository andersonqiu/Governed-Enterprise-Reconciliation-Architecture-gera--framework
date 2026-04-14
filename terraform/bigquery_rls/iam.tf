# GERA Framework — IAM Bindings for the Governed Financial Dataset
#
# Wires Cloud Identity groups (groups.tf) to the BigQuery dataset using
# the principle of least privilege. Groups receive only the permissions
# needed for their clearance tier.
#
# Also provisions a dedicated service account for the GERA reconciliation
# pipeline so it can write results without using any human credential.
#
# Cross-module note:
#   The custom IAM roles referenced below are defined in ../abac/main.tf.
#   Because these live in separate Terraform roots, they are referenced by
#   their stable role ID string rather than a resource reference. Apply the
#   abac/ module first (or use a shared remote state backend) to ensure
#   the roles exist before applying this module.
#
# NIST CSF 2.0 Controls: PR.AA-01 (Access control), PR.AA-05 (Least privilege)

# ---------------------------------------------------------------------------
# Pipeline service account
#
# Used by the GERA Python framework when writing reconciliation results to
# BigQuery. Scoped to dataEditor on this dataset only — no project-wide
# permissions.
# ---------------------------------------------------------------------------

resource "google_service_account" "gera_pipeline" {
  project      = var.project_id
  account_id   = "gera-reconciliation-pipeline"
  display_name = "GERA Reconciliation Pipeline"
  description  = "Service account for the GERA framework reconciliation pipeline. Writes results to the governed financial dataset."
}

# ---------------------------------------------------------------------------
# Dataset-level IAM bindings — human groups
#
# roles/bigquery.dataViewer grants:
#   bigquery.tables.getData, bigquery.tables.list, bigquery.datasets.get
#
# Row-level visibility is further restricted by the policies in
# rls_policies.tf — dataViewer alone is not sufficient to read rows,
# the user must also match a row access policy grantee.
# ---------------------------------------------------------------------------

resource "google_bigquery_dataset_iam_member" "analysts_viewer" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "group:${google_cloud_identity_group.gera_analysts.group_key[0].id}"
}

resource "google_bigquery_dataset_iam_member" "finance_leads_viewer" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "group:${google_cloud_identity_group.gera_finance_leads.group_key[0].id}"
}

resource "google_bigquery_dataset_iam_member" "data_engineers_viewer" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "group:${google_cloud_identity_group.gera_data_engineers.group_key[0].id}"

  # Data engineers also need dataEditor to run the pipeline locally.
  # The pipeline service account (below) is the preferred write path in prod.
}

resource "google_bigquery_dataset_iam_member" "data_engineers_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "group:${google_cloud_identity_group.gera_data_engineers.group_key[0].id}"
}

resource "google_bigquery_dataset_iam_member" "auditors_viewer" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "group:${google_cloud_identity_group.gera_auditors.group_key[0].id}"
}

# ---------------------------------------------------------------------------
# Dataset-level IAM binding — pipeline service account
#
# dataEditor allows the pipeline to INSERT rows. The rls_restricted policy
# in rls_policies.tf grants the SA the TRUE filter so it can read back
# any row it just wrote for verification.
# ---------------------------------------------------------------------------

resource "google_bigquery_dataset_iam_member" "pipeline_sa_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.gera_pipeline.email}"
}

# Allow the pipeline SA to submit BigQuery jobs in the project.
resource "google_project_iam_member" "pipeline_sa_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.gera_pipeline.email}"
}

# ---------------------------------------------------------------------------
# Project-level custom role bindings — groups → abac/ roles
#
# Roles are looked up via data sources so this module does not need to
# hardcode role ID strings. The abac/ module must be applied first.
#
# Prerequisite: apply ../abac/main.tf before this module.
# ---------------------------------------------------------------------------

data "google_project_iam_custom_role" "gera_analyst" {
  project = var.project_id
  role_id = "gera_analyst"
}

data "google_project_iam_custom_role" "gera_finance_lead" {
  project = var.project_id
  role_id = "gera_finance_lead"
}

data "google_project_iam_custom_role" "gera_data_engineer" {
  project = var.project_id
  role_id = "gera_data_engineer"
}

data "google_project_iam_custom_role" "gera_compliance_auditor" {
  project = var.project_id
  role_id = "gera_compliance_auditor"
}

resource "google_project_iam_member" "analysts_custom_role" {
  project = var.project_id
  role    = data.google_project_iam_custom_role.gera_analyst.id
  member  = "group:${google_cloud_identity_group.gera_analysts.group_key[0].id}"
}

resource "google_project_iam_member" "finance_leads_custom_role" {
  project = var.project_id
  role    = data.google_project_iam_custom_role.gera_finance_lead.id
  member  = "group:${google_cloud_identity_group.gera_finance_leads.group_key[0].id}"
}

resource "google_project_iam_member" "data_engineers_custom_role" {
  project = var.project_id
  role    = data.google_project_iam_custom_role.gera_data_engineer.id
  member  = "group:${google_cloud_identity_group.gera_data_engineers.group_key[0].id}"
}

resource "google_project_iam_member" "auditors_custom_role" {
  project = var.project_id
  role    = data.google_project_iam_custom_role.gera_compliance_auditor.id
  member  = "group:${google_cloud_identity_group.gera_auditors.group_key[0].id}"
}
