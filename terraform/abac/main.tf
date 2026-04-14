# GERA Framework — Attribute-Based Access Control (ABAC) Roles
#
# Defines IAM custom roles with sensitivity-level gating.
# Each role maps to a NIST data sensitivity tier.
#
# NIST CSF 2.0 Control: PR.AA-01 (Identity Management & Access Control)

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
}

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

resource "google_project_iam_custom_role" "gera_analyst" {
  project     = var.project_id
  role_id     = "gera_analyst"
  title       = "GERA Analyst"
  description = "Read-only access to INTERNAL sensitivity data"

  permissions = [
    "bigquery.tables.getData",
    "bigquery.jobs.create",
  ]
}

resource "google_project_iam_custom_role" "gera_finance_lead" {
  project     = var.project_id
  role_id     = "gera_finance_lead"
  title       = "GERA Finance Lead"
  description = "Read + export access to CONFIDENTIAL sensitivity data"

  permissions = [
    "bigquery.tables.getData",
    "bigquery.tables.export",
    "bigquery.jobs.create",
  ]
}

resource "google_project_iam_custom_role" "gera_data_engineer" {
  project     = var.project_id
  role_id     = "gera_data_engineer"
  title       = "GERA Data Engineer"
  description = "Read/write access to CONFIDENTIAL sensitivity data"

  permissions = [
    "bigquery.tables.getData",
    "bigquery.tables.create",
    "bigquery.tables.update",
    "bigquery.jobs.create",
  ]
}

resource "google_project_iam_custom_role" "gera_compliance_auditor" {
  project     = var.project_id
  role_id     = "gera_compliance_auditor"
  title       = "GERA Compliance Auditor"
  description = "Full read access including RESTRICTED audit logs"

  permissions = [
    "bigquery.tables.getData",
    "bigquery.tables.list",
    "bigquery.jobs.create",
    "logging.logEntries.list",
  ]
}

# ---------------------------------------------------------------------------
# Outputs — consumed by bigquery_rls/iam.tf to bind groups to these roles.
# ---------------------------------------------------------------------------

output "gera_analyst_role_id" {
  description = "Full resource ID of the gera_analyst custom role"
  value       = google_project_iam_custom_role.gera_analyst.id
}

output "gera_finance_lead_role_id" {
  description = "Full resource ID of the gera_finance_lead custom role"
  value       = google_project_iam_custom_role.gera_finance_lead.id
}

output "gera_data_engineer_role_id" {
  description = "Full resource ID of the gera_data_engineer custom role"
  value       = google_project_iam_custom_role.gera_data_engineer.id
}

output "gera_compliance_auditor_role_id" {
  description = "Full resource ID of the gera_compliance_auditor custom role"
  value       = google_project_iam_custom_role.gera_compliance_auditor.id
}
