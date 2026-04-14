# GERA Framework — BigQuery Row-Level Security with ABAC
#
# Implements attribute-based access control for financial reconciliation
# data. Users can only access rows matching their sensitivity clearance.
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

variable "dataset_id" {
  description = "BigQuery dataset ID"
  type        = string
  default     = "gera_financial_data"
}

variable "location" {
  description = "BigQuery dataset location"
  type        = string
  default     = "US"
}

variable "org_domain" {
  description = "Cloud Identity domain for the organisation (e.g. example.com)"
  type        = string
}

variable "customer_id" {
  description = "Cloud Identity customer ID, found in Admin Console > Account > Account settings (e.g. C0xxxxxxx)"
  type        = string
}

resource "google_bigquery_dataset" "governed_financial_data" {
  project    = var.project_id
  dataset_id = var.dataset_id
  location   = var.location

  description = "GERA governed financial reconciliation data with RLS"

  labels = {
    framework       = "gera"
    nist_control    = "pr-aa-01"
    data_governance = "enabled"
  }
}

resource "google_bigquery_table" "reconciliation_results" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  table_id   = "reconciliation_results"

  description = "Cross-system reconciliation results with sensitivity labels"

  schema = jsonencode([
    { name = "record_id",         type = "STRING",    mode = "REQUIRED" },
    { name = "source_system",     type = "STRING",    mode = "REQUIRED" },
    { name = "target_system",     type = "STRING",    mode = "REQUIRED" },
    { name = "match_status",      type = "STRING",    mode = "REQUIRED" },
    { name = "amount_difference", type = "FLOAT64",   mode = "NULLABLE" },
    { name = "gate_decision",     type = "STRING",    mode = "REQUIRED" },
    { name = "z_score",           type = "FLOAT64",   mode = "NULLABLE" },
    { name = "sensitivity_level", type = "STRING",    mode = "REQUIRED" },
    { name = "created_at",        type = "TIMESTAMP", mode = "REQUIRED" },
  ])
}

resource "google_bigquery_table" "user_attributes" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.governed_financial_data.dataset_id
  table_id   = "user_attributes"

  description = "User attribute table for ABAC row-level security"

  schema = jsonencode([
    { name = "user_email",            type = "STRING", mode = "REQUIRED" },
    { name = "role",                  type = "STRING", mode = "REQUIRED" },
    { name = "department",            type = "STRING", mode = "REQUIRED" },
    { name = "sensitivity_clearance", type = "STRING", mode = "REQUIRED" },
    { name = "nist_label",            type = "STRING", mode = "NULLABLE" },
  ])
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "dataset_id" {
  description = "BigQuery dataset ID for the governed financial data"
  value       = google_bigquery_dataset.governed_financial_data.dataset_id
}

output "analyst_group_email" {
  description = "Email of the GERA analysts Cloud Identity group"
  value       = "gera-analysts@${var.org_domain}"
}

output "auditor_group_email" {
  description = "Email of the GERA compliance auditors Cloud Identity group"
  value       = "gera-auditors@${var.org_domain}"
}

output "pipeline_sa_email" {
  description = "Service account email used by the GERA reconciliation pipeline"
  value       = google_service_account.gera_pipeline.email
}
