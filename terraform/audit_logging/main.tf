# GERA Framework — Append-Only Audit Logging Sink
#
# BigQuery tables for immutable audit trail storage.
# Supports SOX Section 404 seven-year retention and
# NIST CSF 2.0 DE.CM continuous monitoring.
#
# NIST CSF 2.0 Controls: PR.DS-01 (Data Security), DE.CM-01 (Monitoring)

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
  description = "BigQuery dataset ID for audit logs"
  type        = string
  default     = "gera_audit_logs"
}

variable "location" {
  description = "BigQuery dataset location"
  type        = string
  default     = "US"
}

variable "retention_days" {
  description = "Table retention in days (~7 years for SOX)"
  type        = number
  default     = 2555
}

resource "google_bigquery_dataset" "audit_logs" {
  project    = var.project_id
  dataset_id = var.dataset_id
  location   = var.location

  description = "GERA append-only audit logs with hash chaining"

  default_table_expiration_ms = var.retention_days * 24 * 60 * 60 * 1000

  labels = {
    framework    = "gera"
    nist_control = "pr-ds-01"
    sox_relevant = "true"
  }
}

resource "google_bigquery_table" "gate_decisions" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.audit_logs.dataset_id
  table_id   = "gate_decisions"

  description = "Audit trail for all pipeline gate decisions"

  schema = jsonencode([
    { name = "event_id",       type = "STRING",    mode = "REQUIRED" },
    { name = "timestamp",      type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "gate_name",      type = "STRING",    mode = "REQUIRED" },
    { name = "decision",       type = "STRING",    mode = "REQUIRED" },
    { name = "record_count",   type = "INT64",     mode = "NULLABLE" },
    { name = "anomaly_count",  type = "INT64",     mode = "NULLABLE" },
    { name = "anomaly_rate",   type = "FLOAT64",   mode = "NULLABLE" },
    { name = "baseline_mean",  type = "FLOAT64",   mode = "NULLABLE" },
    { name = "baseline_std",   type = "FLOAT64",   mode = "NULLABLE" },
    { name = "previous_hash",  type = "STRING",    mode = "REQUIRED" },
    { name = "event_hash",     type = "STRING",    mode = "REQUIRED" },
  ])
}

resource "google_bigquery_table" "access_log" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.audit_logs.dataset_id
  table_id   = "access_log"

  description = "Data access audit trail"

  schema = jsonencode([
    { name = "event_id",          type = "STRING",    mode = "REQUIRED" },
    { name = "timestamp",         type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "actor",             type = "STRING",    mode = "REQUIRED" },
    { name = "action",            type = "STRING",    mode = "REQUIRED" },
    { name = "resource",          type = "STRING",    mode = "REQUIRED" },
    { name = "sensitivity_level", type = "STRING",    mode = "NULLABLE" },
    { name = "ip_address",        type = "STRING",    mode = "NULLABLE" },
    { name = "event_hash",        type = "STRING",    mode = "REQUIRED" },
  ])
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "dataset_id" {
  description = "BigQuery dataset ID for the audit logs"
  value       = google_bigquery_dataset.audit_logs.dataset_id
}

output "gate_decisions_table_id" {
  description = "Table ID for pipeline gate decision audit log"
  value       = google_bigquery_table.gate_decisions.table_id
}

output "access_log_table_id" {
  description = "Table ID for data access audit log"
  value       = google_bigquery_table.access_log.table_id
}
