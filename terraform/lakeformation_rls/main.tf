# GERA Framework — AWS Lake Formation Row-Level Security with ABAC
#
# AWS equivalent of ../bigquery_rls/. Implements attribute-based row-level
# security for financial reconciliation data using Lake Formation data cells
# filters. Users can only access rows matching their sensitivity clearance.
#
# Architecture mapping (GCP → AWS):
#   BigQuery dataset            → Glue database + S3 bucket
#   BigQuery table              → Glue table (schema in Glue catalog)
#   Cloud Identity groups       → IAM groups (see groups.tf)
#   BigQuery row access policy  → Lake Formation data cells filter (see rls_policies.tf)
#   BigQuery dataset IAM member → Lake Formation permissions (see iam.tf)
#   Service account             → IAM role for the pipeline (see iam.tf)
#
# NIST CSF 2.0 Control: PR.AA-01 (Identity Management & Access Control)
#
# Usage:
#   terraform apply \
#     -var="aws_account_id=123456789012" \
#     -var="aws_region=us-east-1"

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "database_name" {
  description = "Glue catalog database name (equivalent to BigQuery dataset)"
  type        = string
  default     = "gera_financial_data"
}

variable "org_name" {
  description = "Short organisation identifier used as a prefix for IAM resource names"
  type        = string
  default     = "gera"
}

# ---------------------------------------------------------------------------
# S3 bucket — underlying storage for the data lake
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "governed_financial_data" {
  bucket = "${var.org_name}-governed-financial-data-${var.aws_account_id}"

  tags = {
    Framework      = "gera"
    NistControl    = "pr-aa-01"
    DataGovernance = "enabled"
  }
}

resource "aws_s3_bucket_versioning" "governed_financial_data" {
  bucket = aws_s3_bucket.governed_financial_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "governed_financial_data" {
  bucket = aws_s3_bucket.governed_financial_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "governed_financial_data" {
  bucket                  = aws_s3_bucket.governed_financial_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# Glue catalog database — equivalent to a BigQuery dataset
# ---------------------------------------------------------------------------

resource "aws_glue_catalog_database" "governed_financial_data" {
  name        = var.database_name
  description = "GERA governed financial reconciliation data with Lake Formation RLS"

  location_uri = "s3://${aws_s3_bucket.governed_financial_data.bucket}/"

  parameters = {
    framework       = "gera"
    nist_control    = "pr-aa-01"
    data_governance = "enabled"
  }
}

# ---------------------------------------------------------------------------
# Glue catalog table — reconciliation_results
# Equivalent to the BigQuery reconciliation_results table.
# sensitivity_level is the column used by Lake Formation row filters.
# ---------------------------------------------------------------------------

resource "aws_glue_catalog_table" "reconciliation_results" {
  database_name = aws_glue_catalog_database.governed_financial_data.name
  name          = "reconciliation_results"
  description   = "Cross-system reconciliation results with sensitivity labels"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification" = "parquet"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.governed_financial_data.bucket}/reconciliation_results/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    columns {
      name    = "record_id"
      type    = "string"
      comment = "Unique identifier for the reconciliation record"
    }
    columns {
      name    = "source_system"
      type    = "string"
      comment = "Originating system (e.g. ERP, CRM)"
    }
    columns {
      name    = "target_system"
      type    = "string"
      comment = "Destination system"
    }
    columns {
      name    = "match_status"
      type    = "string"
      comment = "MATCHED | UNMATCHED_SOURCE | UNMATCHED_TARGET | CONFLICT"
    }
    columns {
      name    = "amount_difference"
      type    = "double"
      comment = "Monetary difference between source and target"
    }
    columns {
      name    = "gate_decision"
      type    = "string"
      comment = "PASS | FLAG | BLOCK from the Z-score gate"
    }
    columns {
      name    = "z_score"
      type    = "double"
      comment = "Statistical anomaly score from Layer 2 validation"
    }
    columns {
      name    = "sensitivity_level"
      type    = "string"
      comment = "PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED — drives RLS filters"
    }
    columns {
      name    = "created_at"
      type    = "timestamp"
      comment = "Record creation timestamp (UTC)"
    }
  }
}

# ---------------------------------------------------------------------------
# Glue catalog table — user_attributes
# Stores per-user clearance levels, mirroring BigQuery user_attributes.
# Used as the ABAC lookup table for dynamic clearance evaluation.
# ---------------------------------------------------------------------------

resource "aws_glue_catalog_table" "user_attributes" {
  database_name = aws_glue_catalog_database.governed_financial_data.name
  name          = "user_attributes"
  description   = "User attribute table for ABAC row-level security"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification" = "parquet"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.governed_financial_data.bucket}/user_attributes/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    columns {
      name    = "user_arn"
      type    = "string"
      comment = "IAM principal ARN — equivalent to BigQuery user_email"
    }
    columns {
      name    = "role"
      type    = "string"
      comment = "Functional role (analyst | finance_lead | data_engineer | auditor)"
    }
    columns {
      name    = "department"
      type    = "string"
      comment = "Business unit or department name"
    }
    columns {
      name    = "sensitivity_clearance"
      type    = "string"
      comment = "Highest tier this user may access: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED"
    }
    columns {
      name    = "nist_label"
      type    = "string"
      comment = "Optional NIST CSF 2.0 control label for this user's access grant"
    }
  }
}

# ---------------------------------------------------------------------------
# Lake Formation — register S3 location
# Required before Lake Formation can manage permissions on the bucket.
# ---------------------------------------------------------------------------

resource "aws_lakeformation_resource" "governed_financial_data" {
  arn = aws_s3_bucket.governed_financial_data.arn
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "database_name" {
  description = "Glue catalog database name for the governed financial data"
  value       = aws_glue_catalog_database.governed_financial_data.name
}

output "s3_bucket_name" {
  description = "S3 bucket backing the governed financial data lake"
  value       = aws_s3_bucket.governed_financial_data.bucket
}

output "pipeline_role_arn" {
  description = "IAM role ARN used by the GERA reconciliation pipeline"
  value       = aws_iam_role.gera_pipeline.arn
}

output "analysts_group_name" {
  description = "IAM group name for GERA analysts"
  value       = aws_iam_group.gera_analysts.name
}

output "auditors_group_name" {
  description = "IAM group name for GERA compliance auditors"
  value       = aws_iam_group.gera_auditors.name
}
