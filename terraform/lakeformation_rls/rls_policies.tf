# GERA Framework — Lake Formation Data Cells Filters (Row-Level Security)
#
# AWS equivalent of ../bigquery_rls/rls_policies.tf.
# Applies four data cells filters to the reconciliation_results table,
# one per sensitivity tier. Lake Formation evaluates ALL filters that match
# the querying principal — a row is visible if ANY matching filter allows it.
#
# AWS mapping:
#   google_bigquery_row_access_policy → aws_lakeformation_data_cells_filter
#                                       + aws_lakeformation_permissions
#
# Clearance hierarchy (cumulative — higher clearance includes lower tiers):
#
#   PUBLIC       → all four groups
#   INTERNAL     → all four groups (analysts see PUBLIC + INTERNAL)
#   CONFIDENTIAL → finance-leads, data-engineers, auditors
#   RESTRICTED   → auditors only (no row filter — sees all rows)
#
# NIST CSF 2.0 Controls: PR.AA-01 (Access control), PR.DS-01 (Data-at-rest)

locals {
  db   = aws_glue_catalog_database.governed_financial_data.name
  tbl  = aws_glue_catalog_table.reconciliation_results.name
}

# ---------------------------------------------------------------------------
# Filter 1 — PUBLIC rows
# Principals: all four groups
# Row expression: sensitivity_level = 'PUBLIC'
# ---------------------------------------------------------------------------

resource "aws_lakeformation_data_cells_filter" "rls_public" {
  table_data {
    catalog_id    = var.aws_account_id
    database_name = local.db
    table_name    = local.tbl
    name          = "rls_public"

    row_filter {
      filter_expression = "sensitivity_level = 'PUBLIC'"
    }

    # No column exclusions — all columns visible within the allowed rows.
    column_wildcard {}
  }
}

# ---------------------------------------------------------------------------
# Filter 2 — INTERNAL rows
# Principals: all four groups (analysts have INTERNAL clearance)
# Combined with filter 1, analysts see: PUBLIC + INTERNAL rows.
# ---------------------------------------------------------------------------

resource "aws_lakeformation_data_cells_filter" "rls_internal" {
  table_data {
    catalog_id    = var.aws_account_id
    database_name = local.db
    table_name    = local.tbl
    name          = "rls_internal"

    row_filter {
      filter_expression = "sensitivity_level = 'INTERNAL'"
    }

    column_wildcard {}
  }
}

# ---------------------------------------------------------------------------
# Filter 3 — CONFIDENTIAL rows
# Principals: finance-leads, data-engineers, auditors (analysts excluded)
# Combined with filters 1 & 2, finance-leads and data-engineers see:
# PUBLIC + INTERNAL + CONFIDENTIAL rows.
# ---------------------------------------------------------------------------

resource "aws_lakeformation_data_cells_filter" "rls_confidential" {
  table_data {
    catalog_id    = var.aws_account_id
    database_name = local.db
    table_name    = local.tbl
    name          = "rls_confidential"

    row_filter {
      filter_expression = "sensitivity_level = 'CONFIDENTIAL'"
    }

    column_wildcard {}
  }
}

# ---------------------------------------------------------------------------
# Filter 4 — RESTRICTED (all rows)
# Principals: auditors only, pipeline service role
#
# all_rows_wildcard is equivalent to BigQuery's TRUE predicate — no row
# filter is applied, so auditors can read every row regardless of
# sensitivity_level.
# ---------------------------------------------------------------------------

resource "aws_lakeformation_data_cells_filter" "rls_restricted" {
  table_data {
    catalog_id    = var.aws_account_id
    database_name = local.db
    table_name    = local.tbl
    name          = "rls_restricted"

    row_filter {
      # all_rows_wildcard means no row-level filter — principal sees all rows.
      all_rows_wildcard {}
    }

    column_wildcard {}
  }
}

# ---------------------------------------------------------------------------
# Lake Formation permissions — bind filters to IAM group principals
#
# Each aws_lakeformation_permissions block grants a specific IAM group the
# right to use one data cells filter. Lake Formation resolves the IAM group
# ARN at query time to the calling user's group memberships.
# ---------------------------------------------------------------------------

# — PUBLIC filter grants —

resource "aws_lakeformation_permissions" "analysts_public" {
  principal = aws_iam_group.gera_analysts.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_public.table_data[0].name
  }

  permissions = ["SELECT"]
}

resource "aws_lakeformation_permissions" "finance_leads_public" {
  principal = aws_iam_group.gera_finance_leads.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_public.table_data[0].name
  }

  permissions = ["SELECT"]
}

resource "aws_lakeformation_permissions" "data_engineers_public" {
  principal = aws_iam_group.gera_data_engineers.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_public.table_data[0].name
  }

  permissions = ["SELECT"]
}

resource "aws_lakeformation_permissions" "auditors_public" {
  principal = aws_iam_group.gera_auditors.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_public.table_data[0].name
  }

  permissions = ["SELECT"]
}

# — INTERNAL filter grants —

resource "aws_lakeformation_permissions" "analysts_internal" {
  principal = aws_iam_group.gera_analysts.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_internal.table_data[0].name
  }

  permissions = ["SELECT"]
}

resource "aws_lakeformation_permissions" "finance_leads_internal" {
  principal = aws_iam_group.gera_finance_leads.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_internal.table_data[0].name
  }

  permissions = ["SELECT"]
}

resource "aws_lakeformation_permissions" "data_engineers_internal" {
  principal = aws_iam_group.gera_data_engineers.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_internal.table_data[0].name
  }

  permissions = ["SELECT"]
}

resource "aws_lakeformation_permissions" "auditors_internal" {
  principal = aws_iam_group.gera_auditors.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_internal.table_data[0].name
  }

  permissions = ["SELECT"]
}

# — CONFIDENTIAL filter grants (analysts excluded) —

resource "aws_lakeformation_permissions" "finance_leads_confidential" {
  principal = aws_iam_group.gera_finance_leads.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_confidential.table_data[0].name
  }

  permissions = ["SELECT"]
}

resource "aws_lakeformation_permissions" "data_engineers_confidential" {
  principal = aws_iam_group.gera_data_engineers.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_confidential.table_data[0].name
  }

  permissions = ["SELECT"]
}

resource "aws_lakeformation_permissions" "auditors_confidential" {
  principal = aws_iam_group.gera_auditors.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_confidential.table_data[0].name
  }

  permissions = ["SELECT"]
}

# — RESTRICTED filter grants (auditors + pipeline role only) —

resource "aws_lakeformation_permissions" "auditors_restricted" {
  principal = aws_iam_group.gera_auditors.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_restricted.table_data[0].name
  }

  permissions = ["SELECT"]
}

resource "aws_lakeformation_permissions" "pipeline_restricted" {
  principal = aws_iam_role.gera_pipeline.arn

  data_cells_filter {
    database_name = local.db
    table_name    = local.tbl
    name          = aws_lakeformation_data_cells_filter.rls_restricted.table_data[0].name
  }

  permissions = ["SELECT", "INSERT", "DELETE", "DESCRIBE"]
}
