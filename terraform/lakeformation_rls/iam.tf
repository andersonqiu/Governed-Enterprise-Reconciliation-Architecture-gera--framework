# GERA Framework — IAM Roles & Lake Formation Database Permissions (AWS)
#
# AWS equivalent of ../bigquery_rls/iam.tf.
# Wires IAM groups to the Glue database and provisions a dedicated IAM role
# for the GERA reconciliation pipeline.
#
# Layer overview:
#   1. IAM groups get an inline policy allowing Athena queries + S3 read.
#      This is the "floor" permission — Lake Formation data cells filters
#      (rls_policies.tf) further restrict which rows are visible.
#   2. The pipeline IAM role gets S3 read/write + Glue catalog access so
#      the Python reconciliation framework can write results.
#   3. Lake Formation database-level SELECT is granted to each group,
#      enabling Athena queries against the Glue catalog.
#
# Cross-module note:
#   The custom IAM managed policies referenced below mirror the ABAC roles
#   in ../abac/main.tf. Those roles are GCP-specific; the policies here
#   are the AWS equivalent, defined inline for self-containment.
#
# NIST CSF 2.0 Controls: PR.AA-01 (Access control), PR.AA-05 (Least privilege)

# ---------------------------------------------------------------------------
# Pipeline IAM role
# Assumed by the GERA Python framework running on EC2, ECS, or Lambda.
# ---------------------------------------------------------------------------

resource "aws_iam_role" "gera_pipeline" {
  name        = "${var.org_name}-reconciliation-pipeline"
  description = "Assumed by the GERA reconciliation pipeline to write results to the governed data lake."
  path        = "/gera/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
      # Also allow ECS tasks and Lambda to assume this role.
      {
        Effect    = "Allow"
        Principal = { Service = "ecs-tasks.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Framework   = "gera"
    NistControl = "pr-aa-05"
  }
}

# Pipeline role: read/write access to the governed S3 bucket.
resource "aws_iam_role_policy" "pipeline_s3" {
  name = "gera-pipeline-s3"
  role = aws_iam_role.gera_pipeline.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ReadWrite"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.governed_financial_data.arn,
          "${aws_s3_bucket.governed_financial_data.arn}/*",
        ]
      }
    ]
  })
}

# Pipeline role: Glue catalog read/write for table metadata.
resource "aws_iam_role_policy" "pipeline_glue" {
  name = "gera-pipeline-glue"
  role = aws_iam_role.gera_pipeline.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GlueCatalogReadWrite"
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetTables",
          "glue:BatchCreatePartition",
          "glue:CreatePartition",
          "glue:UpdatePartition",
        ]
        Resource = "*"
      }
    ]
  })
}

# Pipeline role: submit Athena queries for verification reads.
resource "aws_iam_role_policy" "pipeline_athena" {
  name = "gera-pipeline-athena"
  role = aws_iam_role.gera_pipeline.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AthenaQuery"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
        ]
        Resource = "*"
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# IAM group policies — Athena + S3 read (floor permissions)
#
# These policies allow group members to run Athena queries and read from S3.
# Actual row visibility is controlled by Lake Formation data cells filters.
# ---------------------------------------------------------------------------

resource "aws_iam_group_policy" "analysts_query" {
  name  = "gera-analysts-query"
  group = aws_iam_group.gera_analysts.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AthenaQuery"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
        ]
        Resource = "*"
      },
      {
        Sid    = "S3Read"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.governed_financial_data.arn,
          "${aws_s3_bucket.governed_financial_data.arn}/*",
        ]
      }
    ]
  })
}

resource "aws_iam_group_policy" "finance_leads_query" {
  name  = "gera-finance-leads-query"
  group = aws_iam_group.gera_finance_leads.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AthenaQuery"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:GetWorkGroup",
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ReadExport"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]
        Resource = [
          aws_s3_bucket.governed_financial_data.arn,
          "${aws_s3_bucket.governed_financial_data.arn}/*",
        ]
      }
    ]
  })
}

resource "aws_iam_group_policy" "data_engineers_query" {
  name  = "gera-data-engineers-query"
  group = aws_iam_group.gera_data_engineers.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AthenaQuery"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ReadWrite"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket", "s3:PutObject", "s3:DeleteObject"]
        Resource = [
          aws_s3_bucket.governed_financial_data.arn,
          "${aws_s3_bucket.governed_financial_data.arn}/*",
        ]
      },
      {
        Sid    = "GlueRead"
        Effect = "Allow"
        Action = ["glue:GetDatabase", "glue:GetTable", "glue:GetTables"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_group_policy" "auditors_query" {
  name  = "gera-auditors-query"
  group = aws_iam_group.gera_auditors.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AthenaQuery"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:ListWorkGroups",
        ]
        Resource = "*"
      },
      {
        Sid    = "S3FullRead"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.governed_financial_data.arn,
          "${aws_s3_bucket.governed_financial_data.arn}/*",
        ]
      },
      {
        Sid    = "GlueRead"
        Effect = "Allow"
        Action = ["glue:GetDatabase", "glue:GetTable", "glue:GetTables", "glue:GetPartitions"]
        Resource = "*"
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Lake Formation database-level permissions
#
# Grants each group DESCRIBE on the Glue database so Athena can enumerate
# tables. Row-level visibility is still enforced by the data cells filters
# in rls_policies.tf — database DESCRIBE alone does not expose row data.
# ---------------------------------------------------------------------------

resource "aws_lakeformation_permissions" "analysts_db" {
  principal = aws_iam_group.gera_analysts.arn

  database {
    catalog_id = var.aws_account_id
    name       = local.db
  }

  permissions = ["DESCRIBE"]
}

resource "aws_lakeformation_permissions" "finance_leads_db" {
  principal = aws_iam_group.gera_finance_leads.arn

  database {
    catalog_id = var.aws_account_id
    name       = local.db
  }

  permissions = ["DESCRIBE"]
}

resource "aws_lakeformation_permissions" "data_engineers_db" {
  principal = aws_iam_group.gera_data_engineers.arn

  database {
    catalog_id = var.aws_account_id
    name       = local.db
  }

  permissions = ["DESCRIBE", "CREATE_TABLE", "ALTER"]
}

resource "aws_lakeformation_permissions" "auditors_db" {
  principal = aws_iam_group.gera_auditors.arn

  database {
    catalog_id = var.aws_account_id
    name       = local.db
  }

  permissions = ["DESCRIBE"]
}

resource "aws_lakeformation_permissions" "pipeline_db" {
  principal = aws_iam_role.gera_pipeline.arn

  database {
    catalog_id = var.aws_account_id
    name       = local.db
  }

  permissions = ["DESCRIBE", "CREATE_TABLE", "ALTER"]
}
