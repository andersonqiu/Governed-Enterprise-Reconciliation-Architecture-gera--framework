# GERA Framework — IAM Groups for ABAC (AWS)
#
# Defines the four IAM groups that map to GERA sensitivity clearance tiers,
# mirroring the Cloud Identity groups in ../bigquery_rls/groups.tf.
#
# AWS mapping:
#   Cloud Identity group     → aws_iam_group
#   Cloud Identity membership → aws_iam_user_group_membership
#
# Each group is granted Lake Formation permissions in iam.tf and is listed
# as a principal in the data cells filter policies in rls_policies.tf.
#
# NIST CSF 2.0 Control: PR.AA-01 (Identities and credentials are managed)

# ---------------------------------------------------------------------------
# Variables — demo IAM user names (one per group)
# Replace with real usernames or manage memberships outside Terraform.
# ---------------------------------------------------------------------------

variable "analyst_demo_user" {
  description = "Demo IAM username for the gera-analysts group"
  type        = string
  default     = "analyst-demo"
}

variable "finance_lead_demo_user" {
  description = "Demo IAM username for the gera-finance-leads group"
  type        = string
  default     = "finance-lead-demo"
}

variable "data_engineer_demo_user" {
  description = "Demo IAM username for the gera-data-engineers group"
  type        = string
  default     = "data-engineer-demo"
}

variable "auditor_demo_user" {
  description = "Demo IAM username for the gera-auditors group"
  type        = string
  default     = "auditor-demo"
}

# ---------------------------------------------------------------------------
# IAM Groups
#
# Clearance tiers (lowest → highest):
#   PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED
# ---------------------------------------------------------------------------

resource "aws_iam_group" "gera_analysts" {
  name = "${var.org_name}-analysts"
  path = "/gera/"
}

resource "aws_iam_group" "gera_finance_leads" {
  name = "${var.org_name}-finance-leads"
  path = "/gera/"
}

resource "aws_iam_group" "gera_data_engineers" {
  name = "${var.org_name}-data-engineers"
  path = "/gera/"
}

resource "aws_iam_group" "gera_auditors" {
  name = "${var.org_name}-auditors"
  path = "/gera/"
}

# ---------------------------------------------------------------------------
# Demo IAM users
#
# These exist only to demonstrate group membership. In production, federate
# with your IdP (Okta, Azure AD, etc.) via IAM Identity Center instead of
# creating IAM users directly.
# ---------------------------------------------------------------------------

resource "aws_iam_user" "analyst_demo" {
  name = var.analyst_demo_user
  path = "/gera/demo/"

  tags = {
    Framework           = "gera"
    SensitivityClearance = "INTERNAL"
    Department          = "Finance"
  }
}

resource "aws_iam_user" "finance_lead_demo" {
  name = var.finance_lead_demo_user
  path = "/gera/demo/"

  tags = {
    Framework           = "gera"
    SensitivityClearance = "CONFIDENTIAL"
    Department          = "Finance"
  }
}

resource "aws_iam_user" "data_engineer_demo" {
  name = var.data_engineer_demo_user
  path = "/gera/demo/"

  tags = {
    Framework           = "gera"
    SensitivityClearance = "CONFIDENTIAL"
    Department          = "Engineering"
  }
}

resource "aws_iam_user" "auditor_demo" {
  name = var.auditor_demo_user
  path = "/gera/demo/"

  tags = {
    Framework           = "gera"
    SensitivityClearance = "RESTRICTED"
    Department          = "Compliance"
  }
}

# ---------------------------------------------------------------------------
# Group memberships
# ---------------------------------------------------------------------------

resource "aws_iam_user_group_membership" "analyst_demo" {
  user   = aws_iam_user.analyst_demo.name
  groups = [aws_iam_group.gera_analysts.name]
}

resource "aws_iam_user_group_membership" "finance_lead_demo" {
  user   = aws_iam_user.finance_lead_demo.name
  groups = [aws_iam_group.gera_finance_leads.name]
}

resource "aws_iam_user_group_membership" "data_engineer_demo" {
  user   = aws_iam_user.data_engineer_demo.name
  groups = [aws_iam_group.gera_data_engineers.name]
}

resource "aws_iam_user_group_membership" "auditor_demo" {
  user   = aws_iam_user.auditor_demo.name
  groups = [aws_iam_group.gera_auditors.name]
}
