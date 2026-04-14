# GERA Framework — Cloud Identity Groups for ABAC
#
# Defines the four user groups that map to GERA sensitivity clearance tiers.
# Each group is bound to a custom IAM role (see ../abac/main.tf) and granted
# access to the governed financial dataset via Row-Level Security policies
# (see rls_policies.tf).
#
# Prerequisites:
#   - Cloud Identity or Workspace with the Cloud Identity API enabled
#   - customer_id from Admin Console > Account > Account settings
#
# NIST CSF 2.0 Control: PR.AA-01 (Identities and credentials are managed)
#
# Usage:
#   terraform apply \
#     -var="project_id=my-project" \
#     -var="org_domain=example.com" \
#     -var="customer_id=C0abc1234"

# ---------------------------------------------------------------------------
# Variables — example member emails (one demo user per group)
# Replace these with real user emails or manage memberships outside Terraform.
# ---------------------------------------------------------------------------

variable "analyst_demo_user" {
  description = "Demo member email for the gera-analysts group"
  type        = string
  default     = "analyst.demo@example.com"
}

variable "finance_lead_demo_user" {
  description = "Demo member email for the gera-finance-leads group"
  type        = string
  default     = "finance-lead.demo@example.com"
}

variable "data_engineer_demo_user" {
  description = "Demo member email for the gera-data-engineers group"
  type        = string
  default     = "data-engineer.demo@example.com"
}

variable "auditor_demo_user" {
  description = "Demo member email for the gera-auditors group"
  type        = string
  default     = "auditor.demo@example.com"
}

# ---------------------------------------------------------------------------
# Cloud Identity Groups
#
# Clearance tiers (lowest → highest):
#   PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED
#
# Each group name maps directly to a sensitivity_clearance value stored in
# the user_attributes BigQuery table. RLS policies join on this value at
# query time via SESSION_USER().
# ---------------------------------------------------------------------------

resource "google_cloud_identity_group" "gera_analysts" {
  display_name         = "GERA Analysts"
  description          = "Read-only access to INTERNAL and PUBLIC reconciliation data. Typical members: business analysts, FP&A staff."
  initial_group_config = "EMPTY"

  parent = "customers/${var.customer_id}"

  group_key {
    id = "gera-analysts@${var.org_domain}"
  }

  labels = {
    "cloudidentity.googleapis.com/groups.discussion_forum" = ""
  }
}

resource "google_cloud_identity_group" "gera_finance_leads" {
  display_name         = "GERA Finance Leads"
  description          = "Read and export access to CONFIDENTIAL and below reconciliation data. Typical members: finance managers, controllers."
  initial_group_config = "EMPTY"

  parent = "customers/${var.customer_id}"

  group_key {
    id = "gera-finance-leads@${var.org_domain}"
  }

  labels = {
    "cloudidentity.googleapis.com/groups.discussion_forum" = ""
  }
}

resource "google_cloud_identity_group" "gera_data_engineers" {
  display_name         = "GERA Data Engineers"
  description          = "Read/write access to CONFIDENTIAL and below reconciliation data. Typical members: data pipeline engineers, ETL developers."
  initial_group_config = "EMPTY"

  parent = "customers/${var.customer_id}"

  group_key {
    id = "gera-data-engineers@${var.org_domain}"
  }

  labels = {
    "cloudidentity.googleapis.com/groups.discussion_forum" = ""
  }
}

resource "google_cloud_identity_group" "gera_auditors" {
  display_name         = "GERA Compliance Auditors"
  description          = "Full read access including RESTRICTED audit logs. Typical members: internal audit, SOX compliance officers, external auditors."
  initial_group_config = "EMPTY"

  parent = "customers/${var.customer_id}"

  group_key {
    id = "gera-auditors@${var.org_domain}"
  }

  labels = {
    "cloudidentity.googleapis.com/groups.discussion_forum" = ""
  }
}

# ---------------------------------------------------------------------------
# Group Memberships — demo users
#
# In production, manage memberships via your identity provider (IdP) sync or
# HR system integration rather than Terraform, to avoid drift.
# ---------------------------------------------------------------------------

resource "google_cloud_identity_group_membership" "analyst_demo" {
  group = google_cloud_identity_group.gera_analysts.id

  preferred_member_key {
    id = var.analyst_demo_user
  }

  roles {
    name = "MEMBER"
  }
}

resource "google_cloud_identity_group_membership" "finance_lead_demo" {
  group = google_cloud_identity_group.gera_finance_leads.id

  preferred_member_key {
    id = var.finance_lead_demo_user
  }

  roles {
    name = "MEMBER"
  }
}

resource "google_cloud_identity_group_membership" "data_engineer_demo" {
  group = google_cloud_identity_group.gera_data_engineers.id

  preferred_member_key {
    id = var.data_engineer_demo_user
  }

  roles {
    name = "MEMBER"
  }
}

resource "google_cloud_identity_group_membership" "auditor_demo" {
  group = google_cloud_identity_group.gera_auditors.id

  preferred_member_key {
    id = var.auditor_demo_user
  }

  roles {
    name = "MEMBER"
  }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "analysts_group_id" {
  description = "Resource ID of the gera-analysts Cloud Identity group"
  value       = google_cloud_identity_group.gera_analysts.id
}

output "auditors_group_id" {
  description = "Resource ID of the gera-auditors Cloud Identity group"
  value       = google_cloud_identity_group.gera_auditors.id
}
