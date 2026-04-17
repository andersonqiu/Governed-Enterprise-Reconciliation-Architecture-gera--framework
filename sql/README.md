# GERA Framework — SQL DDL

Reference table definitions for the GERA Framework, provided in two dialects so
each row-level-security Terraform module has real, documented schemas to attach
policies to:

| Dialect       | Directory          | Target                                           | Aligned Terraform module          |
| ------------- | ------------------ | ------------------------------------------------ | --------------------------------- |
| BigQuery SQL  | [`bigquery/`](bigquery/) | GCP BigQuery (standard SQL)                     | `terraform/bigquery_rls/`         |
| Athena DDL    | [`athena/`](athena/)   | AWS Athena / Glue catalog (external tables over S3, Parquet) | `terraform/lakeformation_rls/`    |

Both dialects expose the same logical schema — column names, types, and
semantics are deliberately identical so that a cross-cloud audit produces
identical query results. Only storage, partitioning, and dialect-specific
features differ.

**One intentional exception:** `user_attributes.user_email` (BigQuery) vs
`user_attributes.user_arn` (Athena / Glue). GCP federates identity by email
address, AWS by IAM ARN — using each cloud's native principal format keeps
the ABAC row-access policies idiomatic on both platforms. All other columns
in `user_attributes` (`role`, `department`, `sensitivity_clearance`,
`nist_label`) are identical across dialects.

## Tables

Each table corresponds to a Python dataclass in the `gera` package. Column
names match the dataclass field names one-for-one so that a row can be
round-tripped between the runtime and the warehouse without translation.

| File                                     | Table                      | Python counterpart                                           |
| ---------------------------------------- | -------------------------- | ------------------------------------------------------------ |
| `01_audit_log.sql`                       | `audit_log`                | `gera.governance.AuditEvent`                                 |
| `02_semantic_registry.sql`               | `semantic_registry`        | `gera.governance.MetricDefinition`                           |
| `03_reconciliation_results.sql`          | `reconciliation_results`   | `gera.reconciliation.MatchResult` (+ Z-score decision)       |
| `04_exceptions_queue.sql`                | `exceptions_queue`         | `gera.reconciliation.GERAException`                          |
| `05_zscore_anomalies.sql`                | `zscore_anomalies`         | `gera.validation.Anomaly`                                    |
| `views/v_audit_chain_verification.sql`   | view                       | `gera.governance.AuditLogger.verify_chain()`                 |

The `reconciliation_results` table is also declared inside
`terraform/bigquery_rls/main.tf` and `terraform/lakeformation_rls/main.tf`
because the RLS policies need the schema at plan time; the DDL here is the
authoritative definition and should be kept in sync if the schema changes.

## Dialect mapping

| Concept                 | BigQuery                                              | Athena / Glue                                                     |
| ----------------------- | ----------------------------------------------------- | ----------------------------------------------------------------- |
| Timestamp               | `TIMESTAMP`                                           | `TIMESTAMP` (stored as Parquet INT96 or Iceberg)                  |
| Floating amount         | `FLOAT64`                                             | `DOUBLE`                                                          |
| String                  | `STRING`                                              | `STRING` (Parquet) / `VARCHAR` (Iceberg)                          |
| JSON payload            | `JSON`                                                | `STRING` (JSON-serialized) — Athena JSON functions parse at read  |
| Array                   | `ARRAY<STRING>`                                       | `ARRAY<STRING>`                                                   |
| Partition by date       | `PARTITION BY DATE(timestamp)`                        | `PARTITIONED BY (event_date STRING)` + partition projection       |
| Retention (7 yr / SOX)  | `OPTIONS(partition_expiration_days=2555)`             | S3 lifecycle rule on the `audit_log/` prefix (outside DDL)        |
| Row-level security      | `CREATE ROW ACCESS POLICY`                            | Lake Formation `aws_lakeformation_data_cells_filter`              |
| Primary key enforcement | `PRIMARY KEY ... NOT ENFORCED` (advisory only)        | Not supported — enforced at write time by the pipeline            |
| Hash-chain verification | `WINDOW` function view                                | Same `WINDOW` function view, Presto SQL compatible                |

## Running the DDL

### BigQuery

```bash
# With the bq CLI (requires gcloud auth and a target dataset)
bq query --use_legacy_sql=false --project_id="$GCP_PROJECT" \
  < sql/bigquery/01_audit_log.sql
```

Replace `${dataset}` with the dataset created by `terraform/bigquery_rls/`
(defaults to `governed_financial_data`).

### Athena

```bash
# Using AWS CLI
aws athena start-query-execution \
  --query-string "$(cat sql/athena/01_audit_log.sql)" \
  --result-configuration OutputLocation="s3://${athena_results_bucket}/" \
  --query-execution-context Database="${database}"
```

Replace `${database}` with the Glue database created by
`terraform/lakeformation_rls/` (defaults to `gera_financial_data`) and
`${bucket}` placeholders with the S3 bucket it created.

## Portability notes

Porting to PostgreSQL or Snowflake is straightforward — replace:

- `PARTITION BY DATE(timestamp)` → PostgreSQL: native range partitioning; Snowflake: `CLUSTER BY (DATE(timestamp))`
- `JSON` type → PostgreSQL `JSONB`; Snowflake `VARIANT`
- `ARRAY<STRING>` → PostgreSQL `TEXT[]`; Snowflake `ARRAY`
- `OPTIONS(partition_expiration_days=2555)` → scheduled `DELETE` job or Snowflake's data retention policy

The logical schema (column names and semantics) is dialect-neutral.
