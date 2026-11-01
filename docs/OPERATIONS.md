# Storage, backups and audit operations

## Current synthetic hosting

Application records use managed PostgreSQL through the internal `DATABASE_URL`; production settings reject local SQLite. Restarting/redeploying the web container does not deliberately reset account, study or assessment records. No durable records belong on the web service's ephemeral filesystem. Packet rows and withheld/calibration rows are separate database tables, with server-side role controls; this is not cryptographic separation from the database operator.

As configured November 1, 2026, the Render database uses the Free compute plan and expires December 1, 2026. There is **no managed recovery or automatic logical backup on Free**. No backup job, paid upgrade, network allowlist change or recovery guarantee has been enabled by this iteration. Persistence is not a backup. The live service is a synthetic demonstration, not qualified storage for research records.

Current official references, checked November 1, 2026:

- [Render recovery and backups](https://render.com/docs/postgresql-backups): Free databases lack recovery and automatic logical exports. Paid compute supports recovery; retention depends on the workspace plan.
- [Render Free limitations](https://render.com/docs/free): web filesystem is ephemeral, Postgres is separate persistent storage, Free Postgres expires after 30 days, and Free web services do not offer shell/one-off-job access.

## Backup procedure for a qualified deployment

Before real records, migrations or any destructive maintenance, arrange a complete database backup from an authorized Linux runner with internal network access, or enable appropriate paid database recovery. Native PostgreSQL client tools are required for `pg_dump` and `pg_restore`; these are not a-Shell stdlib commands. Free web shell access is unavailable, so do not pretend a manual shell backup has run on the current service.

1. Use PostgreSQL client tools matching the database major version. Provide connection values through a protected environment/secret mechanism, not committed files, terminal screenshots or command-line URLs containing passwords.
2. On an already authorized internal runner, run `pg_dump --format=custom --no-owner --no-acl --file=backup.dump` using protected `PGHOST`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`, `PGPORT`, `PGSSLMODE` configuration. Restrict file permissions before writing. Do not open database external access just to make this convenient.
3. Compute SHA-256, encrypt the backup, and copy it to durable off-service storage with explicit access control and retention. Record backup time, source database identity, schema migration head and checksum outside the app. Do not upload a private database dump to public GitHub Actions artifacts or this public repository.
4. Restore to an empty isolated database with `pg_restore --no-owner --no-acl --dbname=isolated_restore backup.dump` using protected environment values. Never point the test restore at the source database. A full dump includes accounts, sessions, exposure history and audit records; protect it as sensitive data.
5. Run database readiness, application integrity checks, counts and retained round/receipt hash comparisons against the restored copy. A successful dump command alone is not a restore test. Define and rehearse the recovery window and retention policy before collecting research reviews.

Closed-round JSON exports are portable records, not backups: they omit credentials, sessions, live drafts and other tables, and the author version omits private calibration responses. Feedback-only exports deliberately omit adjudicated material. These exports must remain separate even when both are retained by the operator.

## Audit boundary

The application appends chained Event records for round creation, freeze/open, correction links, declarations, eligibility, assessment lock/amendment, exposure, closure, feedback and downloads. Each event uses canonical JSON SHA-256 over round ID, actor account, kind, detail, server timestamp and previous hash. Initial assessments and audit events reject existing-row saves, queryset updates and deletes; raw SQL/database-owner modifications remain possible.

Infrastructure changes, Render console actions, direct database commands and credential operations are not automatically observed by the app. Retain infrastructure/provider audit logs and record maintenance outside the data being maintained. Periodically retain database snapshots and chain heads externally if stronger detection is required. Do not include passwords, connection URLs, private answers or leaked labels in maintenance logs or public anchors.

Shared synthetic demo credentials must not be reused for a real deployment. Credential rotation must update account password hashes deliberately: changing `CAPSULE_DEMO_PASSWORD` alone does not reset existing accounts. The hosted seed intentionally does not overwrite them. No credential rotation is part of this schema migration.
