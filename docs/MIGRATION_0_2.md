# Migration 0.2

## Before deploying

1. Stop accepting writes for the maintenance window. A schema migration is not safe with old and new application workers writing simultaneously.
2. Take a complete, verified database backup and rehearse restoration to a separate disposable database. See `OPERATIONS.md`. A post-closure round JSON export is not a full database backup.
3. Retain existing external round hashes and reviewer receipts outside the service. Do not regenerate or republish old contracts as 0.2.
4. Run the full suite against PostgreSQL, including `capsule.test_migration`, and the checklist in `TEST_CHECKLIST_0_2.md`.
5. Use the same persistent application secret and database. Do not rerun a fixture reset or rotate credentials as part of this schema migration.

## Apply

[needs Linux runner] Existing Django dependencies in `requirements-hosted.txt` are sufficient; there is no additional runtime package.

```sh
python manage.py migrate --plan
python manage.py migrate --noinput
python manage.py check
```

Migration `0003_roundsecrets_remove_round_withheld_and_more` creates `capsule_roundsecrets`, copies each existing round's withheld JSON into its corresponding private row, and only then removes the old column. New calibration metadata is stored in this private table, never the packet item. New columns add parent-version links, the publication URL/attestation time, protocol version, per-item receipts and audit chain hashes. Legacy events receive a chain based on their stored values; this does not retroactively prove chronology.

Every pre-existing round is marked protocol `0.1`, including existing drafts. Its state, packet, deadline, contract JSON, nonce, commitment, assignments, credentials and existing assessments remain unchanged. Legacy declarations, judgments, single-step freeze/open and no-peer-release policy remain in force for those rounds. Create a new study or linked correction to use protocol 0.2. Existing receipts retain their original schema and hash; their timestamp was not part of the original commitment and is not silently upgraded.

New protocol 0.2 rounds are `draft → frozen → open → closed`. Do not publish a private contract or receipt to satisfy the anchor step; publish only the round ID and commitment hash. The stored publication URL records author attestation, not independent verification.

## Verify after migration

- Confirm row counts for studies, rounds, assignments, assessments and private rows match expectations. Every round must have one private row.
- Recompute existing contracts; verify previously retained commitment hashes are unchanged. Old records do not gain new policy keys.
- Confirm old credentials still sign in and the hosted seed reports no records or credentials changed.
- Create a disposable new synthetic round; exercise freeze, external publication attestation, open, both reviewer locks, receipts and closure.
- Confirm feedback-only downloads omit labels and round exports omit feedback records/text.
- Confirm author exports redact calibration responses, steward reports include them only after closure, and reviewer payloads never flag calibration.

## Rollback

The migration has a tested reverse data-copy operation: it restores withheld JSON from the private table before restoring the old non-null field. Reversing the migration drops all 0.2-only metadata, receipts, calibration settings, parent links and publication details. Therefore reverse only before any new 0.2 records are accepted, and only with a verified full backup. After new writes, use a forward repair or restore the complete snapshot into an isolated database; do not casually reverse and discard new evidence.

The code deployment has not been applied to the hosted database as part of preparing this branch. The current Free database has no managed backup/recovery, so its persistence must not be confused with recoverability. See the current infrastructure limitations in `OPERATIONS.md`.
