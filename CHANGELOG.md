# 0.2 iteration candidate — 2026-11-01

- Add separate private material table, preserving legacy contracts/receipts through migration.
- New rounds freeze before an external-publication attestation and opening; corrections link new versions.
- Add timestamped per-item receipts and an a-Shell-compatible verifier.
- Add relationship/stake declarations, optional username credit consent, five judgments and steward-only calibration reports.
- Add chained append-only application audit events, calibration redaction and disjoint feedback exports.
- Improve mobile header, JSON placeholders/height, reviewer rows, UTC picker and hash copying.
- Supply migration, backup limits and acceptance checklist. Candidate is not deployed.

## v0.1.1 — synthetic deployment candidate

- Add Gunicorn/WSGI, Docker packaging and Railway health configuration.
- Add explicit synthetic hosted setup that never resets existing judgments on restart.
- Add a persistent demo notice, host/origin settings and proxy HTTPS configuration.
- Add database-backed sign-in rate limits and five hosting tests.
- Include a PostgreSQL GitHub Actions verification workflow; not run here.
- Owner authorized synthetic demo hosting; repository-based deployment is being prepared.

# Changelog

## 0.1.0-local — November 1, 2026

First local prototype: protected evidence-support round with author/reviewer/steward roles, frozen packet/roster/deadline, declaration and admission, locked assessment, amendment, private salted receipt, whole-round closure, exposure history and private export. Separate post-round feedback records.

Validation: 15 automated Django tests passed with SQLite; Django system checks and migration consistency passed. No browser QA, PostgreSQL concurrency qualification, independent security review, real reviewer pilot, GitHub publication or hosted deployment.
