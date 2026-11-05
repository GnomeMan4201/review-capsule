# Review Capsule 0.2 iteration

Implementation candidate for the requested iteration. This branch is separate from the running demo; deployment and hosted migration have not been performed for this iteration.

## Changed files

| Files | Change |
| --- | --- |
| `capsule/forms.py`, `templates/capsule/form.html` | Empty JSON fields with schema placeholders; server validation; add/remove reviewer rows; future UTC datetime picker; relationship/stake/exposure declaration and optional username credit consent |
| `capsule/templates/capsule/base.html`, `capsule/assets/enhancements.js`, `capsule/middleware.py` | Single-row mobile header with truncation, banner spacing, bounded textareas, progressive Copy button; same-origin external script only; inline scripts remain disallowed |
| `capsule/models.py`, migration `0003_*` | Separate private results/calibration table; linked versions and protocol marker; timestamped item receipts; append-only assessment/amendment/event ORM APIs; chained audit hashes |
| `capsule/services.py` | Freeze → publication attestation → open; frozen-content guards; per-item receipts; new judgment choices; calibration filtering; post-closure peer access |
| `capsule/views.py`, `config/urls.py`, desk/review/receipt/home templates | Role-limited reports, linked correction form, external hash anchor form, typed separate exports |
| `capsule/management/commands/demo.py`, `hosted_demo.py` | New synthetic fixtures use 0.2 judgments; initial seeding adds an audit event; existing seed remains unchanged |
| `scripts/verify_receipt.py` | Read-only Python stdlib receipt verifier, including bound timestamp checks; usable in a-Shell |
| `capsule/tests.py`, `test_iteration.py`, `test_migration.py` | Legacy boundaries, new flow, calibration canaries, feedback separation, hash consistency/tampering, immutability and migration preservation |
| `docs/MIGRATION_0_2.md`, `docs/TEST_CHECKLIST_0_2.md`, `docs/OPERATIONS.md` | Migration, restore/backup limitations and manual acceptance checklist |

## Protocol decisions

New rounds use contract schema 0.2. Freezing locks the packet, roster, deadline, role IDs, policy, private-material commitments and parent version. The frozen round cannot accept declarations or packets until the author records an external HTTPS publication URL and attests that the exact hash was published. The app does not fetch the URL or verify its content/time. Independent publication is a human action; a stored URL is not proof of witnessing.

Corrections create a new draft version in the same study, linked to the earlier round. Earlier rounds remain intact and keep their state. If a reviewer has another frozen/open round in that study, result and peer-work release are blocked. A correction is not a way to reset exposure history.

Each new locked item has SHA-256 over the exact object `{round_id, reviewer, item_id, judgment, reasoning, timestamp}`. `reviewer` is the internal account ID, not a verified human identity. Encoding is canonical compact JSON: sorted keys, UTF-8, literal Unicode, no NaN. Downloaded complete receipts include the payload and hash; the enclosing salted assessment commitment also binds the item receipts. These are private consistency receipts, not trusted timestamps. Compare a retained copy with later downloads to detect a change.

No calibration marker or expected answer is sent with reviewer packets. Calibration answers/receipts are excluded from author reports and author exports; the author receives a deliberately redacted receipt and cannot recompute the full aggregate commitment from that redaction. The steward's closed-round export is complete. Reviewer-owned receipts retain all their own items without flagging calibration status. Peer-work and reviewer-results endpoints omit calibration responses/labels. Do not place calibration answers inside free-form notice prose; the tool cannot identify semantic leaks.

Feedback has a separate table and a feedback-only export. Round exports contain no feedback text or feedback records. Audit events can record that a feedback action occurred using its record ID, without copying feedback text into the audit table.

The audit log covers application workflow mutations and export downloads. Events bind actor account, action, detail, server timestamp and previous-event hash. Application saves, queryset updates and deletion are blocked for existing audit events. Existing events are chained during migration; that chain begins at migration, not at the original time of an independently witnessed event. Raw SQL, database-owner access and infrastructure console actions are outside this application boundary. A privileged operator can still replace records or truncate a chain; externally retain chain heads and database audit logs if stronger operator accountability is required.

Kill criterion: if independent developers cannot complete a synthetic declaration → assessment → receipt flow without coaching, simplify the workflow or narrow this project to a packet/export adapter before collecting real reviews.

## Verification status

42 Django tests passed locally on Python 3.12 / SQLite, including migration forward/reverse preservation and receipt tampering checks. `manage.py check` and `makemigrations --check --dry-run` passed. PostgreSQL CI and mobile browser acceptance for this iteration must be reported separately from local results. The synthetic live demo remains on its existing version until this change is reviewed and deployed.
