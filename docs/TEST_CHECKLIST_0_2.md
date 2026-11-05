# Freeze / lock / receipt acceptance checklist

Use synthetic content and separate role sessions. Preserve all failures and do not overwrite the running demo's frozen round to test a new policy.

## Automated Linux checks

```sh
python -m pip install -r requirements-hosted.txt
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test -v 2
```

The existing GitHub Actions workflow runs these against PostgreSQL 16 and uploads `verification-log`. Local SQLite results do not establish PostgreSQL concurrency behavior. Simultaneous close/submit and cross-round release still need production qualification.

## Author preparation and mobile UI

- [ ] At iPhone portrait width, logo, username and Sign out share one row; long usernames truncate without horizontal overflow.
- [ ] Banner and eyebrow have visible vertical separation.
- [ ] JSON boxes start empty; schema appears as placeholder only. About twelve visible lines, internal scroll; Save stays reachable.
- [ ] Add a reviewer row; remove a row with its Delete checkbox; save retains at least two unique existing accounts and rejects author/steward overlap.
- [ ] UTC picker shows UTC labeling. Past deadlines and invalid dates fail on the server, not just in the browser.
- [ ] Malformed JSON, duplicate item IDs and `expected`, `answer`, `label`, `key` (including altered case) inside packet items fail to save. Extra/nested object keys also fail the allowlist.
- [ ] Add a hidden calibration item through the private map. Its expected judgment matches the new enum; unknown item IDs fail.

## Freeze and publication

- [ ] Freeze produces a 64-character commitment and `frozen` state. Reviewer declaration/packet endpoints remain blocked.
- [ ] Copy button copies only the exact hash. If clipboard API is unavailable, text is selected for manual copy.
- [ ] Publish hash + round ID to a GitHub commit or post outside the app; retain the permalink.
- [ ] Opening without the checked publication attestation, without a URL, with HTTP or with a same-site demo URL fails.
- [ ] Author records the external HTTPS permalink, attests publication and opens. Steward/reviewer cannot open. Hash remains identical.
- [ ] Frozen packet, private material, roster, deadline and policy writes/deletes fail through application ORM entry points. The old round remains intact when a linked correction version is prepared.

## Reviewer declaration and lock

- [ ] Relationship, stake, prior exposure and AI evaluation are explicit yes/no questions. Username credit consent is optional.
- [ ] Packet stays blocked until a separate steward applies the policy. Conflicts/stakes/exposure cannot be waived by that button.
- [ ] Reviewer packet HTML/JSON contains no expected answers, private calibration map or peer assessments.
- [ ] Exactly five new judgment options appear: Established, Partly, Not established, Uncertain, The question needs fixing. No scores or agreement display.
- [ ] Lock requires every item and reasoning. Repeated lock cannot replace the original; a correction appears only as a dated amendment.
- [ ] Download receipt immediately. Each item hash binds round ID, reviewer account ID, item ID, judgment, reasoning and server timestamp.

## Receipt verification (iPhone / a-Shell)

The script is Python stdlib only and read-only; no network, root or external binary is used.

```sh
python3 scripts/verify_receipt.py --help
python3 scripts/verify_receipt.py receipt.json
```

- [ ] Original private receipt exits 0. Edited reasoning, timestamp, round ID or reviewer ID exits 1. Malformed input exits 1 without printing private contents. CLI usage errors exit 2.
- [ ] Save a private copy outside the service; later download produces identical bound contents and hashes. Server timestamps are not claimed as independently witnessed time.
- [ ] Another reviewer, author or steward cannot request this private receipt endpoint.

## Closure, calibration, exports and audit

- [ ] Before closure, author/steward desk and export endpoints return no initial judgments or reasoning. Reviewer cannot read peer work/results.
- [ ] Early closure fails with any frozen assignment missing; frozen deadline closure retains missingness.
- [ ] After closure, admitted reviewer can see non-calibration peer work only if no related frozen/open assignment remains. Other accounts cannot use that reviewer's endpoint.
- [ ] Calibration responses/receipts are absent from author reports/exports and peer endpoints; only the steward's closed-round report contains expected judgment and observed responses. Reviewer-owned receipt does not mark calibration status.
- [ ] Round export includes packet, roster, contract/nonce/hash, original receipts and closed results; excludes feedback records/text. Author calibration receipts are explicitly redacted. Feedback-only export excludes labels and assessments.
- [ ] Audit chain contains actor, action, timestamp, previous hash and hash. Existing events cannot be edited/deleted via application saves/querysets. Export actions append events too.
- [ ] An externally retained audit head is needed to detect privileged history replacement/truncation; do not present the local chain as operator-proof.
- [ ] Full database backup restores into an isolated database and verifies retained contract/receipt hashes before real-study use. Round JSON exports alone are insufficient.

## Recorded evidence

42 tests passed locally with SQLite; migration forward/reverse preservation and per-item receipt tampering are included. UI/browser observations, PostgreSQL CI and hosted migration results should be recorded only after they are actually run. This checklist is not evidence those manual steps passed.
