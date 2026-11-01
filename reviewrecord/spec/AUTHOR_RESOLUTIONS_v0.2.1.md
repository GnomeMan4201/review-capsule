# Author resolutions: v0.2 → v0.2.1

Source: author instructions in this conversation, November 1, 2026. This is a resolution ledger, not an export of the missing v0.2 source document and not a frozen full specification.

## Technical resolutions

| ID | Author resolution |
| --- | --- |
| S1 | `record_hash = SHA-256(canon-v1({"files":[{"path", "sha256"} … sorted by path],"spec":"0.2.1"}))`. Exclude `manifest.json`, `anchors/*`, and `record_hash` from that projection. Store `record_hash` beside the manifest file list. |
| S2 | Add `commits/<rid>.json` and `proofs/<rid>.json`. A proof has `leaf_index`, `tree_size`, `hashes[]`. `rid = "r-" + first 16 lowercase hex characters of SHA-256(UTF-8(reviewer_key string))`. |
| S3 | Add reviewer-signed `withdrawal`. A steward-recorded withdrawal must carry `steward_attested`; report it as attested rather than reviewer-stated. |
| S4 | Policy fields: `judgment_options`, `min_locks`, `min_reveals`, `time_box_minutes`, `duplicate_policy`, `withdrawal_policy`, `disposition_required`. Fixed five judgments. First commit per reviewer key counts; later commits get `DUPLICATE_COMMIT`. |
| S5 | The close record is the declared reveal boundary. It does not prove first actual disclosure. |
| S6 | Exactly one role-authorized signature per envelope. Reject extra signatures; reject unknown envelope fields in strict mode. Never authorize through `keyid`. |
| S7 | Each adapter declares type, authority, evidence format, validation backend and confirmation policy. Two counting anchors require different declared authorities. This comparison does not authenticate those authority declarations. |
| S8 | Scan only tool-authored reports/templates/UI text. Exclude `limits.txt` and quoted/input content. Add a template test; quoted research content is not a tool verdict. |
| S9 | `limits.txt`: UTF-8, no BOM, LF only, exact statement followed by one LF. Envelope files contain exact canon-v1 bytes; reject other serialization with `ENVELOPE_NONCANONICAL`. Object hashes cover the actual canonical file bytes. |
| S10 | Support `--expected-author-key` and `--expected-steward-key`. Without expected keys, identity comparison is `not_checked`; report only signature/key self-consistency. |

The byte-level rules in the build brief remain authoritative where the absent v0.2 source differs. Existing Capsule receipt bytes remain `legacy-v0`; do not rename their canonicalization.

## Round-1 decisions

1. Target three reviewers; `min_locks=2`, `min_reveals=2`.
2. Steward remains required. Reviewer self-publication is additional evidence; reviewer-primary operation is deferred to v0.3.
3. Counting anchor types are OpenTimestamps and RFC 3161 under a named public TSA with different declared authority. Archive snapshots are optional and non-counting. Bitcoin requires six blocks of confirmation evidence; the OTS validation backend must be reported.
4. GitHub/ORCID history is optional, shown only if supplied.
5. Coverage checks name the author's public `rounds.json` GitHub registry and each author-listed additional URL. Similarity warnings are manual; do not claim all rounds have been discovered.
6. Do not require a second steward. Add and display `steward_is_author_operator` as a warning.
7. Locked/unrevealed reviewers count toward `min_locks`. `min_reveals` is separate; retain `REVEAL_MISSING`.
8. Anonymous reviewers remain anonymous in round 1. No later credit mechanism is introduced.
9. One complete verifier plus separately implemented/cross-checked canon-v1 and Merkle primitives for round 1. This is not a claim of separate human review.
10. Cross-check language: JavaScript.

## Operational instructions

Do not block on a-Shell; round-1 verification runs in GitHub Actions. Capsule's current free PostgreSQL data is disposable, expires December 1, 2026 and has no automatic backup. Export deliberate review bundles to GitHub; never export secrets or sensitive research as test material. No Capsule migration/deploy is part of this phase.

## Limits bytes to carry forward

The following paragraph is the required statement; `limits.txt` contains its UTF-8 bytes followed by one LF:

This record shows that a specific packet and policy were registered before review, that each listed reviewer's published assessment matches a commitment recorded before the declared reveal stage, and that changes to committed content are detectable against retained commitments. Statements about relationships, stakes and prior exposure are signed declarations by the participants and are not verified. It does not certify the independence, competence, or honesty of any participant, the absence of collusion or off-platform contact, the success of blinding, or the correctness of the research.
