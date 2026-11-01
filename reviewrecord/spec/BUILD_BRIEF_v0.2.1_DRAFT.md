# Build Brief: Portable Review Record and Verifier — v0.2.1 working draft

Source basis: the author-provided build brief, S1–S10/decisions 1–10, and the pasted Review Record Specification v0.2.1. This is a working revision of the brief, not a claim to be an unchanged export of the earlier brief. The original pasted specification is preserved separately as `REVIEW_RECORD_SPEC_v0.2.1_DRAFT.md`.

Status: NOT FROZEN. Byte-level requirements below are mechanically copied from source specification sections 3–6. Conflicts identified in `FREEZE_BLOCKERS.md` are unresolved; this document does not silently settle them. The source specification wins after freeze; before freeze, conflicts must be reported.

## 1. Product and claim boundary

Build, in order: protocol definition and cross-checked frozen vectors; verifier with per-check outcomes; author/reviewer/steward signing and bundle tools; kill-test CI on every change. The Review Capsule interface comes last and receives no special verification treatment. No account platform, marketplace, research scoring, leaderboard or AI evaluator is part of this first build.

Every record must carry the exact required statement reproduced at the end of this brief. Commitments in anchored structures supply an existence upper bound; they do not establish the time content was first disclosed. Relationship, stake and exposure statements are participant declarations, not facts established by the verifier.

Do not use the prohibited quality/independence phrases as tool verdicts. Scan tool-authored report/template/UI text; do not scan quoted input or the required limits statement. Report counts by `pass`, `fail`, `missing`, `pending`, `unverifiable`, `not_checked`; no aggregate VERIFIED verdict. Offline is the default. Explicit network flags are required; unreachable services do not produce passing outcomes.

## 2. Author constraints and existing work

The author works from an iPhone using a-Shell/GitHub. Round-1 verification uses GitHub Actions; a-Shell availability is not a gate. Prefer Python stdlib with at most two direct dependencies. List direct and transitive dependencies and versions. If a later iPhone verifier requires a verification-only Python Ed25519 fallback, qualify it against published RFC vectors and malformed inputs before making support claims. No actual participant key may be generated or stored by Capsule or the steward for somebody else.

Review Capsule PR #1 is an unmerged separate application iteration: UI fixes, private table separation, freeze/publication/open, server receipts, corrections, calibration and disjoint feedback exports. It does not implement this protocol. Those old receipts remain legacy-v0, never canon-v1. Existing hosted data is synthetic/disposable. Managed PostgreSQL is separate from the ephemeral web container, but the current Free database expires December 1, 2026 with no automatic backups. Export deliberate public synthetic bundles to GitHub; do not publish secrets or real sensitive research.

## 3. Decisions carried forward

- Target 3 reviewer keys; minimum locks 2 and verified reveals 2. Counts are keys, not established distinct humans.
- Steward required; reviewer self-publication is extra evidence. Reviewer-primary operation is deferred to v0.3.
- OTS plus RFC 3161 with different declared authorities; optional archive evidence does not count. Require 6 Bitcoin confirmations and declare the validation backend. FreeTSA.org is the tested RFC 3161 candidate under the fetched CA, not a service audit or production trust decision.
- Optional GitHub/ORCID history; no listing requirement.
- Coverage names the author's public GitHub rounds.json and additional listed registries. Similarity is a manual warning, never proof of a shared work identity.
- Disclose `steward_is_author_operator`; no second steward required for round 1.
- Unrevealed locks count for min_locks but not min_reveals; REVEAL_MISSING remains visible. Locked-then-withdrawn counting is still unresolved in the supplied specification.
- Anonymous reviewers remain anonymous for round 1; no later credit mechanism is implemented.
- One complete verifier with separately written Python/JavaScript canon-v1 and Merkle references. This is not outside human review.
- Open feedback and adjudicated records never share an export or table.

## 4. Byte-level technical profile copied from the specification

The following block is copied verbatim from specification sections 3–6, excluding their section-3 heading. Its identity is checked by the phase-0 document check; it must be regenerated if that source block changes.

<!-- BEGIN SPEC TECHNICAL BLOCK -->

- **Canonicalization (`canon-v1`):** UTF-8, no insignificant whitespace. Allowed values: objects, arrays, strings, integers, booleans, null. Floats and exponent notation are rejected. Integers are decimal in the range -(2^53 - 1) to 2^53 - 1, no leading zeros, no `-0`. Object keys are sorted ascending by Unicode code point (equal to UTF-8 byte order); duplicate keys in input are rejected. Strings: escape `"` and `\`; write U+0008, U+0009, U+000A, U+000C, U+000D as `\b \t \n \f \r`; write other control characters U+0000 to U+001F as `\u00xx` with lowercase hex; everything else literal UTF-8; lone surrogates rejected; no Unicode normalization. It is not RFC 8785 and must not be labeled as such. Records made under any earlier format keep their original format identifier (the existing Review Capsule receipts are `legacy-v0`).
- **Hash:** SHA-256, written `sha256:` plus 64 lowercase hex characters.
- **Signatures:** Ed25519 over a DSSE envelope (section 3.1). Author, reviewers and steward each generate their own keys locally. Public keys are written `ed25519:` plus base64url (no padding) of the raw 32-byte key. The steward never holds an author's or reviewer's key.
- **Random values:** 32 bytes from the operating system CSPRNG, base64url without padding.
- **Timestamps:** ISO 8601 UTC with `Z`, advisory only. Git author and committer dates are configurable and are never evidence of time. Order comes from hash references to earlier anchored records (section 4.7), not from clocks in the records.
- **Anchors:** publication of a hash somewhere the operator does not control (section 4.7).

### 3.1 Signed objects and file bytes (S6, S9)

- Every signed object is a DSSE envelope. Conform to the DSSE specification (version 1.0.2 was read by the implementer; check the current version). The signed bytes are the DSSE PAE of `payloadType` and the payload bytes.
- This specification defines a **strict application profile** on top of DSSE: exactly one signature per envelope, made by the role key named in the registration (author, steward) or the reviewer's declaration; unknown envelope fields are rejected; `keyid` is an unauthenticated hint and authorization never depends on it. This profile is not a claim about every DSSE parser.
- `payloadType` is `application/vnd.reviewrecord.<type>.v1+json`, where `<type>` is `registration`, `declaration`, `commit`, `assessment`, `logentry`, `close`, `disposition` or `withdrawal`. A verifier rejects an envelope whose `payloadType` does not match the payload's `type` field.
- Producers write `payload` and `sig` as standard base64 with padding. Verifiers accept the standard and URL-safe variants that DSSE requires them to accept, and must keep the exact envelope bytes as received: different base64 spellings of one payload give different file hashes, and committed files are never re-normalized after receipt.
- Signed envelope files are stored as the canon-v1 serialization of the envelope object. A file that is not canon-v1 bytes is rejected as `ENVELOPE_NONCANONICAL`.
- `object_hash` of a signed object is SHA-256 of its envelope file bytes.
- `limits.txt` is UTF-8, no BOM, LF line endings only, the statement in section 8 followed by exactly one LF. It is compared byte for byte.

## 4. Objects

All objects carry `type` and `round_id`. All objects except the registration also carry `registration_hash`, the `object_hash` of the registration envelope.

### 4.1 Round registration (author-signed, anchored before any reviewer receives the packet)

```json
{
  "type": "registration",
  "spec": "0.2.1",
  "canon": "canon-v1",
  "round_id": "r-2026-11-xx-a",
  "work_id": "short stable identifier for the research",
  "author_key": "ed25519:...",
  "steward_key": "ed25519:...",
  "steward_is_author_operator": true,
  "packet_hash": "sha256:...",
  "policy_hash": "sha256:...",
  "withheld_commitment": "sha256:...",
  "reviewers_target": 3,
  "deadline": "2026-11-30T12:00:00Z",
  "prior_rounds": ["r-..."],
  "registered_at": "2026-11-..Z"
}
```

Rules:

- `packet_hash` and `policy_hash` are SHA-256 of the canon-v1 bytes of those documents.
- `withheld_commitment` is SHA-256 of the canon-v1 bytes of `{"results": <withheld results>, "salt": <salt>}`. The salt is held by the author and released after close.
- `prior_rounds` lists every earlier round on the same `work_id`, including abandoned or unfavorable ones. A record that omits an earlier round found in a named registry is reported as incomplete. The verifier cannot prove that no undisclosed round exists.
- `steward_is_author_operator` is a disclosure. The verifier shows `true` as a warning; round 1 does not require a second steward.
- The registration is the root of the log: every later object includes `registration_hash`.

### 4.2 Packet

A list of items. Each item contains only `id`, `evidence` and `candidate` (the conclusion to assess). It contains no expected answers, no author identity, and no framing language signalling the intended verdict. The author runs and records a leakage check (identity, answer, framing) before freezing. The leakage check is the author's statement, not a verified fact.

### 4.3 Policy (S4)

Machine-readable, hashed in the registration. Required fields:

| Field | Meaning |
|---|---|
| `judgment_options` | Fixed in v0.2.1: `established`, `partly_established`, `not_established`, `uncertain`, `question_needs_fixing`. No scores, no agreement display. |
| `min_locks` | Minimum distinct reviewers with a commitment in the log. Round 1: 2. |
| `min_reveals` | Minimum distinct reviewers whose assessment is revealed and verified. Round 1: 2. |
| `time_box_minutes` | Advisory length of a review. |
| `duplicate_policy` | The first `commit` per `reviewer_key` counts; later ones are reported as `DUPLICATE_COMMIT` and do not count. |
| `withdrawal_policy` | How withdrawals are recorded and counted (see 4.9). |
| `disposition_required` | Whether every declared concern needs a disposition. Round 1: true. |

Counting rules are computed from these fields only. A round is `complete` only if locks >= `min_locks` and verified reveals >= `min_reveals`; otherwise `incomplete`. An unrevealed lock counts toward `min_locks` but not `min_reveals`, and is reported as `REVEAL_MISSING`.

### 4.4 Reviewer declaration (reviewer-signed, before the packet is released)

```json
{
  "type": "declaration",
  "round_id": "r-...",
  "registration_hash": "sha256:...",
  "reviewer_key": "ed25519:...",
  "relationship_to_author": "none | acquaintance | collaborator | other:...",
  "stake_in_result": "none | describe",
  "prior_exposure": "none | describe",
  "identity_disclosure": "real | pseudonym | anonymous",
  "credit_consent": false,
  "history_url": "optional GitHub or ORCID URL, shown only if given"
}
```

The steward checks only that the declaration is complete and signed, not that it is true. Statements such as no prior exposure are signed declarations, not facts the record proves. A verifiable history is optional and never a requirement to be listed.

### 4.5 Locked assessment, commit and acknowledgement

Assessment (reviewer-signed, kept private until close):

```json
{
  "type": "assessment",
  "round_id": "r-...",
  "registration_hash": "sha256:...",
  "reviewer_key": "ed25519:...",
  "items": [
    {
      "id": "item-1",
      "judgment": "not_established",
      "reasoning": "...",
      "concerns": [{"cid": "c1", "text": "..."}]
    }
  ],
  "locked_at": "2026-11-..Z"
}
```

Commit (reviewer-signed, sent to the steward): `{"type": "commit", "round_id", "registration_hash", "reviewer_key", "commitment": "sha256:<object_hash of the assessment envelope>"}`.

Flow:

1. The reviewer signs the assessment locally.
2. The reviewer sends the steward only the signed commit.
3. The steward returns a signed `logentry` (section 4.6) as the acknowledgement, and appends it to the round log.
4. The reviewer keeps the full signed assessment, the commit and the steward's acknowledgement as their receipt. A reviewer may also publish their commitment directly to an independent channel; the verifier treats that as extra evidence when present. Suppression becomes provable only when such external evidence exists.
5. After close, reviewers submit the full assessment for publication. Anyone can check that it hashes to the committed value.

A retained copy proves possession. With the steward's signed acknowledgement and anchored inclusion, it lets a reviewer show what they committed and that it was received before close.

### 4.6 Round log (S3, S5)

The steward keeps an append-only, hash-chained log of `logentry` envelopes (steward-signed):

```json
{
  "type": "logentry",
  "round_id": "r-...",
  "registration_hash": "sha256:...",
  "seq": 1,
  "kind": "declaration | commit | withdrawal",
  "ref_hash": "sha256:<object_hash of the referenced object>",
  "prev_entry_hash": "sha256:<registration_hash for seq 1, otherwise object_hash of entry seq-1>"
}
```

Entries have consecutive `seq` starting at 1. A gap or broken link is `LOG_CHAIN_BROKEN`. Each entry is returned to the party it concerns as their acknowledgement; a missing one is `ACK_MISSING`.

### 4.7 Close record (steward-signed) and the reveal boundary (S5)

```json
{
  "type": "close",
  "round_id": "r-...",
  "registration_hash": "sha256:...",
  "final_seq": 9,
  "last_entry_hash": "sha256:...",
  "tree_size": 3,
  "tree_head": "sha256:...",
  "locked_count": 3,
  "withdrawn": [{"reviewer_key": "ed25519:...", "reason": "optional"}],
  "status": "complete | incomplete",
  "closed_at": "2026-11-..Z"
}
```

- The **close record is the declared reveal boundary** in round 1. There is no separate reveal authorization. This does not prove when anyone first saw any content.
- `tree_head` is the Merkle tree head over all `commit` entries, built exactly as in RFC 9162 section 2.1: leaf hash SHA-256(0x00 || leaf data), node hash SHA-256(0x01 || left || right), empty tree hash SHA-256 of the empty string, split at the largest power of two strictly less than n. Leaf data is the raw 32 bytes of each commitment, in log order, `commit` entries only. Inclusion proofs are verified with the algorithm in RFC 9162 section 2.1.3.2. Implement from the RFC text and cross-check; never invent expected hashes.
- A reviewer who locked but never revealed stays listed as locked and unrevealed.

### 4.8 Anchors (S7)

An anchor publishes a hash somewhere the operator does not control. Any object that includes hash H shows its data existed before that object was created, so order comes from that inclusion chain, not from timestamps.

- **Targets:** `registration_hash`, the close `object_hash`, `record_hash`, and optionally periodic log heads.
- **Requirement:** each target needs at least two anchors of different declared **authorities**. Two anchors are independent only if their authorities differ; two anchor types with the same authority do not count as independent.
- **Round 1 types:**
  - `ots`: OpenTimestamps. Confirmed only when a verified Bitcoin attestation reaches **6 confirmations**. A calendar-only proof is `pending`. If no Bitcoin verification backend is available the status is `unverifiable_offline`.
  - `rfc3161`: an RFC 3161 timestamp token from a named public time-stamping authority. Candidate named in the phase-0 package: FreeTSA.org, `https://freetsa.org/tsr`. That names a service; it is not an audit of its clock, policy or availability. A production profile must pin and explain its CA material rather than accepting a root from an arbitrary bundle.
  - `archive`: a public snapshot containing the hash. Optional and non-counting.
- **Adapter declaration:** each anchor adapter declares its type, authority, evidence format, validation backend and confirmation policy, and the report names them.
- **Status values:** `confirmed`, `pending`, `invalid`, `unverifiable_offline`, `missing`.
- A git commit is a publication channel, not a time source. Anchor proofs are stored beside the data they anchor, never inside the payload whose hash they anchor.

### 4.9 Withdrawals (S3)

A reviewer may sign a `withdrawal` object (`type`, `round_id`, `registration_hash`, `reviewer_key`, optional `reason`) and send it for logging. A withdrawal recorded by the steward without a reviewer signature is allowed only if flagged `steward_attested: true` and is reported as attested by the steward, not as stated by the reviewer. Withdrawal does not remove a lock from the log; counting follows `withdrawal_policy`.

### 4.10 Dispositions (author-signed, after close)

For each declared concern:

```json
{
  "type": "disposition",
  "round_id": "r-...",
  "registration_hash": "sha256:...",
  "concern_ref": {"assessment_commitment": "sha256:...", "item_id": "item-1", "cid": "c1"},
  "status": "adopted | under_examination | unresolved | declined",
  "reason": "required, non-empty",
  "change_ref": "link to what changed, if adopted"
}
```

A record with a declared concern lacking a disposition is `dispositions_incomplete`. Declined and unresolved items remain in the published record permanently. The verifier checks dispositions only for concerns declared in the `concerns` lists; it cannot find concerns embedded in prose.

## 5. The final record (bundle) (S1, S2)

```
bundle/
  manifest.json
  registration.json          # DSSE envelope, author-signed
  policy.json  packet.json
  withheld.json              # results plus salt, released after close
  declarations/<rid>.json
  commits/<rid>.json         # signed commit envelope
  log/<seq>.json             # signed logentry envelopes
  proofs/<rid>.json          # inclusion proof: {leaf_index, tree_size, hashes[]}
  close.json
  assessments/<rid>.json     # revealed after close
  dispositions/<n>.json
  anchors/<name>.json  anchors/<name>.ots  anchors/<name>.tsr ...
  limits.txt
```

- `rid` is `"r-"` plus the first 16 hex characters of SHA-256 of the reviewer's `reviewer_key` string.
- **`record_hash`** is SHA-256 of the canon-v1 bytes of `{"files": [{"path": ..., "sha256": ...}, ...], "spec": "0.2.1"}`, with `files` sorted ascending by `path`. The file list excludes `manifest.json` itself, everything under `anchors/`, and the `record_hash` field. `record_hash` is stored in `manifest.json` beside the file list, not inside the hashed projection.
- Anchor proofs sit beside the data they anchor, so no hash contains its own proof.
- Withheld results are released only after close, with the salt, so `withheld_commitment` can be verified.

## 6. Verification procedure

Anyone can run it offline except anchor and registry lookups. Each step produces outcome records and never short-circuits the report.

1. Parse every file: `CANON_INVALID`, `ENVELOPE_MALFORMED`, `ENVELOPE_NONCANONICAL`.
2. Recompute `packet_hash`, `policy_hash` and, once the salt is present, `withheld_commitment`: `HASH_MISMATCH`, `WITHHELD_COMMITMENT_MISMATCH`.
3. Verify every signature against the key named in the registration (author, steward) or declaration (reviewer); reject extra signatures and unknown fields in strict mode: `SIGNATURE_INVALID`, `KEY_MISMATCH`.
4. Check every object's `registration_hash` and `round_id`: `REGISTRATION_BINDING_MISMATCH`.
5. Walk the log: consecutive `seq`, chain links, an entry for each declaration and commit: `LOG_CHAIN_BROKEN`, `ACK_MISSING`, `DUPLICATE_COMMIT`.
6. Recompute the tree from the `commit` entries and compare with `tree_head`, `tree_size` and `last_entry_hash`: `TREE_HEAD_MISMATCH`.
7. For each revealed assessment: hash its envelope, find the matching commitment, verify its inclusion proof: `COMMIT_NOT_IN_TREE`, `INCLUSION_PROOF_INVALID`. A commit with no revealed assessment: `REVEAL_MISSING`.
8. Compare locks and verified reveals with `min_locks` and `min_reveals`: `LOCKS_BELOW_MINIMUM`, `REVEALS_BELOW_MINIMUM`.
9. Anchors: each target has two anchors with different declared authorities; report each status: `ANCHOR_MISSING`, `ANCHOR_PENDING`, `ANCHOR_INVALID`, `ANCHOR_UNVERIFIABLE_OFFLINE`, `ANCHOR_NOT_INDEPENDENT`.
10. Dispositions: every declared `cid` has one with a non-empty reason: `DISPOSITION_MISSING`, `DISPOSITION_NO_REASON`.
11. Registry coverage: if registries are supplied, compare `prior_rounds` with rounds found for the same `work_id`: `PRIOR_ROUND_UNLISTED`; if none supplied: `REGISTRY_NOT_CHECKED`. Never report that no other round exists. Round 1's named registry is the author's public `rounds.json` in a GitHub repository plus any URLs the author lists; the report names exactly what was checked. Similarity between works is a manual warning, never an identity claim.
12. `limits.txt` equals the section 8 statement byte for byte: `LIMITS_MISSING_OR_ALTERED`. The forbidden-claim scan (S8) covers only text authored by the tool itself (reports, templates, UI strings). It does not scan `limits.txt` or quoted or input content, and a test confirms the tool's own templates contain no forbidden terms: `FORBIDDEN_CLAIM_PRESENT`.

**Identity of the author and steward (S10):** the verifier accepts `--expected-author-key` and `--expected-steward-key`. Without them the report marks author and steward identity as `not_checked` and states that only self-consistency was verified.

**Output rules:** each check is `pass`, `fail`, `missing`, `pending`, `unverifiable` or `not_checked`. The verifier emits a JSON report and a plain-text summary. There is no single "VERIFIED" result; the summary is a count by status. Exit 0 only if every mandatory check passes, 1 if anything fails or is missing, 2 if nothing failed but something is pending, unverifiable or not checked. Network checks are explicit flags, and an unreachable network gives `unverifiable`, never `pass`. The tool never prints "independent", "certified" or "trusted" as a verdict.

<!-- END SPEC TECHNICAL BLOCK -->

## 5. Repository layout and phase gates

```
reviewrecord/
  spec/ vectors/ src/rr/ tests/ examples/
  .github/workflows/ci.yml
```

- Phase 0: resolve all acceptance-affecting conflicts, synchronize both documents, generate/cross-check canon-v1 and Merkle vectors in Python and JavaScript, and freeze the protocol/vector set before production libraries.
- Phase 1: canon, DSSE and Merkle libraries; pass frozen vectors and published RFC data.
- Phase 2: rrverify CLI; write kill tests first and show failures before implementing the verifier, then make all required outcomes pass their acceptance tests.
- Phase 3: participant-local rrsign and steward log tool; build a fully synthetic round using only these tools.
- Phase 4: bundle builder and anchor helpers; demonstrate a real OTS pending-to-confirmed path and RFC 3161 path, distinct from mocked test adapters.
- Phase 5: CI/docs hardening. Run kill tests on changes, retain readable logs/artifacts, and avoid unsupported verdict wording.
- Phase 6: optional Capsule export/import integration; signing keys stay with participants and the verifier gives the interface no privileged role.

Conflict: source specification section 11 says "no new software beyond the vectors" for the first manual round. The verifier-first phase sequence above is retained from the build brief and remains unresolved against that phrase. No interpretation is selected here.

## 6. Required tests and evidence

Kill tests: pre-signing assessment exchange must not become a factual independence/no-exposure verdict; substituted assessment content; missing required reveal; one missing counting anchor; backdated Git publication with no time weight; omitted prior round shown in a supplied registry.

Additional tests: wrong signer; altered payload; payloadType/type mismatch; duplicate commitment; reordered/skipped/broken log; wrong registration binding; OTS calendar-only proof remains pending; altered limits; empty disposition reason; float/exponent rejection. Include canonical sort/control/integer/surrogate cases, DSSE PAE examples, published RFC 8032 signatures, RFC 9162 tree sizes 1/2/3/4/5/7/8 with every inclusion path, and a complete synthetic round with expected per-check report.

Do not type invented expected hashes/signatures. Generate and cross-check. Keep raw failures and distinguish draft primitive checks from full protocol kill tests. Demonstrating a timestamp exchange is not equivalent to demonstrating a complete two-anchor review round.

## 7. Working and honesty rules

Use primary DSSE, RFC 9162, RFC 8032, RFC 3161 and OpenTimestamps sources; record the versions/content identifiers read. Maintain the change ledger with each deliverable. If an acceptance test depends on an unresolved rule, stop that implementation and report the conflict with choices instead of guessing. Do not describe the protocol as secure or cryptographically reviewed; neither has been established.

Report unmet tests explicitly, including concurrency, key lifecycle/revocation, real reviewer demand, off-platform contact, sockpuppets, collusion, identity/framing leakage, hidden rounds under other work IDs, and publication refusal. The tool does not measure research quality.

Kill criterion: stop and report if substituted content, missing mandatory evidence or an unsupported independence claim is accepted as a passing mandatory verification result.

## 8. Required limits statement

This record shows that a specific packet and policy were registered before review, that each listed reviewer's published assessment matches a commitment recorded before the declared reveal stage, and that changes to committed content are detectable against retained commitments. Statements about relationships, stakes and prior exposure are signed declarations by the participants and are not verified. It does not certify the independence, competence, or honesty of any participant, the absence of collusion or off-platform contact, the success of blinding, or the correctness of the research.
