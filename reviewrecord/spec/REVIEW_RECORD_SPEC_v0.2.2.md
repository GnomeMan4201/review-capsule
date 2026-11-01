# Review Record Specification v0.2.2 (implementation baseline)

Provenance: v0.2.2 is the author-supplied v0.2.1 with author resolutions S11–S16 applied. The v0.2.1 source is preserved; the exact change patch is distributed separately. Neither version has been reviewed by a cryptographer.

Status: implementation baseline for the first synthetic/manual round. Do not rely on it for high-stakes claims. This specification is authoritative over the synchronized build brief for the frozen technical profile. Freeze hashes identify exact document/vector bytes, not a security qualification. Changes to a frozen acceptance rule require a new version and retained change record.

## 1. What the record claims, and what it does not

**It claims (process integrity):**

- This exact packet and policy were registered before review began.
- Each listed reviewer's published assessment matches a commitment recorded before the declared reveal stage.
- Changes to committed content are detectable against retained commitments.
- The author published a disposition and reason for each declared concern.
- Rounds on this work are listed, including abandoned ones, with coverage reported against named registries.

**It does not claim:**

- That the research is correct.
- That any reviewer is independent, competent, or honest.
- That the author and a reviewer did not collude.
- That blinding held, or that no reviewer saw anyone else's work first. Authorship of code and writing is often guessable, and off-platform contact cannot be detected. No prior exposure is a signed declaration, not a proven fact.
- When assessment content was first disclosed to anyone. The cryptography shows a commitment existed in a structure whose hash is anchored, which gives an upper bound on time.

Every record carries the statement in section 8 verbatim, as the file `limits.txt` and as the `limits` field.

## 2. Roles

- **Author:** owns the research, prepares the packet, signs the registration and the dispositions.
- **Steward:** runs the round: collects commitments, returns signed acknowledgements, publishes the signed round log and close record. Has its own signing key. May be the author's operator, in which case the registration says so (`steward_is_author_operator`). Never sees assessments before close. Must not be a reviewer in the same round.
- **Reviewer:** assesses the packet. Holds their own signing key. Identity may be real, pseudonymous, or anonymous; the disclosure level is recorded. Round 1 offers no credit mechanism for anonymous reviewers.

## 3. Primitives

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
  "spec": "0.2.2",
  "canon": "canon-v1",
  "round_id": "r-2026-11-xx-a",
  "work_id": "short stable identifier for the research",
  "author_key": "ed25519:...",
  "steward_key": "ed25519:...",
  "steward_is_author_operator": true,
  "limits": "This record shows that a specific packet and policy were registered before review, that each listed reviewer's published assessment matches a commitment recorded before the declared reveal stage, and that changes to committed content are detectable against retained commitments. Statements about relationships, stakes and prior exposure are signed declarations by the participants and are not verified. It does not certify the independence, competence, or honesty of any participant, the absence of collusion or off-platform contact, the success of blinding, or the correctness of the research.",
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
- `limits` is the section 8 statement with no trailing LF. It is signed and anchored with this registration. `limits.txt` must equal that field followed by exactly one LF. Both are checked against the statement for the declared spec version. Changing the statement requires a new registration. A version does not automatically authorize different limits text.

### 4.2 Packet

A list of items. Each item contains only `id`, `evidence` and `candidate` (the conclusion to assess). It contains no expected answers, no author identity, and no framing language signalling the intended verdict. The author runs and records a leakage check (identity, answer, framing) before freezing. The leakage check is the author's statement, not a verified fact.

### 4.3 Policy (S4)

Machine-readable, hashed in the registration. Required fields:

| Field | Meaning |
|---|---|
| `judgment_options` | Fixed in v0.2.2: `established`, `partly_established`, `not_established`, `uncertain`, `question_needs_fixing`. No scores, no agreement display. |
| `min_locks` | Minimum distinct reviewers with a commitment in the log. Round 1: 2. |
| `min_reveals` | Minimum distinct reviewers whose assessment is revealed and verified. Round 1: 2. |
| `time_box_minutes` | Advisory length of a review. |
| `duplicate_policy` | Round 1: `first_commit_per_reviewer_key`. The first `commit` by log seq per full `reviewer_key` counts; later ones are retained, reported as `DUPLICATE_COMMIT`, and do not increase `locked_count`. All commit log entries, including duplicates, remain tree leaves. |
| `withdrawal_policy` | Round 1: `retain_locks_count_valid_reveals`. A withdrawal never removes a lock. A withdrawn reviewer contributes a reveal only by publishing a valid reveal; the author/steward cannot veto its validity. Without a reveal report both `WITHDRAWN` and `REVEAL_MISSING`. See 4.9. |
| `disposition_required` | Whether every declared concern needs a disposition. Round 1: true. |

Counting rules are computed from these fields only. After checking the available bundle, the verifier computes `round_status`: `complete` only if locks >= `min_locks` and verified reveals >= `min_reveals`; otherwise `incomplete`. This is a verifier result, not a signed participant claim. The signed close has no `status` field because reveals do not yet exist when it is signed. An unrevealed lock counts toward `min_locks` but not `min_reveals`, and is reported as `REVEAL_MISSING`. Round completeness does not erase any other failing, missing or unresolved checks and is not an overall verification verdict.

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
  "closed_at": "2026-11-..Z"
}
```

- The **close record is the declared reveal boundary** in round 1. There is no separate reveal authorization. This does not prove when anyone first saw any content.
- `tree_head` is the Merkle tree head over all `commit` entries, built exactly as in RFC 9162 section 2.1: leaf hash SHA-256(0x00 || leaf data), node hash SHA-256(0x01 || left || right), empty tree hash SHA-256 of the empty string, split at the largest power of two strictly less than n. Leaf data is the raw 32 bytes of each commitment, in log order, `commit` entries only. Inclusion proofs are verified with the algorithm in RFC 9162 section 2.1.3.2. Implement from the RFC text and cross-check; never invent expected hashes.
- `tree_size` is the number of commit log entries, duplicates included. `locked_count` is the number of distinct full reviewer keys with a counting (first-by-seq) commit. Check both counts separately, including `tree_size >= locked_count`; do not deduplicate the Merkle leaf list.
- The signed close is created before reveals. It retains `locked_count`, which is known at close, but contains no reveal-dependent `status`. The verifier's later `round_status` follows section 4.3.
- A reviewer who locked but never revealed stays listed as locked and unrevealed. A valid reveal must match that reviewer's counting commit to contribute to `min_reveals`; later commits are retained as duplicates, not replacements for the first assessment.

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

A reviewer may sign a `withdrawal` object (`type`, `round_id`, `registration_hash`, `reviewer_key`, optional `reason`) and send it for logging. A withdrawal recorded by the steward without a reviewer signature is allowed only if flagged `steward_attested: true` and is reported as attested by the steward, not as stated by the reviewer. Withdrawal never removes a lock from the log or its contribution to `min_locks`. Under round-1 `withdrawal_policy`, a withdrawn reviewer contributes to `min_reveals` only if they choose to publish a valid reveal. Neither author nor steward can force publication or make an otherwise valid published reveal ineligible merely because of withdrawal. A withdrawn reviewer without a reveal receives both `WITHDRAWN` and `REVEAL_MISSING`. A verifier can check supplied evidence; it cannot make an operator serve omitted files, so the reviewer must retain and be able to supply their own reveal/receipt. The steward-attested variant is signed by the steward and explicitly carries `steward_attested: true`; report it as attested, never reviewer-stated.

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
  registration.json          # DSSE envelope, author-signed, includes limits
  policy.json  packet.json
  withheld.json              # results plus salt, released after close
  declarations/<rid>/<hex64>.json
  commits/<rid>/<hex64>.json
  withdrawals/<rid>/<hex64>.json
  log/<seq>.json             # steward-signed acknowledgement envelopes
  close.json                 # no status; immutable declared reveal boundary
  assessments/<rid>/<commit_hex64>.json
  proofs/<rid>/<commit_hex64>.json
  dispositions/<n>.json
  anchors/<name>.json  anchors/<name>.ots  anchors/<name>.tsr ...
  limits.txt
```

- `rid` is `"r-"` plus the first 16 lowercase hex characters of SHA-256 of the UTF-8 `reviewer_key` string. Filing by a truncated rid never authorizes a signer or merges counts: use the complete reviewer key for signature and distinct-key accounting.
- For declarations, commits and withdrawals, `hex64` is the object's own complete `object_hash` without `sha256:`. Never replace a prior object with a later one.
- For an assessment, `commit_hex64` is the digest from the commit payload's `commitment` field: the assessment envelope's own object hash, not the signed commit envelope's hash. The signed commit has a separate hash used for its path and log `ref_hash`. This interpretation follows the requirement that each reviewer-submitted signed object is named by its own hash.
- The proof is an unsigned JSON document `{leaf_index, tree_size, hashes[]}` for the named assessment commitment. Its path uses that commitment digest, not the proof file's hash. Each sibling hash uses the hash encoding in section 3; the Merkle algorithm operates on its decoded 32 bytes. Check proof linkage to the corresponding counting commit, tree size and log-derived leaf index.
- `RID_MISMATCH`: a reviewer-object path rid does not match the full reviewer key in its payload. `PATH_HASH_MISMATCH`: a reviewer-signed object's filename digest does not match its file object hash. Proof files have the explicit commitment-linkage rule above; they are not signed objects and do not name their own digest.
- **`record_hash`** is SHA-256 of the canon-v1 bytes of `{"files": [{"path": ..., "sha256": ...}, ...], "spec": "0.2.2"}`, with files sorted ascending by path. List every included non-anchor file except manifest.json, exactly once. File sha256 values use section 3's prefixed encoding. The projection excludes manifest.json itself, anchors/* and the record_hash field. manifest.json stores spec, files and record_hash beside one another. Paths are relative bundle paths; duplicate names, parent traversal and symlink escapes are rejected rather than treated as evidence outside the bundle.
- Anchor proofs sit beside the data they anchor, so no hash contains its own proof. Anchor files are checked by their target-binding adapters, not made valid merely by appearing in a manifest.
- Withheld results are released only after close, with the salt, so withheld_commitment can be verified.

## 6. Verification procedure

Anyone can run it offline except anchor and registry lookups. Each step produces outcome records and never short-circuits the report.

1. Parse every file and validate reviewer-object path binding: `CANON_INVALID`, `ENVELOPE_MALFORMED`, `ENVELOPE_NONCANONICAL`, `RID_MISMATCH`, `PATH_HASH_MISMATCH`. Verify the manifest file hashes and record_hash projection; changes remain `HASH_MISMATCH`.
2. Recompute `packet_hash`, `policy_hash` and, once the salt is present, `withheld_commitment`: `HASH_MISMATCH`, `WITHHELD_COMMITMENT_MISMATCH`.
3. Verify every signature against the key named in the registration (author, steward) or declaration (reviewer); reject extra signatures and unknown fields in strict mode: `SIGNATURE_INVALID`, `KEY_MISMATCH`.
4. Check every object's `registration_hash` and `round_id`: `REGISTRATION_BINDING_MISMATCH`.
5. Walk the log: consecutive `seq`, chain links, an entry for each declaration and commit: `LOG_CHAIN_BROKEN`, `ACK_MISSING`, `DUPLICATE_COMMIT`.
6. Recompute the tree from all commit log entries, duplicates included, and compare tree_head, tree_size and last_entry_hash. Independently compute locked_count from first commits per distinct full reviewer key, and check tree_size >= locked_count: `TREE_HEAD_MISMATCH` for any close/tree/count mismatch. Never use tree_size as a substitute for distinct-key lock count.
7. For each revealed assessment: hash its envelope, find the matching commitment, verify its inclusion proof: `COMMIT_NOT_IN_TREE`, `INCLUSION_PROOF_INVALID`. A commit with no revealed assessment: `REVEAL_MISSING`.
8. Compare counting locks and valid reveals matching counting commits with min_locks and min_reveals: `LOCKS_BELOW_MINIMUM`, `REVEALS_BELOW_MINIMUM`. Compute and report round_status as a verifier result: complete only when both minimums are met. A withdrawal retains its lock; a withdrawn reviewer with no reveal is both `WITHDRAWN` and `REVEAL_MISSING`. A supplied valid reveal can count despite withdrawal. Do not compare completeness to a signed close.status: that field does not exist.
9. Anchors: each target has two anchors with different declared authorities; report each status: `ANCHOR_MISSING`, `ANCHOR_PENDING`, `ANCHOR_INVALID`, `ANCHOR_UNVERIFIABLE_OFFLINE`, `ANCHOR_NOT_INDEPENDENT`.
10. Dispositions: every declared `cid` has one with a non-empty reason: `DISPOSITION_MISSING`, `DISPOSITION_NO_REASON`.
11. Registry coverage: if registries are supplied, compare `prior_rounds` with rounds found for the same `work_id`: `PRIOR_ROUND_UNLISTED`; if none supplied: `REGISTRY_NOT_CHECKED`. Never report that no other round exists. Round 1's named registry is the author's public `rounds.json` in a GitHub repository plus any URLs the author lists; the report names exactly what was checked. Similarity between works is a manual warning, never an identity claim.
12. The signed registration limits field equals the section 8 statement for its declared spec version, with no trailing LF, and limits.txt equals that exact field plus one LF: `LIMITS_MISSING_OR_ALTERED`. The forbidden-claim scan (S8) covers only text authored by the tool itself (reports, templates, UI strings). It does not scan `limits.txt` or quoted or input content, and a test confirms the tool's own templates contain no forbidden terms: `FORBIDDEN_CLAIM_PRESENT`.

**Identity of the author and steward (S10):** the verifier accepts `--expected-author-key` and `--expected-steward-key`. Without them the report marks author and steward identity as `not_checked` and states that only self-consistency was verified.

**Output rules:** each check is `pass`, `fail`, `missing`, `pending`, `unverifiable` or `not_checked`. The verifier emits a JSON report and a plain-text summary. There is no single "VERIFIED" result; the summary is a count by status. Exit 0 only if every mandatory check passes, 1 if anything fails or is missing, 2 if nothing failed but something is pending, unverifiable or not checked. Network checks are explicit flags, and an unreachable network gives `unverifiable`, never `pass`. The tool never prints "independent", "certified" or "trusted" as a verdict.

## 7. Threat model

| Threat | Mitigated by | Residual risk |
|---|---|---|
| Author edits packet after review | Anchored `packet_hash` bound into every later object | None if anchors verify |
| Author changes expected answers | `withheld_commitment` with salt | None if salt is revealed |
| Steward alters or suppresses an assessment | Signed acknowledgement, reviewer-held receipt, anchored log and tree head | Steward can still refuse to publish; suppression is provable only if the reviewer holds the acknowledgement or published the commitment directly |
| Reviewer sees others' work first | Commit before reveal | Not detectable. Treated as a signed declaration; the record never claims it did not happen |
| Author shops for a friendly round | Mandatory `prior_rounds`, registration before opening | Author can use a new `work_id`; coverage is reported against named registries only |
| Sockpuppet reviewers | Declarations, optional verifiable history | Not solved |
| Author-reviewer collusion | Declarations | Not detectable |
| Packet leaks authorship | Pre-freeze leakage check, disclosed | Often unavoidable for code or distinctive writing |
| Key loss | Reviewers may re-publish from a backed-up receipt | Lost key means the reviewer can no longer prove authorship |
| Sensitive material in packet | Author redacts before freeze; policy states handling | Author responsibility |
| Backdated publication date | Hash-chained references to anchored records; git dates not trusted | Depends on the anchors' confirmation depth and authorities |
| Two implementations read the same bytes differently | canon-v1, DSSE strict profile, RFC 9162 tree, shared vectors, two implementations of the primitives | Primitives were cross-checked in two languages only; no outside review |
| Operator is also the author | `steward_is_author_operator` disclosure and warning | No second steward in round 1 |

## 8. Required `limits` statement (verbatim)

> This record shows that a specific packet and policy were registered before review, that each listed reviewer's published assessment matches a commitment recorded before the declared reveal stage, and that changes to committed content are detectable against retained commitments. Statements about relationships, stakes and prior exposure are signed declarations by the participants and are not verified. It does not certify the independence, competence, or honesty of any participant, the absence of collusion or off-platform contact, the success of blinding, or the correctness of the research.

## 9. Decisions recorded for round 1

1. Target 3 reviewers; a round is complete with `min_locks` 2 and `min_reveals` 2.
2. The steward-required design stays. Reviewer self-published commitments are extra evidence; making them primary is a v0.3 question.
3. Anchors: OpenTimestamps plus an RFC 3161 token from a named public authority (candidate: FreeTSA.org); archive optional and non-counting; Bitcoin depth 6. The OpenTimestamps validation backend and TSA choice still need feasibility confirmation.
4. Verifiable history (GitHub or ORCID) is optional and shown only if given.
5. Coverage registry: the author's public `rounds.json` plus listed URLs. Work similarity is a manual warning.
6. No second steward required; `steward_is_author_operator` is disclosed.
7. Unrevealed and withdrawn locks count toward min_locks; completeness also needs min_reveals. A withdrawn reviewer contributes a valid reveal only by their own publication choice.
8. Anonymous reviewers stay anonymous in round 1; no credit mechanism.
9. One complete verifier, plus independently cross-checked canon-v1 and Merkle primitives.
10. Cross-check language: JavaScript (Python is the primary implementation).

## 10. Open questions still undecided

- Whether reviewer-published commitments should become the primary channel, making the steward optional (v0.3).
- How to detect a reused `work_id` under a new name beyond a manual warning.
- How anonymous reviewers could receive credit later without exposing identity.
- Whether a second independent verifier is required before any round that matters.
- Which TSA and which Bitcoin verification backend are acceptable for a production profile, and whether a transparency log such as Sigstore Rekor suits this use (untested).
- Availability of native Ed25519 libraries in a-Shell (untested). Round 1 verification runs in GitHub Actions.

## 11. First manual round using checked CLI tools

Round 1 runs only after the verifier passes all kill tests, using checked CLI tools for participant-local signing, log production and bundle construction. The verifier-first phase order in the build brief remains in force; no new hosted interface is required.

1. Write the packet (3 to 6 items) and policy. Run and record the leakage check.
2. Sign and publish the registration with an OpenTimestamps proof plus an RFC 3161 token. A public git commit may carry it but is not trusted for time.
3. Collect declarations; release the packet.
4. Reviewers sign locally and send commits only; the steward returns signed acknowledgements and appends to the log.
5. Close the round, collect full assessments, verify against commitments.
6. Publish dispositions and the final record bundle.
7. Write down every point where this was awkward. That list is the product requirements.

**Kill tests**, run with synthetic reviewers before inviting real ones. The protocol fails if the verifier reports success on any of these:

- Two synthetic reviewers exchange assessments before signing, then complete every step correctly. The verifier must not report independence or no prior exposure as verified.
- The content of one revealed assessment is substituted. Expect `HASH_MISMATCH` or `COMMIT_NOT_IN_TREE`.
- A required reveal is removed. Expect `REVEAL_MISSING`.
- One of the two anchors on any target is removed. Expect `ANCHOR_MISSING` or `ANCHOR_NOT_INDEPENDENT`.
- A git commit carrying the registration is backdated. The verifier gives it no time weight.
- A registered prior round is removed from `prior_rounds` when a supplied registry shows it. Expect `PRIOR_ROUND_UNLISTED`.

## 12. Changelog

- v0.2.2: author resolutions S11–S16. Removed close.status; verifier derives round_status from locks and verified reveals. Retained locked_count at close and defined tree_size as all commit log entries including duplicates. Retained withdrawal locks; valid reviewer-published reveals can count despite withdrawal, while absence is WITHDRAWN plus REVEAL_MISSING. Added signed registration limits with exact limits.txt linkage. Reviewer-signed object paths now contain full object digests; added RID_MISMATCH and PATH_HASH_MISMATCH. Distinguished assessment commitment digest from signed commit envelope digest and unsigned proof naming. Kept verifier-first and required passing kill tests before a manual round. Round-1 policy strings encode the already authorized counting semantics. A generated patch retains every textual change from the supplied v0.2.1.

- v0.2.1: S1 `record_hash` projection defined; S2 `commits/` and `proofs/` added with schemas and `rid`; S3 `withdrawal` type and steward-attested variant; S4 policy schema and counting rules; S5 close record is the declared reveal boundary; S6 strict single-signature profile, `keyid` is a hint only; S7 anchor adapters declare authority, independence means different authorities, `rfc3161` added as a counting type, OTS needs 6 confirmations; S8 forbidden-claim scan limited to tool-authored text; S9 `limits.txt` bytes, canonical envelope files, `object_hash` over file bytes, `ENVELOPE_NONCANONICAL`; S10 expected-key flags; `steward_is_author_operator`; `min_locks` 2 and `min_reveals` 2; round-1 registry named; optional `history_url`; added `DUPLICATE_COMMIT`, `REVEALS_BELOW_MINIMUM`; decisions 1-10 recorded in section 9.
- v0.2: claims narrowed to commitments and publication order; independence and no prior exposure moved to signed declarations; steward key and acknowledgements; canon-v1 and DSSE; RFC 9162 tree; concern IDs; separate verifier outcomes; kill tests.
- v0.1: initial draft.
