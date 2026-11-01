# Implementation checkpoint — 2026-11-01

Demonstrated in the previous verifier milestone: six kill tests first failed because rr.verify did not exist (evidence/kill-tests-red.log), then passed against the implementation. Production canon-v1/PAE/Merkle functions match the frozen vectors. Adversarial tests cover signatures, paths, logs, duplicate counting, withdrawals, limits, malformed shapes, inclusion proofs and unresolved anchors. CLI outcomes are per check; no overall acceptance label exists.

The twelve frozen baseline files remain unchanged. No normative spec revision was made at this checkpoint. Additional error codes identify malformed documents/paths, unknown concern dispositions and missing expected keys. Policy literal values follow the frozen counting vectors.

## Reviewer-local CLI addition

A candidate `rrreview` tool now supports local generation of a passphrase-encrypted Ed25519 private key, signing reviewer declarations/assessments/reviewer-stated withdrawals and deriving a signed commit **only from a locally verified, signed assessment**. The full assessment is not placed in that commit. Output files are exclusive-create, mode 0600. No network transport or submission step exists. See `docs/REVIEWER_LOCAL_CLI.md`.

Additional regression tests cover signing, exact commitment linkage, key permissions, no-rewrite behavior, role refusal, declaration fields, malformed inputs, tampered assessments, altered signed packets/policies and wrong-round signing. Signing declarations/withdrawals now requires a signed registration pinned to an out-of-band expected author public key; assessments/commits additionally require matching frozen packet/policy, and assessments must cover the exact packet item IDs. Locally signed assessments must be read/written from a mode-0700 owner-owned directory on a qualified POSIX host. This does not authenticate an external registration anchor or prevent a reviewer manually revealing private text outside the tool.

## Implementation limits, not assumptions of success

- One Python verifier; Python/JavaScript cross-checks cover the primitives, not a second verifier.
- A candidate steward-side `rrsteward` tool now implements local initialization, signed pre-close reviewer-object intake, hash-chained acknowledgements, a signed immutable close, and post-close signed assessment import with RFC 9162 inclusion proofs. Full author signing, steward-attested withdrawals, independent reveal publication, author disposition signing, and final bundle-building tools are **not** implemented. The fixture generator remains test code. Round 1 is not ready.
- Bitcoin Core validation is implemented behind an explicit network flag and environment-supplied RPC URL. A real Bitcoin attestation reaching six confirmations has not been tested here. Calendar upgrades/submissions are not automated.
- RFC 3161 verification requires OpenSSL and an explicitly supplied external CA policy file. The application does not select CA material from bundle input. A production TSA CA pin/policy remains to be reviewed. The earlier FreeTSA feasibility evidence is separate from the sample round's placeholders.
- Registry input is a user-supplied local snapshot with source, work_id and prior_rounds. It is not automatically fetched or authenticated. Coverage is limited to named snapshots; unexamined work identity/similarity is not inferred.
- Resource ceilings: 4,096 files, 1 MiB per file, 24 MiB total; additional 200:1 ZIP uncompressed/compressed ratio ceiling. ZIP traversal, duplicate names and symlinks are rejected. Reads are bounded by remaining resource limits rather than trusting a ZIP header's claimed size. Adversarial tests cover oversized entries, high compression ratio and inconsistent central-directory sizes. General fuzzing, decompressor CPU-budget testing, and external security review have not been performed.
- Library behavior on an iPhone/a-Shell is untested. GitHub Actions uses Python 3.12; no fallback Ed25519 implementation is claimed.
- The protocol and local key-handling workflow have not been reviewed by a cryptographer. Do not describe this implementation as secure.

Spec changes silently applied: none. A2/A3's eventual proof-derived authority and timing semantics may require an explicit, versioned normative revision; the frozen baseline must not be edited in place. Any future byte-level correction requires updating both normative documents and replacing the baseline explicitly, rather than rewriting the frozen vectors.

Next acceptance gates: author-local signing/dispositions and a final bundle builder, explicit crash/recovery and suppression tests, a complete synthetic round built only through actor tools; external OTS pending-to-six-confirmation evidence; pinned TSA policy, a second verifier, and independent human review. The hosted Capsule remains separate and its receipts remain legacy-v0.

## Correction audit checkpoint (A1–A3, A6, A8, A4 historical test)

An external code review report found the type/authority presence gate incorrectly used unconfirmed descriptors. The candidate verifier now emits `ANCHOR_GATE_UNCONFIRMED` when either required type lacks confirmed evidence, and `ANCHOR_AUTHORITY_NOT_CHECKED` when adapters claim both types are confirmed but verified authority identity is unavailable. `ANCHOR_ORDER_NOT_CHECKED` is always emitted pending a proof-derived timing model. These are **containment, not A2/A3 completion**. Unsigned descriptor authority labels have no gate power; see `docs/ANCHOR_GATE_AUDIT.md` for proof requirements and the claim-boundary counterexample.

The verifier rejects signing-key reuse across reviewer/author/steward roles using `ROLE_KEY_REUSED`. The signed limits statement is compared to the built-in normative constant and has new byte-sync tests against spec/limits.txt and specification section 8. A4 retained real synthetic FreeTSA evidence has been run through the current adapter via CI tests: positive digest under historical FreeTSA CA, wrong digest, and wrong CA. This is not an endorsement of the service, nor a nonce/policy/expiration/signer identity qualification.

No production A2 ordering proof, A3 authenticated authorities, A4 TSA trust policy, A5 OTS six-confirmation path or full synthetic round made through actor tools has been demonstrated. Round 1 stays blocked. The two GitHub workflows have distinct scopes: `reviewrecord-vectors.yml` tests this protocol; `verify.yml` tests the hosted Capsule application.

## A10 bounded archive ingestion

The initial ZIP reader checked declared metadata sizes but called `ZipFile.read` without a bounded application read loop. It now streams at most 64 KiB per iteration under the remaining per-file/total cap, compares received length with declared length, and rejects 200:1+ compression amplification before extraction. Directory reads are also byte-bounded. This is a practical guard, not an adversarial proof against all decompression bombs, metadata races or CPU exhaustion. Regression tests in `tests/test_zip_limits.py` cover representative hostile ZIPs.

## A5 and A13 additional regression checkpoint

The OTS adapter has a *candidate* mainnet preflight: the configured Bitcoin Core RPC must report `chain=main` and return Bitcoin mainnet's known genesis hash. The confirmed branch records block height, hash, time and observed confirmation count in the per-anchor detail. The backend identity remains the caller-configured RPC and its truthfulness is not independently established. The adapter now checks all included Bitcoin header attestations and fails the entire proof if any one fails; tests exercise wrong-chain/wrong-genesis and **mocked** multiple-attestation outcomes. A real, upgraded, six-confirmation attestation has **not** been verified. The proof-derived signer/authority and temporal-order gates remain blocked.

A13 tests now demonstrate the frozen DSSE profile's accepted standard/URL-safe Base64 variants, rejection of mixed alphabets, unpadded URL-safe public-key encoding, and Ed25519 rejection of S+group-order signatures. Tightening payload/signature Base64 to exactly one spelling conflicts with the frozen spec's explicit dual-variant acceptance rule and requires a recorded profile revision; do not silently narrow it.

## B1/B3/C1 partial implementation — offline participant boundaries

The reviewer CLI now checks signed registration, an out-of-band expected author public key, current round/hash, packet/policy hashes and complete assessment coverage **before** creating a signed assessment or commit. Declaration signing remains possible with only registration and expected author key, because the declaration precedes packet release. The optional `--expected-registration-hash` supports an additional out-of-band registration pin. This is not a verified external timestamp.

The reviewer CLI refuses assessment drafts/outputs outside an owner-owned private immediate directory on POSIX. No participant assessment or passphrase is intentionally echoed by the tools. This restriction does not prevent copies made by external software or human disclosure.

Candidate `rrsteward` stages: `init`, `intake`, `close`. It refuses pre-close assessment objects, unsupported object types, foreign reviewer signatures, exact replays, further appends after close, and existing log-chain alterations; accepted declarations/commits/withdrawals receive hash-chained, steward-signed receipts. A close contains all commitment Merkle leaves, distinct lock count and no reveal-dependent status. The test suite has synthetic negative checks for the stated cases. See `docs/STEWARD_CLI_CANDIDATE.md`.

**Unresolved threats:** a steward can still read assessment content received off-platform; orphan handling deliberately halts rather than proving crash recovery; an unanchored steward workspace can be rewritten by a compromised operator; proof of complete log publication requires external evidence and reviewer-held receipts; steward-attested withdrawals and independent publication/bundle production are absent. The independent reviewer and external anchors remain hard Round-1 blockers.

## C1 post-close reveal and proof milestone

The steward importer now refuses any reveal until the signed close matches the complete local log and Merkle/lock fields. A reviewer-signed assessment must have the same registration, a valid reviewer signature, complete item and judgment coverage, and envelope-object hash matching the reviewer's **first** counting commitment; withdrawal does not invalidate this choice. The importer computes a RFC 9162 inclusion path from all logged commitment leaves, self-checks it and stores matching assessment/proof files under hash-bound paths. Replayed, premature, uncommitted and orphaned proofs are refused. CI demonstrated 94 synthetic tests passing on commit `33c5bd2a` (including five post-close tests); these are not independently reproduced or externally anchored observations.

Two-file assessment/proof storage is not transactionally atomic; inconsistent partial writes cause a halt on next reveal. A reviewer can publish their signed assessment outside the steward; the CLI's local acceptance does not give the steward control of the reviewer's right to do that. Steward-attested withdrawals and external suppression evidence remain to be designed/qualified.
