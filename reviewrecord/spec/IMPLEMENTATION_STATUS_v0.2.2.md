# Implementation checkpoint — 2026-11-01

Demonstrated in the previous verifier milestone: six kill tests first failed because rr.verify did not exist (evidence/kill-tests-red.log), then passed against the implementation. Production canon-v1/PAE/Merkle functions match the frozen vectors. Adversarial tests cover signatures, paths, logs, duplicate counting, withdrawals, limits, malformed shapes, inclusion proofs and unresolved anchors. CLI outcomes are per check; no overall acceptance label exists.

The twelve frozen baseline files remain unchanged. No normative spec revision was made at this checkpoint. Additional error codes identify malformed documents/paths, unknown concern dispositions and missing expected keys. Policy literal values follow the frozen counting vectors.

## Reviewer-local CLI addition

A candidate `rrreview` tool now supports local generation of a passphrase-encrypted Ed25519 private key, signing reviewer declarations/assessments/reviewer-stated withdrawals and deriving a signed commit **only from a locally verified, signed assessment**. The full assessment is not placed in that commit. Output files are exclusive-create, mode 0600. No network transport or submission step exists. See `docs/REVIEWER_LOCAL_CLI.md`.

Nine new regression tests cover signing, exact commitment linkage, key permission, no-rewrite behavior, role refusal, declaration fields, malformed inputs and tampered assessments. CI on the branch checks these alongside verifier/primitive tests. This is tool functionality in a synthetic environment, not validation of the reviewer/steward communication process. The reviewer must check the real registration/packet and must retain private artifacts until close; the CLI does not enforce that timeline.

## Implementation limits, not assumptions of success

- One Python verifier; Python/JavaScript cross-checks cover the primitives, not a second verifier.
- Author signing, steward log, close, acknowledgement and final bundle-building CLI tools are not implemented. The fixture generator is test code, not a participant tool. The new reviewer CLI is only a partial participant tool. Round 1 is not ready.
- Bitcoin Core validation is implemented behind an explicit network flag and environment-supplied RPC URL. A real Bitcoin attestation reaching six confirmations has not been tested here. Calendar upgrades/submissions are not automated.
- RFC 3161 verification requires OpenSSL and an explicitly supplied external CA policy file. The application does not select CA material from bundle input. A production TSA CA pin/policy remains to be reviewed. The earlier FreeTSA feasibility evidence is separate from the sample round's placeholders.
- Registry input is a user-supplied local snapshot with source, work_id and prior_rounds. It is not automatically fetched or authenticated. Coverage is limited to named snapshots; unexamined work identity/similarity is not inferred.
- Resource ceilings: 4,096 files, 1 MiB per file, 24 MiB total. ZIP traversal, duplicate names and symlinks are rejected. General fuzzing and external security review have not been performed.
- Library behavior on an iPhone/a-Shell is untested. GitHub Actions uses Python 3.12; no fallback Ed25519 implementation is claimed.
- The protocol and local key-handling workflow have not been reviewed by a cryptographer. Do not describe this implementation as secure.

Spec changes still needed: none identified and silently applied. Any future byte-level correction requires updating both normative documents and replacing the baseline explicitly, rather than rewriting the frozen vectors.

Next acceptance gates: checked author-local and steward-local signing/receipt/close tools; a full synthetic round built only through participant tools and an explicit privacy-leakage negative test; real OTS pending-to-six-confirmation evidence; pinned TSA policy; CI checks for those paths. The hosted Capsule remains separate and its receipts remain legacy-v0.
