# Implementation checkpoint — 2026-11-01

Demonstrated here: six kill tests first failed because rr.verify did not exist (evidence/kill-tests-red.log), then passed against the implementation. Production canon-v1/PAE/Merkle functions match the frozen vectors. Adversarial tests cover signatures, paths, logs, duplicate counting, withdrawals, limits, malformed shapes, inclusion proofs and unresolved anchors. CLI outcomes are per check; no overall acceptance label exists.

The twelve frozen baseline files remain unchanged. No normative spec revision was made at this checkpoint. Additional error codes identify malformed documents/paths, unknown concern dispositions and missing expected keys. Policy literal values follow the frozen counting vectors.

Implementation limits, not assumptions of success:

- One Python verifier; Python/JavaScript cross-checks cover the primitives, not a second verifier.
- Participant signing, steward log and bundle-building CLI tools are not implemented. The fixture generator is test code, not a participant tool. Round 1 is not ready.
- Bitcoin Core validation is implemented behind an explicit network flag and environment-supplied RPC URL. A real Bitcoin attestation reaching six confirmations has not been tested here. Calendar upgrades/submissions are not automated.
- RFC 3161 verification requires OpenSSL and an explicitly supplied external CA policy file. The application does not select CA material from bundle input. A production TSA CA pin/policy remains to be reviewed. The earlier FreeTSA feasibility evidence is separate from the sample round's placeholders.
- Registry input is a user-supplied local snapshot with source, work_id and prior_rounds. It is not automatically fetched or authenticated. Coverage is limited to named snapshots; unexamined work identity/similarity is not inferred.
- Resource ceilings: 4,096 files, 1 MiB per file, 24 MiB total. ZIP traversal, duplicate names and symlinks are rejected. General fuzzing and external security review have not been performed.
- Library behavior on an iPhone/a-Shell is untested. GitHub Actions uses Python 3.12; no fallback Ed25519 implementation is claimed.
- The protocol has not been reviewed by a cryptographer. Do not describe this implementation as secure.

Spec changes still needed: none identified and silently applied. Any future byte-level correction requires updating both normative documents and replacing the baseline explicitly, rather than rewriting the frozen vectors.

Next acceptance gates: checked participant-local signing/steward/bundle tools; a full synthetic round built only through those tools; real OTS pending-to-six-confirmation evidence; pinned TSA policy; CI checks for those paths. The hosted Capsule remains separate and its receipts remain legacy-v0.
