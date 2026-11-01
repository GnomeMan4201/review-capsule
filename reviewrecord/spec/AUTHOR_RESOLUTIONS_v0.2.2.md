# Author resolutions S11–S16 applied

Source: author instructions supplied in this conversation. Prior v0.2.1 source/brief remain preserved alongside the revised v0.2.2 baseline and exact source diff.

- S11: close.status removed. locked_count remains a signed close-time count. The verifier computes later complete/incomplete round_status using the policy, counting locks and verified reveals; it is not a signed claim or an overall verification verdict.
- S12: verifier-first retained. Section 11 now requires passing kill tests and checked CLI tools before round 1; no new hosted interface is required.
- S13: withdrawals never remove locks. A withdrawn reviewer can supply a valid reveal that counts; a missing reveal remains WITHDRAWN plus REVEAL_MISSING. Steward-attested withdrawals remain labelled attested.
- S14: exact version-specific limits text is in the signed registration without trailing LF; limits.txt is that field plus exactly one LF. Changing limits requires a new registration.
- S15: reviewer objects use content-addressed paths. Declarations/commits/withdrawals have rid/own-object-digest; assessments and proofs use rid/assessment-commitment-digest. Added RID_MISMATCH and PATH_HASH_MISMATCH. The full reviewer key remains the counting/authentication identity; truncated rid is only filing information.
- S16: tree_size counts every commit log entry, duplicates included. locked_count counts distinct full reviewer keys with a first-by-seq counting commit. Check both and tree_size >= locked_count.

## Terminology needed to keep the two digests distinct

`commit_hex64` is the assessment commitment value inside the signed commit payload. It is the assessment envelope's own digest. The signed commit envelope has a different digest, used for commits/<rid>/<hex64>.json and the log's ref_hash. This follows S15's explicit own-object-hash requirement. Unsigned proof filenames use the assessment commitment; they are not filenames for the proof's own digest.

## Current scope and remaining gates

The current document/profile and primitive/semantic vectors are identified by FREEZE_v0.2.2.json. No production verifier/signing tool existed before this baseline was recorded. The freeze does not claim cryptographer review, complete signed-round acceptance, successful kill tests, six-confirmation OTS verification, or real reviewer observations.

Full-round fixtures and their expected report, failing verifier kill tests, production library tests, key lifecycle qualification, anchor adapters and the real OTS pending-to-confirmed path remain separate implementation gates. Future acceptance-affecting ambiguities must be recorded, not silently guessed into the frozen baseline.
