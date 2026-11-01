# Steward CLI: pre-close intake and close (candidate, not Round 1)

[needs Linux runner] Python 3.12, `cryptography==50.0.2`; run on a trusted local Linux filesystem. iOS/a-Shell compatibility and crash/power-loss resilience are **untested**.

This utility performs **only a subset of C1**. It has no network interface, does not collect full assessments before close, does not produce reveal inclusion proofs, does not publish reviewer-held receipts, and does not assemble a verifiable final bundle. No real participant review round is authorized.

## Roles and trust boundary

A steward uses a **steward-owned** locally encrypted private key. It is never included in the bundle, and the tool only reads it through a local prompt. The author supplies a signed registration, packet, policy, and an out-of-band author signing-key identity. The steward must independently establish the intended author identity, and may additionally check an externally published registration hash. The current `init` command pins the expected author key, not an external timestamp. That means registration-before-review and completeness of a steward-maintained log are **not** externally demonstrated.

`intake` permits exactly reviewer-signed `declaration`, `commit`, or reviewer-stated `withdrawal` DSSE envelopes. Pre-close `assessment`, `close`, `logentry` and other types are refused without writing to the workspace; the code still necessarily reads input bytes to identify their type, so this does not prove that no human could access an assessment elsewhere. Reviewers should **never submit** assessment files before close. A valid declaration must precede a commit; a replay of an identical signed commit is refused. A distinct later commit by the same reviewer is retained but never adds another distinct lock.

For accepted objects, the tool writes the signed object under its hash-bound path and signs a hash-chained `logentry` acknowledgement. Each subsequent operation checks the full existing chain, reviewer signatures, and whether every stored object is acknowledged. If a crash leaves an object without a receipt, the next operation **halts on the orphan**, rather than silently repairing history. This is a safety choice, not proven crash durability. Concurrent appends are serialized with a local advisory lock.

`close` signs the declared reveal boundary, the Merkle root/tree size over every logged commitment (duplicates included), and the distinct-key locked count. It does not write `close.status`. Further `intake` operations then fail. The signed clock value is advisory, not external evidence of ordering.

## Synthetic-only operation

From `reviewrecord/`, after `python -m pip install -e .`:

```sh
rrsteward init \
  --workspace ./steward-work \
  --registration ./registration.json \
  --packet ./packet.json --policy ./policy.json \
  --expected-author-key 'ed25519:<EXPECTED_AUTHOR_KEY>' \
  --steward-private-key ./local-steward-private.pem

rrsteward intake \
  --workspace ./steward-work \
  --input ./reviewer-signed-declaration.json \
  --expected-author-key 'ed25519:<EXPECTED_AUTHOR_KEY>' \
  --steward-private-key ./local-steward-private.pem

rrsteward intake \
  --workspace ./steward-work \
  --input ./reviewer-signed-commit.json \
  --expected-author-key 'ed25519:<EXPECTED_AUTHOR_KEY>' \
  --steward-private-key ./local-steward-private.pem

rrsteward close \
  --workspace ./steward-work \
  --expected-author-key 'ed25519:<EXPECTED_AUTHOR_KEY>' \
  --steward-private-key ./local-steward-private.pem
```

The tool does not generate or accept somebody else's keys on their behalf. The example `local-steward-private.pem` is a locally generated, passphrase-encrypted Ed25519 PKCS8 key that must already match the public key in the signed registration. Real credential or reviewer content must not be put in any CI fixture.

## Negative checks and hard limitations

The CI test suite uses only known synthetic keys and exercises refusal of (a) assessment submitted before close without persistence, (b) wrong reviewer signing key, (c) intake after close, (d) exact commit replay, (e) altered prior log entry, and (f) repeated close. The test fixture's actual assessment is intentionally never written to the steward workspace during intake.

Unresolved: proof of log completeness under malicious truncation without an external checkpoint or reviewer-held acknowledgement; crash recovery under SIGKILL/power loss; trusted registration-time anchoring; steward-attested withdrawals; controlled post-close assessment/reveal intake, Merkle proof building and bundle assembly; external TSA/OTS verification; second verifier and independent human review. A compromised steward key or a malicious operator who edits the entire unanchored workspace can equivocate; the tool is not a substitute for external anchoring.

**Stop criterion:** If any rejected pre-close assessment appears in the steward workspace, a foreign-key object obtains a signed acknowledgement, or the tool appends after close, the workflow must not be used for Round 1. A CI pass is only evidence for the tested synthetic path.
