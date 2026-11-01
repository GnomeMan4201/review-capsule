# Reviewer-local CLI checkpoint (v0.2.2 candidate)

This is a **reviewer-side helper**, not a hosted submission service, complete participant workflow or authorization to run Round 1. [needs Linux runner] Python 3.12 and the project's pinned cryptography/OpenTimestamps dependencies. iPhone/a-Shell behavior has not been demonstrated.

From `reviewrecord/`, install `python -m pip install -e .`, then:

```sh
rrreview keygen --private-key my-review-key.pem
rrreview pubkey --private-key my-review-key.pem
rrreview sign --private-key my-review-key.pem --input declaration-draft.json --output declaration-signed.json
rrreview sign --private-key my-review-key.pem --input assessment-draft.json --output assessment-PRIVATE.json
rrreview commit --private-key my-review-key.pem --assessment assessment-PRIVATE.json --output commit-to-steward.json
```

All commands are local and offline. `keygen` prompts twice for a passphrase and saves an encrypted Ed25519 PKCS8 key in a new mode-0600 file. `pubkey` prints only the public key. The signing and commitment commands prompt for the passphrase, require new output paths and never print the assessment body. Do not sync keys or pre-close assessments to GitHub or the steward.

Draft input is JSON, canonicalized before signing, with strict field and reviewer-key matching checks. `sign` only accepts `declaration`, `assessment` and reviewer-stated `withdrawal`; it cannot sign a steward-attested withdrawal. The `commit` command reads the locally signed assessment, verifies the signature against the same reviewer key, hashes its exact envelope bytes and creates a separately signed `commit` envelope. **Only the commit envelope is sent to the steward before close.** The signed assessment is retained locally for optional release after the steward publishes close. A withdrawal does not delete a committed lock.

A reviewer must use the actual registration's `round_id` and `registration_hash`; the tool does not authenticate the registration, check packet leakage, prove key holder identity, establish the close boundary, deliver files, obtain acknowledgements or verify anchors. Importantly, a valid local signature does not imply eligibility or human independence. The complete record still needs `rrverify`, independently grounded anchor/registry evidence and explicit checks.

**Known gaps:** No completed author or steward signing tools, append-only log builder, controlled receipt exchange or final bundle builder. Encrypted-key handling and password prompts have not been security-audited; the tests use synthetic passphrases. Avoid real participant content until all acceptance gates are met.

**Stop criterion:** Do not progress to a real round if the reviewer helper can be made to emit full assessment content inside a pre-close commit, accept a foreign key's signature, overwrite an existing signed output, or bypass strict role separation.
