# Reviewer-local CLI checkpoint (v0.2.2 candidate)

This helper is **offline**, not a complete submission service or authorization for Round 1. [needs Linux runner] Python 3.12 and pinned dependencies. a-Shell/iPhone behavior has not been tested.

## Trusted inputs

Obtain the author's Ed25519 public key **outside the registration and packet exchange** (for example, an independently confirmed author channel). Supply it using `--expected-author-key`. A self-signed replacement registration containing a new attacker key must not be accepted simply because its signature verifies. Optionally pin `--expected-registration-hash` obtained from a separate reliable channel.

A reviewer must receive `registration.json` (signed DSSE envelope). For signing assessments and creating commitments, they also need the exact frozen `packet.json` and `policy.json`.

`rrreview` locally verifies the registration signature using the expected author key, checks its profile and limits, requires distinct role keys, binds `round_id` and `registration_hash`, verifies byte-level packet and policy hashes, and checks that the assessment covers exactly the packet items using the allowed judgments.

**Do not give the reviewer the packet before signing their declaration**, as the specification places that declaration before packet release. Declaration/withdrawal signing requires the signed registration and expected author key, but does not require packet/policy. The reviewer should check that the received registration matches the independently obtained author key and intended round.

## Commands

From `reviewrecord/`, install `python -m pip install -e .`. Use a synthetic round only while the workflow is under construction.

```sh
rrreview keygen --private-key reviewer-private.pem
rrreview pubkey --private-key reviewer-private.pem

rrreview sign \
  --private-key reviewer-private.pem \
  --registration registration.json \
  --expected-author-key 'ed25519:<EXPECTED_AUTHOR_PUBLIC_KEY>' \
  --input declaration-draft.json \
  --output declaration-signed.json

rrreview sign \
  --private-key reviewer-private.pem \
  --registration registration.json \
  --expected-author-key 'ed25519:<EXPECTED_AUTHOR_PUBLIC_KEY>' \
  --packet packet.json --policy policy.json \
  --input assessment-draft.json \
  --output assessment-PRIVATE.json

rrreview commit \
  --private-key reviewer-private.pem \
  --registration registration.json \
  --expected-author-key 'ed25519:<EXPECTED_AUTHOR_PUBLIC_KEY>' \
  --packet packet.json --policy policy.json \
  --assessment assessment-PRIVATE.json \
  --output commit-to-steward.json
```

Use the optional `--expected-registration-hash sha256:...` on signing and commitment commands if an out-of-band registration hash is available.

The encrypted Ed25519 PKCS8 private key is exclusive-created with mode 0600. Passwords are prompted locally (not accepted through argv/environment options). The draft input may use ordinary JSON, canonicalized before signing. Existing signed outputs are not overwritten.

The signed assessment is retained locally; only the **signed commit envelope** may be sent to the steward pre-close. The commit hashes the exact signed assessment envelope bytes, not only its inner payload. The signer does not send data automatically, and it does not independently check a registration's external anchor, packet leakage, human identity, off-platform contact, or temporal ordering.

**Unresolved confidentiality gate:** A reviewer can still manually choose a public output directory, and no steward intake tool exists yet to reject premature assessment submission. Until B3/C1's storage and intake negative tests pass, no real pre-close participant data should be handled.

**Stop criterion:** A foreign author key, mismatched registration, altered packet, incomplete assessment, mismatched policy or foreign reviewer signature must be refused with no signed output; a pre-close steward must never ingest or persist assessment content. An independently controlled release boundary and the external anchor requirements remain unfinished.
