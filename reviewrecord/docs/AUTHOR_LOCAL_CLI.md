# Candidate rrauthor — author-local registration and dispositions

[needs Linux runner] Python 3.12 and pinned cryptography dependency. No network, no automatic research publication, no TSA/OTS anchoring. No real Round 1 is authorized.

## Registration

`rrauthor register` reads the author-owned encrypted Ed25519 PKCS8 key through a local prompt. The author provides a fixed packet, policy, an unreleased `withheld.json` containing `results` and a 32-byte base64url `salt`, and an explicit `prior_rounds.json` list. An empty array `[]` is a deliberate **signed declaration** that no previous rounds are known under this `work_id`; it does not prove absence of undisclosed rounds. The tool refuses a missing list or a list containing repeated/empty identifiers.

The withheld file must reside in an owner-owned mode-0700 local directory. It remains outside the public registration output. Registration contains only the SHA-256 commitment over canonical withheld bytes; do not publish the salt or full withheld document until after close. The tool validates the round-1 packet/policy structure, required fields, role-key separation, explicit operator disclosure, and deadline syntax. Timestamp strings are signer assertions, not external time evidence.

Example:

```sh
rrauthor register \
  --private-key ./private/author-key.pem \
  --steward-key 'ed25519:<STEWARD_PUBLIC_KEY>' \
  --packet ./packet.json --policy ./policy.json \
  --withheld ./private/withheld.json \
  --prior-rounds ./prior_rounds.json \
  --round-id 'r-synthetic-1' --work-id 'synthetic-work' \
  --reviewers-target 3 --deadline '2026-12-01T12:00:00Z' \
  --operator-is-not-author \
  --output ./registration.json
```

Choose exactly one of `--operator-is-author` or `--operator-is-not-author`. The registered author key must be communicated to reviewers over a separately established trusted channel; otherwise the registration signature proves only self-consistency. `rrauthor` does **not** collect or verify external anchor receipts, establish packet-release order, or authenticate the declared prior-round registry.

## Dispositions

`rrauthor disposition` only runs against an existing steward-signed close and a signed reviewer assessment plus its Merkle inclusion proof. The proof must match the root signed into the close. The concern ID and item ID must occur in that exact signed assessment. Output is a new, author-signed disposition; existing files are not overwritten. It does not itself fetch the source code or verify the truth of an `adopted` change link: `status`, `reason`, and `change_ref` remain author assertions.

A disposition draft contains `concern_ref` with `assessment_commitment`, `item_id`, `cid`; `status` one of `adopted`, `under_examination`, `unresolved`, `declined`; non-empty `reason`; and `change_ref` when adopted.

```sh
rrauthor disposition \
  --private-key ./private/author-key.pem \
  --registration ./registration.json --close ./close.json \
  --assessment ./reviewer-assessment.json \
  --proof ./reviewer-inclusion-proof.json \
  --draft ./disposition-draft.json \
  --output ./disposition-signed.json
```

The signed concern can later be included in a final bundle; the *full bundle verifier* must independently check its source, duplicates, all dispositions and log bindings. A valid local author signature is not a judgment on research correctness.

## Scope and stop criterion

Test coverage uses synthetic reviewer/author keys, deliberate empty `prior_rounds`, malformed/absent prior lists, wrong roles, withheld result IDs, protected outputs, valid concern signing and tampered inclusion proofs.

**Stop criterion:** If signing a registration can silently omit prior rounds, leak withheld results, or accept a steward signing key equal to the author's key, or if a disposition may reference an assessment not included in the signed close tree, the tool cannot be used for Round 1.

The remaining blocker is a tool-built final record with externally obtained anchors, a registered public history and independent human review. Do not treat this author tool as authorization for a live round.
