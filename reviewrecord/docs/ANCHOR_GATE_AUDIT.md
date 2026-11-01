# Anchor-gate correction checkpoint — v0.2.2 (candidate implementation)

This document is **implementation evidence and an unresolved design register**, not a normative protocol change. The frozen v0.2.2 specification, brief, and twelve frozen vectors remain unchanged. Independent protocol/cryptographic review has not occurred.

## Confirmed defect and immediate containment (A1)

In the previous verifier, the sets used to assess anchor type presence and claimed authority separation were populated before proof verification. A pending OTS calendar attestation and an unverifiable or invalid RFC 3161 token could therefore satisfy the *type and purported authority* presence conditions despite having no confirmed pair. That is a false-positive gate design even when individual statuses were separately unresolved.

The candidate verifier now distinguishes:
- **Observed type:** unsigned descriptor declares `ots` or `rfc3161`. Only this is used to report a structurally missing required type.
- **Confirmed type:** the backend returned `confirmed`, not `pending`, `invalid`, `missing` or `unverifiable_offline`.
- **Qualified independent authorities:** deliberately **not established**. No descriptor text is counted as evidence of authority identity.

When the confirmed type set lacks either required type, `ANCHOR_GATE_UNCONFIRMED` is reported as **pending**. An absent type is also reported as `ANCHOR_MISSING` (**missing**). If both types are confirmed through the existing adapters, `ANCHOR_AUTHORITY_NOT_CHECKED` remains **not_checked** until the proof-derived authority validation is implemented and tested. No `ANCHOR_GATE_CONFIRMED` is emitted by this interim implementation. This is fail closed; it is not a production-capable two-authority gate.

## A2: temporal ordering is NOT established

The candidate emits `ANCHOR_ORDER_NOT_CHECKED` and keeps its status **not_checked**. These do not establish time ordering: descriptor-supplied dates; the signed `registered_at`, `locked_at`, `closed_at` and `deadline` fields; Git author/committer dates; mere existence of a hash in a bundle; a pending OTS calendar attestation.

A future proof-aware adapter must report the verified TSA token `genTime`, and a verified Bitcoin mainnet attestation's block height/hash/time, with source/provenance, chain identity, confirmation count, backend identity and validation policy. Only authenticated data can enter a time comparison. Compare registration and close target evidence, showing intervals and uncertainty; do not promote an uncheckable comparison to `pass`.

**Claim-boundary issue:** A registration anchor no later than a close anchor does *not*, by itself, prove that the registration was anchored before a reviewer received the packet or locked an assessment. Nor does a close anchor prove that a reviewer kept assessment content private until close. External packet-release/receipt evidence and a documented operating rule are needed for the former. The signed close plus committed hashes establishes declared log commitment structure, not first disclosure time. Any stronger claim requires a separate protocol revision and an independently evaluated protocol argument.

## A3: label is not authority

`anchors/<descriptor>.json` is outside `record_hash` by construction. The untrusted `authority` value remains visible for human inspection, but is labeled `authority_basis: descriptor label only; unauthenticated`. Relabeling the field (even adding a fake `status: confirmed` or `attested_time`) cannot make the current gate pass.

Production gate design: for OTS require mainnet genesis/chain checks and a verified six-deep block header, derive the Bitcoin chain identity from the verified backend and name that node as a trust assumption; for RFC 3161 verify the token cryptographically and bind the signer certificate fingerprint and policy to an external pinned TSA CA policy, independent of descriptor text. Validate both adapters with retained real evidence and adversarial fixtures before enabling any qualified authority gate.

## Tests and acceptance

`tests/test_anchor_gate.py` contains negative regression tests for pending OTS + placeholder TSR, placeholder TSR with explicit CA file, relabeled authority and fake timestamps, simulated per-anchor `confirmed` statuses without proof-derived authority, and signed self-reported dates without external ordering.

The expected synthetic report in `examples/expected-report.json` is updated for three non-passing anchor gates and one unchecked ordering outcome. The fixture must continue to have exit 2 (or exit 1 when an invalid proof is actually checked); never exit 0.

**Kill criterion:** A bundle containing only pending/unverifiable or fabricated external timestamp/authority data must never have a passing aggregate anchor or ordering status. If a test can force a pass from descriptor fields or status-only adapter outputs, block Round 1.

## Still required

A4 validated RFC 3161 signer/nonce/policy/time/CA lifecycle; A5 Bitcoin mainnet/genesis and verified block metadata plus actual six-confirmation OTS evidence; operational registration-before-packet release proof; demonstrated two-authority gate; independent human scrutiny; full-review-round negative fixtures. The interim state intentionally prevents claiming a confirmed review round.
