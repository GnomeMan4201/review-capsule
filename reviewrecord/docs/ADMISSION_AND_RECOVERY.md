# Pre-close custody, admission and crash-recovery procedure — candidate

This is an operational limitation register, not a finding of participant independence or a versioned change to frozen spec v0.2.2.

## A. Admission and custody policy

**Current rule:** the steward may accept any well-formed declaration from a distinct eligible signing key that is not the author or steward. There is no signed allowlist, personhood screening, invitation record, or enforced `reviewers_target` cap. `reviewers_target` is a planning target, not a maximum. The first commitment per full reviewer key counts; later commitments by the same reviewer remain separate tree leaves under the frozen protocol and are reported as duplicates by the verifier. A same commitment digest submitted by two different reviewer keys is rejected at steward intake and separately flagged by `rrverify` as `COMMITMENT_REUSED_ACROSS_KEYS` in a supplied bundle. Distinct keys controlled by one person are **not detectable** here.

Admission decisions, including rejections, are steward-controlled and not independently attested. There is no public roster of everyone who attempted to participate, and rejecting a reviewer could bias which critiques enter the record. This is a **Round-1 governance blocker** until an admission/decline log and admission criteria are frozen and disclosed. Existing declarations describe participant claims, not verified eligibility or reviewer independence.

**Commitment secrecy model:** the steward workspace stores a plaintext copy of the packet and policy, public reviewer keys/declarations, each full signed commit envelope containing the assessment hash, and signed log acknowledgements. The assessment content itself must remain exclusively with each reviewer until close. Commitments need not be published before close; the steward controls access to its local records and signing key. However, a hash may leak through a steward-issued acknowledgement or reviewer publication. That is why copied commitment digests are rejected across distinct reviewer keys; this guard does **not** prevent copied or collusive assessments under distinct hashes.

The steward machine, filesystem permissions, backup/sync services, host administrator and operator are trust assumptions. Private workspace directories are mode 0700 in the candidate. This does **not** protect data from a compromised host, backups, administrator, screenshots, other software, or a reviewer manually releasing their own assessment. Participant-independent receipts and externally anchored checkpoints remain necessary for claims that go beyond operator assertions.

## B. Closing is allowed while incomplete

The protocol does not require the steward to wait until `min_locks` or the declared `deadline` before signing close. Closing with zero locks, before the deadline, or with fewer than `min_locks` can be necessary to record failure or abandonment. `close` is a signed **declared boundary**, not a machine-approved review. The verifier must report `LOCKS_BELOW_MINIMUM`, `REVEALS_BELOW_MINIMUM`, missing reveals, and computed `round_status=incomplete` as appropriate. Early close does not imply author or steward misconduct, and does not erase incomplete outcomes.

`registered_at`, `deadline`, `locked_at` and `closed_at` are signer-supplied timestamps, syntactically checked but **not independently authenticated time evidence**. The steward host clock generates `closed_at`; it may be wrong or manipulable. Nothing that depends on time passes until actual externally verified anchors and an adequate temporal-order policy exist.

## C. Human-run incident handling when an append or reveal crashes

**Current supported approach is preservation and abandonment, not in-place repair.** A crash after writing an object but before its acknowledgement leaves an orphan. A crash between reveal assessment and inclusion-proof writes leaves an incomplete pair. Both halt future steward operations. No CLI subcommand currently reconstructs or deletes these files. No SIGKILL/power-cut recovery claim is made.

1. **Stop all writers** immediately. Do not rerun intake, rename files, delete orphans or recreate signatures. Do not use the incomplete bundle as if its publication order were established.
2. Take an offline, byte-identical snapshot of the entire workspace and retain original file modes. On a trusted Linux host, inventory every file's relative path, size and SHA-256 into an incident document. Preserve reviewer-held acknowledgements and any independent commitment publications as separate evidence. Do not put private keys, passphrases or unrevealed assessments in the public incident report.
3. Classify the incident as an **orphaned pre-close object**, **partial post-close reveal**, or **suspected tamper/truncation**. Record the observed signed log sequence and last valid hash, the exact failing operation, the affected object hash and whether a reviewer claims to hold a receipt. Distinguish `receipt not retrieved` from `receipt known absent`. A missing local receipt does not prove it was never issued.
4. If the signed close was never created, **abandon the round** rather than invent a retroactive receipt or modify log history. Retain its registration and incident report. Start a fresh round with a new `round_id`; explicitly include the abandoned ID in `prior_rounds`. Do not reuse the old log or packet-release claims. Tell reviewers that commitments in the aborted round are not counted in the replacement unless they opt into the new round.
5. If the close exists and the interrupted write was a post-close reveal, preserve both versions. The reviewer can publish their locally signed assessment and receipt through an independent channel. A later *new* publication bundle may include those same signed bytes and a freshly computed inclusion proof, provided a separate verifier checks the match. The candidate steward CLI does not repair its own workspace; document the publication as an external continuation, not an uninterrupted local workflow.
6. If external checkpoint evidence disagrees with the local chain, treat this as potential equivocation or truncation; do **not** silently restart under the same `work_id` without documenting the incident. In every case, retain the unfavorable or aborted round in the public history registry if disclosed to participants.

**Human decision boundary:** The author must approve abandonment/restart and any public incident summary. No automatic operation can establish that a new acknowledgement would have existed at the claimed pre-crash time. This procedure prioritizes retained evidence over automatic availability.

## D. Acceptance requirements still open

- A tested SIGKILL/disk-interruption harness and recovery evidence from an actual Linux filesystem; current unit tests only simulate orphans.
- Signed, reviewable admission/decline policy. Any roster or cap that changes normative eligibility must be a versioned spec/policy decision before a real round.
- A second verifier and independent reviewer scrutiny of the steward filesystem, record completeness and exported bundles.
- Authenticated anchor identity and time ordering; no confirmed six-deep OTS evidence.

**Kill criterion:** If a failed append or reveal can be silently repaired by rewriting, deleting or skipping previously received signed bytes, or if a copied cross-key commitment can count as a valid independent lock without detection, stop the protocol.
