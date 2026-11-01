# Review Record v0.2.2 — implementation status (2026-11-01)

**Status:** draft PR #2, not merged, not deployed, no real Round 1 authorized. This document describes candidate tools and observed synthetic CI results, **not** independent security or cryptographic review. The frozen normative v0.2.2 specification, build brief, limits and cross-language primitive vectors remain unchanged. No external reviewer of this protocol has participated.

## Implementation inventory

| Component | Current scope | Evidence / qualification limit |
|---|---|---|
| `rrverify` | Offline directory/ZIP verifier; per-check outcomes for signatures, registration/packet/policy binding, hash/log/tree/first-commit counting, reveal proofs, dispositions, limits, registry and anchor adapters | Candidate; A2/A3 anchor authority and time gate deliberately non-passing |
| `rrreview` | Locally encrypted Ed25519 key; signed declarations, private assessments, reviewer-stated withdrawals and commitments; out-of-band author-key pin, packet/policy check and owner-only private assessment directory | No network upload, no iOS/a-Shell test, no independent reviewer following instructions |
| `rrsteward` | Registration intake; local pre-close declaration/commit/withdrawal intake, hash-chained signed acknowledgements, explicit steward-attested withdrawal, signed immutable close; post-close reveal import and Merkle proofs | Local workspace operator remains trusted; no atomic multi-file writes, no verified SIGKILL/power-loss recovery |
| `rrauthor` | Local registration signing with explicit `prior_rounds` input (including deliberate `[]`), withheld commitment and steward-operator disclosure; proof-bound author disposition signing after close | Result salt must be privately held until close; `change_ref` truth is not authenticated; no external registration anchor |
| `rrbundle` | Candidate final directory assembly from checked steward workspace, author withheld results/salt and signed dispositions; canonical manifest and `record_hash`, optional supplied anchors | Does not itself confirm anchors; `--allow-incomplete` is an explicitly diagnostic mode; real actor-only end-to-end review not run |

The reference round generator in `tests/reference_round.py` remains a **synthetic vector source**, not a participant tool. The bundle regression combines a tool-generated steward lifecycle with signed inputs from this fixture. It does not demonstrate a full external human review.

## Synthetic CI evidence

At commit `4290ac84`, GitHub Actions `reviewrecord-vectors.yml` ran **113 tests** and reported `OK` (GitHub run `41324667090`). Included are retained six kill tests, frozen reference vectors, reviewer and author signing, steward pre-close negative tests, post-close proof generation, attested withdrawal handling, duplicate/same-key and cross-key commitment behavior, limits synchronization, malformed ZIP inputs and an exported bundle checked by `rrverify`.

The test-built bundle with **no anchors** remains non-passing (exit 1 due to missing external proofs). The synthetic test-built bundle with *pending calendar OTS* evidence and *unverifiable RFC3161 placeholders* yields exit **2** with no other integrity failures. It has **zero externally confirmed anchors**, and this is a test assertion only, not a qualified production profile. These reports still show `round_status=complete` for the synthetic review counts; that is **not** an overall verification verdict or an independent-research claim.

The `.github/workflows/verify.yml` workflow tests the separate hosted Django Capsule, not Review Record. Earlier local 37-test and CI 94-test snapshots are historical; do not quote them as the current test count.

## Corrected security boundaries

- **A1:** pending/unverifiable anchors do not satisfy the confirmed-type gate; unsigned labels do not prove two authorities. `ANCHOR_GATE_UNCONFIRMED`, `ANCHOR_AUTHORITY_NOT_CHECKED` and `ANCHOR_ORDER_NOT_CHECKED` are not passing outcomes. A2/A3 remain unqualified.
- **A4/A5:** a retained real *synthetic* FreeTSA token passes the current digest-and-CA test path; wrong digest/CA fails. This is not a nonce, signer identity, TSA policy, token-time/expiry or certificate pin audit. Mainnet/genesis preflight and mocked OTS metadata paths exist; no upgraded, real six-deep OTS proof has passed the verifier.
- **A6/A8/A10/A13:** role-key overlap is refused; built-in limits match frozen spec and `limits.txt` in CI; ZIP reads are bounded with a compression-ratio ceiling; Base64/Ed25519 noncanonical tests exist. The frozen DSSE profile explicitly permits both standard and URL-safe Base64 spellings; changing that requires a versioned decision.
- **Commitment reuse:** exact same commitment hash under different reviewer keys is refused at intake; `rrverify` emits `COMMITMENT_REUSED_ACROSS_KEYS` on supplied colliding evidence. Multiple *different* commitments by the same reviewer keep their leaves and only the first counts.
- **Withdrawal:** the steward may issue a separately marked, steward-signed `steward_attested: true` withdrawal only for a declared reviewer. Its origin is **steward-attested**, not reviewer-stated. It does not remove any locked commitment or veto a valid reveal.
- **Admission:** any otherwise eligible signing key can currently submit a declaration; no signed roster, target cap, personhood check or audit trail of rejected admissions. It remains steward discretion and is a live-round governance blocker.
- **Close:** may be signed early or with zero locks. Its `closed_at` is a steward-clock assertion; `rrverify` computes any incomplete lock/reveal outcome. Timestamp field syntax is not independent chronology.
- **Crashes:** simulated orphaned pre-close objects or interrupted two-file post-close reveals halt without silent repair. The conservative *human-run* incident procedure preserves the workspace, documents a failed round and starts a separately registered replacement; there is no tested in-place recovery or real power-loss qualification.

See `docs/ADMISSION_AND_RECOVERY.md`, `docs/STEWARD_CLI_CANDIDATE.md`, `docs/AUTHOR_LOCAL_CLI.md`, `docs/BUNDLE_CANDIDATE.md`, `docs/ANCHOR_GATE_AUDIT.md`, and `docs/ROUND1_GATE.md`.

## Unresolved / must not claim

1. No authenticated proof-derived TSA signer identity, pinned production CA trust policy, nonce/policy/time/expiry qualification, or confirmed two-authority temporal ordering. Real OTS pending → upgraded → six confirmations remains untested.
2. No proof of pre-review packet-release chronology. Signing a registration and later anchoring its hash does **not** prove reviewers received the packet only afterwards.
3. No independently authenticated/fresh prior-round registry, public review invitation/decline accounting, protection from sockpuppets or collusion, or external guarantee that steward receipts were never suppressed.
4. No complete independent second-language verifier or full property/fuzz corpus. The existing JavaScript cross-checks only primitive operations.
5. No external cryptographer/security-engineer review, no live participant dry run, no independent reader validation of reviewer instructions, and no tested iOS execution.
6. No real three-target externally confirmed and independently ordered bundle. Synthetic actor tests are not evidence about real research outcomes.
7. No systematic code-mutation test proving that **each** historical fix is caught by regression tests when removed; the individual negative cases passed, but mutation coverage is not demonstrated.

**Hard stop:** if pre-close assessment bytes enter the steward workspace, a foreign signature obtains an acknowledgement, a copied cross-key commitment passes without a failing finding, a broken log or substituted reveal passes, or pending/unauthenticated anchors satisfy a final time gate, no Round 1 proceeds.

**Decision:** PR #2 remains draft and unmerged. All `docs/ROUND1_GATE.md` hard gates remain required; an external-review waiver must be a separate explicit author decision and does not establish that a review occurred. No deployment, recruitment, or research correctness claim is authorized by CI.
