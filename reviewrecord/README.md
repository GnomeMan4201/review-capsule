# Portable Review Record — v0.2.2 candidate

**Draft/unmerged. Not deployed. Not independently reviewed. No Round 1 authorized.**

The protocol records signed commitments, reviewer declarations and the declared close/reveal boundary. It supports **process-integrity checks only**, not evidence of participant independence, no contact/collusion, blinding or research correctness. The frozen specification is `spec/REVIEW_RECORD_SPEC_v0.2.2.md` with `spec/BUILD_BRIEF_v0.2.2.md`, `spec/FREEZE_v0.2.2.json` and `spec/limits.txt`. Historical source/draft files are retained separately.

## Current tools

| CLI | Role and current candidate function |
|---|---|
| `rrverify` | Read-only offline bundle verifier, per-check outcomes and explicit exit status |
| `rrreview` | Reviewer-local key, declaration, assessment and commitment signing |
| `rrsteward` | Offline pre-close intake with signed acknowledgements; explicitly attested withdrawals; signed close; post-close reveal and inclusion proof |
| `rrauthor` | Author-local registration, explicit prior-round list and proof-bound dispositions |
| `rrbundle` | Assemble manifest and signed-object bundle, with explicitly incomplete diagnostic export or supplied anchor evidence |

These tools use Python 3.12+, `cryptography==50.0.2` and `opentimestamps-client==0.8.0` (native OpenSSL for TSA verification). [needs Linux runner] iOS/a-Shell behavior is not tested. Python/JavaScript cross-checks cover primitives, **not** a second full verifier. None of these tools is a hosted service or an automatic reviewer-selection system.

## Reproduction

From `reviewrecord/`:

```sh
python -m pip install -e .
python tools/vector_reference.py
node tools/vector_crosscheck.mjs
python tools/counting_vectors.py
node tools/counting_crosscheck.mjs
python tools/rfc8032_vectors.py
node tools/rfc8032_crosscheck.mjs
python -m unittest discover -s tests -v
rrverify /path/to/bundle --json report.json
```

The frozen vectors check canon-v1 JSON, RFC 9162 Merkle tree/inclusion proofs, DSSE PAE and published RFC 8032 Ed25519 cases. `--write` on vector tools regenerates output and must not silently replace the accepted freeze.

GitHub Actions: `.github/workflows/reviewrecord-vectors.yml` checks frozen hashes, vectors and the Python regression suite. At commit `abbdcd18`, the Review Record run reported **122 synthetic tests passing**, including a locally generated RFC 3161 positive and wrong-target rejection through the full verifier. Historical 113-test results at `4290ac84` are recorded in `spec/IMPLEMENTATION_STATUS_v0.2.2.md`. The separate `.github/workflows/verify.yml` checks the Django/hosted Capsule, **not** Review Record. The stored red-first kill-test evidence and all current limitations are described in `spec/IMPLEMENTATION_STATUS_v0.2.2.md`.

## Anchor and identity boundary

`rrverify` accepts a directory/ZIP; JSON defaults to stdout and a summary goes to stderr. Exit **1** means failed/missing checks, **2** means pending/unverifiable/not-checked without failures, **0** requires every mandatory check to pass. `round_status=complete` means only that lock/reveal minimums were met; it is not an overall verification verdict.

Supply `--expected-author-key` and `--expected-steward-key` obtained by a separately authenticated channel. Otherwise identity is `not_checked`. `--registry PATH` provides a locally supplied registry snapshot; freshness, origin and undisclosed rounds are not established. Offline is the default. `--network` enables only configured Bitcoin Core RPC; `--tsa-ca PATH` selects externally supplied TSA CA policy material. Nothing automatically trusts an unverified CA from the bundle.

The synthetic fixture has pending OTS and unverified RFC 3161 placeholders. **No real six-confirmation OTS proof or externally qualified two-authority ordering has been demonstrated.** Descriptor authority strings cannot qualify a gate. `ANCHOR_GATE_UNCONFIRMED`, `ANCHOR_AUTHORITY_NOT_CHECKED` and `ANCHOR_ORDER_NOT_CHECKED` deliberately remain non-passing. The historical real *synthetic* FreeTSA evidence demonstrates only a narrow digest/CA feasibility check. The strict-path local TSA regression now checks target/request/TSTInfo imprint equality, numeric DER policy, nonce, external signer/CA pins and token time. **This does not qualify FreeTSA or any real authority**, check revocation or key compromise, or establish anchoring before packet release. See `docs/TSA_BINDING_REMEDIATION.md`.

## Protocol workflow and limitations

- Reviewer signs a declaration before packet release. Their signed assessment remains private and only the signed commitment is sent before close.
- Steward holds plaintext packet, declarations and commitment hashes on a trusted local machine. Its candidate tool refuses pre-close assessment submissions and rejects identical commitment hashes from different reviewer keys, but cannot prevent external reviewer or steward disclosure.
- Steward signs the immutable declared close boundary, then accepts a reviewer-chosen reveal and generates a matching Merkle inclusion proof. Withdrawal never removes a lock, and an attested withdrawal is labeled as the steward's statement.
- Author supplies the held results and salt only after close, signs dispositions with retained negative findings, and bundle assembly computes a non-self-referential manifest/record hash. Export does **not** confirm real anchors.
- Steward admission remains discretionary; `reviewers_target` is advisory and no signed admission/decline ledger exists. Early/empty closes are permitted and remain incomplete under the verifier's threshold policy. Simulated crash orphans cause a halt, not silent repair.

## Documents

- [Implementation status](spec/IMPLEMENTATION_STATUS_v0.2.2.md)
- [Reviewer CLI](docs/REVIEWER_LOCAL_CLI.md)
- [Steward CLI](docs/STEWARD_CLI_CANDIDATE.md)
- [Author CLI](docs/AUTHOR_LOCAL_CLI.md)
- [Bundle builder](docs/BUNDLE_CANDIDATE.md)
- [Admission, custody and crash procedure](docs/ADMISSION_AND_RECOVERY.md)
- [External anchor-gate audit](docs/ANCHOR_GATE_AUDIT.md)
- [Written Round-1 acceptance gate](docs/ROUND1_GATE.md)

The broader Review Capsule hosted app remains separate and its existing receipts are `legacy-v0`. No deployment, merge, live participant test or cryptographic reviewer sign-off has occurred. GitHub CI is evidence of only the executed synthetic tests.
