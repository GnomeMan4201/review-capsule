# Portable Review Record — v0.2.2 implementation baseline

This package contains the specification/build brief, author resolutions, reproducible primitive/semantic vectors and phase-0 evidence. The protocol has not been reviewed by a cryptographer. No security qualification is claimed.

Current documents: spec/REVIEW_RECORD_SPEC_v0.2.2.md and spec/BUILD_BRIEF_v0.2.2.md. S11–S16 are applied. The exact patch from the supplied v0.2.1 source is retained. Historical source/draft files remain labelled separately. FREEZE_v0.2.2.json records the current baseline bytes before production libraries.

## What ran

- Python/JavaScript agreed on 26 canonical-input cases, including the FF5E/1F600 ordering trap, Unicode/control handling, integer boundaries, duplicate keys, floats, exponents and lone surrogates.
- Both agreed on RFC 9162 roots for sizes 0, 1, 2, 3, 4, 5, 7 and 8. All 30 inclusion proofs checked; JavaScript rejected 90 altered-leaf, out-of-range-index and extra-proof cases.
- Three DSSE PAE cases agree, including the published hello-world example and multibyte byte-length checks.
- Three published RFC 8032 signatures matched using Python cryptography and Node crypto; altered signatures were rejected in both.
- Ten new counting and twelve path-function cases agree in Python and JavaScript. These are semantic test inputs, not signature findings. They cover duplicate leaves versus distinct lock counts, withdrawn/missing/valid reveals, first-commit retention and path hash/rid mismatches.
- The earlier real synthetic FreeTSA RFC 3161 request verified under the fetched FreeTSA root; changed-target verification failed. No new TSA request is implied by this version update.

Separate implementations are not separate human review. These checks do not establish signed-bundle acceptance, complete expected report, verifier kill tests, malformed-signature qualification, or a production verification path. No rrverify or participant signing tool exists yet.

## Reproduce [needs Linux runner]

Python 3.12 and Node 24 were used. Direct test dependency: cryptography==50.0.2. Node uses built-ins only. OpenSSL 3.0.13 was used for the earlier TSA exchange. Direct/transitive versions are recorded in evidence/runtime.json.

```sh
python -m pip install cryptography==50.0.2
python tools/vector_reference.py
node tools/vector_crosscheck.mjs
python tools/counting_vectors.py
node tools/counting_crosscheck.mjs
python tools/rfc8032_vectors.py
node tools/rfc8032_crosscheck.mjs
```

These checks read existing fixtures. Explicit --write regenerates vectors and must not silently replace an accepted frozen baseline. Python canon/Merkle/counting helpers use stdlib and may be tried in a-Shell, but iPhone execution was not tested. Known public RFC test seeds must never be used for actual participants.

## Current acceptance boundary

The baseline freeze is a reproducible checkpoint, not a completed verifier or permission to run a real review round. Round 1 requires passing full kill tests and checked CLI tools. The full signed-round fixture and expected report are still to be written. GitHub CI results are recorded separately from local outputs.

OpenTimestamps has not been submitted or confirmed here. Its documented verification path requires Bitcoin verification infrastructure; no Bitcoin service has been provisioned and the six-confirmation path is untested. Offline/unavailable checks cannot be reported as confirmed.

FreeTSA.org is a tested RFC 3161 candidate, not an audit of its operator or timekeeping. The experimental root was fetched over HTTPS; a later anchor adapter must pin/explain accepted CA material instead of trusting a root from an arbitrary bundle. The retained TSA files represent one synthetic feasibility target, not a completed two-anchor review record.

Review Capsule PR #1 remains separate and unmerged. Its receipts remain legacy-v0. No app/database deployment or migration is part of this package.

The delivery checksum list and baseline freeze record are not a protocol round manifest and are not externally timestamped anchors.

In this GitHub source tree, binary TSA request/response evidence is stored as .b64 files; decode it before replaying OpenSSL checks. The downloadable package retains original binary files. Root .github/workflows/reviewrecord-vectors.yml runs baseline checks; Capsule has separate CI.
