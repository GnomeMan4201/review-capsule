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

Separate implementations are not separate human review. A candidate rrverify CLI now checks signed synthetic bundles. Six kill tests and additional adversarial/vector/CLI tests run in CI. The test-first red output is retained. Participant signing/steward/bundle CLI tools and confirmed anchor qualification remain unfinished. See spec/IMPLEMENTATION_STATUS_v0.2.2.md for the exact boundary.

## Reproduce [needs Linux runner]

Python 3.12 and Node 24 were used. Direct dependencies: cryptography==50.0.2 and opentimestamps-client==0.8.0. Node uses built-ins only. OpenSSL 3.0.13 was used for the earlier TSA exchange. Direct/transitive versions are recorded in evidence/runtime.json.

```sh
python -m pip install -e .
python tools/vector_reference.py
node tools/vector_crosscheck.mjs
python tools/counting_vectors.py
node tools/counting_crosscheck.mjs
python tools/rfc8032_vectors.py
node tools/rfc8032_crosscheck.mjs
python -m unittest discover -s tests -v
python -m rr.cli /path/to/bundle --json report.json
```

These checks read existing fixtures. Explicit --write regenerates vectors and must not silently replace an accepted frozen baseline. Python canon/Merkle/counting helpers use stdlib and may be tried in a-Shell, but iPhone execution was not tested. Known public RFC test seeds must never be used for actual participants.

## Current acceptance boundary

The baseline freeze is a reproducible checkpoint, not a completed verifier or permission to run a real review round. Round 1 requires passing full kill tests and checked CLI tools. A complete synthetic signed-object fixture and its expected unresolved report are under examples/. It is not a confirmed anchored record. GitHub CI results are recorded separately from local outputs.

OpenTimestamps has not been submitted or confirmed here. Its documented verification path requires Bitcoin verification infrastructure; no Bitcoin service has been provisioned and the six-confirmation path is untested. Offline/unavailable checks cannot be reported as confirmed.

FreeTSA.org is a tested RFC 3161 candidate, not an audit of its operator or timekeeping. The experimental root was fetched over HTTPS; a later anchor adapter must pin/explain accepted CA material instead of trusting a root from an arbitrary bundle. The retained TSA files represent one synthetic feasibility target, not a completed two-anchor review record.

Review Capsule PR #1 remains separate and unmerged. Its receipts remain legacy-v0. No app/database deployment or migration is part of this package.

The delivery checksum list and baseline freeze record are not a protocol round manifest and are not externally timestamped anchors.


## CLI evidence and identity policy

`rrverify` accepts a directory or ZIP. JSON goes to stdout by default (or `--json PATH`), and a count summary goes to stderr. Exit 1 means failed/missing evidence; exit 2 means pending/unverifiable/not-checked outcomes without failures; exit 0 requires all mandatory checks to pass.

Supply `--expected-author-key KEY --expected-steward-key KEY` to check expected keys. Omitted keys yield not_checked identity outcomes. Declarations are displayed as declared by participant. The limits statement is signed in registration and compared byte for byte against limits.txt.

Offline is the default. `--network` permits only the configured Bitcoin Core RPC backend; `--bitcoin-rpc-env NAME` chooses the environment variable holding its URL. Credentials are not emitted. `--tsa-ca PATH` supplies external TSA CA material for OpenSSL verification. Bundle-provided roots are never selected automatically. Confirmed OTS evidence with six confirmations has not been demonstrated here.

`--registry PATH` accepts a local JSON snapshot: `{"source":"named URL or snapshot","work_id":"...","prior_rounds":["..."]}`. It may be repeated. This checks supplied content, not its provenance, and names precisely the snapshots used.

The example's OTS references and RFC 3161 placeholders remain unresolved; the tool never promotes descriptor status assertions to confirmations. See examples/README.md for reproduction. Historical binary TSA evidence is transported as .b64 on GitHub; it is separate from the example round. The root repository workflow runs the frozen baseline checks plus verifier tests from reviewrecord/.
