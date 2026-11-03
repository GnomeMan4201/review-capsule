# Candidate rrbundle — signed-object final record assembly

[needs Linux runner] Python 3.12 and project dependencies. Offline. **A successful export is not a verified review round**. There is no network submission, real anchor generation or permission to recruit participants.

The exporter reads a steward workspace after signed close. It checks the signed log, close fields, first-commit reveal/proof linkage, registered packet/policy, author-supplied withheld results/salt and supplied author-signed concern dispositions. It copies actor-signed bytes without altering them, builds `manifest.json` and computes `record_hash` over every included non-anchor file as specified in v0.2.2.

The author must explicitly supply the withheld file **only after close**. No pre-close step needs it. The exporter requires exactly one author-signed disposition for every explicitly listed concern in the revealed assessments; unsigned, duplicate and unknown concerns are refused.

## Diagnostic export without anchors

```sh
rrbundle \
  --workspace ./steward-work \
  --expected-author-key 'ed25519:<EXPECTED_AUTHOR_PUBLIC_KEY>' \
  --withheld ./private/withheld.json \
  --dispositions ./signed-dispositions \
  --allow-incomplete \
  --output ./bundle-incomplete

rrverify ./bundle-incomplete \
  --expected-author-key 'ed25519:<EXPECTED_AUTHOR_PUBLIC_KEY>' \
  --expected-steward-key 'ed25519:<EXPECTED_STEWARD_PUBLIC_KEY>'
```

This exports an explicitly incomplete diagnostic bundle. The verifier must report missing anchor evidence and cannot exit 0. It also cannot establish identity beyond supplied independently known expected keys.

To include externally obtained anchor descriptors and files, omit `--allow-incomplete` and instead supply `--anchors ./anchor-evidence`. Descriptor targets must refer to the registration, close or computed record hash. **The exporter does not verify Bitcoin confirmations, RFC 3161 signer identity, TSA policy or ordering**. It only transports locally supplied bytes. `rrverify` must perform evidence checks; the existing combined anchor gate intentionally remains unresolved pending proof-derived authority and attested-time implementation. A successful export with an anchor directory is not evidence that any proof was confirmed.

A record hash excludes `anchors/*`; this permits anchoring a fixed record without a self-referential hash. For synthetic tests, the bundle is first generated with `--allow-incomplete`, then test-only pending OTS calendar proofs and explicitly invalid TSA placeholders are generated for the exact three target hashes, and a second bundle with those test anchors is exported. The verifier should report **exit 2** (pending/unverifiable), no integrity failures, and never present the synthetic proof as Bitcoin-confirmed.

## Failure handling

The output directory must not already exist and is initially private (mode 0700). An interruption partway through writing leaves a partial export; it must be preserved or quarantined and never represented as complete. Rerun to a **new** output path only after reviewing the incident. Do not edit the contents of a signed record, or quietly omit declined dispositions.

The exporter does not prove completeness against a steward who suppressed objects before they were externally acknowledged, authenticate the supplied registry snapshot, determine reviewer eligibility, prove independent human participation or protect against a compromised workstation.

**Stop criterion:** If a tool-built output passes `rrverify` when an included signed source was changed, a declared concern lacks its signed disposition, or the only anchors are synthetic placeholders, the final-record workflow fails qualification.
