# After the collector routing repair

These literal ots info outputs were produced locally with opentimestamps-client 0.8.0 from the binary proof files in evidence commit 3f9780fdba9f8baf3c31a40daf0ab07bef1007d6. The outputs contain BitcoinBlockHeaderAttestation(974172) and the original pending calendar references. They do not establish mainnet header binding or confirmation depth. No Bitcoin RPC was selected or queried.

Collector repair: 44ee6f56c8c20397ad52cdf39401da046957e77c. Actions run 41359926591 upgraded all three existing proofs with no -c pool overrides, no resubmission and no target/preimage change. It preserved the previous versions. The pinned verifier still exits 2 with 158 pass, 0 fail, 0 missing, 3 pending, 6 unverifiable, 2 not checked. OTS validation_backend is now none configured; OTS outcomes are unverifiable_offline. The required-type gates remain pending.

Further hourly retries were paused after all three files acquired Bitcoin attestations because the next check requires an operator-chosen mainnet backend. Native GitHub cron remains inactive. PR #2 stays draft/unmerged and its published pin remains d54432f3e4c67f11ea53c16ebb383c1aec1f9224. No protocol source was changed by this repair. All 135 current synthetic tests pass locally and the evidence-branch suite passed GitHub Actions.

The historical TSA inputs in this experiment are placeholders. A separate, matching token/request and externally chosen CA/signer/OID policy are still needed before a strict FreeTSA run can be attempted. Registry-message and neutral-check-name improvements are only in the labelled companion view; the pinned verifier output remains literal.
