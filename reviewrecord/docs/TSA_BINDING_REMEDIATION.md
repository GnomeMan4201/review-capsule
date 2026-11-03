# TSA target-binding remediation — candidate checkpoint (2026-11-01)

**Security status:** Draft PR #2, no independent cryptographic review, no authorized real round. This is a defect record and a synthetic test checkpoint, not evidence of production TSA qualification. Frozen v0.2.2 normative files are unchanged.

## Confirmed vulnerability at 1921ede8

The strict RFC 3161 `rr.anchor_evidence.inspect()` branch verified a timestamp response against its **bundle-provided request**, not against the **descriptor target**. A signed token, matching request, signer certificate and externally provided pins could be reused for another registration/close/record hash and still produce `confirmed`. Malformed timestamp responses were also classified as `unverifiable_offline`, obscuring rejection versus unavailable verification.

Second-model audit: `claude_prepublication_audit_2026-11-01.md` (supplied externally by the author). That AI audit is not independent human review.

## Red-phase evidence

Test-only commit `182f0549` added `tests/test_tsa_strict.py`, generating a local test CA and TSA at runtime (no external network or persistent private keys). GitHub Actions [run 41336315166](https://github.com/GnomeMan4201/review-capsule/actions/runs/41336315166) ran 121 tests; two new regressions failed:
- Valid token/request for hash A was accepted for descriptor target hash B (`confirmed` instead of `invalid`).
- Malformed token was marked `unverifiable_offline` instead of `invalid`.

The locally stamped positive token passed. These failures are the **expected red phase**, not a passing security gate.

## Candidate repair

- `src/rr/tsa_der.py`: bounded DER extraction of a nonce-bearing RFC 3161 request's SHA-256 `MessageImprint`, and of the CMS-signed `TSTInfo` imprint, numeric policy OID, and `genTime`. This parser only extracts fields; **OpenSSL still performs signature and trust-path verification**.
- `src/rr/anchor_evidence.py`: require BOTH request and signed TSTInfo message imprints to match the descriptor target; require numeric policy OID equality to the external pin; verify response against original request, signer certificate fingerprint and externally supplied CA at the token time. Binary OID decoding does not depend on OpenSSL's display aliases such as `tsa_policy1`.
- Invalid/malformed/mismatched evidence returns `invalid` (verifier check `fail`, exit 1). Missing trust inputs or unavailable OpenSSL/backend returns `unverifiable_offline` (unverifiable, potentially exit 2). A missing nonce fails.
- `tests/test_tsa_strict.py`: positive locally generated token, wrong target negative, malformed negative, absent trust-input negative, and full `rrverify` integration for a wrong-target token.

To reproduce on Linux, use Python 3.12+, native OpenSSL, and the pinned project dependencies:
```sh
cd reviewrecord
python3 -m pip install -e .
python3 -m unittest discover -s tests -p 'test_tsa_strict.py' -v
python3 -m unittest discover -s tests -v
```

## Still unqualified

No real TSA token bound to the three actual review targets is proven under an independently sourced and lifecycle-qualified signer/CA policy. The locally generated certificate and policy pins are **test fixtures**; they cannot establish service independence.

Revocation, compromise or backdating of a TSA signing key, externally controlled pin provenance, real FreeTSA strict-path interoperability, and the true first packet-release time remain outside demonstrated coverage. Bitcoin OTS six-confirmation live verification is not demonstrated. External anchoring supplies **upper bounds on object existence**, not direct event creation times or proof of reviewer exposure. In particular, comparing two attested upper bounds is not proof that a packet was released after registration.

**Kill criterion:** No TSA proof may return `confirmed` for an anchor target unless an originally nonce-bearing request and the cryptographically verified TSTInfo carry that same SHA-256 digest. Any adversarial mismatch that still confirms blocks Round 1.

This is an implementation qualification record; no normative specification or signed-round evidence was altered.
