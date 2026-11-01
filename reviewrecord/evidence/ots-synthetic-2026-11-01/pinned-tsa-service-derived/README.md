# Retained-token exercise with service-derived TSA pins

Scope: throwaway synthetic round only. The verifier source is unchanged at
`d54432f3e4c67f11ea53c16ebb383c1aec1f9224`. Inputs were fetched from evidence
snapshot `41011fe3f20ebb03dcfad04fb502b0549c7734b3`. This was a local Linux
execution, not a GitHub Actions execution. No new calendar, TSA, explorer or
Bitcoin network request was made. Existing proof history was not changed.

## Demonstrated output

The reconstructed unconfigured baseline equals the retained external-demo
report as a parsed JSON object. `baseline.json` preserves that rerun output.
The unchanged pinned CLI was then run with CA, signer and policy pins supplied:

```text
Integrity checks: 162 pass, 0 fail, 0 missing, 3 pending, 3 unverifiable, 1 not checked
rrverify exit_code=2
```

All three RFC3161 rows are `confirmed` under these supplied pins. All three OTS
rows remain `unverifiable_offline`: no Bitcoin backend was enabled. All three
target gates remain `ANCHOR_GATE_UNCONFIRMED` / `pending`. Registry coverage is
`not_checked`. Registration-to-close token-time comparison now passes, but the
report explicitly says it does not prove packet release order. These retained
tokens were obtained after the completed synthetic round.

The wrong-policy control changes only the supplied policy OID to `1.2.3.4.999`.
All three TSA anchors become `invalid`; the control exits 1:

```text
Integrity checks: 158 pass, 3 fail, 0 missing, 3 pending, 3 unverifiable, 2 not checked
```

## Trust inputs and remaining limits

`service-derived-pins.json` was derived from the retained FreeTSA CA file and
token signer/policy. The CA and signer certificate came from FreeTSA itself.
This is a mechanically exercised pin path, not an author-approved production
authority profile. No CA governance, revocation, key-compromise handling or
clock qualification was tested. No node header binding or six-confirmation
depth check was run. No outside reviewer or real research was involved.

The original descriptors inside the bundle are retained byte-for-byte from
the reconstructed baseline. Their `validation_backend` labels still say
production pins were not selected. The CLI inputs below, `run.json`, and the
proof-derived rows in the literal report describe what actually ran; descriptor
labels alone are not execution evidence. The pinned report was not rewritten
to improve its wording.

## Inputs and reproduction

`bundle.zip.b64` contains the complete reconstructed bundle, including retained
real OTS files, TSA responses and original requests. Decoded ZIP SHA-256:
`8bece6e9cfd0740c9cae7acbd53f1f600ca6971a80d57c524678f2a9a2f45fac`.
`input-files.json` lists SHA-256 of every bundle file. CA/signer copies are
outside the bundle, as are the supplied policy pins. No committed target,
registration, packet, policy, assessment or manifest was changed.

Runtime used: Python 3.12.14, cryptography 50.0.2, opentimestamps 0.5.0,
OpenSSL 3.0.13. The command below requires a Linux runner with those dependencies
and the source checkout pinned to the commit above. Run it from this evidence
directory, setting `PYTHONPATH` to the pinned checkout's `reviewrecord/src`.

```sh
python -c 'import base64,pathlib,zipfile,io; zipfile.ZipFile(io.BytesIO(base64.b64decode(pathlib.Path("bundle.zip.b64").read_bytes()))).extractall("bundle")'
python -m rr.cli bundle --json rerun-report.json \
  --expected-author-key ed25519:E9Qr7-BevC_AoKf7Rnk3PEfL_74RfvTsM9LDESN0L2M \
  --expected-steward-key ed25519:FY0ZfQGqVG8NfK4My5VGH-y3LIsobA98H_IVFwkUZHg \
  --tsa-ca cacert.pem --tsa-untrusted tsa.crt \
  --tsa-policy service-derived-pins.json
```

Exit 2 is expected. Omit all three `--tsa-*` arguments for the baseline. Replace
the policy filename with `wrong-policy-pins.json` for the rejection control.
No `--network` flag is used. Expected keys are synthetic fixture keys, not an
assertion about a human identity. The reports and summaries here are literal
CLI output; run.json records exit codes and scope.

## Next intentional revision queue

These are wording concerns to transfer to the public concerns list when the
author chooses a revision; this run does not edit that list or main:

- Distinguish a missing/placeholder token from a real token lacking supplied
  CA/signer/policy configuration in the report itself, rather than only in the
  evidence index. Preserve historical reports and the public source pin.
- Separate descriptor backend labels from the actual runtime backend/pin
  inputs in the report.
- Replace the `REGISTRY_NOT_CHECKED` detail `Check did not match.` with a
  description that no registry coverage was supplied.

No protocol changes, merges, deployments, follow-up resumption or production
trust decisions were made in this exercise. The draft PR and DEV.to source pin
remain unchanged. This protocol has not had a cryptographer's review.
