# OTS reviewer pack — fixed synthetic snapshot 5b2fc74

The three actual binary .ots files are under targets/, alongside their exact preimage bytes. These are the committed calendar-returned files, not generated substitutes. This pack snapshots evidence commit 5b2fc7417afefc17a6b6f3dda4bc4a2b0f161bb3 and the pinned candidate d54432f3e4c67f11ea53c16ebb383c1aec1f9224. All research, reviewers, keys and assessments in the underlying example are synthetic.

## Reproduce the offline check [needs Linux runner]

```sh
python -m pip install opentimestamps-client==0.8.0
python check_pending_proofs.py
```

proof-inspection.json is the output produced by running this command. Each starting SHA-256 digest matches its target; each preimage hashes to that target; each proof file hash matches the retained Actions journal. Each file contains two pending calendar attestations and no Bitcoin attestation. No calendar was contacted by this offline check. The same OTS parsing library was used; this is not a second human or cryptographic review.

## Report labels and evidence limits

pinned-verifier-report.json is the original literal report, byte for byte. It has not been edited to improve its wording. readable-report.json is a separately labelled companion view: pass-check names are neutral, failure codes appear only for fail/missing outcomes, and registry coverage says “No registry coverage supplied.” It preserves every check status and the source report hash.

The original validation_backend: Bitcoin Core field is a descriptor label, not an execution claim. Actual Bitcoin RPC backend: **none configured**. The OTS Python parser ran; Bitcoin mainnet-header binding and depth >= 6 did not. The companion view explicitly distinguishes those facts. No node or operator was selected.

The RFC 3161 files in the underlying OTS experiment are explicit SYNTHETIC-UNVERIFIED-RFC3161-PLACEHOLDER inputs. They are not the historical FreeTSA feasibility token. Adding CA/signer/OID pins cannot make placeholder bytes pass. A real strict-path run requires matching tokens and original requests plus externally selected CA, signer and policy pins. No such FreeTSA production qualification was performed here.

## Follow-up trigger

GitHub cron remains inactive on the evidence-only branch. A separate ChatGPT scheduled task reruns the existing GitHub Actions collect job, only when idle; the Actions job checks out the evidence branch head and records upgrades. The recorded first task run reran job 124969278689 in run 41346438636, attempt 2. The calendars returned Not found and proof bytes remained unchanged. The task is bounded to twelve checks and must pause for an RPC operator choice if Bitcoin attestations arrive without a chosen backend. Future execution is not guaranteed by the presence of a schedule.

## Narrow meaning

This pack demonstrates local file parsing and hash binding only. Pending calendar references are not Bitcoin confirmation, authority authentication or proof of first disclosure. No RPC, depth, TSA signer-policy, registry coverage or packet-release ordering result is claimed. The original verifier exit code remains 2. PR #2 remains draft and the published candidate pin is unchanged. The hosted Capsule login link is unrelated; no demo login or testing was requested.
