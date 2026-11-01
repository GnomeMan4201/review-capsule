# Throwaway synthetic OTS evidence run

Source candidate: d54432f3e4c67f11ea53c16ebb383c1aec1f9224. This uses only the public synthetic example at that revision. There is no real research or real reviewer. The protocol PR and the DEV.to pin remain untouched.

`targets.json` lists the three gate targets. `targets/*.preimage` contains the **exact bytes** whose SHA-256 is that target: registration envelope bytes, close envelope bytes, and canon-v1 manifest projection bytes. These are not ASCII encodings of their digest. `ots stamp` hashes those files directly; stamping a digest string would produce a different target and would be refused.

The first Actions push runs `ots stamp` over all missing target files in one client invocation. The client batches the three file hashes with its nonce/Merkle machinery, then submits to the two explicitly selected calendars: https://a.pool.opentimestamps.org and https://b.pool.opentimestamps.org. Later runs use `ots upgrade` restricted to those calendar URLs. Calendar selection is a service availability/privacy assumption, not evidence of Bitcoin confirmation or a second anchor authority.

The original binary `.ots` files are retained beside the preimages and committed. `.ots.b64` files are transport mirrors only. `initial/` preserves the first returned proof bytes and `proof-history/` keeps every observed proof version by its own SHA-256. Git commit clocks do not prove time. The run journals preserve command argv/exit/stdout/stderr and advisory collection time.

`report.json` is the literal pinned verifier output over a derived bundle containing the real proof files. `summary.txt` contains the exact summary and verifier exit code. The original RFC 3161 placeholders remain unresolved: this is an OTS experiment, not a TSA qualification or a two-authority process record. The derived bundle is reproducible and deliberately excluded from git; its non-anchor bytes and record hash stay unchanged.

No Bitcoin node has been selected for the initial run. No RPC check is performed by default. A later explicit `verify_rpc` dispatch requires secret RR_BITCOIN_RPC and variable RR_BITCOIN_RPC_OPERATOR. The pinned gate checks mainnet genesis, header binding and depth >= 6 through that configured node. Its operator's tip/header data remain a node-trust assumption. Calendar-returned block/status assertions alone never pass the gate. A Bitcoin block timestamp is not a precise first-disclosure clock.

The workflow includes workflow_dispatch and hourly cron. GitHub schedules run only when the workflow is on the default branch; this evidence-only branch does **not** activate cron or change main. After the first push, the existing workflow job can be rerun to upgrade proofs. A separate scheduled follow-up may rerun it without merging PR #2. See the conversation for the actual schedule result; the presence of YAML is not evidence a timer is active.

The source and output limits are process integrity only. All unconfirmed/unavailable evidence stays non-passing. No production deployment, merge or real use is authorized by this run.

## First actual submission

Actions run 41346438636, attempt 1, completed calendar submission with client exit 0. All three returned proof files contain calendar references (alice/bob calendar endpoints) and no Bitcoin attestation yet. Proof commit: 2c0e52a9d988076e21abd50d1052f28e016d4cb2. The literal pinned report at that commit is retained as report.json; its exit code is 2. The collection time recorded in runs/41346438636-1.json is advisory Actions-clock metadata.

An hourly follow-up task was created for up to twelve checks to rerun the existing Actions collect job. This is separate from GitHub cron, which remains inactive on the evidence-only branch. The follow-up must pause for an operator choice if Bitcoin attestations appear but no RPC has been selected. No automatic selection of a public node is authorized.

The OTS 0.8.0 upgrade command exits when its first file is incomplete. Therefore the collector upgrades each retained proof in a separate invocation, preserving all exit codes and calendar output rather than letting a pending first file skip the others. Client exit 1 can mean an incomplete proof; consult the recorded stderr before calling it a calendar-access failure. In either case, the pinned report remains the evidence outcome.
