# Read-only OTS request diagnostics

These diagnostics run ots info on the retained files, list the embedded calendar commitment bytes, and compare GET responses from the embedded calendars with the pool hosts used by prior -c overrides. They do not stamp, resubmit, overwrite proofs, call Bitcoin RPC or assert confirmation. Only the four explicitly allowlisted OTS hosts can be queried, with same-host HTTPS redirect rules and the OTS library response cap. Repeated request URLs across the three batched proofs are deduplicated.

The installed opentimestamps-client 0.8.0 source selects args.calendar_urls when -c is supplied, but logs attestation.uri in its warning. Thus previous lines headed Alice/Bob do not mean those native hosts were queried. The previous argv actually supplied a.pool and b.pool for both pending branches. Duplicate warning labels arise from the two overrides. Previous stderr did not retain HTTP status, final URL or exception class. New result files explicitly do.

The library converts HTTP 404 into CommitmentNotFoundError and sanitizes response text (including newline as underscore). A syntactically valid unfinished timestamp is a different result, not something to infer from Not found. Live response data and times are observations of these services, not authenticated time or Bitcoin confirmation.

Each results.json contains literal ots info stdout for all files plus requested URLs and response status/body. A parsed Bitcoin attestation in a calendar response is still unqualified without an operator-chosen mainnet backend and depth check. Existing proof histories, non-anchor targets, the pinned verifier and PR #2 are unchanged.

The separate hourly follow-up task remains bounded to twelve checks; native GitHub cron remains inactive on this branch. A read-only diagnostic is not a resubmission and does not reset the submission clock.

## Observed routing defect and repair

Actions diagnostic run 41359711322 captured HTTP 404 with body `Not found\n` for the four pool-host lookups. The matching native Alice and Bob lookups returned HTTP 200 and timestamp responses containing a BitcoinBlockHeaderAttestation for height 974172. This is evidence of a request-routing problem in the collector, not evidence that the original commitments were lost. Calendar-supplied block height remains unqualified until a chosen node checks it.

The collector had incorrectly forced its submission pool URLs onto upgrade requests. The repair removes upgrade `-c` overrides and permits only the exact embedded Alice/Bob URIs observed in the retained proofs. Submission behavior and all preimages/targets are unchanged. Unexpected embedded calendar URLs are refused before network access. Prior proof bytes are retained by hash before upgrade. The OTS descriptor now says `none configured` when no Bitcoin RPC was selected; this changes anchor metadata only, not the pinned verifier or its literal output rules.

No resubmission is required to correct the demonstrated routing error. No claim is made about confirmation depth or Bitcoin-mainnet inclusion based only on these calendar responses.
