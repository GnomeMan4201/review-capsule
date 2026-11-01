# Round-1 eligibility gate — 2026-11-01 (not authorized)

Review Record v0.2.2 remains a *draft candidate protocol*, not a security-certified system, a research-correctness validator, or a guarantee of reviewers' independence. Neither the author nor an assisting AI constitutes an independent human cryptographic review. The frozen specification governs, and normative changes require an explicit versioned decision.

## Mandatory gates

| Gate | Condition | State (2026-11-01) |
|---|---|---|
| G1 Frozen protocol | Normative spec/brief, limits and vectors unchanged; baseline hash checked | **Demonstrated in GitHub CI**, limited to frozen source files |
| G2 Verifier kill tests | Signature, role, log, path, Merkle, counting, withdrawn, omission and malformed-evidence negative cases | **Partial** — synthetic CI demonstrated, negative fixture set not exhaustive |
| G3 Participant signing | Local author, reviewer and steward roles checked without sharing private keys | **Candidate implemented** — only synthetic tests; no iPhone test or separate operator reproduction |
| G4 Confidential pre-close intake | Never store pre-close assessment; foreign key and copied commitment rejected; signed receipts | **Candidate tested**; compromised host/manual off-tool disclosure unsolved |
| G5 Steward lifecycle | Signed append log, immutable close, withdrawn reviewer valid reveal, inclusion proof; recovery evidence | **Partial** — simulated interruption tests; no SIGKILL/power-loss qualification |
| G6 Admission governance | A disclosed, frozen invitation/admission/decline policy with auditable rejection accounting | **Open** — steward discretion only |
| G7 Full actor-produced bundle | Tool-created bundle, expected keys, verified manifest, dispositions and retained negative evidence | **Candidate synthetic tests**, no real externally anchored bundle |
| G8 External anchors | For registration, close and record, verified OTS depth >=6 and an RFC3161 token under pinned policy, derived authorities and attested times | **Open** — no real confirmed two-authority round; gate fails closed |
| G9 External ordering | Registration anchored before packet release, close/commit and reveal ordering bounded by authenticated proof + receipts | **Open**, signed clocks not evidence |
| G10 Independent cross-implementation | Second verifier in a different language on same positive/negative bundle corpus | **Open** — JavaScript only cross-checks primitives |
| G11 Input hardening | Resource caps, typed error handling, fuzz/property tests, recovery and negative-input fixture coverage | **Partial** — ZIP, signature, limits tests exist; broader fuzz/recovery unfinished |
| G12 Independent human review | Cryptographer/security engineer reads exact pinned spec and code, tests reproduction and documents findings; or author explicitly waives this gate in writing | **Open**, no review or waiver |
| G13 Final rehearsal | Throwaway packet reviewed end-to-end with all actor tools, external anchors, named registry and a reviewer independently following instructions | **Open** |

All gates must be met before asking real external reviewers to participate. An explicit, signed author waiver of G12 is a recorded policy choice, not equivalent evidence of independent scrutiny, and does not waive G8/G9 or any confidentiality kill criterion. No gate is satisfied merely because GitHub CI is green.

## Stop conditions

- A pre-close steward intake stores a full assessment or issues a signed receipt under a mismatched reviewer's key.
- A copied commitment under distinct reviewer keys increases lock count without any explicit failure.
- A missing/invalid/pending anchor is treated as a confirmed independent timing authority, or unsigned descriptor metadata creates a time claim.
- A forged/truncated/reordered log or modified first-counting reveal is accepted.
- An operator silently repairs an interrupted append or removes a negative/withdrawn review.
- A published tool report contains a single global scientific correctness verdict or claims participant independence.

Any one stops live operation, even if a count threshold reports `round_status=complete`.

## Decision rights

No merge, external deployment, participant onboarding or actual review round occurs without an explicit author decision. Keeping PR #2 draft is intentional. Research process integrity claims remain limited to what a separately verified signed and externally anchored record supports. Review contents are not proof of correctness, competence, honesty, blinding, absence of prior exposure, or lack of collusion.
