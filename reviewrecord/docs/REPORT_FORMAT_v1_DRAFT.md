# Draft report format: reviewrecord-report/v1

[assumed] AI-assisted implementation by ChatGPT; claim boundary: process integrity only. This is an opt-in draft output contract, not an amended frozen v0.2.2 protocol or evidence of reader comprehension. Security qualification: not established. Merge requires specific approval.

[demonstrated here] Baseline is Part B draft PR #11 at e0e178e9f09aacaa194b8cd20b86c1b5da00378b, based on d54432f3e4c67f11ea53c16ebb383c1aec1f9224. At the original pin, verify.py:127 and 275–278 emit operator/withdrawal notices as pass; 279–283 produces verified_reveals and threshold-only round_status. report.py:16 folds only emitted blocking statuses. Source: https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/verify.py#L275

[demonstrated here] Frozen spec line 106 and 278 require the old round_status output. Line 286 defines six statuses and exits. Lines 84,125,218 distinguish declarations and attribution from facts. The new format deliberately changes the output contract under a separate identifier; it does not claim to be byte-compatible frozen v0.2.2 output. The spec field still identifies the signed protocol version; report_format identifies the report contract.

## Selection and schema

[assumed] Library selection: verify_bundle(..., report_format='reviewrecord-report/v1'). CLI selection: rrverify BUNDLE --report-format reviewrecord-report/v1. Default legacy format retains old fields/example output. Full verifier execution needs the Linux runner and existing pinned cryptography/OpenTimestamps/OpenSSL dependencies; the standalone renderer uses stdlib only.

[demonstrated here] report_v1.render removes only pass notices with OPERATOR_DISCLOSURE, WITHDRAWN or WITHDRAWAL_STEWARD_ATTESTED. It retains every fail/missing/pending/unverifiable/not_checked check and every matched structural/signature/binding/count predicate. Exit code comes from the existing check fold; statement and coverage collections do not enter it. Pass totals are recomputed from retained check rows.

| Field | Meaning and boundaries |
|---|---|
| report_format | [assumed] Exact identifier reviewrecord-report/v1; explicit opt-in. |
| spec | [assumed] Signed protocol version, currently 0.2.2; not the report-format version. |
| statements_and_events | [assumed] Declaration content, operator boolean for true and false, withdrawal assertions, author disposition content. Each row carries kind, basis, source, subject, asserted_by, content, wording, attribution, check_refs. No top-level check-status or exit-effect field. |
| attribution | [assumed] Claimed signing key, not a claim the signature matched. Check_refs are JSON pointers to retained signature/path/binding/shape outcomes for the source, including failures. A rejected claim may still be displayed with its failure evidence. |
| basis | [assumed] participant_declared, steward_attested, author_declared: attribution labels, not check statuses. |
| coverage_notices | [assumed] scope, subject, execution, reason, candidate_count, checked_count, wording. These describe encountered scope; they do not enumerate all mandatory checks. No status or exit-effect override. |
| review_counts | [assumed] logged_distinct_commit_keys, first_commit_matching_reveals, commit_log_entries, policy_min_locks, policy_min_reveals. Counts use signing keys and local predicates, not people or external membership. Values are null where not computed/available. |
| count_scope | [assumed] Supplied record only; other failures remain separate. |
| checks/counts/exit_code | [assumed] Six defined check statuses, Part B vocabulary guard and existing fold. pass counts matched predicates rather than the moved notices. |

[assumed] New-format output removes round_status, verified_reveals, locked_count, tree_size and the old declarations array; their scoped/count/content counterparts are above. The separately signed close document and its fields are unchanged. No combined round verdict, boolean or compatibility alias is added in the new format. Per-reviewer reveal/withdrawal metadata remains scoped metadata.

[assumed] “Matched predicate” does not endorse signed content, meaningful author changes, separate controlling parties, causal order, unique log history, actual first disclosure or research correctness. S-8's ordering label is not repaired by this report change; its time-comparison behavior remains a separate concern.

## Applicability and held decisions

| Situation | Notice reason / wording | Present exit effect |
|---|---|---|
| disposition_required=false | [demonstrated here] policy_disabled: “Disposition-presence checking skipped: disposition_required=false. No claim that dispositions are complete.” | [assumed] Preserve today's effect; do not add a new blocker. Existing supplied-disposition failures still count. Whether a strict Round 1 profile should instead emit not_checked/2 is HELD. |
| Matching empty snapshot | [demonstrated here] matching_snapshot_empty: “Matching supplied registry snapshot contains zero prior-round entries; zero membership comparisons performed. Coverage outside this snapshot is unknown.” | [assumed] Preserve today's zero-comparison behavior. Global registry coverage is not established. |
| Different work_id | [demonstrated here] work_id_mismatch: “Snapshot skipped: work_id does not match this registration.” | [assumed] Preserve the existing REGISTRY_NOT_CHECKED blocker when no matching coverage exists. |
| Descriptor outside required targets | [demonstrated here] target_not_requested: “Descriptor skipped: target is outside this invocation's required target set. Required target checks are reported separately.” | [assumed] Notice is inert; a surplus descriptor cannot satisfy a required target. |
| Non-object descriptor entry | [demonstrated here] descriptor_not_object: “Entry skipped by current descriptor enumeration: expected an object. This notice does not assess required-target coverage.” | [assumed] Preserve today's enumeration skip; required-target absence still blocks. |

[assumed] Missing pins, absent registries and unavailable backends remain actual not_checked/unverifiable check outcomes. They are not converted into inert coverage notices. Default wording for not_checked becomes “Check not evaluated; examine scope and configuration.” Existing explicit details remain intact.

[assumed] Future exit effects of skipped required checks, mandatory-check inventories, empty-report safeguards, roster and fork designs remain unselected. This branch provides no strict-profile option. Later invitation/decline/countersignature statements would use the side section; future roster/head comparison predicates would need separate check definitions; unperformed comparisons would need coverage notices. No membership set or fork predicate is chosen here.

## Local red-first evidence and controls

[demonstrated here] Initial report-v1/red.log: `Ran 10 tests in 0.393s` / `FAILED (errors=10)` before the opt-in API existed. Final report-v1/green.log: `Ran 13 tests in 0.936s` / `OK`. Removing A/C/D while retaining Part B: removed.log `Ran 13 tests in 0.545s` / `FAILED (errors=16)`. These failures include absent API/schema support; they are not evidence of a broken anchor predicate.

[demonstrated here] Adversarial testing of the first renderer produced `Ran 13 tests in 0.911s` / `FAILED (errors=3)`: an unhashable descriptor target and unknown list/dict statuses crashed newly introduced membership/default-text paths. Type guards addressed those cases; regression tests remain. Forbidden tool-authored side wording still adds fail checks.

[demonstrated here] Restored full.log: `Ran 139 tests in 5.336s` / `OK`: 122 original baseline methods, four Part B guard/control methods, thirteen format/control methods. Separately known-gap.log: `Ran 1 test in 0.000s` / `OK`, reproducing the empty/unrelated-pass boundary; not a mitigation or extra assurance test. PR #7's five observations are not included in this total. Frozen file and projection hashes matched locally; neither was edited.

[demonstrated here] controls.json retains measured outputs. Explicit MOCKED anchor baseline returns 0; actual offline adapter with synthetic pending OTS/placeholder TSA returns 2. MOCKED steward allegation, false disposition policy, empty matching registry and omitted-C variants each still return 0, with unchanged legacy/new-format exits. These are limits of the current predicates, not detection or real anchor qualification.

[assumed] Negative controls are in test_report_v1.py: invalid withdrawal signer -> 1; enabled disposition policy with three missing dispositions -> 1/three missing rows; snapshot naming an omitted prior round -> 1; unmatched-only snapshot -> 2; required anchor descriptor removed despite surplus descriptor -> 1; required reveal removed -> 1; missing pins/registries or offline backend remain 2. Exit 2 on the offline baseline is not detection of an omission or fork.

[demonstrated here] New examples/report-v1/expected-report.json is a synthetic offline output: pass=156, fail=0, missing=0, pending=6, unverifiable=3, not_checked=2, exit_code=2. It is not a mocked exit-0 anchor report. Frozen examples/expected-report.json remains unchanged, including its 158 informational/predicate passes.

## Spec and artifact impact

| Change | Frozen lines / artifacts implicated | This branch |
|---|---|---|
| Separate statements/events | [demonstrated here] Spec 84,103,125,218,236,286 | [assumed] New report contract only; frozen spec unchanged. No reviewer-consent requirement added. |
| Coverage display | [demonstrated here] Spec 104,212–213,269,280–281,284,286 | [assumed] Inert notices preserve existing exits. Strict required-profile behavior HELD. |
| Scoped fields | [demonstrated here] Spec 99–106,199,278; frozen counting vectors name old fields | [assumed] New output names/example; frozen counting vectors still test the old counting contract. No arithmetic change. |
| Primitive/freeze files | [demonstrated here] Frozen baseline covers spec, tools and vector bytes | [assumed] No changes; new sample lives in a separate directory. |

[assumed] Before this format replaces legacy output, the report contract and any corresponding normative references need a separately approved versioned revision. This draft exposes it only by explicit selection. No new protocol acceptance profile or frozen-file rewrite is authorized by this implementation.

## Three remaining failure modes and unrun work

[assumed] Side sections could hide caveats in a future viewer; check pointers and adjacent caveat text are present, but actual reader comprehension remains unknown. No UI was built.

[assumed] Inert notices could make deliberately weak scope look acceptable; tests preserve both mocked false-policy exit 0 and strict true-policy missing-disposition exit 1, without selecting a future strict profile. Labels alone do not solve this policy issue.

[assumed] Narrower counts could still be read as a whole-record judgment. Missing-reveal and omitted-C controls expose the local scope; no expected roster, unique head, missing mandatory-check inventory or causal-order evidence is created by naming.

[unknown] Hosted CI, actual iPhone/a-Shell execution, human reader testing, external human cryptographic review, all-real-anchor exit 0, universal malformed-input coverage, performance bounds of the new renderer, and exhaustive code-to-evidence coverage were not established. Local tests use synthetic fixtures; all new exit-0 anchor controls use an explicitly MOCKED adapter.
