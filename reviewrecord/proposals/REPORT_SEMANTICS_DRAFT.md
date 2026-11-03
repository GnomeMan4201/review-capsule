# Draft: Review Record report semantics
[assumed] Recommendation for review only: put party statements/events in a separate section; retain the six check statuses; report skipped coverage separately without changing the exit fold; replace the broad round label with scoped measurements. This is a proposed report-contract revision, not an adopted protocol or an implemented remedy.

[assumed] Claim boundary: process integrity only. This draft was prepared with ChatGPT assistance. AI assistance is not an independent review. No human cryptographer review is claimed. Security qualification: not established.

[demonstrated here] Candidate source pin: [d54432f3e4c67f11ea53c16ebb383c1aec1f9224](https://github.com/GnomeMan4201/review-capsule/tree/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord). The proposal quotes the re-read source below. Experimental evidence is separately pinned at [12de4dce40ab7cd0ddc73fe5d60c7364bbfb525f](https://github.com/GnomeMan4201/review-capsule/blob/12de4dce40ab7cd0ddc73fe5d60c7364bbfb525f/reviewrecord/experiments/external_concerns/known_gap_tests.py); it is not production source.

[unknown] The requested “audit items 1 to 28” cannot be mapped exactly: the audit visible in this conversation contains 19 table rows without item numbers, plus boundary observations. This document covers those available categories and Parts A–F. It does not invent nine missing items or claim a complete 28-item crosswalk.

[assumed] Scope of this PR: this document only. No implementation, executable tests, spec/vector/freeze edits, mitigation adoption, roster choice, fork choice, merge, deployment or publication outside the requested draft PR. The proposed tests below are specifications, not files that were created or run.

## Evidence ledger

[demonstrated here] [report.py:6](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/report.py#L6): `'checks':[],'declarations':[],'reviewers':[],'anchors':[],'registry_coverage':[],'round_status':'incomplete'`.

[demonstrated here] [report.py:11](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/report.py#L11): `self.data['checks'].append({'code':code,'status':status,'subject':subject,'detail':detail or TOOL_TEXT['ok' if status=='pass' else 'fail']})`.

[demonstrated here] [report.py:13–16](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/report.py#L13):
> counts={name:0 for name in ('pass','fail','missing','pending','unverifiable','not_checked')}
> counts.update(Counter(x['status'] for x in self.data['checks']))
> self.data['counts']=counts
> self.data['exit_code']=1 if counts['fail'] or counts['missing'] else 2 if any(counts[k] for k in ('pending','unverifiable','not_checked')) else 0

[demonstrated here] [verify.py:127](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/verify.py#L127): `if reg.get('steward_is_author_operator') is True:report.add('OPERATOR_DISCLOSURE','pass','registration.json',TOOL_TEXT['warning'])`.

[demonstrated here] [verify.py:168–169](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/verify.py#L168): `add('DECLARATION_MALFORMED',complete,name);ok=ok and complete` and the appended data includes `{'basis':'declared by participant'}`. The declaration statement is already separate data; its shape check is a different predicate.

[demonstrated here] [verify.py:275–278](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/verify.py#L275):
> report.add('WITHDRAWAL_STEWARD_ATTESTED','pass',k,
>     detail='Steward signed this withdrawal allegation; reviewer consent is not established.')
> else:
>     report.add('WITHDRAWN','pass',k,detail='Withdrawal is retained; it does not remove the lock.')

[demonstrated here] [verify.py:279–283](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/verify.py#L279): `report.data.update(locked_count=locked,tree_size=len(commits),verified_reveals=reveals)`; `report.data['round_status']='complete' if locked>=policy['min_locks'] and reveals>=policy['min_reveals'] else 'incomplete'`.

[demonstrated here] [verify.py:295–300](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/verify.py#L295) checks nonempty disposition reasons and allowed status/change_ref shapes, then applies missing-disposition coverage only under `if policy_ok and policy['disposition_required']:`.

[demonstrated here] [verify.py:310](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/verify.py#L310): `if not name.startswith('anchors/') or type(descriptor) is not dict or descriptor.get('target')!=target:continue`.

[demonstrated here] [verify.py:377–380](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/verify.py#L377): matching snapshots are appended to `registry_coverage`; membership rows come from `for round_id in registry['prior_rounds']:`; the fallback checks whether `registry_coverage` is empty, not whether any membership comparisons occurred.

[demonstrated here] [spec:106](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/spec/REVIEW_RECORD_SPEC_v0.2.2.md#L106): “Counting rules are computed from these fields only.” It explicitly defines threshold-only `round_status` and says it is not an overall verdict.

[demonstrated here] [spec:125](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/spec/REVIEW_RECORD_SPEC_v0.2.2.md#L125): “The steward checks only that the declaration is complete and signed, not that it is true.”

[demonstrated here] [spec:218](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/spec/REVIEW_RECORD_SPEC_v0.2.2.md#L218) permits a steward-attested withdrawal and requires attribution to the steward rather than the reviewer. [Spec:84](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/spec/REVIEW_RECORD_SPEC_v0.2.2.md#L84) calls operator-role information a disclosure and warning.

[demonstrated here] [spec:286](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/spec/REVIEW_RECORD_SPEC_v0.2.2.md#L286):
> each check is `pass`, `fail`, `missing`, `pending`, `unverifiable` or `not_checked`.
> Exit 0 only if every mandatory check passes, 1 if anything fails or is missing, 2 if nothing failed but something is pending, unverifiable or not checked.

[demonstrated here] [spec:5](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/spec/REVIEW_RECORD_SPEC_v0.2.2.md#L5): “Changes to a frozen acceptance rule require a new version and retained change record.”

[demonstrated here] The pinned [expected report](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/examples/expected-report.json) has `"round_status": "complete"`, `"verified_reveals": 3`, `"pass": 158`, and `"exit_code": 2`. Its statement/event pass rows are `OPERATOR_DISCLOSURE` and `WITHDRAWN`.

## A. Statements separate from checks

[assumed] “Pass” should mean only that an identified predicate matched identified evidence. It must not mean that a party's signed content is true. A signature predicate may match while the signed assertion is false.

| Question | Option 1: declared/attested inside checks | Option 2: separate statements/events section |
|---|---|---|
| Representation | [assumed] Retain matched predicates as pass; replace notice rows with declared/attested. This expands the check vocabulary to eight statuses. | [assumed] Add `statements_and_events`; records carry `kind`, `basis`, `source`, `subject`, `asserted_by`, `content`, `check_refs`, and `wording`. They have no check-status or exit-effect field. |
| Steward-attested withdrawal with otherwise matched mandatory checks | [assumed] Exit 0 only if the fold is explicitly extended to treat declared/attested as informational. Under Part B's six-status rule it must instead return 1; this option therefore cannot coexist unchanged with Part B. | [assumed] Exit 0 remains possible. Signature/binding/path/log/count predicates stay in checks; the allegation contributes no pass and no blocker. |
| Same withdrawal with offline unresolved anchors | [assumed] Exit 2 under an extended informational fold; 1 if the six-status guard rejects the new statuses. | [assumed] Exit 2 remains 2. Removing an informational pass cannot erase unresolved anchor rows. |
| Is that desirable? | [assumed] A well-attributed allegation should not by itself decide the exit. Expanding statuses creates an extra policy question about how those statuses fold. | [assumed] Preserving the existing exit is desirable for this reporting-only change: v0.2.2 permits the steward allegation. Requiring reviewer consent would be a separate acceptance-rule revision, not a report cleanup. |
| Reader of pass count | [assumed] Should see matched predicates only, but mixed row types encourage treating “declared” as a weaker successful check. | [assumed] Gets a count of matched predicates; separately sees statements/events. No inference of consent, truth, distinct people, or whole-record coverage follows. |
| Changed fields | [assumed] `checks[].status`, `counts`, `summary`, possibly declaration/disposition content links and fold rules. | [assumed] New section; removal of three informational code variants from `checks`; lower pass counts/summary; source links from existing declaration/reviewer displays; disposition content newly exposed. |
| Spec/examples | [demonstrated here] Spec 286 enumerates six statuses; 84,125,218 distinguish disclosure and attribution. [assumed] New status vocabulary needs a revision. | [demonstrated here] Spec 84,103,125,218 govern these notices; 286 governs output. [assumed] Formal relocation/schema needs a new report contract; preserve required notice meaning in the new section. |

[assumed] Recommendation: Option 2. It preserves the six-status vocabulary and existing exit effects without assigning exit semantics to two new statuses. This is a structural recommendation, not evidence that readers will understand the presentation better.

[assumed] Proposed side-record bases: `participant_declared`, `steward_attested`, and `author_declared`; these are attribution values, not check statuses. A withdrawal event is a recorded statement about withdrawal, not proof the real-world event happened.

[assumed] Suggested wording: declaration — “Participant states: …; truth not established by these checks.” Steward withdrawal — “Steward states this reviewer withdrew; reviewer consent is not established.” Reviewer withdrawal — “Reviewer-key statement of withdrawal retained; lock retained.” Operator role — “Author registration declares steward_is_author_operator=true/false; role claim not factually established.” Disposition — “Author records disposition X with reason Y; any claimed change is not established by this row.”

[assumed] Record both operator boolean values so false is not mistaken for factual role separation. Preserve raw content and source attribution even when checks fail; `check_refs` must point to signature/binding outcomes, not silently label failed-signature content as authenticated. If source decoding fails, retain the existing parse failure rather than inventing attributed content.

[assumed] Keep `DECLARATION_MALFORMED`, signature/binding/path/log checks, withdrawal-set equality, retained-lock/reveal checks, and disposition shape/reason checks in `checks`. They are predicates. Move only statement content and informational event notices; do not remove these actual checks.

[assumed] No side row can suppress, replace or change a check outcome, including the tool-authored wording boundary. Moving text to a side section must not bypass that boundary; quoted participant input remains distinguished from tool-authored text.

[assumed] Examples affected in a later revision: a new-version counterpart of `examples/expected-report.json`, expected report snapshots in tests, and new counterparts of PR #7 e3/e4 outputs. Existing retained evidence is immutable history, not material to regenerate in place. The current example would lose two informational pass rows (158 to 156) under Option 2 alone and keep exit 2; this arithmetic is a proposed expectation, not an executed revised report.

## B. Unknown-status rejection, separate from coverage

[assumed] Let S = {pass, fail, missing, pending, unverifiable, not_checked}. Proposed total exit function on a sequence of check-status values:
1. If any value is not a string in S, return 1 and report a report-format error.
2. Otherwise, if any value is fail or missing, return 1.
3. Otherwise, if any value is pending, unverifiable or not_checked, return 2.
4. Otherwise return 0.

[assumed] The format error should have code `REPORT_STATUS_UNRECOGNIZED`, status `fail`, and wording “Report check status is outside the six defined values.” Preserve the offending value as diagnostic data; do not silently coerce it to pass or discard it. Check membership/type before folding.

[demonstrated here] Spec 286 defines exactly S and the same 1/2/0 precedence for those values. [assumed] This changes no exit outcome for any well-formed status sequence the frozen output contract defines. It changes handling of out-of-contract outputs such as `"typo"`, not the acceptance mapping for conforming reports. This claim is limited to the status fold, not every malformed bundle input.

[assumed] Empty sequences still return 0. A report containing only an unrelated pass still returns 0. Unknown-status rejection does not establish that mandatory checks ran. A mandatory-check inventory, empty-report guard, interrupted-run policy and report-completion evidence remain larger, unselected work; none is smuggled into this item.

[assumed] Option 2 side records and applicability notices never enter this fold. Existing check statuses, including existing not_checked blockers, continue to enter it. There is no configurable ignore-status option.

## C. Applicability without accidental exit changes

[assumed] Add a top-level `coverage_notices` array outside `checks`. Each notice has `scope`, `subject`, `execution`, `reason`, `candidate_count` (number or null), `checked_count`, and `wording`. It has no `status`, no `pass` flag and no user-supplied exit override. Exit folding reads only `checks`.

[assumed] These notices describe encountered scope, not a mandatory-check inventory. A notice cannot establish that every applicable check has been scheduled or executed.

| Case | Proposed notice | Exact proposed wording | Exit effect |
|---|---|---|---|
| disposition_required=false | [assumed] scope=disposition_presence; execution=skipped; reason=policy_disabled; checked_count=0; candidate_count=number of declared concerns | [assumed] “Disposition-presence checking skipped: disposition_required=false. No claim that dispositions are complete.” | [assumed] No new blocker. Existing checks on supplied dispositions still fold, including failures. |
| Matching empty registry snapshot | [assumed] scope=prior_round_membership; execution=zero_candidates; reason=matching_snapshot_empty; candidate_count=0; checked_count=0; subject identifies snapshot/source | [assumed] “Matching supplied registry snapshot contains zero prior-round entries; zero membership comparisons performed. Coverage outside this snapshot is unknown.” | [assumed] No new blocker. Preserve today's empty matching-snapshot behavior. |
| Registry for another work_id | [assumed] execution=skipped; reason=work_id_mismatch; checked_count=0 | [assumed] “Snapshot skipped: work_id does not match this registration.” | [assumed] Notice is inert; retain today's REGISTRY_NOT_CHECKED row when no matching coverage exists. |
| Nonmatching anchor descriptor target | [assumed] scope=anchor_descriptor; execution=skipped; reason=target_not_requested; checked_count=0; subject identifies path | [assumed] “Descriptor skipped: target is outside this invocation's required target set. Required target checks are reported separately.” | [assumed] No new blocker; never let this notice suppress ANCHOR_MISSING or target gates. |
| Non-dictionary JSON under anchors/ | [assumed] execution=skipped; reason=descriptor_not_object; checked_count=0 | [assumed] “Entry skipped by current descriptor enumeration: expected an object. This notice does not assess required-target coverage.” | [assumed] Preserve current skip behavior for this proposal. Whether malformed surplus entries should fail is a separate decision. |
| No supplied registries, missing key pins, unavailable anchor backend | [assumed] Optional supplementary notice referencing existing check rows | [assumed] “See the corresponding check outcome; this notice does not replace it.” | [assumed] Keep existing not_checked/unverifiable effects; do not downgrade them to inert notices. |

[assumed] Do not label a skipped check “Check did not match.” Use “not evaluated” with a reason. A zero-candidate enumeration is neither a pass nor an assertion of global absence.

## D. Scoped measurements rather than a round verdict

[assumed] Remove `round_status` in a new report contract. Replace it with `review_counts`, containing:
- `logged_distinct_commit_keys`: current locked_count measurement;
- `first_commit_matching_reveals`: current verified_reveals measurement;
- `commit_log_entries`: current tree_size measurement;
- `policy_min_locks` and `policy_min_reveals`: supplied policy numbers, or null if unavailable/malformed.

[assumed] Retain the separate lock/reveal threshold checks. Add no combined boolean, adjective, badge or round verdict. Counts concern supplied record structure and full signing keys; they do not count people or prove expected-member completeness, unique log history, first-disclosure timing, consent or research correctness.

[assumed] Display wording: “Supplied record: N distinct commitment keys; M first-commit-matching reveals; K commit log entries. Policy minimums: L locks, R reveals. Examine separate check outcomes and coverage notices.”

[assumed] Internal count computation is unchanged. The narrower reveal name does not assert that all surrounding evidence matched: include wording “Counted under local assessment/signature/binding/inclusion predicates; other check failures remain separate.”

[assumed] A count object is not inherently a single verdict. Readers may still treat M >= R as success; no name can guarantee interpretation. A broader round-level field is not necessary. Keeping `round_status` as a compatibility alias would retain the specific ambiguity, so prefer a versioned schema break rather than an alias in the new format.

## E. Red-first test plan; no tests implemented or run

[assumed] The following are exact proposed test names and assertions, not existing results. “Expected red” predicts behavior against the pin; it is not an observed test failure. A future implementation task must record baseline output, negative-control output, failing assertion, corrected result and failure again after removing the fix. Do not combine known-gap observations with the ordinary passing suite.

[demonstrated here] Existing [meta_probe.py](https://github.com/GnomeMan4201/review-capsule/blob/12de4dce40ab7cd0ddc73fe5d60c7364bbfb525f/reviewrecord/experiments/external_concerns/meta_probe.py) patches `rr.verify.anchor_evidence.inspect` with a test double. The retained [meta-probe.json](https://github.com/GnomeMan4201/review-capsule/blob/12de4dce40ab7cd0ddc73fe5d60c7364bbfb525f/reviewrecord/evidence/external-concerns-2026-11-02/meta-probe.json) says `"offline_control_exit": 2`, `"simulated_control_exit": 0`, `"mutation_control_exit": 0`, and `"mutation_exit_counts": {"0": 0, "1": 84, "2": 0}`.

[assumed] Harness controls for the new tests: M = full synthetic fixture with pinned supplied keys, nonempty matching synthetic registry and explicitly MOCKED qualified anchors; baseline exit 0. O = same fixture with actual offline adapter and synthetic pending/placeholder anchors; baseline exit 2. M is not anchor evidence. Under M, independently remove a required reveal or invalidate a signature and refresh manifest/record-target fixtures without repairing the defect; expected exit 1. Rebuild/re-sign only when the test specifically needs an internally consistent permitted alternative. Record these controls before relying on any semantic assertion.

| Proposed change / exact known-gap test name | Baseline | Negative control | Exact distinguishing assertion; expected red at pin | Pass condition in a future revision |
|---|---|---|---|---|
| A: `test_statement_events_do_not_count_as_matched_predicates` | [assumed] M with reviewer-stated withdrawal, then internally consistent steward-attested variant; O variants too | [assumed] Invalid withdrawal signer with refreshed manifest/anchor fixture; signature failure must remain exit 1 | [assumed] No checks with codes OPERATOR_DISCLOSURE, WITHDRAWN or WITHDRAWAL_STEWARD_ATTESTED; corresponding side row exists and steward wording contains “reviewer consent is not established”. Pin still puts notices in checks. | [assumed] Pass count equals number of matched predicate rows; M remains 0, O remains 2, invalid signer remains 1; attribution retained. |
| A: `test_statement_truth_is_not_inferred_from_shape_or_signature` | [assumed] Well-formed signed exposure/relationship declaration and author disposition content | [assumed] Malformed declaration or empty disposition reason, re-signed/rehash-consistent; actual shape failure must remain | [assumed] Side content has source/check_refs and caveat; shape/signature rows remain in checks; no statement-truth pass is created. Pin lacks side representation. | [assumed] Attribution and actual predicates remain separate; side section cannot erase failures. |
| A: `test_operator_false_is_declared_not_role_separation` | [assumed] Internally consistent true and false operator disclosures under M | [assumed] Wrong registration signer; side record cannot convey successful attribution | [assumed] Side row exists for both boolean values with “role claim not factually established”; no operator pass row. Pin has no false notice. | [assumed] Both displayed as claims, no identity/personhood claim; exits follow checks only. |
| B: `test_unrecognized_check_status_forces_nonzero` | [assumed] Direct Report with a synthetic pass row returns 0 | [assumed] Same synthetic code with fail returns 1; not_checked returns 2 | [assumed] For each of “typo”, “declared”, “attested”, null, true, 0 and “PASS”, result exit=1 and diagnostic code REPORT_STATUS_UNRECOGNIZED. Pin accepts or mishandles values rather than enforcing this contract. | [assumed] Every out-of-vocabulary value rejected; all 64 subsets of the six legal statuses retain prior fold outputs, including empty -> 0. |
| C: `test_disabled_disposition_coverage_is_visible_and_exit_neutral` | [assumed] M with disposition_required=false, three concerns and zero dispositions | [assumed] Same internally consistent profile with true and missing dispositions -> three missing rows, exit 1; O false -> 2 | [assumed] coverage_notices contains policy_disabled, candidate_count=3, checked_count=0, specified wording; exit remains 0 under M. Pin has no notice. | [assumed] Visible skip without newly blocking M or removing genuine missing/fail rows. |
| C: `test_empty_registry_is_zero_candidates_not_positive_coverage` | [assumed] M with matching empty snapshot; zero membership comparisons | [assumed] Matching nonempty snapshot names an omitted prior round -> PRIOR_ROUND_UNLISTED/fail and 1; unmatched-only snapshot retains not_checked and 2 | [assumed] Notice reason=matching_snapshot_empty, counts 0/0, caveat present; M exit=0. Pin has only the generic coverage entry. | [assumed] Empty scope exposed; nonempty mismatch still discriminates; no new global absence claim. |
| C: `test_skipped_anchor_descriptor_is_visible_without_masking_required_targets` | [assumed] M plus surplus canonical descriptor for a nonrequested target | [assumed] Remove a required current-target descriptor; unrelated descriptor cannot satisfy that target and exit=1 | [assumed] Notice reason=target_not_requested, checked_count=0, subject=surplus path; M exit=0. Pin silently skips it. | [assumed] Notice present and inert, required-target checks unchanged. |
| C: `test_nonobject_anchor_notice_preserves_current_scope` | [assumed] M plus canonical non-object JSON under anchors/ | [assumed] Replace a required descriptor with the non-object -> required-type missing row and 1 | [assumed] Surplus entry receives descriptor_not_object notice, M exit=0. Pin has no such notice. | [assumed] Enumerated skip visible; replacement cannot satisfy required targets. |
| C: `test_existing_unchecked_outcomes_are_not_reclassified_as_inert` | [assumed] O and M lacking expected key or matching registry | [assumed] Full M supplies these; exit=0 | [assumed] Revised schema exists AND original not_checked/unverifiable rows still fold to 2. Pin fails the schema assertion, not the already-correct blocking assertion. | [assumed] No regression from 2 to 0; this is chiefly a preservation control, not evidence of a current exit bug. |
| C: `test_not_checked_default_does_not_say_check_did_not_match` | [assumed] Direct synthetic not_checked row with omitted detail | [assumed] Direct synthetic fail row retains mismatch wording | [assumed] not_checked detail contains “not evaluated” and not “did not match”; exit stays 2. | [assumed] Wording distinguishes execution from mismatch for every non-pass status; fold unchanged. |
| D: `test_scoped_counts_replace_complete_label_without_hiding_failures` | [assumed] M and O, three locks/reveals; then a lower-count consistent fixture | [assumed] Missing required reveal -> 1 even when remaining reveals meet minimum; below-minimum fixture retains threshold failure | [assumed] Neither round_status nor verified_reveals exists; review_counts has proposed numeric fields; no combined verdict; numerical values equal old measurements. Pin exposes old keys. | [assumed] Same calculations and exits, explicit local scope, no overall status introduced. |
| Boundary: `test_side_sections_cannot_change_exit` | [assumed] Identical check list with valid side sections empty/populated | [assumed] One check changed from pass to fail -> 1 in both; not_checked -> 2 in both | [assumed] New-format support and identical exits for identical checks, including false-sounding assertions in side content. Pin lacks new format. | [assumed] No mutable exit-effect override; tool-authored claim-scan failures remain check failures. |

[assumed] A negative control is not discriminating if its baseline already produces the same asserted outcome. In particular, O's exit 2 must never be presented as fork detection or proof that a newly introduced semantic defect is rejected. Tests must assert specific new side rows/coverage/count fields, and use M plus an actual fail control when testing the exit.

[assumed] The unknown-status item needs only direct Report cases, not mocked anchors. M/O are required for integration exit-preservation claims. A test becoming green while source predicates are mocked is not evidence those predicates actually matched real proofs.

## F. Spec and artifact impact

[assumed] This table describes a future adoption, not edits authorized by this PR. Formal schema changes should use a distinct report-format version instead of silently shipping altered fields under the old format. The report-format version is not chosen here.

| Change | Frozen spec lines affected | Vectors affected | Report schema/examples affected | New spec revision? |
|---|---|---|---|---|
| A Option 1: declared/attested in checks (not recommended) | [demonstrated here] 84,125,218 attribution; 286 six statuses/exit | [assumed] No primitive byte algorithms; report fixtures change | [assumed] Status enum/counts/summary/fold and expected report | [assumed] Yes: expands enumerated statuses and needs exit semantics; incompatible with B unchanged |
| A Option 2: separate statements/events (recommended for review) | [demonstrated here] 84,103,125,218 notice obligations; 236 disposition content; 286 output | [assumed] Canon/PAE/Merkle/RFC8032 unchanged; counting rules unchanged | [assumed] New section, attribution links, moved notice rows/pass totals; new expected-report counterpart | [assumed] Yes for formal revised output contract; no change to permission for steward allegations |
| B: reject unknown statuses | [demonstrated here] 286 already limits vocabulary and defines legal fold | [assumed] None; 64 legal status subsets preserve outcomes | [assumed] New error code for out-of-contract data; conforming reports unchanged | [assumed] No new acceptance rule for defined statuses; implementation correction can stand alone. Record rationale; do not edit frozen text |
| C: inert coverage_notices | [demonstrated here] 104 disposition policy; 212–213 anchor reporting; 269 outcomes; 280–281 coverage; 284 existing identity notices; 286 exit | [assumed] No primitive/counting change | [assumed] New array; examples for zero/skipped scope; original check blockers retained | [assumed] Version the output contract; no new acceptance rule if exit-neutral. Any newly mandatory scope would require separate protocol revision |
| C: accurate default wording | [demonstrated here] 286 status distinctions; report.py:11 currently shares mismatch default | [assumed] None | [assumed] Text and snapshots only | [assumed] No acceptance-rule revision; document text compatibility change |
| D: numeric review_counts; remove old keys | [demonstrated here] 99–106;199;278;286 | [demonstrated here] counting-paths-v0.2.2.json includes round_status and verified_reveals. [assumed] New semantic-vector/report counterparts needed; primitive vectors unchanged | [assumed] Breaking key removal/new object, CLI/example/test consumers | [assumed] Yes: explicit frozen field/result contract changes even with identical arithmetic |
| Mandatory-check inventory / empty-report guard | [demonstrated here] 286 “every mandatory check” is relevant | [unknown] No selected requirement inventory or vector impact | [unknown] Unselected | [assumed] Outside this proposal; make a separate decision before implementation |
| Roster/fork rows | [unknown] Future obligations not selected | [unknown] Depends on later design | [assumed] Future membership/head-comparison predicates would be checks; invitation/decline/countersignature statements would be attributed side records; unperformed comparisons would need coverage notices | [unknown] No roster/fork design or new predicate selected here |

[demonstrated here] [primitive-v0.2.2.json](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/vectors/primitive-v0.2.2.json) contains canonical, Merkle and PAE cases; [counting-paths-v0.2.2.json](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/vectors/counting-paths-v0.2.2.json) separately includes count field names and complete/incomplete expectations. The [freeze record](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/spec/FREEZE_v0.2.2.json) includes both. [assumed] New-version counterparts must preserve historical frozen files rather than rewrite them.

## Findings, disposition, mitigation and limits

[demonstrated here] The existing pin places the cited notices in pass, silently skips the cited scopes, and derives round_status from thresholds. The quoted source establishes these findings; retained experiment outputs support only the bounded synthetic scenarios they contain.

[assumed] Proposed disposition for this new document: under examination. Mitigation: none adopted or implemented by this PR. Security qualification: not established. No reader study or human cryptographer assessment is supplied.

[assumed] Three ways this proposal could be wrong or more misleading:
1. A side section could hide caveats when readers inspect only checks. Require adjacent presentation/source links and test comprehension later; structural separation alone does not solve presentation.
2. Exit-neutral coverage notices could make intentionally weak scope look acceptable. Preserve every existing blocker and prominently expose zero/skipped scope; whether a stricter profile should forbid it is unresolved.
3. Narrower counts and a six-status guard could create false confidence while mandatory checks are absent, signatures are self-consistent under supplied keys, or anchors are mocked/self-pinned. Keep the empty-report limitation explicit and all anchor mock labels visible; do not claim the guard establishes coverage.

[demonstrated here] Spec 286's quoted vocabulary excludes declared/attested; report.py:16's quoted fold has no nonempty guard. [assumed] These expose Option 1's conflict with B and B's inability to solve mandatory-check coverage. Migrating all existing blocking rows from the expected report into inert notices would remove its reasons for exit 2; C must forbid that migration. [unknown] Proposed presentation/implementation resistance remains untested.

[unknown] Roster completeness, post-acknowledgement suppression with retained receipts, audience fork exposure, pin provenance, actual separate authority control, causal ordering, actual first disclosure, declaration truth, reviewer consent, meaningful disposition changes, and practical added value over existing workflows remain outside the evidence supplied here.

[assumed] No roster or fork design is chosen. If later proposed, factual statements about intended membership, invitations, declines, withdrawals and countersignatures depend on A's separation; omitted/unavailable comparison coverage depends on C; scoped key/head comparisons depend on B and D but require separately selected predicates. Neither a notice nor a count invents an expected roster or detects a second head it was not given.

## What was read or run; decision

[demonstrated here] For drafting, re-read pinned verify.py, report.py, the full v0.2.2 spec and examples/expected-report.json. Prior audit inputs available in this session include PR #7 source/reports/meta-probe, the concern register and PR #4/#6 test source, and frozen-vector/freeze files. Current PR metadata read during drafting returned draft=true, merged=false for #2 and #7.

[unknown] No implementation, test execution, mutation run, full verifier run, new mocked-anchor experiment, real TSA/OTS run, reader study or new human review was performed for this proposal. The test plan is untested; no red/green/removal sequence is claimed. No executable known-gap tests are added. Existing historical run logs are not new runs.

[assumed] Single decision requested: approve Option 2 and Parts B–D as the direction for a separately authorized, versioned report-contract implementation, with the mandatory-check inventory, roster and fork designs still unselected?
