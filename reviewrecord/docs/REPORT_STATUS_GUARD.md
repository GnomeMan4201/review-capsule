# Part B only: report status vocabulary guard (draft)

[demonstrated here] Baseline: d54432f3e4c67f11ea53c16ebb383c1aec1f9224, report.py:13–16 counts arbitrary statuses then returns 0 when no blocking status occurs. Spec line 286 defines exactly pass/fail/missing/pending/unverifiable/not_checked. Source: https://github.com/GnomeMan4201/review-capsule/blob/d54432f3e4c67f11ea53c16ebb383c1aec1f9224/reviewrecord/src/rr/report.py#L13

[assumed] Scope: reject unknown status values with a fail diagnostic; retain the offending row. The six defined status sequences keep the frozen fold. No spec revision, mandatory-check inventory, nonempty-report rule, coverage-effect decision, roster or fork design is introduced. Empty reports still exit 0. AI-assisted implementation by ChatGPT; claim boundary: process integrity only. Security qualification: not established.

[demonstrated here] Baseline local run: `Ran 122 tests in 4.920s` / `OK`. Logs are in ../evidence/report-status-guard/. New tests were run before implementation: red.log ends `FAILED (failures=5, errors=5)`. Non-string/unhashable statuses exposed crashes as well as unknown-string false success.

[demonstrated here] An adversarial test of the first guard found that a pass row using the diagnostic name and subject could suppress the diagnostic: adversarial-red.log ends `FAILED (failures=1)`. The final guard recognizes an existing diagnostic only when its status is fail.

[demonstrated here] Final runs are retained in green.log, removed.log and full.log. The explicit empty/unrelated-pass known-gap observation has been moved out of tests/ into experiments/report_status and is counted separately in known-gap.log. Earlier raw red logs retain the earlier test layout.

[assumed] Baseline and negative controls: synthetic pass -> 0; fail -> 1; not_checked -> 2. All 64 legal status subsets are checked, including empty. Synthetic typo/declared/attested/PASS/null/true/0/list/object inputs must produce exit 1. These report-class tests do not use anchor mocks and do not establish bundle-level reachability.

[assumed] Three possible errors were challenged: legal-status behavior could regress (64-subset control); a similarly named pass could bypass rejection (spoof control); repeat finish could duplicate diagnostics (repeat control). The test retaining empty/unrelated-pass exit 0 documents a known boundary, not mitigation of missing mandatory checks.

[unknown] No human cryptographer review, live bundle with all real anchor requirements, runtime interruption qualification or mandatory-check coverage is supplied. Full logs describe synthetic local tests. PR #7 known-gap observations are not added to the passing-suite total. Merge requires separate approval.

[demonstrated here] Current green.log: `Ran 4 tests in 0.001s` / `OK`; removed.log: `FAILED (failures=6, errors=5)`; full.log: `Ran 126 tests in 4.688s` / `OK`. Separately, known-gap.log: `Ran 1 test in 0.000s` / `OK`, reproducing empty/unrelated-pass exit 0 rather than remedying it.
