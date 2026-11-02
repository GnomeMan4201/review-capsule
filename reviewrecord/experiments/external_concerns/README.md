# E-3 / E-4 experimental known-gap observations

[demonstrated here] Base: `d54432f3e4c67f11ea53c16ebb383c1aec1f9224`, draft PR #2.
This branch changes no verifier, frozen spec, frozen vectors or existing tests.
No mitigation is selected. Disposition: under examination. Mitigation: unresolved.
Security qualification: not established. These are synthetic observations, not a
human audit or participant round. Count these separately from the passing suite.

## Reproduce on Linux

Python 3.12+, third-party dependencies pinned by `reviewrecord/pyproject.toml`:
`cryptography==50.0.2`, `opentimestamps-client==0.8.0` and its dependencies.
The CLI observation uses subprocess; a-Shell compatibility is unknown.

From the repository root:

```bash
python -m pip install -e ./reviewrecord
python -m unittest discover -s reviewrecord/tests -v
python -m unittest discover -s reviewrecord/experiments/external_concerns -p known_gap_tests.py -v
python reviewrecord/experiments/external_concerns/meta_probe.py --help
python reviewrecord/experiments/external_concerns/meta_probe.py --write reviewrecord/evidence/external-concerns-2026-11-02/meta-probe.json
```

The five unittest observations write synthetic reports under
`reviewrecord/evidence/external-concerns-2026-11-02/`. The meta-probe writes only
when `--write` is supplied; otherwise it prints JSON. Its exit 0 means the
experiment completed, not that the protocol passed. The dedicated Actions
workflow uploads reports and logs; the existing baseline workflow is unchanged.

## Results from this session

[demonstrated here] Local Python 3.12.14: **122 existing tests OK**;
separately **5 known-gap observations reproduced**. Do not call this a
127-test assurance suite. Raw output is retained alongside the JSON reports.

| Known-gap observation | Result | Limits |
|---|---|---|
| E-4a | `round_status=complete`, exit 2; three pending OTS and three offline-unverifiable TSA descriptors. CLI also returned 2. | Count thresholds only; this behavior follows frozen spec section 4.3. |
| E-4b | `WITHDRAWAL_STEWARD_ATTESTED` has status `pass`, and the detail says reviewer consent is not established. | The steward signature is checked; the allegation itself is not reviewer consent. |
| E-4c | Three retained concerns and zero dispositions under a properly rebound/signed `disposition_required=false` policy; no disposition-check line. Strict-policy control reports three `DISPOSITION_MISSING` rows and exit 1. | False is accepted by the schema; the frozen Round-1 profile requires true. This is silent policy weakening/reporting, not a demonstrated signature bypass. |
| Report aggregation (not an external concern or end-to-end bypass) | Empty `Report.finish()` and a report with only one unrelated synthetic passing row both return exit 0. | No nonempty or expected-structural-check guard in the report class; no verifier bypass demonstrated. |
| E-3 | Two different steward-signed log/close heads for the exact same registration. Full log has three commitments, alternate omits reviewer C and has two. Both are threshold-complete, zero fail/missing, exit 2. | Real offline checks do **not** accept either as an overall pass. Synthetic anchors are unresolved. No live split audience or real timestamp uniqueness test. |

E-3 exit 2 is **not fork detection**. It is caused by unresolved anchors. With
explicitly mocked qualified anchors, both the full control and the omitted-C
variant return exit 0; no fork-detection property has been demonstrated.

## Meta-test feasibility and findings

[demonstrated here] The bounded probe has an actual nonzero offline control
(exit 2) and a separate explicitly simulated all-pass control (exit 0). The latter
uses a mocked anchor inspector plus expected signing keys and a supplied
synthetic registry snapshot. The mock rejects changed/missing proof bytes; it
does not qualify any external evidence. There is no real all-pass control here.

- **64 status subsets (not bundle scenarios):** `Report.finish()` follows the present 0/1/2 fold for all
  subsets of `pass`, `fail`, `missing`, `pending`, `unverifiable` and `not_checked`.
  Each included status contributes one synthetic report row; 2^6 = 64 includes
  the empty subset. This checks aggregation logic, not evidence or semantics.
  An empty `Report` yields exit 0.
  That is a report-class observation; reachability of an empty report from
  `verify_bundle` is **[unknown]**. It is not a new end-to-end bypass finding.
- **84 file mutations, baseline 0 -> exit 1 in every case:** one removal and one first-byte corruption of each of
  42 fixture files, without repairing the manifest. All used the simulated
  all-pass control (exit 0), not the separate offline control (exit 2). Every
  mutation returned exactly exit 1; each JSON case retains its path, operation,
  exit, status counts and non-pass codes. The runner now asserts exit 1 for every
  mutation. No survivors. For anchor proof files, the test double itself rejects byte changes; this
  is not real anchor tamper validation. Other mutations can fail on inventory/hash
  checks, so this does not establish that every semantic predicate detects its own missing evidence.
- **Three rebuilt semantic controls:** omission of C, steward-attested withdrawal,
  and disabled dispositions each return exit 0 with simulated anchors. Their
  manifests, signatures, log links, roots and proofs are rebuilt consistently.
  This separates statement semantics and absent requirements from damaged bytes.
  These are top-level exit-0 logic observations under mocks, not real rounds.
  Withdrawal and false-policy variants are permitted by current semantics; the
  issue is their scope and reporting, not a demonstrated signature bypass.
- **68 statically discovered literal codes:** inventoried with source locations,
  including dynamic anchor mapping literals and envelope error literals. This
  is not an exhaustive reachability proof, nor 68 evidence mutation tests.

[unknown] Exhaustive "every code" evidence coverage. A feasible next experiment
would need an explicit code/requirement/evidence/trigger map with reachable
fixtures and a real all-pass anchor control, plus per-predicate mutations that
avoid being masked by a manifest failure. That work is not implemented here.
Some codes are diagnostics, absence findings or configuration outcomes and do
not have one evidence object to corrupt. A roster absent from the requirements
cannot be discovered merely by folding emitted rows. The proposed meta-test
would **not automatically find the roster gap** without an expected-set oracle.

Kill criterion for interpreting this probe: do not claim exhaustive non-vacuity
or fork exclusion from a fold test or byte-mutation sweep. Retain it only as a
bounded diagnostic with controls and disclosed uncovered requirements.

## Sources and attribution

Public DEV.to comments on the linked article: E-3, Shuttlewright; E-4,
`@zade_meadows` (handle only, as requested). The latter explicitly reported a
source reading at d54432f3, not execution. The supplied brief says Claude also
read the same three source paths; that prior reading is not counted as a test
or as independently reproduced here. These new executions are separate.

See the concerns branch register and `DESIGN_NOTES.md`. The root README introduction is now isolated in docs-only [PR #8](https://github.com/GnomeMan4201/review-capsule/pull/8), targeting main. It is removed from this experiment's diff. No README introduction is published to main by this experiment.

## Empty-report guard inspection (2026-11-02)

[demonstrated here] At pinned d54432f3, `Report.finish()` has no explicit guard
requiring a nonempty check set and returns exit 0 for a freshly constructed
`Report`. The normal `verify_bundle` flow does not immediately finish an empty
report: its sole early return is the optimized-runtime rejection, which first
adds `RUNTIME_UNSUPPORTED` as fail. The other return is at the end of the checks.
The CLI does not catch arbitrary verifier exceptions and convert them to an
empty report; it returns the result of the verifier. This is source inspection,
not a guarantee about every interruption or future call site.

Two ad hoc local CLI checks (not additions to either suite): an empty input
directory returned process/report exit 1 with 17 checks; a missing input path
returned process/report exit 1 with 18 checks. A direct empty `Report.finish()`
returned 0. No end-to-end false-success path was demonstrated by these checks.
[unknown] Universal protection against interrupted execution; no such protection
is established by the report class. No guard implementation is added here.

### Fifth known-gap observation (2026-11-02)

[demonstrated here] `test_known_gap_report_can_exit_zero_without_structural_checks`
now retains two report-class cases in `empty-report.json`: no checks, and one
unrelated synthetic passing row. Both return exit 0 with `round_status=incomplete`.
This is one separately counted known-gap test with two subcases. Local rerun:
**5 known-gap observations reproduced**. The existing suite remains separate at
122 tests from the retained baseline run; it was not rerun for this report-class
test addition. No guard is implemented and no expected structural-check set is
selected. A future guard must define required check coverage, rather than merely
require one arbitrary passing row. Whether any normal verifier path can return
an empty/insufficient report as exit 0 remains [unknown]. This test does not
establish an end-to-end false-success path.
