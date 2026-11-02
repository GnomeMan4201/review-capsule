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

The four unittest observations write synthetic reports under
`reviewrecord/evidence/external-concerns-2026-11-02/`. The meta-probe writes only
when `--write` is supplied; otherwise it prints JSON. Its exit 0 means the
experiment completed, not that the protocol passed. The dedicated Actions
workflow uploads reports and logs; the existing baseline workflow is unchanged.

## Results from this session

[demonstrated here] Local Python 3.12.14: **122 existing tests OK**;
separately **4 known-gap observations reproduced**. Do not call this a
126-test assurance suite. Raw output is retained alongside the JSON reports.

| Known-gap observation | Result | Limits |
|---|---|---|
| E-4a | `round_status=complete`, exit 2; three pending OTS and three offline-unverifiable TSA descriptors. CLI also returned 2. | Count thresholds only; this behavior follows frozen spec section 4.3. |
| E-4b | `WITHDRAWAL_STEWARD_ATTESTED` has status `pass`, and the detail says reviewer consent is not established. | The steward signature is checked; the allegation itself is not reviewer consent. |
| E-4c | Three retained concerns and zero dispositions under a properly rebound/signed `disposition_required=false` policy; no disposition-check line. Strict-policy control reports three `DISPOSITION_MISSING` rows and exit 1. | False is accepted by the schema; the frozen Round-1 profile requires true. This is silent policy weakening/reporting, not a demonstrated signature bypass. |
| E-3 | Two different steward-signed log/close heads for the exact same registration. Full log has three commitments, alternate omits reviewer C and has two. Both are threshold-complete, zero fail/missing, exit 2. | Real offline checks do **not** accept either as an overall pass. Synthetic anchors are unresolved. No live split audience or real timestamp uniqueness test. |

## Meta-test feasibility and findings

[demonstrated here] The bounded probe has an actual nonzero offline control
(exit 2) and a separate explicitly simulated all-pass control (exit 0). The latter
uses a mocked anchor inspector plus expected signing keys and a supplied
synthetic registry snapshot. The mock rejects changed/missing proof bytes; it
does not qualify any external evidence. There is no real all-pass control here.

- **64 status subsets:** `Report.finish()` follows the present 0/1/2 fold for all
  combinations of its six supported statuses. An empty `Report` yields exit 0.
  That is a report-class observation; reachability of an empty report from
  `verify_bundle` is **[unknown]**. It is not a new end-to-end bypass finding.
- **84 file mutations:** one removal and one first-byte corruption of each of
  42 fixture files, without repairing the manifest. Every mutation produced
  nonzero exit; no survivors. Many fail on inventory/hash checks, so this does
  not establish that every semantic predicate detects its own missing evidence.
- **Three rebuilt semantic controls:** omission of C, steward-attested withdrawal,
  and disabled dispositions each return exit 0 with simulated anchors. Their
  manifests, signatures, log links, roots and proofs are rebuilt consistently.
  This separates statement semantics and absent requirements from damaged bytes.
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

See the concerns branch register and `DESIGN_NOTES.md`. No README intro has
been invented: the author's separately supplied exact wording is still pending.
