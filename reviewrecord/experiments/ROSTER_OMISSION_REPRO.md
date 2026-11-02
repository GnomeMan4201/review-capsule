# Reproduction note — pre-enrollment reviewer omission (exploratory, 2026-11-01)

**Tracker:** [Issue #3](https://github.com/GnomeMan4201/review-capsule/issues/3) (ANP2 Network and Arjun Sharma public comment reports).  
**Base:** frozen Review Record v0.2.2 at `d54432f3e4c67f11ea53c16ebb383c1aec1f9224`.  
**Scope:** independent exploratory test branch. No v0.2.2 normative files or primitive vectors changed.  
**Status [demonstrated in GitHub CI]:** [run 41383186659](https://github.com/GnomeMan4201/review-capsule/actions/runs/41383186659) at candidate test commit `707e0c62dc2e42d37922c982fb9667c45b2858d2` reported 123 tests, `OK`, including `test_pre_enrollment_exclusion_invisible_to_round_completeness ... ok`. The exact job log was inspected on 2026-11-01 (US Central; 2026-11-02 UTC). This is synthetic tool behavior only, **not** a confirmed anchored final record or external human audit.

## Premise, not a retrieved fact

The synthetic test operator privately declares intended participants A, B, C. This **external intended roster** is not submitted to the v0.2.2 system and is *not* independently witnessed. The registration has `reviewers_target=3` but binds no member list. That planning count is not a promise that all three are admitted.

## Procedure

The regression `test_pre_enrollment_exclusion_invisible_to_round_completeness` in `tests/test_steward_cli.py`:

1. Generate a public synthetic reference round with local test keys for A/B/C (no human reviewers).
2. Start the real candidate `rrsteward` path with the unchanged signed registration, packet and policy.
3. Admit A and B only. Submit their signed declarations and commitments; do not submit C's declaration or commitment.
4. Produce a steward-signed close, then import A/B signed assessments after close through the candidate steward tool.
5. Invoke `rrverify` against the resulting steward workspace with expected author/steward keys.
6. Assert: `reviewers_target=3`; two admitted keys; no C declaration; `locked_count=2`; `verified_reveals=2`; `round_status=complete`; per-threshold checks pass and no missing reveal for C is generated.

The test intentionally does **not** require overall `exit_code=0`: a steward workspace without the publication manifest, withheld-results/dispositions and externally confirmed anchors is **not a fully verified final bundle**. Completion here is the frozen threshold-count result only. A future test should assemble the independently verifiable full synthetic bundle and keep anchor gates separate.

## Interpretation boundary

- If the regression passes, it demonstrates a narrow *set-selection visibility* failure: the verifier cannot infer an intended member missing before enrollment when the member list was never committed.
- It does **not** demonstrate forged signatures, altered hash chains, external checkpoint failures, that a real reviewer was mistreated, bias in assessments, or that the full finalized bundle would pass every check.
- The test deliberately makes the test operator know C. That knowledge is **not evidence that an outside reader can establish C's expected membership**.
- The pre-existing design already disclosed steward admission discretion and this limitation; the experiment strengthens the example, not a novelty claim.

## Follow-on matrix (NOT run in this regression)

| Case | Independent prior evidence | Desired result |
|---|---|---|
| No enrollment for expected C, uncommitted roster | None | Threshold can be complete; no roster-completeness claim |
| C has steward-signed acknowledgement, but steward omits its entry | Retained receipt / external checkpoint | A check can flag disagreement **if** external evidence is supplied |
| C is on a witnessed pre-round roster, but never admitted | Independently anchored invitation/enrollment commitment | A new v0.3 roster audit should flag unmatched status, or the design fails |
| Steward never invites a qualified outsider | No independent membership criterion | Undetectable from an enrollment record alone |

## Competing designs for v0.3 — no selection yet

- **Separate pre-round signed roster / invitation-ID commitment**, witnessed outside the steward's custody. Define privacy-preserving identifiers, reviewer access/consent, opt-outs and change control.
- **Typed enrollment events** in a signed append-only chain, **plus** independently committed initial invitation set. Without that initial set, suppressing an invitation or registration still leaves no evidence.

Do not pick based on elegance. Choose only after attacks against both the pre-enrollment and post-acknowledgement boundaries. A signed roster created **only at close** is not sufficient.

**Kill criterion:** reject a roster-completeness claim if an independently precommitted intended participant can be silently omitted while all claimed roster checks pass.

**Decision boundary:** issue unresolved; no Round 1, deployment, merge, frozen-rule edit or retrospective claim of independent review.
