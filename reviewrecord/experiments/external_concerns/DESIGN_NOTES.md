# Unselected design questions for E-3 / E-4

These are design notes, not implementation decisions. Frozen v0.2.2 is unchanged.
Disposition: under examination; mitigation unresolved; security qualification
not established. No proposed field or signer policy is adopted by this branch.

## Threshold naming

[demonstrated here] The frozen spec explicitly names `round_status` in sections
4.3, 4.7 and verifier requirements, and defines it solely by two count minimums.
The counting vectors contain expected `round_status` values; the frozen Python
and JavaScript counting crosschecks use that field too. The expected example
report and CLI consumers also depend on it. A direct rename to
`threshold_status` would conflict with the current frozen contract and vectors.
A future revision would need updated spec, vector expectations, crosschecks,
example reports and migration/compatibility rules. Even an additive alias needs
a documented output contract. No rename or alias is made now.

## Attestation status

[demonstrated here] The steward's signature is verified under its signing key,
while the withdrawal allegation is not evidence of reviewer consent. The report
already contains the caveat and attestor identity, but counts the row as `pass`.
`TOOL_TEXT['declared']` is message text, **not an implemented status**: the current
status enumeration and exit fold contain six other statuses only.

An eventual `declared` or `attested` status would need explicit counting and exit
semantics, plus separation of signature/content matching from the party's claim.
Adding the label alone risks treating a mandatory check as satisfied or making
all such reports perpetually unresolved by accident. That policy is not selected.

## Disabled checks

[demonstrated here] `disposition_required=false` suppresses missing-disposition
rows without a row announcing that fact. The schema permits false, while the
Round-1 profile specifies true. A visible `not_checked` row could disclose this,
but would change exit behavior under the present fold. A future revision needs
to distinguish a disabled optional check from an unmet required profile and
specify both the report row and exit behavior. No status/code is added here.

## Aggregate verdict

[demonstrated here] `Report.finish()` already folds emitted statuses to exit 0,
1 or 2. A new `round_verdict=pass` would duplicate the fold and introduce an
obvious whole-round reading. Even a perfectly implemented fold cannot establish
requirements that never emitted a row, the completeness of the intended reviewer
population, or research correctness.

[unknown] No proposed single positive `round_verdict` has been shown to avoid a
"verified" reading. A machine-only numeric exit mirror or a diagnostic count
can state bounded execution results, but does not solve that interpretation
problem. The present evidence does not justify a positive whole-round verdict.
No aggregate field is selected or implemented.

## Countersigned close and signer set

[demonstrated here] The two synthetic heads are locally consistent under the
same registration. [unknown] A reviewer-countersigned close has not been tested
as a mitigation here. Shuttlewright proposed signing a close summary binding
roster hash, log head and close time; timestamps alone do not establish a unique
published head.

The required signer set must come from a roster committed before the steward
can select the close audience. Letting the steward choose the countersigners at
close recreates the omission problem. An independently retrievable roster
commitment, canonical close summary, all-signers versus quorum rule, retained
signature distribution and comparison/gossip mechanism need evaluation. If a
quorum is allowed, conflicting closes may share no honest required signer;
if all signers are required, missing/refusing/offline reviewers can block close.
A signature should explicitly acknowledge inclusion of the signer's own
commitment in the bound head, rather than merely receipt of an opaque head.
Countersigning a declared close time does not prove wall-clock or packet-release
ordering. Key compromise, collusion and exclusions before roster commitment
remain separate boundaries. No roster or countersigning protocol is chosen.

Kill criterion: reject a proposed fork mitigation if the steward can still choose
its required signer set after admission, or if two incompatible closes can both
meet its acceptance rule without detection under the stated witness assumptions.
