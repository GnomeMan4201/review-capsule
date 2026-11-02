# Review Record — public concern disposition list

Manual tracking. There is no automated audit log, and nothing here is a formal
review. Comments and issues are informal input. No independent cryptographic
review has happened.

Statuses: **adopted**, **under examination**, **unresolved**, **declined**.
Every entry gets a reason. Declined and unresolved entries stay listed.
Here, **finding evidence** is distinct from **disposition** (how the concern is handled)
and **mitigation** (whether a remedy has actually been selected and implemented).
A synthetic regression reproducing a limitation does not mean the mitigation is adopted
or that the protocol is security-qualified. Credit: handle, name, or none, as
the reporter chooses.

Where concerns come from: GitHub issues on this repo, comments on the DEV.to
post, direct messages (summarised, with permission).

| ID | Date | Source | Concern (one line) | Status | Reason / link to change or test | Credit |
|----|------|--------|--------------------|--------|---------------------------------|--------|
| E-1 | 2026-11-01 | [ANP2 Network, public DEV.to comment](https://dev.to/gnomeman4201/can-a-research-review-leave-a-checkable-record-help-me-break-this-35g1) | Pre-enrollment exclusions cannot be detected against an uncommitted reviewer roster; threshold completeness is not member-set completeness. | under examination | **Finding:** reproduced for a synthetic A/B/C pre-enrollment omission by [known-gap regression `test_pre_enrollment_exclusion_invisible_to_round_completeness`](https://github.com/GnomeMan4201/review-capsule/pull/4); [CI run](https://github.com/GnomeMan4201/review-capsule/actions/runs/41383186659) reported 123 passing tests, one of which documents this known limitation. **Disposition:** under examination ([Issue #3](https://github.com/GnomeMan4201/review-capsule/issues/3), related to S-6). **Mitigation:** unresolved; no roster design selected or adopted. **Security qualification:** not established; the test does not establish a verified full bundle or independently witnessed roster. | Public handle as shown; credit preference not confirmed |
| E-2 | 2026-11-01 | [Arjun Sharma, public DEV.to comment](https://dev.to/gnomeman4201/can-a-research-review-leave-a-checkable-record-help-me-break-this-35g1) | Could a steward exclude an inconvenient participant and still produce a complete-looking record? Distinguish pre-enrollment omission from suppression after receipt. | under examination | **Finding:** the same [synthetic known-gap regression](https://github.com/GnomeMan4201/review-capsule/pull/4) demonstrates only pre-enrollment omission; it does **not** reproduce a post-acknowledgement attack. A signed acknowledgement makes omission checkable **only when an auditor can obtain and authenticate the retained receipt or independent evidence**. **Disposition:** under examination ([Issue #3](https://github.com/GnomeMan4201/review-capsule/issues/3)). **Mitigation:** unresolved; independent publication/receipt custody and pre-round membership commitment remain open. **Security qualification:** not established. | Public name as shown; credit preference not confirmed |

## Known open items from the author's own audit (not outside input)

| ID | Item | Status | Reference |
|----|------|--------|-----------|
| S-1 | Registration-before-close order check is nearly tautological (close record contains the registration hash) | under examination | [ANCHOR_GATE_AUDIT](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3/reviewrecord/docs/ANCHOR_GATE_AUDIT.md) |
| S-2 | Timestamps give upper bounds only; Bitcoin block time can skew | under examination | [ANCHOR_GATE_AUDIT](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3/reviewrecord/docs/ANCHOR_GATE_AUDIT.md) |
| S-3 | Two anchor authorities are distinct by construction; control of the pin list matters | unresolved | [ANCHOR_GATE_AUDIT](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3/reviewrecord/docs/ANCHOR_GATE_AUDIT.md) |
| S-4 | TSA revocation is not checked | unresolved | [TSA_BINDING_REMEDIATION](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3/reviewrecord/docs/TSA_BINDING_REMEDIATION.md) |
| S-5 | OTS metadata is parsed from detail text | under examination | [ANCHOR_GATE_AUDIT](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3/reviewrecord/docs/ANCHOR_GATE_AUDIT.md) |
| S-6 | Admission is at the steward's discretion; no auditable rejection log | unresolved | [ADMISSION_AND_RECOVERY](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3/reviewrecord/docs/ADMISSION_AND_RECOVERY.md) |
| S-7 | TSA target was not bound to the token imprint (fixed at d54432f3) | adopted | [TSA_BINDING_REMEDIATION](https://github.com/GnomeMan4201/review-capsule/blob/d54432f3/reviewrecord/docs/TSA_BINDING_REMEDIATION.md) |

(References point at the pinned commit d54432f3 of draft PR #2. The S-items are the author's own audit findings, not outside input.)
