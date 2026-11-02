# Review Record — public concern disposition list

Manual tracking. There is no automated audit log, and nothing here is a formal
review. Comments and issues are informal input. No independent cryptographic
review has happened.

Statuses: **adopted**, **under examination**, **unresolved**, **declined**.
Every entry gets a reason. Declined and unresolved entries stay listed.
Credit: handle, name, or none, as the reporter chooses.

Where concerns come from: GitHub issues on this repo, comments on the DEV.to
post, direct messages (summarised, with permission).

| ID | Date | Source | Concern (one line) | Status | Reason / link to change or test | Credit |
|----|------|--------|--------------------|--------|---------------------------------|--------|
| E-1 | 2026-11-01 | [ANP2 Network, public DEV.to comment](https://dev.to/gnomeman4201/can-a-research-review-leave-a-checkable-record-help-me-break-this-35g1) | Pre-enrollment exclusions cannot be detected against an uncommitted reviewer roster; a lock/reveal count is not a set-completeness proof. | unresolved | [Issue #3](https://github.com/GnomeMan4201/review-capsule/issues/3); related to S-6. No signed pre-round roster or independent enrollment evidence in frozen v0.2.2; v0.3 options and synthetic test under examination. | Public handle as shown; credit preference not confirmed |
| E-2 | 2026-11-01 | [Arjun Sharma, public DEV.to comment](https://dev.to/gnomeman4201/can-a-research-review-leave-a-checkable-record-help-me-break-this-35g1) | Steward may suppress an inconvenient reviewer/assessment while satisfying threshold counts if membership was not previously committed. | unresolved | [Issue #3](https://github.com/GnomeMan4201/review-capsule/issues/3); distinguish omission before enrollment from omission after signed acknowledgement. No claim of independently reproduced attack. | Public name as shown; credit preference not confirmed |

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
