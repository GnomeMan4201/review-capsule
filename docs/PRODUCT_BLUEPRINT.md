# Review Capsule — product blueprint and integrity contract

Working name only; naming availability and product novelty have not been established. Prepared November 1, 2026. Status: researched design, not implemented or independently validated software.

## Product decision

Build a small, self-hostable tool for preparing versioned research review packets, assigning bounded human review tasks, controlling disclosure through a review round, and exporting a verifiable account of the process. Target independent developers and researchers who do not have a journal's review infrastructure. Design the first release for multiple studies owned by one research group, with a separate reviewer/steward role. Defer a public multi-tenant marketplace.

The useful product hypothesis is that a portable review contract plus an exposure record will make small research reviews easier to perform and more inspectable than ad hoc files and discussion threads. This is not a claim of novelty. OpenReview already supplies fine-grained access controls, review workflows and conflict tooling; Anonymous GitHub supplies repository anonymization; Registered Reports supply a methods-before-outcomes publication model. Validate the narrow utility gap before building a replacement for those systems.

The promise should be: **control disclosure, preserve independent first judgments, and record the limits of the review.** Do not promise bias-free research, guaranteed independent humans, institutional peer review, or tamper-proof history on an author-controlled server.

## What changes from the two-page proposal

A public page and private desk are useful interfaces, not an integrity boundary. Permissions, artifact partitioning, state transitions and exports must be enforced on the server. A hidden tab, browser storage, or a button that reveals a label cannot protect material already delivered to a browser.

Do not reveal results after one item if the reviewer has outstanding related assignments. Do not include a named expected failure or preferred conclusion in a label-review invitation. Do not populate a public lab with all model outputs while trying to recruit outcome-unexposed labelers from that same audience.

Retain separate task types rather than treating all reviews as interchangeable:

| Track | Reviewer sees | Reviewer supplies | Permitted interpretation |
| --- | --- | --- | --- |
| Open discussion | Released research, public concerns and responses | Critique, questions, suggestions | Public feedback; no automatic conversion into study labels |
| Protocol review | Frozen question, design and analysis plan; prior pilots disclosed as such | Confounds, adequacy, feasibility, stopping-rule critique | Review of a specified protocol; not journal acceptance |
| Independent annotation | Only task-necessary evidence and candidate, or a separate paragraph-only implication task | Own assessment and reasoning, before relevant outcomes/peer answers | Labels under the recorded eligibility and disclosure policy |
| Reproduction | Frozen code, environment, input/output records as required | What was actually run, logs, deviations and observed result | Reproduction of a specified computation; not automatically external scientific validation |

Fresh context is not fresh exposure. A reproduction reviewer who has read answers cannot subsequently provide a first-exposure label on the same material. Preserve their valuable contribution in the appropriate track.

## Review the reviewers' task, not just the paper

Every round declares exactly what judgment is requested and why each visible field is necessary. An evidence-support task requires the candidate conclusion; a naive implication task must not show it first. They need separate forms, assignments and reviewer pools or an exposure-aware schedule. Support assessment and probability-of-real-world-truth judgments are also different tasks.

An invitation describes effort and requested work without implying a desired verdict. A methods reviewer may be asked to inspect a known weakness. A blinded annotation reviewer should not receive that same leading brief.

A reviewer can choose uncertain, out of expertise, conflict, or already exposed without being treated as an unhelpful participant. Reviewer disagreement is retained rather than forced into consensus. Expert status and independence must be supported by an explicit policy and human review, not by an account badge.

## Contract frozen before the first assignment

Each review round binds:

- Study version, task definition, artifact digests, reviewer-visible packet and withheld material categories.
- Whether data/results already exist and are already public; known prior pilot exposure.
- Which identities are visible to whom, and which kind of masking is attempted.
- Eligibility, conflicts, prior exposure and permitted assistance policies.
- Assignment and item-order rules; no mid-round selection of favorable reviewers or cases.
- Review deadline, revision policy, release trigger and exclusion/adjudication rules.
- Publication/credit consent, data retention and handling of withdrawal or sensitive content.
- Operator/steward identities and what privileged access the operator retains.

Default disclosure: reviewers cannot see peers' answers before the round closes, and results remain withheld until all of their related protected assignments are locked or the frozen deadline resolves them. Author-facing review bodies also remain closed until round closure. The steward sees eligibility records and completion state. Any configured exceptional access must be disclosed before review begins.

A deadline may close a round with incomplete reviews; that is recorded as incomplete, not quietly extended until agreement appears. Material revisions create a new round/version. Early release or a deadline change requires a visible amendment and cannot retroactively be described as following the original contract.

## Core workflow

1. Author creates draft study and declares prospective/retrospective status.
2. Author constructs separate allowlisted packets for each track, rather than uploading one ZIP to every reviewer.
3. A preview shows exactly the packet a reviewer will receive. A leakage check flags identifiers, original repository links, answers and remote embeds; a person must verify context and omissions.
4. Freeze the review contract and version. Register or independently anchor the digest externally if making timing claims.
5. Screen reviewer eligibility and exposure before delivery. Record which policy admitted or excluded each reviewer.
6. Deliver only assigned packet bytes. Record delivery, not a fictitious claim that the person read every byte.
7. Reviewer submits and locks an initial assessment; receive a receipt. Subsequent permitted corrections are dated amendments, never overwrites.
8. Close the round under its frozen rule. Release authorized material and start discussion or adjudication as a separate stage.
9. Export records showing versions, initial assessments, revisions, eligibility/exposure decisions, missing reviews, concerns, responses and disclosure events. Publish only the consented/de-identified subset.

A public concern board remains useful after or outside the protected round. “Adopted” requires a linked version/change and reason. “Declined” requires a reason. Unresolved findings remain visible. Moderation/redaction is permitted for sensitive or abusive material, but recorded as a redaction event rather than a false claim that nothing existed. Publication consent is obtained before collection; no promise that private feedback will always become public.

## Roles and independence

Author, reviewer and steward are study-scoped roles; an account may have different roles in different studies. The assignment/exposure history follows the person across tracks for the same study and related items. A new role cannot reset prior exposure.

Recommended pilot governance: author prepares materials; a separate steward screens conflicts and applies frozen admission/release rules; reviewers provide judgments. Without an independent steward, disclose that selection and administration remain author-controlled. Do not disable useful self-administered research, but do not present it as independent administration.

A friendship is not proof of an invalid assessment, and an unfamiliar account is not proof of independence. Declare relationships and apply the predeclared conflict policy consistently. Authentication proves control of an account, not that it is a unique person, an unaffiliated expert, or free of AI assistance. Use human attestations and assistance disclosures; never infer “human reviewed” solely from a login or CAPTCHA.

Avoid asking one reviewer to assess “conflicts with the anonymous author” without access to a neutral steward who knows author identities. Also distinguish author masking from outcome masking: outreach by the author, the hosting domain or recognizable prose can reveal identity even when labels are hidden.

## Exposure record and leakage boundaries

Keep separate fields for declared prior exposure, tool-delivered artifacts, permitted disclosures, reported outside exposure, and discovered incidents. Absence of a logged event means only “not recorded”; it is not evidence of no exposure.

| Risk | First-release control | Residual limit |
| --- | --- | --- |
| Answers in HTML/JSON/network responses | Server sends task-specific allowlist only; deny result endpoints | Operator or compromised server can access storage |
| Identity through code/metadata | Curated snapshot; remove Git history, author links, revealing filenames/metadata | Recognizable content and external searches can identify authors |
| Peer answers influence a first judgment | No peer bodies, votes or sentiment summaries before closure | Outside conversations cannot be prevented |
| Results seen elsewhere | Prior-exposure declaration and incident route; frozen classification policy | Self-reports are incomplete and cannot be verified exhaustively |
| Outcome-biased author interaction | Locked round; no interpretive live coaching or adaptive packet edits | Operator can act outside the tool |
| Hidden reassignment or altered reviews | Versioned assignments, locked originals, reviewer receipts and append-only application events | A database owner can rewrite local history unless externally witnessed |
| Selective use of positive feedback | Publish permitted round accounting and missing/excluded counts; typed sources | The tool cannot guarantee honest claims elsewhere |
| Untrusted research code/files | No server execution; attachments inert and private; reproduction locally in reviewer-controlled isolation | Safe execution requires a real isolation design, not just a container label |
| Identity/credit exposed without consent | Separate private identity store from consented public attribution | Released/downloaded information cannot be recalled reliably |

An incident is an event to preserve and classify, not a reason to delete an inconvenient review. Decisions must follow the frozen rule and preserve the initial record. Do not label every exposed participant “biased”; exposure is a limitation with task-specific consequences.

## Architecture recommendation

Use a conventional server-rendered web application: Django, PostgreSQL, private artifact storage and a responsive interface. Django supplies authentication and permission primitives, but we must implement and test per-study/per-assignment authorization; default model permissions alone do not enforce this design. Pin a supported patched version at implementation time. Keep first-release operation single-organization and self-hostable, with documented installation, migrations, backups and export.

Do not make the public page the application's only data store. Avoid a large single-page frontend initially: small server-rendered responses make reviewer-visible information easier to inspect, and suit phone use. The author desk and reviewer area can share a codebase while enforcing separate server permissions.

Use separate API/data projections for public feedback and protected assessments. Never return a full study object and rely on the browser to hide fields. No generic “download all” endpoint for reviewers. Private blobs require an assignment check on each access; avoid public storage URLs. Revoke future access when assignments change, while acknowledging that prior downloads cannot be erased.

First artifact support: plain text/structured JSON and inert code snapshots. Defer arbitrary archive ingestion, active HTML/notebook rendering, remote URLs with server-side fetching, and executing submitted code. Those features introduce unnecessary disclosure and security risks before the review boundary is proven.

Model the following entities: Study, StudyVersion, Artifact, RoundContract, ReviewRound, Participant, EligibilityDecision, Assignment, ExposureEvent, LockedAssessment, AssessmentAmendment, PublicFeedback, ConcernDisposition, ConsentRecord, AuditEvent and Receipt. Events reference artifact/version hashes. Review types cannot be converted by a form field into adjudicated labels. Consensus/adjudication is a new derived record linked to initial assessments.

Store private identities separately from public pseudonyms. Exports have an explicit public/private profile. An append-only application table plus content hashes is a useful history, not immutable storage. A reviewer receipt binds opaque round/version ID and a salted cryptographic commitment to their locked submission; keep the nonce private until authorized verification. Do not publish bare hashes of low-entropy labels, which may reveal a judgment by guessing. Independent external anchoring strengthens chronology claims, not the truth of submitted content. Do not invent a custom cryptographic protocol in v0.1; review the receipt scheme before calling it a security guarantee.

Default first release trusts the hosting operator with server-readable data and says so. If withholding content even from the operator becomes a requirement, stop and design independent key custody/client-side encryption with outside security review. A private admin page does not solve that threat model.

## First vertical slice and cheap kill test

Build one complete protected round before a public dashboard or outreach automation:

- One study version; one task type; two reviewer accounts; one author and a distinct steward.
- Two fresh synthetic items, with author-expected labels stored separately.
- Conflict/exposure declaration, server-authorized assignment, review/lock, receipt, closure/release and export.
- One open-feedback submission that cannot enter the protected-label export.
- No automatic AI feedback, scoring, recommendations, matching or reputation badges.

Use synthetic canaries in withheld label/result fields. Test as anonymous visitor, author, reviewer A, reviewer B, steward and operator; check rendered pages, network responses, source, downloads, stale links and alternate IDs. Do not confuse the operator's documented access with a reviewer boundary failure.

Acceptance tests: no unauthorized withheld bytes or other reviewer answers; sealed packet unchanged after freeze; no second assignment identity bypass; atomic close/submit behavior under concurrency; no draft overwrite of a locked assessment; no public-feedback promotion; new version cannot silently inherit old approvals; import/export round-trip reproduces the same commitments and consent profile; review amendments and missing/excluded cases remain accounted for.

Invite a few actual developers only after this fixture passes. Ask whether they can understand exactly what is requested, complete it on a phone, retrieve a receipt and explain the disclosure policy without coaching. Compare effort and resulting records with a simple existing workflow using private forms/files and a preregistration service or OpenReview configuration. No review invitations are authorized or sent by this design exercise.

Kill/narrow the project if the small group cannot complete the workflow, if it needs ongoing author coaching that steers answers, if the leakage boundary fails, or if existing tooling solves the task with less burden. In the last case, build a packet/export adapter and onboarding guide rather than another platform.

## Release order

Milestone 1: integrity contract, fixture data, threat model and automated boundary tests.
Milestone 2: working protected round, external developer inspection, limited pilot and documented failures.
Milestone 3: public concern board, mobile author desk, additional protocol/reproduction tracks and export adapters.
Milestone 4: GitHub release and DEV.to explanation using the demonstrated behavior and known limits. No “zero bias,” “certified independent,” or “scientifically validated” badges.

Repository deliverables: README, research-integrity contract, SECURITY.md, CONTRIBUTING.md, fixture-only demo, threat model, permission matrix, leakage tests, schema/export specification, install guide, changelog and an explicit open-source license chosen before release. Actual blinded study packets and reviewer personal data never belong in the tool's public repository. Tool source can be public while active study material remains private.

DEV.to should tell the engineering story: why review UI is not a disclosure boundary; what the small prototype enforces; the automated leakage tests; what still depends on human governance; how to try it on synthetic material; where it overlaps existing systems. Publish it as a tested early tool, not a completed solution to peer review.

Success measures: reviewer task comprehension/completion; coverage by requested review type; accurately recorded exposure and missingness; reproducible exports; inspectable unresolved concerns; review effort. Counts of approvals, adopted suggestions or agreeable reviewers are not scientific quality scores.

## Application to the current evidence-ordering study

The original four cases, findings and discussion are already public. Renaming those cases cannot make them fresh, outcome-unexposed stimuli. They can demonstrate the tool and support disclosed retrospective review; use fresh, independently developed held-out items for the prospective protected round. People from the existing thread may be excellent protocol reviewers while being ineligible for a specifically first-exposure annotation task. Preserve that distinction instead of excluding their contribution entirely.

The existing v1.2 kit remains a draft. The tool must not import its empty review templates as completed human review, or mark its provisional 9,600-call schedule “approved” merely because it has a manifest hash.

## Primary sources consulted

OpenReview object/access model: https://docs.openreview.net/getting-started/objects-in-openreview
OpenReview conflict tooling: https://docs.openreview.net/how-to-guides/paper-matching-and-assignment/how-to-compute-conflicts-between-users
OpenReview field disclosure: https://docs.openreview.net/how-to-guides/submissions-comments-reviews-and-decisions/how-to-hide-reveal-fields
Anonymous GitHub and its limits: https://anonymous.4open.science/ and https://anonymous.4open.science/faq
ICML 2026 double-blind limitations: https://icml.cc/Conferences/2026/PeerReviewFAQ
Center for Open Science Registered Reports: https://www.cos.io/initiatives/registered-reports
JOSS review guidance: https://joss.readthedocs.io/en/latest/reviewer_guidelines.html
Django auth primitives: https://docs.djangoproject.com/en/5.2/topics/auth/default/
Django uploaded-content security: https://docs.djangoproject.com/en/6.0/topics/security/

The architecture, product hypothesis and acceptance criteria above are design recommendations, not capabilities observed in implemented Review Capsule software.
