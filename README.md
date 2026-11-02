# Review Capsule

## Review Record (draft)

Independent researchers rarely have a lab or team to check their work. When I ask people to review an investigation, two things can go wrong: if I tell a reviewer my theory first, I may influence their answer, and afterwards nobody may be able to check how the review was handled, such as whether an answer was changed, dropped or cherry-picked.

Review Record is a draft protocol and offline verifier intended to make the recorded parts of that process checkable. Its intended workflow asks reviewers to lock in their own judgment before assessments are revealed. Anyone with the supplied records can later check whether a published assessment matches its recorded commitment.

It does not show that reviewers were independent, that blinding worked, or that the research is correct. It cannot establish that nobody saw an assessment early, or that an intended reviewer was included when the roster was never committed. It is an unfinished draft with no outside cryptographic review. Known gaps are tracked in [REVIEWRECORD_CONCERNS.md](https://github.com/GnomeMan4201/review-capsule/blob/concerns/reviewrecord-disposition-list/REVIEWRECORD_CONCERNS.md).

## Hosted Review Capsule prototype

A small research-review workflow that separates the evidence a reviewer needs from the answers they should not see yet.

**Status: v0.1.1 synthetic demo deployed on Render. Not ready for real confidential research or independent-review collection.** AI-assisted design and implementation; not independently audited. Working name, not a verified unique product name.

The central promise is controlled disclosure and an inspectable first assessment. The software cannot guarantee an independent human, zero bias, secrecy from the server operator, or scientific validity.

## Hosted synthetic demo

Open [Review Capsule](https://review-capsule-demo.onrender.com). Start with `demo-author`. The generated demo password is stored privately in Render: open the `review-capsule-demo` service, choose **Environment**, and copy `CAPSULE_DEMO_PASSWORD`. The same demo password supports `demo-steward`, `demo-reviewer-a`, and `demo-reviewer-b`; sign out between roles. These accounts demonstrate the workflow, not independence.

Render confirmed deploy `dep-dbjilnm7bikc73fitqmg` live on November 1, 2026, from commit `e5cc4a2d0642b73137157bd08e1f914343e28aa7`. The public HTTPS login page and database health endpoint were observed working. A complete hosted authenticated role walkthrough remains pending. All 23 tests passed locally; the PostgreSQL verification job also completed successfully in [run 41304343034](https://github.com/GnomeMan4201/review-capsule/actions/runs/41304343034).

The free web service sleeps while idle. The free database expires December 1, 2026; do not use this instance for real records. Database external connections are blocked. Automatic application deploys are off. No secrets are stored in this repository.

## What works in this prototype

- An author prepares a structured evidence-support packet, separate withheld results, a frozen deadline and reviewer roster.
- A separate steward applies the declared conflict, prior-exposure and AI-assessment policy before packet delivery.
- Each reviewer receives only their assigned packet; no expected labels or other assessments are sent with it.
- The initial assessment is locked. Later corrections are separate dated amendments.
- A salted receipt binds the exact assessment to an assignment and round commitment.
- Closure requires every frozen assignment to be submitted, or the frozen deadline to pass. Missing assignments remain in the record.
- Results remain withheld until closure and while the reviewer has other open assignments in the same study. Peer answers remain private in v0.1.
- Tool-recorded result exposure or reported external exposure prevents first-exposure eligibility in later rounds of the same study.
- Post-round feedback is a distinct record type and stays outside assessment records.
- Author/steward export is private and includes missingness, original assessments, amendments and exposure events.

No hidden-results data lives in browser storage or a frontend-only reveal component. This is server-side authorization, not a simulated security boundary in a static page.

## Quick start — Python 3.10+ [needs Linux runner]

Django 5.2 is used. Development instructions below are for a local machine or controlled development host. iPhone users can inspect the source and documents, and use the hosted demo once deployment and browser verification are complete.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py test
python manage.py demo
python manage.py runserver 127.0.0.1:8000
```

Open http://127.0.0.1:8000 . `demo` prompts for a local password and creates four explicitly synthetic role accounts: `demo-author`, `demo-steward`, `demo-reviewer-a`, `demo-reviewer-b`. Use separate browser profiles, or sign out between roles. These are fixtures, not real independent reviewers. The command will not overwrite existing demo accounts.

A generated development secret is process-local; sessions reset on restart unless you configure a persistent local `CAPSULE_SECRET_KEY`. Do not commit secrets or real research data.

### Walk through a complete round

1. As author, open the draft desk, inspect the exact packet and freeze the round.
2. As each reviewer, submit the conflict/exposure/assistance declaration before opening evidence.
3. As steward, inspect declarations and record a reason. Apply the frozen rule; this version cannot waive conflicts.
4. As each admitted reviewer, open the packet, answer every item, and lock the assessment. Retrieve the private receipt.
5. As steward, close only when all frozen reviewers submitted or the deadline passed.
6. Reviewers can now request withheld material, provided they have no related open assignments. No peer assessments are returned to them.
7. As author/steward, download the private export. Keep it private: consent-based public publication is not implemented.

`Prepare a round` supports new drafts using existing local accounts. There is no public registration, account recovery or automated invitation flow. Additional local accounts can be created with Django's user-management shell; an operator must handle identity checks and credential delivery outside this prototype. The built-in default Django admin site is deliberately not exposed.

## Development verification

Twenty Django tests passed on Python 3.12 with SQLite in this session. Five added checks cover hosted setup, restart preservation, shared sign-in throttling and the demo notice. They exercise the full declaration → steward admission → packet → lock → closure → export path and adversarial access cases. `python manage.py check` also passed.

The same 20-test suite also passed on PostgreSQL 16 in [GitHub Actions run 41295540261](https://github.com/GnomeMan4201/review-capsule/actions/runs/41295540261) on November 1, 2026. This extends database coverage but does not test simultaneous transitions.

The tests are **not** independent security review, proof of no leakage, unique-human verification, scientific review or a production concurrency qualification. Browser layout and PostgreSQL concurrent close/submit behavior have not been tested. There are no real reviewer observations or research results in this package.

See [the hosted demo plan](docs/HOSTED_DEMO.md) for the exact proposed source transfer, resources and verification limits.

## Production is a separate milestone

Read [SECURITY.md](SECURITY.md), [the integrity contract](docs/INTEGRITY.md), [the threat model](docs/THREAT_MODEL.md), and [the roadmap](docs/ROADMAP.md). Production settings reject SQLite and require a configured secret and PostgreSQL. That guard is not a production qualification. The PostgreSQL driver specification is in `requirements-postgres.txt`; resolve and pin the driver, qualify concurrent transitions and deployment security before actual use.

Do not expose Django's development server to the public. HTTPS proxy settings, explicit host/origin settings, database-backed sign-in throttling and a deployment container are included as a candidate configuration. Hosted verification, secure account recovery, backups, public-consent exports, retention, external timestamping and outside security review remain release gates for real use.

## Why another tool?

OpenReview already offers rich review workflows and access controls. Anonymous GitHub already addresses repository anonymization. Registered Reports are an established methods-first publication process. This prototype tests a narrower product hypothesis: independent developers may benefit from a small review packet, explicit exposure history, locked first judgments and portable receipts without running a journal workflow.

Novelty has not been established. If configuring or integrating existing tools is easier for actual reviewers, narrow this project to a packet/export adapter.

See the accompanying product blueprint for sources and the broader design. The public tool repository should contain synthetic fixtures only. Active blinded study materials and reviewer personal data must stay out of public Git history.

## License

MIT, under the GnomeMan4201 handle. This license covers this prototype's code and synthetic fixtures; it grants no rights over third-party research or reviewer contributions uploaded later.
