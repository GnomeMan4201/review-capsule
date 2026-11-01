# Synthetic hosted demo: deployment candidate

## Status

Prepared November 1, 2026. Deployment is not verified. The owner authorized the synthetic demo deployment. Direct CLI upload is blocked by the execution environment network policy; deployment is being prepared through a source repository.

## Exact proposed action

Upload this application source to a **new Review Capsule project** in the user's connected Railway workspace, **GnomeMan4201's Projects**. Build and run the Django container with a dedicated PostgreSQL database. Generate an HTTPS service address so the owner can exercise the synthetic author, steward and two reviewer roles on an iPhone. This is a third-party source transfer and hosted compute/database usage may incur charges under the user's Railway plan.

The transfer should include code, templates, migrations, documentation and invented fixture definitions only. Exclude credentials, environment files, local databases, real study bundles, human reviews, receipts and private exports. Neither the UINET project nor its data is part of this deployment.

The owner has authorized uploading this source and deploying the synthetic demo to that new Railway project. No real research collection, public reviewer invitation, DEV.to posting, or GitHub repository publication is included in this deployment step.

## Configuration to apply after authorization

- Use the checked-in Dockerfile and railway.json.
- Configure `CAPSULE_DEBUG=0`, `CAPSULE_SYNTHETIC_DEMO=1`.
- Generate a persistent random `CAPSULE_SECRET_KEY` and a separate random `CAPSULE_DEMO_PASSWORD` of at least 24 characters. Store them as Railway variables, never in Git, logs or the source package.
- Set `CAPSULE_HOSTS` to the exact generated service hostname and `healthcheck.railway.app`; set `CAPSULE_ORIGINS` to the exact HTTPS service origin. Never use wildcard hosts.
- Configure `CAPSULE_PG_DATABASE`, `CAPSULE_PG_USER`, `CAPSULE_PG_PASSWORD`, `CAPSULE_PG_HOST`, `CAPSULE_PG_PORT` from the dedicated PostgreSQL service's private-network references. Do not expose the database with a public TCP proxy.
- Launch one application replica. The container runs migrations, invokes `hosted_demo`, then starts Gunicorn. The seed command creates only the four synthetic accounts and one DRAFT; existing complete fixtures are preserved. Resolve partial fixtures explicitly.
- The same generated demo password permits practicing four roles. This is intentionally an operator demonstration, not independent review or verified human separation. Keep credentials privately with the owner; there is no signup or password-recovery flow.

## Verification completed in this session

`python manage.py test -v 1`: 20 tests, OK, on Python 3.12 with SQLite. `python manage.py check`: no issues. `python manage.py makemigrations --check --dry-run`: no changes detected.

These tests cover the existing protected-review boundary and the added setup/throttle behavior. They do not qualify a deployed database, multiple workers under concurrent attack, infrastructure, or a browser. The PostgreSQL workflow in `.github/workflows/verify.yml` has been supplied but not run.

## Required hosted checks before handoff

1. Verify the build and healthy deployment; health must query PostgreSQL successfully.
2. Verify HTTPS, cookies, explicit hosts/origins, CSRF protection, authentication redirects and no-store responses through the real proxy. The HTTPS proxy-header assumption still requires deployed verification.
3. Exercise author freeze, reviewer declarations, steward decisions, both locked submissions, closure and whole-round reveal in separate browser sessions or by signing out between roles.
4. Attempt direct cross-role packet/receipt/export access. Inspect actual reviewer response bodies for planted withheld canaries.
5. Verify restart preserves data and passwords. Exercise PostgreSQL simultaneous submit/close and duplicate submission before any claim about concurrent correctness.
6. Leave a new synthetic draft ready for the owner after walkthrough testing. Publish no confidential export.

## Limits that remain

This code cannot guarantee zero bias, reviewer identity, independence, no external exposure or secrecy from a database/server administrator. Local sign-in throttling tests are not a DoS qualification; its address bucket may group visitors behind a shared proxy. Administrative data changes and races between separate rounds require further scrutiny. Real research hosting requires security review, backup/restore and retention policies, account lifecycle controls, consent publication and operational ownership beyond this demo.

Kill criterion for this milestone: if a reviewer session obtains withheld material or another review before the frozen release rule permits it, stop deployment and repair the boundary before inviting anyone.
