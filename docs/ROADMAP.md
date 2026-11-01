# Next decisions and release gates

Completed: local, server-rendered protected evidence-support round; draft intake; separate stewardship; frozen roster/packet/deadline; declarations; independent first submissions; amendments; whole-round closure; private receipts/export; synthetic route tests.

Next, before real research:

1. Have an outside developer inspect authorization, fixtures and exposure logic. Reproduce the tests on a clean machine.
2. Add PostgreSQL-backed concurrent submission/closure tests, export/receipt verification CLI and import round-trip tests. Qualify backups/restore and failure recovery.
3. Test mobile/browser workflows. The owner currently works from an iPhone; a secure controlled hosted demo must make the workflow inspectable there without a second machine.
4. Implement real identity/account lifecycle, secure deployment, login abuse controls, consent, retention/withdrawal and de-identified public exports.
5. Add protocol review and reproduction as separate task types. Preserve their different information requirements. Add cross-study exposure/material linking before supporting related study families.
6. Pilot with a few real reviewers on fresh synthetic material. Track whether they understand the task and disclosures, not whether they agree with the author.

Only then release a clearly labeled early GitHub version and a DEV.to write-up. Keep the original evidence-ordering pilot separate from the tool qualification; its cases/results are already public. No automatically generated “independent,” “human verified,” “peer reviewed” or “bias free” badge.

If reviewers cannot understand the workflow without outcome-leading coaching, or an existing OpenReview/private-form workflow works better, narrow this to a review-packet and export adapter.

Not built: public community concern board; consent-based credit; review marketplace; anonymous account onboarding; external timestamp anchoring; encrypted operator-blind storage; email reminders; GitHub issue integrations; result-quality scoring; AI reviewers; hosted production service. No outside reviewer has been contacted and nothing has been published.
