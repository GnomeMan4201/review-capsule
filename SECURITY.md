# Security status and reporting

This is an unaudited local prototype. It is not approved for confidential research or public deployment. No private reporting address or hosted service exists yet. Until a maintainer establishes a private reporting channel, do not publish sensitive study content, credentials, live exploit targets or reviewer identities in an issue. A public GitHub issue may discuss a synthetic, non-sensitive reproduction of a prototype defect.

## Trust boundary

The application attempts to withhold results and other people's assessments from reviewer requests, and to withhold initial assessments from author/steward routes until closure. The hosting operator, database administrator, anyone with shell/backups and a malicious modified application remain trusted. There is no end-to-end encryption or independent key custody.

Login proves control of an account only. Declarations and steward review do not prove unique identity, expertise, lack of outside exposure or absence of AI assistance. Review receipt commitments use SHA-256 with random 256-bit nonces; this design has not received independent cryptographic review. Local server timestamps are not independently trusted timestamps.

## Data handling

- All application responses use `Cache-Control: no-store, private`; content is escaped; scripts and remote embeds are disabled by CSP.
- No upload, remote URL fetch or research-code execution endpoint exists.
- Initial assessments and declarations have no application edit/delete path. Amendments are separate. Direct database writes can bypass application rules, and full database rewrites are not prevented.
- Frozen contract checks detect unaccompanied packet/roster/withheld changes. They do not defeat an operator who rewrites data and commitments together.
- Private exports and receipts contain sensitive judgments and identifiers. There is no consent-driven public export yet. Do not publish private exports.
- No third-party AI service receives review content. Reviewer assistance declarations remain self-reported.

## Required before public or real-study use

Independent authorization/security review; PostgreSQL transaction/concurrency tests; production web server and reverse proxy; TLS/cookie/origin/host configuration; brute-force protection; account lifecycle and recovery; deployment secret management; backups and restore qualification; retention/withdrawal policy; consent and safe public exports; monitoring without result-bearing log leakage; external commitment witnessing if claiming independently verifiable chronology.

The test suite demonstrates specific routes and policies on synthetic records. It is not proof that every leakage route has been eliminated.
