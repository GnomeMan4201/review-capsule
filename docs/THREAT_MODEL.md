# Prototype threat model and validation boundary

| Threat | Implemented control | Known residual |
| --- | --- | --- |
| Reviewer requests another assignment or receipt | Server checks assignment account on each route | Account sharing, compromised sessions, operator access |
| Expected answers appear in reviewer payloads | Explicit packet allowlist; separate withheld JSON; planted-value response tests | Semantically leading evidence/candidates still need human packet review |
| Reviewer sees peer answers after one item | Whole-assignment lock; whole-round release; peer answers never returned in v0.1 | Outside conversations and screenshots |
| Author reads initial bodies before closure | Desk/export routes withhold them | Author running the server can read database/backups |
| Packet or roster quietly changes after freeze | Recomputed salted contract commitment plus frozen-field ORM guards | Malicious operator rewrites all records and hashes |
| Locked review overwritten | No application update path; separate amendment records | Direct database modification |
| Exposed reviewer submits as first-exposure reviewer | Admission and submission consult recorded study exposure | Undeclared exposure and distinct related studies not automatically linked |
| Public feedback becomes a study label | Separate tables and disjoint exports; no conversion route | A dishonest report outside the tool |
| Active research attachment executes | No attachments, executable rendering, or server execution | Future upload support needs a new design |
| Close races submission | Shared round lock in transactions | SQLite does not qualify row-level concurrency; PostgreSQL test pending |
| Low-entropy label guessed from public hash | Salts/nonces not published in generic reviewer packet | Custom receipt scheme still needs external review |

The current exposure scope is a study. Relationships across different study records are not inferred. Creating a new study ID must not be used to claim a previously exposed person is unexposed; a cross-study material registry belongs in a later design.

No browser QA, PostgreSQL concurrency exercise, penetration test or independent audit has been completed. The 15 tests are automated, author-run synthetic checks. The public launch must not claim “zero leakage.”

0.2 adds a chained application audit log and external commitment-publication attestation. Neither prevents a privileged operator replacing storage/history. Migration chains legacy events at migration time; it does not establish retrospective independent chronology. See NEXT_ITERATION.md for calibration redaction and peer-release boundaries.
