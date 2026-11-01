# Synthetic round

All keys, declarations, evidence and reasoning here are invented public test data. The deterministic signing seeds in tests/reference_round.py must never be used by participants.

Decode synthetic-round.zip.b64 with Python, then run the installed CLI:

```sh
python -c "import base64,pathlib; pathlib.Path('/tmp/synthetic-round.zip').write_bytes(base64.b64decode(pathlib.Path('examples/synthetic-round.zip.b64').read_bytes()))"
python -m rr.cli /tmp/synthetic-round.zip --json /tmp/report.json
```

The command exits 2, not 0. Without expected keys it also reports two identity checks as not checked. fixture-metadata.json supplies the public keys used to produce expected-report.json. That expected report has 158 pass, 0 fail, 0 missing, 3 pending, 3 unverifiable, 1 not checked; the remaining registry check has no supplied snapshot.

The OTS files are locally serialized calendar references to example.invalid, not submitted calendar receipts. The RFC 3161 files are explicit unverified placeholders, not timestamp tokens. They exercise unresolved reporting. Supplying a CA cannot make these placeholder bytes pass. No confirmed two-anchor round is supplied.

A successful counting result (round_status complete) is separate from evidence outcomes and the process exit code. This example has three locks and three valid reveals; one reviewer withdrew and voluntarily revealed. Its evidence remains unresolved.

Regenerate explicitly with `python tests/reference_round.py --write /tmp/new-round/bundle`. The tests compare a regenerated report with expected-report.json and decode/check the archived copy. Anchor confirmation requires separate checked evidence and backend configuration.
