# Bounded mutation/fold experiment; Python 3.12+, project deps [needs Linux runner].
"""Offline diagnostic. Synthetic all-pass controls mock anchor evidence, never qualify it."""
import argparse
import ast
from contextlib import contextmanager
import itertools
import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from fixtures import ROOT, create, rebuild, refresh_manifest
from rr.verify import verify_bundle
from rr.report import Report
from rr import dsse


@contextmanager
def simulated_anchors(folder):
    expected = {p.relative_to(folder).as_posix(): p.read_bytes() for p in (folder / 'anchors').glob('*')}
    reg = dsse.decode((folder / 'registration.json').read_bytes()).object_hash
    close = dsse.decode((folder / 'close.json').read_bytes()).object_hash

    def inspect(descriptor, files, **kwargs):
        proof_name = descriptor['proof']
        if proof_name not in expected or files.get(proof_name) != expected[proof_name]:
            return dict(status='invalid', detail='SIMULATION: proof bytes changed or missing')
        return dict(status='confirmed', detail='SIMULATION ONLY; no external authority qualified',
                    authority='simulation:' + descriptor['type'],
                    attested_time='2026-11-01T12:00:00Z' if descriptor['target'] == reg else
                                  '2026-11-01T14:00:00Z' if descriptor['target'] == close else
                                  '2026-11-01T15:00:00Z', basis='experiment test double')

    with patch('rr.verify.anchor_evidence.inspect', side_effect=inspect):
        yield


def verify(folder, meta):
    return verify_bundle(folder, expected_author_key=meta['author_key'], expected_steward_key=meta['steward_key'],
                         registries=[dict(source='SYNTHETIC supplied snapshot', work_id='synthetic-work',
                                          prior_rounds=['synthetic-prior-round'])])


def code_inventory():
    """Static literal inventory, not a reachability proof or mutation coverage claim."""
    found = {}
    for file in (ROOT / 'src/rr').rglob('*.py'):
        tree = ast.parse(file.read_text())
        for node in ast.walk(tree):
            values = []
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ''
                if name in ('add', 'missing', 'EnvelopeError') and node.args:
                    values = [node.args[0]]
            # Anchor status mapping contains (code, status) tuples.
            if isinstance(node, ast.Tuple) and len(node.elts) == 2:
                second = node.elts[1]
                if isinstance(second, ast.Constant) and second.value in ('pass', 'fail', 'pending', 'missing', 'unverifiable'):
                    values = [node.elts[0]]
            for value in values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.isupper():
                    found.setdefault(value.value, []).append(str(file.relative_to(ROOT)) + ':' + str(node.lineno))
    return found


def run():
    statuses = ('pass', 'fail', 'missing', 'pending', 'unverifiable', 'not_checked')
    folds = []
    for flags in itertools.product((False, True), repeat=len(statuses)):
        report = Report()
        selected = [s for s, enabled in zip(statuses, flags) if enabled]
        for status in selected:
            report.add('SYNTHETIC_CODE', status)
        result = report.finish()
        expected = 1 if any(s in selected for s in ('fail', 'missing')) else 2 if any(s in selected for s in ('pending', 'unverifiable', 'not_checked')) else 0
        assert result['exit_code'] == expected
        folds.append(dict(statuses=selected, exit_code=result['exit_code']))
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp) / 'base'
        meta = create(base)
        offline_control = verify(base, meta)
        with simulated_anchors(base):
            control = verify(base, meta)
            assert control['exit_code'] == 0, control['summary']
            mutations = []
            for relative in sorted(p.relative_to(base) for p in base.rglob('*') if p.is_file()):
                for operation in ('remove', 'corrupt'):
                    trial = Path(temp) / 'trial'
                    shutil.copytree(base, trial)
                    path = trial / relative
                    if operation == 'remove':
                        path.unlink()
                    else:
                        raw = path.read_bytes()
                        path.write_bytes(b'!' + raw[1:])
                    result = verify(trial, meta)
                    assert result['exit_code'] == 1, (relative.as_posix(), operation, result['summary'])
                    mutations.append(dict(path=relative.as_posix(), operation=operation, exit_code=result['exit_code'], counts=result['counts'],
                                          nonpass_codes=sorted({x['code'] for x in result['checks'] if x['status'] != 'pass'})))
                    shutil.rmtree(trial)
        semantic = []
        for name, options, remove_dispositions in (
            ('omitted-reviewer-c', {'omit': 'reviewer-c'}, False),
            ('steward-attested-withdrawal', {'attested': True}, False),
            ('disabled-dispositions-with-three-concerns', {'policy_off': True}, True),
        ):
            trial = Path(temp) / name
            shutil.copytree(base, trial)
            rebuild(trial, **options)
            if remove_dispositions:
                for path in (trial / 'dispositions').glob('*.json'):
                    path.unlink()
                refresh_manifest(trial)
            with simulated_anchors(trial):
                result = verify(trial, meta)
            semantic.append(dict(name=name, exit_code=result['exit_code'], round_status=result['round_status'],
                                 locked_count=result['locked_count'], counts=result['counts']))
        return dict(label='demonstrated here: bounded synthetic experiment, not exhaustive per-code coverage',
                    base_commit='d54432f3e4c67f11ea53c16ebb383c1aec1f9224',
                    offline_control_exit=offline_control['exit_code'], simulated_control_exit=control['exit_code'],
                    mutation_control_exit=control['exit_code'], mutation_expected_exit=1,
                    mutation_exit_counts={str(code): sum(x['exit_code'] == code for x in mutations) for code in (0, 1, 2)},
                    mutation_anchor_validation='test double checks expected proof bytes; no real anchor parsing/qualification tested by this sweep',
                    fold_statuses=list(statuses), fold_interpretation='all 64 subsets of the six statuses, including empty; one synthetic row per included status; not bundle scenarios',
                    caveat='All-pass controls use mocked anchor validation and a supplied synthetic registry snapshot. No real fully qualified all-pass bundle demonstrated.',
                    fold_cases=folds, empty_report_exit=folds[0]['exit_code'],
                    static_literal_code_inventory=code_inventory(),
                    mutation_cases=mutations, mutation_survivors=[x for x in mutations if x['exit_code'] == 0],
                    semantic_cases=semantic,
                    exhaustive_per_code_coverage='unknown; no evidence-to-code reachability/requirement map exists; diagnostic and absent-set cases cannot be generated by mutating an emitted row alone')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', type=Path, help='Explicitly write JSON findings; otherwise print only.')
    args = parser.parse_args()
    try:
        result = run()
        output = json.dumps(result, indent=2) + '\n'
        if args.write:
            args.write.parent.mkdir(parents=True, exist_ok=True)
            args.write.write_text(output)
        else:
            print(output, end='')
        return 0  # Experiment completed, not a verifier verdict.
    except (OSError, ValueError, AssertionError, KeyError) as exc:
        print('Experiment failed: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
