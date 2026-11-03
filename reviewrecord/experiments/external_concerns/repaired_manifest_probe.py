# Compare repaired-manifest mutations; Python 3.12+, project dependencies [needs Linux runner].
"""Retained experimental results, not coverage claims; all anchor qualification is mocked."""
import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

from fixtures import ROOT, create, refresh_manifest
from meta_probe import simulated_anchors, verify

SOURCE = ROOT / 'evidence/external-concerns-2026-11-02/meta-probe.json'
PIN = '12de4dce40ab7cd0ddc73fe5d60c7364bbfb525f'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def repair(folder, base, relative):
    """Let the unchanged helper run, then restore a targeted descriptor mutation.

    Its two descriptor prerequisites are temporarily supplied only when that
    descriptor is the mutation target. This preserves all 84 target operations.
    The helper's overwrite of manifest.json/record.ots is deliberately retained.
    """
    descriptors = ('anchors/record-ots.json', 'anchors/record-tsa.json')
    target = folder / relative
    original_mutation = target.read_bytes() if target.exists() else None
    if relative in descriptors:
        target.write_bytes((base / relative).read_bytes())
    refresh_manifest(folder)
    expected_record_proof = (folder / 'anchors/record.ots').read_bytes()
    if relative in descriptors:
        if original_mutation is None:
            target.unlink()
        else:
            target.write_bytes(original_mutation)
    return expected_record_proof, relative in descriptors


def summary(result):
    return dict(exit_code=result['exit_code'], counts=result['counts'],
                nonpass_codes=sorted({r['code'] for r in result['checks'] if r['status'] != 'pass'}))


def run():
    raw_source = SOURCE.read_bytes()
    original = json.loads(raw_source)
    keys = [(r['path'], r['operation']) for r in original['mutation_cases']]
    require(len(keys) == len(set(keys)) == 84, 'Expected 84 distinct retained trials')
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        base = root / 'base'
        meta = create(base)
        require(set(keys) == {(p.relative_to(base).as_posix(), op)
                for p in base.rglob('*') if p.is_file() for op in ('remove', 'corrupt')},
                'Generated fixture differs from retained trial inventory')
        offline = verify(base, meta)
        with simulated_anchors(base):
            control = verify(base, meta)
        require(offline['exit_code'] == 2 and control['exit_code'] == 0, 'Control changed')
        expected = root / 'mock-expectations'
        shutil.copytree(base, expected)
        negative = root / 'negative'
        shutil.copytree(base, negative)
        next((negative / 'assessments').rglob('*.json')).unlink()
        expected_proof, _ = repair(negative, base, 'negative-control')
        (expected / 'anchors/record.ots').write_bytes(expected_proof)
        with simulated_anchors(expected):
            negative_result = verify(negative, meta)
        require(negative_result['exit_code'] == 1 and any(
            r['code'] == 'REVEAL_MISSING' for r in negative_result['checks']),
            'Removed-reveal negative control failed to discriminate')
        trials = []
        for old in original['mutation_cases']:
            relative, operation = old['path'], old['operation']
            trial = root / 'trial'
            shutil.copytree(base, trial)
            target = trial / relative
            if operation == 'remove':
                target.unlink()
            else:
                target.write_bytes(b'!' + target.read_bytes()[1:])
            mutated_bytes = target.read_bytes() if target.exists() else None
            # Repeat the original unrepaired observation, with base proof expectations.
            with simulated_anchors(base):
                unrepaired = verify(trial, meta)
            require(unrepaired['exit_code'] == old['exit_code'] == 1,
                    'Unrepaired comparison differs from retained result')
            proof, temporary_descriptor = repair(trial, base, relative)
            after = target.read_bytes() if target.exists() else None
            # Only helper-regenerated record proof is accepted as changed fixture data.
            # Other proof expectations remain the unmutated base bytes.
            (expected / 'anchors/record.ots').write_bytes(proof)
            with simulated_anchors(expected):
                repaired = verify(trial, meta)
            trials.append(dict(path=relative, operation=operation,
                retained_original_exit=old['exit_code'], unrepaired=summary(unrepaired),
                repaired=summary(repaired), mutation_preserved=after == mutated_bytes,
                helper_overwrote_target=after != mutated_bytes,
                temporary_descriptor_prerequisite=temporary_descriptor))
            shutil.rmtree(trial)
    return dict(label='demonstrated here: retained experimental results, not coverage claims',
        source_commit=PIN, verifier_commit='d54432f3e4c67f11ea53c16ebb383c1aec1f9224',
        original_result_path=str(SOURCE.relative_to(ROOT.parent)),
        original_result_sha256=hashlib.sha256(raw_source).hexdigest(),
        anchor_mode='MOCKED qualification; expected original proof bytes except helper-regenerated record.ots; no real anchor qualification',
        repair_method='Unchanged fixtures.refresh_manifest; target record descriptor temporarily restored for helper prerequisites then mutation reapplied; manifest/record.ots overwrites retained and flagged',
        limitations='Unknown per-code coverage; manifest repair is not repair of signatures/log bindings; mock byte gate can dominate; overwritten mutations are not surviving-defect tests',
        controls=dict(offline=summary(offline), mocked=summary(control),
                      repaired_removed_reveal_negative=summary(negative_result)),
        original_retained_exit_counts=original['mutation_exit_counts'],
        rerun_unrepaired_exit_counts={str(c):sum(t['unrepaired']['exit_code']==c for t in trials) for c in (0,1,2)},
        repaired_exit_counts={str(c):sum(t['repaired']['exit_code']==c for t in trials) for c in (0,1,2)},
        changed_exits=[dict(path=t['path'], operation=t['operation'],
            before=t['unrepaired']['exit_code'], after=t['repaired']['exit_code'],
            mutation_preserved=t['mutation_preserved']) for t in trials
            if t['unrepaired']['exit_code'] != t['repaired']['exit_code']],
        zero_exit_trials=[dict(path=t['path'],operation=t['operation'],mutation_preserved=t['mutation_preserved'])
            for t in trials if t['repaired']['exit_code']==0], trials=trials)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', type=Path, help='Explicit result destination; otherwise stdout only.')
    args = parser.parse_args()
    try:
        result = run()
        output = json.dumps(result, indent=2) + '\n'
        if args.write:
            args.write.parent.mkdir(parents=True, exist_ok=True)
            args.write.write_text(output)
            print(json.dumps({k:result[k] for k in ('label','repaired_exit_counts','changed_exits')}, indent=2))
        else:
            print(output, end='')
        return 0  # Experiment completion, not a verifier verdict.
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as exc:
        print('Experiment failed: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
