# Known-gap observations; Python 3.12+, project deps [needs Linux runner].
"""Run separately from tests/: successful assertions reproduce gaps, not remedies."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fixtures import create, rebuild, refresh_manifest, pub, rid
from rr.verify import verify_bundle
from rr import dsse
from rr.report import Report

OUTPUT = Path(__file__).resolve().parents[2] / 'evidence/external-concerns-2026-11-02'


class KnownGapTests(unittest.TestCase):
    def test_known_gap_report_can_exit_zero_without_structural_checks(self):
        observations = []
        for label, add_unrelated_row in [('empty', False), ('unrelated-pass-only', True)]:
            with self.subTest(case=label):
                report = Report()
                if add_unrelated_row:
                    report.add('SYNTHETIC_UNRELATED_CHECK', 'pass')
                result = report.finish()
                self.assertEqual(result['exit_code'], 0)
                self.assertEqual(result['round_status'], 'incomplete')
                self.assertEqual(len(result['checks']), int(add_unrelated_row))
                observations.append(dict(case=label, report=result))
        OUTPUT.mkdir(parents=True, exist_ok=True)
        (OUTPUT / 'empty-report.json').write_text(json.dumps(observations, indent=2) + '\n')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / 'bundle'
        self.meta = create(self.folder)

    def verify(self, name, folder=None):
        result = verify_bundle(folder or self.folder, expected_author_key=self.meta['author_key'],
                               expected_steward_key=self.meta['steward_key'])
        OUTPUT.mkdir(parents=True, exist_ok=True)
        (OUTPUT / (name + '.json')).write_text(json.dumps(result, indent=2) + '\n')
        self.assertEqual(result['counts']['fail'], 0)
        self.assertEqual(result['counts']['missing'], 0)
        self.assertEqual(result['exit_code'], 2)
        return result

    def test_known_gap_e4a_complete_with_unresolved_anchors(self):
        result = self.verify('e4a')
        self.assertEqual(result['round_status'], 'complete')
        self.assertEqual([x['status'] for x in result['anchors']].count('pending'), 3)
        self.assertEqual([x['status'] for x in result['anchors']].count('unverifiable_offline'), 3)
        process = subprocess.run([sys.executable, '-m', 'rr.cli', str(self.folder),
            '--expected-author-key', self.meta['author_key'], '--expected-steward-key', self.meta['steward_key']],
            capture_output=True, text=True, check=False)
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(json.loads(process.stdout)['round_status'], 'complete')

    def test_known_gap_e4b_steward_allegation_in_pass_bucket(self):
        rebuild(self.folder, attested=True)
        result = self.verify('e4b')
        rows = [x for x in result['checks'] if x['code'] == 'WITHDRAWAL_STEWARD_ATTESTED']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status'], 'pass')
        self.assertIn('reviewer consent is not established', rows[0]['detail'])
        self.assertEqual(result['reviewers'][0]['withdrawal_basis'], 'attested')

    def test_known_gap_e4c_disabled_disposition_check_is_silent(self):
        rebuild(self.folder, policy_off=True)
        for p in (self.folder / 'dispositions').glob('*.json'):
            p.unlink()
        refresh_manifest(self.folder)
        result = self.verify('e4c')
        self.assertEqual(result['verified_reveals'], 3)
        # Each retained assessment still has a concern; none has a disposition.
        for p in (self.folder / 'assessments').rglob('*.json'):
            self.assertTrue(dsse.decode(p.read_bytes()).value['items'][0]['concerns'])
        self.assertFalse(any('DISPOSITION' in x['code'] for x in result['checks']))
        self.assertFalse(any('disposition' in (x['detail'] + x['subject']).lower() for x in result['checks']))
        # The strict control is the original signed fixture with its dispositions removed.
        control = Path(self.temp.name) / 'strict'
        create(control)
        for p in (control / 'dispositions').glob('*.json'):
            p.unlink()
        refresh_manifest(control)
        report = verify_bundle(control)
        self.assertEqual(report['exit_code'], 1)
        self.assertEqual(sum(x['code'] == 'DISPOSITION_MISSING' for x in report['checks']), 3)

    def test_known_gap_e3_two_consistent_heads_same_registration(self):
        fork = Path(self.temp.name) / 'fork'
        shutil.copytree(self.folder, fork)
        rebuild(fork, omit='reviewer-c')
        self.assertEqual((fork / 'registration.json').read_bytes(), (self.folder / 'registration.json').read_bytes())
        full = self.verify('e3-full')
        reduced = self.verify('e3-omitted', fork)
        self.assertNotEqual(dsse.decode((fork / 'close.json').read_bytes()).value['last_entry_hash'],
                            dsse.decode((self.folder / 'close.json').read_bytes()).value['last_entry_hash'])
        self.assertTrue(list((self.folder / 'commits' / rid(pub('reviewer-c'))).glob('*.json')))
        self.assertFalse((fork / 'commits' / rid(pub('reviewer-c'))).exists())
        self.assertEqual(full['locked_count'], 3)
        self.assertEqual(reduced['locked_count'], 2)
        self.assertEqual(full['round_status'], reduced['round_status'])
        # Neither is an overall acceptance: both return 2 on real offline anchor checks.
        self.assertEqual(full['round_status'], 'complete')


if __name__ == '__main__':
    unittest.main()
