# Test opt-in report format using MOCKED anchors; Python 3.12+, project deps [needs Linux runner].
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path

from reference_round import create, canon, envelope
from report_v1_fixtures import rebuild, refresh_manifest, mocked_anchors
from rr import dsse
from rr.report import Report
from rr.verify import verify_bundle


class ReportV1Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name) / 'bundle'
        self.meta = create(self.folder)

    def run_report(self, *, modern=False, mocked=True, registry=None, pins=True):
        options = dict(registries=[dict(source='SYNTHETIC snapshot', work_id='synthetic-work',
                                       prior_rounds=['synthetic-prior-round'])] if registry is None else registry)
        if pins:
            options.update(expected_author_key=self.meta['author_key'], expected_steward_key=self.meta['steward_key'])
        if modern:
            options['report_format'] = 'reviewrecord-report/v1'
        with mocked_anchors(self.folder) if mocked else nullcontext():
            return verify_bundle(self.folder, **options)

    def equivalent_exit(self, **options):
        old = self.run_report(**options)
        new = self.run_report(modern=True, **options)
        self.assertEqual(new['exit_code'], old['exit_code'])
        return old, new

    def test_scoped_counts_and_statements_preserve_mocked_and_offline_exits(self):
        baseline = self.run_report()
        self.assertEqual(baseline['exit_code'], 0)  # MOCKED anchors, not real evidence.
        for mocked, expected in ((True, 0), (False, 2)):
            old, new = self.equivalent_exit(mocked=mocked)
            self.assertEqual(new['exit_code'], expected)
            self.assertEqual(new['report_format'], 'reviewrecord-report/v1')
            self.assertEqual(new['spec'], '0.2.2')
            self.assertNotIn('round_status', new)
            self.assertNotIn('verified_reveals', new)
            self.assertNotIn('locked_count', new)
            self.assertNotIn('tree_size', new)
            self.assertEqual(new['review_counts']['first_commit_matching_reveals'], 3)
            self.assertEqual(new['review_counts']['logged_distinct_commit_keys'], 3)
            self.assertEqual(new['counts']['pass'], old['counts']['pass'] - 2)
            self.assertFalse(any(c['code'] in ('OPERATOR_DISCLOSURE', 'WITHDRAWN', 'WITHDRAWAL_STEWARD_ATTESTED') for c in new['checks']))
            self.assertEqual(len(new['statements_and_events']), 8)  # 3 declarations, 3 dispositions, 1 operator, 1 withdrawal.
            for statement in new['statements_and_events']:
                self.assertNotIn('status', statement)
                self.assertTrue(statement['check_refs'])
                for ref in statement['check_refs']:
                    self.assertTrue(ref.startswith('/checks/'))
                    self.assertIn('status', new['checks'][int(ref.rsplit('/', 1)[1])])

    def test_steward_claim_is_side_content_not_consent_or_pass(self):
        rebuild(self.folder, attested=True)
        old, new = self.equivalent_exit()
        self.assertEqual(old['exit_code'], 0)  # MOCKED anchors.
        claim = next(s for s in new['statements_and_events'] if s['kind'] == 'withdrawal')
        self.assertEqual(claim['basis'], 'steward_attested')
        self.assertIn('reviewer consent is not established', claim['wording'])
        self.assertTrue(any(c['code'] == 'SIGNATURE_INVALID' and c['status'] == 'pass' for c in new['checks']))
        p = next((self.folder / 'withdrawals').rglob('*.json'))
        p.write_bytes(envelope(dsse.decode(p.read_bytes()).value, 'author'))
        refresh_manifest(self.folder)
        old, new = self.equivalent_exit()
        self.assertEqual(new['exit_code'], 1)
        self.assertTrue(any(c['code'] == 'SIGNATURE_INVALID' and c['status'] == 'fail' for c in new['checks']))

    def test_operator_false_is_also_a_declaration(self):
        p = self.folder / 'registration.json'
        value = dsse.decode(p.read_bytes()).value
        value['steward_is_author_operator'] = False
        p.write_bytes(envelope(value, 'author'))
        rebuild(self.folder)
        old, new = self.equivalent_exit()
        self.assertEqual(old['exit_code'], 0)  # MOCKED anchors.
        operator = next(s for s in new['statements_and_events'] if s['kind'] == 'operator_disclosure')
        self.assertIs(operator['content']['steward_is_author_operator'], False)
        self.assertIn('not factually established', operator['wording'])

    def test_disabled_dispositions_visible_but_strict_effect_unselected(self):
        rebuild(self.folder, policy_off=True)
        for p in (self.folder / 'dispositions').glob('*.json'):
            p.unlink()
        refresh_manifest(self.folder)
        old, new = self.equivalent_exit()
        self.assertEqual(old['exit_code'], 0)  # MOCKED anchors; permitted current schema.
        notice = next(n for n in new['coverage_notices'] if n['reason'] == 'policy_disabled')
        self.assertEqual((notice['candidate_count'], notice['checked_count']), (3, 0))
        self.assertNotIn('status', notice)
        self.assertNotIn('exit_effect', notice)
        strict = Path(self.tmp.name) / 'strict'
        meta = create(strict)
        for p in (strict / 'dispositions').glob('*.json'):
            p.unlink()
        refresh_manifest(strict)
        with mocked_anchors(strict):
            control = verify_bundle(strict, report_format='reviewrecord-report/v1', expected_author_key=meta['author_key'], expected_steward_key=meta['steward_key'])
        self.assertEqual(control['exit_code'], 1)
        self.assertEqual(sum(c['code'] == 'DISPOSITION_MISSING' for c in control['checks']), 3)

    def test_empty_registry_notice_and_mismatch_control(self):
        registry = [dict(source='SYNTHETIC empty', work_id='synthetic-work', prior_rounds=[])]
        old, new = self.equivalent_exit(registry=registry)
        self.assertEqual(old['exit_code'], 0)  # MOCKED anchors.
        notice = next(n for n in new['coverage_notices'] if n['reason'] == 'matching_snapshot_empty')
        self.assertEqual((notice['candidate_count'], notice['checked_count']), (0, 0))
        self.assertIn('unknown', notice['wording'])
        registry[0]['prior_rounds'] = ['omitted-round']
        old, new = self.equivalent_exit(registry=registry)
        self.assertEqual(new['exit_code'], 1)
        registry[0].update(work_id='other', prior_rounds=[])
        old, new = self.equivalent_exit(registry=registry)
        self.assertEqual(new['exit_code'], 2)
        self.assertTrue(any(n['reason'] == 'work_id_mismatch' for n in new['coverage_notices']))

    def test_surplus_descriptors_do_not_mask_missing_required_anchor(self):
        (self.folder / 'anchors/surplus.json').write_bytes(canon(dict(type='ots', target='sha256:' + '0' * 64)))
        (self.folder / 'anchors/nonobject.json').write_bytes(canon([]))
        old, new = self.equivalent_exit()
        self.assertEqual(old['exit_code'], 0)  # MOCKED anchors.
        self.assertEqual(sum(n['reason'] == 'target_not_requested' for n in new['coverage_notices']), 1)
        self.assertEqual(sum(n['reason'] == 'descriptor_not_object' for n in new['coverage_notices']), 1)
        (self.folder / 'anchors/registration-ots.json').unlink()
        old, new = self.equivalent_exit()
        self.assertEqual(new['exit_code'], 1)
        self.assertTrue(any(c['code'] == 'ANCHOR_MISSING' for c in new['checks']))

    def test_counts_do_not_hide_a_missing_reveal_or_select_roster(self):
        rebuild(self.folder, omit='reviewer-c')
        old, new = self.equivalent_exit()
        self.assertEqual(new['review_counts']['logged_distinct_commit_keys'], 2)
        self.assertEqual(new['exit_code'], 0)  # MOCKED anchors; no roster check selected.
        next((self.folder / 'assessments').rglob('*.json')).unlink()
        refresh_manifest(self.folder)
        old, new = self.equivalent_exit()
        self.assertEqual(new['exit_code'], 1)
        self.assertTrue(any(c['code'] == 'REVEAL_MISSING' for c in new['checks']))

    def test_existing_unchecked_rows_remain_blocking(self):
        for options in (dict(pins=False), dict(registry=[]), dict(mocked=False)):
            old, new = self.equivalent_exit(**options)
            self.assertEqual(new['exit_code'], 2)

    def test_direct_report_not_checked_wording_and_side_neutrality(self):
        report = Report(report_format='reviewrecord-report/v1')
        report.add('SYNTHETIC_UNCHECKED', 'not_checked')
        report.statement('declaration', 'participant_declared', 'synthetic', 'synthetic', 'claimed-key', {}, 'Participant states this; truth not established.')
        result = report.finish()
        self.assertEqual(result['exit_code'], 2)
        self.assertIn('not evaluated', result['checks'][0]['detail'])
        self.assertNotIn('did not match', result['checks'][0]['detail'])
        control = Report(report_format='reviewrecord-report/v1')
        control.add('SYNTHETIC_FAILURE', 'fail')
        self.assertEqual(control.finish()['exit_code'], 1)

    def test_cli_opt_in_and_unknown_format(self):
        command = [sys.executable, '-m', 'rr.cli', str(self.folder)]
        result = subprocess.run(command + ['--report-format', 'reviewrecord-report/v1'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)['report_format'], 'reviewrecord-report/v1')
        self.assertEqual(subprocess.run(command + ['--report-format', 'unknown'], capture_output=True).returncode, 2)

    def test_nonstring_surplus_target_cannot_crash_either_format(self):
        (self.folder / 'anchors/surplus.json').write_bytes(canon(dict(type='ots', target=[])))
        old, new = self.equivalent_exit()
        self.assertEqual(new['exit_code'], 0)  # MOCKED anchors; current targets unchanged.
        self.assertTrue(any(n['reason'] == 'target_not_requested' for n in new['coverage_notices']))

    def test_unknown_status_cannot_crash_new_renderer(self):
        for status in (None, True, [], {}):
            with self.subTest(status=status):
                report = Report(report_format='reviewrecord-report/v1')
                report.add('SYNTHETIC_UNKNOWN', status)
                self.assertEqual(report.finish()['exit_code'], 1)

    def test_side_wording_boundary_cannot_bypass_checks(self):
        report = Report(report_format='reviewrecord-report/v1')
        report.add('SYNTHETIC_MATCH', 'pass')
        report.statement('declaration', 'participant_declared', 'synthetic', 'synthetic', 'claimed-key', {}, 'trusted')
        report.coverage_notice('synthetic', 'synthetic', 'skipped', 'synthetic', 0, 0, 'trusted')
        result = report.finish()
        self.assertEqual(result['exit_code'], 1)
        self.assertEqual(sum(c['code'] == 'FORBIDDEN_CLAIM_PRESENT' for c in result['checks']), 2)


if __name__ == '__main__':
    unittest.main()
