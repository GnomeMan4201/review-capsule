# Check report status vocabulary; Python 3.12+, stdlib [a-Shell ok].
import itertools
import unittest

from rr.report import Report


class ReportStatusTests(unittest.TestCase):
    def test_all_defined_status_subsets_keep_the_frozen_exit_mapping(self):
        statuses = ('pass', 'fail', 'missing', 'pending', 'unverifiable', 'not_checked')
        for flags in itertools.product((False, True), repeat=6):
            selected = [s for s, use in zip(statuses, flags) if use]
            with self.subTest(statuses=selected):
                report = Report()
                for status in selected:
                    report.add('SYNTHETIC_CONTROL', status)
                result = report.finish()
                expected = 1 if {'fail', 'missing'} & set(selected) else 2 if {'pending', 'unverifiable', 'not_checked'} & set(selected) else 0
                self.assertEqual(result['exit_code'], expected)
                self.assertFalse(any(c['code'] == 'REPORT_STATUS_UNRECOGNIZED' for c in result['checks']))

    def test_unknown_status_is_rejected_even_beside_a_matched_row(self):
        for status in ('typo', 'declared', 'attested', 'PASS', None, True, 0, [], {}):
            with self.subTest(status=status):
                report = Report()
                report.add('SYNTHETIC_MATCH', 'pass')
                report.add('SYNTHETIC_UNKNOWN', status)
                result = report.finish()
                self.assertEqual(result['exit_code'], 1)
                diagnostics = [c for c in result['checks'] if c['code'] == 'REPORT_STATUS_UNRECOGNIZED']
                self.assertEqual(len(diagnostics), 1)
                self.assertEqual(diagnostics[0]['status'], 'fail')
                self.assertEqual(diagnostics[0]['subject'], 'checks/1/status')
                self.assertEqual(set(result['counts']), {'pass', 'fail', 'missing', 'pending', 'unverifiable', 'not_checked'})
                self.assertEqual(result['checks'][1]['status'], status)

    def test_repeated_finish_does_not_duplicate_status_diagnostics(self):
        report = Report()
        report.add('SYNTHETIC_UNKNOWN', 'typo')
        first = report.finish()
        first_count = len(first['checks'])
        again = report.finish()
        self.assertEqual(again['exit_code'], 1)
        self.assertEqual(len(again['checks']), first_count)
        self.assertEqual(sum(c['code'] == 'REPORT_STATUS_UNRECOGNIZED' for c in again['checks']), 1)

    def test_pass_row_named_like_diagnostic_cannot_suppress_rejection(self):
        report = Report()
        report.add('SYNTHETIC_UNKNOWN', 'typo')
        report.add('REPORT_STATUS_UNRECOGNIZED', 'pass', 'checks/0/status')
        self.assertEqual(report.finish()['exit_code'], 1)


if __name__ == '__main__':
    unittest.main()
