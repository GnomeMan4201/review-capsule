# Known-gap report observations; Python 3.12+, project stdlib module [a-Shell ok].
import unittest
from rr.report import Report

class KnownGapTests(unittest.TestCase):
    def test_empty_and_unrelated_pass_still_exit_zero(self):
        for populated in (False, True):
            with self.subTest(unrelated_pass=populated):
                report=Report()
                if populated:report.add('SYNTHETIC_UNRELATED','pass')
                self.assertEqual(report.finish()['exit_code'],0)

if __name__=='__main__':unittest.main()
