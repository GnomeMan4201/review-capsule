# Frozen limits statement synchronization tests; Python 3.12+, stdlib [needs Linux runner].
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from rr.constants import LIMITS
from rr.verify import verify_bundle
from reference_round import create
import tempfile


class LimitsSyncTests(unittest.TestCase):
    def test_constant_file_and_normative_section_agree_byte_for_byte(self):
        file_bytes=(ROOT/"spec/limits.txt").read_bytes()
        spec=(ROOT/"spec/REVIEW_RECORD_SPEC_v0.2.2.md").read_text(encoding="utf-8")
        block=spec.split("## 8. Required `limits` statement (verbatim)\n\n",1)[1].split("\n\n## 9.",1)[0]
        self.assertTrue(block.startswith("> "))
        self.assertEqual(block[2:].encode("utf-8"),LIMITS.encode("utf-8"))
        self.assertEqual(file_bytes,(LIMITS+"\n").encode("utf-8"))

    def test_signed_consistent_weaker_limits_still_fail_builtin_policy(self):
        from reference_round import envelope, canon
        import json,base64
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)
            meta=create(path)
            registration=path/"registration.json"
            original=json.loads(registration.read_bytes())
            payload=json.loads(base64.b64decode(original["payload"]))
            payload["limits"]="A weaker and misleading statement"
            registration.write_bytes(envelope(payload,"author"))
            (path/"limits.txt").write_text(payload["limits"]+"\n")
            report=verify_bundle(path,expected_author_key=meta["author_key"],
                                 expected_steward_key=meta["steward_key"])
            self.assertEqual(report["exit_code"],1)
            self.assertTrue(any(c["code"]=="LIMITS_MISSING_OR_ALTERED" and
                                c["status"]=="fail" for c in report["checks"]))


if __name__=="__main__":
    unittest.main()
