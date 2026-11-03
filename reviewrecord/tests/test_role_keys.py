# Role-key separation tests; Python 3.12+, synthetic fixtures [needs Linux runner].
import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

from reference_round import create, envelope
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from rr.verify import verify_bundle


class RoleSeparationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)/"bundle"
        self.meta=create(self.folder)

    def verify(self):
        return verify_bundle(self.folder,expected_author_key=self.meta["author_key"],
                             expected_steward_key=self.meta["steward_key"])

    def test_reviewer_signed_by_author_key_is_rejected(self):
        path=next((self.folder/"declarations").rglob("*.json"))
        value=json.loads(base64.b64decode(json.loads(path.read_bytes())["payload"]))
        value["reviewer_key"]=self.meta["author_key"]
        path.write_bytes(envelope(value,"author"))
        report=self.verify()
        self.assertEqual(report["exit_code"],1)
        self.assertTrue(any(c["code"]=="ROLE_KEY_REUSED" and c["status"]=="fail"
                            for c in report["checks"]))

    def test_steward_key_cannot_be_reviewer_key(self):
        path=next((self.folder/"assessments").rglob("*.json"))
        value=json.loads(base64.b64decode(json.loads(path.read_bytes())["payload"]))
        value["reviewer_key"]=self.meta["steward_key"]
        path.write_bytes(envelope(value,"steward"))
        report=self.verify()
        self.assertEqual(report["exit_code"],1)
        self.assertTrue(any(c["code"]=="ROLE_KEY_REUSED" and c["status"]=="fail"
                            for c in report["checks"]))

    def test_author_and_steward_must_use_separate_signing_keys(self):
        path=self.folder/"registration.json"
        value=json.loads(base64.b64decode(json.loads(path.read_bytes())["payload"]))
        value["steward_key"]=self.meta["author_key"]
        path.write_bytes(envelope(value,"author"))
        report=self.verify()
        self.assertEqual(report["exit_code"],1)
        self.assertTrue(any(c["code"]=="ROLE_KEY_REUSED" and c["status"]=="fail"
                            for c in report["checks"]))


if __name__=="__main__":
    unittest.main()
