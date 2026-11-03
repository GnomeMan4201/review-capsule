# Anchor-gate negative tests; Python 3.12+, fixture dependencies [needs Linux runner].
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reference_round import create, canon
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from rr.verify import verify_bundle


class AnchorGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "bundle"
        self.metadata = create(self.path)

    def check(self, **options):
        return verify_bundle(
            self.path,
            expected_author_key=self.metadata["author_key"],
            expected_steward_key=self.metadata["steward_key"],
            **options,
        )

    def find(self, report, code):
        return [entry for entry in report["checks"] if entry["code"] == code]

    def test_pending_ots_and_placeholder_tsa_do_not_pass_any_anchor_gate(self):
        report = self.check()
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(len(self.find(report, "ANCHOR_GATE_UNCONFIRMED")), 3)
        self.assertTrue(all(x["status"] == "pending" for x in
                            self.find(report, "ANCHOR_GATE_UNCONFIRMED")))
        self.assertFalse(self.find(report, "ANCHOR_GATE_CONFIRMED"))
        self.assertEqual(len(self.find(report, "ANCHOR_ORDER_NOT_CHECKED")), 1)

    def test_placeholder_token_with_external_ca_cannot_qualify_gate(self):
        ca = Path(__file__).resolve().parents[1] / "evidence" / "freetsa-ca.pem"
        report = self.check(tsa_ca=ca)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(len(self.find(report, "ANCHOR_GATE_UNCONFIRMED")), 3)
        self.assertTrue(self.find(report, "ANCHOR_INVALID"))
        self.assertFalse(self.find(report, "ANCHOR_GATE_CONFIRMED"))

    def test_descriptor_authority_relabeling_has_no_power(self):
        original = self.check()
        for name in ("registration-tsa.json", "record-tsa.json", "close-tsa.json"):
            path = self.path / "anchors" / name
            value = json.loads(path.read_bytes())
            value["authority"] = "a-made-up-second-authority"
            value["status"] = "confirmed"
            value["attested_time"] = "1970-01-01T00:00:00Z"
            path.write_bytes(canon(value))
        report = self.check()
        self.assertEqual(report["exit_code"], original["exit_code"])
        self.assertEqual(len(self.find(report, "ANCHOR_GATE_UNCONFIRMED")), 3)
        self.assertEqual(len(self.find(report, "ANCHOR_ORDER_NOT_CHECKED")), 1)
        self.assertTrue(all(a["authority_basis"] == "descriptor label only; unauthenticated"
                            for a in report["anchors"]))

    def test_even_mocked_confirmations_do_not_authorize_unverified_authority(self):
        # An adapter-status assertion, without proof-derived authority or attested time,
        # must never be promoted to a passing two-authority gate.
        with patch("rr.verify.anchors.check", return_value=("confirmed", "mocked evidence")):
            report = self.check()
        self.assertEqual(len(self.find(report, "ANCHOR_GATE_UNCONFIRMED"))+len(self.find(report, "ANCHOR_AUTHORITY_NOT_CHECKED")), 3)
        self.assertEqual(len(self.find(report, "ANCHOR_ORDER_NOT_CHECKED")), 1)
        self.assertFalse(self.find(report, "ANCHOR_GATE_CONFIRMED"))
        self.assertEqual(report["exit_code"], 2)

    def test_signed_timestamp_fields_are_not_external_order_evidence(self):
        from reference_round import envelope
        path = self.path / "close.json"
        value = json.loads(path.read_bytes())
        import base64
        payload = json.loads(base64.b64decode(value["payload"]))
        payload["closed_at"] = "1970-01-01T00:00:00Z"
        path.write_bytes(envelope(payload, "steward"))
        report = self.check()
        self.assertEqual(len(self.find(report, "ANCHOR_ORDER_NOT_CHECKED")), 1)
        self.assertFalse(self.find(report, "ANCHOR_ORDER_CONFIRMED"))


if __name__ == "__main__":
    unittest.main()
