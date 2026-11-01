# Proof-derived anchor gate synthetic qualification tests; Python 3.12+, project deps [needs Linux runner].
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reference_round import create
from rr.verify import verify_bundle
from rr.anchor_evidence import inspect


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/"bundle"
        self.meta=create(self.root)

    def verify(self,clock_reversed=False):
        reg=self.meta["registration_hash"]
        from rr.dsse import decode
        close_hash=decode((self.root/"close.json").read_bytes()).object_hash
        def simulated(descriptor,files,**kw):
            kind=descriptor["type"]
            target=descriptor["target"]
            time=("2026-11-01T13:00:00Z" if target==reg else
                  "2026-11-01T14:00:00Z" if target==close_hash else
                  "2026-11-01T15:00:00Z")
            if clock_reversed:
                time="2026-11-01T19:00:00Z" if target==reg else "2026-11-01T14:00:00Z"
            return {"status":"confirmed","detail":"SIMULATED ONLY",
                    "authority":"btc:"+kind if kind=="ots" else "tsa:synthetic-pinned-fingerprint",
                    "attested_time":time,"basis":"synthetic test double, not real evidence"}
        with patch("rr.verify.anchor_evidence.inspect",side_effect=simulated):
            return verify_bundle(self.root,expected_author_key=self.meta["author_key"],
                                 expected_steward_key=self.meta["steward_key"])

    def test_only_mocked_qualified_identities_produce_typed_anchor_gate(self):
        report=self.verify()
        checks=report["checks"]
        self.assertEqual(len([c for c in checks if c["code"]=="ANCHOR_AUTHORITY_CONFIRMED"]),3)
        self.assertTrue(any(c["code"]=="ANCHOR_ORDER_ATTESTED" for c in checks))
        self.assertEqual(report["exit_code"],2)
        self.assertNotIn("verified",report.get("round_status",""))

    def test_reverse_proof_reported_time_produces_failure(self):
        report=self.verify(clock_reversed=True)
        self.assertEqual(report["exit_code"],1)
        self.assertTrue(any(c["code"]=="ANCHOR_ORDER_INCONSISTENT" and c["status"]=="fail"
                            for c in report["checks"]))

    def test_tsa_without_out_of_band_policy_cannot_qualify(self):
        desc={"type":"rfc3161","proof":"anchor.tsr","target":"sha256:"+"1"*64,
              "authority":"arbitrary","request":"query.tsq"}
        result=inspect(desc,{"anchor.tsr":b"fake-tsa-response"},tsa_ca=None)
        self.assertNotEqual(result["status"],"confirmed")
        self.assertIsNone(result["authority"])
        self.assertIsNone(result["attested_time"])


if __name__=="__main__":
    unittest.main()
