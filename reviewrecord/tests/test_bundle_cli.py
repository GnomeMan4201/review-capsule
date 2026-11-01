# Actor-tool bundle and verifier agreement; Python 3.12+, project dependencies [needs Linux runner].
import contextlib
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from reference_round import create,key,canon
from rr import dsse
from rr.steward_cli import initialize,intake,close,reveal
from rr.bundle_cli import assemble
from rr.verify import verify_bundle


PASS="SYNTHTHETIC ONLY PASSWORD FOR BUNDLE TEST"


class BundleConstructionTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)
        self.ref=self.root/"reference"
        self.meta=create(self.ref)
        self.private=self.root/"private"
        self.private.mkdir(mode=0o700)
        self.steward_key=self.private/"steward.pem"
        self.steward_key.write_bytes(key("steward").private_bytes(
            serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(PASS.encode())))
        self.steward_key.chmod(0o600)
        self.workspace=self.root/"workspace"
        self.out=self.root/"assembled"

    def build_steward_round(self):
        with patch("rr.review_cli.getpass.getpass",return_value=PASS):
            initialize(self.workspace,self.ref/"registration.json",
                       self.ref/"packet.json",self.ref/"policy.json",
                       self.meta["author_key"],self.steward_key)
            for kind in ("declarations","commits","withdrawals"):
                for path in sorted((self.ref/kind).rglob("*.json")):
                    intake(self.workspace,path,self.meta["author_key"],self.steward_key)
            close(self.workspace,self.meta["author_key"],self.steward_key)
        for source in sorted((self.ref/"assessments").rglob("*.json")):
            reveal(self.workspace,source,self.meta["author_key"])

    def assemble(self,out,**kw):
        return assemble(workspace=self.workspace,
            expected_author_key=self.meta["author_key"],
            withheld_path=self.ref/"withheld.json",
            disposition_dir=self.ref/"dispositions",
            output=out,**kw)

    def test_tool_built_synthetic_bundle_is_cryptographically_consistent(self):
        self.build_steward_round()
        hash_value=self.assemble(self.out,allow_incomplete=True)
        report=verify_bundle(self.out,
                             expected_author_key=self.meta["author_key"],
                             expected_steward_key=self.meta["steward_key"])
        self.assertEqual(report["exit_code"],1)
        self.assertEqual(report["round_status"],"complete")
        self.assertEqual(report["locked_count"],3)
        self.assertEqual(report["verified_reveals"],3)
        self.assertEqual(hash_value,canon.loads((self.out/"manifest.json").read_bytes())["record_hash"])
        non_anchor=[x for x in report["checks"] if x["status"] in ("fail","missing") and
                    not x["code"].startswith("ANCHOR_")]
        self.assertEqual(non_anchor,[],non_anchor)

    def test_pending_synthetic_anchor_proofs_yield_exit_two_not_zero(self):
        from opentimestamps.core.timestamp import DetachedTimestampFile,Timestamp
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.notary import PendingAttestation
        from opentimestamps.core.serialize import BytesSerializationContext
        self.build_steward_round()
        h=self.assemble(self.out,allow_incomplete=True)
        reg=self.meta["registration_hash"]
        close_hash=dsse.decode((self.out/"close.json").read_bytes()).object_hash
        proofs=self.root/"pending-anchors"
        proofs.mkdir(mode=0o700)
        for name,target in (("registration",reg),("close",close_hash),("record",h)):
            timestamp=Timestamp(bytes.fromhex(target[7:]))
            timestamp.attestations.add(PendingAttestation("https://example.invalid/calendar"))
            detached=DetachedTimestampFile(OpSHA256(),timestamp)
            ctx=BytesSerializationContext()
            detached.serialize(ctx)
            (proofs/(name+".ots")).write_bytes(ctx.getbytes())
            (proofs/(name+"-ots.json")).write_bytes(canon.dumps({
                "type":"ots","authority":"bitcoin","target":target,
                "proof":"anchors/"+name+".ots","evidence_format":"ots-detached",
                "validation_backend":"Bitcoin Core",
                "confirmation_policy":{"min_confirmations":6}
            }))
            (proofs/(name+".tsr")).write_bytes(b"SYNTHETIC-UNVERIFIED-TOKEN")
            (proofs/(name+"-tsa.json")).write_bytes(canon.dumps({
                "type":"rfc3161","authority":"UNVERIFIED-CANDIDATE","target":target,
                "proof":"anchors/"+name+".tsr","evidence_format":"rfc3161-response",
                "validation_backend":"OpenSSL","confirmation_policy":{"ca_required":True}
            }))
        second=self.root/"with-pending"
        again=self.assemble(second,anchor_dir=proofs)
        self.assertEqual(again,h)
        report=verify_bundle(second,expected_author_key=self.meta["author_key"],
                             expected_steward_key=self.meta["steward_key"])
        self.assertEqual(report["exit_code"],2,[x for x in report["checks"]
                        if x["status"] in ("fail","missing")])
        self.assertEqual(report["counts"]["fail"],0)
        self.assertEqual(report["counts"]["missing"],0)
        self.assertEqual(len([x for x in report["checks"]
                              if x["code"]=="ANCHOR_GATE_UNCONFIRMED"]),3)
        self.assertEqual(report["round_status"],"complete")

    def test_bundle_builder_refuses_close_log_tamper(self):
        self.build_steward_round()
        path=self.workspace/"bundle"/"log"/"1.json"
        raw=bytearray(path.read_bytes());raw[5]^=1;path.write_bytes(raw)
        with self.assertRaises(ValueError):
            self.assemble(self.out,allow_incomplete=True)
        self.assertFalse(self.out.exists())

    def test_bundle_builder_refuses_missing_disposition(self):
        self.build_steward_round()
        incomplete=self.root/"missing-dispositions"
        incomplete.mkdir(mode=0o700)
        one=next((self.ref/"dispositions").glob("*.json"))
        (incomplete/"one.json").write_bytes(one.read_bytes())
        with self.assertRaises(ValueError):
            self.assemble(self.out,disposition_dir=incomplete,allow_incomplete=True)
        self.assertFalse(self.out.exists())


if __name__=="__main__":
    unittest.main()
