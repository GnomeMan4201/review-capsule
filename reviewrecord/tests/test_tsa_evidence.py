# Retained real synthetic FreeTSA evidence regression; Python 3.12+, native OpenSSL [needs Linux runner].
import base64
import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from rr.anchors import check

ROOT=Path(__file__).resolve().parents[1]
EVIDENCE=ROOT/"evidence"


@unittest.skipUnless(shutil.which("openssl"),"Native openssl required")
class RetainedTSAEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.token=base64.b64decode((EVIDENCE/"freetsa-response.tsr.b64").read_text())
        self.request=base64.b64decode((EVIDENCE/"freetsa-request.tsq.b64").read_text())
        self.target=b"reviewrecord v0.2.1 synthetic TSA feasibility\n"
        self.target_hash="sha256:"+hashlib.sha256(self.target).hexdigest()
        self.desc={
            "type":"rfc3161",
            "target":self.target_hash,
            "proof":"anchors/proof.tsr",
            "authority":"UNAUTHENTICATED LABEL",
            "evidence_format":"rfc3161-response",
            "validation_backend":"OpenSSL",
            "confirmation_policy":{"ca_required":True},
        }
        self.files={"anchors/proof.tsr":self.token}

    def test_original_synthetic_token_and_digest_match(self):
        status,detail=check(self.desc,self.files,tsa_ca=EVIDENCE/"freetsa-ca.pem")
        self.assertEqual(status,"confirmed",detail)

    def test_wrong_digest_fails(self):
        desc=self.desc|{"target":"sha256:"+hashlib.sha256(b"wrong").hexdigest()}
        status,_=check(desc,self.files,tsa_ca=EVIDENCE/"freetsa-ca.pem")
        self.assertEqual(status,"invalid")

    def test_wrong_ca_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            ca=Path(folder)/"ca.pem"
            ca.write_text("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n")
            status,_=check(self.desc,self.files,tsa_ca=ca)
            self.assertEqual(status,"invalid")

    def test_unsigned_declared_time_and_authority_do_not_influence_verification(self):
        desc=self.desc|{"authority":"a-fabricated-authority","attested_time":"1970-01-01T00:00:00Z"}
        status,_=check(desc,self.files,tsa_ca=EVIDENCE/"freetsa-ca.pem")
        self.assertEqual(status,"confirmed")


if __name__=="__main__":
    unittest.main()
