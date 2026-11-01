# Strict RFC3161 target-binding regression; Python 3.12+, OpenSSL and cryptography [needs Linux runner].
import hashlib,json,shutil,subprocess,tempfile,unittest
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from rr.anchor_evidence import inspect

@unittest.skipUnless(shutil.which("openssl"),"OpenSSL is required")
class StrictTSABindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.home=Path(cls.tmp.name)
        cls.a=b"synthetic timestamped bytes A\n"
        cls.b=b"different bytes B\n"
        (cls.home/"a.bin").write_bytes(cls.a)
        def cmd(*args):
            done=subprocess.run(["openssl",*args],cwd=cls.home,capture_output=True,text=True,timeout=20)
            if done.returncode:raise AssertionError("OpenSSL fixture: "+done.stderr[:400])
        try:
            cmd("req","-x509","-newkey","rsa:2048","-nodes","-keyout","ca.key","-out","ca.pem",
                "-subj","/CN=Review Record Synthetic CA","-days","10",
                "-addext","basicConstraints=critical,CA:TRUE",
                "-addext","keyUsage=critical,keyCertSign,cRLSign")
            cmd("req","-new","-newkey","rsa:2048","-nodes","-keyout","tsa.key","-out","tsa.csr",
                "-subj","/CN=Review Record Synthetic TSA")
            (cls.home/"ext.cnf").write_text("extendedKeyUsage=critical,timeStamping\n"
                "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n")
            cmd("x509","-req","-in","tsa.csr","-CA","ca.pem","-CAkey","ca.key","-CAcreateserial",
                "-out","tsa.pem","-days","10","-extfile","ext.cnf")
            (cls.home/"serial").write_text("01")
            (cls.home/"tsa.cnf").write_text("[tsa]\ndefault_tsa=tsa1\n[tsa1]\n"
                "dir=.\nserial=./serial\ncrypto_device=builtin\nsigner_cert=./tsa.pem\n"
                "signer_key=./tsa.key\nsigner_digest=sha256\ndefault_policy=1.2.3.4.99\n"
                "digests=sha256\naccuracy=secs:1\nordering=yes\ntsa_name=yes\n"
                "ess_cert_id_chain=no\ness_cert_id_alg=sha256\n")
            cmd("ts","-query","-data","a.bin","-sha256","-cert","-out","req.tsq")
            cmd("ts","-reply","-queryfile","req.tsq","-config","tsa.cnf","-section","tsa1","-out","resp.tsr")
            cmd("ts","-verify","-in","resp.tsr","-queryfile","req.tsq","-CAfile","ca.pem")
        except BaseException:
            cls.tmp.cleanup();raise
        ca=cls.home/"ca.pem";tsa=cls.home/"tsa.pem"
        signer=x509.load_pem_x509_certificate(tsa.read_bytes())
        cls.policy=cls.home/"pin.json"
        cls.policy.write_text(json.dumps({"ca_sha256":hashlib.sha256(ca.read_bytes()).hexdigest(),
                            "signer_sha256":signer.fingerprint(hashes.SHA256()).hex(),
                            "policy_oid":"1.2.3.4.99"}))
        cls.evidence={"anchors/token.tsr":(cls.home/"resp.tsr").read_bytes(),
                      "anchors/request.tsq":(cls.home/"req.tsq").read_bytes()}
        cls.ca=ca
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def evidence_for(self,target,files=None):
        return inspect({"type":"rfc3161","target":"sha256:"+hashlib.sha256(target).hexdigest(),
                    "authority":"UNVERIFIED LABEL","proof":"anchors/token.tsr","request":"anchors/request.tsq"},
                    self.evidence if files is None else files,tsa_ca=self.ca,tsa_policy=self.policy)
    def test_actual_stamped_target_qualifies_in_local_fixture(self):
        result=self.evidence_for(self.a)
        self.assertEqual(result["status"],"confirmed",result)
        self.assertEqual(result["policy_oid"],"1.2.3.4.99")
        self.assertTrue(result["authority"].startswith("tsa-signer-sha256:"))
        self.assertIsNotNone(result["attested_time"])
    def test_valid_token_for_different_target_fails(self):
        result=self.evidence_for(self.b)
        self.assertEqual(result["status"],"invalid",result)
        self.assertIsNone(result["authority"])
        self.assertIsNone(result["attested_time"])
    def test_malformed_token_is_invalid_not_offline(self):
        evidence=dict(self.evidence);evidence["anchors/token.tsr"]=b"not a timestamp response"
        self.assertEqual(self.evidence_for(self.a,files=evidence)["status"],"invalid")
    def test_unpinned_ca_is_unverifiable_not_confirmed(self):
        result=inspect({"type":"rfc3161","target":"sha256:"+hashlib.sha256(self.a).hexdigest(),
                       "proof":"anchors/token.tsr","request":"anchors/request.tsq"},self.evidence)
        self.assertNotEqual(result["status"],"confirmed")
        self.assertIsNone(result["authority"])

if __name__=="__main__":unittest.main()
