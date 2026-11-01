# Base64 and non-canonical Ed25519 S tests; Python 3.12+, cryptography [needs Linux runner].
import base64
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from rr import dsse,canon


ED25519_L=2**252+27742317777372353535851937790883648493


class SignatureEncodingTests(unittest.TestCase):
    def test_base64_alphabets_are_deliberate_current_profile(self):
        payload=b"\xfb\xff"
        standard=base64.b64encode(payload).decode("ascii")
        urlsafe=base64.urlsafe_b64encode(payload).decode("ascii")
        self.assertIn("+",standard)
        self.assertIn("/",standard)
        self.assertIn("-",urlsafe)
        self.assertIn("_",urlsafe)
        self.assertEqual(dsse.b64decode(standard),payload)
        self.assertEqual(dsse.b64decode(urlsafe),payload)
        self.assertEqual(dsse.b64decode(standard.rstrip("=")),payload)
        self.assertEqual(dsse.b64decode(urlsafe.rstrip("=")),payload)
        for invalid in ("+_8=","-/8=","+_8","-/8"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    dsse.b64decode(invalid)

    def test_noncanonical_ed25519_s_plus_order_is_rejected(self):
        key=Ed25519PrivateKey.generate()
        public=key.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        label="ed25519:"+base64.urlsafe_b64encode(public).decode().rstrip("=")
        payload=canon.dumps({"type":"commit","round_id":"synthetic",
            "registration_hash":"sha256:"+"a"*64,
            "reviewer_key":label,"commitment":"sha256:"+"b"*64})
        ptype="application/vnd.reviewrecord.commit.v1+json"
        sig=key.sign(dsse.pae(ptype,payload))
        self.assertEqual(len(sig),64)
        assert_s=int.from_bytes(sig[32:],"little")
        self.assertLess(assert_s,ED25519_L)
        forged=sig[:32]+(assert_s+ED25519_L).to_bytes(32,"little")
        def wrap(signature):
            return dsse.decode(canon.dumps({
                "payloadType":ptype,
                "payload":base64.b64encode(payload).decode(),
                "signatures":[{"sig":base64.b64encode(signature).decode()}]}))
        self.assertTrue(dsse.verify_signature(wrap(sig),label))
        self.assertFalse(dsse.verify_signature(wrap(forged),label))

    def test_public_key_encoding_is_single_url_safe_unpadded(self):
        key=Ed25519PrivateKey.generate()
        public=key.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        label="ed25519:"+base64.urlsafe_b64encode(public).decode().rstrip("=")
        self.assertEqual(dsse.public_bytes(label),public)
        with self.assertRaises(ValueError):
            dsse.public_bytes(label+"=")


if __name__=="__main__":
    unittest.main()
