# Author candidate signing tests; Python 3.12+, cryptography==50.0.2 [needs Linux runner].
import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from reference_round import create,key,pub
from rr import canon,dsse
from rr.author_cli import register,disposition,main

PASSWORD="SYNTHETIC AUTHOR PASSPHRASE NEVER REUSE"


class AuthorToolTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)
        self.bundle=self.root/"reference"
        self.meta=create(self.bundle)
        self.secret=self.root/"author-private.pem"
        self.secret.write_bytes(key("author").private_bytes(
            serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(PASSWORD.encode())))
        self.secret.chmod(0o600)
        self.secure=self.root/"private";self.secure.mkdir(mode=0o700)
        self.withheld=self.secure/"withheld.json"
        self.withheld.write_bytes((self.bundle/"withheld.json").read_bytes())
        self.withheld.chmod(0o600)
        self.prior=self.root/"prior.json"
        self.prior.write_bytes(canon.dumps([]))
        self.generated=self.root/"new-registration.json"

    def do_register(self,**overrides):
        kwargs={
            "private_key":self.secret,"steward_key":pub("steward"),
            "packet_path":self.bundle/"packet.json",
            "policy_path":self.bundle/"policy.json",
            "withheld_path":self.withheld,"prior_rounds_path":self.prior,
            "round_id":"new-synthetic-author-round","work_id":"synthetic-work",
            "reviewers_target":3,"deadline":"2026-12-01T12:00:00Z",
            "operator_is_author":False,"output":self.generated
        }
        kwargs.update(overrides)
        with patch("rr.review_cli.getpass.getpass",return_value=PASSWORD):
            return register(**kwargs)

    def test_registration_signed_and_empty_prior_list_is_explicit(self):
        result=self.do_register()
        record=dsse.decode(self.generated.read_bytes())
        self.assertEqual(result,record.object_hash)
        self.assertTrue(dsse.verify_signature(record,pub("author")))
        self.assertEqual(record.value["prior_rounds"],[])
        self.assertEqual(record.value["withheld_commitment"],
                         canon.hash_value(canon.loads(self.withheld.read_bytes())))
        self.assertNotIn("synthetic results",self.generated.read_text())

    def test_reject_invalid_steward_key_without_output(self):
        with self.assertRaises(ValueError):
            self.do_register(steward_key=pub("author"))
        self.assertFalse(self.generated.exists())

    def test_reject_missing_prior_list_or_invalid_result_ids(self):
        self.prior.unlink()
        with self.assertRaises(ValueError):
            self.do_register()
        self.assertFalse(self.generated.exists())
        self.prior.write_bytes(canon.dumps([]))
        secret=canon.loads(self.withheld.read_bytes())
        secret["results"]={"another-item":"established"}
        self.withheld.write_bytes(canon.dumps(secret))
        with self.assertRaises(ValueError):
            self.do_register()
        self.assertFalse(self.generated.exists())

    def test_no_overwrite_of_registered_output(self):
        self.generated.write_bytes(b"EXISTING")
        with self.assertRaises(FileExistsError):
            self.do_register()
        self.assertEqual(self.generated.read_bytes(),b"EXISTING")

    def test_disposition_matches_signed_assessment_and_inclusion_proof(self):
        from rr.verify import rid
        assessment=next((self.bundle/"assessments").rglob("*.json"))
        record=dsse.decode(assessment.read_bytes())
        proof=self.bundle/"proofs"/rid(record.value["reviewer_key"])/(record.object_hash[7:]+".json")
        draft=self.root/"disposition-draft.json"
        draft.write_bytes(canon.dumps({
            "concern_ref":{
                "assessment_commitment":record.object_hash,
                "item_id":"item-1","cid":"c1"},
            "status":"under_examination","reason":"Synthetic assessment retained"
        }))
        target=self.root/"disposition.json"
        with patch("rr.review_cli.getpass.getpass",return_value=PASSWORD):
            digest=disposition(private_key=self.secret,
                registration_path=self.bundle/"registration.json",
                close_path=self.bundle/"close.json",
                assessment_path=assessment,proof_path=proof,draft_path=draft,
                output=target)
        signed=dsse.decode(target.read_bytes())
        self.assertEqual(digest,signed.object_hash)
        self.assertTrue(dsse.verify_signature(signed,pub("author")))
        self.assertEqual(signed.value["concern_ref"]["cid"],"c1")

    def test_forged_inclusion_proof_prevents_disposition(self):
        from rr.verify import rid
        assessment=next((self.bundle/"assessments").rglob("*.json"))
        record=dsse.decode(assessment.read_bytes())
        original=self.bundle/"proofs"/rid(record.value["reviewer_key"])/(record.object_hash[7:]+".json")
        proof=canon.loads(original.read_bytes())
        proof["leaf_index"]=99
        bad=self.root/"bad-proof.json";bad.write_bytes(canon.dumps(proof))
        draft=self.root/"draft.json"
        draft.write_bytes(canon.dumps({
            "concern_ref":{"assessment_commitment":record.object_hash,"item_id":"item-1","cid":"c1"},
            "status":"declined","reason":"Synthetic refusal"
        }))
        target=self.root/"not-signed.json"
        with patch("rr.review_cli.getpass.getpass",return_value=PASSWORD):
            with self.assertRaises(ValueError):
                disposition(private_key=self.secret,registration_path=self.bundle/"registration.json",
                    close_path=self.bundle/"close.json",assessment_path=assessment,
                    proof_path=bad,draft_path=draft,output=target)
        self.assertFalse(target.exists())


if __name__=="__main__":
    unittest.main()
