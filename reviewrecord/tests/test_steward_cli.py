# Steward intake boundary regressions; Python 3.12+, cryptography==50.0.2 [needs Linux runner].
import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from reference_round import create,key,envelope
from rr import canon,dsse,merkle
from rr.steward_cli import main


PASSWORD="Synthetic steward passphrase for tests only"


class StewardIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.ref=self.root/"reference"
        self.meta=create(self.ref)
        self.workspace=self.root/"steward"
        self.private=self.root/"steward-key.pem"
        encoded=key("steward").private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(PASSWORD.encode()))
        self.private.write_bytes(encoded)
        self.private.chmod(0o600)
        self.stdout=io.StringIO()
        self.stderr=io.StringIO()

    def invoke(self,kind,extra=()):
        args=[kind,"--workspace",str(self.workspace),
              "--steward-private-key",str(self.private),
              "--expected-author-key",self.meta["author_key"],*extra]
        with patch("rr.review_cli.getpass.getpass",return_value=PASSWORD):
            with contextlib.redirect_stdout(self.stdout),contextlib.redirect_stderr(self.stderr):
                return main(args)

    def init(self):
        result=self.invoke("init",[
            "--registration",str(self.ref/"registration.json"),
            "--packet",str(self.ref/"packet.json"),
            "--policy",str(self.ref/"policy.json")])
        self.assertEqual(result,0,self.stderr.getvalue())
        self.stdout=io.StringIO();self.stderr=io.StringIO()

    def pick(self,folder,reviewer_key=None):
        for p in sorted((self.ref/folder).rglob("*.json")):
            obj=dsse.decode(p.read_bytes()).value
            if reviewer_key is None or obj.get("reviewer_key")==reviewer_key:
                return p,obj
        raise AssertionError("No fixture for "+folder)

    def intake(self,p):
        return self.invoke("intake",["--input",str(p)])

    def declaration_and_commit(self):
        decl,dec=self.pick("declarations")
        self.assertEqual(self.intake(decl),0,self.stderr.getvalue())
        self.stdout=io.StringIO();self.stderr=io.StringIO()
        commit,_=self.pick("commits",dec["reviewer_key"])
        self.assertEqual(self.intake(commit),0,self.stderr.getvalue())
        self.stdout=io.StringIO();self.stderr=io.StringIO()
        return commit

    def files(self):
        return {p.relative_to(self.workspace).as_posix():p.read_bytes()
                for p in self.workspace.rglob("*") if p.is_file() and p.name!="lock"}

    def test_assessment_preclose_rejected_without_persistence(self):
        self.init()
        assessment,_=self.pick("assessments")
        before=self.files()
        self.assertEqual(self.intake(assessment),2)
        self.assertEqual(self.files(),before)
        self.assertFalse((self.workspace/"bundle"/"log").exists())
        self.assertIn("refuses this object type",self.stderr.getvalue())
        self.assertNotIn("synthetic concern",self.stderr.getvalue().lower())

    def test_valid_receipts_and_signed_close_uses_all_commit_leaves(self):
        self.init()
        self.declaration_and_commit()
        self.assertEqual(self.invoke("close"),0,self.stderr.getvalue())
        bundle=self.workspace/"bundle"
        receipt=dsse.decode((bundle/"log"/"2.json").read_bytes())
        close=dsse.decode((bundle/"close.json").read_bytes())
        self.assertTrue(dsse.verify_signature(receipt,self.meta["steward_key"]))
        self.assertTrue(dsse.verify_signature(close,self.meta["steward_key"]))
        self.assertEqual(close.value["tree_size"],1)
        self.assertEqual(close.value["locked_count"],1)
        self.assertNotIn("status",close.value)
        self.assertEqual(close.value["last_entry_hash"],receipt.object_hash)
        self.assertEqual(close.value["tree_head"],
            "sha256:"+merkle.root([canon.hash_bytes(
                self.pick("commits")[1]["commitment"])]).hex())

    def test_intake_after_close_rejected_without_new_log(self):
        self.init()
        self.declaration_and_commit()
        self.assertEqual(self.invoke("close"),0)
        before=self.files()
        other,_=self.pick("declarations",None)
        self.assertEqual(self.intake(other),2)
        self.assertEqual(self.files(),before)

    def test_replayed_commit_is_rejected_without_file_changes(self):
        self.init()
        commit=self.declaration_and_commit()
        before=self.files()
        self.assertEqual(self.intake(commit),2)
        self.assertEqual(self.files(),before)

    def test_invalid_signer_cannot_claim_someone_elses_reviewer_key(self):
        self.init()
        decl,dec=self.pick("declarations")
        payload=dec.copy()
        forged=self.root/"forged.json"
        forged.write_bytes(envelope(payload,"reviewer-b" if
                                    dec["reviewer_key"]!=
                                    self._pub_b() else "reviewer-a"))
        before=self.files()
        self.assertEqual(self.intake(forged),2)
        self.assertEqual(self.files(),before)

    def _pub_b(self):
        from reference_round import pub
        return pub("reviewer-b")

    def test_mutated_existing_log_blocks_append(self):
        self.init()
        self.declaration_and_commit()
        path=self.workspace/"bundle"/"log"/"1.json"
        raw=bytearray(path.read_bytes())
        raw[-5]=ord("A") if raw[-5]!=ord("A") else ord("B")
        path.write_bytes(raw)
        another,_=self.pick("declarations",self._pub_b())
        before=self.files()
        self.assertEqual(self.intake(another),2)
        self.assertEqual(self.files(),before)

    def test_close_cannot_be_reissued(self):
        self.init()
        self.declaration_and_commit()
        self.assertEqual(self.invoke("close"),0)
        original=self.files()
        self.assertEqual(self.invoke("close"),2)
        self.assertEqual(self.files(),original)

    def test_preclose_rejects_unexpected_type_without_content_echo(self):
        self.init()
        fake=self.root/"secret-assessment.json"
        secret="DO-NOT-LOG-THIS-ASSESSMENT-MESSAGE"
        raw=canon.dumps({"type":"assessment","round_id":self.meta["round_id"],
            "reasoning":secret})
        fake.write_bytes(raw)
        before=self.files()
        self.assertEqual(self.intake(fake),2)
        self.assertEqual(self.files(),before)
        self.assertNotIn(secret,self.stdout.getvalue()+self.stderr.getvalue())


if __name__=="__main__":
    unittest.main()
