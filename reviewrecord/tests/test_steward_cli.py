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
              "--expected-author-key",self.meta["author_key"],*extra]
        if kind!="reveal":
            args+=["--steward-private-key",str(self.private)]
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


    def prepare_full_close(self):
        self.init()
        for path in sorted((self.ref/"declarations").rglob("*.json")):
            self.assertEqual(self.intake(path),0,self.stderr.getvalue())
            self.stdout=io.StringIO();self.stderr=io.StringIO()
        for path in sorted((self.ref/"commits").rglob("*.json")):
            self.assertEqual(self.intake(path),0,self.stderr.getvalue())
            self.stdout=io.StringIO();self.stderr=io.StringIO()
        for path in sorted((self.ref/"withdrawals").rglob("*.json")):
            self.assertEqual(self.intake(path),0,self.stderr.getvalue())
            self.stdout=io.StringIO();self.stderr=io.StringIO()
        self.assertEqual(self.invoke("close"),0,self.stderr.getvalue())
        self.stdout=io.StringIO();self.stderr=io.StringIO()

    def reveal(self,path):
        return self.invoke("reveal",["--input",str(path)])

    def test_postclose_reveals_generate_valid_proofs_for_three_reviewers(self):
        self.prepare_full_close()
        from rr.verify import rid
        bundle=self.workspace/"bundle"
        close=dsse.decode((bundle/"close.json").read_bytes())
        for assessment in sorted((self.ref/"assessments").rglob("*.json")):
            obj=dsse.decode(assessment.read_bytes())
            self.assertEqual(self.reveal(assessment),0,self.stderr.getvalue())
            self.stdout=io.StringIO();self.stderr=io.StringIO()
            key=obj.value["reviewer_key"]
            proof_path=bundle/"proofs"/rid(key)/(obj.object_hash[7:]+".json")
            stored=bundle/"assessments"/rid(key)/(obj.object_hash[7:]+".json")
            self.assertEqual(stored.read_bytes(),assessment.read_bytes())
            proof=canon.loads(proof_path.read_bytes())
            self.assertEqual(proof["tree_size"],3)
            self.assertTrue(merkle.inclusion(
                canon.hash_bytes(obj.object_hash),
                proof["leaf_index"],proof["tree_size"],
                [canon.hash_bytes(x) for x in proof["hashes"]],
                canon.hash_bytes(close.value["tree_head"])))
        self.assertEqual(len(list((bundle/"assessments").rglob("*.json"))),3)

    def test_withdrawn_reviewers_valid_reveal_is_not_vetoed(self):
        self.prepare_full_close()
        from reference_round import pub
        path,_=self.pick("assessments",pub("reviewer-c"))
        self.assertEqual(self.reveal(path),0,self.stderr.getvalue())

    def test_reveal_before_close_has_no_effect(self):
        self.init()
        path,_=self.pick("assessments")
        before=self.files()
        self.assertEqual(self.reveal(path),2)
        self.assertEqual(self.files(),before)
        self.assertFalse((self.workspace/"bundle"/"assessments").exists())

    def test_uncommitted_postclose_assessment_is_refused(self):
        self.init()
        self.declaration_and_commit()
        self.assertEqual(self.invoke("close"),0)
        committed=self.pick("assessments",None)
        from rr import canon
        original=dsse.decode(committed[0].read_bytes())
        edited=original.value.copy()
        edited["items"]=[dict(x) for x in edited["items"]]
        edited["items"][0]["reasoning"]="Modified after close"
        from reference_round import pub
        role=next(role for role in ("reviewer-a","reviewer-b","reviewer-c")
                  if pub(role)==edited["reviewer_key"])
        source=self.root/"different-assessment.json"
        source.write_bytes(envelope(edited,role))
        before=self.files()
        self.assertEqual(self.reveal(source),2)
        self.assertEqual(self.files(),before)

    def test_replay_and_orphan_proof_are_refused(self):
        self.prepare_full_close()
        assessment,_=self.pick("assessments")
        self.assertEqual(self.reveal(assessment),0,self.stderr.getvalue())
        self.assertEqual(self.reveal(assessment),2)
        from rr.verify import rid
        obj=dsse.decode(assessment.read_bytes())
        proof=self.workspace/"bundle"/"proofs"/rid(obj.value["reviewer_key"])/(obj.object_hash[7:]+".json")
        proof.unlink()
        next_assessment=next(p for p in (self.ref/"assessments").rglob("*.json") if p!=assessment)
        before=self.files()
        self.assertEqual(self.reveal(next_assessment),2)
        self.assertEqual(self.files(),before)


    def test_attested_withdrawal_is_signer_attributed_to_steward(self):
        self.init()
        from reference_round import pub,rid
        reviewer=pub("reviewer-a")
        decl,_=self.pick("declarations",reviewer)
        self.assertEqual(self.intake(decl),0,self.stderr.getvalue())
        self.stdout=io.StringIO();self.stderr=io.StringIO()
        args=["--reviewer-key",reviewer]
        self.assertEqual(self.invoke("attest-withdrawal",args),0,self.stderr.getvalue())
        folder=self.workspace/"bundle"/"withdrawals"/rid(reviewer)
        obj=dsse.decode(next(folder.glob("*.json")).read_bytes())
        self.assertEqual(obj.value["steward_attested"],True)
        self.assertTrue(dsse.verify_signature(obj,self.meta["steward_key"]))
        self.assertFalse(dsse.verify_signature(obj,reviewer))
        self.assertEqual(self.invoke("close"),0,self.stderr.getvalue())
        close=dsse.decode((self.workspace/"bundle"/"close.json").read_bytes())
        self.assertEqual(close.value["withdrawn"][0]["reviewer_key"],reviewer)
        self.assertNotIn("status",close.value)

    def test_steward_cannot_attest_without_prior_declaration(self):
        self.init()
        from reference_round import pub
        before=self.files()
        self.assertEqual(self.invoke("attest-withdrawal",["--reviewer-key",pub("reviewer-b")]),2)
        self.assertEqual(self.files(),before)

    def test_cross_key_commitment_copy_is_rejected_before_any_write(self):
        from reference_round import pub
        self.init()
        for role in ("reviewer-a","reviewer-b"):
            declaration,_=self.pick("declarations",pub(role))
            self.assertEqual(self.intake(declaration),0,self.stderr.getvalue())
        original,_=self.pick("commits",pub("reviewer-a"))
        self.assertEqual(self.intake(original),0,self.stderr.getvalue())
        from_ref=dsse.decode(original.read_bytes())
        copy=from_ref.value.copy()
        copy["reviewer_key"]=pub("reviewer-b")
        forged=self.root/"copied-commit.json"
        forged.write_bytes(envelope(copy,"reviewer-b"))
        before=self.files()
        self.assertEqual(self.intake(forged),2)
        self.assertEqual(self.files(),before)
        self.assertIn("already used",self.stderr.getvalue())

    def test_empty_close_is_signed_but_under_minimum_when_checked(self):
        self.init()
        self.assertEqual(self.invoke("close"),0,self.stderr.getvalue())
        close=dsse.decode((self.workspace/"bundle"/"close.json").read_bytes())
        self.assertEqual(close.value["locked_count"],0)
        self.assertEqual(close.value["tree_size"],0)
        self.assertNotIn("status",close.value)
        self.assertIn("closed_at",close.value)

    def test_interrupted_reveal_write_remains_halted_without_auto_repair(self):
        self.prepare_full_close()
        from rr.verify import rid
        assessment,_=self.pick("assessments")
        record=dsse.decode(assessment.read_bytes())
        bundle=self.workspace/"bundle"
        path=bundle/"assessments"/rid(record.value["reviewer_key"])
        path.mkdir(parents=True,mode=0o700)
        (path/(record.object_hash[7:]+".json")).write_bytes(assessment.read_bytes())
        other=next(p for p in (self.ref/"assessments").rglob("*.json") if p!=assessment)
        before=self.files()
        self.assertEqual(self.reveal(other),2)
        self.assertEqual(self.files(),before)



    def test_intake_crash_orphan_aborts_without_rewriting_evidence(self):
        self.init()
        from rr.verify import rid
        declaration,value=self.pick("declarations")
        signature=dsse.decode(declaration.read_bytes())
        bundle=self.workspace/"bundle"
        folder=bundle/"declarations"/rid(value["reviewer_key"])
        folder.mkdir(parents=True,mode=0o700)
        (folder/(signature.object_hash[7:]+".json")).write_bytes(declaration.read_bytes())
        snapshot=self.files()
        self.assertEqual(self.intake(declaration),2)
        self.assertEqual(self.invoke("close"),2)
        self.assertEqual(self.files(),snapshot)
        self.assertFalse((bundle/"close.json").exists())


if __name__=="__main__":
    unittest.main()
