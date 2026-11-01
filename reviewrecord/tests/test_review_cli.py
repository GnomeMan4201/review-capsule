# Reviewer-local signing regression tests; Python 3.12+, cryptography==50.0.2 [needs Linux runner].
import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rr import canon, dsse
from rr.review_cli import main
from reference_round import create


PASSWORD = "synthetic test passphrase - never use for a participant"


class ReviewerToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.secret = self.folder / "reviewer.key"
        self.out = io.StringIO()
        self.err = io.StringIO()
        self.metadata=create(self.folder/"round")
        self.registration=self.folder/"round"/"registration.json"
        self.packet=self.folder/"round"/"packet.json"
        self.policy=self.folder/"round"/"policy.json"

    def run_cli(self, args, passwords=None):
        if args[0] in ("sign","commit"):
            args=list(args)+[
                "--registration",str(self.registration),
                "--expected-author-key",self.metadata["author_key"],
                "--packet",str(self.packet),
                "--policy",str(self.policy)]
        with patch("rr.review_cli.getpass.getpass", side_effect=passwords or []):
            with contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.err):
                return main(args)

    def keygen(self):
        self.assertEqual(
            self.run_cli(["keygen", "--private-key", str(self.secret)],
                         [PASSWORD, PASSWORD]), 0
        )
        pub = self.out.getvalue().strip()
        self.out = io.StringIO()
        self.err = io.StringIO()
        return pub

    def draft(self, obj, name="draft.json"):
        path = self.folder / name
        path.write_text(json.dumps(obj), encoding="utf-8")
        return path

    def base(self, public, kind="assessment"):
        return {
            "type": kind,
            "round_id": self.metadata["round_id"],
            "registration_hash": self.metadata["registration_hash"],
            "reviewer_key": public,
        }

    def assessment(self, public):
        return self.base(public) | {
            "locked_at": "2026-11-01T12:00:00Z",
            "items": [{
                "id": "item-1", "judgment": "not_established",
                "reasoning": "Unpublished sensitive synthetic reviewer comment",
                "concerns": [{"cid": "c1", "text": "Synthetic issue"}],
            }],
        }

    def test_key_is_encrypted_and_private(self):
        public = self.keygen()
        self.assertTrue(public.startswith("ed25519:"))
        self.assertTrue(self.secret.read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.secret.stat().st_mode), 0o600)
        self.assertEqual(self.run_cli(["pubkey", "--private-key", str(self.secret)], [PASSWORD]), 0)
        self.assertEqual(self.out.getvalue().strip(), public)
        self.assertNotIn(PASSWORD, self.out.getvalue() + self.err.getvalue())

    def test_local_assessment_and_commit_signature_and_hash(self):
        public = self.keygen()
        src = self.draft(self.assessment(public))
        assessment = self.folder / "assessment-private.json"
        self.assertEqual(self.run_cli(["sign", "--private-key", str(self.secret),
                                       "--input", str(src), "--output", str(assessment)],
                                      [PASSWORD]), 0)
        self.assertEqual(self.out.getvalue(), "")
        self.assertNotIn("Unpublished sensitive", self.err.getvalue())
        self.assertIn("WITHHOLD", self.err.getvalue())
        a = dsse.decode(assessment.read_bytes())
        self.assertTrue(dsse.verify_signature(a, public))
        self.assertEqual(a.value["type"], "assessment")
        self.out = io.StringIO()
        self.err = io.StringIO()
        commit_file = self.folder / "commit-public.json"
        self.assertEqual(self.run_cli(["commit", "--private-key", str(self.secret),
                                       "--assessment", str(assessment), "--output", str(commit_file)],
                                      [PASSWORD]), 0)
        commit = dsse.decode(commit_file.read_bytes())
        self.assertTrue(dsse.verify_signature(commit, public))
        self.assertEqual(commit.value["commitment"], canon.digest(assessment.read_bytes()))
        self.assertNotIn("Unpublished sensitive", commit_file.read_text() + self.err.getvalue())
        self.assertEqual(src.read_text(), json.dumps(self.assessment(public)))

    def test_reject_mismatched_reviewer_identity(self):
        self.keygen()
        draft = self.draft(self.assessment("ed25519:" + "A" * 43))
        target = self.folder / "rejected.json"
        self.assertEqual(self.run_cli(["sign", "--private-key", str(self.secret),
                                       "--input", str(draft), "--output", str(target)],
                                      [PASSWORD]), 2)
        self.assertFalse(target.exists())

    def test_reject_duplicate_fields_without_rewriting(self):
        self.keygen()
        raw = self.folder / "duplicate.json"
        raw.write_text('{"type":"assessment","type":"withdrawal"}', encoding="utf-8")
        target = self.folder / "bad.json"
        self.assertEqual(self.run_cli(["sign", "--private-key", str(self.secret),
                                       "--input", str(raw), "--output", str(target)],
                                      [PASSWORD]), 2)
        self.assertFalse(target.exists())

    def test_no_overwrite_of_existing_commit_file(self):
        public = self.keygen()
        src = self.draft(self.assessment(public))
        target = self.folder / "locked.json"
        target.write_bytes(b"KEEP")
        self.assertEqual(self.run_cli(["sign", "--private-key", str(self.secret),
                                       "--input", str(src), "--output", str(target)],
                                      [PASSWORD]), 2)
        self.assertEqual(target.read_bytes(), b"KEEP")

    def test_reject_plaintext_key_and_wrong_password(self):
        self.secret.write_bytes(b"nonencrypted")
        self.secret.chmod(0o600)
        self.assertEqual(self.run_cli(["pubkey", "--private-key", str(self.secret)],
                                      [PASSWORD]), 2)
        self.secret.unlink()
        self.keygen()
        self.assertEqual(self.run_cli(["pubkey", "--private-key", str(self.secret)],
                                      ["wrong-passphrase"]), 2)

    def test_reviewer_may_not_sign_steward_object_or_attest_withdrawal(self):
        public = self.keygen()
        target = self.folder / "no.json"
        value = self.base(public, "close")
        self.assertEqual(self.run_cli(["sign", "--private-key", str(self.secret),
                                       "--input", str(self.draft(value)),
                                       "--output", str(target)], [PASSWORD]), 2)
        self.assertFalse(target.exists())
        value = self.base(public, "withdrawal") | {"steward_attested": True}
        self.assertEqual(self.run_cli(["sign", "--private-key", str(self.secret),
                                       "--input", str(self.draft(value)),
                                       "--output", str(target)], [PASSWORD]), 2)
        self.assertFalse(target.exists())

    def test_reject_foreign_signed_assessment_for_commit(self):
        public = self.keygen()
        src = self.draft(self.assessment(public))
        signed = self.folder / "signed.json"
        self.assertEqual(self.run_cli(["sign", "--private-key", str(self.secret),
                                       "--input", str(src), "--output", str(signed)],
                                      [PASSWORD]), 0)
        tampered = canon.loads(signed.read_bytes())
        tampered["signatures"][0]["sig"] = "A" * 88
        signed.write_bytes(canon.dumps(tampered))
        target = self.folder / "commit.json"
        self.assertEqual(self.run_cli(["commit", "--private-key", str(self.secret),
                                       "--assessment", str(signed),
                                       "--output", str(target)], [PASSWORD]), 2)
        self.assertFalse(target.exists())

    def test_declaration_disclosures_preserved(self):
        public = self.keygen()
        d = self.base(public, "declaration") | {
            "relationship_to_author": "none",
            "stake_in_result": "none",
            "prior_exposure": "none",
            "identity_disclosure": "pseudonym",
            "credit_consent": False
        }
        target = self.folder / "declaration.json"
        self.assertEqual(self.run_cli(["sign", "--private-key", str(self.secret),
                                       "--input", str(self.draft(d)),
                                       "--output", str(target)], [PASSWORD]), 0)
        record = dsse.decode(target.read_bytes())
        self.assertTrue(dsse.verify_signature(record, public))
        self.assertEqual(record.value, d)


    def test_reject_packet_mutation_before_assessment_signing(self):
        public=self.keygen()
        original=canon.loads(self.packet.read_bytes())
        original[0]["candidate"]="Different conclusion after registration."
        self.packet.write_bytes(canon.dumps(original))
        src=self.draft(self.assessment(public))
        dest=self.folder/"wrong-packet.json"
        result=self.run_cli(["sign","--private-key",str(self.secret),
                             "--input",str(src),"--output",str(dest)],[PASSWORD])
        self.assertEqual(result,2)
        self.assertFalse(dest.exists())
        self.assertIn("Packet or policy digest",self.err.getvalue())

    def test_reject_wrong_round_even_with_signed_registration(self):
        public=self.keygen()
        value=self.assessment(public)
        value["round_id"]="a-different-round"
        dest=self.folder/"wrong-round.json"
        result=self.run_cli(["sign","--private-key",str(self.secret),
                             "--input",str(self.draft(value)),"--output",str(dest)],[PASSWORD])
        self.assertEqual(result,2)
        self.assertFalse(dest.exists())

    def test_reject_mismatched_policy_even_with_valid_registration(self):
        public=self.keygen()
        policy=canon.loads(self.policy.read_bytes())
        policy["judgment_options"]=["established"]
        self.policy.write_bytes(canon.dumps(policy))
        dest=self.folder/"wrong-policy.json"
        result=self.run_cli(["sign","--private-key",str(self.secret),
                             "--input",str(self.draft(self.assessment(public))),
                             "--output",str(dest)],[PASSWORD])
        self.assertEqual(result,2)
        self.assertFalse(dest.exists())

    def test_reject_missing_or_altered_assessment_item(self):
        public=self.keygen()
        value=self.assessment(public)
        value["items"][0]["id"]="not-in-packet"
        dest=self.folder/"wrong-item.json"
        result=self.run_cli(["sign","--private-key",str(self.secret),
                             "--input",str(self.draft(value)),"--output",str(dest)],[PASSWORD])
        self.assertEqual(result,2)
        self.assertFalse(dest.exists())

    def test_reject_foreign_expected_author_key(self):
        from rr.review_context import validate_registration,ContextError
        from reference_round import pub
        with self.assertRaises(ContextError):
            validate_registration(self.registration,pub("reviewer-b"))

    def test_commit_refuses_when_packet_has_changed_since_signing(self):
        public=self.keygen()
        assessment=self.folder/"signed-assessment.json"
        result=self.run_cli(["sign","--private-key",str(self.secret),
                             "--input",str(self.draft(self.assessment(public))),
                             "--output",str(assessment)],[PASSWORD])
        self.assertEqual(result,0)
        packet=canon.loads(self.packet.read_bytes())
        packet[0]["evidence"].append("New text was added.")
        self.packet.write_bytes(canon.dumps(packet))
        self.out=io.StringIO()
        self.err=io.StringIO()
        commit=self.folder/"should-not-exist.json"
        result=self.run_cli(["commit","--private-key",str(self.secret),
                             "--assessment",str(assessment),"--output",str(commit)],[PASSWORD])
        self.assertEqual(result,2)
        self.assertFalse(commit.exists())

    def test_reject_untrusted_registration_anchor_hash(self):
        from rr.review_context import validate_registration,ContextError
        with self.assertRaises(ContextError):
            validate_registration(self.registration,self.metadata["author_key"],
                                  "sha256:"+"0"*64)



if __name__ == "__main__":
    unittest.main()
