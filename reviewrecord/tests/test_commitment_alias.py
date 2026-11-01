# Cross-key commitment reuse: synthetic negative verifier test [needs Linux runner].
import json
import tempfile
import unittest
from pathlib import Path

from reference_round import create,manifest,canon,envelope,h,pub,rid
from rr.verify import verify_bundle
from rr import dsse


class CommitmentAliasTests(unittest.TestCase):
    def test_signed_foreign_key_copy_is_reported_not_counted_silently(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            meta=create(root/"bundle")
            bundle=root/"bundle"
            owner_a=next((bundle/"commits"/rid(pub("reviewer-a"))).glob("*.json"))
            owner_b=next((bundle/"commits"/rid(pub("reviewer-b"))).glob("*.json"))
            first=dsse.decode(owner_a.read_bytes()).value["commitment"]
            original=dsse.decode(owner_b.read_bytes())
            copied=original.value.copy()
            copied["commitment"]=first
            new_data=envelope(copied,"reviewer-b")
            new_hash=h(new_data)
            old_hash=original.object_hash
            owner_b.unlink()
            (owner_b.parent/(new_hash[7:]+".json")).write_bytes(new_data)
            previous=meta["registration_hash"]
            for file in sorted((bundle/"log").glob("*.json"),key=lambda p:int(p.stem)):
                record=dsse.decode(file.read_bytes())
                value=record.value.copy()
                if value["ref_hash"]==old_hash:
                    value["ref_hash"]=new_hash
                value["prev_entry_hash"]=previous
                raw=envelope(value,"steward")
                file.write_bytes(raw)
                previous=h(raw)
            manifest(bundle)
            report=verify_bundle(bundle,expected_author_key=meta["author_key"],
                                 expected_steward_key=meta["steward_key"])
            found=[x for x in report["checks"]
                   if x["code"]=="COMMITMENT_REUSED_ACROSS_KEYS"]
            self.assertTrue(found)
            self.assertTrue(all(x["status"]=="fail" for x in found))
            self.assertEqual(report["exit_code"],1)
            self.assertEqual(report["tree_size"],3)


if __name__=="__main__":
    unittest.main()
