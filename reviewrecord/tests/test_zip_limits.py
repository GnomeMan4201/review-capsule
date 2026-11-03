# Bounded ZIP ingestion adversarial tests; Python 3.12+, stdlib + project [needs Linux runner].
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from rr.verify import verify_bundle,MAX_ZIP_RATIO,MAX_FILE


class ZipResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.archive=Path(self.temp.name)/"bundle.zip"

    def verify(self):
        return verify_bundle(self.archive)

    def test_compression_bomb_is_rejected_before_read(self):
        with zipfile.ZipFile(self.archive,"w",compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("bomb.bin",b"0"*(MAX_FILE//2))
        report=self.verify()
        self.assertEqual(report["exit_code"],1)
        self.assertTrue(any(c["code"]=="BUNDLE_LIMIT_EXCEEDED" and
                            "compression ratio" in c["detail"] for c in report["checks"]))

    def test_large_stored_entry_is_rejected(self):
        with zipfile.ZipFile(self.archive,"w",compression=zipfile.ZIP_STORED) as z:
            z.writestr("large.bin",b"x"*(MAX_FILE+1))
        report=self.verify()
        self.assertEqual(report["exit_code"],1)
        self.assertTrue(any(c["code"]=="BUNDLE_LIMIT_EXCEEDED" for c in report["checks"]))

    def test_bad_declared_size_cannot_silently_pass(self):
        with zipfile.ZipFile(self.archive,"w",compression=zipfile.ZIP_STORED) as z:
            z.writestr("single.bin",b"not-actually-empty")
        raw=bytearray(self.archive.read_bytes())
        signature=b"PK\x01\x02"
        start=raw.find(signature)
        self.assertGreaterEqual(start,0)
        # Central directory uncompressed size at offset +24.
        raw[start+24:start+28]=(0).to_bytes(4,"little")
        self.archive.write_bytes(raw)
        report=self.verify()
        self.assertEqual(report["exit_code"],1)
        self.assertTrue(any(c["code"] in ("BUNDLE_UNREADABLE","BUNDLE_LIMIT_EXCEEDED")
                            for c in report["checks"]))

    def test_regular_archive_is_still_read(self):
        with zipfile.ZipFile(self.archive,"w",compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("normal.txt",b"An ordinary file.\n")
        report=self.verify()
        self.assertFalse(any(c["code"] in ("BUNDLE_UNREADABLE","BUNDLE_LIMIT_EXCEEDED",
                                           "BUNDLE_PATH_INVALID") for c in report["checks"]))


if __name__=="__main__":
    unittest.main()
