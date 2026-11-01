# All network replies are mocked; synthetic header bytes are not a real block.
import hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('anchor_demo',ROOT/'tools/anchor_demo_evidence.py');d=importlib.util.module_from_spec(s);s.loader.exec_module(d)
class DemoTests(unittest.TestCase):
 def test_header_root_byte_order_and_hash_binding(self):
  root=bytes(range(32));header=bytes(36)+root+bytes(12)
  block_hash=hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
  r=d.header_binding(header.hex(),block_hash,root)
  self.assertTrue(r['header_hash_matches']);self.assertTrue(r['header_merkle_root_matches']);self.assertFalse(r['pow_or_chain_validation_run'])
  self.assertFalse(d.header_binding(header.hex(),block_hash,root[::-1])['header_merkle_root_matches'])
 def test_changed_header_is_rejected_by_hash(self):
  header=bytes(80);changed=bytes(79)+b'\x01';h=hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
  self.assertFalse(d.header_binding(changed.hex(),h,bytes(32))['header_hash_matches'])
 def test_non_header_bytes_rejected(self):
  with self.assertRaises(ValueError):d.header_binding('00','00'*32,bytes(32))
 def test_explorer_failure_is_unavailable_not_match(self):
  with tempfile.TemporaryDirectory() as tmp,patch.object(d,'fetch',side_effect=URLError('mock unavailable')):
   r=d.explorer('https://blockstream.info/api',974172,bytes(32),Path(tmp))
  self.assertEqual(r['status'],'unavailable');self.assertNotIn('header_hash_matches',r)
 def test_wrong_preimage_refused_before_tsa_post(self):
  with tempfile.TemporaryDirectory() as tmp,patch.object(d,'fetch') as post:
   r=d.tsa_request('synthetic','sha256:'+hashlib.sha256(b'expected').hexdigest(),b'changed',Path(tmp),Path(tmp)/'ca',Path(tmp)/'signer')
   post.assert_not_called()
  self.assertEqual(r['evidence_state'],'no token obtained');self.assertIn('error',r)
if __name__=='__main__':unittest.main()
