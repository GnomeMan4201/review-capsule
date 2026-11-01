# All HTTP responses are mocked; this file does not submit or upgrade proofs.
import importlib.util,io,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError,URLError
from opentimestamps.core.timestamp import Timestamp
from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.serialize import BytesSerializationContext
p=Path(__file__).resolve().parents[1]/'tools/ots_calendar_diagnostics.py'
s=importlib.util.spec_from_file_location('diag',p);d=importlib.util.module_from_spec(s);s.loader.exec_module(d)
class Response:
 status=200
 def __init__(self,raw):self.raw=raw
 def read(self,n):return self.raw[:n]
 def geturl(self):return 'https://alice.btc.calendar.opentimestamps.org/timestamp/'+'00'*32
 def __enter__(self):return self
 def __exit__(self,*a):pass
class Tests(unittest.TestCase):
 def test_unlisted_host_refused(self):
  with self.assertRaises(ValueError):d.query('https://example.invalid/timestamp/'+'00'*32,bytes(32))
 def test_404_preserved(self):
  url='https://alice.btc.calendar.opentimestamps.org/timestamp/'+'00'*32
  err=HTTPError(url,404,'Not Found',{},io.BytesIO(b'Not found\n'))
  with patch.object(d._opener,'open',side_effect=err):r=d.query(url,bytes(32))
  self.assertEqual(r['http_status'],404);self.assertEqual(r['response_body_utf8'],'Not found\n')
 def test_transport_error_not_404(self):
  with patch.object(d._opener,'open',side_effect=URLError('network unavailable')):r=d.query('https://a.pool.opentimestamps.org/timestamp/'+'00'*32,bytes(32))
  self.assertIsNone(r['http_status']);self.assertEqual(r['error_type'],'URLError')
 def test_get_and_pending_timestamp(self):
  stamp=Timestamp(bytes(32));stamp.attestations.add(PendingAttestation('https://alice.btc.calendar.opentimestamps.org'))
  ctx=BytesSerializationContext();stamp.serialize(ctx)
  def read(req,timeout):
   self.assertEqual(req.get_method(),'GET');self.assertIsNone(req.data);return Response(ctx.getbytes())
  with patch.object(d._opener,'open',side_effect=read):r=d.query('https://alice.btc.calendar.opentimestamps.org/timestamp/'+'00'*32,bytes(32))
  self.assertEqual(r['response_kind'],'timestamp');self.assertEqual(r['attestations'][0]['type'],'PendingAttestation')
 def test_invalid_timestamp_not_promoted(self):
  with patch.object(d._opener,'open',return_value=Response(b'not a timestamp')):r=d.query('https://a.pool.opentimestamps.org/timestamp/'+'00'*32,bytes(32))
  self.assertEqual(r['response_kind'],'invalid_timestamp')
if __name__=='__main__':unittest.main()
