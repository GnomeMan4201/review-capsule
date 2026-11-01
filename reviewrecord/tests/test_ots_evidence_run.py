"""Local collector tests. Calendar calls are mocked; these are not submission evidence."""
import contextlib,importlib.util,io,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ots_evidence_run',ROOT/'tools/ots_evidence_run.py');run=importlib.util.module_from_spec(spec);spec.loader.exec_module(run)

def pending(target):
    from opentimestamps.core.timestamp import Timestamp,DetachedTimestampFile
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.serialize import BytesSerializationContext
    t=Timestamp(bytes.fromhex(target[7:]));t.attestations.add(PendingAttestation('https://alice.btc.calendar.opentimestamps.org'))
    proof=DetachedTimestampFile(OpSHA256(),t);ctx=BytesSerializationContext();proof.serialize(ctx);return ctx.getbytes()

class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)/'evidence'
        executable=patch.object(run.shutil,'which',return_value='/mock/ots');executable.start();self.addCleanup(executable.stop)
    def test_exact_preimages_not_digest_text(self):
        bundle,targets=run.prepare(ROOT,self.root)
        for row in targets['targets']:
            raw=(self.root/row['preimage']).read_bytes()
            self.assertEqual(run.digest(raw),row['target']);self.assertNotEqual(run.digest(row['target'].encode()),row['target'])
            self.assertEqual(len(raw),row['byte_length'])
        self.assertEqual(run.digest((self.root/'targets/registration.preimage').read_bytes()),run.dsse.decode((bundle/'registration.json').read_bytes()).object_hash)
    def test_prepare_refuses_changed_retained_target(self):
        run.prepare(ROOT,self.root);(self.root/'targets/record.preimage').write_bytes(b'changed')
        with self.assertRaises(ValueError):run.prepare(ROOT,self.root)
    def test_wrong_proof_binding_rejected(self):
        _,targets=run.prepare(ROOT,self.root);a,b=targets['targets'][:2]
        with self.assertRaises(ValueError):run.inspect_proof(pending(a['target']),b['target'])
    def test_calendar_failure_cannot_leave_placeholder_passing(self):
        failure=dict(argv=['ots','stamp'],exit_code=1,stdout='',stderr='Mock calendar unavailable')
        with patch.object(run,'command',return_value=failure),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run.collect(ROOT,self.root),1)
        report=json.loads((self.root/'report.json').read_bytes())
        self.assertEqual(report['exit_code'],1)
        self.assertTrue(any(x['code']=='ANCHOR_MISSING' and x['status']=='missing' for x in report['checks']))
    def test_pending_bytes_transported_without_confirmation(self):
        def stamp(argv,timeout=150):
            targets=json.loads((self.root/'targets.json').read_bytes())
            for row in targets['targets']:(self.root/(row['preimage']+'.ots')).write_bytes(pending(row['target']))
            return dict(argv=argv,exit_code=0,stdout='',stderr='mock test-only calendar response')
        with patch.object(run,'command',side_effect=stamp),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run.collect(ROOT,self.root),0)
        report=json.loads((self.root/'report.json').read_bytes())
        self.assertEqual(report['exit_code'],2);self.assertFalse(any(x['status']=='confirmed' for x in report['anchors']))
        self.assertEqual(len(list((self.root/'initial').glob('*.ots'))),3)
        for row in json.loads((self.root/'targets.json').read_bytes())['targets']:
            self.assertEqual((self.root/(row['preimage']+'.ots')).read_bytes(),(self.root/'bundle/anchors'/(row['name']+'.ots')).read_bytes())
    def test_incomplete_upgrade_does_not_skip_other_targets(self):
        _,targets=run.prepare(ROOT,self.root)
        for row in targets['targets']:(self.root/(row['preimage']+'.ots')).write_bytes(pending(row['target']))
        calls=[]
        def incomplete(argv,timeout=150):
            calls.append(argv);return dict(argv=argv,exit_code=1,stdout='',stderr='Mock incomplete calendar proof')
        with patch.object(run,'command',side_effect=incomplete),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):run.collect(ROOT,self.root)
        self.assertEqual(len(calls),3)
        for argv in calls:self.assertEqual(argv[1],'upgrade');self.assertNotIn('-c',argv);self.assertEqual(sum(str(x).endswith('.ots') for x in argv),1)
        self.assertEqual(json.loads((self.root/'report.json').read_bytes())['exit_code'],2)
    def test_unknown_embedded_calendar_refused_before_network(self):
        _,targets=run.prepare(ROOT,self.root)
        for row in targets['targets']:(self.root/(row['preimage']+'.ots')).write_bytes(pending(row['target']))
        with patch.object(run,'UPGRADE_CALENDARS',set()),patch.object(run,'command') as request:
            with self.assertRaises(ValueError):run.collect(ROOT,self.root)
            request.assert_not_called()
    def test_no_rpc_is_chosen_implicitly(self):
        with patch.dict(run.os.environ,{'RR_BITCOIN_RPC':'http://example.invalid','RR_BITCOIN_RPC_OPERATOR':'test-only'},clear=False),patch.object(run,'command',return_value=dict(argv=['mock'],exit_code=1,stdout='',stderr='unavailable')),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            run.collect(ROOT,self.root)
        journals=list((self.root/'runs').glob('*.json'));self.assertFalse(json.loads(journals[0].read_bytes())['rpc']['used'])
if __name__=='__main__':unittest.main()
