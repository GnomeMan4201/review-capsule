# Adversarial tests use public synthetic keys only.
import base64,json,sys,tempfile,unittest,zipfile,subprocess
from pathlib import Path
from reference_round import create,manifest,canon,envelope
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from rr import canon as canonical,dsse,merkle,anchors
from rr.verify import verify_bundle
from rr.report import TOOL_TEXT
ROOT=Path(__file__).resolve().parents[1]
class PrimitiveTests(unittest.TestCase):
    def test_frozen_vectors(self):
        v=json.loads((ROOT/'vectors/primitive-v0.2.2.json').read_bytes())
        for case in v['canonical']:
            with self.subTest(case=case['id']):
                raw=bytes.fromhex(case['input_hex'])
                if case['accepted']:self.assertEqual(canonical.dumps(canonical.loads(raw)).hex(),case['canon_hex'])
                else:
                    with self.assertRaises(canonical.CanonError):canonical.loads(raw)
        for case in v['pae']:self.assertEqual(dsse.pae(case['payload_type'],bytes.fromhex(case['payload_hex'])).hex(),case['pae_hex'])
        for case in v['merkle']:
            leaves=[bytes.fromhex(x) for x in case['leaves_hex']];root=bytes.fromhex(case['root_hex']);self.assertEqual(merkle.root(leaves),root)
            for proof in case['proofs']:
                i=proof['leaf_index'];path=[bytes.fromhex(x.removeprefix('sha256:')) for x in proof['hashes']]
                self.assertTrue(merkle.inclusion(leaves[i],i,len(leaves),path,root))
                self.assertFalse(merkle.inclusion(bytes(32),i,len(leaves),path,root))
    def test_templates_have_no_forbidden_verdict(self):
        for text in TOOL_TEXT.values():self.assertNotRegex(text.lower(),r'\b(independent|certified|trusted|validated research)\b')
class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.folder=Path(self.tmp.name)/'bundle';self.meta=create(self.folder)
    def run_verify(self,**kw):
        return verify_bundle(self.folder,expected_author_key=self.meta['author_key'],expected_steward_key=self.meta['steward_key'],**kw)
    def change(self,pattern,fn,role=None):
        p=next(self.folder.glob(pattern));e=json.loads(p.read_bytes());v=json.loads(base64.b64decode(e['payload']));fn(v)
        if role:p.write_bytes(envelope(v,role))
        else:e['payload']=base64.b64encode(canon(v)).decode();p.write_bytes(canon(e))
        return p
    def expect(self,code,**kw):
        result=self.run_verify(**kw);self.assertEqual(result['exit_code'],1);self.assertTrue(any(x['code']==code and x['status'] in ('fail','missing') for x in result['checks']),code)
    def test_baseline_is_unresolved_not_success(self):
        r=self.run_verify();self.assertEqual(r['exit_code'],2);self.assertEqual(r['counts']['fail'],0);self.assertEqual(r['counts']['missing'],0)
        self.assertEqual(r['round_status'],'complete');self.assertEqual(r['verified_reveals'],3)
        self.assertEqual([a['status'] for a in r['anchors']].count('pending'),3)
        self.assertEqual([a['status'] for a in r['anchors']].count('unverifiable_offline'),3)
    def test_duplicate_commit_retained_without_extra_lock(self):
        import shutil
        shutil.rmtree(self.folder);self.meta=create(self.folder,duplicate=True)
        r=self.run_verify();self.assertEqual(r['tree_size'],4);self.assertEqual(r['locked_count'],3)
        self.expect('DUPLICATE_COMMIT')
        self.assertTrue(any(c['code']=='TREE_HEAD_MISMATCH' and c['status']=='pass' for c in r['checks']))
    def test_cli_writes_report_and_returns_two(self):
        p=Path(self.tmp.name)/'report.json'
        import os
        env=os.environ|{'PYTHONPATH':str(ROOT/'src')}
        run=subprocess.run([sys.executable,'-m','rr.cli',str(self.folder),'--json',str(p)],env=env,capture_output=True,text=True)
        self.assertEqual(run.returncode,2,run.stderr);self.assertEqual(json.loads(p.read_bytes())['exit_code'],2)
        self.assertIn('Integrity checks:',run.stderr)
    def test_example_report_matches(self):
        self.assertEqual(self.run_verify(),json.loads((ROOT/'examples/expected-report.json').read_bytes()))
        archive=Path(self.tmp.name)/'example.zip'
        archive.write_bytes(base64.b64decode((ROOT/'examples/synthetic-round.zip.b64').read_bytes()))
        self.assertEqual(verify_bundle(archive,expected_author_key=self.meta['author_key'],expected_steward_key=self.meta['steward_key']),self.run_verify())
    def test_optimized_runtime_is_rejected(self):
        import os
        env=os.environ|{'PYTHONPATH':str(ROOT/'src')}
        run=subprocess.run([sys.executable,'-O','-m','rr.cli',str(self.folder)],env=env,capture_output=True,text=True)
        self.assertEqual(run.returncode,1);self.assertIn('RUNTIME_UNSUPPORTED',run.stdout)
    def test_wrong_key(self):
        self.change('close.json',lambda v:None,'author');self.expect('SIGNATURE_INVALID')
    def test_tampered_payload(self):
        self.change('close.json',lambda v:v.update(locked_count=99));self.expect('SIGNATURE_INVALID')
    def test_payload_type(self):
        p=self.folder/'close.json';e=json.loads(p.read_bytes());e['payloadType']='application/vnd.reviewrecord.commit.v1+json';p.write_bytes(canon(e));self.expect('ENVELOPE_MALFORMED')
    def test_extra_signature(self):
        p=self.folder/'close.json';e=json.loads(p.read_bytes());e['signatures']*=2;p.write_bytes(canon(e));self.expect('ENVELOPE_MALFORMED')
    def test_unknown_envelope_field(self):
        p=self.folder/'close.json';e=json.loads(p.read_bytes());e['extra']=1;p.write_bytes(canon(e));self.expect('ENVELOPE_MALFORMED')
    def test_noncanonical_file(self):
        p=self.folder/'close.json';p.write_bytes(p.read_bytes()+b'\n');self.expect('ENVELOPE_NONCANONICAL')
    def test_keyid_has_no_authority(self):
        p=self.folder/'close.json';e=json.loads(p.read_bytes());e['signatures'][0]['keyid']='unrelated hint';p.write_bytes(canon(e));manifest(self.folder)
        r=self.run_verify();self.assertTrue(any(c['code']=='SIGNATURE_INVALID' and c['subject']=='close.json' and c['status']=='pass' for c in r['checks']))
    def test_skipped_seq(self):
        self.change('log/2.json',lambda v:v.update(seq=20),'steward');self.expect('LOG_CHAIN_BROKEN')
    def test_reordered_log(self):
        a=self.folder/'log/1.json';b=self.folder/'log/2.json';aa=a.read_bytes();a.write_bytes(b.read_bytes());b.write_bytes(aa);self.expect('LOG_CHAIN_BROKEN')
    def test_wrong_prev(self):
        self.change('log/2.json',lambda v:v.update(prev_entry_hash='sha256:'+'0'*64),'steward');self.expect('LOG_CHAIN_BROKEN')
    def test_foreign_registration(self):
        self.change('assessments/*/*.json',lambda v:v.update(registration_hash='sha256:'+'0'*64),'reviewer-a');self.expect('REGISTRATION_BINDING_MISMATCH')
    def test_altered_limits(self):
        (self.folder/'limits.txt').write_text('altered\n');self.expect('LIMITS_MISSING_OR_ALTERED')
    def test_empty_disposition(self):
        self.change('dispositions/1.json',lambda v:v.update(reason=''),'author');self.expect('DISPOSITION_NO_REASON')
    def test_float_in_payload(self):
        p=self.folder/'close.json';e=json.loads(p.read_bytes());v=json.loads(base64.b64decode(e['payload']));v['locked_count']=3.0;e['payload']=base64.b64encode(json.dumps(v).encode()).decode();p.write_bytes(canon(e));self.expect('CANON_INVALID')
    def test_wrong_rid(self):
        p=next((self.folder/'assessments').rglob('*.json'));q=p.parent.parent/'r-0000000000000000'/p.name;q.parent.mkdir();p.rename(q);self.expect('RID_MISMATCH')
    def test_wrong_hash_path(self):
        p=next((self.folder/'assessments').rglob('*.json'));p.rename(p.with_name('0'*64+'.json'));self.expect('PATH_HASH_MISMATCH')
    def test_bad_inclusion(self):
        p=next((self.folder/'proofs').rglob('*.json'));v=json.loads(p.read_bytes());v['leaf_index']=99;p.write_bytes(canon(v));self.expect('INCLUSION_PROOF_INVALID')
    def test_tree_size(self):
        self.change('close.json',lambda v:v.update(tree_size=2),'steward');self.expect('TREE_HEAD_MISMATCH')
    def test_withdrawn_missing_reveal(self):
        from reference_round import pub,rid
        next((self.folder/'assessments'/rid(pub('reviewer-a'))).glob('*.json')).unlink();manifest(self.folder)
        r=self.run_verify();self.assertEqual(r['locked_count'],3);self.assertEqual(r['verified_reveals'],2)
        self.assertTrue(any(x['code']=='WITHDRAWN' for x in r['checks']));self.expect('REVEAL_MISSING')
    def test_unmatched_registry_not_checked(self):
        r=self.run_verify(registries=[dict(source='local snapshot',work_id='other',prior_rounds=[])]);self.assertTrue(any(x['code']=='REGISTRY_NOT_CHECKED' for x in r['checks']))
    def test_malformed_ots(self):
        (self.folder/'anchors/registration.ots').write_bytes(b'invalid');self.expect('ANCHOR_INVALID')
    def test_tsa_placeholder_never_confirmed(self):
        self.expect('ANCHOR_INVALID',tsa_ca=ROOT/'evidence/freetsa-ca.pem')
    def test_malformed_shapes_do_not_crash(self):
        for name in ('manifest.json','packet.json','policy.json','registration.json','close.json'):
            p=self.folder/name;old=p.read_bytes()
            for value in (None,[],{},1,'string',True):
                with self.subTest(name=name,value=value):
                    p.write_bytes(canon(value));self.assertEqual(self.run_verify()['exit_code'],1)
            p.write_bytes(old)
    def test_zip_traversal_rejected(self):
        p=Path(self.tmp.name)/'bad.zip'
        with zipfile.ZipFile(p,'w') as z:z.writestr('../outside','x')
        r=verify_bundle(p);self.assertEqual(r['exit_code'],1);self.assertTrue(any(x['code']=='BUNDLE_PATH_INVALID' for x in r['checks']))
if __name__=='__main__':unittest.main()
