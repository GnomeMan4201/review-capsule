# Protocol kill tests before implementation; Python 3.12+, fixture dependencies [needs Linux runner].
import base64,json,sys,tempfile,unittest
from pathlib import Path
from reference_round import create,manifest,canon
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))

class KillTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)/'bundle';self.meta=create(self.folder)
    def verify(self,registries=None):
        try:from rr.verify import verify_bundle
        except ImportError:self.fail('RED PHASE: rr.verify does not exist; this kill test predates implementation.')
        return verify_bundle(self.folder,expected_author_key=self.meta['author_key'],expected_steward_key=self.meta['steward_key'],registries=registries or [])
    def codes(self,report):return {x['code'] for x in report['checks']}
    def test_01_pre_signing_exchange_is_not_a_factual_verdict(self):
        # Exchange is deliberately off-platform. No signed object can detect it.
        report=self.verify()
        self.assertTrue(report['declarations'])
        for d in report['declarations']:self.assertEqual(d['basis'],'declared by participant')
        for check in report['checks']:
            self.assertNotRegex(check.get('detail','').lower(),r'\b(independent|certified|trusted|validated research)\b')
        self.assertNotIn('no_prior_exposure_verified',report)
    def test_02_substituted_assessment_does_not_pass(self):
        p=next((self.folder/'assessments').rglob('*.json'));e=json.loads(p.read_bytes())
        value=json.loads(base64.b64decode(e['payload']));value['items'][0]['reasoning']='Substituted synthetic content.'
        e['payload']=base64.b64encode(canon(value)).decode();p.write_bytes(canon(e))
        report=self.verify();self.assertIn('HASH_MISMATCH',self.codes(report));self.assertEqual(report['exit_code'],1)
    def test_03_missing_reveal_stays_listed(self):
        next((self.folder/'assessments').rglob('*.json')).unlink();manifest(self.folder)
        report=self.verify();self.assertIn('REVEAL_MISSING',self.codes(report));self.assertEqual(report['exit_code'],1)
        self.assertTrue(any(not x['revealed'] for x in report['reviewers']))
    def test_04_removing_required_anchor_does_not_pass(self):
        (self.folder/'anchors/registration-tsa.json').unlink()
        report=self.verify();self.assertIn('ANCHOR_MISSING',self.codes(report));self.assertEqual(report['exit_code'],1)
    def test_05_git_clock_has_no_weight(self):
        p=self.folder/'anchors/git-publication.json';p.write_bytes(canon(dict(type='git',authority='GitHub',target=self.meta['registration_hash'],author_date='1970-01-01T00:00:00Z',committer_date='1970-01-01T00:00:00Z')))
        report=self.verify();self.assertIn('GIT_PUBLICATION_TIME_IGNORED',self.codes(report))
        self.assertFalse(any(x.get('type')=='git' and x.get('status')=='confirmed' for x in report['anchors']))
    def test_06_registry_detects_omitted_prior_round(self):
        import shutil
        shutil.rmtree(self.folder);self.meta=create(self.folder,prior_rounds=[])
        registry=dict(source='https://example.invalid/rounds.json',work_id='synthetic-work',prior_rounds=['synthetic-prior-round'])
        report=self.verify([registry]);self.assertIn('PRIOR_ROUND_UNLISTED',self.codes(report));self.assertEqual(report['exit_code'],1)

if __name__=='__main__':unittest.main()
