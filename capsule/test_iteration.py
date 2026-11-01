"""Synthetic freeze/lock/receipt regression tests; Django, Python 3.12 [needs Linux runner]."""
import copy,json
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied,ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from .models import Study,Round,RoundSecrets,Assignment,Assessment,Event,Feedback
from .forms import StudyForm
from . import services as s

class IterationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.author,cls.steward,cls.a,cls.b,cls.outsider=[get_user_model().objects.create_user(username=n,password='synthetic-fixture-only') for n in ('author','steward','a','b','outsider')]
    def setUp(self):
        self.study=Study.objects.create(title='Synthetic fixture',author=self.author,steward=self.steward)
        self.packet=[{'id':'ordinary','evidence':['A source states X.'],'candidate':'The source states X.'},
                     {'id':'hidden-item','evidence':['A record says Y.'],'candidate':'The record says Y.'}]
        self.r=Round.objects.create(study=self.study,question='Assess these conclusions.',packet=self.packet,
            withheld={'ordinary':'ESTABLISHED','hidden-item':'ESTABLISHED'},deadline=timezone.now()+timedelta(days=2))
        secret=self.r.secrets;secret.calibration={'hidden-item':'ESTABLISHED'};secret.save()
        self.aa=Assignment.objects.create(round=self.r,reviewer=self.a)
        self.ab=Assignment.objects.create(round=self.r,reviewer=self.b)
    def freeze_open(self):
        self.r=s.freeze(self.r.pk,self.author)
        self.r=s.open_round(self.r.pk,self.author,'https://github.com/example/anchors/commit/abc')
    def admit(self,a,user,**flags):
        data=dict(relationship=False,stake=False,prior_exposure=False,ai_assessment=False,note='',credit_consent=False)
        data.update(flags);s.declare(a.pk,user,data)
        return s.admit(a.pk,self.steward,'Apply exact frozen policy.')
    def answer(self,a,user,marker='ordinary reasoning'):
        s.packet(a.pk,user)
        return s.submit(a.pk,user,{'ordinary':{'verdict':'PARTLY','reason':marker},'hidden-item':{'verdict':'ESTABLISHED','reason':'CALIBRATION-REASON-CANARY'}})
    def finish(self):
        self.freeze_open();self.admit(self.aa,self.a);self.admit(self.ab,self.b)
        self.answer(self.aa,self.a);self.answer(self.ab,self.b,'PEER-REASON-CANARY')
        self.r=s.close(self.r.pk,self.steward)
    def test_freeze_requires_external_anchor_then_open(self):
        self.r=s.freeze(self.r.pk,self.author);commitment=self.r.commitment
        self.assertEqual(self.r.state,'frozen')
        with self.assertRaises(ValidationError): s.declare(self.aa.pk,self.a,{})
        with self.assertRaises(PermissionDenied): s.packet(self.aa.pk,self.a)
        with self.assertRaises(PermissionDenied): s.open_round(self.r.pk,self.steward,'https://example.org/anchor')
        for url in ('http://example.org/a','https://review-capsule-demo.onrender.com/a'):
            with self.assertRaises(ValidationError): s.open_round(self.r.pk,self.author,url)
        self.client.force_login(self.author)
        response=self.client.post(reverse('open_round',args=[self.r.pk]),{'url':'https://example.org/anchor'})
        self.assertEqual(response.status_code,400)
        self.r=s.open_round(self.r.pk,self.author,'https://example.org/anchor')
        self.assertEqual(self.r.commitment,commitment);s.verify(self.r)
        self.assertEqual(self.r.state,'open')
    def test_frozen_content_and_roster_mutations_rejected(self):
        self.freeze_open()
        for field,value in [('packet',[]),('deadline',self.r.deadline+timedelta(days=1)),('question','changed'),('contract',{}),('protocol','0.1')]:
            changed=Round.objects.get(pk=self.r.pk);setattr(changed,field,value)
            with self.assertRaises(ValidationError): changed.save()
            with self.assertRaises(ValidationError): Round.objects.filter(pk=self.r.pk).update(**{field:value})
        with self.assertRaises(ValidationError): Assignment.objects.create(round=self.r,reviewer=self.outsider)
        with self.assertRaises(ValidationError): self.aa.delete()
        with self.assertRaises(ValidationError): Assignment.objects.filter(pk=self.aa.pk).update(reviewer=self.outsider)
        secret=RoundSecrets.objects.get(round=self.r);secret.calibration={}
        with self.assertRaises(ValidationError): secret.save()
        with self.assertRaises(ValidationError): RoundSecrets.objects.filter(round=self.r).update(withheld={})
    def test_linked_correction_keeps_old_commitment_and_versions(self):
        self.freeze_open();old=self.r.commitment
        r=s.correction(self.r.pk,self.author,'Corrected task',self.packet,{}, {},self.r.deadline,[self.a,self.b])
        self.assertEqual(r.previous_id,self.r.pk);self.assertEqual(r.version,2);self.assertEqual(r.state,'draft')
        self.r.refresh_from_db();self.assertEqual(self.r.commitment,old);s.verify(self.r)
        self.assertEqual(r.assignment_set.count(),2)
        with self.assertRaises(PermissionDenied): s.correction(self.r.pk,self.steward,'x',self.packet,{}, {},self.r.deadline,[self.a,self.b])
    def test_relationship_stake_exposure_and_assistance_cannot_be_waived(self):
        self.freeze_open();self.assertFalse(self.admit(self.aa,self.a,stake=True).eligible)
        self.assertFalse(self.admit(self.ab,self.b,relationship=True).eligible)
        with self.assertRaises(PermissionDenied): s.packet(self.aa.pk,self.a)
    def test_timestamped_item_receipts_and_lock_are_stable(self):
        self.freeze_open();self.admit(self.aa,self.a);record=self.answer(self.aa,self.a)
        original=copy.deepcopy(record.item_receipts)
        for item in original:
            self.assertEqual(s.digest(item['payload']),item['sha256'])
            self.assertEqual(item['payload']['timestamp'],record.submitted_at.isoformat())
            changed=copy.deepcopy(item['payload']);changed['timestamp']='changed'
            self.assertNotEqual(s.digest(changed),item['sha256'])
        with self.assertRaises(ValidationError): self.answer(self.aa,self.a,'replacement')
        record.answers={}
        with self.assertRaises(ValidationError): record.save()
        with self.assertRaises(ValidationError): Assessment.objects.filter(assignment=self.aa).update(answers={})
        s.amend(self.aa.pk,self.a,'Later qualification')
        record.refresh_from_db();self.assertEqual(record.item_receipts,original)
        self.client.force_login(self.a)
        data=self.client.get(reverse('receipt_json',args=[self.aa.pk])).json()
        self.assertEqual(data['items'],original)
        self.assertEqual(s.digest({k:data[k] for k in ('assignment','round_commitment','answers','nonce','items')}),data['commitment'])
    def test_calibration_never_marked_in_reviewer_packet(self):
        self.freeze_open();self.admit(self.aa,self.a);self.client.force_login(self.a)
        for route in ('review','packet'):
            response=self.client.get(reverse(route,args=[self.aa.pk]))
            self.assertEqual(response.status_code,200)
            self.assertNotIn('calibration',response.content.decode().lower())
        response=self.client.get(reverse('review',args=[self.aa.pk]))
        for label in ('Established','Partly','Not established','Uncertain','The question needs fixing'): self.assertContains(response,label)
    def test_calibration_reports_steward_only_and_peers_after_closure(self):
        self.freeze_open();self.admit(self.aa,self.a);self.admit(self.ab,self.b)
        self.answer(self.aa,self.a);self.answer(self.ab,self.b,'PEER-REASON-CANARY')
        for user in (self.author,self.steward):
            self.client.force_login(user)
            response=self.client.get(reverse('desk',args=[self.study.pk]))
            self.assertNotContains(response,'CALIBRATION-REASON-CANARY')
            self.assertNotContains(response,'PEER-REASON-CANARY')
            self.assertEqual(self.client.get(reverse('export',args=[self.r.pk])).status_code,403)
        with self.assertRaises(PermissionDenied): s.peer_work(self.aa.pk,self.a)
        self.r=s.close(self.r.pk,self.steward)
        data=s.peer_work(self.aa.pk,self.a)
        self.assertIn('PEER-REASON-CANARY',json.dumps(data));self.assertNotIn('CALIBRATION-REASON-CANARY',json.dumps(data))
        self.assertNotIn('hidden-item',s.results(self.aa.pk,self.a)['withheld'])
        self.client.force_login(self.author)
        for name,arg in [('desk',self.study.pk),('export',self.r.pk)]:
            response=self.client.get(reverse(name,args=[arg]));self.assertNotContains(response,'CALIBRATION-REASON-CANARY')
        self.client.force_login(self.steward)
        data=self.client.get(reverse('export',args=[self.r.pk])).json()
        self.assertEqual(data['calibration_report'][0]['expected'],'ESTABLISHED')
        self.assertIn('CALIBRATION-REASON-CANARY',json.dumps(data))
    def test_feedback_and_labels_have_disjoint_exports(self):
        self.finish();s.feedback(self.r.pk,self.outsider,'PUBLIC-LAB-CANARY')
        self.client.force_login(self.author)
        record=self.client.get(reverse('export',args=[self.r.pk])).json()
        feedback=self.client.get(reverse('feedback_export',args=[self.r.pk])).json()
        self.assertNotIn('PUBLIC-LAB-CANARY',json.dumps(record));self.assertNotIn('feedback',record)
        self.assertNotIn('withheld',feedback);self.assertNotIn('assessments',feedback)
        self.assertIn('PUBLIC-LAB-CANARY',json.dumps(feedback))
    def test_append_only_audit_hash_chain(self):
        self.finish();previous=''
        for event in Event.objects.filter(round=self.r).order_by('id'):
            self.assertEqual(event.previous_hash,previous)
            self.assertEqual(event.hash,s.digest({'round':str(self.r.pk),'actor':event.actor_id,'kind':event.kind,
                'detail':event.detail,'timestamp':event.created_at.isoformat(),'previous_hash':previous}))
            previous=event.hash
        event=Event.objects.filter(round=self.r).first()
        with self.assertRaises(ValidationError): event.delete()
        with self.assertRaises(ValidationError): Event.objects.filter(pk=event.pk).update(detail={})
        with self.assertRaises(ValidationError): Event.objects.all().delete()
    def form_data(self):
        return dict(title='Another synthetic study',question='Assess this task',steward='steward',deadline=(timezone.now()+timedelta(days=1)).strftime('%Y-%m-%dT%H:%M'),packet=json.dumps(self.packet),withheld='{}',calibration='{}',
            **{'reviewers-TOTAL_FORMS':'2','reviewers-INITIAL_FORMS':'0','reviewers-MIN_NUM_FORMS':'2','reviewers-MAX_NUM_FORMS':'20','reviewers-0-username':'a','reviewers-1-username':'b'})
    def test_create_form_empty_json_picker_and_add_remove_rows(self):
        self.client.force_login(self.author)
        response=self.client.get(reverse('create'))
        self.assertContains(response,'datetime-local');self.assertContains(response,'Add reviewer row')
        self.assertNotContains(response,'>null</textarea>')
        data=self.form_data();data['add_reviewer']='1'
        response=self.client.post(reverse('create'),data);self.assertContains(response,'reviewers-2-username')
        self.assertEqual(Study.objects.count(),1)
        data=self.form_data();data.update({'reviewers-TOTAL_FORMS':'3','reviewers-2-username':'outsider','reviewers-2-DELETE':'on'})
        response=self.client.post(reverse('create'),data);self.assertEqual(response.status_code,302)
        r=Round.objects.exclude(pk=self.r.pk).get();self.assertEqual(r.assignment_set.count(),2)
        self.assertNotIn('withheld',{f.name for f in Round._meta.fields})
        self.assertEqual(r.secrets.withheld,{})
    def test_invalid_packet_keys_malformed_json_and_past_deadlines(self):
        self.client.force_login(self.author)
        for key in ('expected','answer','label','key','EXPECTED'):
            data=self.form_data();bad=copy.deepcopy(self.packet);bad[0][key]='leak';data['packet']=json.dumps(bad)
            response=self.client.post(reverse('create'),data);self.assertEqual(response.status_code,200)
            self.assertEqual(Study.objects.count(),1)
        data=self.form_data();data['packet']='{malformed'
        self.client.post(reverse('create'),data);self.assertEqual(Study.objects.count(),1)
        data=self.form_data();data['deadline']='2020-01-01T00:00'
        response=self.client.post(reverse('create'),data);self.assertContains(response,'future UTC deadline')
    def test_new_declaration_form_and_credit_consent(self):
        self.freeze_open();self.client.force_login(self.a)
        response=self.client.post(reverse('declaration',args=[self.aa.pk]),dict(relationship='no',stake='no',prior_exposure='no',ai_assessment='no',note='',credit_consent='on'))
        self.assertEqual(response.status_code,302)
        self.aa.refresh_from_db();self.assertTrue(self.aa.declaration['credit_consent'])
        self.assertFalse(self.aa.eligible)
    def test_receipt_verifier_rejects_changed_content_and_timestamp(self):
        import importlib.util
        from pathlib import Path
        spec=importlib.util.spec_from_file_location('verify_receipt',Path(__file__).resolve().parent.parent/'scripts'/'verify_receipt.py')
        verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
        self.freeze_open();self.admit(self.aa,self.a);record=self.answer(self.aa,self.a)
        data=s.receipt_data(record);verifier.verify(data)
        for key in ('reasoning','timestamp','reviewer','round_id'):
            changed=copy.deepcopy(data);changed['items'][0]['payload'][key]='tampered'
            with self.assertRaises(ValueError): verifier.verify(changed)
    def test_related_frozen_round_blocks_peer_and_result_release(self):
        self.finish()
        r=s.correction(self.r.pk,self.author,self.r.question,self.packet,{}, {},self.r.deadline,[self.a,self.b])
        s.freeze(r.pk,self.author)
        with self.assertRaises(PermissionDenied): s.peer_work(self.aa.pk,self.a)
        with self.assertRaises(PermissionDenied): s.results(self.aa.pk,self.a)
    def test_direct_primary_key_overwrite_and_declaration_rewrite_blocked(self):
        self.freeze_open();self.admit(self.aa,self.a);record=self.answer(self.aa,self.a)
        replacement=Assessment(assignment=self.aa,answers={},nonce='changed',commitment='changed')
        with self.assertRaises(ValidationError): replacement.save()
        original=Round.objects.get(pk=self.r.pk)
        replacement=Round(id=original.pk,study=self.study,packet=[],question='changed',deadline=original.deadline)
        with self.assertRaises(ValidationError): replacement.save()
        self.aa.refresh_from_db();self.aa.declaration={}
        with self.assertRaises(ValidationError): self.aa.save()
        with self.assertRaises(ValidationError): Assignment.objects.filter(pk=self.aa.pk).update(declaration={})
