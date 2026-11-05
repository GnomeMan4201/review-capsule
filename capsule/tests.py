import json,uuid
from datetime import timedelta
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied,ValidationError
from django.test import TestCase,Client
from django.urls import reverse
from django.utils import timezone
from .models import Study,Round,Assignment,Assessment,Feedback,Exposure,Amendment,RoundSecrets
from . import services as s

class BoundaryTests(TestCase):
    def setUp(self):
        self.author,self.steward,self.a,self.b,self.outsider=[get_user_model().objects.create_user(username=name,password='synthetic-test-only-842') for name in ('author','steward','reviewer-a','reviewer-b','outsider')]
        self.study=Study.objects.create(title='Synthetic review fixture',author=self.author,steward=self.steward)
        self.r=Round.objects.create(protocol='0.1',study=self.study,question='Assess evidence support.',packet=[dict(id='item-1',evidence=['A stipulated source says X.'],candidate='The source says X.')],withheld={'answer_canary':'WITHHELD-CANARY-82a7','model_output':'MODEL-CANARY-a139'},deadline=timezone.now()+timedelta(days=1))
        self.aa=Assignment.objects.create(round=self.r,reviewer=self.a);self.ab=Assignment.objects.create(round=self.r,reviewer=self.b)
        self.r=s.freeze(self.r.pk,self.author)
    def admit(self,a,user):
        s.declare(a.pk,user,dict(conflict=False,prior_exposure=False,ai_assessment=False,note='Test fixture declaration'))
        s.admit(a.pk,self.steward,'Test fixture policy applied')
    def answer(self,a,user,reason='PRIVATE-REVIEW-CANARY'):
        s.packet(a.pk,user)
        return s.submit(a.pk,user,{'item-1':dict(verdict='SUPPORTED',reason=reason)})
    def login(self,user):self.client.force_login(user)

    def test_declaration_and_steward_are_required(self):
        with self.assertRaises(PermissionDenied):s.packet(self.aa.pk,self.a)
        s.declare(self.aa.pk,self.a,dict(conflict=False,prior_exposure=False,ai_assessment=False,note=''))
        with self.assertRaises(PermissionDenied):s.admit(self.aa.pk,self.author,'Author cannot admit')
        with self.assertRaises(PermissionDenied):s.packet(self.aa.pk,self.a)
        s.admit(self.aa.pk,self.steward,'Independent policy decision')
        self.assertEqual(s.packet(self.aa.pk,self.a)['items'],self.r.packet)

    def test_conflicts_and_prior_exposure_are_not_silently_waived(self):
        s.declare(self.aa.pk,self.a,dict(conflict=False,prior_exposure=True,ai_assessment=False,note='Saw results'))
        a=s.admit(self.aa.pk,self.steward,'Apply policy without discretionary waiver')
        self.assertFalse(a.eligible)
        with self.assertRaises(PermissionDenied):s.packet(a.pk,self.a)
        with self.assertRaises(ValidationError):s.declare(a.pk,self.a,dict(conflict=False,prior_exposure=False,ai_assessment=False,note='Try resetting'))

    def test_packet_has_no_withheld_or_identity_fields(self):
        self.admit(self.aa,self.a);self.login(self.a)
        for name in ('packet','review','home'):
            args=[self.aa.pk] if name!='home' else []
            response=self.client.get(reverse(name,args=args))
            self.assertEqual(response.status_code,200)
            text=response.content.decode()
            for marker in ('WITHHELD-CANARY','MODEL-CANARY','answer_canary','model_output'):self.assertNotIn(marker,text)
            self.assertEqual(response['Cache-Control'],'no-store, private')
        payload=self.client.get(reverse('packet',args=[self.aa.pk])).json()
        self.assertEqual(set(payload),{'assignment','question','items','deadline','commitment','identity_policy','operator_trust'})

    def test_other_reviewer_and_outsider_cannot_read_or_write(self):
        self.admit(self.aa,self.a);self.admit(self.ab,self.b);self.answer(self.aa,self.a)
        for user in (self.b,self.outsider,self.author,self.steward):
            self.login(user)
            for route in ('packet','review','receipt','receipt_json','results','declaration','exposure'):
                response=self.client.get(reverse(route,args=[self.aa.pk]))
                self.assertIn(response.status_code,(403,404))
                self.assertNotIn('PRIVATE-REVIEW-CANARY',response.content.decode())
            with self.assertRaises(PermissionDenied):s.submit(self.aa.pk,user,{'item-1':dict(verdict='SUPPORTED',reason='intrusion')})

    def test_author_and_steward_cannot_get_assessments_before_close(self):
        self.admit(self.aa,self.a);self.answer(self.aa,self.a)
        for user in (self.author,self.steward):
            self.login(user)
            response=self.client.get(reverse('desk',args=[self.study.pk]))
            self.assertEqual(response.status_code,200)
            self.assertNotIn('PRIVATE-REVIEW-CANARY',response.content.decode())
            self.assertEqual(self.client.get(reverse('export',args=[self.r.pk])).status_code,403)
        with self.assertRaises(ValidationError):s.close(self.r.pk,self.steward)
        with self.assertRaises(PermissionDenied):s.close(self.r.pk,self.author)

    def test_locked_submission_amendment_and_private_receipt(self):
        self.admit(self.aa,self.a);record=self.answer(self.aa,self.a)
        with self.assertRaises(ValidationError):self.answer(self.aa,self.a,'replacement')
        s.amend(self.aa.pk,self.a,'A later qualification')
        record.refresh_from_db();self.assertEqual(record.answers['item-1']['reason'],'PRIVATE-REVIEW-CANARY')
        self.assertEqual(Amendment.objects.count(),1)
        self.login(self.a);r=self.client.get(reverse('receipt_json',args=[self.aa.pk]))
        receipt=r.json()
        self.assertEqual(s.digest({k:receipt[k] for k in ('assignment','round_commitment','answers','nonce')}),receipt['commitment'])
        self.assertNotIn('WITHHELD-CANARY',r.content.decode())
        self.assertEqual(self.client.get(reverse('results',args=[self.aa.pk])).status_code,403)

    def test_whole_round_release_and_typed_private_export(self):
        self.admit(self.aa,self.a);self.admit(self.ab,self.b)
        self.answer(self.aa,self.a);self.answer(self.ab,self.b,'SECOND-PRIVATE-REASON')
        s.close(self.r.pk,self.steward)
        self.login(self.a)
        response=self.client.get(reverse('results',args=[self.aa.pk]));self.assertEqual(response.status_code,200)
        self.assertIn('WITHHELD-CANARY',response.content.decode())
        self.assertNotIn('SECOND-PRIVATE-REASON',response.content.decode())
        s.feedback(self.r.pk,self.outsider,'OPEN-FEEDBACK-IS-NOT-A-LABEL')
        self.assertEqual(Assessment.objects.count(),2);self.assertEqual(Feedback.objects.count(),1)
        self.assertEqual(self.client.get(reverse('export',args=[self.r.pk])).status_code,403)
        self.login(self.author);export=self.client.get(reverse('export',args=[self.r.pk])).json()
        self.assertEqual(len(export['assignments']),2)
        self.assertNotIn('feedback',export)
        self.assertNotIn('OPEN-FEEDBACK-IS-NOT-A-LABEL',json.dumps(export))
        self.assertEqual(len(self.client.get(reverse('feedback_export',args=[self.r.pk])).json()['feedback']),1)
        self.assertEqual(s.digest({'contract':export['contract'],'nonce':export['contract_nonce']}),export['commitment'])
        self.assertFalse(any(x['missing'] for x in export['assignments']))

    def test_frozen_packet_roster_and_withheld_changes_are_detected(self):
        self.admit(self.aa,self.a)
        with self.assertRaises(ValidationError): RoundSecrets.objects.filter(round=self.r).update(withheld={'changed':'not allowed'})
        with self.assertRaises(ValidationError): Assignment.objects.create(round=self.r,reviewer=self.outsider)
        with self.assertRaises(ValidationError): Round.objects.filter(pk=self.r.pk).update(packet=[])
        self.assertEqual(s.packet(self.aa.pk,self.a)['items'],self.r.packet)

    def test_external_exposure_preserves_existing_assessment(self):
        self.admit(self.aa,self.a);self.answer(self.aa,self.a)
        s.report_exposure(self.aa.pk,self.a,'Saw the source results elsewhere')
        self.assertEqual(Assessment.objects.count(),1)
        self.aa.refresh_from_db();self.assertFalse(self.aa.eligible)
        with self.assertRaises(PermissionDenied):s.packet(self.aa.pk,self.a)

    def test_deadline_closure_accounts_for_missing_reviews(self):
        self.admit(self.aa,self.a);self.answer(self.aa,self.a)
        with patch('capsule.services.timezone.now',return_value=self.r.deadline+timedelta(seconds=1)):
            with self.assertRaises(PermissionDenied):s.packet(self.ab.pk,self.b)
            s.close(self.r.pk,self.steward)
        self.login(self.author)
        export=self.client.get(reverse('export',args=[self.r.pk])).json()
        self.assertEqual(sum(x['missing'] for x in export['assignments']),1)

    def test_known_exposure_carries_to_new_round(self):
        self.admit(self.aa,self.a);s.report_exposure(self.aa.pk,self.a,'Previously exposed')
        second=Round.objects.create(protocol='0.1',study=self.study,version=2,question=self.r.question,packet=self.r.packet,withheld={},deadline=self.r.deadline)
        aa=Assignment.objects.create(round=second,reviewer=self.a);Assignment.objects.create(round=second,reviewer=self.b)
        s.freeze(second.pk,self.author)
        s.declare(aa.pk,self.a,dict(conflict=False,prior_exposure=False,ai_assessment=False,note='Claim no exposure'))
        self.assertFalse(s.admit(aa.pk,self.steward,'Server exposure history wins').eligible)

    def test_no_release_while_related_assignment_open(self):
        self.admit(self.aa,self.a);self.admit(self.ab,self.b);self.answer(self.aa,self.a);self.answer(self.ab,self.b);s.close(self.r.pk,self.steward)
        second=Round.objects.create(protocol='0.1',study=self.study,version=2,question=self.r.question,packet=self.r.packet,withheld={},deadline=self.r.deadline)
        Assignment.objects.create(round=second,reviewer=self.a);Assignment.objects.create(round=second,reviewer=self.b);s.freeze(second.pk,self.author)
        with self.assertRaises(PermissionDenied):s.results(self.aa.pk,self.a)

    def test_anonymous_csrf_and_unknown_ids(self):
        self.assertEqual(self.client.get(reverse('packet',args=[self.aa.pk])).status_code,302)
        csrf=Client(enforce_csrf_checks=True);csrf.force_login(self.author)
        self.assertEqual(csrf.post(reverse('freeze',args=[self.r.pk])).status_code,403)
        self.login(self.a)
        self.assertEqual(self.client.get(reverse('packet',args=[uuid.uuid4()])).status_code,404)

    def test_unsafe_text_is_escaped_not_executed(self):
        # New draft has hostile task text, but no script execution or remote embeds are supported.
        self.admit(self.aa,self.a);self.login(self.a)
        with patch('capsule.services.packet',return_value={'question':'<script>unsafe()</script>','items':self.r.packet,'commitment':self.r.commitment}):
            response=self.client.get(reverse('review',args=[self.aa.pk]))
        self.assertNotIn('<script>unsafe()',response.content.decode())
        self.assertIn('&lt;script&gt;',response.content.decode())
        self.assertIn("script-src 'self'",response['Content-Security-Policy'])
        self.assertNotIn("script-src 'self' 'unsafe-inline'",response['Content-Security-Policy'])

    def test_human_form_submission_path(self):
        self.login(self.a)
        self.assertEqual(self.client.post(reverse('declaration',args=[self.aa.pk]),{'conflict':'no','prior_exposure':'no','ai_assessment':'no','note':''}).status_code,302)
        self.login(self.steward)
        self.assertEqual(self.client.post(reverse('admit',args=[self.aa.pk]),{'text':'Apply eligibility rule'}).status_code,302)
        self.login(self.a);self.assertEqual(self.client.get(reverse('review',args=[self.aa.pk])).status_code,200)
        self.assertEqual(self.client.post(reverse('review',args=[self.aa.pk]),{'verdict_item-1':'NOT_ESTABLISHED','reason_item-1':'My first independent reasoning'}).status_code,302)
        self.assertEqual(Assessment.objects.count(),1)
        self.assertEqual(self.client.get(reverse('receipt',args=[self.aa.pk])).status_code,200)
