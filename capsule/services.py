"""Application boundary, not a defense against a database/server administrator."""
import hashlib,json,secrets
from django.core.exceptions import PermissionDenied,ValidationError
from django.db import transaction
from django.utils import timezone
from .models import Round,Assignment,Assessment,Amendment,Exposure,Event,Feedback

def digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()

def check_packet(packet):
    if not isinstance(packet,list) or not 1<=len(packet)<=20:raise ValidationError('Supply 1–20 items.')
    seen=set()
    for p in packet:
        if not isinstance(p,dict) or set(p)!={'id','evidence','candidate'}:raise ValidationError('Each item needs exactly id, evidence and candidate.')
        if not isinstance(p['id'],str) or not p['id'].strip() or len(p['id'])>80 or p['id'] in seen:raise ValidationError('Use unique item IDs.')
        seen.add(p['id'])
        if not isinstance(p['candidate'],str) or not 1<=len(p['candidate'].strip())<=4000:raise ValidationError('Invalid candidate.')
        if not isinstance(p['evidence'],list) or not 1<=len(p['evidence'])<=20 or any(not isinstance(v,str) or not 1<=len(v.strip())<=4000 for v in p['evidence']):raise ValidationError('Invalid evidence.')

def has_exposure(a):
    return Exposure.objects.filter(assignment__round__study_id=a.round.study_id,assignment__reviewer_id=a.reviewer_id,kind__in=['results_delivered','reported_external_exposure']).exists()

def event(r,user,kind,**detail):Event.objects.create(round=r,actor=user,kind=kind,detail=detail)

def contract_for(r):
    return dict(schema='review-capsule-contract/0.1',round_id=str(r.pk),version=r.version,
        question=r.question,packet=r.packet,deadline=r.deadline.isoformat(),
        assignments=sorted([{'assignment':str(a.pk),'reviewer':a.reviewer_id} for a in r.assignment_set.all()],key=lambda x:x['assignment']),
        author=r.study.author_id,steward=r.study.steward_id,
        withheld_commitment=digest({'withheld':r.withheld,'nonce':r.contract_nonce}),
        release='all locked or frozen deadline; whole round only',
        task='evidence_support',identity='author identity not guaranteed hidden',
        eligibility='separate steward; declared no conflicts, prior results/peer exposure, or AI judgment assistance; no recorded result exposure for study',
        visibility='reviewer own assignment only; withheld results after closure; peer answers are never exposed by this version',
        operator_trust='operator can read storage; no claim of cryptographic secrecy or unique human verification',
        assistance='no AI-generated evaluation in protected assessments; ordinary accessibility tools permitted')

def verify(r):
    if not r.commitment or r.contract!=contract_for(r) or digest({'contract':r.contract,'nonce':r.contract_nonce})!=r.commitment:
        raise ValidationError('Frozen contract mismatch. Stop and investigate.')

@transaction.atomic
def freeze(rid,user):
    r=Round.objects.select_for_update().select_related('study').get(pk=rid)
    if r.study.author_id!=user.pk:raise PermissionDenied
    if r.state!='draft':raise ValidationError('Already frozen.')
    if r.study.author_id==r.study.steward_id:raise ValidationError('Choose a separate steward.')
    if r.deadline<=timezone.now():raise ValidationError('Deadline must be in the future.')
    assignments=list(r.assignment_set.all())
    if len(assignments)<2 or any(a.reviewer_id in (r.study.author_id,r.study.steward_id) for a in assignments):raise ValidationError('Assign at least two reviewers, separate from author/steward.')
    check_packet(r.packet)
    r.contract_nonce=secrets.token_hex(32);r.contract=contract_for(r)
    r.commitment=digest({'contract':r.contract,'nonce':r.contract_nonce});r.state='open'
    r.save(update_fields=['contract','contract_nonce','commitment','state']);event(r,user,'round_frozen',commitment=r.commitment)
    return r

@transaction.atomic
def declare(aid,user,declaration):
    # Lock order is always round then assignment, including close and submission.
    a0=Assignment.objects.get(pk=aid)
    r=Round.objects.select_for_update().get(pk=a0.round_id)
    a=Assignment.objects.select_for_update().get(pk=aid)
    if a.reviewer_id!=user.pk:raise PermissionDenied
    verify(r)
    if r.state!='open' or timezone.now()>=r.deadline:raise ValidationError('Round is not accepting declarations.')
    if a.declaration is not None:raise ValidationError('Initial declaration is locked; report new exposure separately.')
    if set(declaration)!={'conflict','prior_exposure','ai_assessment','note'} or any(type(declaration[k]) is not bool for k in ('conflict','prior_exposure','ai_assessment')):raise ValidationError('Invalid declaration.')
    if not isinstance(declaration['note'],str) or len(declaration['note'])>4000:raise ValidationError('Invalid note.')
    a.declaration=declaration;a.declared_at=timezone.now();a.save(update_fields=['declaration','declared_at'])
    event(r,user,'declaration_recorded',assignment=str(a.pk))

@transaction.atomic
def admit(aid,user,reason):
    a0=Assignment.objects.get(pk=aid);r=Round.objects.select_for_update().select_related('study').get(pk=a0.round_id)
    a=Assignment.objects.select_for_update().get(pk=aid)
    if r.study.steward_id!=user.pk:raise PermissionDenied
    verify(r)
    if r.state!='open' or timezone.now()>=r.deadline:raise ValidationError('Round is closed for admission.')
    if a.decided_at:raise ValidationError('Admission decision is locked.')
    if not a.declaration or not reason.strip():raise ValidationError('Declaration and reason required.')
    exposed=Exposure.objects.filter(assignment__round__study_id=r.study_id,assignment__reviewer_id=a.reviewer_id,kind__in=['results_delivered','reported_external_exposure']).exists()
    a.eligible=not exposed and not any(a.declaration[k] for k in ('conflict','prior_exposure','ai_assessment'))
    a.decision_reason=reason;a.decided_at=timezone.now();a.save(update_fields=['eligible','decision_reason','decided_at'])
    event(r,user,'eligibility_decided',assignment=str(a.pk),eligible=a.eligible,reason=reason)
    return a

@transaction.atomic
def packet(aid,user):
    a0=Assignment.objects.get(pk=aid);r=Round.objects.select_for_update().get(pk=a0.round_id)
    a=Assignment.objects.get(pk=aid)
    if a.reviewer_id!=user.pk:raise PermissionDenied
    verify(r)
    if not a.eligible or has_exposure(a) or r.state!='open' or timezone.now()>=r.deadline:raise PermissionDenied
    Exposure.objects.create(assignment=a,kind='packet_delivered')
    # Explicit allowlist: never serialize Round, Study, author or withheld fields.
    return dict(assignment=str(a.pk),question=r.question,items=r.packet,deadline=r.deadline.isoformat(),
                commitment=r.commitment,identity_policy=r.contract['identity'],operator_trust=r.contract['operator_trust'])

@transaction.atomic
def submit(aid,user,answers):
    a0=Assignment.objects.get(pk=aid);r=Round.objects.select_for_update().get(pk=a0.round_id)
    a=Assignment.objects.select_for_update().get(pk=aid)
    if a.reviewer_id!=user.pk:raise PermissionDenied
    verify(r)
    if not a.eligible or has_exposure(a) or r.state!='open' or timezone.now()>=r.deadline:raise ValidationError('Assignment cannot accept a protected assessment.')
    if Assessment.objects.filter(assignment=a).exists():raise ValidationError('Initial assessment is locked.')
    if not Exposure.objects.filter(assignment=a,kind='packet_delivered').exists():raise ValidationError('Open the assigned packet first.')
    if not isinstance(answers,dict) or set(answers)!={p['id'] for p in r.packet}:raise ValidationError('Answer every assigned item exactly once.')
    for value in answers.values():
        if (not isinstance(value,dict) or set(value)!={'verdict','reason'} or value['verdict'] not in ('SUPPORTED','NOT_ESTABLISHED','UNCERTAIN','OUT_OF_EXPERTISE') or not isinstance(value['reason'],str) or not 1<=len(value['reason'].strip())<=4000):raise ValidationError('Each answer needs a verdict and reasoning.')
    nonce=secrets.token_hex(32)
    commitment=digest({'assignment':str(a.pk),'round_commitment':r.commitment,'answers':answers,'nonce':nonce})
    record=Assessment.objects.create(assignment=a,answers=answers,nonce=nonce,commitment=commitment)
    event(r,user,'assessment_locked',assignment=str(a.pk),commitment=commitment)
    return record

@transaction.atomic
def close(rid,user):
    r=Round.objects.select_for_update().select_related('study').get(pk=rid)
    if r.study.steward_id!=user.pk:raise PermissionDenied
    verify(r)
    if r.state!='open':raise ValidationError('Round is not open.')
    assignments=r.assignment_set.all()
    # No author-selected exclusions before early closure; missing/ineligible remain counted until deadline.
    if timezone.now()<r.deadline and assignments.count()!=Assessment.objects.filter(assignment__round=r).count():raise ValidationError('Wait for every frozen assignment or the frozen deadline.')
    r.state='closed';r.closed_at=timezone.now();r.save(update_fields=['state','closed_at']);event(r,user,'round_closed')
    return r

@transaction.atomic
def results(aid,user):
    a0=Assignment.objects.get(pk=aid);r=Round.objects.select_for_update().get(pk=a0.round_id)
    a=Assignment.objects.get(pk=aid)
    if a.reviewer_id!=user.pk:raise PermissionDenied
    verify(r)
    if r.state!='closed' or not a.eligible:raise PermissionDenied
    # Do not reveal while this person has another open protected assignment in this study.
    if Assignment.objects.filter(reviewer=user,round__study_id=r.study_id,round__state='open').exists():raise PermissionDenied
    Exposure.objects.create(assignment=a,kind='results_delivered')
    return dict(round=str(r.pk),withheld=r.withheld,closed_at=r.closed_at.isoformat(),
                notice='Post-round material. Peer assessments remain private in this prototype.')

@transaction.atomic
def report_exposure(aid,user,note):
    a0=Assignment.objects.get(pk=aid);r=Round.objects.select_for_update().get(pk=a0.round_id)
    a=Assignment.objects.select_for_update().get(pk=aid)
    if a.reviewer_id!=user.pk:raise PermissionDenied
    if not note.strip() or len(note)>4000:raise ValidationError('Describe exposure without pasting results.')
    Exposure.objects.create(assignment=a,kind='reported_external_exposure',detail=note)
    a.eligible=False;a.save(update_fields=['eligible'])
    event(r,user,'exposure_reported',assignment=str(a.pk))

@transaction.atomic
def amend(aid,user,text):
    a=Assignment.objects.select_related('round').get(pk=aid)
    r=Round.objects.select_for_update().get(pk=a.round_id)
    if a.reviewer_id!=user.pk:raise PermissionDenied
    if not text.strip() or len(text)>4000:raise ValidationError('Amendment text required.')
    record=Assessment.objects.get(assignment=a)
    Amendment.objects.create(assessment=record,text=text)
    event(r,user,'assessment_amended',assignment=str(a.pk))

@transaction.atomic
def feedback(rid,user,text):
    r=Round.objects.select_for_update().get(pk=rid)
    if r.state!='closed' or not text.strip() or len(text)>4000:raise ValidationError('Discussion opens after round closure; text required.')
    row=Feedback.objects.create(round=r,author=user,text=text)
    event(r,user,'feedback_recorded',feedback=row.pk)
    return row
