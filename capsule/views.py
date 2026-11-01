import json
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied,ValidationError,ObjectDoesNotExist
from django.db import transaction
from django.http import JsonResponse,HttpResponseBadRequest,Http404
from django.shortcuts import render,redirect,get_object_or_404
from django.views.decorators.http import require_POST
from .models import Study,Round,Assignment,Assessment,Event,Feedback,Exposure
from . import services as svc
from .forms import StudyForm,DeclarationForm,ReasonForm,ReviewerFormSet,reviewer_accounts,AnchorForm

def health(request):
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute('SELECT 1')
        cursor.fetchone()
    return JsonResponse({'status':'ok'})

def error_view(fn):
    def wrapped(request,*args,**kwargs):
        try:return fn(request,*args,**kwargs)
        except ObjectDoesNotExist:raise Http404
        except ValidationError as e:return render(request,'capsule/error.html',{'message':'; '.join(e.messages)},status=400)
    return wrapped

@login_required
def home(request):
    return render(request,'capsule/home.html',dict(assignments=Assignment.objects.filter(reviewer=request.user).select_related('round'),
        authored=Study.objects.filter(author=request.user),stewarded=Study.objects.filter(steward=request.user)))

def study_form(request, previous=None):
    initial={}
    if previous:
        initial=dict(title=previous.study.title,steward=previous.study.steward.username,question=previous.question,
            packet=previous.packet,withheld=previous.withheld,calibration=previous.secrets.calibration)
    data=request.POST.copy() if request.method=='POST' else None
    adding=data is not None and 'add_reviewer' in data
    if adding:
        try: total=int(data.get('reviewers-TOTAL_FORMS','2'))
        except ValueError: total=2
        data['reviewers-TOTAL_FORMS']=str(min(max(total,2)+1,20))
    form=StudyForm(data,initial=initial)
    if previous:
        # A correction changes the round, not the study's role identities.
        form.fields.pop('title');form.fields.pop('steward')
    rows=[{'username':a.reviewer.username} for a in previous.assignment_set.select_related('reviewer')] if previous else None
    reviewers=ReviewerFormSet(data,prefix='reviewers',initial=rows)
    if request.method=='POST' and not adding:
        valid=form.is_valid(); roster_valid=reviewers.is_valid()
        if valid and roster_valid:
            try:
                users=reviewer_accounts(reviewers)
                c=form.cleaned_data
                steward=previous.study.steward if previous else c['steward']
                if steward==request.user or any(u in (steward,request.user) for u in users):
                    raise ValidationError('Author, steward and reviewers must be separate accounts.')
                if previous:
                    r=svc.correction(previous.pk,request.user,c['question'],c['packet'],c['withheld'],c['calibration'],c['deadline'],users)
                else:
                    with transaction.atomic():
                        study=Study.objects.create(title=c['title'],author=request.user,steward=steward)
                        r=Round.objects.create(study=study,question=c['question'],packet=c['packet'],withheld=c['withheld'],deadline=c['deadline'])
                        secret=r.secrets;secret.calibration=c['calibration'];secret.save()
                        for u in users: Assignment.objects.create(round=r,reviewer=u)
                        svc.event(r,request.user,'draft_created')
                return redirect('desk',sid=r.study_id)
            except ValidationError as e: form.add_error(None,e)
    return render(request,'capsule/form.html',dict(form=form,reviewers=reviewers,
        title='Prepare a linked correction' if previous else 'Prepare a review round',
        intro='The previous version remains intact. Preview this new version before freezing.' if previous else 'Separate reviewer evidence from withheld results. Preview before freezing.'))

@login_required
@error_view
def create_study(request): return study_form(request)

@login_required
@error_view
def correction(request,rid):
    previous=get_object_or_404(Round.objects.select_related('study'),pk=rid)
    if previous.study.author_id!=request.user.pk: raise PermissionDenied
    if not previous.commitment: raise ValidationError('Freeze the original round before creating a linked correction.')
    svc.verify(previous)
    return study_form(request,previous)

@login_required
@error_view
def desk(request,sid):
    study=get_object_or_404(Study,pk=sid)
    if request.user.pk not in (study.author_id,study.steward_id):raise PermissionDenied
    rounds=[]
    for r in study.round_set.order_by('version'):
        # Progress/eligibility only; initial judgments are not sent to the desk before close.
        assignments=list(r.assignment_set.select_related('reviewer'))
        assessments=[]
        if r.state=='closed':
            for record in Assessment.objects.filter(assignment__round=r).select_related('assignment__round'):
                data=svc.receipt_data(record,include_calibration=request.user.pk==study.steward_id)
                assessments.append(data)
        rounds.append(dict(id=r.pk,version=r.version,state=r.state,question=r.question,packet=r.packet,
            deadline=r.deadline,commitment=r.commitment,assignments=assignments,assessments=assessments,
            protocol=r.protocol,previous=r.previous_id,anchor_url=r.anchor_url,
            calibration=svc.calibration_report(r,request.user) if request.user.pk==study.steward_id else []))
    return render(request,'capsule/desk.html',dict(study=study,rounds=rounds,is_author=request.user.pk==study.author_id,is_steward=request.user.pk==study.steward_id))

@login_required
@require_POST
@error_view
def freeze(request,rid):svc.freeze(rid,request.user);return redirect('desk',sid=Round.objects.get(pk=rid).study_id)

@login_required
@require_POST
@error_view
def close(request,rid):svc.close(rid,request.user);return redirect('desk',sid=Round.objects.get(pk=rid).study_id)

@login_required
@error_view
def declaration(request,aid):
    a=get_object_or_404(Assignment,pk=aid,reviewer=request.user)
    form=DeclarationForm(request.POST or None,legacy=a.round.protocol!='0.2')
    if request.method=='POST' and form.is_valid():
        c=form.cleaned_data
        flags=('relationship','stake','prior_exposure','ai_assessment') if a.round.protocol=='0.2' else ('conflict','prior_exposure','ai_assessment')
        data={k:c[k]=='yes' for k in flags}|{'note':c['note']}
        if a.round.protocol=='0.2': data['credit_consent']=c['credit_consent']
        svc.declare(aid,request.user,data)
        return redirect('home')
    return render(request,'capsule/form.html',dict(form=form,title='Before opening your packet',intro='A relationship or previous exposure can change the kind of review you can provide. Declare it; the steward applies the frozen policy. Your account does not itself establish independence.'))

@login_required
@require_POST
@error_view
def admit(request,aid):
    form=ReasonForm(request.POST)
    if not form.is_valid():return HttpResponseBadRequest('A decision reason is required.')
    a=svc.admit(aid,request.user,form.cleaned_data['text']);return redirect('desk',sid=a.round.study_id)

@login_required
@error_view
def review(request,aid):
    if request.method=='POST':
        a=get_object_or_404(Assignment,pk=aid,reviewer=request.user)
        items=a.round.packet
        answers={p['id']:{'verdict':request.POST.get('verdict_'+p['id'],''),'reason':request.POST.get('reason_'+p['id'],'')} for p in items}
        svc.submit(aid,request.user,answers);return redirect('receipt',aid=aid)
    data=svc.packet(aid,request.user)
    a=Assignment.objects.select_related('round').get(pk=aid)
    data['modern']=a.round.protocol=='0.2'
    return render(request,'capsule/review.html',data)

@login_required
@error_view
def packet_json(request,aid):return JsonResponse(svc.packet(aid,request.user))

@login_required
def receipt(request,aid):
    a=get_object_or_404(Assignment,pk=aid,reviewer=request.user)
    record=get_object_or_404(Assessment,assignment=a)
    return render(request,'capsule/receipt.html',dict(a=a,record=record,amendments=record.amendment_set.all()))

@login_required
def receipt_json(request,aid):
    a=get_object_or_404(Assignment,pk=aid,reviewer=request.user)
    r=get_object_or_404(Assessment,assignment=a)
    return JsonResponse(svc.receipt_data(r),json_dumps_params={'indent':2})

@login_required
@error_view
def result_json(request,aid):return JsonResponse(svc.results(aid,request.user))

@login_required
@error_view
def exposure(request,aid):
    get_object_or_404(Assignment,pk=aid,reviewer=request.user)
    form=ReasonForm(request.POST or None)
    if request.method=='POST' and form.is_valid():
        svc.report_exposure(aid,request.user,form.cleaned_data['text']);return redirect('home')
    return render(request,'capsule/form.html',dict(form=form,title='Report new exposure',intro='Keep the original assessment. Record what happened; future protected submissions will be blocked pending a new review policy.'))

@login_required
@require_POST
@error_view
def amend(request,aid):
    form=ReasonForm(request.POST)
    if not form.is_valid():return HttpResponseBadRequest('Amendment details required.')
    svc.amend(aid,request.user,form.cleaned_data['text']);return redirect('receipt',aid=aid)

@login_required
@require_POST
@error_view
def feedback(request,rid):
    form=ReasonForm(request.POST)
    if not form.is_valid():return HttpResponseBadRequest('Feedback details required.')
    svc.feedback(rid,request.user,form.cleaned_data['text']);return redirect('home')

@login_required
@error_view
def export_round(request,rid):
    r=get_object_or_404(Round.objects.select_related('study'),pk=rid)
    if request.user.pk not in (r.study.author_id,r.study.steward_id):raise PermissionDenied
    svc.verify(r)
    if r.state!='closed':raise PermissionDenied
    # A PRIVATE author/steward export, never public by default.
    assignments=[]
    for a in r.assignment_set.order_by('id'):
        record=Assessment.objects.filter(assignment=a).first()
        assessment=None if record is None else svc.receipt_data(record,include_calibration=request.user.pk==r.study.steward_id)
        if assessment is not None: assessment['amendments']=list(record.amendment_set.values('text','created_at')) if request.user.pk==r.study.steward_id or not (r.protocol=='0.2' and r.secrets.calibration) else []
        assignments.append(dict(id=str(a.pk),reviewer_account_id=a.reviewer_id,declaration=a.declaration,
            eligible_now=a.eligible,decision_reason=a.decision_reason,decided_at=a.decided_at,
            missing=record is None,assessment=assessment,
            exposure_events=list(a.exposure_set.values('kind','detail','created_at'))))
    svc.event(r,request.user,'private_export_downloaded',role='steward' if request.user.pk==r.study.steward_id else 'author')
    data=dict(schema='review-capsule-private-export/0.2',round=str(r.pk),contract=r.contract,contract_nonce=r.contract_nonce,
        commitment=r.commitment,packet=r.packet,previous_round=str(r.previous_id) if r.previous_id else None,
        anchor_url=r.anchor_url,closed_at=r.closed_at,withheld=r.withheld,assignments=assignments,
        events=list(Event.objects.filter(round=r).order_by('id').values('kind','actor_id','detail','created_at','previous_hash','hash')),
        warning='PRIVATE: identities, declarations and assessments. No publication consent workflow is implemented; do not publish this export.')
    if request.user.pk==r.study.steward_id: data['calibration_report']=svc.calibration_report(r,request.user)
    response=JsonResponse(data,json_dumps_params={'indent':2})
    response['Content-Disposition']='attachment; filename="private-round-export.json"'
    return response


@login_required
@require_POST
@error_view
def open_round(request,rid):
    form=AnchorForm(request.POST)
    if not form.is_valid(): return render(request,'capsule/form.html',dict(form=form,title='Record external commitment publication'),status=400)
    r=svc.open_round(rid,request.user,form.cleaned_data['url'])
    return redirect('desk',sid=r.study_id)

@login_required
@error_view
def peers(request,aid): return JsonResponse(svc.peer_work(aid,request.user),json_dumps_params={'indent':2})

@login_required
@error_view
def feedback_export(request,rid):
    r=get_object_or_404(Round.objects.select_related('study'),pk=rid)
    if request.user.pk not in (r.study.author_id,r.study.steward_id) or r.state!='closed': raise PermissionDenied
    svc.event(r,request.user,'feedback_export_downloaded')
    return JsonResponse({'schema':'review-capsule-feedback-only/0.1','round':str(r.pk),
        'feedback':list(Feedback.objects.filter(round=r).values('id','author_id','text','created_at'))})

def enhancements(request):
    from pathlib import Path
    from django.http import HttpResponse
    return HttpResponse((Path(__file__).parent/'assets'/'enhancements.js').read_text(),content_type='text/javascript')
