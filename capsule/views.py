import json
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied,ValidationError,ObjectDoesNotExist
from django.db import transaction
from django.http import JsonResponse,HttpResponseBadRequest,Http404
from django.shortcuts import render,redirect,get_object_or_404
from django.views.decorators.http import require_POST
from .models import Study,Round,Assignment,Assessment,Event,Feedback,Exposure
from . import services as svc
from .forms import StudyForm,DeclarationForm,ReasonForm

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

@login_required
@error_view
def create_study(request):
    form=StudyForm(request.POST or None)
    if request.method=='POST' and form.is_valid():
        c=form.cleaned_data
        if c['steward']==request.user or request.user in c['reviewers'] or c['steward'] in c['reviewers']:
            form.add_error(None,'Author, steward and reviewers must be separate accounts for this protected round.')
        else:
            with transaction.atomic():
                study=Study.objects.create(title=c['title'],author=request.user,steward=c['steward'])
                r=Round.objects.create(study=study,question=c['question'],packet=c['packet'],withheld=c['withheld'],deadline=c['deadline'])
                Assignment.objects.bulk_create([Assignment(round=r,reviewer=u) for u in c['reviewers']])
                svc.event(r,request.user,'draft_created')
            return redirect('desk',sid=study.pk)
    return render(request,'capsule/form.html',{'form':form,'title':'Prepare a review round','intro':'Separate the evidence a reviewer needs from answers they must not see. Preview before freezing.'})

@login_required
@error_view
def desk(request,sid):
    study=get_object_or_404(Study,pk=sid)
    if request.user.pk not in (study.author_id,study.steward_id):raise PermissionDenied
    rounds=[]
    for r in study.round_set.order_by('version'):
        # Progress/eligibility only; initial judgments are not sent to the desk before close.
        assignments=list(r.assignment_set.select_related('reviewer'))
        assessments=list(Assessment.objects.filter(assignment__round=r)) if r.state=='closed' else []
        rounds.append(dict(id=r.pk,version=r.version,state=r.state,question=r.question,packet=r.packet,
            deadline=r.deadline,commitment=r.commitment,assignments=assignments,assessments=assessments))
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
    form=DeclarationForm(request.POST or None)
    if request.method=='POST' and form.is_valid():
        c=form.cleaned_data
        svc.declare(aid,request.user,{k:c[k]=='yes' for k in ('conflict','prior_exposure','ai_assessment')}|{'note':c['note']})
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
    return JsonResponse(dict(schema='review-capsule-receipt/0.1',assignment=str(a.pk),round_commitment=a.round.commitment,
        answers=r.answers,nonce=r.nonce,commitment=r.commitment,submitted_at=r.submitted_at.isoformat(),
        warning='Private receipt. Do not share evaluative content before the round closes. Server time is not an independent timestamp.'))

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
        assessment=None if record is None else dict(answers=record.answers,nonce=record.nonce,commitment=record.commitment,
            submitted_at=record.submitted_at.isoformat(),amendments=list(record.amendment_set.values('text','created_at')))
        assignments.append(dict(id=str(a.pk),reviewer_account_id=a.reviewer_id,declaration=a.declaration,
            eligible_now=a.eligible,decision_reason=a.decision_reason,decided_at=a.decided_at,
            missing=record is None,assessment=assessment,
            exposure_events=list(a.exposure_set.values('kind','detail','created_at'))))
    data=dict(schema='review-capsule-private-export/0.1',round=str(r.pk),contract=r.contract,contract_nonce=r.contract_nonce,
        commitment=r.commitment,closed_at=r.closed_at,withheld=r.withheld,assignments=assignments,
        feedback=list(Feedback.objects.filter(round=r).values('id','author_id','text','created_at')),
        events=list(Event.objects.filter(round=r).order_by('id').values('kind','actor_id','detail','created_at')),
        warning='PRIVATE: identities, declarations and assessments. No publication consent workflow is implemented; do not publish this export.')
    response=JsonResponse(data,json_dumps_params={'indent':2})
    response['Content-Disposition']='attachment; filename="private-round-export.json"'
    return response
