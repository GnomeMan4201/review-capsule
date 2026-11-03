# Render scoped report fields; Python 3.12+, stdlib [a-Shell ok].
from collections import Counter
from copy import deepcopy
from .report import CHECK_STATUSES

FORMAT='reviewrecord-report/v1'
NOTICE_CODES={'OPERATOR_DISCLOSURE','WITHDRAWN','WITHDRAWAL_STEWARD_ATTESTED'}
DEFAULTS={'missing':'Required evidence is missing.','pending':'Check pending; completion condition is not yet met.',
          'unverifiable':'Check could not be evaluated with available evidence or backend.',
          'not_checked':'Check not evaluated; examine scope and configuration.'}


def render(legacy,statements,coverage,policy):
    result=deepcopy(legacy)
    result['report_format']=FORMAT
    kept=[];remap={}
    for index,check in enumerate(result['checks']):
        # Remove only informational passes. Never discard a blocking outcome.
        if check['code'] in NOTICE_CODES and check['status']=='pass':continue
        remap[index]=len(kept);kept.append(check)
        if check['detail']=='Check did not match.' and type(check['status']) is str and check['status'] in DEFAULTS:
            check['detail']=DEFAULTS[check['status']]
    result['checks']=kept
    for check in kept:
        if check['code']=='REPORT_STATUS_UNRECOGNIZED':
            parts=check['subject'].split('/')
            if len(parts)==3 and parts[0]=='checks' and parts[1].isdigit() and int(parts[1]) in remap:
                check['subject']='checks/'+str(remap[int(parts[1])])+'/status'
    result['statements_and_events']=deepcopy(statements)
    for statement in result['statements_and_events']:
        statement['check_refs']=['/checks/'+str(i) for i,c in enumerate(kept) if c['subject']==statement['source']]
    result['coverage_notices']=deepcopy(coverage)
    result['review_counts']={
        'logged_distinct_commit_keys':result.pop('locked_count',None),
        'first_commit_matching_reveals':result.pop('verified_reveals',None),
        'commit_log_entries':result.pop('tree_size',None),
        'policy_min_locks':policy['min_locks'] if policy else None,
        'policy_min_reveals':policy['min_reveals'] if policy else None}
    result['count_scope']='Supplied record only; counts use signing keys, not people. Reveal counts use local assessment/signature/binding/inclusion predicates; other failures remain separate.'
    result.pop('round_status',None)
    # Source content now has one canonical location in the new format.
    result.pop('declarations',None)
    counts={status:0 for status in CHECK_STATUSES}
    counts.update(Counter(c['status'] for c in kept if type(c.get('status')) is str and c['status'] in CHECK_STATUSES))
    result['counts']=counts
    result['summary']='Matched predicates and other check outcomes: '+', '.join(str(counts[k])+' '+k.replace('_',' ') for k in counts)
    # Only pass notices were removed. Preserve the existing check exit fold.
    return result
