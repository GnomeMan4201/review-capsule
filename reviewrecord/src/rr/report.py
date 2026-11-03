# Per-check reporting; Python 3.10+, stdlib [a-Shell ok].
from collections import Counter
import re
CHECK_STATUSES=('pass','fail','missing','pending','unverifiable','not_checked')
TOOL_TEXT={'ok':'Check matched.','fail':'Check did not match.','declared':'declared by participant','warning':'Operator role disclosure is present.','identity':'Expected key was not supplied; only key/signature self-consistency was checked.','unavailable':'Required validation evidence or backend is unavailable.'}
class Report:
    def __init__(self,*,report_format='legacy'):
        if report_format not in ('legacy','reviewrecord-report/v1'):raise ValueError('Unknown report format.')
        self.report_format=report_format;self.statements=[];self.coverage=[];self.policy=None
        self.data={'spec':'0.2.2','checks':[],'declarations':[],'reviewers':[],'anchors':[],'registry_coverage':[],'round_status':'incomplete'}
    def statement(self,kind,basis,source,subject,asserted_by,content,wording):
        if self.report_format=='legacy':return
        if re.search(r'\b(independent|certified|trusted|validated research)\b',wording,re.I):
            self.add('FORBIDDEN_CLAIM_PRESENT','fail','tool-authored statement wording',
                     'A tool-authored message violated the wording boundary.')
            wording='Message omitted because it violated the wording boundary.'
        self.statements.append(dict(kind=kind,basis=basis,source=source,subject=subject,
            asserted_by=asserted_by,content=content,wording=wording,
            attribution='Claimed signing key; examine referenced signature and binding checks.'))
    def coverage_notice(self,scope,subject,execution,reason,candidate_count,checked_count,wording):
        if self.report_format=='legacy':return
        if re.search(r'\b(independent|certified|trusted|validated research)\b',wording,re.I):
            self.add('FORBIDDEN_CLAIM_PRESENT','fail','tool-authored coverage wording',
                     'A tool-authored message violated the wording boundary.')
            wording='Message omitted because it violated the wording boundary.'
        self.coverage.append(dict(scope=scope,subject=subject,execution=execution,reason=reason,
                                 candidate_count=candidate_count,checked_count=checked_count,wording=wording))
    def add(self,code,status,subject='',detail=None):
        if detail and re.search(r'\b(independent|certified|trusted|validated research)\b',detail,re.I):
            self.data['checks'].append({'code':'FORBIDDEN_CLAIM_PRESENT','status':'fail','subject':'tool-authored detail','detail':'A tool-authored message violated the wording boundary.'})
            detail='Message omitted because it violated the wording boundary.'
        self.data['checks'].append({'code':code,'status':status,'subject':subject,'detail':detail or TOOL_TEXT['ok' if status=='pass' else 'fail']})
    def finish(self):
        for index,check in enumerate(list(self.data['checks'])):
            status=check.get('status')
            if type(status) is str and status in CHECK_STATUSES:continue
            subject='checks/'+str(index)+'/status'
            if not any(x['code']=='REPORT_STATUS_UNRECOGNIZED' and x['status']=='fail' and x['subject']==subject for x in self.data['checks']):
                self.add('REPORT_STATUS_UNRECOGNIZED','fail',subject,
                         'Report check status is outside the six defined values.')
        counts={name:0 for name in CHECK_STATUSES}
        counts.update(Counter(x['status'] for x in self.data['checks']
                              if type(x.get('status')) is str and x['status'] in CHECK_STATUSES))
        self.data['counts']=counts
        self.data['exit_code']=1 if counts['fail'] or counts['missing'] else 2 if any(counts[k] for k in ('pending','unverifiable','not_checked')) else 0
        self.data['summary']='Integrity checks: '+', '.join(str(counts[k])+' '+k.replace('_',' ') for k in counts)
        if self.report_format=='reviewrecord-report/v1':
            from .report_v1 import render
            return render(self.data,self.statements,self.coverage,self.policy)
        return self.data
