# Per-check reporting; Python 3.10+, stdlib [a-Shell ok].
from collections import Counter
import re
CHECK_STATUSES=('pass','fail','missing','pending','unverifiable','not_checked')
TOOL_TEXT={'ok':'Check matched.','fail':'Check did not match.','declared':'declared by participant','warning':'Operator role disclosure is present.','identity':'Expected key was not supplied; only key/signature self-consistency was checked.','unavailable':'Required validation evidence or backend is unavailable.'}
class Report:
    def __init__(self):self.data={'spec':'0.2.2','checks':[],'declarations':[],'reviewers':[],'anchors':[],'registry_coverage':[],'round_status':'incomplete'}
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
        return self.data
