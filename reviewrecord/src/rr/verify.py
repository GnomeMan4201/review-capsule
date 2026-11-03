# Offline-first bundle checks; Python 3.12+, cryptography and optional OTS [needs Linux runner].
import hashlib,re,stat,zipfile,sys,zlib
from datetime import datetime
from pathlib import Path,PurePosixPath
from . import canon,dsse,merkle,anchors,anchor_evidence
from .constants import SPEC,LIMITS,JUDGMENTS
from .report import Report,TOOL_TEXT
MAX_FILE=1024*1024;MAX_TOTAL=24*1024*1024;MAX_FILES=4096;MAX_ZIP_RATIO=200

def valid_time(value):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z',value):return False
    try:datetime.fromisoformat(value);return True
    except ValueError:return False

def rid(key):return 'r-'+hashlib.sha256(key.encode()).hexdigest()[:16]
def safe_path(name):
    return type(name) is str and bool(name) and '\\' not in name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/'))
def read_bundle(path,report):
    """Bounded ingestion: never trust a ZIP central-directory size as a read cap."""
    result={};total=0
    try:
        if Path(path).is_dir():
            for p in sorted(Path(path).rglob('*')):
                if p.is_symlink():
                    report.add('BUNDLE_PATH_INVALID','fail',detail='Symlink entries are rejected.')
                    continue
                if not p.is_file():continue
                name=p.relative_to(path).as_posix()
                if not safe_path(name):
                    report.add('BUNDLE_PATH_INVALID','fail',name);continue
                if len(result)>=MAX_FILES or total>=MAX_TOTAL:
                    report.add('BUNDLE_LIMIT_EXCEEDED','fail',name);continue
                size=p.stat().st_size;limit=min(MAX_FILE,MAX_TOTAL-total)
                if size>limit:
                    report.add('BUNDLE_LIMIT_EXCEEDED','fail',name);continue
                with p.open('rb') as stream:
                    data=stream.read(limit+1)
                if len(data)>limit:
                    report.add('BUNDLE_LIMIT_EXCEEDED','fail',name);continue
                if len(data)!=size:
                    report.add('BUNDLE_UNREADABLE','fail',name);continue
                result[name]=data;total+=len(data)
        else:
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if info.is_dir():continue
                    name=info.filename
                    if not safe_path(name) or name in result or stat.S_ISLNK(info.external_attr>>16):
                        report.add('BUNDLE_PATH_INVALID','fail',name);continue
                    if len(result)>=MAX_FILES or total>=MAX_TOTAL:
                        report.add('BUNDLE_LIMIT_EXCEEDED','fail',name);continue
                    limit=min(MAX_FILE,MAX_TOTAL-total)
                    if info.file_size>limit:
                        report.add('BUNDLE_LIMIT_EXCEEDED','fail',name);continue
                    if info.file_size>0 and (info.compress_size<=0 or
                                             info.file_size>info.compress_size*MAX_ZIP_RATIO):
                        report.add('BUNDLE_LIMIT_EXCEEDED','fail',name,detail='ZIP compression ratio exceeds the allowed ceiling.')
                        continue
                    # A lying header or decompressor cannot cause an unbounded read.
                    chunks=[];received=0
                    with z.open(info) as stream:
                        while True:
                            block=stream.read(min(65536,limit-received+1))
                            if not block:break
                            received+=len(block)
                            if received>limit:
                                report.add('BUNDLE_LIMIT_EXCEEDED','fail',name)
                                break
                            chunks.append(block)
                    if received>limit:continue
                    if received!=info.file_size:
                        report.add('BUNDLE_UNREADABLE','fail',name);continue
                    result[name]=b''.join(chunks);total+=received
    except (OSError,EOFError,ValueError,zipfile.BadZipFile,RuntimeError,zlib.error):
        report.add('BUNDLE_UNREADABLE','fail')
    return result

def verify_bundle(path,*,expected_author_key=None,expected_steward_key=None,registries=None,network=False,bitcoin_rpc=None,tsa_ca=None,tsa_policy=None,tsa_untrusted=None,report_format='legacy'):
    report=Report(report_format=report_format)
    if sys.flags.optimize:
        report.add('RUNTIME_UNSUPPORTED','fail',detail='Run without Python optimization so all schema guards execute.')
        return report.finish()
    files=read_bundle(path,report);parsed={};decoded={};valid={}
    def add(code,ok,subject='',detail=None):report.add(code,'pass' if ok else 'fail',subject,detail)
    def missing(code,subject):report.add(code,'missing',subject)
    for name,raw in files.items():
        if not name.endswith('.json'):continue
        try:parsed[name]=canon.loads(raw)
        except canon.CanonError:report.add('CANON_INVALID','fail',name);continue
        value=parsed[name]
        is_envelope=name in ('registration.json','close.json') or name.split('/')[0] in ('declarations','commits','withdrawals','assessments','log','dispositions')
        if is_envelope:
            try:decoded[name]=dsse.decode(raw)
            except dsse.EnvelopeError as e:report.add(e.code,'fail',name)
    manifest=parsed.get('manifest.json');record_hash=None
    if type(manifest) is not dict:missing('MANIFEST_MISSING','manifest.json')
    else:
        try:
            entries=manifest['files'];assert type(entries) is list
            names=[e['path'] for e in entries]
            assert all(type(e) is dict and set(e)=={'path','sha256'} and safe_path(e['path']) for e in entries)
            assert len(names)==len(set(names)) and names==sorted(names)
            inventory={n for n in files if n!='manifest.json' and not n.startswith('anchors/')}
            add('HASH_MISMATCH',set(names)==inventory,'manifest inventory')
            for e in entries:
                ok=e['path'] in files and canon.digest(files[e['path']])==e['sha256'];add('HASH_MISMATCH',ok,e['path'])
            projection=dict(files=entries,spec=manifest['spec']);record_hash=canon.hash_value(projection)
            add('HASH_MISMATCH',manifest['spec']==SPEC and record_hash==manifest['record_hash'],'record_hash')
        except (KeyError,TypeError,AssertionError,ValueError):report.add('MANIFEST_MALFORMED','fail','manifest.json')
    reg_record=decoded.get('registration.json');reg=reg_record.value if reg_record else {};registration_hash=reg_record.object_hash if reg_record else None
    if not reg:missing('REGISTRATION_MISSING','registration.json')
    reg_ok=True
    try:
        assert reg['type']=='registration' and reg['spec']==SPEC and reg['canon']=='canon-v1'
        for field in ('round_id','work_id'):assert type(reg[field]) is str and reg[field].strip()
        dsse.public_bytes(reg['author_key']);dsse.public_bytes(reg['steward_key'])
        if reg['author_key']==reg['steward_key']:report.add('ROLE_KEY_REUSED','fail','registration.json',detail='Author and steward must use distinct signing keys.')
        for field in ('packet_hash','policy_hash','withheld_commitment'):canon.hash_bytes(reg[field])
        assert type(reg['prior_rounds']) is list and all(type(x) is str for x in reg['prior_rounds']) and len(reg['prior_rounds'])==len(set(reg['prior_rounds']))
        assert type(reg['reviewers_target']) is int and reg['reviewers_target']>=1
        assert type(reg['steward_is_author_operator']) is bool
        assert valid_time(reg['registered_at']) and valid_time(reg['deadline'])
    except (KeyError,ValueError,AssertionError,TypeError):reg_ok=False;report.add('REGISTRATION_MALFORMED','fail','registration.json')
    for role,expected in [('author',expected_author_key),('steward',expected_steward_key)]:
        if expected is None:report.add('EXPECTED_KEY_NOT_SUPPLIED','not_checked',role,TOOL_TEXT['identity'])
        else:add('KEY_MISMATCH',reg.get(role+'_key')==expected,role)
    if reg.get('steward_is_author_operator') is True:report.add('OPERATOR_DISCLOSURE','pass','registration.json',TOOL_TEXT['warning'])
    if type(reg.get('steward_is_author_operator')) is bool:
        report.statement('operator_disclosure','author_declared','registration.json','registration.json',reg.get('author_key'),
            {'steward_is_author_operator':reg['steward_is_author_operator']},
            'Author registration declares the operator role; role claim not factually established.')
    statement_ok=reg.get('limits')==LIMITS
    add('LIMITS_MISSING_OR_ALTERED',statement_ok,'registration.limits')
    add('LIMITS_MISSING_OR_ALTERED',files.get('limits.txt')==(LIMITS+'\n').encode() and statement_ok,'limits.txt')
    for name,record in decoded.items():
        value=record.value;kind=value['type'];key=None
        folders={'registration':'registration.json','close':'close.json','logentry':'log','disposition':'dispositions','declaration':'declarations','commit':'commits','withdrawal':'withdrawals','assessment':'assessments'}
        location=name==folders[kind] if kind in ('registration','close') else name.split('/')[0]==folders[kind]
        add('OBJECT_LOCATION_MISMATCH',location,name)
        schema_ok=location
        try:
            if kind=='logentry':
                assert type(value.get('seq')) is int and value['seq']>0 and value.get('kind') in ('declaration','commit','withdrawal')
                canon.hash_bytes(value['ref_hash']);canon.hash_bytes(value['prev_entry_hash'])
            if kind=='commit':canon.hash_bytes(value['commitment'])
            if kind in ('assessment','close'):assert valid_time(value['locked_at' if kind=='assessment' else 'closed_at'])
            if kind=='withdrawal':assert 'steward_attested' not in value or type(value['steward_attested']) is bool
        except (AssertionError,KeyError,ValueError,TypeError):
            schema_ok=False;report.add('OBJECT_MALFORMED','fail',name)
        if kind in ('registration','disposition'):key=reg.get('author_key')
        elif kind in ('logentry','close') or (kind=='withdrawal' and value.get('steward_attested') is True):key=reg.get('steward_key')
        else:key=value.get('reviewer_key')
        if kind=='declaration':
            report.statement('declaration','participant_declared',name,value.get('reviewer_key'),key,
                {k:value[k] for k in ('relationship_to_author','stake_in_result','prior_exposure','identity_disclosure','credit_consent') if k in value},
                'Participant states these disclosures; truth not established by these checks.')
        elif kind=='withdrawal':
            attested=value.get('steward_attested') is True
            report.statement('withdrawal','steward_attested' if attested else 'participant_declared',name,value.get('reviewer_key'),key,
                dict(value),'Steward states this reviewer withdrew; reviewer consent is not established.' if attested else
                'Reviewer-key statement of withdrawal retained; lock retained. See separate log and counting checks.')
        elif kind=='disposition':
            report.statement('disposition','author_declared',name,name,key,dict(value),
                'Author records this disposition and reason; any claimed change is not established by this row.')
        ok=schema_ok and key is not None and dsse.verify_signature(record,key)
        add('SIGNATURE_INVALID',ok,name)
        if name!='registration.json':
            bound=reg_ok and value.get('registration_hash')==registration_hash and value.get('round_id')==reg.get('round_id')
            add('REGISTRATION_BINDING_MISMATCH',bound,name);ok=ok and bound
        if kind in ('declaration','commit','withdrawal','assessment'):
            try:
                key_value=value['reviewer_key'];dsse.public_bytes(key_value)
                parts=name.split('/');expected_folder={'declaration':'declarations','commit':'commits','withdrawal':'withdrawals','assessment':'assessments'}[kind]
                right_rid=len(parts)==3 and parts[0]==expected_folder and parts[1]==rid(key_value)
                add('RID_MISMATCH',right_rid,name)
                right_hash=len(parts)==3 and parts[2]==record.object_hash[7:]+'.json';add('PATH_HASH_MISMATCH',right_hash,name)
                ok=ok and right_rid and right_hash
                if key_value in (reg.get('author_key'),reg.get('steward_key')):
                    report.add('ROLE_KEY_REUSED','fail',name,detail='A reviewer signing key cannot be the author or steward signing key.')
                    ok=False
                if kind=='declaration':
                    complete=all(type(value.get(k)) is str and bool(value[k].strip()) for k in ('relationship_to_author','stake_in_result','prior_exposure')) and value.get('identity_disclosure') in ('real','pseudonym','anonymous') and type(value.get('credit_consent')) is bool
                    complete=complete and key_value!=reg.get('steward_key')
                    add('DECLARATION_MALFORMED',complete,name);ok=ok and complete
                    report.data['declarations'].append({k:value[k] for k in ('reviewer_key','relationship_to_author','stake_in_result','prior_exposure','identity_disclosure','credit_consent') if k in value}|{'basis':'declared by participant'})
            except (KeyError,ValueError,TypeError):report.add('KEY_MISMATCH','fail',name);ok=False
        if ok:valid[name]=record
    policy=parsed.get('policy.json');packet=parsed.get('packet.json');policy_ok=True;item_ids=set()
    for name,field in [('policy.json','policy_hash'),('packet.json','packet_hash')]:
        if name not in parsed:missing('DOCUMENT_MISSING',name)
        else:
            try:add('HASH_MISMATCH',canon.hash_value(parsed[name])==reg.get(field),name)
            except (ValueError,TypeError):report.add('CANON_INVALID','fail',name)
    try:
        assert type(policy) is dict and policy['judgment_options']==list(JUDGMENTS)
        assert all(type(policy[k]) is int and policy[k]>0 for k in ('min_locks','min_reveals','time_box_minutes'))
        assert policy['duplicate_policy']=='first_commit_per_reviewer_key' and policy['withdrawal_policy']=='retain_locks_count_valid_reveals'
        assert type(policy['disposition_required']) is bool
    except (AssertionError,KeyError,TypeError):policy_ok=False;report.add('POLICY_MALFORMED','fail','policy.json')
    report.policy=policy if policy_ok else None
    try:
        assert type(packet) is list and 0<len(packet)<=1000
        for item in packet:
            assert type(item) is dict and set(item)=={'id','evidence','candidate'}
            assert type(item['id']) is str and item['id'].strip() and item['id'] not in item_ids
            assert type(item['candidate']) is str and item['candidate'].strip()
            assert type(item['evidence']) is list and item['evidence'] and all(type(v) is str and v.strip() for v in item['evidence'])
            item_ids.add(item['id'])
    except (AssertionError,KeyError,TypeError):report.add('PACKET_MALFORMED','fail','packet.json')
    if 'withheld.json' not in parsed:missing('WITHHELD_MISSING','withheld.json')
    else:
        try:
            w=parsed['withheld.json'];assert type(w) is dict and set(w)=={'results','salt'}
            salt=w['salt'];assert type(salt) is str and re.fullmatch(r'[A-Za-z0-9_-]{43}',salt) and len(dsse.b64decode(salt))==32
            add('WITHHELD_COMMITMENT_MISMATCH',canon.hash_value(w)==reg.get('withheld_commitment'),'withheld.json')
        except (ValueError,AssertionError,KeyError,TypeError):report.add('WITHHELD_COMMITMENT_MISMATCH','fail','withheld.json')
    by_hash={r.object_hash:(name,r) for name,r in valid.items()}
    raw_log=[(name,record) for name,record in valid.items() if name.startswith('log/')]
    log=[]
    for name,record in raw_log:
        v=record.value
        if v['type']!='logentry' or type(v.get('seq')) is not int or v['seq']<1:report.add('LOG_CHAIN_BROKEN','fail',name)
        else:log.append((v['seq'],name,record))
    log.sort(key=lambda x:x[0]);previous=registration_hash;commits=[];first={};withdrawals={};ack=set();declared_keys=set();commitment_owners={}
    for expected,(seq,name,record) in enumerate(log,1):
        value=record.value;add('LOG_CHAIN_BROKEN',seq==expected and value.get('prev_entry_hash')==previous and name=='log/'+str(seq)+'.json',name)
        previous=record.object_hash;ref=value.get('ref_hash');kind=value.get('kind');referenced=by_hash.get(ref)
        if not referenced or kind not in ('declaration','commit','withdrawal') or referenced[1].value['type']!=kind:
            report.add('ACK_MISSING','fail',name);continue
        object_name,obj=referenced;ack.add(obj.object_hash);v=obj.value;k=v.get('reviewer_key')
        if kind=='declaration':declared_keys.add(k)
        elif kind=='withdrawal':withdrawals[k]='attested' if v.get('steward_attested') is True else 'reviewer-stated'
        else:
            try:leaf=canon.hash_bytes(v['commitment'])
            except (ValueError,KeyError):report.add('COMMIT_NOT_IN_TREE','fail',object_name);continue
            if k not in declared_keys:report.add('ACK_MISSING','fail',object_name,detail='A logged declaration must precede the commit.')
            owner=commitment_owners.get(v['commitment'])
            if owner is not None and owner!=k:
                report.add('COMMITMENT_REUSED_ACROSS_KEYS','fail',object_name,
                           detail='The same assessment commitment appears under different reviewer signing keys.')
            commitment_owners.setdefault(v['commitment'],k)
            commits.append((k,v['commitment'],object_name,seq))
            if k in first:report.add('DUPLICATE_COMMIT','fail',object_name)
            else:first[k]=(v['commitment'],len(commits)-1)
    for name,record in valid.items():
        if record.value['type'] in ('declaration','commit','withdrawal'):add('ACK_MISSING',record.object_hash in ack,name)
    leaves=[canon.hash_bytes(x[1]) for x in commits];root=merkle.root(leaves)
    close_record=valid.get('close.json');close=close_record.value if close_record else None
    if not close or close.get('type')!='close':missing('CLOSE_MISSING','close.json')
    else:
        matches=type(close.get('tree_size')) is int and close['tree_size']==len(commits) and type(close.get('locked_count')) is int and close['locked_count']==len(first) and close['tree_size']>=close['locked_count']
        matches=matches and close.get('tree_head')=='sha256:'+root.hex() and close.get('last_entry_hash')==previous and close.get('final_seq')==len(log) and 'status' not in close
        add('TREE_HEAD_MISMATCH',matches,'close.json')
        try:add('WITHDRAWAL_MISMATCH',{x['reviewer_key'] for x in close['withdrawn']}==set(withdrawals),'close.withdrawn')
        except (KeyError,TypeError):report.add('WITHDRAWAL_MISMATCH','fail','close.withdrawn')
    revealed={};concerns=set()
    for name,record in valid.items():
        v=record.value
        if v['type']!='assessment':continue
        k=v.get('reviewer_key');commitment=record.object_hash
        indices=[i for i,x in enumerate(commits) if x[0]==k and x[1]==commitment]
        add('COMMIT_NOT_IN_TREE',bool(indices),name)
        try:
            items=v['items'];assert type(items) is list and len(items)==len(item_ids)
            assert {x['id'] for x in items}==item_ids and len({x['id'] for x in items})==len(items)
            local=set()
            for item in items:
                assert set(item)=={'id','judgment','reasoning','concerns'} and item['judgment'] in JUDGMENTS
                assert type(item['reasoning']) is str and item['reasoning'].strip() and type(item['concerns']) is list
                for concern in item['concerns']:
                    assert type(concern) is dict and set(concern)=={'cid','text'} and type(concern['cid']) is str and concern['cid'].strip() and type(concern['text']) is str and concern['text'].strip()
                    ref=(commitment,item['id'],concern['cid']);assert ref not in local;local.add(ref)
            answer_ok=True
        except (KeyError,AssertionError,TypeError):answer_ok=False;local=set();report.add('ASSESSMENT_MALFORMED','fail',name)
        proof_name='proofs/'+rid(k)+'/'+commitment[7:]+'.json';proof=parsed.get(proof_name)
        proof_ok=False
        try:
            assert type(proof) is dict and set(proof)=={'leaf_index','tree_size','hashes'} and type(proof['hashes']) is list
            proof_ok=bool(indices) and proof['leaf_index'] in indices and proof['tree_size']==len(commits) and merkle.inclusion(canon.hash_bytes(commitment),proof['leaf_index'],proof['tree_size'],[canon.hash_bytes(x) for x in proof['hashes']],root)
        except (KeyError,ValueError,TypeError,AssertionError):pass
        add('INCLUSION_PROOF_INVALID',proof_ok,proof_name)
        if indices and answer_ok and proof_ok:
            concerns.update(local)
            if k in first and first[k][0]==commitment:revealed[k]=record
    for k,(commitment,index) in first.items():
        present=k in revealed
        report.data['reviewers'].append(dict(reviewer_key=k,commitment=commitment,revealed=present,withdrawn=k in withdrawals,withdrawal_basis=withdrawals.get(k)))
        if not present:missing('REVEAL_MISSING',commitment)
        if k in withdrawals:
            if withdrawals[k]=='attested':
                report.data['reviewers'][-1]['withdrawal_attestor']=reg.get('steward_key')
                report.add('WITHDRAWAL_STEWARD_ATTESTED','pass',k,
                    detail='Steward signed this withdrawal allegation; reviewer consent is not established.')
            else:
                report.add('WITHDRAWN','pass',k,detail='Withdrawal is retained; it does not remove the lock.')
    locked=len(first);reveals=len(revealed);report.data.update(locked_count=locked,tree_size=len(commits),verified_reveals=reveals)
    if policy_ok:
        add('LOCKS_BELOW_MINIMUM',locked>=policy['min_locks'],'round')
        add('REVEALS_BELOW_MINIMUM',reveals>=policy['min_reveals'],'round')
        report.data['round_status']='complete' if locked>=policy['min_locks'] and reveals>=policy['min_reveals'] else 'incomplete'
    else:report.add('COUNTING_NOT_CHECKED','not_checked','round')
    dispositions={}
    for name,record in valid.items():
        if record.value['type']!='disposition':continue
        value=record.value
        try:
            ref=value['concern_ref'];ref=(ref['assessment_commitment'],ref['item_id'],ref['cid'])
            assert all(type(x) is str for x in ref)
            if ref not in concerns:report.add('DISPOSITION_UNKNOWN_CONCERN','fail',name)
            if ref in dispositions:report.add('DUPLICATE_DISPOSITION','fail',name)
            dispositions[ref]=value
            add('DISPOSITION_NO_REASON',type(value.get('reason')) is str and bool(value['reason'].strip()),name)
            add('DISPOSITION_MALFORMED',value.get('status') in ('adopted','under_examination','unresolved','declined') and (value['status']!='adopted' or type(value.get('change_ref')) is str and bool(value['change_ref'].strip())),name)
        except (AssertionError,TypeError,KeyError):report.add('DISPOSITION_MALFORMED','fail',name)
    if policy_ok and policy['disposition_required']:
        for ref in sorted(concerns):
            if ref not in dispositions:missing('DISPOSITION_MISSING','/'.join(ref))
    elif policy_ok:
        report.coverage_notice('disposition_presence','policy.json','skipped','policy_disabled',len(concerns),0,
            'Disposition-presence checking skipped: disposition_required=false. No claim that dispositions are complete.')
    targets={x for x in (registration_hash,close_record.object_hash if close_record else None,record_hash) if x}
    for name,descriptor in parsed.items():
        if not name.startswith('anchors/'):continue
        if type(descriptor) is not dict:
            report.coverage_notice('anchor_descriptor',name,'skipped','descriptor_not_object',None,0,
                'Entry skipped by current descriptor enumeration: expected an object. This notice does not assess required-target coverage.')
        elif type(descriptor.get('target')) is not str or descriptor['target'] not in targets:
            report.coverage_notice('anchor_descriptor',name,'skipped','target_not_requested',None,0,
                "Descriptor skipped: target is outside this invocation's required target set. Required target checks are reported separately.")
    anchor_metadata={}
    for target in sorted(targets):
        observed_types=set()
        confirmed_types=set()
        qualified={}
        # Descriptor authority labels are unauthenticated because anchors/ is excluded
        # from record_hash. Never use the label to satisfy an independence gate.
        for name,descriptor in parsed.items():
            if not name.startswith('anchors/') or type(descriptor) is not dict or descriptor.get('target')!=target:continue
            kind=descriptor.get('type')
            if kind=='git':report.add('GIT_PUBLICATION_TIME_IGNORED','not_checked',name,detail='Git dates have no time weight.');continue
            if kind=='archive':report.add('OPTIONAL_ANCHOR','not_checked',name,detail='Archive evidence does not count for this profile.');continue
            if kind not in ('ots','rfc3161'):report.add('ANCHOR_INVALID','fail',name);continue
            if not all(type(descriptor.get(k)) is str and descriptor[k].strip() for k in ('authority','proof','evidence_format','validation_backend')) or type(descriptor.get('confirmation_policy')) is not dict:
                report.add('ANCHOR_INVALID','fail',name);continue
            observed_types.add(kind)
            evidence=anchor_evidence.inspect(descriptor,files,network=network,
                bitcoin_rpc=bitcoin_rpc,tsa_ca=tsa_ca,tsa_policy=tsa_policy,
                tsa_untrusted=tsa_untrusted)
            status,detail=evidence["status"],evidence["detail"]
            details={k:descriptor[k] for k in ('type','authority','target','evidence_format','validation_backend','confirmation_policy')}
            details.update(status=status,detail=detail,
                           authority_basis='proof-derived' if evidence.get('authority') else 'descriptor label only; unauthenticated')
            if evidence.get('authority'):
                details.update(verified_authority=evidence['authority'],
                               attested_time=evidence['attested_time'],
                               evidence_basis=evidence['basis'])
                qualified.setdefault(kind,[]).append(evidence)
            report.data['anchors'].append(details)
            mapping={'confirmed':('ANCHOR_CONFIRMED','pass'),'pending':('ANCHOR_PENDING','pending'),'invalid':('ANCHOR_INVALID','fail'),'unverifiable_offline':('ANCHOR_UNVERIFIABLE_OFFLINE','unverifiable'),'missing':('ANCHOR_MISSING','missing')}
            code,state=mapping[status];report.add(code,state,name,detail)
            if status=='confirmed':confirmed_types.add(kind)
        if not {'ots','rfc3161'}<=observed_types:
            missing('ANCHOR_MISSING',target)
        # A1: only independently proven confirmations can satisfy the target gate.
        # A3: confirmation itself is insufficient while the proof authority identity
        # is not authenticated. Do not use descriptor strings for identity.
        if not {'ots','rfc3161'}<=confirmed_types:
            report.add('ANCHOR_GATE_UNCONFIRMED','pending',target,detail='Required anchor types are not both confirmed for this target.')
        elif not all(qualified.get(kind) for kind in ('ots','rfc3161')):
            report.add('ANCHOR_AUTHORITY_NOT_CHECKED','not_checked',target,detail='Proof-derived authorities are not available; declared labels cannot establish independence.')
        else:
            identities={e['authority'] for kind in ('ots','rfc3161') for e in qualified[kind]}
            if len(identities)<2:
                report.add('ANCHOR_NOT_INDEPENDENT','fail',target,detail='Distinct verified proof authorities are required.')
            else:
                report.add('ANCHOR_AUTHORITY_CONFIRMED','pass',target,
                           detail='Two proof-derived identities; trust assumptions are recorded per anchor.')
        anchor_metadata[target]=qualified
    # Compare only authenticated proof-reported times, never signed clock strings.
    reg_times=[e.get('attested_time') for group in anchor_metadata.get(registration_hash,{}).values() for e in group]
    cls_hash=close_record.object_hash if close_record else None
    close_times=[e.get('attested_time') for group in anchor_metadata.get(cls_hash,{}).values() for e in group]
    if reg_times and close_times and all(reg_times) and all(close_times):
        try:
            from datetime import datetime
            latest_registration=max(datetime.fromisoformat(x.replace('Z','+00:00')) for x in reg_times)
            earliest_close=min(datetime.fromisoformat(x.replace('Z','+00:00')) for x in close_times)
            if latest_registration<=earliest_close:
                report.add('ANCHOR_ORDER_ATTESTED','pass','registration -> close',
                           detail='Proof-reported registration time <= close time; does not prove packet release order.')
            else:
                report.add('ANCHOR_ORDER_INCONSISTENT','fail','registration -> close',
                           detail='Proof-reported registration time is later than a close time.')
        except (ValueError,TypeError):
            report.add('ANCHOR_ORDER_NOT_CHECKED','not_checked','registration -> close',
                       detail='Verified attested times were not comparable.')
    else:
        report.add('ANCHOR_ORDER_NOT_CHECKED','not_checked','registration -> close',detail='Verified attested times for registration and close have not been established.')
    if len(targets)!=3:report.add('ANCHOR_TARGET_NOT_CHECKED','not_checked','targets')
    if not registries:report.add('REGISTRY_NOT_CHECKED','not_checked','registries')
    for registry in registries or []:
        try:
            assert type(registry) is dict and type(registry['source']) is str and type(registry['work_id']) is str and type(registry['prior_rounds']) is list and all(type(x) is str for x in registry['prior_rounds'])
            if registry['work_id']!=reg.get('work_id'):
                report.coverage_notice('prior_round_membership',registry['source'],'skipped','work_id_mismatch',len(registry['prior_rounds']),0,
                    'Snapshot skipped: work_id does not match this registration.')
                continue
            report.data['registry_coverage'].append({'source':registry['source'],'basis':'supplied snapshot; completeness outside this snapshot is not established'})
            if not registry['prior_rounds']:
                report.coverage_notice('prior_round_membership',registry['source'],'zero_candidates','matching_snapshot_empty',0,0,
                    'Matching supplied registry snapshot contains zero prior-round entries; zero membership comparisons performed. Coverage outside this snapshot is unknown.')
            for round_id in registry['prior_rounds']:add('PRIOR_ROUND_UNLISTED',round_id in reg.get('prior_rounds',[]),registry['source'])
        except (AssertionError,KeyError,TypeError):report.add('REGISTRY_MALFORMED','fail','registry')
    if registries and not report.data['registry_coverage']:report.add('REGISTRY_NOT_CHECKED','not_checked','registries')
    return report.finish()
