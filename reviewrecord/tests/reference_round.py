# Produce public synthetic round fixtures; Python 3.12+, cryptography/OpenTimestamps [needs Linux runner].
"""Test/vector reference only: never creates or accepts participant keys."""
import base64,hashlib,json,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from vector_reference import canon_input,tree,proof

def canon(x):return canon_input(json.dumps(x,ensure_ascii=False).encode())
def h(b):return 'sha256:'+hashlib.sha256(b).hexdigest()
def key(role):return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(('PUBLIC-SYNTHETIC-ONLY:'+role).encode()).digest())
def pub(role):return 'ed25519:'+base64.urlsafe_b64encode(key(role).public_key().public_bytes_raw()).decode().rstrip('=')
def rid(k):return 'r-'+hashlib.sha256(k.encode()).hexdigest()[:16]
def envelope(value,role):
    payload=canon(value);kind=('application/vnd.reviewrecord.'+value['type']+'.v1+json').encode()
    pae=b'DSSEv1 '+str(len(kind)).encode()+b' '+kind+b' '+str(len(payload)).encode()+b' '+payload
    return canon(dict(payloadType=kind.decode(),payload=base64.b64encode(payload).decode(),signatures=[dict(keyid=pub(role),sig=base64.b64encode(key(role).sign(pae)).decode())]))
def manifest(folder):
    files=[{'path':p.relative_to(folder).as_posix(),'sha256':h(p.read_bytes())} for p in sorted(folder.rglob('*')) if p.is_file() and p.name!='manifest.json' and p.relative_to(folder).parts[0]!='anchors']
    projection={'files':files,'spec':'0.2.2'}
    (folder/'manifest.json').write_bytes(canon(projection|{'record_hash':h(canon(projection))}))
    return h(canon(projection))
def create(folder,prior_rounds=None,duplicate=False):
    from opentimestamps.core.timestamp import DetachedTimestampFile,Timestamp
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.serialize import BytesSerializationContext
    folder.mkdir(parents=True,exist_ok=True)
    limits=(ROOT/'spec/limits.txt').read_text().removesuffix('\n')
    def write(name,data):
        p=folder/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);return h(data)
    policy=dict(judgment_options=['established','partly_established','not_established','uncertain','question_needs_fixing'],min_locks=2,min_reveals=2,time_box_minutes=20,duplicate_policy='first_commit_per_reviewer_key',withdrawal_policy='retain_locks_count_valid_reveals',disposition_required=True)
    packet=[dict(id='item-1',evidence=['A stipulated record states that Pump K was serviced Monday.'],candidate='The record states that Pump K was serviced Monday.')]
    packet_hash=write('packet.json',canon(packet));policy_hash=write('policy.json',canon(policy))
    withheld=dict(results={'item-1':'established'},salt=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('='))
    write('withheld.json',canon(withheld));write('limits.txt',(limits+'\n').encode())
    registration=dict(type='registration',spec='0.2.2',canon='canon-v1',round_id='synthetic-round-1',work_id='synthetic-work',author_key=pub('author'),steward_key=pub('steward'),steward_is_author_operator=True,limits=limits,packet_hash=packet_hash,policy_hash=policy_hash,withheld_commitment=h(canon(withheld)),reviewers_target=3,deadline='2026-11-30T12:00:00Z',prior_rounds=['synthetic-prior-round'] if prior_rounds is None else prior_rounds,registered_at='2026-11-01T12:00:00Z')
    registration_hash=write('registration.json',envelope(registration,'author'));log=[];commits=[];concerns=[]
    def signed(object_type,role,**fields):return envelope(dict(type=object_type,round_id=registration['round_id'],registration_hash=registration_hash,**fields),role)
    def append(kind,ref_hash):
        seq=len(log)+1;entry=signed('logentry','steward',seq=seq,kind=kind,ref_hash=ref_hash,prev_entry_hash=log[-1] if log else registration_hash)
        log.append(write('log/'+str(seq)+'.json',entry))
    for role in ('reviewer-a','reviewer-b','reviewer-c'):
        k=pub(role);r=rid(k)
        d=signed('declaration',role,reviewer_key=k,relationship_to_author='none',stake_in_result='none',prior_exposure='none',identity_disclosure='pseudonym',credit_consent=False)
        digest=h(d);write('declarations/'+r+'/'+digest[7:]+'.json',d);append('declaration',digest)
        a=signed('assessment',role,reviewer_key=k,items=[dict(id='item-1',judgment='established',reasoning='The candidate describes only what the supplied record states.',concerns=[{'cid':'c1','text':'Keep the stipulated authenticity limitation explicit.'}])],locked_at='2026-11-01T13:00:00Z')
        commitment=h(a);write('assessments/'+r+'/'+commitment[7:]+'.json',a)
        c=signed('commit',role,reviewer_key=k,commitment=commitment);digest=h(c)
        write('commits/'+r+'/'+digest[7:]+'.json',c);append('commit',digest);commits.append((r,commitment))
        if duplicate and role=='reviewer-a':append('commit',digest);commits.append((r,commitment))
        concerns.append((commitment,'item-1','c1'))
    withdrawal=signed('withdrawal','reviewer-a',reviewer_key=pub('reviewer-a'),reason='Synthetic withdrawal; reviewer chooses to publish their valid reveal anyway.')
    wh=h(withdrawal);write('withdrawals/'+rid(pub('reviewer-a'))+'/'+wh[7:]+'.json',withdrawal);append('withdrawal',wh)
    leaves=[bytes.fromhex(c[7:]) for _,c in commits]
    close=signed('close','steward',final_seq=len(log),last_entry_hash=log[-1],tree_size=len(leaves),tree_head='sha256:'+tree(leaves).hex(),locked_count=3,withdrawn=[{'reviewer_key':pub('reviewer-a'),'reason':'Synthetic withdrawal'}],closed_at='2026-11-01T14:00:00Z')
    close_hash=write('close.json',close)
    for index,(r,c) in enumerate(commits):write('proofs/'+r+'/'+c[7:]+'.json',canon(dict(leaf_index=index,tree_size=len(leaves),hashes=['sha256:'+v.hex() for v in proof(leaves,index)])))
    for index,(commitment,item,cid) in enumerate(concerns):write('dispositions/'+str(index+1)+'.json',signed('disposition','author',concern_ref=dict(assessment_commitment=commitment,item_id=item,cid=cid),status='under_examination',reason='Synthetic concern retained for the process demonstration.'))
    record_hash=manifest(folder)
    targets={'registration':registration_hash,'close':close_hash,'record':record_hash}
    for name,target in targets.items():
        timestamp=Timestamp(bytes.fromhex(target[7:]));timestamp.attestations.add(PendingAttestation('https://example.invalid/synthetic-calendar'))
        detached=DetachedTimestampFile(OpSHA256(),timestamp);ctx=BytesSerializationContext();detached.serialize(ctx)
        write('anchors/'+name+'.ots',ctx.getbytes())
        write('anchors/'+name+'-ots.json',canon(dict(type='ots',authority='bitcoin',target=target,proof='anchors/'+name+'.ots',evidence_format='ots-detached',validation_backend='Bitcoin Core',confirmation_policy={'min_confirmations':6})))
        # Explicit unverified evidence placeholder. A configured adapter must reject it.
        write('anchors/'+name+'.tsr',b'SYNTHETIC-UNVERIFIED-RFC3161-PLACEHOLDER\n')
        write('anchors/'+name+'-tsa.json',canon(dict(type='rfc3161',authority='FreeTSA.org',target=target,proof='anchors/'+name+'.tsr',evidence_format='rfc3161-response',validation_backend='OpenSSL',confirmation_policy={'ca_required':True})))
    return dict(author_key=pub('author'),steward_key=pub('steward'),registration_hash=registration_hash,round_id=registration['round_id'],work_id=registration['work_id'])
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description='Write public synthetic reference fixture; never participant data.');p.add_argument('--write',action='store_true',required=True);p.add_argument('directory',type=Path);args=p.parse_args()
    metadata=create(args.directory);(args.directory.parent/'fixture-metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print('Synthetic reference round written; provisional anchors are not confirmations.')
