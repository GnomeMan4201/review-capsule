#!/usr/bin/env python3
"""Throwaway synthetic OTS collection. Run with the pinned verifier installed.

Calendar submission/upgrade is opt-in via `collect`; prepare has no network.
No calendar response is treated as Bitcoin confirmation.
"""
import argparse,base64,hashlib,io,json,os,shutil,subprocess,sys,time,zipfile
from datetime import datetime,timezone
from pathlib import Path
from rr import canon,dsse
from rr.verify import verify_bundle

PIN='d54432f3e4c67f11ea53c16ebb383c1aec1f9224'
CALENDARS=['https://a.pool.opentimestamps.org','https://b.pool.opentimestamps.org']
UPGRADE_CALENDARS={'https://alice.btc.calendar.opentimestamps.org','https://bob.btc.calendar.opentimestamps.org'}
NAMES=('registration','close','record')

def save_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def same_or_new(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        if path.read_bytes()!=raw:raise ValueError('Existing target bytes differ: '+path.name)
    else:path.write_bytes(raw)
def digest(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()

def prepare(source,root):
    """Extract the pinned public fixture and retain the exact three preimages."""
    source=Path(source);root=Path(root);root.mkdir(parents=True,exist_ok=True)
    bundle=root/'bundle'
    if bundle.exists():shutil.rmtree(bundle)
    bundle.mkdir()
    raw=base64.b64decode((source/'examples/synthetic-round.zip.b64').read_bytes(),validate=False)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        for info in z.infolist():
            if info.is_dir():continue
            p=bundle/info.filename
            if not p.resolve().is_relative_to(bundle.resolve()) or info.file_size>1024*1024:raise ValueError('Fixture ZIP path or size mismatch.')
            p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(z.read(info))
    manifest=canon.loads((bundle/'manifest.json').read_bytes())
    projection=canon.dumps({'files':manifest['files'],'spec':manifest['spec']})
    preimages={'registration':(bundle/'registration.json').read_bytes(),'close':(bundle/'close.json').read_bytes(),'record':projection}
    reg=dsse.decode(preimages['registration']);close=dsse.decode(preimages['close'])
    if close.value['registration_hash']!=reg.object_hash or digest(projection)!=manifest['record_hash']:raise ValueError('Fixture target binding mismatch.')
    for entry in manifest['files']:
        if digest((bundle/entry['path']).read_bytes())!=entry['sha256']:raise ValueError('Fixture inventory mismatch.')
    rows=[]
    for name in NAMES:
        target=root/'targets'/(name+'.preimage');same_or_new(target,preimages[name])
        rows.append(dict(name=name,target=digest(preimages[name]),preimage='targets/'+name+'.preimage',byte_length=len(preimages[name]),meaning='exact file bytes' if name!='record' else 'canon-v1 manifest projection, excluding anchors and manifest itself'))
    value=dict(source_pin=PIN,scope='throwaway synthetic fixture; no research or real participants',hash_algorithm='SHA-256',targets=rows)
    same_or_new(root/'targets.json',(json.dumps(value,indent=2)+'\n').encode())
    return bundle,value

def inspect_proof(raw,target):
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.serialize import BytesDeserializationContext
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.notary import PendingAttestation,BitcoinBlockHeaderAttestation
    detached=DetachedTimestampFile.deserialize(BytesDeserializationContext(raw))
    if not isinstance(detached.file_hash_op,OpSHA256) or detached.file_digest!=bytes.fromhex(target[7:]):raise ValueError('OTS file digest/algorithm does not match target.')
    attestations=list(detached.timestamp.all_attestations())
    return dict(proof_sha256=digest(raw),calendar_references=[a.uri for _,a in attestations if isinstance(a,PendingAttestation)],bitcoin_attestation_heights=[a.height for _,a in attestations if isinstance(a,BitcoinBlockHeaderAttestation)],confirmation_basis='not established by parsing; requires configured mainnet RPC')

def command(argv,timeout=150):
    start=time.monotonic()
    try:
        run=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
        return dict(argv=argv,exit_code=run.returncode,stdout=run.stdout,stderr=run.stderr,elapsed_seconds=round(time.monotonic()-start,3))
    except subprocess.TimeoutExpired as e:
        def text(v):return v.decode(errors='replace') if isinstance(v,bytes) else v or ''
        return dict(argv=argv,exit_code=None,stdout=text(e.stdout),stderr=text(e.stderr),error='command timeout',elapsed_seconds=round(time.monotonic()-start,3))

def collect(source,root,*,allow_rpc=False):
    root=Path(root);bundle,targets=prepare(source,root)
    now=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    run_id=os.environ.get('GITHUB_RUN_ID','local')+'-'+os.environ.get('GITHUB_RUN_ATTEMPT','1')
    journal=dict(source_pin=PIN,advisory_collected_at=now,github_run_id=run_id,calendars=CALENDARS,commands=[],proofs={},rpc=dict(used=False,operator=None,trust_assumption='No operator-chosen node was used. Calendar status cannot satisfy the anchor gate.'))
    ots=shutil.which('ots')
    if not ots:raise ValueError('opentimestamps-client executable is unavailable.')
    journal['stamp_calendars']=CALENDARS
    journal['upgrade_policy']='Use embedded allowlisted calendar URIs; no -c pool overrides.'
    journal['upgrade_calendars']=[]
    existing=[];missing=[]
    for row in targets['targets']:
        p=root/row['preimage'];proof=Path(str(p)+'.ots')
        if proof.exists():
            raw=proof.read_bytes();info=inspect_proof(raw,row['target'])
            if any(uri not in UPGRADE_CALENDARS for uri in info['calendar_references']):raise ValueError('Unexpected embedded calendar; inspect before contacting it.')
            journal['upgrade_calendars']=sorted(set(journal['upgrade_calendars'])|set(info['calendar_references']))
            same_or_new(root/'proof-history'/(digest(raw)[7:]+'.ots'),raw)
            existing.append(proof)
        else:missing.append(p)
    options=[x for url in CALENDARS for x in ('-c',url)]
    if missing:
        journal['commands'].append(command([ots,'stamp',*options,'-m','2','--timeout','20',*map(str,missing)]))
    # The client exits on an incomplete first file. Invoke once per proof so
    # one pending calendar response does not skip the other two targets.
    for proof in existing:
        journal['commands'].append(command([ots,'upgrade','--timeout','20',str(proof)]))
    for row in targets['targets']:
        name=row['name'];p=root/row['preimage'];proof=Path(str(p)+'.ots')
        if not proof.exists():
            # Remove the local synthetic placeholder from the *derived* bundle.
            (bundle/'anchors'/(name+'.ots')).unlink(missing_ok=True)
            journal['proofs'][name]={'status':'missing','detail':'No real calendar proof file was produced.'};continue
        raw=proof.read_bytes();info=inspect_proof(raw,row['target']);journal['proofs'][name]=info
        same_or_new(root/'proof-history'/(info['proof_sha256'][7:]+'.ots'),raw)
        same_or_new(root/'initial'/(name+'.ots'),raw) if name in [x.stem for x in missing] else None
        # ASCII mirror is transport only; original binary bytes are also committed.
        Path(str(proof)+'.b64').write_text(base64.b64encode(raw).decode()+'\n')
        (bundle/'anchors'/(name+'.ots')).write_bytes(raw)
        descriptor=canon.loads((bundle/'anchors'/(name+'-ots.json')).read_bytes())
        descriptor['authority']='bitcoin-mainnet (declared; proof-derived identity required)'
        descriptor['validation_backend']='none configured' if not allow_rpc else 'operator-configured Bitcoin Core RPC; execution requires a Bitcoin attestation'
        (bundle/'anchors'/(name+'-ots.json')).write_bytes(canon.dumps(descriptor))
    rpc=os.environ.get('RR_BITCOIN_RPC') if allow_rpc else None
    operator=os.environ.get('RR_BITCOIN_RPC_OPERATOR') if allow_rpc else None
    if allow_rpc and (not rpc or not operator):raise ValueError('RPC verification requires an explicitly configured URL and operator label.')
    if rpc:journal['rpc']=dict(used=True,operator=operator,trust_assumption='The configured RPC operator supplies the mainnet tip and block headers; its node data are a trust assumption.')
    keys=canon.loads((Path(source)/'examples/fixture-metadata.json').read_bytes())
    report=verify_bundle(bundle,expected_author_key=keys['author_key'],expected_steward_key=keys['steward_key'],network=bool(rpc),bitcoin_rpc=rpc)
    journal['verifier_exit_code']=report['exit_code'];journal['verifier_summary']=report['summary']
    journal['not_run']=['Strict production TSA qualification (no external CA/signer/policy selection)','Packet release chronology / first disclosure observation']
    if not rpc:journal['not_run'].append('Bitcoin RPC verification and six-confirmation check; no node was selected')
    save_json(root/'report.json',report);save_json(root/'runs'/(run_id+'.json'),journal)
    (root/'summary.txt').write_text(report['summary']+'\nrrverify exit_code='+str(report['exit_code'])+'\n')
    # A literal copy of the machine-readable verifier output is preserved above.
    print(json.dumps(report,ensure_ascii=False,indent=2));print('rrverify exit_code='+str(report['exit_code']),file=sys.stderr)
    return 1 if any(x.get('status')=='missing' for x in journal['proofs'].values()) or any(x['exit_code'] not in (0,) for x in journal['commands']) else 0

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=('prepare','collect'));p.add_argument('--source',type=Path,required=True);p.add_argument('--run-root',type=Path,required=True);p.add_argument('--verify-rpc',action='store_true');args=p.parse_args()
    try:
        if args.command=='prepare':_,value=prepare(args.source,args.run_root);print(json.dumps(value,indent=2));return 0
        return collect(args.source,args.run_root,allow_rpc=args.verify_rpc)
    except (OSError,ValueError,KeyError,TypeError) as e:print('Evidence collection failed: '+str(e),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
