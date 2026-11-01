#!/usr/bin/env python3
"""Synthetic-only explorer comparison and real matching FreeTSA requests.

Explorer responses are not node confirmation. Service-sourced CA material is
not an approved production pin policy. This command cannot qualify either.
"""
import argparse,base64,hashlib,io,json,shutil,subprocess,time,zipfile
from datetime import datetime,timezone
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import URLError,HTTPError
from opentimestamps.core.timestamp import DetachedTimestampFile
from opentimestamps.core.serialize import BytesDeserializationContext
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from rr import canon
from rr.verify import verify_bundle
from rr.tsa_der import request_imprint,token_tstinfo
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtensionOID,ExtendedKeyUsageOID

EXPLORERS=('https://blockstream.info/api','https://mempool.space/api')
TSA='https://freetsa.org/tsr'
def sha(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()
def save(path,data):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
def jsave(path,data):save(path,(json.dumps(data,indent=2)+'\n').encode())
def fetch(url,data=None):
    req=Request(url,data=data,headers={'User-Agent':'ReviewRecord-Synthetic-Demo/0.2.2','Content-Type':'application/timestamp-query'} if data is not None else {'User-Agent':'ReviewRecord-Synthetic-Demo/0.2.2'})
    with urlopen(req,timeout=25) as response:
        raw=response.read(1024*1024+1)
        if len(raw)>1024*1024:raise ValueError('Response exceeds bound.')
        return raw,dict(url=url,final_url=response.geturl(),http_status=response.status,body_sha256=sha(raw),bytes=len(raw))
def command(argv):
    r=subprocess.run([str(x) for x in argv],capture_output=True,text=True,timeout=25)
    return dict(argv=[str(x) for x in argv],exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr)
def header_binding(header_hex,block_hash,internal_root):
    raw=bytes.fromhex(header_hex.strip())
    if len(raw)!=80:raise ValueError('Expected an 80-byte Bitcoin header.')
    computed=hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
    return dict(header_hash_matches= computed==block_hash,header_merkle_root_matches=raw[36:68]==internal_root,header_merkle_root_display=raw[36:68][::-1].hex(),pow_or_chain_validation_run=False)
def explorer(base,height,internal_root,out):
    row=dict(source=base,trust_basis='Explorer-operated API; not an operator-chosen Bitcoin node',status='unavailable',responses=[])
    try:
        raw,meta=fetch(base+'/block-height/'+str(height));row['responses'].append(meta);block_hash=raw.decode().strip()
        if len(block_hash)!=64 or any(c not in '0123456789abcdef' for c in block_hash):raise ValueError('Explorer block hash encoding invalid.')
        save(out/'block-hash.txt',raw)
        raw,meta=fetch(base+'/block/'+block_hash);row['responses'].append(meta);save(out/'block.json',raw);block=json.loads(raw)
        raw,meta=fetch(base+'/block/'+block_hash+'/header');row['responses'].append(meta);save(out/'header.hex',raw);binding=header_binding(raw.decode(),block_hash,internal_root)
        raw,meta=fetch(base+'/blocks/tip/height');row['responses'].append(meta);save(out/'tip-height.txt',raw);tip=int(raw)
        raw,meta=fetch(base+'/block/'+block_hash+'/status');row['responses'].append(meta);save(out/'block-status.json',raw);status=json.loads(raw)
        depth=tip-height+1
        matches=block.get('height')==height and block.get('id')==block_hash and block.get('merkle_root')==internal_root[::-1].hex() and all(binding[k] for k in ('header_hash_matches','header_merkle_root_matches'))
        row.update(status='matching explorer data' if matches else 'mismatch',block_hash=block_hash,reported_height=block.get('height'),reported_merkle_root=block.get('merkle_root'),reported_tip=tip,reported_depth=depth,explorer_reports_best_chain=status.get('in_best_chain'),explorer_reported_depth_at_least_six=depth>=6,**binding)
    except (OSError,ValueError,KeyError,URLError) as e:row.update(error_type=type(e).__name__,error=str(e))
    return row

def tsa_request(name,target,preimage,out,ca,signer):
    row=dict(target=target,evidence_state='no token obtained',production_pin_policy='not selected',commands=[])
    folder=out/name;folder.mkdir(parents=True)
    query=folder/'request.tsq';response=folder/'response.tsr';token=folder/'token.der'
    try:
        if sha(preimage)!=target:raise ValueError('Preimage/target mismatch.')
        row['commands'].append(command(['openssl','ts','-query','-digest',target[7:],'-sha256','-cert','-out',query]))
        if row['commands'][-1]['exit_code']!=0:raise ValueError('Request creation failed.')
        if request_imprint(query.read_bytes())!=bytes.fromhex(target[7:]):raise ValueError('Request imprint mismatch.')
        raw,meta=fetch(TSA,query.read_bytes());save(response,raw);row['http']=meta
        row['commands'].append(command(['openssl','ts','-reply','-in',response,'-token_out','-out',token]))
        row['commands'].append(command(['openssl','ts','-reply','-in',response,'-text']))
        if not token.exists():raise ValueError('No parsable RFC3161 token returned.')
        info=token_tstinfo(token.read_bytes());row.update(evidence_state='real token received',token_imprint='sha256:'+info['imprint'].hex(),imprint_matches_target=info['imprint']==bytes.fromhex(target[7:]),reported_policy_oid=info['policy_oid'],reported_gen_time=info['attested_time'],request_sha256=sha(query.read_bytes()),response_sha256=sha(raw))
        certs=pkcs7.load_der_pkcs7_certificates(token.read_bytes());fps=[]
        for cert in certs:
            try:
                if ExtendedKeyUsageOID.TIME_STAMPING in cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value:fps.append(cert.fingerprint(hashes.SHA256()).hex())
            except x509.ExtensionNotFound:pass
        row['token_tsa_signer_sha256']=fps
        positive=command(['openssl','ts','-verify','-in',response,'-queryfile',query,'-CAfile',ca,'-untrusted',signer]);row['commands'].append(positive)
        row['request_signature_chain_nonce_match_under_service_ca']=positive['exit_code']==0
        wrong_target=command(['openssl','ts','-verify','-in',response,'-digest','00'*32,'-CAfile',ca,'-untrusted',signer]);row['commands'].append(wrong_target);row['wrong_target_rejected']=wrong_target['exit_code']!=0
        other=folder/'different-nonce.tsq';row['commands'].append(command(['openssl','ts','-query','-digest',target[7:],'-sha256','-cert','-out',other]))
        if request_imprint(other.read_bytes())!=bytes.fromhex(target[7:]):raise ValueError('Negative-control request target mismatch.')
        wrong_nonce=command(['openssl','ts','-verify','-in',response,'-queryfile',other,'-CAfile',ca,'-untrusted',signer]);row['commands'].append(wrong_nonce);row['different_nonce_rejected']=wrong_nonce['exit_code']!=0
        row['trust_limit']='CA and signer files came from this same TSA over HTTPS. No independent pin governance, revocation or clock qualification was performed.'
    except (OSError,ValueError,KeyError,URLError,subprocess.TimeoutExpired) as e:row.update(error_type=type(e).__name__,error=str(e))
    return row

def run(root,source,out):
    if out.exists():raise ValueError('Evidence output exists; retain original bytes.')
    out.mkdir(parents=True);targets=json.loads((root/'targets.json').read_bytes());roots=set();before={}
    for name in ('registration','close','record'):
        path=root/'targets'/(name+'.preimage.ots');before[name]=sha(path.read_bytes())
        detached=DetachedTimestampFile.deserialize(BytesDeserializationContext(path.read_bytes()))
        for msg,a in detached.timestamp.all_attestations():
            if isinstance(a,BitcoinBlockHeaderAttestation):roots.add((a.height,msg))
    if len(roots)!=1:raise ValueError('Expected a common retained attestation height/root.')
    height,internal_root=roots.pop()
    evidence=dict(scope='Throwaway synthetic evidence only',advisory_run_time=datetime.now(timezone.utc).isoformat(),source_pin=targets['source_pin'],ots_height=height,ots_internal_merkle_root=internal_root.hex(),ots_display_merkle_root=internal_root[::-1].hex(),bitcoin_rpc_backend='none configured',node_header_depth_gate_run=False,explorers=[],tsa={})
    for base in EXPLORERS:evidence['explorers'].append(explorer(base,height,internal_root,out/'explorers'/base.split('/')[2]))
    certdir=out/'service-sourced-certificates';certdir.mkdir()
    certs_ok=True;evidence['certificate_sources']=[]
    for name in ('cacert.pem','tsa.crt'):
        try:
            raw,meta=fetch('https://freetsa.org/files/'+name);save(certdir/name,raw);cert=x509.load_pem_x509_certificate(raw)
            evidence['certificate_sources'].append(meta|dict(file=name,der_sha256=cert.fingerprint(hashes.SHA256()).hex(),trust='same-service HTTPS download; provisional only'))
        except (OSError,ValueError,URLError) as e:certs_ok=False;evidence['certificate_sources'].append(dict(file=name,error=str(e)))
    if certs_ok:
        for index,row in enumerate(targets['targets']):
            if index:time.sleep(1.1) # FreeTSA public policy: maximum one request/second/IP.
            evidence['tsa'][row['name']]=tsa_request(row['name'],row['target'],(root/row['preimage']).read_bytes(),out/'tsa',certdir/'cacert.pem',certdir/'tsa.crt')
    # Produce a derived bundle without pretending the old placeholder is a token.
    bundle=out/'bundle';bundle.mkdir()
    with zipfile.ZipFile(io.BytesIO(base64.b64decode((source/'examples/synthetic-round.zip.b64').read_bytes()))) as z:
        for info in z.infolist():
            if info.is_dir():continue
            p=bundle/info.filename
            if not p.resolve().is_relative_to(bundle.resolve()):raise ValueError('Fixture ZIP path invalid.')
            save(p,z.read(info))
    for row in targets['targets']:
        name=row['name'];save(bundle/'anchors'/(name+'.ots'),(root/'targets'/(name+'.preimage.ots')).read_bytes())
        ots=json.loads((bundle/'anchors'/(name+'-ots.json')).read_bytes());ots['validation_backend']='none configured';save(bundle/'anchors'/(name+'-ots.json'),canon.dumps(ots))
        descriptor=json.loads((bundle/'anchors'/(name+'-tsa.json')).read_bytes());response=out/'tsa'/name/'response.tsr';query=out/'tsa'/name/'request.tsq'
        if response.exists() and evidence['tsa'].get(name,{}).get('evidence_state')=='real token received':
            save(bundle/'anchors'/(name+'.tsr'),response.read_bytes());save(bundle/'anchors'/(name+'.tsq'),query.read_bytes())
            descriptor.update(authority='FreeTSA.org (candidate; production pins not selected)',request='anchors/'+name+'.tsq',validation_backend='none configured (production CA/signer/policy not selected)')
        else:
            (bundle/'anchors'/(name+'.tsr')).unlink(missing_ok=True)
            descriptor.update(authority='placeholder; no RFC3161 token obtained',validation_backend='none configured; no token',evidence_state='placeholder_no_token')
        save(bundle/'anchors'/(name+'-tsa.json'),canon.dumps(descriptor))
    keys=json.loads((source/'examples/fixture-metadata.json').read_bytes())
    report=verify_bundle(bundle,expected_author_key=keys['author_key'],expected_steward_key=keys['steward_key'])
    jsave(out/'report.json',report);save(out/'summary.txt',(report['summary']+'\nrrverify exit_code='+str(report['exit_code'])+'\n').encode())
    evidence['pinned_verifier_exit_code']=report['exit_code'];evidence['pinned_verifier_summary']=report['summary']
    evidence['explorer_agreement_is_node_confirmation']=False
    evidence['proof_files_unchanged']=all(sha((root/'targets'/(name+'.preimage.ots')).read_bytes())==digest for name,digest in before.items())
    evidence['production_tsa_policy_used']=False
    jsave(out/'results.json',evidence);print(json.dumps(evidence,indent=2))
    for name,row in evidence['tsa'].items():
        if not all(row.get(k) for k in ('imprint_matches_target','request_signature_chain_nonce_match_under_service_ca','wrong_target_rejected','different_nonce_rejected')):return 1
    return 0 if len(evidence['tsa'])==3 else 1

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();raise SystemExit(run(a.root,a.source,a.output))
if __name__=='__main__':main()
