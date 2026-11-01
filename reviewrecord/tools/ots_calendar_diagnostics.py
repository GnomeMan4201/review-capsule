#!/usr/bin/env python3
"""Read-only diagnostics for the retained, public synthetic OTS proofs.

No submission, upgrade write, Bitcoin RPC or confirmation assertion occurs.
"""
import argparse,base64,hashlib,importlib.metadata,json,os,shutil,subprocess
from datetime import datetime,timezone
from pathlib import Path
from urllib.error import HTTPError,URLError
from urllib.parse import urljoin,urlparse
from opentimestamps.core.timestamp import DetachedTimestampFile,Timestamp
from opentimestamps.core.serialize import BytesDeserializationContext
from opentimestamps.core.notary import PendingAttestation,BitcoinBlockHeaderAttestation
from opentimestamps.calendar import RemoteCalendar,_opener,MAX_RESPONSE_LENGTH

POOLS=('https://a.pool.opentimestamps.org','https://b.pool.opentimestamps.org')
EMBEDDED=('https://alice.btc.calendar.opentimestamps.org','https://bob.btc.calendar.opentimestamps.org')
ALLOWED=set(POOLS+EMBEDDED)
def h(raw):return hashlib.sha256(raw).hexdigest()
def query(url,commitment):
    from urllib.request import Request
    base=url.split('/timestamp/')[0]
    if base not in ALLOWED or urlparse(url).scheme!='https':raise ValueError('Calendar not allowlisted.')
    row={'requested_url':url,'http_status':None,'response_kind':'unavailable'}
    req=Request(url,headers=RemoteCalendar(base).request_headers)
    try:
        with _opener.open(req,timeout=15) as response:
            raw=response.read(MAX_RESPONSE_LENGTH+1)
            row.update(http_status=response.status,final_url=response.geturl())
            if len(raw)>MAX_RESPONSE_LENGTH:
                row.update(response_kind='oversize',response_sha256=h(raw));return row
            row.update(response_bytes=len(raw),response_sha256=h(raw),response_base64=base64.b64encode(raw).decode())
            if response.status==200:
                try:
                    ctx=BytesDeserializationContext(raw);stamp=Timestamp.deserialize(ctx,commitment);ctx.assert_eof()
                    row.update(response_kind='timestamp',attestations=[{'type':type(a).__name__,'height':a.height if isinstance(a,BitcoinBlockHeaderAttestation) else None,'uri':a.uri if isinstance(a,PendingAttestation) else None} for _,a in stamp.all_attestations()])
                except Exception as e:row.update(response_kind='invalid_timestamp',error_type=type(e).__name__)
    except HTTPError as e:
        raw=e.read(1024);row.update(http_status=e.code,response_kind='http_error',error_type=type(e).__name__,response_body_utf8=raw.decode('utf-8',errors='replace'),response_body_base64=base64.b64encode(raw).decode())
    except (URLError,TimeoutError,OSError) as e:row.update(error_type=type(e).__name__,error=str(e))
    row['confirmation_basis']='No Bitcoin node/header/depth check was performed.'
    return row

def inspect(root,query_calendars=False):
    rows=[];requests={};ots=shutil.which('ots')
    if not ots:raise ValueError('OTS executable unavailable.')
    for name in ('registration','close','record'):
        p=root/'targets'/(name+'.preimage.ots');before=p.read_bytes()
        detached=DetachedTimestampFile.deserialize(BytesDeserializationContext(before))
        info=subprocess.run([ots,'info',str(p)],capture_output=True,text=True,timeout=20)
        if info.returncode:raise ValueError('ots info failed.')
        entries=[]
        for msg,a in detached.timestamp.all_attestations():
            if not isinstance(a,PendingAttestation):continue
            if a.uri not in EMBEDDED:raise ValueError('Unexpected embedded calendar; inspect before contacting it.')
            # Keep the proof's calendar commitment, not the raw file digest.
            native=urljoin(a.uri,'timestamp/'+msg.hex())
            overrides=[urljoin(base,'timestamp/'+msg.hex()) for base in POOLS]
            entries.append(dict(embedded_calendar=a.uri,calendar_commitment=msg.hex(),native_request_url=native,previous_override_request_urls=overrides))
            for url in (native,*overrides):requests[url]=msg
        rows.append(dict(name=name,proof_sha256=h(before),file_digest=detached.file_digest.hex(),ots_info_stdout=info.stdout,ots_info_stderr=info.stderr,ots_info_exit_code=info.returncode,pending_routes=entries))
        if before!=p.read_bytes():raise ValueError('Diagnostic changed a proof file.')
    responses=[query(url,msg) for url,msg in sorted(requests.items())] if query_calendars else []
    return dict(scope='Read-only calendar lookup; no stamp/resubmission, upgrade write or Bitcoin verification',advisory_time=datetime.now(timezone.utc).isoformat(),client_version=importlib.metadata.version('opentimestamps-client'),library_version=importlib.metadata.version('opentimestamps'),proofs=rows,live_gets=responses,network_queries_requested=query_calendars,source_note='OTS 0.8.0 upgrade -c overrides queried calendar_url; warnings print attestation.uri rather than calendar_url. Previous stderr alone does not record HTTP status or final routing.')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--query-calendars',action='store_true');args=p.parse_args()
    result=inspect(args.root,args.query_calendars);args.output.parent.mkdir(parents=True,exist_ok=True)
    if args.output.exists():raise ValueError('Diagnostic output exists; retain prior bytes.')
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    for row in result['proofs']:
        (args.output.parent/('ots-info-'+row['name']+'.txt')).write_text(row['ots_info_stdout'])
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
