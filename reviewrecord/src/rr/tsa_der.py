# RFC3161 DER field extraction; Python 3.12+, stdlib [a-Shell ok].
"""Bounded DER decoding. This module does NOT verify signatures."""
from datetime import datetime,timezone
import re

_SHA256_OID='2.16.840.1.101.3.4.2.1'
_SIGNED_DATA_OID='1.2.840.113549.1.7.2'
_TSTINFO_OID='1.2.840.113549.1.9.16.1.4'

class DERError(ValueError):
    pass

def _node(data,at):
    if at>=len(data):raise DERError('Truncated ASN.1 tag.')
    tag=data[at];at+=1
    if (tag&0x1f)==0x1f:raise DERError('High tag numbers not supported.')
    if at>=len(data):raise DERError('Truncated ASN.1 length.')
    first=data[at];at+=1
    if first==0x80:raise DERError('Indefinite ASN.1 length rejected.')
    if first&0x80:
        n=first&0x7f
        if n==0 or n>4 or at+n>len(data):raise DERError('Invalid ASN.1 length.')
        if data[at]==0:raise DERError('Overlong ASN.1 length.')
        size=int.from_bytes(data[at:at+n],'big');at+=n
        if size<128:raise DERError('Nonminimal ASN.1 length.')
    else:size=first
    if size>1048576 or at+size>len(data):raise DERError('ASN.1 field exceeds buffer or limit.')
    return (tag,data[at:at+size],at+size)

def _children(data,tag):
    if tag not in (0x30,0x31,0xa0):raise DERError('Expected constructed ASN.1 tag.')
    out=[];at=0
    while at<len(data):
        if len(out)>=128:raise DERError('Too many ASN.1 members.')
        entry=_node(data,at);out.append((entry[0],entry[1]));at=entry[2]
    return out

def _one(data,tag):
    if len(data)>1048576:raise DERError('Input limit exceeded.')
    t,v,end=_node(data,0)
    if t!=tag or end!=len(data):raise DERError('Unexpected or trailing ASN.1 data.')
    return v

def _field(fields,index,tag):
    if index>=len(fields) or fields[index][0]!=tag:raise DERError('Unexpected ASN.1 structure.')
    return fields[index][1]

def _oid(data):
    if not data:raise DERError('Empty OID.')
    vals=[];acc=0;start=True
    for n in data:
        if start and n==0x80:raise DERError('Nonminimal OID component.')
        acc=(acc<<7)|(n&0x7f)
        if acc>2**63:raise DERError('OID component too large.')
        start=False
        if not n&0x80:
            vals.append(acc);acc=0;start=True
    if not start:raise DERError('Unterminated OID component.')
    v=vals[0]
    if v<40:arcs=[0,v]
    elif v<80:arcs=[1,v-40]
    else:arcs=[2,v-80]
    return '.'.join(str(x) for x in arcs+vals[1:])

def _der_len(n):
    if n<128:return bytes([n])
    v=n.to_bytes((n.bit_length()+7)//8,'big')
    return bytes([0x80|len(v)])+v

def _imprint(der):
    f=_children(_one(der,0x30),0x30)
    if len(f)!=2:raise DERError('MessageImprint must have exactly two members.')
    algo=_children(_field(f,0,0x30),0x30)
    if not algo or _oid(_field(algo,0,0x06))!=_SHA256_OID:
        raise DERError('Only SHA-256 timestamps are accepted.')
    if len(algo)>2 or (len(algo)==2 and algo[1]!=(0x05,b'')):
        raise DERError('Unexpected hash algorithm parameters.')
    digest=_field(f,1,0x04)
    if len(digest)!=32:raise DERError('Unexpected SHA-256 digest length.')
    return digest

def request_imprint(der):
    f=_children(_one(der,0x30),0x30)
    if len(f)<3 or f[0]!=(0x02,b'\x01'):
        raise DERError('Unsupported timestamp request version.')
    mi=_field(f,1,0x30)
    digest=_imprint(b'\x30'+_der_len(len(mi))+mi)
    nonce_fields=[v for tag,v in f[2:] if tag==0x02]
    if len(nonce_fields)!=1 or not any(nonce_fields[0]):
        raise DERError('Nonce is required.')
    return digest

def _time(value):
    try:val=value.decode('ascii')
    except UnicodeDecodeError:raise DERError('Non-ASCII generalized time.') from None
    match=re.fullmatch(r'(\d{14})(?:\.(\d{1,6}))?Z',val)
    if not match:raise DERError('Noncanonical TSTInfo time.')
    try:stamp=datetime.strptime(match.group(1),'%Y%m%d%H%M%S').replace(tzinfo=timezone.utc)
    except ValueError:raise DERError('Invalid TSTInfo timestamp.') from None
    if match.group(2):stamp=stamp.replace(microsecond=int(match.group(2).ljust(6,'0')))
    return stamp,stamp.isoformat().replace('+00:00','Z')

def token_tstinfo(token_der):
    cms=_children(_one(token_der,0x30),0x30)
    if len(cms)!=2 or _oid(_field(cms,0,0x06))!=_SIGNED_DATA_OID:
        raise DERError('Expected CMS signed-data token.')
    signed=_children(_field(cms,1,0xa0),0xa0)
    if len(signed)!=1 or signed[0][0]!=0x30:
        raise DERError('Malformed SignedData wrapper.')
    fields=_children(signed[0][1],0x30)
    encap=_children(_field(fields,2,0x30),0x30)
    if len(encap)!=2 or _oid(_field(encap,0,0x06))!=_TSTINFO_OID:
        raise DERError('Expected TSTInfo CMS content.')
    content=_children(_field(encap,1,0xa0),0xa0)
    if len(content)!=1 or content[0][0]!=0x04:
        raise DERError('TSTInfo must be an OCTET STRING.')
    info=_children(_one(content[0][1],0x30),0x30)
    if len(info)<5 or info[0]!=(0x02,b'\x01'):
        raise DERError('Invalid TSTInfo version or fields.')
    policy=_oid(_field(info,1,0x06))
    mi=_field(info,2,0x30)
    digest=_imprint(b'\x30'+_der_len(len(mi))+mi)
    _field(info,3,0x02)
    timestamp,time_text=_time(_field(info,4,0x18))
    return dict(policy_oid=policy,imprint=digest,stamp=timestamp,attested_time=time_text)
