# Strict DSSE application profile; Python 3.10+, cryptography==50.0.2 [needs Linux runner].
import base64,re
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .canon import dumps,loads,digest,CanonError
TYPES={'registration','declaration','commit','assessment','logentry','close','disposition','withdrawal'}
class EnvelopeError(ValueError):
    def __init__(self,code):self.code=code;super().__init__(code)
def b64decode(text):
    if type(text) is not str or not (re.fullmatch(r'[A-Za-z0-9+/]*={0,2}',text) or re.fullmatch(r'[A-Za-z0-9_-]*={0,2}',text)):raise ValueError('base64')
    if len(text.rstrip('='))%4==1:raise ValueError('base64 length')
    return base64.b64decode(text+'='*((-len(text))%4),altchars=b'-_',validate=True)
def public_bytes(key):
    if type(key) is not str or not key.startswith('ed25519:'):raise ValueError('key encoding')
    text=key[8:]
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}',text):raise ValueError('key encoding')
    raw=b64decode(text)
    if len(raw)!=32 or base64.urlsafe_b64encode(raw).decode().rstrip('=')!=text:raise ValueError('key encoding')
    return raw
def pae(kind,payload):
    k=kind.encode('utf-8');return b'DSSEv1 '+str(len(k)).encode()+b' '+k+b' '+str(len(payload)).encode()+b' '+payload
@dataclass
class Decoded:
    value:dict
    payload_type:str
    payload:bytes
    signature:bytes
    object_hash:str

def decode(raw):
    try:e=loads(raw)
    except CanonError:raise EnvelopeError('CANON_INVALID') from None
    if raw!=dumps(e):raise EnvelopeError('ENVELOPE_NONCANONICAL')
    try:
        if type(e) is not dict or set(e)!={'payloadType','payload','signatures'}:raise ValueError()
        if type(e['signatures']) is not list or len(e['signatures'])!=1:raise ValueError()
        signature=e['signatures'][0]
        if type(signature) is not dict or not {'sig'}<=set(signature)<={'sig','keyid'}:raise ValueError()
        if 'keyid' in signature and type(signature['keyid']) is not str:raise ValueError()
        payload=b64decode(e['payload']);sig=b64decode(signature['sig'])
        if len(sig)!=64:raise ValueError()
        value=loads(payload)
        if type(value) is not dict or value.get('type') not in TYPES or type(e['payloadType']) is not str:raise ValueError()
        if e['payloadType']!='application/vnd.reviewrecord.'+value['type']+'.v1+json':raise ValueError()
        if payload!=dumps(value):raise CanonError('noncanonical payload')
        return Decoded(value,e['payloadType'],payload,sig,digest(raw))
    except CanonError:raise EnvelopeError('CANON_INVALID') from None
    except (ValueError,KeyError,TypeError):raise EnvelopeError('ENVELOPE_MALFORMED') from None

def verify_signature(record,key):
    try:Ed25519PublicKey.from_public_bytes(public_bytes(key)).verify(record.signature,pae(record.payload_type,record.payload));return True
    except (ValueError,InvalidSignature,TypeError):return False
