#!/usr/bin/env python3
# Extract/check published RFC 8032 Ed25519 vectors; Python 3.10+, cryptography==50.0.2 [needs Linux runner].
import argparse,json,re,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
ROOT=Path(__file__).resolve().parents[1]

def extract(text):
    result=[]
    for number in (1,2,3):
        block=text.split('-----TEST '+str(number)+'\n',1)[1].split('-----TEST ',1)[0]
        def field(start,end=None):
            data=block.split(start,1)[1]
            if end: data=data.split(end,1)[0]
            return ''.join(re.findall(r'^\s+([0-9a-f]{2,})\s*$',data,re.M))
        seed=field('SECRET KEY:','PUBLIC KEY:');public=field('PUBLIC KEY:','MESSAGE')
        message=re.search(r'MESSAGE \(length ([0-9]+) bytes?\):',block)
        if message is None: raise ValueError('message field missing')
        body=field(message.group(0),'SIGNATURE:');signature=field('SIGNATURE:')
        if len(bytes.fromhex(body))!=int(message.group(1)): raise ValueError('message extraction')
        result.append(dict(id='rfc8032-test-'+str(number),seed_hex=seed,public_hex=public,message_hex=body,signature_hex=signature))
    return result

def check(rows):
    for row in rows:
        private=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(row['seed_hex']))
        public=private.public_key()
        if public.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()!=row['public_hex']:raise ValueError('public key')
        message=bytes.fromhex(row['message_hex']);signature=bytes.fromhex(row['signature_hex'])
        if private.sign(message)!=signature: raise ValueError('signature mismatch')
        public.verify(signature,message)
        altered=bytearray(signature);altered[0]^=1
        try: public.verify(bytes(altered),message)
        except InvalidSignature: pass
        else: raise ValueError('altered signature accepted')
        row['public_spki_der_hex']=public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo).hex()
        row['private_pkcs8_der_hex']=private.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).hex()

def main():
    parser=argparse.ArgumentParser(description='Check published public RFC 8032 test keys only. Not a signer for user keys.')
    parser.add_argument('--write',action='store_true',help='Extract RFC tests into a draft fixture')
    args=parser.parse_args()
    try:
        target=ROOT/'vectors'/'rfc8032-draft.json'
        if args.write:
            rows=extract((ROOT/'evidence'/'rfc8032.txt').read_text());check(rows)
            target.write_text(json.dumps({'source':'RFC 8032 section 7.1, January 2017','note':'Public test seeds only. Never use these for participant keys.','vectors':rows},indent=2)+'\n')
        else:
            rows=json.loads(target.read_text())['vectors'];check(rows)
        print(json.dumps({'rfc8032_cases':len(rows),'published_signatures_match':len(rows),'altered_signatures_rejected':len(rows)}));return 0
    except (OSError,ValueError,KeyError,IndexError,InvalidSignature) as exc:
        print('RFC vector check failed: '+type(exc).__name__,file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
