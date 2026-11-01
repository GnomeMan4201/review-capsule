#!/usr/bin/env python3
# Generate/check draft canon-v1 and RFC 9162 vectors; Python 3.10+, stdlib [a-Shell ok].
"""Phase-0 reference only. Not a bundle verifier or signing implementation."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

MAX_INT=(1<<53)-1
ROOT=Path(__file__).resolve().parents[1]


def sha(data): return hashlib.sha256(data).digest()

def canon_input(data):
    def pairs(values):
        result={}
        for key,value in values:
            if key in result: raise ValueError('duplicate key')
            result[key]=value
        return result
    def integer(text):
        if text=='-0': raise ValueError('negative zero')
        value=int(text)
        if not -MAX_INT<=value<=MAX_INT: raise ValueError('integer range')
        return value
    def forbidden(_): raise ValueError('number form')
    value=json.loads(data.decode('utf-8'),object_pairs_hook=pairs,parse_int=integer,
        parse_float=forbidden,parse_constant=forbidden)
    def check(value):
        if isinstance(value,str): value.encode('utf-8')
        elif isinstance(value,list):
            for item in value: check(item)
        elif isinstance(value,dict):
            for key,item in value.items(): check(key);check(item)
    check(value)
    return json.dumps(value,ensure_ascii=False,allow_nan=False,sort_keys=True,separators=(',',':')).encode('utf-8')

def split(n): return 1<<((n-1).bit_length()-1)

def tree(leaves):
    if not leaves: return sha(b'')
    if len(leaves)==1: return sha(b'\x00'+leaves[0])
    k=split(len(leaves))
    return sha(b'\x01'+tree(leaves[:k])+tree(leaves[k:]))

def proof(leaves,index):
    if len(leaves)==1: return []
    k=split(len(leaves))
    if index<k: return proof(leaves[:k],index)+[tree(leaves[k:])]
    return proof(leaves[k:],index-k)+[tree(leaves[:k])]

def reconstruct(leaf,index,size,path):
    if not 0<=index<size: raise ValueError('index')
    if size==1:
        if path: raise ValueError('extra proof node')
        return sha(b'\x00'+leaf)
    if not path: raise ValueError('missing proof node')
    k=split(size)
    if index<k: return sha(b'\x01'+reconstruct(leaf,index,k,path[:-1])+path[-1])
    return sha(b'\x01'+path[-1]+reconstruct(leaf,index-k,size-k,path[:-1]))

def inputs():
    return [
        ('object_whitespace',b' { "z" : null, "a": [true,false,0,1,-1] } '),
        ('empty_object',b'{}'),('empty_array',b'[]'),('empty_string',b'""'),
        ('codepoint_sort','{"😀":1,"～":2}'.encode()),
        ('controls',json.dumps({'text':''.join(chr(i) for i in range(32))+'"\\'}).encode()),
        ('unicode_literals','{"s":"é é 😀 ～ / \u2028 \u2029"}'.encode()),
        ('unicode_escape_pair',br'{"s":"\ud83d\ude00"}'),
        ('limits',b'[-9007199254740991,9007199254740991]'),
        ('nested',b'{"b":{"z":2,"a":1},"a":[{"y":null,"x":true}]}'),
        ('duplicate',b'{"a":1,"a":2}'),('duplicate_escaped',br'{"a":1,"\u0061":2}'),
        ('float',b'1.0'),('exponent',b'1e0'),('negative_zero',b'-0'),
        ('leading_zero',b'01'),('positive_overflow',b'9007199254740992'),
        ('negative_overflow',b'-9007199254740992'),('nan',b'NaN'),('infinity',b'Infinity'),
        ('lone_high_surrogate',br'"\ud800"'),('lone_low_surrogate',br'"\udfff"'),
        ('literal_control',b'"\x00"'),('bad_utf8',b'"\xff"'),
        ('trailing_data',b'{}[]'),('trailing_comma',b'[1,]'),
    ]

def make_vectors():
    canonical=[]
    for name,data in inputs():
        row={'id':name,'input_hex':data.hex()}
        try:
            output=canon_input(data)
            row.update(accepted=True,canon_hex=output.hex(),sha256='sha256:'+sha(output).hex())
        except (ValueError,UnicodeError): row['accepted']=False
        canonical.append(row)
    merkle=[]
    for size in (0,1,2,3,4,5,7,8):
        leaves=[sha(('reviewrecord-synthetic-commit-'+str(i)).encode()) for i in range(size)]
        paths=[{'leaf_index':i,'tree_size':size,'hashes':[h.hex() for h in proof(leaves,i)]} for i in range(size)]
        for path in paths:
            assert reconstruct(leaves[path['leaf_index']],path['leaf_index'],size,[bytes.fromhex(h) for h in path['hashes']])==tree(leaves)
        merkle.append({'tree_size':size,'leaves_hex':[h.hex() for h in leaves],
            'root_hex':tree(leaves).hex(),'proofs':paths})
    pae=[]
    for label,payload_type,payload in [('published_dsse_example','http://example.com/HelloWorld',b'hello world'),
        ('empty_payload','application/vnd.reviewrecord.commit.v1+json',b''),
        ('utf8_byte_lengths','example/é','😀'.encode())]:
        kind=payload_type.encode()
        encoded=b'DSSEv1 '+str(len(kind)).encode()+b' '+kind+b' '+str(len(payload)).encode()+b' '+payload
        pae.append({'id':label,'payload_type':payload_type,'payload_hex':payload.hex(),'pae_hex':encoded.hex()})
    return {'status':'implementation-baseline','spec':'0.2.2','canonical':canonical,'merkle':merkle,'pae':pae}

def main():
    parser=argparse.ArgumentParser(description='Generate or compare phase-0 draft primitive vectors. Read-only by default.')
    parser.add_argument('--write',action='store_true',help='Explicitly write generated draft vectors')
    parser.add_argument('--output',type=Path,default=ROOT/'vectors'/'primitive-v0.2.2.json')
    args=parser.parse_args()
    try:
        value=make_vectors()
        if args.write:
            args.output.parent.mkdir(parents=True,exist_ok=True)
            args.output.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        elif json.loads(args.output.read_text())!=value: raise ValueError('stored vectors differ')
        print(json.dumps({'canonical_cases':len(value['canonical']),'merkle_sizes':len(value['merkle']),
            'inclusion_proofs':sum(len(t['proofs']) for t in value['merkle']),'pae_cases':len(value['pae']),
            'status':'draft vectors match generated results'}))
        return 0
    except (OSError,ValueError,UnicodeError) as exc:
        print('Vector operation failed: '+type(exc).__name__,file=sys.stderr);return 1
if __name__=='__main__': raise SystemExit(main())
