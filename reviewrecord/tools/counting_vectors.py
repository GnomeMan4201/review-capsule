#!/usr/bin/env python3
# Generate/check v0.2.2 counting/path vectors; Python 3.10+, stdlib [a-Shell ok].
"""Semantic rules only; not signed-bundle verification."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def count(x):
    first={};duplicate=[];entries=[e for e in sorted(x['log'],key=lambda e:e['seq']) if e['kind']=='commit']
    for e in entries:
        if e['reviewer_key'] in first:duplicate.append(e['seq'])
        else:first[e['reviewer_key']]=e['commitment']
    revealed={r['reviewer_key'] for r in x['reveals'] if r['valid'] and first.get(r['reviewer_key'])==r['commitment']}
    missing=sorted(set(first)-revealed);withdrawn=set(x['withdrawn'])
    return dict(tree_size=len(entries),locked_count=len(first),verified_reveals=len(revealed),duplicate_seq=duplicate,
        withdrawn=sorted(withdrawn),missing_reveals=missing,withdrawn_and_missing=sorted(withdrawn&set(missing)),
        round_status='complete' if len(first)>=x['min_locks'] and len(revealed)>=x['min_reveals'] else 'incomplete')
def make():
    # Tokens are semantic test identifiers, not assertions that participant signatures are valid.
    a,b,c='synthetic-reviewer-a','synthetic-reviewer-b','synthetic-reviewer-c'
    h=['sha256:'+sha(('synthetic-assessment-'+str(i)).encode()) for i in range(4)]
    def log(*pairs):return [dict(seq=i+1,kind='commit',reviewer_key=k,commitment=v) for i,(k,v) in enumerate(pairs)]
    def reveals(*pairs):return [dict(reviewer_key=k,commitment=v,valid=True) for k,v in pairs]
    inputs=[('two_valid',log((a,h[0]),(b,h[1])),reveals((a,h[0]),(b,h[1])),[]),
      ('duplicate_same',log((a,h[0]),(a,h[0]),(b,h[1])),reveals((a,h[0]),(b,h[1])),[]),
      ('duplicate_distinct',log((a,h[0]),(a,h[2]),(b,h[1])),reveals((a,h[0]),(b,h[1])),[]),
      ('later_not_replacement',log((a,h[0]),(a,h[2]),(b,h[1])),reveals((a,h[2]),(b,h[1])),[]),
      ('withdrawn_missing',log((a,h[0]),(b,h[1])),reveals((b,h[1])),[a]),
      ('withdrawn_valid',log((a,h[0]),(b,h[1])),reveals((a,h[0]),(b,h[1])),[a]),
      ('withdrawn_invalid',log((a,h[0]),(b,h[1])),[dict(reviewer_key=a,commitment=h[0],valid=False),*reveals((b,h[1]))],[a]),
      ('three_locks_two_reveals',log((a,h[0]),(b,h[1]),(c,h[2])),reveals((a,h[0]),(b,h[1])),[]),
      ('many_leaves_one_lock',log(*[(a,h[i%4]) for i in range(8)]),reveals((a,h[0])),[]),('empty',[],[],[])]
    cases=[]
    for name,entries,published,withdrawn in inputs:
        row=dict(id=name,log=entries,reveals=published,withdrawn=withdrawn,min_locks=2,min_reveals=2)
        row['expected']=count(row);cases.append(row)
    paths=[]
    for kind in ('declarations','commits','withdrawals','assessments'):
        data=json.dumps({'synthetic':kind,'reviewer_key':a},sort_keys=True,separators=(',',':')).encode();rid='r-'+sha(a.encode())[:16];digest=sha(data)
        for name,path,codes in [('matching',f'{kind}/{rid}/{digest}.json',[]),('wrong_rid',f'{kind}/r-0000000000000000/{digest}.json',['RID_MISMATCH']),('wrong_hash',f'{kind}/{rid}/'+('0'*64)+'.json',['PATH_HASH_MISMATCH'])]:
            paths.append(dict(id=kind+'_'+name,file_hex=data.hex(),reviewer_key=a,path=path,expected=codes))
    return dict(spec='0.2.2',scope='Semantic counting and filename functions only. Test reviewer tokens, file bytes and valid flags are not signed-envelope acceptance fixtures.',counting=cases,paths=paths)
def main():
    p=argparse.ArgumentParser(description='Read-only semantic vector comparison, not rrverify.');p.add_argument('--write',action='store_true');args=p.parse_args()
    try:
        data=make();target=ROOT/'vectors/counting-paths-v0.2.2.json'
        if args.write:target.write_text(json.dumps(data,indent=2)+'\n')
        elif json.loads(target.read_text())!=data:raise ValueError('vector difference')
        print(json.dumps(dict(counting_cases=len(data['counting']),path_cases=len(data['paths']),result='semantic vectors match')));return 0
    except (ValueError,OSError) as e:print(type(e).__name__,file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
