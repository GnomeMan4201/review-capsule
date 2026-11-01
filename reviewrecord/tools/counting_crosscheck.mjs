#!/usr/bin/env node
// Cross-check v0.2.2 counting/path rules; Node 20+, built-ins [needs Linux runner].
import fs from 'node:fs';import crypto from 'node:crypto';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
if(process.argv.includes('--help')){console.log('Usage: node tools/counting_crosscheck.mjs\nRead-only semantic check, not rrverify.');process.exit(0);}
try{
 const data=JSON.parse(fs.readFileSync(new URL('../vectors/counting-paths-v0.2.2.json',import.meta.url),'utf8'));
 for(const row of data.counting){
  const entries=[...row.log].sort((a,b)=>a.seq-b.seq).filter(e=>e.kind==='commit'),first=new Map(),duplicate=[];
  for(const e of entries){if(first.has(e.reviewer_key))duplicate.push(e.seq);else first.set(e.reviewer_key,e.commitment);}
  const revealed=new Set(row.reveals.filter(r=>r.valid&&first.get(r.reviewer_key)===r.commitment).map(r=>r.reviewer_key));
  const missing=[...first.keys()].filter(k=>!revealed.has(k)).sort(),withdrawn=[...new Set(row.withdrawn)].sort();
  const actual={tree_size:entries.length,locked_count:first.size,verified_reveals:revealed.size,duplicate_seq:duplicate,
    withdrawn,missing_reveals:missing,withdrawn_and_missing:withdrawn.filter(k=>missing.includes(k)),
    round_status:first.size>=row.min_locks&&revealed.size>=row.min_reveals?'complete':'incomplete'};
  if(JSON.stringify(actual)!==JSON.stringify(row.expected)||actual.tree_size<actual.locked_count)throw Error('count '+row.id);
 }
 for(const row of data.paths){const parts=row.path.split('/'),codes=[];
  if(parts[1]!=='r-'+sha(Buffer.from(row.reviewer_key)).slice(0,16))codes.push('RID_MISMATCH');
  if(parts[2]!==sha(Buffer.from(row.file_hex,'hex'))+'.json')codes.push('PATH_HASH_MISMATCH');
  if(JSON.stringify(codes)!==JSON.stringify(row.expected))throw Error('path '+row.id);
 }
 console.log(JSON.stringify({counting_cases:data.counting.length,path_cases:data.paths.length,result:'cross-language semantic vectors match'}));
}catch(e){console.error('Semantic cross-check failed: '+e.message);process.exitCode=1;}
