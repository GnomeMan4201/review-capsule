#!/usr/bin/env node
// Cross-check draft canon-v1, PAE and RFC 9162 vectors; Node 20+, built-ins [needs Linux runner].
// Separate parser/encoder and tree implementation; not a production verifier.
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const hash=b=>crypto.createHash('sha256').update(b).digest();
const equal=(a,b)=>Buffer.from(a).equals(Buffer.from(b));
function parseCanon(bytes) {
  const input=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
  let i=0;
  function space(){while(/[\x20\x09\x0a\x0d]/.test(input[i]??'X'))i++;}
  function string(){
    if(input[i++]!=='"')throw Error('string');let result='';
    while(i<input.length){
      const c=input[i++];if(c==='"'){
        for(const cp of result){const n=cp.codePointAt(0);if(n>=0xd800&&n<=0xdfff)throw Error('surrogate');}
        return result;
      }
      if(c==='\\'){
        const e=input[i++];const m={'"':'"','\\':'\\','/':'/','b':'\b','f':'\f','n':'\n','r':'\r','t':'\t'};
        if(e==='u'){const h=input.slice(i,i+4);if(!/^[0-9a-fA-F]{4}$/.test(h))throw Error('escape');result+=String.fromCharCode(parseInt(h,16));i+=4;}
        else if(Object.hasOwn(m,e))result+=m[e];else throw Error('escape');
      } else {if(c.charCodeAt(0)<32)throw Error('control');result+=c;}
    }throw Error('unterminated');
  }
  function value(){
    space();const c=input[i];
    if(c==='"')return string();
    if(c==='{'){
      i++;space();const out=new Map();if(input[i]==='}'){i++;return out;}
      while(true){space();const k=string();space();if(input[i++]!==':')throw Error('colon');
        if(out.has(k))throw Error('duplicate');out.set(k,value());space();
        const end=input[i++];if(end==='}')return out;if(end!==',')throw Error('object');}
    }
    if(c==='['){i++;space();const out=[];if(input[i]===']'){i++;return out;}
      while(true){out.push(value());space();const end=input[i++];if(end===']')return out;if(end!==',')throw Error('array');}}
    for(const [token,result] of [['true',true],['false',false],['null',null]]){
      if(input.startsWith(token,i)){i+=token.length;return result;}}
    const match=/^-?(?:0|[1-9][0-9]*)/.exec(input.slice(i));if(!match)throw Error('value');
    i+=match[0].length;if(match[0]==='-0')throw Error('negative zero');
    const n=Number(match[0]);if(!Number.isSafeInteger(n))throw Error('range');return n;
  }
  const result=value();space();if(i!==input.length)throw Error('trailing');
  function order(a,b){const aa=Array.from(a,c=>c.codePointAt(0)),bb=Array.from(b,c=>c.codePointAt(0));
    for(let n=0;n<Math.min(aa.length,bb.length);n++)if(aa[n]!==bb[n])return aa[n]-bb[n];return aa.length-bb.length;}
  function emit(v){if(v instanceof Map)return '{'+[...v.keys()].sort(order).map(k=>JSON.stringify(k)+':'+emit(v.get(k))).join(',')+'}';
    if(Array.isArray(v))return '['+v.map(emit).join(',')+']';return JSON.stringify(v);}
  return Buffer.from(emit(result));
}
function merkle(leaves){
  if(!leaves.length)return hash(Buffer.alloc(0));
  const frontier=[];
  for(const leaf of leaves){let h=hash(Buffer.concat([Buffer.from([0]),leaf])),height=0;
    while(frontier[height]){h=hash(Buffer.concat([Buffer.from([1]),frontier[height],h]));frontier[height]=null;height++;}
    frontier[height]=h;
  }
  let root=null;for(const h of frontier)if(h)root=root?hash(Buffer.concat([Buffer.from([1]),h,root])):h;
  return root;
}
function inclusion(leaf,index,size,proof,root){
  if(index<0||index>=size)return false;let fn=index,sn=size-1,r=hash(Buffer.concat([Buffer.from([0]),leaf]));
  for(const p of proof){if(sn===0)return false;
    if((fn&1)===1||fn===sn){r=hash(Buffer.concat([Buffer.from([1]),p,r]));if((fn&1)===0)while(fn!==0&&(fn&1)===0){fn>>=1;sn>>=1;}}
    else r=hash(Buffer.concat([Buffer.from([1]),r,p]));fn>>=1;sn>>=1;
  }return sn===0&&equal(r,root);
}
function main(){
  if(process.argv.includes('--help')){console.log('Usage: node tools/vector_crosscheck.mjs [vectors.json]\nRead-only Python/JavaScript draft-vector cross-check.');return;}
  if(process.argv.length>3)throw Error('usage');
  const file=process.argv[2]??path.join(path.dirname(fileURLToPath(import.meta.url)),'../vectors/primitive-v0.2.2.json');
  const vectors=JSON.parse(fs.readFileSync(file,'utf8'));let count=0,proofs=0,mutations=0;
  for(const v of vectors.canonical){let actual=null;try{actual=parseCanon(Buffer.from(v.input_hex,'hex'));}catch{}
    if(v.accepted){if(!actual||actual.toString('hex')!==v.canon_hex||'sha256:'+hash(actual).toString('hex')!==v.sha256)throw Error('canon '+v.id);}
    else if(actual!==null)throw Error('accepted invalid '+v.id);count++;
  }
  for(const t of vectors.merkle){const leaves=t.leaves_hex.map(h=>Buffer.from(h,'hex')),root=Buffer.from(t.root_hex,'hex');
    if(!equal(merkle(leaves),root))throw Error('tree size '+t.tree_size);
    for(const p of t.proofs){const path=p.hashes.map(h=>Buffer.from(h,'hex'));
      if(!inclusion(leaves[p.leaf_index],p.leaf_index,p.tree_size,path,root))throw Error('proof');proofs++;
      const bad=Buffer.from(leaves[p.leaf_index]);bad[0]^=1;
      if(inclusion(bad,p.leaf_index,p.tree_size,path,root))throw Error('substituted leaf');mutations++;
      if(inclusion(leaves[p.leaf_index],p.tree_size,p.tree_size,path,root))throw Error('bad index');mutations++;
      if(inclusion(leaves[p.leaf_index],p.leaf_index,p.tree_size,[...path,Buffer.alloc(32)],root))throw Error('extra proof');mutations++;
    }
  }
  for(const v of vectors.pae){const type=Buffer.from(v.payload_type),body=Buffer.from(v.payload_hex,'hex');
    const pae=Buffer.concat([Buffer.from('DSSEv1 '+type.length+' '),type,Buffer.from(' '+body.length+' '),body]);
    if(pae.toString('hex')!==v.pae_hex)throw Error('PAE');}
  console.log(JSON.stringify({canonical_cases:count,merkle_sizes:vectors.merkle.length,inclusion_proofs:proofs,rejected_mutations:mutations,pae_cases:vectors.pae.length,status:'cross-language draft vectors match'}));
}
try{main();}catch(e){console.error('Cross-check failed: '+e.message);process.exitCode=1;}
