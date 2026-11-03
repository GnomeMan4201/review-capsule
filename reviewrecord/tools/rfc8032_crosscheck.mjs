#!/usr/bin/env node
// Cross-check published RFC 8032 signatures; Node 20+, built-in crypto [needs Linux runner].
import fs from 'node:fs';
import crypto from 'node:crypto';
if(process.argv.includes('--help')){console.log('Usage: node tools/rfc8032_crosscheck.mjs [fixture.json]\nChecks public RFC test keys only.');process.exit(0);}
try{
 const file=process.argv[2]??new URL('../vectors/rfc8032-draft.json',import.meta.url);
 const rows=JSON.parse(fs.readFileSync(file,'utf8')).vectors;
 for(const row of rows){
  const publicKey=crypto.createPublicKey({key:Buffer.from(row.public_spki_der_hex,'hex'),format:'der',type:'spki'});
  const privateKey=crypto.createPrivateKey({key:Buffer.from(row.private_pkcs8_der_hex,'hex'),format:'der',type:'pkcs8'});
  const message=Buffer.from(row.message_hex,'hex'),signature=Buffer.from(row.signature_hex,'hex');
  if(!crypto.verify(null,message,publicKey,signature))throw Error('published signature');
  if(!crypto.sign(null,message,privateKey).equals(signature))throw Error('published signature mismatch');
  const changed=Buffer.from(signature);changed[0]^=1;
  if(crypto.verify(null,message,publicKey,changed))throw Error('altered signature');
 }
 console.log(JSON.stringify({rfc8032_cases:rows.length,published_signatures_match:rows.length,altered_signatures_rejected:rows.length}));
}catch(e){console.error('RFC cross-check failed: '+e.message);process.exitCode=1;}
