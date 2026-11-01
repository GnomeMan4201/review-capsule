#!/usr/bin/env python3
# Offline proof-byte binding check; Python 3.12+, opentimestamps-client==0.8.0 [needs Linux runner].
"""Parse retained .ots files. This command does not check Bitcoin or TSA evidence."""
import argparse,hashlib,importlib.metadata,json
from pathlib import Path
from opentimestamps.core.timestamp import DetachedTimestampFile
from opentimestamps.core.serialize import BytesDeserializationContext
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.notary import PendingAttestation,BitcoinBlockHeaderAttestation

def digest(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()
def inspect(folder):
    targets=json.loads((folder/'targets.json').read_bytes())
    journal=json.loads((folder/'run-journal.json').read_bytes());rows=[]
    for row in targets['targets']:
        name=row['name'];preimage=(folder/row['preimage']).read_bytes()
        raw=(folder/(row['preimage']+'.ots')).read_bytes()
        detached=DetachedTimestampFile.deserialize(BytesDeserializationContext(raw))
        attestations=list(detached.timestamp.all_attestations())
        pending=[a.uri for _,a in attestations if isinstance(a,PendingAttestation)]
        bitcoin=[a.height for _,a in attestations if isinstance(a,BitcoinBlockHeaderAttestation)]
        rows.append(dict(name=name,proof_file=row['preimage']+'.ots',proof_bytes=len(raw),proof_sha256=digest(raw),
            matches_retained_journal=digest(raw)==journal['proofs'][name]['proof_sha256'],
            starting_digest='sha256:'+detached.file_digest.hex(),target=row['target'],
            sha256_algorithm=isinstance(detached.file_hash_op,OpSHA256),
            starting_digest_matches_target='sha256:'+detached.file_digest.hex()==row['target'],
            preimage_hash_matches_target=digest(preimage)==row['target'],
            pending_calendar_attestations=pending,bitcoin_attestation_heights=bitcoin))
    return dict(scope='Offline parsing and target/file-byte binding only',
        parser='opentimestamps '+importlib.metadata.version('opentimestamps'),
        client='opentimestamps-client '+importlib.metadata.version('opentimestamps-client'),
        bitcoin_rpc_backend='none configured',bitcoin_header_check_run=False,confirmation_depth_check_run=False,
        tsa_signer_policy_check_run=False,proofs=rows)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',type=Path,default=Path(__file__).resolve().parent);args=p.parse_args()
    try:
        result=inspect(args.directory);print(json.dumps(result,indent=2))
        return 0 if all(all(row[k] for k in ('matches_retained_journal','sha256_algorithm','starting_digest_matches_target','preimage_hash_matches_target')) for row in result['proofs']) else 1
    except (OSError,ValueError,KeyError,TypeError) as e:print('Proof parsing failed: '+str(e));return 1
if __name__=='__main__':raise SystemExit(main())
