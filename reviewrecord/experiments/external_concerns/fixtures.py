# Rebuild public synthetic evidence; Python 3.12+, project dependencies [needs Linux runner].
"""Experimental fixture transformations, never participant data or protocol fixes."""
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from reference_round import create, canon, envelope, h, pub, rid, manifest, tree, proof
from rr import dsse


def rebuild(folder, *, policy_off=False, omit=None, attested=False):
    """Re-sign dependent objects and rebuild proofs; preserve the registration for forks."""
    values = {p.relative_to(folder).as_posix(): dsse.decode(p.read_bytes()).value
              for prefix in ('declarations', 'commits', 'withdrawals', 'assessments', 'log', 'dispositions')
              for p in (folder / prefix).rglob('*.json')}
    registration = dsse.decode((folder / 'registration.json').read_bytes()).value
    close = dsse.decode((folder / 'close.json').read_bytes()).value
    if policy_off:
        policy = json.loads((folder / 'policy.json').read_bytes())
        policy['disposition_required'] = False
        (folder / 'policy.json').write_bytes(canon(policy))
        registration['policy_hash'] = h(canon(policy))
        (folder / 'registration.json').write_bytes(envelope(registration, 'author'))
    reg_hash = h((folder / 'registration.json').read_bytes())
    for prefix in ('declarations', 'commits', 'withdrawals', 'assessments', 'log', 'dispositions', 'proofs'):
        shutil.rmtree(folder / prefix, ignore_errors=True)
    shutil.rmtree(folder / 'anchors', ignore_errors=True)

    def write(name, raw):
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return h(raw)

    def role_for(key):
        return next(role for role in ('reviewer-a', 'reviewer-b', 'reviewer-c') if pub(role) == key)

    mapped = {}
    assessments = []
    omitted_key = pub(omit) if omit else None
    for kind in ('assessment', 'declaration', 'commit', 'withdrawal'):
        for name, original in values.items():
            if original['type'] != kind or original.get('reviewer_key') == omitted_key:
                continue
            value = dict(original, registration_hash=reg_hash)
            role = role_for(value['reviewer_key'])
            if kind == 'commit':
                value['commitment'] = mapped[value['commitment']]
            if kind == 'withdrawal' and attested:
                value['steward_attested'] = True
                role = 'steward'
            raw = envelope(value, role)
            digest = h(raw)
            mapped[h(envelope(original, role_for(original['reviewer_key'])))] = digest
            prefix = {'assessment': 'assessments', 'declaration': 'declarations',
                      'commit': 'commits', 'withdrawal': 'withdrawals'}[kind]
            write(prefix + '/' + rid(value['reviewer_key']) + '/' + digest[7:] + '.json', raw)
            if kind == 'assessment':
                assessments.append((value['reviewer_key'], digest))

    previous = reg_hash
    leaves = []
    committed_keys = set()
    withdrawals = set()
    seq = 0
    for name in sorted((n for n in values if n.startswith('log/')), key=lambda n: int(Path(n).stem)):
        original = values[name]
        if original['ref_hash'] not in mapped:
            continue
        seq += 1
        value = dict(original, registration_hash=reg_hash, seq=seq,
                     prev_entry_hash=previous, ref_hash=mapped[original['ref_hash']])
        previous = write('log/' + str(seq) + '.json', envelope(value, 'steward'))
        referenced = next(v for v in values.values() if v['type'] == original['kind']
                          and h(envelope(v, role_for(v['reviewer_key']))) == original['ref_hash'])
        if original['kind'] == 'commit':
            leaves.append(bytes.fromhex(mapped[referenced['commitment']][7:]))
            committed_keys.add(referenced['reviewer_key'])
        if original['kind'] == 'withdrawal':
            withdrawals.add(referenced['reviewer_key'])
    close.update(registration_hash=reg_hash, final_seq=seq, last_entry_hash=previous,
                 tree_size=len(leaves), tree_head='sha256:' + tree(leaves).hex(),
                 locked_count=len(committed_keys),
                 withdrawn=[x for x in close['withdrawn'] if x['reviewer_key'] in withdrawals])
    close_hash = write('close.json', envelope(close, 'steward'))
    for key, digest in assessments:
        index = leaves.index(bytes.fromhex(digest[7:]))
        write('proofs/' + rid(key) + '/' + digest[7:] + '.json', canon(dict(
            leaf_index=index, tree_size=len(leaves), hashes=['sha256:' + x.hex() for x in proof(leaves, index)])))
    for name, original in values.items():
        if original['type'] != 'disposition':
            continue
        old = original['concern_ref']['assessment_commitment']
        if old not in mapped:
            continue
        value = dict(original, registration_hash=reg_hash,
                     concern_ref=dict(original['concern_ref'], assessment_commitment=mapped[old]))
        write(name, envelope(value, 'author'))
    record_hash = manifest(folder)
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.serialize import BytesSerializationContext
    for name, target in {'registration': reg_hash, 'close': close_hash, 'record': record_hash}.items():
        timestamp = Timestamp(bytes.fromhex(target[7:]))
        timestamp.attestations.add(PendingAttestation('https://example.invalid/synthetic-calendar'))
        ctx = BytesSerializationContext()
        DetachedTimestampFile(OpSHA256(), timestamp).serialize(ctx)
        write('anchors/' + name + '.ots', ctx.getbytes())
        write('anchors/' + name + '-ots.json', canon(dict(type='ots', authority='bitcoin', target=target,
            proof='anchors/' + name + '.ots', evidence_format='ots-detached', validation_backend='Bitcoin Core',
            confirmation_policy={'min_confirmations': 6})))
        write('anchors/' + name + '.tsr', b'SYNTHETIC-UNVERIFIED-RFC3161-PLACEHOLDER\n')
        write('anchors/' + name + '-tsa.json', canon(dict(type='rfc3161', authority='FreeTSA.org', target=target,
            proof='anchors/' + name + '.tsr', evidence_format='rfc3161-response', validation_backend='OpenSSL',
            confirmation_policy={'ca_required': True})))
    return dict(author_key=registration['author_key'], steward_key=registration['steward_key'],
                registration_hash=reg_hash)


def refresh_manifest(folder):
    """Keep synthetic record anchor descriptors bound after an inventory change."""
    record_hash = manifest(folder)
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.serialize import BytesSerializationContext
    timestamp = Timestamp(bytes.fromhex(record_hash[7:]))
    timestamp.attestations.add(PendingAttestation('https://example.invalid/synthetic-calendar'))
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), timestamp).serialize(ctx)
    (folder / 'anchors/record.ots').write_bytes(ctx.getbytes())
    for suffix in ('ots', 'tsa'):
        p = folder / ('anchors/record-' + suffix + '.json')
        value = json.loads(p.read_bytes())
        value['target'] = record_hash
        p.write_bytes(canon(value))
    return record_hash
