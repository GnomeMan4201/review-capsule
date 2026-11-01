#!/usr/bin/env python3
# Verify private Review Capsule receipts; Python 3.10+, stdlib only [a-Shell ok].
import argparse
import hashlib
import json
from pathlib import Path
import sys


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()


def verify(data):
    if data.get('redacted'): raise ValueError('Use your complete private receipt; a redacted author export cannot verify the full commitment.')
    schema=data.get('schema')
    if schema not in ('review-capsule-receipt/0.1','review-capsule-receipt/0.2'): raise ValueError('Unsupported receipt schema.')
    fields=['assignment','round_commitment','answers','nonce']
    if schema.endswith('/0.2'):
        fields.append('items')
        if not data['items'] or len(data['items'])!=len(data['answers']): raise ValueError('Missing or extra item receipts.')
        seen=set()
        for item in data['items']:
            payload=item['payload'];item_id=payload['item_id']
            if set(payload)!={'round_id','reviewer','item_id','judgment','reasoning','timestamp'}: raise ValueError('Invalid item receipt fields.')
            if item_id in seen: raise ValueError('Duplicate item receipt.')
            seen.add(item_id)
            if digest(payload)!=item['sha256']: raise ValueError('Item hash mismatch.')
            if payload['timestamp']!=data['submitted_at']: raise ValueError('Timestamp mismatch.')
            if data['answers'][item_id]!={'verdict':payload['judgment'],'reason':payload['reasoning']}: raise ValueError('Answer and receipt differ.')
        if seen!=set(data['answers']): raise ValueError('Receipt IDs differ from answer IDs.')
    if digest({key:data[key] for key in fields})!=data['commitment']: raise ValueError('Assessment commitment mismatch.')


def main():
    parser=argparse.ArgumentParser(description='Read-only consistency check of a complete private Review Capsule receipt. No network requests. Consistency is not independent chronology or proof of human independence.')
    parser.add_argument('receipt',type=Path,help='Downloaded private receipt JSON')
    args=parser.parse_args()
    try:
        data=json.loads(args.receipt.read_text(encoding='utf-8'))
        verify(data)
    except (OSError,ValueError,KeyError,TypeError,UnicodeError,OverflowError) as exc:
        # Do not echo payloads, reasons, passwords or private file contents.
        print('Receipt verification failed: '+(str(exc) if isinstance(exc,ValueError) and not isinstance(exc,json.JSONDecodeError) else type(exc).__name__),file=sys.stderr)
        return 1
    print('Receipt hashes and bound contents match. This does not prove independent time or reviewer identity.')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
