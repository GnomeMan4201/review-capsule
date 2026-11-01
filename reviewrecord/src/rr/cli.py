"""Read-only CLI. No network activity unless explicitly enabled."""
import argparse,json,os,sys
from pathlib import Path
from .verify import verify_bundle
from .canon import loads,CanonError

def main(argv=None):
    parser=argparse.ArgumentParser(description='Check a review-record bundle and report separate outcomes.')
    parser.add_argument('bundle',type=Path)
    parser.add_argument('--json',type=Path,help='Write machine-readable report here; otherwise write it to stdout.')
    parser.add_argument('--expected-author-key');parser.add_argument('--expected-steward-key')
    parser.add_argument('--registry',action='append',type=Path,default=[],help='Local normalized registry snapshot JSON (repeatable).')
    parser.add_argument('--network',action='store_true',help='Enable the configured Bitcoin RPC backend; does not fetch arbitrary bundle URLs.')
    parser.add_argument('--bitcoin-rpc-env',default='RR_BITCOIN_RPC',help='Name of environment variable holding the Bitcoin Core RPC URL.')
    parser.add_argument('--tsa-ca',type=Path,help='External TSA CA policy file, never a root selected from the bundle.')
    args=parser.parse_args(argv);registries=[]
    try:
        for path in args.registry:registries.append(loads(path.read_bytes()))
    except (OSError,CanonError):parser.error('A registry snapshot could not be read as canon-v1 input.')
    report=verify_bundle(args.bundle,expected_author_key=args.expected_author_key,expected_steward_key=args.expected_steward_key,registries=registries,network=args.network,bitcoin_rpc=os.environ.get(args.bitcoin_rpc_env) if args.network else None,tsa_ca=args.tsa_ca)
    rendered=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    if args.json:
        try:args.json.write_text(rendered,encoding='utf-8')
        except OSError:parser.error('The report output file could not be written.')
    else:sys.stdout.write(rendered)
    print(report['summary'],file=sys.stderr)
    return report['exit_code']
if __name__=='__main__':raise SystemExit(main())
