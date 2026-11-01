# Anchor checks; Python 3.12+, optional OpenTimestamps and native OpenSSL [needs Linux runner].
import shutil,subprocess,tempfile
from pathlib import Path
from ..canon import hash_bytes

def check(anchor,files,*,network=False,bitcoin_rpc=None,tsa_ca=None):
    """Never accept status assertions from a descriptor as evidence."""
    kind=anchor.get('type');proof=anchor.get('proof')
    if type(proof) is not str or proof not in files:return 'missing','Required proof file is absent.'
    try:target=hash_bytes(anchor['target'])
    except (KeyError,ValueError):return 'invalid','Target digest is malformed.'
    if kind=='ots':
        try:
            from opentimestamps.core.timestamp import DetachedTimestampFile
            from opentimestamps.core.serialize import BytesDeserializationContext
            from opentimestamps.core.notary import PendingAttestation,BitcoinBlockHeaderAttestation
        except ImportError:return 'unverifiable_offline','OpenTimestamps parser is unavailable.'
        try:
            detached=DetachedTimestampFile.deserialize(BytesDeserializationContext(files[proof]))
            if detached.file_digest!=target:return 'invalid','Proof target does not match.'
            attestations=list(detached.timestamp.all_attestations())
            bitcoin=[(message,a) for message,a in attestations if isinstance(a,BitcoinBlockHeaderAttestation)]
            pending=any(isinstance(a,PendingAttestation) for _,a in attestations)
            if not bitcoin:return ('pending','Calendar reference has no checked Bitcoin attestation.') if pending else ('invalid','No supported attestation.')
        except Exception:return 'invalid','Timestamp proof did not parse or bind correctly.'
        try:
            if not network or not bitcoin_rpc:return 'unverifiable_offline','Bitcoin validation backend was not enabled.'
            from bitcoin.rpc import Proxy
            from datetime import datetime,timezone
            with Proxy(service_url=bitcoin_rpc,timeout=20) as proxy:
                chain_info=proxy.call('getblockchaininfo')
                genesis=proxy.call('getblockhash',0)
                main_genesis='000000000019d6689c085ae165831e93'
                main_genesis+='4ff763ae46a2a6c172b3f1b60a8ce26f'
                if (type(chain_info) is not dict or chain_info.get('chain')!='main'
                        or genesis!=main_genesis):
                    return 'invalid','Configured Bitcoin RPC is not a checked mainnet-genesis backend.'
                tip=proxy.getblockcount();low_depth=False
                for message,attestation in bitcoin:
                    block_hash=proxy.getblockhash(attestation.height)
                    header=proxy.getblockheader(block_hash)
                    try:attestation.verify_against_blockheader(message,header)
                    except Exception:return 'invalid','Bitcoin attestation does not match the fetched header.'
                    confirmations=tip-attestation.height+1
                    if confirmations>=6:
                        try:
                            timestamp=datetime.fromtimestamp(int(header.nTime),tz=timezone.utc).isoformat().replace('+00:00','Z')
                            block_hex=proxy.call('getblockhash',attestation.height)
                        except (ValueError,TypeError,OverflowError,AttributeError):
                            return 'unverifiable_offline','Bitcoin block metadata could not be retrieved.'
                        return 'confirmed',('Bitcoin mainnet genesis checked against configured RPC; '
                            f'height={attestation.height}; block_hash={block_hex}; '
                            f'block_time={timestamp}; confirmations={confirmations}; '
                            'node data are trusted to this configured RPC backend.')
                    low_depth=True
                return ('pending','Bitcoin confirmation threshold is not met.') if low_depth else ('invalid','No valid Bitcoin attestation.')
        except (ValueError,TypeError,KeyError,AssertionError):return 'invalid','Timestamp proof did not parse or bind correctly.'
        except Exception:return 'unverifiable_offline','Timestamp validation backend could not complete.'
    if kind=='rfc3161':
        if not tsa_ca:return 'unverifiable_offline','No externally configured TSA CA was supplied.'
        if not shutil.which('openssl'):return 'unverifiable_offline','OpenSSL backend is unavailable.'
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'response.tsr';path.write_bytes(files[proof])
                run=subprocess.run(['openssl','ts','-verify','-in',str(path),'-digest',target.hex(),'-CAfile',str(tsa_ca)],capture_output=True,timeout=20)
                return ('confirmed','RFC 3161 imprint and certificate verification matched the supplied CA policy.') if run.returncode==0 else ('invalid','RFC 3161 response did not verify under the supplied CA policy.')
        except (OSError,subprocess.TimeoutExpired):return 'unverifiable_offline','TSA validation backend could not complete.'
    return 'unverifiable_offline','No supported adapter for this evidence type.'
