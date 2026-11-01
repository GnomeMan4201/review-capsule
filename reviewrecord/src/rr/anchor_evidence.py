# Evidence-derived anchor metadata, Python 3.12+, OpenSSL and cryptography [needs Linux runner].
"""Conservative supplemental checks; never promote descriptor strings to authority."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from . import anchors

BTC_GENESIS="000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
class EvidenceError(ValueError):pass

def _invoke(*args):
    run=subprocess.run(["openssl",*map(str,args)],capture_output=True,text=True,
                       timeout=20,check=False)
    if run.returncode!=0:
        raise EvidenceError("OpenSSL evidence parsing or verification failed.")
    return run.stdout

def _gen_time(info):
    found=re.search(r"^\s*Time stamp:\s*(.+?)\s*$",info,re.M)
    if not found:raise EvidenceError("Signed token genTime unavailable.")
    value=re.sub(r"\s+"," ",found.group(1).strip())
    formats=("%b %d %H:%M:%S %Y GMT","%b %d %H:%M:%S.%f %Y GMT")
    for fmt in formats:
        try:
            moment=datetime.strptime(value,fmt).replace(tzinfo=timezone.utc)
            return moment,moment.isoformat().replace("+00:00","Z")
        except ValueError:pass
    raise EvidenceError("Token genTime format not understood.")

def inspect(descriptor,files,*,network=False,bitcoin_rpc=None,tsa_ca=None,
            tsa_policy=None,tsa_untrusted=None):
    # Existing low-level adapter verifies imprint and/or Bitcoin header first.
    kind=descriptor.get("type")
    # Legacy RFC3161 digest-only checks cannot qualify archival tokens whose
    # signer certificate has expired since the signed genTime.
    if kind=="rfc3161":
        if not tsa_ca or not tsa_policy:
            status,detail=anchors.check(descriptor,files,network=network,bitcoin_rpc=bitcoin_rpc,tsa_ca=tsa_ca)
            if status=="confirmed":
                status,detail="unverifiable_offline","TSA requires externally pinned CA/signer/policy and original request."
        else:
            status,detail="confirmed","Raw token present; strict qualification required."
            if not isinstance(descriptor.get("proof"),str) or descriptor["proof"] not in files:
                status,detail="missing","RFC3161 proof file is missing."
    else:
        status,detail=anchors.check(descriptor,files,network=network,bitcoin_rpc=bitcoin_rpc,tsa_ca=tsa_ca)
    result={"status":status,"detail":detail,"authority":None,"attested_time":None,
            "basis":"unqualified"}
    if status!="confirmed":return result
    if descriptor.get("type")=="ots":
        # Values arise from the checked mainnet/genesis, six-deep proof path.
        fields=dict(re.findall(r"\b(height|block_hash|block_time|confirmations)=([^;]+)",detail))
        try:
            if (not detail.startswith("Bitcoin mainnet genesis checked") or
                int(fields["confirmations"])<6 or int(fields["height"])<0 or
                not re.fullmatch(r"[0-9a-f]{64}",fields["block_hash"])):
                raise EvidenceError("Bitcoin proof identity or metadata is not complete.")
            datetime.fromisoformat(fields["block_time"].replace("Z","+00:00"))
        except (KeyError,ValueError):
            result.update(status="unverifiable_offline",detail="OTS proof metadata not independently qualified.")
            return result
        result.update(authority="bitcoin-mainnet:"+BTC_GENESIS,
                      attested_time=fields["block_time"],
                      block_height=int(fields["height"]),block_hash=fields["block_hash"],
                      confirmations=int(fields["confirmations"]),
                      basis="verified OTS attestation through configured mainnet RPC (node-trust assumption)")
        return result
    if descriptor.get("type")!="rfc3161":
        return result
    # Do not treat the old -digest/-CAfile-only path as qualified authority evidence.
    if not tsa_policy or not tsa_ca or not shutil.which("openssl"):
        result.update(status="unverifiable_offline",
                      detail="TSA needs external pinned signer/CA/policy and original nonce-bearing request.")
        return result
    request_path=descriptor.get("request")
    if type(request_path) is not str or request_path not in files:
        result.update(status="unverifiable_offline",
                      detail="Original nonce-bearing TSA request is missing.")
        return result
    try:
        policy=json.loads(Path(tsa_policy).read_text(encoding="utf-8"))
        if (type(policy) is not dict or set(policy)!={"ca_sha256","signer_sha256","policy_oid"}
            or not all(type(policy[x]) is str for x in policy)):
            raise EvidenceError("TSA pin config must contain CA, signer and policy pins.")
        for name in ("ca_sha256","signer_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}",policy[name]):
                raise EvidenceError("Invalid SHA256 pin.")
        if not re.fullmatch(r"[0-2](?:\.\d+){2,}",policy["policy_oid"]):
            raise EvidenceError("Invalid policy OID.")
        if hashlib.sha256(Path(tsa_ca).read_bytes()).hexdigest()!=policy["ca_sha256"]:
            raise EvidenceError("TSA CA file does not match external pinned fingerprint.")
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import ExtensionOID,ExtendedKeyUsageOID
        from cryptography.hazmat.primitives.serialization import pkcs7
        with tempfile.TemporaryDirectory() as work:
            folder=Path(work)
            response=folder/"response.tsr";request=folder/"request.tsq";token=folder/"token.der"
            response.write_bytes(files[descriptor["proof"]])
            request.write_bytes(files[request_path])
            rq=_invoke("ts","-query","-in",request,"-text")
            if not re.search(r"^\s*Nonce:\s*(?!unspecified|none|0x0\s*$)\S+",rq,re.M|re.I):
                raise EvidenceError("Original TSA query has no nonce.")
            reply=_invoke("ts","-reply","-in",response,"-text")
            match=re.search(r"^\s*Policy OID:\s*(\S+)",reply,re.M)
            if not match or match.group(1)!=policy["policy_oid"]:
                raise EvidenceError("Signed TSA token policy OID does not match external pin.")
            moment,time_value=_gen_time(reply)
            token_run=subprocess.run(["openssl","ts","-reply","-in",str(response),
                          "-token_out","-out",str(token)],capture_output=True,timeout=20)
            if token_run.returncode!=0:raise EvidenceError("TSA token extraction failed.")
            candidates=[]
            for cert in pkcs7.load_der_pkcs7_certificates(token.read_bytes()):
                try:
                    eku=cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
                    if ExtendedKeyUsageOID.TIME_STAMPING in eku:
                        candidates.append(cert)
                except x509.ExtensionNotFound:pass
            if len(candidates)!=1:raise EvidenceError("Token does not identify exactly one TSA-signing certificate.")
            signer=candidates[0]
            fingerprint=signer.fingerprint(hashes.SHA256()).hex()
            if fingerprint!=policy["signer_sha256"]:
                raise EvidenceError("Signed token TSA fingerprint is not externally pinned.")
            # The token time is untrusted until the following signature/path/nonce check.
            cmd=["ts","-verify","-in",response,"-queryfile",request,
                 "-CAfile",Path(tsa_ca),"-attime",str(int(moment.timestamp()))]
            if tsa_untrusted:cmd.extend(("-untrusted",Path(tsa_untrusted)))
            _invoke(*cmd)
            result.update(status="confirmed",
                          detail="RFC3161 signature, nonce, TSA policy and pins checked at token time.",
                          authority="tsa-signer-sha256:"+fingerprint,
                          attested_time=time_value,policy_oid=policy["policy_oid"],
                          ca_sha256=policy["ca_sha256"],
                          basis="signed RFC3161 token with original nonce request and external signer/CA pins")
            return result
    except (OSError,ValueError,subprocess.TimeoutExpired,ImportError,TypeError,KeyError):
        result.update(status="unverifiable_offline",
                      detail="TSA proof could not be qualified under the externally pinned policy.")
        return result
