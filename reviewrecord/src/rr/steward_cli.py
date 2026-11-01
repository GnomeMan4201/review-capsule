# Pre-close steward intake/close CLI; Python 3.12+, cryptography==50.0.2 [needs Linux runner].
"""Offline candidate only. No reveal intake, network, anchors or full bundle export."""
import argparse
import contextlib
import fcntl
import os
import stat
import sys
from datetime import datetime,timezone
from pathlib import Path

from . import canon,dsse,merkle
from .constants import LIMITS
from .review_cli import _read_key,_public,_envelope
from .review_context import validate_registration


MAX_FILE=1024*1024


class StewardError(ValueError):
    pass


def _read(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():
        raise StewardError("Expected a local regular file, not a symlink.")
    with path.open("rb") as stream:
        value=stream.read(MAX_FILE+1)
    if len(value)>MAX_FILE:
        raise StewardError("File exceeds the intake byte limit.")
    return value


def _store(path,raw):
    path=Path(path)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise StewardError("Refusing a non-directory or linked output parent.")
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
    if hasattr(os,"O_NOFOLLOW"):flags|=os.O_NOFOLLOW
    fd=os.open(path,flags,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb") as out:
            fd=-1
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        if fd>=0:os.close(fd)
        # A failed write is never treated as an accepted event.
        path.unlink(missing_ok=True)
        raise


def _directory(path):
    if path.is_symlink():raise StewardError("Symlinked directory refused.")
    if not path.exists():path.mkdir(mode=0o700)
    if not path.is_dir():raise StewardError("Expected a directory.")
    if os.name=="posix" and (stat.S_IMODE(path.stat().st_mode)&0o077):
        raise StewardError("Steward workspace directories must be private (0700).")


@contextlib.contextmanager
def _lock(root):
    path=root/"lock"
    if path.is_symlink():raise StewardError("Linked lock path refused.")
    fd=os.open(path,os.O_RDWR | os.O_CREAT | getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)


def _valid_reg(root,expected_author_key,expected_hash=None):
    if root.is_symlink() or not root.is_dir():
        raise StewardError("Unknown or linked steward workspace.")
    state=canon.loads(_read(root/"state.json"))
    if type(state) is not dict or state.get("author_key")!=expected_author_key:
        raise StewardError("Workspace author pin mismatch.")
    bundle=root/"bundle"
    _directory(bundle)
    reg,h=validate_registration(bundle/"registration.json",expected_author_key,
                                 expected_hash or state.get("registration_hash"))
    if h!=state.get("registration_hash") or reg["steward_key"]!=state.get("steward_key"):
        raise StewardError("Workspace registration binding mismatch.")
    for name,field in (("packet.json","packet_hash"),("policy.json","policy_hash")):
        raw=_read(bundle/name)
        value=canon.loads(raw)
        if raw!=canon.dumps(value) or canon.digest(raw)!=reg[field]:
            raise StewardError("Workspace packet/policy no longer matches signed registration.")
    if _read(bundle/"limits.txt")!=(LIMITS+"\n").encode():
        raise StewardError("Workspace limits changed.")
    return state,reg,bundle


def _objects(bundle,reg,registration_hash):
    objects={}
    for kind,folder in (("declaration","declarations"),("commit","commits"),("withdrawal","withdrawals")):
        directory=bundle/folder
        if not directory.exists():continue
        if directory.is_symlink():raise StewardError("Linked input directory.")
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():raise StewardError("Linked input object.")
            if not path.is_file():continue
            record=dsse.decode(_read(path));v=record.value
            key=v.get("reviewer_key")
            if (v.get("type")!=kind or type(key) is not str or
                key in (reg["author_key"],reg["steward_key"]) or
                not dsse.verify_signature(record,key)):
                raise StewardError("Stored object failed reviewer identity/signature checks.")
            if v.get("round_id")!=reg["round_id"] or v.get("registration_hash")!=registration_hash:
                raise StewardError("Stored object registration binding mismatch.")
            from .verify import rid
            if path.relative_to(bundle).as_posix()!=folder+"/"+rid(key)+"/"+record.object_hash[7:]+".json":
                raise StewardError("Stored object is not at its hash-bound path.")
            if kind=="withdrawal" and "steward_attested" in v:
                raise StewardError("Steward-attested withdrawals need a separate, explicit path.")
            if kind=="commit":
                try:canon.hash_bytes(v["commitment"])
                except (KeyError,ValueError,TypeError):
                    raise StewardError("Malformed stored commitment.") from None
            objects[record.object_hash]=(kind,v,record)
    return objects


def _scan(bundle,reg,registration_hash):
    objects=_objects(bundle,reg,registration_hash)
    directory=bundle/"log"
    entries=sorted(directory.glob("*.json"),key=lambda p: int(p.stem) if p.stem.isdecimal() else -1) if directory.exists() else []
    if directory.exists() and directory.is_symlink():
        raise StewardError("Linked log directory.")
    if directory.exists() and any(p.is_symlink() or not p.is_file() for p in directory.iterdir()):
        raise StewardError("Unexpected linked or non-file log entry.")
    if any(p.stem!=str(i) for i,p in enumerate(entries,1)):
        raise StewardError("Log sequence contains a gap, duplicate or unexpected name.")
    previous=registration_hash
    seen=set();declarations=set();commits=[];first=set();withdrawals={}
    for number,path in enumerate(entries,1):
        e=dsse.decode(_read(path));v=e.value
        if (v.get("type")!="logentry" or not dsse.verify_signature(e,reg["steward_key"]) or
            v.get("seq")!=number or v.get("round_id")!=reg["round_id"] or
            v.get("registration_hash")!=registration_hash or v.get("prev_entry_hash")!=previous):
            raise StewardError("Stored log chain or signature failed.")
        ref=v.get("ref_hash");obj=objects.get(ref)
        if not obj or obj[0]!=v.get("kind") or ref in seen:
            raise StewardError("Log references a missing, replayed or wrong-type object.")
        seen.add(ref);kind,value,_=obj;key=value["reviewer_key"]
        if kind=="declaration":
            if key in declarations:raise StewardError("Repeated reviewer declaration refused.")
            declarations.add(key)
        else:
            if key not in declarations:raise StewardError("Commit/withdrawal preceded declaration.")
            if kind=="commit":
                commits.append((key,value["commitment"]))
                first.add(key)
            else:withdrawals[key]=value.get("reason")
        previous=e.object_hash
    if set(objects)!=seen:
        raise StewardError("Orphan signed object: stop instead of repairing a partial append.")
    return previous,entries,objects,declarations,commits,first,withdrawals


def initialize(root,reg_path,packet_path,policy_path,expected_author_key,steward_private):
    reg_hash=None
    reg,reg_hash=validate_registration(reg_path,expected_author_key)
    signer=_read_key(steward_private)
    if _public(signer)!=reg["steward_key"]:
        raise StewardError("Local steward signing key differs from signed registration.")
    files={}
    for path,field in ((packet_path,"packet_hash"),(policy_path,"policy_hash")):
        data=_read(path);value=canon.loads(data)
        if data!=canon.dumps(value) or canon.digest(data)!=reg[field]:
            raise StewardError("Frozen input is not canonical or disagrees with registration.")
        files["packet.json" if field=="packet_hash" else "policy.json"]=data
    if root.exists() or root.is_symlink():
        raise StewardError("Refusing to reuse an existing workspace.")
    root.mkdir(mode=0o700)
    bundle=root/"bundle";_directory(bundle)
    for name,raw in (("registration.json",_read(reg_path)),
                     ("packet.json",files["packet.json"]),
                     ("policy.json",files["policy.json"]),
                     ("limits.txt",(LIMITS+"\n").encode())):
        _store(bundle/name,raw)
    _store(root/"state.json",canon.dumps({
        "author_key":expected_author_key,
        "steward_key":reg["steward_key"],
        "registration_hash":reg_hash
    }))
    _store(root/"lock",b"")
    return reg_hash


def intake(root,source,expected_author_key,steward_private):
    # Reject leaked assessments before reading or writing the workspace.
    raw=_read(source)
    rec=dsse.decode(raw);v=rec.value
    if v.get("type") not in ("declaration","commit","withdrawal"):
        raise StewardError("Pre-close intake refuses this object type without storing it.")
    key=v.get("reviewer_key")
    if type(key) is not str or not dsse.verify_signature(rec,key):
        raise StewardError("Invalid reviewer signature.")
    with _lock(root):
        state,reg,bundle=_valid_reg(root,expected_author_key)
        if (bundle/"close.json").exists():
            raise StewardError("Round is closed; pre-close append is prohibited.")
        if key in (reg["author_key"],reg["steward_key"]):
            raise StewardError("Reviewer signing key conflicts with author/steward.")
        if v.get("registration_hash")!=state["registration_hash"] or v.get("round_id")!=reg["round_id"]:
            raise StewardError("Reviewer object is for another registered round.")
        previous,entries,objects,declarations,commits,first,withdrawals=_scan(bundle,reg,state["registration_hash"])
        if rec.object_hash in objects:
            raise StewardError("Replayed signed object refused.")
        kind=v["type"]
        if kind=="declaration":
            if key in declarations:raise StewardError("Repeated declaration refused.")
            if (not all(type(v.get(k)) is str and v[k].strip()
                       for k in ("relationship_to_author","stake_in_result","prior_exposure")) or
                v.get("identity_disclosure") not in ("real","pseudonym","anonymous") or
                type(v.get("credit_consent")) is not bool):
                raise StewardError("Incomplete reviewer declaration.")
        elif key not in declarations:
            raise StewardError("Declaration must precede commitment or withdrawal.")
        if kind=="commit":
            try:canon.hash_bytes(v["commitment"])
            except (ValueError,KeyError,TypeError):
                raise StewardError("Malformed commitment.") from None
        if kind=="withdrawal" and "steward_attested" in v:
            raise StewardError("Steward attestation cannot use reviewer intake.")
        from .verify import rid
        folder={"declaration":"declarations","commit":"commits","withdrawal":"withdrawals"}[kind]
        p=bundle/folder/rid(key);_directory(bundle/folder);_directory(p)
        obj_path=p/(rec.object_hash[7:]+".json")
        seq=len(entries)+1
        entry={
            "type":"logentry","round_id":reg["round_id"],
            "registration_hash":state["registration_hash"],
            "seq":seq,"kind":kind,"ref_hash":rec.object_hash,
            "prev_entry_hash":previous
        }
        receipt=_envelope(entry,_read_key(steward_private))
        if not dsse.verify_signature(dsse.decode(receipt),reg["steward_key"]):
            raise StewardError("Steward signing key mismatch.")
        # Object first; if receipt cannot be written, future scans fail closed
        # because the unacknowledged object is an orphan, not silently repaired.
        _store(obj_path,raw)
        _directory(bundle/"log")
        _store(bundle/"log"/(str(seq)+".json"),receipt)
        return seq,canon.digest(receipt)


def close(root,expected_author_key,steward_private):
    with _lock(root):
        state,reg,bundle=_valid_reg(root,expected_author_key)
        if (bundle/"close.json").exists():
            raise StewardError("Close already exists; immutable declared boundary.")
        previous,entries,objects,declarations,commits,first,withdrawals=_scan(bundle,reg,state["registration_hash"])
        signer=_read_key(steward_private)
        if _public(signer)!=reg["steward_key"]:
            raise StewardError("Local key is not this round's steward signing key.")
        leaves=[canon.hash_bytes(commitment) for _,commitment in commits]
        withdrawn=[
            {"reviewer_key":key,**({"reason":reason} if reason is not None else {})}
            for key,reason in sorted(withdrawals.items())
        ]
        value={
            "type":"close","round_id":reg["round_id"],
            "registration_hash":state["registration_hash"],
            "final_seq":len(entries),"last_entry_hash":previous,
            "tree_size":len(leaves),"tree_head":"sha256:"+merkle.root(leaves).hex(),
            "locked_count":len(first),"withdrawn":withdrawn,
            "closed_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
        }
        data=_envelope(value,signer)
        _store(bundle/"close.json",data)
        return canon.digest(data)


def main(argv=None):
    p=argparse.ArgumentParser(description="Offline steward candidate: init, pre-close intake, close.")
    sub=p.add_subparsers(dest="command",required=True)
    init=sub.add_parser("init",help="Register a new local workspace; never overwrite.")
    init.add_argument("--registration",type=Path,required=True)
    init.add_argument("--packet",type=Path,required=True)
    init.add_argument("--policy",type=Path,required=True)
    intake_p=sub.add_parser("intake",help="Accept signed reviewer metadata only; reject assessments.")
    intake_p.add_argument("--input",type=Path,required=True)
    sub.add_parser("close",help="Sign immutable close from the checked log.")
    for command in (init,intake_p,sub.choices["close"]):
        command.add_argument("--workspace",type=Path,required=True)
        command.add_argument("--expected-author-key",required=True)
        command.add_argument("--steward-private-key",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        if args.command=="init":
            value=initialize(args.workspace,args.registration,args.packet,args.policy,
                             args.expected_author_key,args.steward_private_key)
            print("Registered local workspace: "+value)
        elif args.command=="intake":
            seq,hash_value=intake(args.workspace,args.input,args.expected_author_key,
                                  args.steward_private_key)
            print("Steward acknowledgement seq="+str(seq)+" hash="+hash_value)
        else:
            print("Signed close: "+close(args.workspace,args.expected_author_key,
                                         args.steward_private_key))
        return 0
    except (OSError,ValueError,TypeError,dsse.EnvelopeError,canon.CanonError) as exc:
        # Never echo untrusted assessment bodies or raw signed payloads.
        print("rrsteward: "+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
