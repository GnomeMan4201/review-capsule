# Final-bundle assembly from signed actor objects; Python 3.12+, project deps [needs Linux runner].
"""Offline candidate export. The exporter does not authenticate anchors or certify a round."""
import argparse
import os
import shutil
import sys
from pathlib import Path

from . import canon,dsse
from .constants import SPEC
from .steward_cli import _valid_reg,_scan,_checked_close,_check_existing_reveals,_read
from .review_context import validate_context

class BundleError(ValueError):
    pass

def _valid_relative(path):
    from .verify import safe_path
    if not safe_path(path):raise BundleError("Unsafe bundle-relative path.")

def _collect(bundle):
    source={}
    folders={"declarations","commits","withdrawals","log","assessments","proofs"}
    names={"registration.json","policy.json","packet.json","limits.txt","close.json"}
    for p in sorted(bundle.rglob("*")):
        if p.is_symlink():raise BundleError("Symlink in source round workspace.")
        if p.is_dir():continue
        if not p.is_file():raise BundleError("Unexpected non-file source node.")
        path=p.relative_to(bundle).as_posix()
        _valid_relative(path)
        if path not in names and path.split("/")[0] not in folders:
            raise BundleError("Unexpected file in steward source bundle.")
        source[path]=_read(p)
    return source

def _dispositions(path,reg,reg_hash,bundle,author_key):
    if path.is_symlink() or not path.is_dir():
        raise BundleError("Disposition input must be a local directory, not a symlink.")
    issues=set()
    for item in (bundle/"assessments").rglob("*.json") if (bundle/"assessments").exists() else []:
        rec=dsse.decode(_read(item))
        v=rec.value
        validate_context(registration=bundle/"registration.json",
            expected_author_key=author_key,reviewer_key=v["reviewer_key"],
            round_id=v["round_id"],registration_hash=v["registration_hash"],
            packet=bundle/"packet.json",policy=bundle/"policy.json",
            assessment=v,expected_registration_hash=reg_hash)
        for answer in v["items"]:
            for concern in answer["concerns"]:
                issues.add((rec.object_hash,answer["id"],concern["cid"]))
    files={};seen=set()
    for number,p in enumerate(sorted(path.iterdir()),1):
        if p.is_symlink() or not p.is_file() or p.suffix!=".json":
            raise BundleError("Unexpected disposition file or symlink.")
        record=dsse.decode(_read(p));v=record.value
        if (v.get("type")!="disposition" or not dsse.verify_signature(record,author_key) or
            v.get("round_id")!=reg["round_id"] or v.get("registration_hash")!=reg_hash):
            raise BundleError("Disposition signature/round binding failed.")
        ref=v.get("concern_ref")
        if type(ref) is not dict or set(ref)!={"assessment_commitment","item_id","cid"}:
            raise BundleError("Malformed disposition concern reference.")
        k=(ref["assessment_commitment"],ref["item_id"],ref["cid"])
        if k not in issues or k in seen:
            raise BundleError("Missing, duplicate or unknown concern reference.")
        if (v.get("status") not in ("adopted","under_examination","unresolved","declined") or
            type(v.get("reason")) is not str or not v["reason"].strip() or
            (v["status"]=="adopted" and
                (type(v.get("change_ref")) is not str or not v["change_ref"].strip()))):
            raise BundleError("Invalid disposition status/reason.")
        seen.add(k);files["dispositions/"+str(number)+".json"]=_read(p)
    if issues!=seen:
        raise BundleError("Every declared concern must have an author-signed disposition.")
    return files

def _anchors(path,targets):
    if path is None:return {}
    if path.is_symlink() or not path.is_dir():
        raise BundleError("Anchors must be provided from an ordinary local directory.")
    files={}
    for p in sorted(path.iterdir()):
        if p.is_symlink() or not p.is_file():
            raise BundleError("Anchors directory includes unexpected link or node.")
        if p.name in files or not p.name or "/" in p.name or p.name in (".",".."):
            raise BundleError("Invalid anchor filename.")
        raw=_read(p)
        if p.suffix==".json":
            try:
                v=canon.loads(raw)
                if type(v) is not dict or v.get("target") not in targets:
                    raise BundleError("Anchor descriptor is not bound to a bundle target.")
            except canon.CanonError as exc:
                raise BundleError("Invalid anchor descriptor JSON.") from exc
        files["anchors/"+p.name]=raw
    return files

def assemble(*,workspace,expected_author_key,withheld_path,
             disposition_dir,output,anchor_dir=None,allow_incomplete=False):
    state,reg,bundle=_valid_reg(workspace,expected_author_key)
    previous,entries,objects,declarations,commits,first,withdrawals=_scan(
        bundle,reg,state["registration_hash"])
    _checked_close(bundle,reg,state["registration_hash"],previous,
                   entries,commits,first,withdrawals)
    leaves=[canon.hash_bytes(value) for _,value in commits]
    _check_existing_reveals(bundle,reg,state["registration_hash"],commits,leaves)
    withheld=_read(withheld_path)
    w=canon.loads(withheld)
    if withheld!=canon.dumps(w) or canon.hash_value(w)!=reg["withheld_commitment"]:
        raise BundleError("Author withheld result/salt does not match registration.")
    files=_collect(bundle)
    files["withheld.json"]=withheld
    files.update(_dispositions(disposition_dir,reg,state["registration_hash"],bundle,
                               expected_author_key))
    items=[{"path":name,"sha256":canon.digest(data)} for name,data in sorted(files.items())]
    projection={"files":items,"spec":SPEC}
    record_hash=canon.hash_value(projection)
    files["manifest.json"]=canon.dumps(projection|{"record_hash":record_hash})
    from . import dsse as application_dsse
    close_hash=application_dsse.decode(files["close.json"]).object_hash
    targets={state["registration_hash"],close_hash,record_hash}
    if anchor_dir is None and not allow_incomplete:
        raise BundleError("No anchor evidence supplied; use --allow-incomplete for synthetic/diagnostic export.")
    files.update(_anchors(anchor_dir,targets))
    if output.exists() or output.is_symlink():
        raise BundleError("Refusing to overwrite existing output directory.")
    output.mkdir(mode=0o700)
    for name,data in sorted(files.items()):
        p=output/name
        p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
        fd=os.open(p,flags,0o600)
        with os.fdopen(fd,"wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    # No claim about external anchor confirmation or independent round completion.
    return record_hash

def main(argv=None):
    p=argparse.ArgumentParser(description="Assemble candidate bundle; run rrverify separately.")
    p.add_argument("--workspace",type=Path,required=True)
    p.add_argument("--expected-author-key",required=True)
    p.add_argument("--withheld",type=Path,required=True)
    p.add_argument("--dispositions",type=Path,required=True)
    p.add_argument("--anchors",type=Path,
                   help="User-provided proofs/descriptors; exporter does NOT validate external authorities.")
    p.add_argument("--allow-incomplete",action="store_true",
                   help="Explicitly write diagnostic bundle without anchors (not Round-1 eligible).")
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args(argv)
    try:
        h=assemble(workspace=a.workspace,expected_author_key=a.expected_author_key,
            withheld_path=a.withheld,disposition_dir=a.dispositions,output=a.output,
            anchor_dir=a.anchors,allow_incomplete=a.allow_incomplete)
        print("Candidate bundle assembled. Record hash="+h)
        print("Run rrverify. Export is not proof of external anchor validity.",file=sys.stderr)
        return 0
    except (OSError,ValueError,TypeError,dsse.EnvelopeError,canon.CanonError) as exc:
        print("rrbundle: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
