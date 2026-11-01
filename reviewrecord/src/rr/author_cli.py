# Author-local registration and disposition signing; Python 3.12+, cryptography==50.0.2 [needs Linux runner].
"""Offline candidate. Never transmits withheld answers or publishes an unanchored registration."""
import argparse
import base64
import re
import sys
from datetime import datetime,timezone
from pathlib import Path

from . import canon,dsse,merkle
from .constants import SPEC,LIMITS,JUDGMENTS
from .review_cli import _read_key,_public,_envelope,_save_new,_private_assessment_path
from .review_context import validate_registration

class AuthorError(ValueError):
    pass

def _json(path):
    try:return canon.loads(Path(path).read_bytes())
    except (OSError,canon.CanonError) as exc:
        raise AuthorError("Input is unreadable or invalid canon-v1-compatible JSON.") from exc

def _utc(time):
    if type(time) is not str or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",time):
        raise AuthorError("Expected ISO-8601 UTC with Z.")
    try:datetime.fromisoformat(time.replace("Z","+00:00"))
    except ValueError:raise AuthorError("Invalid UTC timestamp.") from None

def _validate_inputs(packet,policy,withheld):
    if type(packet) is not list or not 0<len(packet)<=1000:
        raise AuthorError("Packet must have 1 to 1000 items.")
    ids=set()
    for item in packet:
        if type(item) is not dict or set(item)!={"id","candidate","evidence"}:
            raise AuthorError("Malformed packet item.")
        identifier=item["id"]
        if type(identifier) is not str or not identifier.strip() or identifier in ids:
            raise AuthorError("Missing/duplicate item ID.")
        ids.add(identifier)
        if type(item["candidate"]) is not str or not item["candidate"].strip():
            raise AuthorError("Missing candidate conclusion.")
        if (type(item["evidence"]) is not list or not item["evidence"] or
            any(type(x) is not str or not x.strip() for x in item["evidence"])):
            raise AuthorError("Invalid packet evidence.")
    if type(policy) is not dict or set(policy)!={
        "judgment_options","min_locks","min_reveals","time_box_minutes",
        "duplicate_policy","withdrawal_policy","disposition_required"
    }:
        raise AuthorError("Unsupported policy schema.")
    if policy["judgment_options"]!=list(JUDGMENTS) or any(
        type(policy[k]) is not int or policy[k]<1
        for k in ("min_locks","min_reveals","time_box_minutes")
    ) or policy["duplicate_policy"]!="first_commit_per_reviewer_key" or (
        policy["withdrawal_policy"]!="retain_locks_count_valid_reveals"
    ) or type(policy["disposition_required"]) is not bool:
        raise AuthorError("Policy differs from frozen round-1 profile.")
    if type(withheld) is not dict or set(withheld)!={"results","salt"}:
        raise AuthorError("Withheld file must have results and salt.")
    salt=withheld["salt"]
    if (type(salt) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}",salt) or
        len(dsse.b64decode(salt))!=32 or
        base64.urlsafe_b64encode(dsse.b64decode(salt)).decode().rstrip("=")!=salt):
        raise AuthorError("Withheld salt must be 32 random bytes, base64url unpadded.")
    if not isinstance(withheld["results"],dict) or set(withheld["results"])!=ids:
        raise AuthorError("Withheld result IDs must match every packet item.")
    return ids

def register(*,private_key,steward_key,packet_path,policy_path,withheld_path,
             prior_rounds_path,round_id,work_id,reviewers_target,deadline,
             operator_is_author,output):
    private=_read_key(private_key)
    author_key=_public(private)
    dsse.public_bytes(steward_key)
    if steward_key==author_key:raise AuthorError("Author and steward need distinct signing keys.")
    packet=_json(packet_path);policy=_json(policy_path)
    _private_assessment_path(withheld_path,must_exist=True)
    withheld=_json(withheld_path)
    _validate_inputs(packet,policy,withheld)
    prior=_json(prior_rounds_path)
    if (type(prior) is not list or any(type(x) is not str or not x.strip() for x in prior)
            or len(prior)!=len(set(prior))):
        raise AuthorError("Explicit prior-round list is required, even if empty.")
    if type(round_id) is not str or not round_id.strip() or type(work_id) is not str or not work_id.strip():
        raise AuthorError("Round and work identifiers are required.")
    if type(reviewers_target) is not int or reviewers_target<1:
        raise AuthorError("Reviewer target must be a positive integer.")
    _utc(deadline)
    registered_at=datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    payload={
        "type":"registration","spec":SPEC,"canon":"canon-v1",
        "round_id":round_id,"work_id":work_id,
        "author_key":author_key,"steward_key":steward_key,
        "steward_is_author_operator":operator_is_author,
        "limits":LIMITS,
        "packet_hash":canon.hash_value(packet),
        "policy_hash":canon.hash_value(policy),
        "withheld_commitment":canon.hash_value(withheld),
        "reviewers_target":reviewers_target,
        "deadline":deadline,"prior_rounds":prior,
        "registered_at":registered_at
    }
    raw=_envelope(payload,private)
    if not dsse.verify_signature(dsse.decode(raw),author_key):
        raise AuthorError("Author signature self-check failed.")
    _save_new(output,raw)
    return dsse.decode(raw).object_hash

def disposition(*,private_key,registration_path,close_path,assessment_path,
                proof_path,draft_path,output):
    private=_read_key(private_key);author=_public(private)
    reg,registration_hash=validate_registration(registration_path,author)
    close=dsse.decode(Path(close_path).read_bytes());v=close.value
    if (v.get("type")!="close" or not dsse.verify_signature(close,reg["steward_key"]) or
        v.get("round_id")!=reg["round_id"] or
        v.get("registration_hash")!=registration_hash or "status" in v):
        raise AuthorError("Close signature or registration binding failed.")
    assessment=dsse.decode(Path(assessment_path).read_bytes());a=assessment.value
    key=a.get("reviewer_key")
    if (a.get("type")!="assessment" or type(key) is not str or
        key in (author,reg["steward_key"]) or
        not dsse.verify_signature(assessment,key) or
        a.get("round_id")!=reg["round_id"] or
        a.get("registration_hash")!=registration_hash):
        raise AuthorError("Assessment signature or registration binding failed.")
    proof=_json(proof_path)
    if (type(proof) is not dict or set(proof)!={"leaf_index","tree_size","hashes"}
            or type(proof["hashes"]) is not list or
            type(proof["leaf_index"]) is not int or
            type(proof["tree_size"]) is not int or
            proof["tree_size"]!=v.get("tree_size")):
        raise AuthorError("Invalid inclusion-proof metadata.")
    try:
        siblings=[canon.hash_bytes(x) for x in proof["hashes"]]
        root=canon.hash_bytes(v["tree_head"])
        matches=merkle.inclusion(canon.hash_bytes(assessment.object_hash),
                                  proof["leaf_index"],proof["tree_size"],siblings,root)
    except (TypeError,KeyError,ValueError):matches=False
    if not matches:raise AuthorError("Assessment commitment is not in the signed close tree.")
    draft=_json(draft_path)
    if type(draft) is not dict or not {"concern_ref","status","reason"}<=set(draft) or (
        set(draft)-{"concern_ref","status","reason","change_ref"}
    ):
        raise AuthorError("Disposition draft has missing or extra fields.")
    ref=draft["concern_ref"]
    if (type(ref) is not dict or set(ref)!={"assessment_commitment","item_id","cid"} or
        ref["assessment_commitment"]!=assessment.object_hash):
        raise AuthorError("Disposition concern is not bound to the signed assessment.")
    items=a.get("items")
    if (type(items) is not list or not any(
        type(item) is dict and item.get("id")==ref["item_id"] and
        type(item.get("concerns")) is list and any(
            type(x) is dict and x.get("cid")==ref["cid"] for x in item["concerns"])
        for item in items)):
        raise AuthorError("Concern does not appear in the signed reviewer assessment.")
    if (draft["status"] not in ("adopted","under_examination","unresolved","declined")
            or type(draft["reason"]) is not str or not draft["reason"].strip()
            or (draft["status"]=="adopted" and
                (type(draft.get("change_ref")) is not str or not draft["change_ref"].strip()))):
        raise AuthorError("Missing/invalid disposition status, reason or change reference.")
    payload={
        "type":"disposition","round_id":reg["round_id"],
        "registration_hash":registration_hash,**draft
    }
    raw=_envelope(payload,private)
    _save_new(output,raw)
    return dsse.decode(raw).object_hash

def main(argv=None):
    p=argparse.ArgumentParser(description="Offline author candidate: sign registration and dispositions.")
    sub=p.add_subparsers(dest="command",required=True)
    make=sub.add_parser("register",help="Sign registration; never publish withheld results.")
    make.add_argument("--private-key",type=Path,required=True)
    make.add_argument("--steward-key",required=True)
    make.add_argument("--packet",type=Path,required=True)
    make.add_argument("--policy",type=Path,required=True)
    make.add_argument("--withheld",type=Path,required=True)
    make.add_argument("--prior-rounds",type=Path,required=True,
                      help="Explicit JSON array; [] intentionally declares no earlier rounds.")
    make.add_argument("--round-id",required=True)
    make.add_argument("--work-id",required=True)
    make.add_argument("--reviewers-target",required=True,type=int)
    make.add_argument("--deadline",required=True)
    make.add_argument("--operator-is-author",action="store_true")
    make.add_argument("--output",type=Path,required=True)
    disp=sub.add_parser("disposition",help="Sign a verified post-close concern disposition.")
    for name in ("private-key","registration","close","assessment","proof","draft","output"):
        disp.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args(argv)
    try:
        if a.command=="register":
            h=register(private_key=a.private_key,steward_key=a.steward_key,
                packet_path=a.packet,policy_path=a.policy,withheld_path=a.withheld,
                prior_rounds_path=a.prior_rounds,round_id=a.round_id,work_id=a.work_id,
                reviewers_target=a.reviewers_target,deadline=a.deadline,
                operator_is_author=a.operator_is_author,output=a.output)
        else:
            h=disposition(private_key=a.private_key,registration_path=a.registration,
                close_path=a.close,assessment_path=a.assessment,proof_path=a.proof,
                draft_path=a.draft,output=a.output)
        print("Signed object hash: "+h)
        return 0
    except (OSError,ValueError,TypeError,canon.CanonError,dsse.EnvelopeError) as exc:
        print("rrauthor: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
