# Offline reviewer context binding; Python 3.12+, cryptography==50.0.2 [needs Linux runner].
"""Fail-closed checks before reviewer-local signing; not a registration anchor check."""
from pathlib import Path
from . import canon, dsse
from .constants import JUDGMENTS, LIMITS, SPEC

class ContextError(ValueError):
    pass

def _document(path):
    try:
        raw=Path(path).read_bytes()
        obj=canon.loads(raw)
        if raw != canon.dumps(obj):
            raise ContextError("Referenced document must use canon-v1 bytes.")
        return obj, canon.digest(raw)
    except (OSError, canon.CanonError) as exc:
        raise ContextError("Referenced document is unreadable or not canon-v1.") from exc

def _hash(value):
    try:
        canon.hash_bytes(value)
        return True
    except (TypeError, ValueError):
        return False

def validate_registration(path, expected_author_key, expected_registration_hash=None):
    if not expected_author_key:
        raise ContextError("An out-of-band --expected-author-key is required.")
    try:
        dsse.public_bytes(expected_author_key)
        raw=Path(path).read_bytes()
        rec=dsse.decode(raw)
    except (OSError, ValueError, dsse.EnvelopeError) as exc:
        raise ContextError("Registration is unreadable or invalid.") from exc
    v=rec.value
    if v.get("type")!="registration" or v.get("author_key")!=expected_author_key:
        raise ContextError("Registration author identity differs from the expected author key.")
    if not dsse.verify_signature(rec,expected_author_key):
        raise ContextError("Registration signature is invalid.")
    if expected_registration_hash is not None and rec.object_hash!=expected_registration_hash:
        raise ContextError("Registration hash differs from out-of-band expected value.")
    if v.get("spec")!=SPEC or v.get("canon")!="canon-v1" or v.get("limits")!=LIMITS:
        raise ContextError("Registration profile or frozen limits statement differs.")
    if (type(v.get("round_id")) is not str or not v["round_id"].strip() or
        type(v.get("work_id")) is not str or not v["work_id"].strip()):
        raise ContextError("Registration is missing round/work identity.")
    try:
        dsse.public_bytes(v["steward_key"])
    except (KeyError,TypeError,ValueError) as exc:
        raise ContextError("Missing/invalid steward public key.") from exc
    if v["steward_key"]==expected_author_key:
        raise ContextError("Author and steward signing keys must differ.")
    if any(not _hash(v.get(k)) for k in ("packet_hash","policy_hash","withheld_commitment")):
        raise ContextError("Missing or malformed registration document digest.")
    prior=v.get("prior_rounds")
    if type(prior) is not list or any(type(x) is not str for x in prior) or len(prior)!=len(set(prior)):
        raise ContextError("Invalid prior-round declarations.")
    if type(v.get("reviewers_target")) is not int or v["reviewers_target"]<1:
        raise ContextError("Invalid reviewer target.")
    if type(v.get("steward_is_author_operator")) is not bool:
        raise ContextError("Missing steward/operator disclosure.")
    return v,rec.object_hash

def validate_context(*,registration,expected_author_key,reviewer_key,
                     round_id,registration_hash,packet=None,policy=None,
                     assessment=None,expected_registration_hash=None):
    reg,real_hash=validate_registration(registration,expected_author_key,
                                        expected_registration_hash)
    if reviewer_key in (reg["author_key"],reg["steward_key"]):
        raise ContextError("Reviewer may not reuse an author/steward signing key.")
    if round_id!=reg["round_id"] or registration_hash!=real_hash:
        raise ContextError("Reviewer document is bound to the wrong registration/round.")
    if assessment is None:
        return reg
    if packet is None or policy is None:
        raise ContextError("Assessment signing/commit requires both packet and policy.")
    packet_value,packet_hash=_document(packet)
    policy_value,policy_hash=_document(policy)
    if packet_hash!=reg["packet_hash"] or policy_hash!=reg["policy_hash"]:
        raise ContextError("Packet or policy digest does not match the signed registration.")
    if type(packet_value) is not list or not 0<len(packet_value)<=1000:
        raise ContextError("Packet must contain 1 to 1000 items.")
    packet_ids=set()
    for item in packet_value:
        if type(item) is not dict or set(item)!={"id","candidate","evidence"}:
            raise ContextError("Malformed packet item.")
        identifier=item["id"]
        if type(identifier) is not str or not identifier.strip() or identifier in packet_ids:
            raise ContextError("Duplicate or missing packet item identifier.")
        packet_ids.add(identifier)
        if type(item["candidate"]) is not str or not item["candidate"].strip():
            raise ContextError("Malformed candidate.")
        if (type(item["evidence"]) is not list or not item["evidence"] or
            any(type(s) is not str or not s.strip() for s in item["evidence"])):
            raise ContextError("Malformed packet evidence.")
    if type(policy_value) is not dict or policy_value.get("judgment_options")!=list(JUDGMENTS):
        raise ContextError("Unsupported policy judgments.")
    if any(type(policy_value.get(k)) is not int or policy_value[k]<1
           for k in ("min_locks","min_reveals","time_box_minutes")):
        raise ContextError("Malformed policy minimums.")
    if (policy_value.get("duplicate_policy")!="first_commit_per_reviewer_key" or
        policy_value.get("withdrawal_policy")!="retain_locks_count_valid_reveals" or
        type(policy_value.get("disposition_required")) is not bool):
        raise ContextError("Unsupported policy.")
    items=assessment.get("items") if type(assessment) is dict else None
    if type(items) is not list or len(items)!=len(packet_ids):
        raise ContextError("Assessment must cover every packet item exactly once.")
    ids=[item.get("id") for item in items]
    if (any(type(identifier) is not str for identifier in ids) or
        len(set(ids))!=len(ids) or set(ids)!=packet_ids or
        any(item["judgment"] not in policy_value["judgment_options"] for item in items)):
        raise ContextError("Assessment item identifiers or judgments do not match the frozen packet/policy.")
    return reg
