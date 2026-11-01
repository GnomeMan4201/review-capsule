# Local reviewer key/sign/commit CLI; Python 3.12+, cryptography==50.0.2 [needs Linux runner].
"""Reviewer-side only: no network, no steward keys, no pre-close assessment upload."""
import argparse
import base64
import getpass
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import canon, dsse
from .constants import JUDGMENTS


class ReviewerError(ValueError):
    pass


def _public(key):
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "ed25519:" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _password(confirm=False):
    first = getpass.getpass("Local private-key passphrase: ").encode("utf-8")
    if confirm:
        second = getpass.getpass("Confirm passphrase: ").encode("utf-8")
        if first != second:
            raise ReviewerError("Passphrases do not match.")
        if len(first) < 12:
            raise ReviewerError("Use at least 12 UTF-8 bytes for the passphrase.")
    if not first:
        raise ReviewerError("An empty passphrase is not allowed.")
    return first


def _save_new(path, content):
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)
        raise


def _read_key(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ReviewerError("Private key must be an existing local regular file, not a symlink.")
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ReviewerError("Private key permissions must prohibit group/other access (chmod 600).")
    try:
        private = serialization.load_pem_private_key(path.read_bytes(), password=_password())
    except (ValueError, TypeError) as exc:
        raise ReviewerError("Could not unlock an encrypted private key.") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise ReviewerError("Only encrypted Ed25519 PKCS8 private keys are accepted.")
    return private


def _check_common(value, public, kind):
    if type(value) is not dict or value.get("type") != kind:
        raise ReviewerError("Wrong document type.")
    if type(value.get("round_id")) is not str or not value["round_id"].strip():
        raise ReviewerError("Missing round_id.")
    try:
        canon.hash_bytes(value["registration_hash"])
    except (ValueError, TypeError, KeyError):
        raise ReviewerError("Invalid registration_hash.") from None
    if value.get("reviewer_key") != public:
        raise ReviewerError("reviewer_key does not match the local signing key.")


def _validate_review(value, public):
    kind = value.get("type") if type(value) is dict else None
    if kind not in ("declaration", "assessment", "withdrawal"):
        raise ReviewerError("Only reviewer declaration, assessment and withdrawal can be signed.")
    _check_common(value, public, kind)
    mandatory = {"type", "round_id", "registration_hash", "reviewer_key"}
    if kind == "declaration":
        required = mandatory | {
            "relationship_to_author", "stake_in_result", "prior_exposure",
            "identity_disclosure", "credit_consent"
        }
        if not required <= set(value) or set(value) - required - {"history_url"}:
            raise ReviewerError("Unexpected or missing declaration field.")
        if not all(type(value[k]) is str and value[k].strip()
                   for k in ("relationship_to_author", "stake_in_result", "prior_exposure")):
            raise ReviewerError("Incomplete declaration.")
        if value["identity_disclosure"] not in ("real", "pseudonym", "anonymous") or type(value["credit_consent"]) is not bool:
            raise ReviewerError("Invalid identity disclosure or credit consent.")
        if "history_url" in value and (type(value["history_url"]) is not str or not value["history_url"].strip()):
            raise ReviewerError("Invalid optional history_url.")
    elif kind == "withdrawal":
        if set(value) - mandatory - {"reason"}:
            raise ReviewerError("Reviewer withdrawals cannot attest for the steward.")
        if "reason" in value and type(value["reason"]) is not str:
            raise ReviewerError("Invalid withdrawal reason.")
    else:
        if set(value) != mandatory | {"items", "locked_at"}:
            raise ReviewerError("Unexpected or missing assessment field.")
        timestamp = value["locked_at"]
        if type(timestamp) is not str or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", timestamp
        ):
            raise ReviewerError("locked_at must be a UTC ISO-8601 timestamp.")
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            raise ReviewerError("Invalid locked_at.") from None
        items = value["items"]
        if type(items) is not list or not items:
            raise ReviewerError("Assessment items must be a nonempty list.")
        ids = set()
        for item in items:
            if type(item) is not dict or set(item) != {"id", "judgment", "reasoning", "concerns"}:
                raise ReviewerError("Invalid assessment item fields.")
            if type(item["id"]) is not str or not item["id"].strip() or item["id"] in ids:
                raise ReviewerError("Duplicate or empty item id.")
            ids.add(item["id"])
            if item["judgment"] not in JUDGMENTS or type(item["reasoning"]) is not str or not item["reasoning"].strip():
                raise ReviewerError("Invalid item judgment or reasoning.")
            if type(item["concerns"]) is not list:
                raise ReviewerError("Invalid concerns list.")
            cids = set()
            for concern in item["concerns"]:
                if (type(concern) is not dict or set(concern) != {"cid", "text"}
                        or type(concern["cid"]) is not str or not concern["cid"].strip()
                        or type(concern["text"]) is not str or not concern["text"].strip()
                        or concern["cid"] in cids):
                    raise ReviewerError("Duplicate or malformed concern.")
                cids.add(concern["cid"])


def _envelope(payload, private):
    raw = canon.dumps(payload)
    kind = "application/vnd.reviewrecord." + payload["type"] + ".v1+json"
    signed = dsse.pae(kind, raw)
    content = canon.dumps({
        "payloadType": kind,
        "payload": base64.b64encode(raw).decode("ascii"),
        "signatures": [{
            "keyid": _public(private),
            "sig": base64.b64encode(private.sign(signed)).decode("ascii")
        }]
    })
    record = dsse.decode(content)
    if not dsse.verify_signature(record, _public(private)):
        raise ReviewerError("Local signature self-check failed.")
    return content


def _read_json(path):
    try:
        return canon.loads(Path(path).read_bytes())
    except canon.CanonError:
        raise ReviewerError("Input is not valid canon-v1-compatible JSON.") from None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Local reviewer-only key/sign/commit utility; never transmits files."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="Create encrypted reviewer key (never send it).")
    keygen.add_argument("--private-key", type=Path, required=True)
    pubkey = sub.add_parser("pubkey", help="Display reviewer public key only.")
    pubkey.add_argument("--private-key", type=Path, required=True)
    signing = sub.add_parser("sign", help="Sign a local reviewer declaration/assessment/withdrawal.")
    signing.add_argument("--private-key", type=Path, required=True)
    signing.add_argument("--input", type=Path, required=True)
    signing.add_argument("--output", type=Path, required=True)
    commit = sub.add_parser("commit", help="Create signed commit from locally held signed assessment.")
    commit.add_argument("--private-key", type=Path, required=True)
    commit.add_argument("--assessment", type=Path, required=True)
    commit.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            password = _password(confirm=True)
            key = Ed25519PrivateKey.generate()
            encoded = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password)
            )
            _save_new(args.private_key, encoded)
            print(_public(key))
            print("Encrypted private key saved locally. Never share this file.", file=sys.stderr)
        else:
            key = _read_key(args.private_key)
            public = _public(key)
            if args.command == "pubkey":
                print(public)
            elif args.command == "sign":
                payload = _read_json(args.input)
                _validate_review(payload, public)
                _save_new(args.output, _envelope(payload, key))
                print("Signed " + payload["type"] + " written locally.", file=sys.stderr)
                if payload["type"] == "assessment":
                    print("WITHHOLD this assessment until the close is published.", file=sys.stderr)
            else:
                record = dsse.decode(args.assessment.read_bytes())
                if record.value.get("type") != "assessment":
                    raise ReviewerError("Commit source must be a signed assessment.")
                _validate_review(record.value, public)
                if not dsse.verify_signature(record, public):
                    raise ReviewerError("Assessment signature does not match the local reviewer key.")
                payload = {
                    "type": "commit",
                    "round_id": record.value["round_id"],
                    "registration_hash": record.value["registration_hash"],
                    "reviewer_key": public,
                    "commitment": record.object_hash
                }
                _save_new(args.output, _envelope(payload, key))
                print("Signed COMMIT only written locally; send only this commit to the steward.", file=sys.stderr)
        return 0
    except (OSError, ValueError, TypeError, dsse.EnvelopeError) as exc:
        print("rrreview: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
