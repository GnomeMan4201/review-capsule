#!/usr/bin/env python3
# Purpose: test required-evidence coverage in synthetic Review Record bundles; Python 3.12+, project cryptography and opentimestamps. [needs Linux runner]
"""Offline, temporary-fixture-only experiment. Explicit --run required.
Exit 0 for all expected observations, 1 for disagreement, 2 for setup error.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types

OBLIGATIONS = {
    "close": ("CLOSE_MISSING",),
    "proof": ("INCLUSION_PROOF_INVALID",),
    "declaration": ("ACK_MISSING",),
    "dispositions": ("DISPOSITION_MISSING",),
    "withheld": ("WITHHELD_MISSING",),
    "packet": ("DOCUMENT_MISSING", "PACKET_MALFORMED"),
    "limits": ("LIMITS_MISSING_OR_ALTERED",),
    "last_log": ("TREE_HEAD_MISMATCH",),
}

def rows(report, code):
    return [c for c in report["checks"] if c.get("code") == code]

def has_hard(report, codes):
    return any(c["status"] in ("fail", "missing") for k in codes for c in rows(report, k))

def disposition_rows(report):
    return [c for c in report["checks"]
            if "disposition" in str(c.get("code", "")).lower()
            or "disposition" in str(c.get("subject", "")).lower()]

def delete_one(folder, pattern):
    paths = sorted(folder.glob(pattern))
    if not paths:
        raise RuntimeError("Missing expected fixture file: " + pattern)
    paths[0].unlink()
    return [paths[0].relative_to(folder).as_posix()]

def delete_all(folder, pattern):
    paths = sorted(folder.glob(pattern))
    if not paths:
        raise RuntimeError("No fixture files: " + pattern)
    for p in paths:
        p.unlink()
    return [p.relative_to(folder).as_posix() for p in paths]

def repair_manifest_and_anchor(folder, fixture):
    """Rebuild unsigned inventory and synthetic pending record anchor, not signed objects."""
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.serialize import BytesSerializationContext

    new_hash = fixture.manifest(folder)
    timestamp = Timestamp(bytes.fromhex(new_hash[7:]))
    timestamp.attestations.add(PendingAttestation("https://example.invalid/synthetic-calendar"))
    proof = DetachedTimestampFile(OpSHA256(), timestamp)
    ctx = BytesSerializationContext()
    proof.serialize(ctx)
    (folder / "anchors/record.ots").write_bytes(ctx.getbytes())
    for suffix in ("ots", "tsa"):
        path = folder / ("anchors/record-" + suffix + ".json")
        descriptor = json.loads(path.read_bytes())
        descriptor["target"] = new_hash
        path.write_bytes(fixture.canon(descriptor))
    return new_hash

def alternate_policy_false_fixture(fixture):
    """Alter *only* the synthetic generator in memory, with original source unchanged."""
    path = Path(fixture.__file__)
    text = path.read_text(encoding="utf-8")
    if text.count("disposition_required=True") != 1:
        raise RuntimeError("Cannot pinpoint synthetic policy flag")
    altered = text.replace("disposition_required=True", "disposition_required=False", 1)
    alt = types.ModuleType("altered_synthetic_reference_round")
    alt.__file__ = str(path)
    exec(compile(altered, str(path), "exec"), alt.__dict__)
    return alt, hashlib.sha256(altered.encode()).hexdigest()

def report_snapshot(report):
    return {
        "round_status": report.get("round_status"),
        "exit_code": report["exit_code"],
        "counts": report["counts"],
        "locked_count": report.get("locked_count"),
        "verified_reveals": report.get("verified_reveals"),
        "disposition_row_count": len(disposition_rows(report)),
        "checks": report["checks"],
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, required=True, help="Pinned reviewrecord source directory")
    p.add_argument("--expected-commit", required=True, help="Full source commit SHA")
    p.add_argument("--out", type=Path, required=True, help="JSON artifact file")
    p.add_argument("--run", action="store_true", help="Generate and mutate temporary synthetic fixtures")
    args = p.parse_args()
    if not args.run:
        p.error("explicit --run required for experiment")
    root = args.repo.resolve()
    try:
        if not (root / "src/rr/verify.py").is_file():
            raise RuntimeError("Source directory missing verifier")
        got = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True,
                             timeout=10).stdout.strip()
        if got != args.expected_commit:
            raise RuntimeError("Pinned SHA mismatch: " + got)
        sys.path[:0] = [str(root / "src"), str(root / "tests"), str(root / "tools")]
        from rr.verify import verify_bundle
        import reference_round as fixture

        false_fixture, altered_sha = alternate_policy_false_fixture(fixture)
        with tempfile.TemporaryDirectory(prefix="rr-coverage-") as td:
            tmp = Path(td)
            baseline_path = tmp / "baseline"
            identity = fixture.create(baseline_path)
            def verify(path, **kw):
                return verify_bundle(path,
                    expected_author_key=identity["author_key"],
                    expected_steward_key=identity["steward_key"], **kw)
            baseline = verify(baseline_path)
            baseline_ok = baseline["exit_code"] == 2 and baseline["counts"]["fail"] == 0 \
                          and baseline["counts"]["missing"] == 0 \
                          and baseline["round_status"] == "complete"
            results = [{"case": "baseline", "expectation_met": baseline_ok,
                        "expected": "Complete lock/reveal count, unresolved external checks",
                        **report_snapshot(baseline)}]
            mutations = [
                ("close", lambda p: delete_one(p, "close.json")),
                ("proof", lambda p: delete_one(p, "proofs/*/*.json")),
                ("declaration", lambda p: delete_one(p, "declarations/*/*.json")),
                ("dispositions", lambda p: delete_all(p, "dispositions/*.json")),
                ("withheld", lambda p: delete_one(p, "withheld.json")),
                ("packet", lambda p: delete_one(p, "packet.json")),
                ("limits", lambda p: delete_one(p, "limits.txt")),
                ("last_log", lambda p: delete_one(p, "log/7.json")),
            ]
            for label, mutate in mutations:
                folder = tmp / label
                shutil.copytree(baseline_path, folder)
                deleted = mutate(folder)
                new_hash = repair_manifest_and_anchor(folder, fixture)
                actual = verify(folder)
                matched = actual["exit_code"] == 1 and has_hard(actual, OBLIGATIONS[label])
                results.append({"case": "remove_" + label, "deleted": deleted,
                                "record_hash_after_repair": new_hash,
                                "expected_hard_codes": OBLIGATIONS[label],
                                "expectation_met": matched, **report_snapshot(actual)})
            # The frozen spec says Round 1 disposition_required=true; verifier accepts any bool.
            opted_out = tmp / "false_policy"
            false_fixture.create(opted_out)
            control = verify(opted_out)
            folder = tmp / "false_policy_deleted_dispositions"
            shutil.copytree(opted_out, folder)
            deleted = delete_all(folder, "dispositions/*.json")
            new_hash = repair_manifest_and_anchor(folder, false_fixture)
            actual = verify(folder)
            expected = control["exit_code"] == 2 and actual["exit_code"] == 2 \
                       and actual["counts"]["fail"] == 0 \
                       and actual["counts"]["missing"] == 0 \
                       and not disposition_rows(actual)
            results.append({"case": "signed_optout_all_dispositions_removed",
                            "deleted": deleted, "record_hash_after_repair": new_hash,
                            "expected": "No disposition coverage row and no hard failure (signed opt-out)",
                            "control": {"exit_code": control["exit_code"],
                                        "disposition_row_count": len(disposition_rows(control))},
                            "expectation_met": expected, **report_snapshot(actual)})
            # Registry availability must not silently imply full coverage.
            supplied = verify(baseline_path, registries=[{
                "source": "synthetic known registry", "work_id": identity["work_id"],
                "prior_rounds": ["synthetic-prior-round"]
            }])
            control_ok = bool(rows(baseline, "REGISTRY_NOT_CHECKED")) \
                         and bool(supplied["registry_coverage"])
            results.append({"case": "registry_coverage_control",
                            "expected": "Missing registry marked not_checked; supplied snapshot named",
                            "baseline_registry_not_checked": bool(rows(baseline, "REGISTRY_NOT_CHECKED")),
                            "supplied_registry_coverage": supplied["registry_coverage"],
                            "expectation_met": control_ok, **report_snapshot(supplied)})
            output = {
                "project": "Review Record evidence prerequisite coverage",
                "source_commit": got,
                "spec_sha256": hashlib.sha256(
                    (root / "spec/REVIEW_RECORD_SPEC_v0.2.2.md").read_bytes()).hexdigest(),
                "altered_synthetic_generator_sha256": altered_sha,
                "synthetic_only": True,
                "all_expectations_met": all(c["expectation_met"] for c in results),
                "cases": results
            }
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
            for case in results:
                print(("PASS " if case["expectation_met"] else "FAIL ") +
                      case["case"] + " exit=" + str(case["exit_code"]) +
                      " fails=" + str(case["counts"]["fail"]) +
                      " missing=" + str(case["counts"]["missing"]), flush=True)
            print("ALL_EXPECTATIONS_MET=" + str(output["all_expectations_met"]), flush=True)
            return 0 if output["all_expectations_met"] else 1
    except Exception as e:
        print("SETUP_ERROR: " + type(e).__name__ + ": " + str(e), file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
