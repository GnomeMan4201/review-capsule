#!/usr/bin/env python3
# Purpose: independently detect a required-check omission in synthetic Review Record reports; Python 3.12+, pinned project dependencies. [needs Linux runner]
"""Offline research test. Mutates the verifier in memory only; requires --run.
Exit 0: expected controls and counterexample reproduced; 1: mismatch; 2: setup error.
No real participants, network probes, repository writes or qualified external anchors.
"""
import argparse
import base64
import hashlib
import inspect
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types

TARGET = "for ref in sorted(concerns):"
REPLACEMENT = "for ref in ():  # experiment: silently omit mandatory disposition check"

def check_rows(report, code):
    return [c for c in report.get("checks", []) if c.get("code") == code]

def count_matching_missing(report, expected):
    actual = [c.get("subject") for c in check_rows(report, "DISPOSITION_MISSING")
              if c.get("status") == "missing"]
    return set(actual) == expected and len(actual) == len(expected)

def snapshot(report):
    return {
        "exit_code": report["exit_code"],
        "round_status": report.get("round_status"),
        "counts": report.get("counts"),
        "report_format": report.get("report_format", "legacy"),
        "disposition_missing": [
            {"status": x.get("status"), "subject": x.get("subject")}
            for x in check_rows(report, "DISPOSITION_MISSING")
        ],
        "coverage_notices": report.get("coverage_notices"),
        "non_disposition_check_count": sum(
            x.get("code") != "DISPOSITION_MISSING" for x in report["checks"]
        ),
    }

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read_payload(file):
    obj = json.loads(file.read_bytes())
    return json.loads(base64.b64decode(obj["payload"], validate=True))

def independent_obligations(folder):
    """Derive required concern dispositions directly from synthetic signed-object payloads.
    Does not consult rr.verify, check codes or emitted report rows.
    Signature validation remains the responsibility of the pinned verifier control.
    """
    policy = json.loads((folder / "policy.json").read_bytes())
    if policy.get("disposition_required") is not True:
        raise RuntimeError("This test only covers the frozen Round-1 policy=true case")
    required = set()
    for path in sorted((folder / "assessments").rglob("*.json")):
        v = read_payload(path)
        digest = "sha256:" + path.stem
        for item in v["items"]:
            for concern in item["concerns"]:
                required.add((digest, item["id"], concern["cid"]))
    supplied = set()
    for path in sorted((folder / "dispositions").rglob("*.json")):
        c = read_payload(path)["concern_ref"]
        supplied.add((c["assessment_commitment"], c["item_id"], c["cid"]))
    absent = required - supplied
    return {
        "expected_missing": {"/".join(a) for a in absent},
        "declared_concerns": len(required),
        "supplied_dispositions": len(supplied),
        "policy_required": True,
    }

def inject_missing_check(verify_source):
    """Target one exact loop with a transient in-memory substitution.
    No on-disk file or original module is overwritten.
    """
    src = verify_source.read_text(encoding="utf-8")
    if src.count(TARGET) != 1:
        raise RuntimeError("Fault-injection site not unique")
    if "if ref not in dispositions:missing('DISPOSITION_MISSING'" not in src:
        raise RuntimeError("Expected missing-check body not present")
    changed = src.replace(TARGET, REPLACEMENT, 1)
    mod = types.ModuleType("rr._temporary_coverage_fault")
    mod.__package__ = "rr"
    mod.__file__ = str(verify_source)
    exec(compile(changed, str(verify_source) + "#fault-injected", "exec"), mod.__dict__)
    return mod.verify_bundle, hashlib.sha256(src.encode()).hexdigest(), hashlib.sha256(changed.encode()).hexdigest()

def repair_manifest_and_anchor(folder, fixture):
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.serialize import BytesSerializationContext

    new_hash = fixture.manifest(folder)
    ts = Timestamp(bytes.fromhex(new_hash[7:]))
    ts.attestations.add(PendingAttestation("https://example.invalid/synthetic-calendar"))
    file = DetachedTimestampFile(OpSHA256(), ts)
    ctx = BytesSerializationContext()
    file.serialize(ctx)
    (folder / "anchors/record.ots").write_bytes(ctx.getbytes())
    for suffix in ("ots", "tsa"):
        p = folder / ("anchors/record-" + suffix + ".json")
        obj = json.loads(p.read_bytes())
        obj["target"] = new_hash
        p.write_bytes(fixture.canon(obj))
    return new_hash

def execute(verify_func, folder, identity, format_name):
    args = {
        "expected_author_key": identity["author_key"],
        "expected_steward_key": identity["steward_key"],
    }
    if format_name != "legacy":
        args["report_format"] = format_name
    return verify_func(folder, **args)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, required=True, help="Pinned reviewrecord directory")
    ap.add_argument("--expected-commit", required=True, help="Full pinned commit SHA")
    ap.add_argument("--out", type=Path, required=True, help="JSON evidence output")
    ap.add_argument("--run", action="store_true", help="Execute offline synthetic fault-injection controls")
    args = ap.parse_args()
    if not args.run:
        ap.error("pass --run to execute")
    root = args.repo.resolve()
    try:
        verify_path = root / "src/rr/verify.py"
        fixture_path = root / "tests/reference_round.py"
        if not verify_path.is_file() or not fixture_path.is_file():
            raise RuntimeError("Pinned verifier or fixture not found")
        sha = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                             check=True, capture_output=True, text=True, timeout=10).stdout.strip()
        if sha != args.expected_commit:
            raise RuntimeError(f"Commit mismatch: {sha} != {args.expected_commit}")
        sys.path[:0] = [str(root / "src"), str(root / "tests"), str(root / "tools")]
        from rr.verify import verify_bundle as normal_verify
        import reference_round as fixture
        fault_verify, source_sha256, altered_sha256 = inject_missing_check(verify_path)
        formats = ["legacy"]
        if "report_format" in inspect.signature(normal_verify).parameters:
            formats.append("reviewrecord-report/v1")
        with tempfile.TemporaryDirectory(prefix="rr-check-omission-") as t:
            tmp = Path(t)
            valid = tmp / "valid"
            identity = fixture.create(valid)
            missing = tmp / "missing_all_dispositions"
            shutil.copytree(valid, missing)
            deleted = list(sorted((missing / "dispositions").glob("*.json")))
            if len(deleted) != 3:
                raise RuntimeError(f"Expected three synthetic dispositions, got {len(deleted)}")
            for p in deleted: p.unlink()
            rebuilt = repair_manifest_and_anchor(missing, fixture)
            expected_valid = independent_obligations(valid)
            expected_missing = independent_obligations(missing)
            if expected_valid["expected_missing"] or len(expected_missing["expected_missing"]) != 3:
                raise RuntimeError("Oracle fixture count is not 0 vs 3")
            output_rows = []
            for fmt in formats:
                baseline = execute(normal_verify, valid, identity, fmt)
                fault_on_valid = execute(fault_verify, valid, identity, fmt)
                normally_missing = execute(normal_verify, missing, identity, fmt)
                fault_on_missing = execute(fault_verify, missing, identity, fmt)
                other_checks_unchanged = (
                    [c for c in normally_missing["checks"] if c["code"] != "DISPOSITION_MISSING"]
                    == fault_on_missing["checks"]
                )
                base_ok = baseline["exit_code"] == 2 and baseline["counts"]["fail"] == 0 and baseline["counts"]["missing"] == 0
                correct_detector_ok = normally_missing["exit_code"] == 1 and count_matching_missing(
                    normally_missing, expected_missing["expected_missing"]
                )
                fault_effect_ok = (
                    fault_on_missing["exit_code"] == 2
                    and fault_on_missing["counts"]["fail"] == 0
                    and fault_on_missing["counts"]["missing"] == 0
                    and not check_rows(fault_on_missing, "DISPOSITION_MISSING")
                    and other_checks_unchanged
                )
                clean_negative_control_ok = (
                    baseline["exit_code"] == fault_on_valid["exit_code"]
                    and baseline["checks"] == fault_on_valid["checks"]
                    and not check_rows(fault_on_valid, "DISPOSITION_MISSING")
                )
                no_coverage_notices = not any(
                    n.get("scope") == "disposition_presence"
                    for n in (fault_on_missing.get("coverage_notices") or [])
                )
                if fmt != "legacy":
                    fault_effect_ok = fault_effect_ok and no_coverage_notices
                scenarios = [
                    ("valid_baseline", base_ok, baseline),
                    ("valid_with_suppressed_loop_negative_control", clean_negative_control_ok, fault_on_valid),
                    ("missing_dispositions_unmodified", correct_detector_ok, normally_missing),
                    ("missing_dispositions_check_loop_suppressed", fault_effect_ok, fault_on_missing),
                ]
                for label, matched, report in scenarios:
                    oracle = independent_obligations(valid if label.startswith("valid") else missing)
                    actual_report_codes = {x.get("subject") for x in check_rows(report, "DISPOSITION_MISSING")
                                           if x.get("status") == "missing"}
                    result = {
                        "format": fmt,
                        "case": label,
                        "expectation_met": bool(matched),
                        "oracle_expected_missing_count": len(oracle["expected_missing"]),
                        "oracle_expected_missing_subjects": sorted(oracle["expected_missing"]),
                        "reported_missing_count": len(actual_report_codes),
                        "oracle_detects_gap": oracle["expected_missing"] != actual_report_codes,
                        **snapshot(report),
                    }
                    output_rows.append(result)
                    print(("PASS " if matched else "FAIL ") + fmt + " " + label
                          + " exit=" + str(report["exit_code"])
                          + " oracle_gap=" + str(result["oracle_detects_gap"]), flush=True)
            output = {
                "experiment": "One mandatory check loop suppressed in-memory; independent obligations oracle",
                "source_commit": sha,
                "source_verifier_sha256": source_sha256,
                "fault_injected_sha256": altered_sha256,
                "frozen_spec_sha256": sha256(root / "spec/REVIEW_RECORD_SPEC_v0.2.2.md"),
                "synthetic_reference_fixture_sha256": sha256(fixture_path),
                "record_anchor_repaired_to": rebuilt,
                "fault_site": TARGET,
                "fault_substitution": REPLACEMENT,
                "external_anchor_qualification": "not attempted; offline synthetic OTS/TSA fixtures",
                "mutation_is_not_an_input_only_exploit": True,
                "formats": formats,
                "all_expectations_met": all(row["expectation_met"] for row in output_rows),
                "results": output_rows,
            }
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
            print("ALL_EXPECTATIONS_MET=" + str(output["all_expectations_met"]), flush=True)
            return 0 if output["all_expectations_met"] else 1
    except Exception as exc:
        print("SETUP_ERROR: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
