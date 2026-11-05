#!/usr/bin/env python3
# Purpose: probe per-check vacuity in synthetic Review Record bundles; Python 3.12+; project dependencies. [needs Linux runner]
"""Read-only, offline experiments; builds and mutates temporary public synthetic fixtures.

Exit: 0 if all defined expectations match; 1 on contradictory output; 2 on setup error.
"""
import argparse
import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

CODES = (
    "LOG_CHAIN_BROKEN", "TREE_HEAD_MISMATCH", "ACK_MISSING",
    "DECLARATION_MALFORMED", "ENVELOPE_MALFORMED",
    "HASH_MISMATCH", "PATH_HASH_MISMATCH"
)

def rows(report, code):
    return [
        {"status": check.get("status"), "subject": check.get("subject")}
        for check in report.get("checks", [])
        if check.get("code") == code
    ]

def observed(report):
    return {
        "round_status": report.get("round_status"),
        "exit_code": report.get("exit_code"),
        "counts": report.get("counts"),
        "selected_rows": {code: rr for code in CODES if (rr := rows(report, code))},
    }

def last_log_deleted(folder):
    logs = sorted((folder / "log").glob("*.json"), key=lambda p: int(p.stem))
    if not logs: raise ValueError("No logs")
    logs[-1].unlink()

def swapped_log(folder):
    a, b = folder / "log/1.json", folder / "log/2.json"
    aa, bb = a.read_bytes(), b.read_bytes()
    a.write_bytes(bb)
    b.write_bytes(aa)

def truncated_declaration(folder):
    decs = sorted((folder / "declarations").rglob("*.json"))
    if not decs: raise ValueError("No declarations")
    decs[0].write_bytes(b"{}")

def valid_signature_malformed_declaration(folder, ref):
    decs = sorted((folder / "declarations").rglob("*.json"))
    if not decs: raise ValueError("No declarations")
    entry = json.loads(decs[0].read_bytes())
    val = json.loads(base64.b64decode(entry["payload"]))
    role = next((role for role in ("reviewer-a", "reviewer-b", "reviewer-c")
                if ref.pub(role) == val["reviewer_key"]), None)
    if role is None: raise ValueError("No matching synthetic reviewer")
    val["relationship_to_author"] = " "
    decs[0].write_bytes(ref.envelope(val, role))

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, required=True, help="Pinned reviewrecord/ root")
    ap.add_argument("--expected-commit", required=True, help="Full pinned SHA")
    ap.add_argument("--json-out", type=Path, required=True, help="Output evidence JSON")
    args = ap.parse_args()
    root = args.repo.resolve()
    if not (root / "src/rr/verify.py").is_file() or not (root / "tests/reference_round.py").is_file():
        print("SETUP ERROR: project root lacks verifier or synthetic fixture", file=sys.stderr)
        return 2
    try:
        got = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True, timeout=10).stdout.strip()
        if got != args.expected_commit:
            print("SETUP ERROR: expected commit " + args.expected_commit + " but got " + got, file=sys.stderr)
            return 2
        sys.path[:0] = [str(root / "src"), str(root / "tests"), str(root / "tools")]
        from rr.verify import verify_bundle
        import reference_round as ref
        with tempfile.TemporaryDirectory(prefix="rr-zade-") as td:
            temp = Path(td)
            base = temp / "baseline"
            meta = ref.create(base)
            def check(folder):
                return verify_bundle(folder, expected_author_key=meta["author_key"],
                                     expected_steward_key=meta["steward_key"])
            scenarios = [
                ("baseline", None, lambda r: r["round_status"] == "complete" and r["exit_code"] == 2),
                ("delete_final_log", last_log_deleted,
                 lambda r: r["exit_code"] == 1
                 and any(x["status"] == "pass" for x in rows(r, "LOG_CHAIN_BROKEN"))
                 and any(x["status"] == "fail" for x in rows(r, "TREE_HEAD_MISMATCH"))),
                ("reorder_logs_negative_control", swapped_log,
                 lambda r: r["exit_code"] == 1
                 and any(x["status"] == "fail" for x in rows(r, "LOG_CHAIN_BROKEN"))),
                ("truncate_declaration", truncated_declaration,
                 lambda r: r["exit_code"] == 1
                 and any(x["status"] == "pass" for x in rows(r, "DECLARATION_MALFORMED"))
                 and any(x["status"] == "fail" for x in rows(r, "ENVELOPE_MALFORMED"))),
                ("signed_invalid_declaration_negative_control",
                 lambda p: valid_signature_malformed_declaration(p, ref),
                 lambda r: r["exit_code"] == 1
                 and any(x["status"] == "fail" for x in rows(r, "DECLARATION_MALFORMED"))),
            ]
            results = []
            for label, mutation, expected in scenarios:
                if mutation is None:
                    folder = base
                else:
                    folder = temp / label
                    shutil.copytree(base, folder)
                    mutation(folder)
                report = check(folder)
                ok = bool(expected(report))
                result = {"scenario": label, "expectation_met": ok, **observed(report)}
                results.append(result)
                print(("PASS " if ok else "FAIL ") + label +
                      " | exit=" + str(report["exit_code"]) +
                      " | round=" + str(report["round_status"]), flush=True)
            result = {
                "source_commit": got,
                "fixture": "Synthetic public keys only; no real participants",
                "all_expectations_met": all(r["expectation_met"] for r in results),
                "scenarios": results,
            }
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print("ALL_EXPECTATIONS_MET=" + str(result["all_expectations_met"]), flush=True)
            return 0 if result["all_expectations_met"] else 1
    except Exception as exc:
        print(f"SETUP ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
