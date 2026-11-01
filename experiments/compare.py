#!/usr/bin/env python3
# Paired local integrity-attack experiment, Python 3.12+, git, ssh-keygen, Review Record deps [needs Linux runner].
"""Compare actual pinned rrverify against a competent signed Git-tag baseline; synthetic only."""
import argparse,base64,hashlib,json,shutil,subprocess,sys,tempfile,time
from pathlib import Path
PIN="d54432f3e4c67f11ea53c16ebb383c1aec1f9224"
ATTACKS=("control","assessment_substitution","missing_reveal","omitted_disposition",
         "suppressed_commitment","close_substitution")
ROLES=("author","steward","reviewer-a","reviewer-b","reviewer-c")
def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def digest(x):return "sha256:"+hashlib.sha256(x).hexdigest()
def run(*args,cwd=None,check=True):
    p=subprocess.run([str(x) for x in args],cwd=cwd,text=True,capture_output=True,timeout=45)
    if check and p.returncode:raise RuntimeError(str(args[:4])+" failed: "+p.stderr[-450:])
    return p
def git(root,*args,check=True):return run("git",*args,cwd=root,check=check)
def sign(root,keys,name,role,obj):
    git(root,"-c","gpg.format=ssh","-c","user.signingkey="+str(keys[role][0]),
        "tag","-s","-m",canon(obj).decode(),name,"HEAD")
def git_fixture(parent):
    root=parent/"signed-git";root.mkdir()
    git(root,"init","-q");git(root,"config","user.name","Synthetic Fixture")
    git(root,"config","user.email","fixture@example.invalid")
    keys={};keydir=parent/"ephemeral-keys";keydir.mkdir()
    for actor in ROLES:
        private=keydir/actor
        run("ssh-keygen","-q","-t","ed25519","-N","","-C",actor,"-f",private)
        allowed=keydir/(actor+".allowed")
        allowed.write_text('fixture@example.invalid namespaces="git" '+private.with_suffix(".pub").read_text().strip()+"\n")
        keys[actor]=(private,allowed)
    packet=[{"id":"item-1","evidence":["Stipulated service record for Pump K."],
             "candidate":"The supplied record states a service occurred."}]
    policy={"disposition_required":True,"min_locks":2,"min_reveals":2}
    (root/"packet.json").write_bytes(canon(packet));(root/"policy.json").write_bytes(canon(policy))
    git(root,"add",".");git(root,"commit","-qm","freeze synthetic packet")
    sign(root,keys,"registration","author",
         {"type":"registration","packet":digest((root/"packet.json").read_bytes()),
          "policy":digest((root/"policy.json").read_bytes())})
    commits={};assessments={}
    for actor in ROLES[2:]:
        value={"reviewer":actor,"item_id":"item-1","judgment":"uncertain",
               "reasoning":"The source is stipulated, not authenticated.",
               "concerns":[{"id":actor+":c1","text":"Authenticity unknown"}]}
        assessments[actor]=canon(value);commits[actor]=digest(assessments[actor])
        sign(root,keys,"commit/"+actor,actor,{"type":"commit","reviewer":actor,"hash":commits[actor]})
    sign(root,keys,"close","steward",{"type":"close","commitments":commits,"locked_count":3})
    (root/"reveals").mkdir()
    for actor,raw in assessments.items():(root/"reveals"/(actor+".json")).write_bytes(raw)
    (root/"dispositions.json").write_bytes(canon([
        {"concern":actor+":c1","status":"under_examination",
         "reason":"Synthetic limitation recorded"} for actor in assessments]))
    git(root,"add",".");git(root,"commit","-qm","reveals and author dispositions")
    sign(root,keys,"dispositions","author",
         {"type":"dispositions","hash":digest((root/"dispositions.json").read_bytes())})
    return root,keys
def signed_tag(root,keys,name,role,errors):
    if role not in keys:
        errors.add("UNPINNED_ROLE:"+role);return None
    allowed=keys[role][1]
    check=git(root,"-c","gpg.format=ssh","-c","gpg.ssh.allowedSignersFile="+str(allowed),
              "tag","-v",name,check=False)
    if check.returncode:
        errors.add("BAD_SIGNATURE_OR_MISSING_TAG:"+name);return None
    raw=git(root,"cat-file","tag","refs/tags/"+name).stdout
    try:return json.loads(raw.split("\n\n",1)[1].split("-----BEGIN SSH SIGNATURE-----",1)[0].strip())
    except (ValueError,IndexError):
        errors.add("BAD_TAG_PAYLOAD:"+name);return None
def verify_git(root,keys):
    errors=set()
    reg=signed_tag(root,keys,"registration","author",errors)
    close=signed_tag(root,keys,"close","steward",errors)
    if not isinstance(reg,dict) or not isinstance(close,dict):return sorted(errors)
    for file,field in (("packet.json","packet"),("policy.json","policy")):
        p=root/file
        if not p.is_file() or reg.get(field)!=digest(p.read_bytes()):errors.add("REGISTRATION_BINDING:"+file)
    expected=close.get("commitments")
    if not isinstance(expected,dict):
        errors.add("CLOSE_MALFORMED");return sorted(errors)
    observed=set(git(root,"tag","--list","commit/*").stdout.splitlines())
    if observed!={"commit/"+x for x in expected}:errors.add("COMMITMENT_SET_MISMATCH")
    concerns=set()
    for actor,target in expected.items():
        if actor not in ROLES[2:]:
            errors.add("UNPINNED_REVIEWER");continue
        tag=signed_tag(root,keys,"commit/"+actor,actor,errors)
        if not isinstance(tag,dict) or tag.get("reviewer")!=actor or tag.get("hash")!=target:
            errors.add("COMMIT_MISMATCH:"+actor)
        p=root/"reveals"/(actor+".json")
        if not p.is_file():
            errors.add("REVEAL_MISSING:"+actor);continue
        raw=p.read_bytes()
        if digest(raw)!=target:
            errors.add("REVEAL_HASH_MISMATCH:"+actor);continue
        try:
            item=json.loads(raw)
            if item.get("reviewer")!=actor:errors.add("REVIEWER_MISMATCH:"+actor)
            concerns.update(c["id"] for c in item["concerns"])
        except (KeyError,ValueError,TypeError):errors.add("REVEAL_MALFORMED:"+actor)
    tag=signed_tag(root,keys,"dispositions","author",errors)
    p=root/"dispositions.json"
    if not p.is_file():errors.add("DISPOSITIONS_MISSING")
    else:
        raw=p.read_bytes()
        if not isinstance(tag,dict) or tag.get("hash")!=digest(raw):
            errors.add("DISPOSITION_HASH_MISMATCH")
        try:
            ds=json.loads(raw)
            covered={x["concern"] for x in ds if x.get("reason")}
            if not concerns.issubset(covered):errors.add("DISPOSITION_MISSING")
        except (ValueError,KeyError,TypeError):errors.add("DISPOSITION_MALFORMED")
    return sorted(errors)
def attack_git(root,keys,attack):
    if attack=="assessment_substitution":
        p=root/"reveals/reviewer-a.json";x=json.loads(p.read_bytes())
        x["reasoning"]="Replaced assessment";p.write_bytes(canon(x))
    elif attack=="missing_reveal":(root/"reveals/reviewer-a.json").unlink()
    elif attack=="omitted_disposition":
        p=root/"dispositions.json"
        p.write_bytes(canon([x for x in json.loads(p.read_bytes()) if x["concern"]!="reviewer-a:c1"]))
    elif attack=="suppressed_commitment":git(root,"tag","-d","commit/reviewer-a")
    elif attack=="close_substitution":
        git(root,"tag","-d","close")
        sign(root,keys,"close","reviewer-b",
             {"type":"close","commitments":{"reviewer-b":"sha256:"+"0"*64},"locked_count":1})
def attack_rr(root,attack,ref):
    if attack=="assessment_substitution":
        p=next((root/"assessments").rglob("*.json"))
        env=json.loads(p.read_bytes());v=json.loads(base64.b64decode(env["payload"]))
        v["items"][0]["reasoning"]="Replaced assessment"
        env["payload"]=base64.b64encode(ref.canon(v)).decode()
        p.write_bytes(ref.canon(env))
    elif attack=="missing_reveal":
        next((root/"assessments").rglob("*.json")).unlink();ref.manifest(root)
    elif attack=="omitted_disposition":
        (root/"dispositions/1.json").unlink();ref.manifest(root)
    elif attack=="suppressed_commitment":
        next((root/"commits").rglob("*.json")).unlink();ref.manifest(root)
    elif attack=="close_substitution":
        p=root/"close.json";env=json.loads(p.read_bytes())
        v=json.loads(base64.b64decode(env["payload"]));v["locked_count"]=1
        env["payload"]=base64.b64encode(ref.canon(v)).decode()
        p.write_bytes(ref.canon(env));ref.manifest(root)
def execute(src):
    src=src.resolve()
    if run("git","-C",src,"rev-parse","HEAD").stdout.strip()!=PIN:
        raise RuntimeError("Review Record input is not exact pinned commit "+PIN)
    if not (src/"tests/reference_round.py").exists():raise RuntimeError("Missing RR synthetic generator")
    sys.path[:0]=[str(src/"src"),str(src/"tests")]
    import reference_round
    from rr.verify import verify_bundle
    rows=[]
    for attack in ATTACKS:
        with tempfile.TemporaryDirectory(prefix="rr-git-pair-") as d:
            p=Path(d);rr_dir=p/"review-record"
            meta=reference_round.create(rr_dir)
            g,keys=git_fixture(p)
            if attack!="control":
                attack_rr(rr_dir,attack,reference_round);attack_git(g,keys,attack)
            t=time.monotonic()
            rr=verify_bundle(rr_dir,expected_author_key=meta["author_key"],
                             expected_steward_key=meta["steward_key"])
            tr=round(time.monotonic()-t,4)
            findings=sorted({x["code"] for x in rr["checks"] if x["status"] in ("fail","missing")})
            t=time.monotonic();git_findings=verify_git(g,keys);tg=round(time.monotonic()-t,4)
            rows.append({"attack":attack,"review_record":{"detected":bool(findings),
                "exit_code":rr["exit_code"],"failing_codes":findings,
                "pending_or_unchecked":sum(x["status"] in ("pending","unverifiable","not_checked") for x in rr["checks"]),
                "verify_seconds":tr},"signed_git":{"detected":bool(git_findings),
                "failing_codes":git_findings,"verify_seconds":tg}})
    return rows
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",action="store_true",help="Create ephemeral synthetic test cases; never publishes")
    parser.add_argument("--rr-source",type=Path,help="Pinned checkout's reviewrecord/ directory")
    parser.add_argument("--output",type=Path,default=Path("comparison-results.json"))
    args=parser.parse_args()
    if not args.run:
        parser.print_help();return 0
    if args.rr_source is None:parser.error("--rr-source is required with --run")
    for binary in ("git","ssh-keygen","openssl"):
        if not shutil.which(binary):
            print("ERROR: missing "+binary,file=sys.stderr);return 2
    try:
        rows=execute(args.rr_source)
        added=[r["attack"] for r in rows[1:] if r["review_record"]["detected"] and not r["signed_git"]["detected"]]
        result={"rr_pin":PIN,"synthetic_only":True,"git_remote_published":False,
                "real_anchor_qualified":False,"real_chronology_demonstrated":False,
                "selected_attacks_only":True,"rows":rows,"added_detection_cases":added}
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        print(json.dumps({"matrix":str(args.output),"rows":[
            [r["attack"],r["review_record"]["detected"],r["signed_git"]["detected"]] for r in rows],
            "review_record_added_detection":added},indent=2))
        if rows[0]["review_record"]["detected"] or rows[0]["signed_git"]["detected"]:
            raise RuntimeError("Unaltered fixture generated integrity failure")
        missed=[r["attack"] for r in rows[1:] if not r["review_record"]["detected"] or not r["signed_git"]["detected"]]
        if missed:raise RuntimeError("Missing expected detection: "+str(missed))
        return 0
    except (RuntimeError,ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired) as e:
        print("ERROR:",e,file=sys.stderr);return 1
if __name__=="__main__":raise SystemExit(main())
