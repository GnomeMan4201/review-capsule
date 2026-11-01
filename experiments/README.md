# Exploratory benchmark: Review Record vs signed Git commit/reveal

**Synthetic local comparison only. Not a real review, external timestamp proof, or deployed service.**

The test compares actual `rr.verify.verify_bundle` from pinned protocol commit `d54432f3e4c67f11ea53c16ebb383c1aec1f9224` against a competent signed-Git baseline. That baseline uses ephemeral OpenSSH Ed25519 keys, role-pinned signed annotated Git tags for registration, three reviewer commitments, steward close, and dispositions. It also checks the frozen packet and policy, post-close assessment hashes, complete signed close set, and disposition obligation.

**Deliberately equal obligations:** Both sides require all disclosed concern IDs to have dispositions. Both receive all their retained evidence and already-pinned signing keys. The Git repository is **local**, not actually pushed to GitHub; the word "public" in the research question is simulated and no platform-specific public visibility is proven.

Five paired mutations: (1) substituted assessment, (2) missing reveal, (3) omitted disposition, (4) suppressed commitment, (5) replaced close. The normal fixture must have zero failed/missing checks; Review Record `exit 2` from pending/unverifiable anchors **does not count as attack detection**. We compare explicit failed/missing findings from each verifier.

Run [needs Linux runner]: Python 3.12+, git, OpenSSH `ssh-keygen`, native OpenSSL, and pinned Review Record dependencies (`cryptography==50.0.2`, `opentimestamps-client==0.8.0`). The experiment code itself is Python stdlib-first and writes only a designated JSON result and ephemeral synthetic temp directories; execution requires `--run`.

```sh
git clone https://github.com/GnomeMan4201/review-capsule.git
cd review-capsule
git checkout experiment/commit-reveal-baseline-2026-11-01
git clone https://github.com/GnomeMan4201/review-capsule.git upstream
git -C upstream checkout --detach d54432f3e4c67f11ea53c16ebb383c1aec1f9224
python3 -m pip install -e ./upstream/reviewrecord
python3 experiments/compare.py --run --rr-source upstream/reviewrecord --output comparison-results.json
```

The GitHub Actions workflow on this branch runs the benchmark and uploads `comparison-results.json` as an artifact. The protocol PR #2 remains untouched and no merge is needed.

**Limitations:** no live public GitHub tag persistence, no cryptographic external time oracle, no adversarial key compromise, no steward-resigned whole-history replacement, no independent witness receipts, no actor onboarding or performance claims. An honest upstream Git history itself is not inherently append-only or an external timestamp authority. These five attacks are selected because both systems plausibly detect them; do not infer general robustness from their detection. The benchmark may find no incremental detection, in which case further development requires a harder equal-evidence trial.

**Kill criterion:** If the candidate detects no materially important class of manipulation beyond a properly provisioned minimal signed Git baseline, stop expanding Review Record for integrity detection until its added value is demonstrated in harder attacks. No claim about correctness, independence or non-collusion is permitted from this experiment.
