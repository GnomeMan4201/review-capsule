# Source and implementation baseline

Current profile: REVIEW_RECORD_SPEC_v0.2.2.md, with author resolutions S1–S16 applied. BUILD_BRIEF_v0.2.2.md contains a byte-identical copy of its technical sections 3–6. The limits fixture is extracted from the source statement and includes exactly one LF.

Provenance: author-pasted v0.2.1 is preserved in REVIEW_RECORD_SPEC_v0.2.1_DRAFT.md. The v0.2.2 patch was generated from these actual saved texts. Historical v0.2 itself was never supplied, so no claim of a verified line-by-line comparison against that historical file is made.

FREEZE_v0.2.2.json records the exact current documents, limits, primitive vectors, semantic counting/path vectors and reference-tool bytes before production implementation. Old draft vectors and source files remain historical and are not the frozen current profile.

The vector cross-check is separate code in Python and JavaScript, not separate human authorship or outside review. No complete protocol verifier, signing tool, complete signed-round expected report, real OTS confirmation or reviewer observation is implied.
