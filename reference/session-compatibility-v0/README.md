# Session compatibility V0 offline reference corpus

This directory preserves exact files moved from source commit
`586054ae9787a0df620c1da30b588edb89e7f7da` during the DNP1 clean break.
Paths below this directory are the former repository-relative paths.

The corpus is immutable evidence only. It is outside every solution/project,
compile glob, embedded-resource glob, package and runtime graph. It must not be
used as a compatibility fallback or copied into a production artifact.

`MANIFEST.json` and `SHA256SUMS` bind the canonical UTF-8, BOM-preserving,
LF form of every preserved evidence file so checkout line-ending policy cannot
change its identity. Run
`eng/Test-LegacyReferenceCorpus.ps1` to verify the corpus.
