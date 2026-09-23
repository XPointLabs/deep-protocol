# Candidate ML-DSA .NET Android runtime probe

This **test-only** APK packages the exact candidate Android arm64 `.so` whose
SHA-256 is recorded in `native/Deep.MlDsa/evidence/android-api31-arm64.v1.json`.
It validates the packaged bytes, loads the Deep-owned C ABI via .NET, derives
the public test vector, signs/verifies the fixed interoperability transcript,
rejects a tampered message, checks native buffer zeroization, then runs the
70 applicable official ACVP `v1.1.0.43` ML-DSA-65 cases (25 keyGen, 30
seed-format pure external sigGen, 15 pure external sigVer). It has no
project reference to `Deep.Protocol` and is not an account or release client.

Build with `-p:DeepMlDsaAndroidAsset=<absolute-path-to-candidate-so>` and
`-p:DeepMlDsaAcvpVectorsRoot=<absolute-path-to-pinned-ACVP-files-root>` plus
`-p:AndroidSdkDirectory=<Android-SDK-path>`. The vector files are the six
official `prompt.json`/`expectedResults.json` files named by
`eng/Test-DeepMlDsaAcvp.py`; their SHA-256 values are verified again on-device
before parsing. Install only on a selected test device and read the
`DEEP_MLDSA_PROBE` logcat tag. No key material is logged. A green result is a
managed-load/ACVP gate, not provider approval.
