# Candidate ML-DSA .NET Android runtime probe

This **test-only** APK packages the exact candidate Android arm64 `.so` whose
SHA-256 is recorded in `native/Deep.MlDsa/evidence/android-api31-arm64.v1.json`.
It validates the packaged bytes, loads the Deep-owned C ABI via .NET, derives
the public test vector, signs/verifies the fixed interoperability transcript,
rejects a tampered message and checks native buffer zeroization. It has no
project reference to `Deep.Protocol` and is not an account or release client.

Build with `-p:DeepMlDsaAndroidAsset=<absolute-path-to-candidate-so>` and
`-p:AndroidSdkDirectory=<Android-SDK-path>`, install only on a selected test
device, and read the `DEEP_MLDSA_PROBE` logcat tag. No private material is
logged. A green result is a managed-load gate, not provider approval.
