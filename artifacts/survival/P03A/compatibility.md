# P03A compatibility evidence

- Base P03 evidence:
  `90e306ebf9d4ce722b95f128f5ff4bebcaddcde3`.
- ADR/preflight commit:
  `0d797edf58f133932cedd6e1f9bde855244bf2e0`.
- Red contract commit:
  `225b0f131d80f851cf76cd2a7d7c9543bbcd7fc3`.
- Original implementation source:
  `a3f70363cf8aa2eef4f5a8d80be50bc638911201`.
- Corrective overhead red contract:
  `f552aed8a9b22e9f232c43318082f7d67097a59b`.
- Corrective implementation source:
  `241fca1ed9999183a488a8798fdbc822eb091484`.
- Corrected accepted P03 report SHA-256:
  `e691516691d85b0c34850430e7f5f493615658c8577344a7d8a8293b675ee0a2`.
- P01 observer matrix SHA-256:
  `ffcfe4e6df8bbd63b04c1c590e5a47935b8e7504a4c39cf1256b322aeea5a4df`.
- P01 producer contract SHA-256:
  `ec67df8a697a3527fe1875789e64566d109ab422272946b98af2f8d9d6312063`.

Session protobufs, generated bindings, namespaces, Session codec behavior and existing vectors are
unchanged. P03A is a Deep-only DPB1 extension with a new explicitly negotiated payload kind and
critical feature. Legacy DPE1 bytes are recovered exactly; they are not parsed, rewritten or
treated as a new inner protocol.

Old readers reject the new critical feature or payload kind. A P03A reader never retries clear
DPE1 or raw account addressing after failure. There is no production crypto implementation,
runtime registration or default feature offer.
