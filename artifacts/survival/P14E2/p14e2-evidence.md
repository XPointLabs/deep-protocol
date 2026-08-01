# P14E2 activation-trust evidence carrier

This is a sanitized, non-runtime evidence carrier. It records exact source,
review attribution, summarized executable gates, package identity, and the
remaining release boundaries. It contains no binary payloads or raw command
output and does not authorize activation or deployment.

## Exact accepted source

- Source-Commit: 69a712a894b024a09859096025c2bb8fe68a642e
- Source-Tree: d83bbdd001b723738357689bbb2150a51357cb3b
- Source-Branch: survival/w08-p14-activation-trust
- Source-Worktree-Status-At-Acceptance: clean
- Scope: dormant DPF1 activation-trust prerequisites, transition verification,
  verify-only Ed25519 adapter, and exact offline/native supply gates.

## Complete implementation RED/GREEN chain

Each row is commit, tree, and committed subject in chronological order.

- 9e27410dbbaf4380be4b6975dd6be238458827b2|8668ab068277bee68c1cb16bec9ab341eafe23d9|test(p14e2): define activation trust prerequisites
- 9296abf1daf88626827894bb3e1902232b535cdd|7f35560a1eeb29f780a36c0085dc18347a608ff5|test(p14e2): keep invalid rotation vector parser-free
- 3724fb16cf9c2f022832c816dc05e195e2e8a1fe|31cacb738ff123c11570915e22d77fefa998511e|test(p14e2): correct transition boundary controls
- 13b92927762787b335c6a6f772e813471a48edb6|da85a337798cf882e2d26ac31d7c059ee7cfc4a9|test(p14e2): materialize memory mutation vectors
- 825449fd704c046f56e734e027491a409037e4b3|101c6a1d2767c96597e8f4a49f9d8c6312a6dc5b|test(p14e2): bound cross-rid supply proof
- c08cf3b37581314dbd300fb4ff1102ea1171096b|e1e9de9517dcf3b26a7060239d290a185c404993|test(p14e2): require ephemeral continuity cleanup
- 1bf2bb89cfce71f6d141897e40f9ce5507bc0b28|e48258f97456e206ce645df77eb316d9130fa041|feat(p14e2): add dormant activation trust prerequisites
- a08f8dcdc9a46afa449440f52d2a576bd4d151b1|c69e994b1388470be2e3c2c7e1a09826840a1d3f|fix(p14e2): make win arm64 gate powershell compatible
- 080b026b1739c76c1d6287bce457649ff932bd30|5ff69abe861c11e4b664ac815a2c5813e4d9e429|test(p14e2): require nested projection cleanup
- f295b20a881e427a04456dc3680cee9d0c2c6415|d5358d30f1ec65df596e27ffbf6084cebe36ac4a|fix(p14e2): close continuity ownership edges
- 428b181e1ccc05ebd7f02b33083ddbf34e923f91|47b12242c0190d01cb2cf33541e35d8e50e6fdaa|fix(p14e2): lock differential crypto graph
- 764420b8b944d22de457239dee2ec24d1fe59a4e|c419afc286a6721a7581bf9eba979f43cfbd9398|test(p14e2): expose bridge ownership oom gap
- 69a712a894b024a09859096025c2bb8fe68a642e|d83bbdd001b723738357689bbb2150a51357cb3b|fix(p14e2): retain bridge commitment ownership

The initial implementation at `428b181e1ccc05ebd7f02b33083ddbf34e923f91`
received two independent NO-GO findings for the same P2 bridge-commitment
ownership gap. Corrective RED `764420b8b944d22de457239dee2ec24d1fe59a4e`
deterministically injected the exact OOM after SHA-256 and before ownership,
observing a non-zero 32-byte buffer. Corrective GREEN retained local ownership
through callback, allocation, and list transfer, zeroing on every failure while
propagating the exact OOM instance.

## Independent exact-source reviews

These were two separate read-only Codex subagent reviews. They are independent
of the implementing agent for this iteration but are not the external
cryptographic/profile audit that remains mandatory before activation.

- Reviewer-1-Label: /root/p14e2_implementation/p14e2_protocol_review
- Reviewer-1-Scope: independent protocol/architecture exact-source review
- Reviewer-1-Participation: read-only review; no edits; worktree clean before and after
- Reviewer-1-Exact-Source: 69a712a894b024a09859096025c2bb8fe68a642e / d83bbdd001b723738357689bbb2150a51357cb3b
- Reviewer-1-Verdict: GO
- Reviewer-1-P0-P3: 0

- Reviewer-2-Label: /root/p14e2_implementation/p14e2_security_review
- Reviewer-2-Scope: independent security/crypto/supply-chain exact-source review
- Reviewer-2-Participation: read-only review; no edits; worktree clean before and after
- Reviewer-2-Exact-Source: 69a712a894b024a09859096025c2bb8fe68a642e / d83bbdd001b723738357689bbb2150a51357cb3b
- Reviewer-2-Verdict: GO
- Reviewer-2-P0-P3: 0

Both final reports explicitly confirmed no P0, P1, P2, or P3 findings against
the exact accepted source. Reviewer 1 covered transition semantics, independent
dual verification, time snapshots, full ordered bridge prefix, early fork,
DPF1 v1 behavior, ephemeral cleanup, public-surface bounds, and dormancy.
Reviewer 2 covered corrective ownership and OOM behavior, Ed25519 verify-only
constraints, exact dependency/native closure, provenance, offline isolation,
and normalized package reproducibility.

## Executed gates on the exact source

- ActivationTransition-Debug: 19/19
- ActivationTransition-Release: 19/19
- Ed25519-Release: 15/15
- ProfileCarrier-Debug: 85/85
- ProfileCarrier-Release: 85/85
- Protocol-Debug: 173/173
- Protocol-Release: 173/173
- ActivationTransition-Release-Stress: 25/25
- Release-Build: 0 warnings / 0 errors
- Dotnet-Format-Verify-No-Changes: PASS
- Git-Diff-Check: PASS
- Offline-Isolated-Debug-And-Release: PASS
- Offline-Package-Closure: 21 packages
- Windows-ARM64-Isolated-Build: PASS, 0 warnings / 0 errors
- Windows-ARM64-Assembly-SHA256: b6d13263b7a3a7f15a05a87824eac83d0ab54c2c674bfff65ead6acb27543af4
- Provenance-Drift-Rejection: PASS
- Provenance-XNode-Commit: eff452368fa4cb1324c5b3c8ee06e2f10e96b835
- Provenance-XNode-Tree: ee7a54e9eb0bc4c0803b9508627355eec75f0405
- Provenance-XNode-Files: 167
- Provenance-Differential-SHA256: cc8df0559b033ad7c70aa5d19134c06c58fb2dd6cfc10449525e1fb919679dbe
- Two-Clean-Path-Normalized-Reproducibility: PASS

Native asset path, length, and SHA-256 checks:

- win-arm64: runtimes/win-arm64/native/libsodium.dll; 328192 bytes; 1616d5625f8721c9914ee7276f3ce63bc873eab530dfcf04e8c4184e2e77052c
- win-x64: runtimes/win-x64/native/libsodium.dll; 462848 bytes; 64a1f143868309069f0a0a3c8141c0853c4f17243ddf734e92b11c5411739771
- linux-arm64: runtimes/linux-arm64/native/libsodium.so; 422688 bytes; 54f416a70e0d982a63e7f2402ff6f2a8666bf0a430404a4205ed8eee1868b9db
- linux-x64: runtimes/linux-x64/native/libsodium.so; 582600 bytes; 963416833246938fd6983e4aa96248dbccb2f95b30095c4a94678d6fb903404b
- android-arm64: runtimes/android-arm64/native/libsodium.so; 423648 bytes; f4382f2139f1ddd3a32dce406c98f2d41b472e02351bd18df362f8cb29af1952

## Chosen local package

The only chosen release-candidate file for this carrier is
`C:\W\deep-survival\wave08\p14e2-package-final\Deep.Protocol.ProfileCarrier.0.2.0-p14.69a712a.nupkg`.
The package itself is not stored in this branch.

- Chosen-Package-Bytes: 29399
- Chosen-Package-SHA256: fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498
- Chosen-Package-SHA512: x9LZb8nAUE/XQWQS2ZGBGLbPt2FivGRVc9y1xvlsr02CKHaU6scklrBsOebxj/NiTG66QgFCK7Gd7qFEoRe5zw==
- Normalized-Identity-SHA256: baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f
- Chosen-DLL-SHA256: 20489ac15239af11207a0daa670545b975c03eaebb78297adf956af45daa7034
- Chosen-PDB-SHA256: 80f2210e6c61050e2a4edbbf1fa4181ca0d7285d124073fa0d9aa9a77307542a
- Chosen-NuGet-Version: 0.2.0-p14.69a712a
- Chosen-Nuspec-Repository-Commit: 69a712a894b024a09859096025c2bb8fe68a642e
- Chosen-Nuspec-Repository-URL: https://github.com/XPointLabs/deep-protocol.git
- Chosen-Dependency-Deep.Protocol: [0.3.0-p04.b887fa0]
- Chosen-Dependency-Sodium.Core: [1.4.1]
- Chosen-Dependency-libsodium: [1.0.22]

The security reviewer independently produced and inspected another clean-path
package during review:

- Independent-Security-Pack-Bytes: 29401
- Independent-Security-Pack-SHA256: a2fcbe31dcbed2105f3bf2a627825930e463974db3be1d2fa1da8ae33deadf42
- Independent-Security-Pack-Normalized-Identity-SHA256: baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f

The independent security pack raw ZIP size and SHA-256 differ because permitted OPC/ZIP metadata randomness changes raw container bytes; its normalized identity is identical to the chosen package.

The independent pack's raw hash is reviewer evidence only and is not the hash
of the selected file. Reproducibility acceptance is based on the normalized
OPC identity plus identical DLL and PDB hashes, not raw ZIP-byte identity.

## Preserved release boundaries

- CROSS-RID-EXECUTION-PENDING
- PRODUCTION-SIGNER-NO-GO
- CLIENT-ACTIVATION-NO-GO
- EXTERNAL-CRYPTO-PROFILE-REVIEW-PENDING

P14E2 is accepted only as dormant prerequisites. Linux execution remains a
downstream P14C3 responsibility; Android and Windows execution remain a
downstream P14A2b responsibility. No production signer is approved, the client
must not activate the profile, and no external crypto/profile reviewer has yet
approved production use.

## Sanitization and authority

This carrier contains summarized counts and identifiers only. It excludes
NuGet binaries, build directories, logs, command transcripts, machine
environment dumps, credentials, signing material, and test fixtures.

No runtime, DI, network, client, UAT, contract, or deployment change is authorized by this carrier.
