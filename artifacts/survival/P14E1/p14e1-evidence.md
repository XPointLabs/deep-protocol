# P14E1 shared profile carrier evidence

Generated at `2026-07-19T22:24:10Z`.

## Status

- `SHARED-PROFILE-CARRIER-GO`
- `XNODE-CONSUMER-PENDING`
- `CLIENT-VERIFIER-PENDING`
- `PRODUCTION-VERIFIER-NO-GO`
- `ACTIVATION-NO-GO`

The `GO` applies only to the exact dormant shared profile-carrier source and
chosen package evidence below. It does not approve an XNode consumer, client
verifier, production signature verifier, runtime registration, network use, or
activation.

## Exact source and RED/GREEN chain

| Stage | Commit | Tree or relationship | Result |
|---|---|---|---|
| C4 accepted base | `a9db427bd8b242a3d23190d5bc869b0b62fceeef` | direct parent of RED | canonical OPC timestamp baseline |
| C5 RED | `6dfd847689776b8702a8b41d04e824140d4a968e` | direct parent is the accepted base | adds nonempty OPC declaration rejection coverage |
| C5 GREEN/source | `faa598ff32913470cf85d6f2c8a8921cbf2aa287` | tree `b3179330768a6e4c6b344a5ea1217298afed2936`; direct parent is RED | requires semantically empty OPC declarations |

The exact-source worktree was clean before every review and carrier gate.
Base-to-GREEN scope contains only:

- `eng/Get-P14ProfileCarrierNormalizedIdentity.ps1`
- `eng/Test-P14ProfileCarrierNormalizedIdentity.ps1`

There are no base-to-GREEN changes below `src`, ordinary `tests`, `docs`, or
tracked package binaries. `git diff --check` passed.

## Independent reviews

### Review A — dependency audit

- Reviewer label: `dependency_audit_retry`.
- Exact source: `faa598ff32913470cf85d6f2c8a8921cbf2aa287`.
- Verdict: `GO`; `P0/P1/P2/P3 = 0/0/0/0`.
- Disclosure: the reviewer participated in P14 C4, but not C5.

### Review B — exact-source security and correctness audit

- Exact source: `faa598ff32913470cf85d6f2c8a8921cbf2aa287`.
- Verdict: `GO`; `P0/P1/P2/P3 = 0/0/0/0`.
- Disclosure: the reviewer participated in an earlier P14 base, but not C4 or
  C5.
- C5 delta and the cumulative profile-carrier state were evaluated separately.

## C5 empty OPC semantics

`Relationship`, `Default`, and `Override` declarations use the dedicated
empty-element validator. XML whitespace and whitespace-only text are accepted
as semantically empty and normalize identically. Every other child-node kind
is rejected.

An independent `3 declarations x 5 forbidden node kinds` matrix covered
non-whitespace Text, CDATA, child Element, Comment, and ProcessingInstruction:

- cases executed: `15`;
- rejected: `15`;
- accepted: `0`.

The repository focused gate also passed:

- positive normalized OPC randomizations: `4`;
- negative semantic/shape drifts: `17`.

## Chosen package

The package file is not stored in Git by this carrier.

| Property | Exact value |
|---|---|
| Package ID | `Deep.Protocol.ProfileCarrier` |
| Version and DLL ProductVersion | `0.1.0-p14.faa598f` |
| Repository commit embedded in nuspec | `faa598ff32913470cf85d6f2c8a8921cbf2aa287` |
| Size | `24597` bytes |
| Chosen raw `.nupkg` SHA-256 | `5b895ced820d678e6957482989f74621322a7bb0661ede13dcb3184e4f3e960e` |
| NuGet `.nupkg.sha512` content hash | `XV6HBDrOAQKVp9jQDirlxIO1QrdWIFhMuF5ij8HGavGPCMhIvOTHwTwn/bDuSTsMfmQ0BJDDC+RH+VE8BtqR5Q==` |
| Normalized source identity SHA-256 | `ab402ce9420ecb5f3f80a6fb9fd48b807a4bda96565c28f88f3c35ac860719ba` |
| DLL SHA-256 | `40f22fea9731d885c3e8cad33f84fbdc87b51c0196583273c51f4041fb696554` |
| Portable PDB SHA-256 | `3645995bed64789b8e8ae8c5c3d06736cd12c2512769b5bd38f5322020a295d3` |
| PDB format check | portable PDB `BSJB` signature present |

The NuGet content hash was confirmed by restoring the exact chosen file from an
isolated local package source and comparing NuGet's generated
`.nupkg.sha512` value with an independently computed SHA-512/Base64 digest.

The normalized verifier accepted exactly seven entries:

1. `_rels/.rels`
2. `Deep.Protocol.ProfileCarrier.nuspec`
3. `README.md`
4. `lib/net10.0/Deep.Protocol.ProfileCarrier.dll`
5. `lib/net10.0/Deep.Protocol.ProfileCarrier.pdb`
6. `[Content_Types].xml`
7. one exact lowercase 32-hex GUID-named OPC core-properties part

Raw NuGet ZIP hashes can differ because of proven OPC container randomness.
The chosen raw hash binds only the selected file. Reproducible source identity
is established by the byte-identical DLL/PDB and normalized package identity.

## Verification gates

### Two-clean reproducibility

- Two independently randomized clean source extraction paths: passed.
- Version: `0.1.0-p14.faa598f`.
- DLL SHA-256 equal across both builds.
- Portable PDB SHA-256 equal across both builds.
- Normalized manifest and normalized identity equal across both packages.
- Both Release builds completed with `0 warnings / 0 errors`.

### Isolated offline closure

- SDK `10.0.301` with roll-forward disabled: passed.
- Exact vendored package closure: `21/21` names, sizes, and SHA-256 values.
- Locked restore into empty CLI/NuGet/cache homes behind a dead proxy: passed.
- Resolved dependency asset allowlist: passed.
- Ancestor build/config injection rejection: passed.
- Debug ProfileCarrier tests: `47 passed / 0 failed / 0 skipped`.
- Debug Protocol tests: `173 passed / 0 failed / 0 skipped`.
- Release ProfileCarrier tests: `47 passed / 0 failed / 0 skipped`.
- Release Protocol tests: `173 passed / 0 failed / 0 skipped`.
- Debug and Release builds: `0 warnings / 0 errors`.
- Release static graph: `7` nodes, `8` edges; passed.
- Formatting verification: passed.
- Offline pack version, repository commit, DLL ProductVersion, and normalized
  identity checks: passed.

### Exact XNode provenance

- Accepted XNode commit:
  `eff452368fa4cb1324c5b3c8ee06e2f10e96b835`.
- Accepted XNode tree:
  `ee7a54e9eb0bc4c0803b9508627355eec75f0405`.
- Exact materialized file set: `167` files.
- Every accepted Git blob and the complete materialized tree: passed.
- Deliberate source-drift rejection: passed.
- Differential oracle SHA-256:
  `cc8df0559b033ad7c70aa5d19134c06c58fb2dd6cfc10449525e1fb919679dbe`.

## Remaining boundaries

- `XNODE-CONSUMER-PENDING`: the accepted XNode source is provenance/oracle
  input; this package does not activate an XNode consumer.
- `CLIENT-VERIFIER-PENDING`: no client registration, trust persistence, UI, or
  update path is approved here.
- `PRODUCTION-VERIFIER-NO-GO`: production signature verification and signer
  custody/ceremony remain separate blocked work.
- `ACTIVATION-NO-GO`: this evidence contains no network, endpoint selection,
  dependency-injection registration, private-key operation, or activation
  approval.

No package binary was added to Git. No repository push was performed.
