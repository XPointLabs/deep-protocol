# Engineering runbooks

## Local exact-three package closure

`production-protocol-closure.policy.json` and its strict
`production-protocol-closure.policy.schema.json` are the sole materializer policy. They fix the
canonical HTTPS repository URL and `RepositoryType=git`, the three package/project/lock mappings, evaluated direct
`PackageReference` IDs with their exact NuGet constraints, `ProjectReference` IDs, target framework, and allowed pack input/target
mappings. Duplicate JSON properties are rejected before conversion, and the complete policy is
validated against the tracked schema; unknown fields remain forbidden. Changes to this closure require a reviewed
policy change; the scripts do not carry a second package allowlist.

After the protocol change is committed and the worktree is clean, materialize a review-only local
feed from that exact `HEAD`:

```powershell
./eng/New-ProductionProtocolClosure.ps1 `
  -Mode survival `
  -Version 0.6.0-survival.<commit7> `
  -Commit <full-40-character-HEAD> `
  -OutputDirectory C:\review\deep-protocol-0.6.0-survival-<commit7>
```

The command never publishes, registers a NuGet source, repins a consumer, accepts a historical
commit, or accepts a repository-URL override. It never reads Git remotes or `.git/config` as a trust
input: the tracked policy is the sole repository-URL provenance source.
Every tracked worktree file and ancestor must exist without a symlink, junction, or other reparse
point before exact tree blobs are streamed with `git cat-file --batch` into private staging. A dirty tree, alternate
commit, untracked file, untracked policy, or missing policy input is rejected before materializing.
Only regular Git modes `100644` and `100755` are accepted; symlinks and submodules reject before
snapshot creation. Every extracted file is hashed with Git's exact blob framing and compared with
its `ls-tree` blob ID independently of ambient EOL settings, attributes, and export transforms.
Policy/schema validation and manifest hashes use only those verified snapshot bytes, never
raw checkout hashes: a clean `core.autocrlf=true` CRLF checkout over LF blobs is valid.
Hidden files and dot-directories are part of the exact inventory. Filesystem boundaries and
path sets use ordinal comparison on Unix and ordinal-ignore-case on Windows.

The archived projects are evaluated with MSBuild and must expose exactly the policy
`PackageReference` IDs and exact constraints, exactly the policy `ProjectReference` IDs, and the exact
policy `RepositoryType=git` without the materializer supplying that property. Directory.Build and
Directory.Packages discovery is disabled, a tracked source-local NuGet.Config clears ambient feeds,
and restore uses a private package root. The exact selected SDK version, `MSBuildSDKsPath`,
`MSBuildToolsPath`, and mandatory audit import are pinned and verified. `MSBuildAllProjects`,
evaluated inputs, and post-target compiler/pack inputs (including generated sources) must
stay inside the exact snapshot, selected SDK/reference packs, or private locked NuGet root. Every lock file has exactly one framework, equal to its policy target
framework. Every direct and transitive dependency range is parsed by the materializer's fail-closed
non-floating NuGet-range evaluator and must contain the target's resolved version. Locked restore must contain exactly those external
references as `Direct` with their policy-pinned requested/resolved version and internal references as `Project`. Every non-project lock entry needs an
exact version and a canonical base64 SHA-512 `contentHash` that decodes to exactly 64 bytes. Every
transitive entry must be reachable and recorded, but it is never promoted into a direct nuspec
dependency. A nuspec must contain exactly one dependency group for canonical `net10.0`, with no
ungrouped or other-framework dependencies. Its direct IDs must equal the policy/evaluated-project/archived-lock direct set;
their versions are normalized to exact `[version]` form. Package payload entries must equal the
policy pack targets, and tracked pack inputs (currently the carrier README) must be byte-identical
to the source snapshot. Every `build:` DLL/PDB ZIP entry must match its exact
`bin/Release/<TFM>` output and the hash recorded immediately after the compiler audit.
Changing a build output after that audit, even consistently in both builds, rejects.

Compiler globals clear `CompilerResponseFile`, `CscToolPath`, `CscToolExe`, compiler environment,
extra-argument overrides and experimental/interceptor feature switches (not used by this closure);
implicit config and standard-library lookup, shared compilation,
host compilation and skipped execution are disabled. The binlog must contain one successful
root `Csc` invocation from the selected SDK task assembly. All actual Csc invocations, including
referenced projects, must use the exact SDK compiler apphost or exact dotnet-host/SDK-compiler-DLL
pair and a closed command grammar. Bare executable names and alternate tool paths reject.
Every file-bearing switch and source path is checked against the allowed roots; unknown switches
reject. All explicit `@response` files are rejected without opening them, so nested response
files cannot expand. This excludes the compiler task's own generated temporary transport
response file: its complete contents are the Csc command recorded in the binlog. A new SDK
command shape or option requires a reviewed audit update, not permissive fallback.

The destination must be new and under a private, exclusive, non-reparse parent. On Windows the
parent must be current-principal-owned with protected ACL inheritance, one explicit effective
FullControl allow for the current SID, and no ACL rule outside the explicit current-SID/SYSTEM
FullControl allow list. On Unix it must be owned by the current UID and mode `0700`. Unix
directories are created with mode `0700` atomically, not created publicly and chmodded afterward.
The stage, extracted source, raw package, normalized package, and candidate-publication roots are
all newly created private directories; their roots and descendants are reparse-checked before use.
The fresh private work stage is created under that parent so publication is a same-volume atomic
rename. Final directory identity, private ownership/ACL mode, and every file hash are checked after the rename. If identity or
hash validation fails, the redirected path is not followed, rolled back, or deleted.

On failure, work is not recursively cleaned. The owned stage is renamed to a fresh quarantine name
when its stable directory identity can still be proved; otherwise its original path is reported and
left untouched. On success, only the proven stable private work stage is recursively removed after
the published directory has passed post-move identity/hash verification.

The output contains exactly three `.nupkg` files plus
`deep-production-protocol-closure.manifest.v2.json`. The manifest records policy/schema hashes,
policy repository URL, exact commit/tree, raw-blob transport and canonical source-inventory SHA-256/SHA-512,
package repository URL/commit, package SHA-256/SHA-512, exact direct dependencies, and the complete
reachable lock graph. Every non-validation materialization performs two independent restores and
builds under different random source roots and requires byte-identical DLL, portable PDB and
normalized nupkg hashes before publication.

### Threat model

The materializer requires a trusted, exclusive build principal and process. The output parent must
exclude other writable OS principals, protecting against pre-existing links/junctions, accidental
cross-principal writes, and unsafe deletion targets. Compromise of the build principal, or a
malicious concurrent process running as that same OS principal, is explicitly out of scope; ACLs,
mode bits, reparse checks, and path rechecks do not prove safety against that attacker.

Use `-ValidateOnly` for a no-output preflight. It performs the same policy evaluation, locked graph
validation and locked restore from a private exact-Git-blob staging snapshot, then verifies and
removes that stage without building packages or publishing output.
`Test-NewProductionProtocolClosure.ps1` is the focused hostile gate for duplicate/unknown policy
and lock fields, intrinsic `RepositoryType`, blocked ambient MSBuild imports, malformed/out-of-range
lock edges, ambient SDK/generated compiler inputs, raw Git blob bytes, symlink modes, complete
current-workspace snapshots, extra nuspec framework groups, tracked reparse descendants,
clean CRLF/LF policy trust, actual compiler commands and response-file/tool overrides,
target-generated external source/reference/resource inputs, DLL/PDB substitution and hidden files,
effective Windows ACLs, and real Windows/Unix private-directory, move, quarantine and safe-cleanup branches.
`Test-ProductionProtocolClosureReproducibility.ps1` is a no-publish development gate that copies the
complete canonical current workspace inventory (tracked plus non-ignored untracked files, current
working bytes and deletions) into two private random roots without overlays or source mutation, then
independently restores, builds, packs and normalizes all three packages before comparing every DLL,
portable PDB and nupkg SHA-256.

## Deep ML-KEM Braid candidate evidence

`Test-DeepMlKemBraidEvidence.ps1` validates the isolated native candidate's
fixed Rust/Cargo/libcrux provenance, target-specific CycloneDX SBOMs, current
Windows x64 and Android arm64 artifact identities, closed ABI exports,
dependencies, and platform hardening. `-Rebuild` additionally requires an
explicit Android serial and executes the native device probe; it never changes
the managed provider or grants production approval.

`Test-DeepMlKemBraidEvidenceDrift.ps1` is the focused hostile gate. It accepts
the exact baseline and rejects Cargo.lock, upstream provenance, binary, SBOM,
and Windows ARM64 status drift. The evidence inventory and commands are owned
by `../native/Deep.MlKemBraid/README.md`.
