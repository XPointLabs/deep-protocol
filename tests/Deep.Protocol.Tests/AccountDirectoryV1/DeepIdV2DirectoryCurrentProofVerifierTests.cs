using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.Tests.Identity;
using System.Runtime.InteropServices;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed partial class AccountDirectoryFreshnessVerificationTests
{
    [Fact]
    public async Task Did2GenesisHeadAuthor_RequiresThresholdAndExactV2EmptyRoots()
    {
        var fixture = AuthorityFixture.Create();
        var signers = fixture.Witnesses.Take(2)
            .Select(static witness =>
                (IAccountDirectoryAdh1WitnessSigner)new GenesisHeadSigner(
                    witness.Id, witness.Key.PrivateKey))
            .ToArray();
        var authored = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
            fixture.Verified, 1_700_000_000, 1_700_010_000, signers);
        var expected = fixture.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray(),
            minimumReader: 2);
        Assert.Equal(AccountDirectoryAdh1Codec.Encode(expected),
            authored.ExactAdh1.ToArray());
        Assert.Equal(0UL, authored.ProtectedHead.LogGeneration);
        Assert.Empty(authored.ExactTransitions);
        Assert.Empty(authored.ExactAllTransitions);
        Assert.Equal("InsufficientSigners",
            (await Assert.ThrowsAsync<AccountDirectoryHeadAuthoringException>(
                async () => await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
                    fixture.Verified, 1_700_000_000, 1_700_010_000,
                    signers[..1]))).Code);
        Assert.Equal("TimeOutsideAuthority",
            (await Assert.ThrowsAsync<AccountDirectoryHeadAuthoringException>(
                async () => await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
                    fixture.Verified, 1, 2, signers))).Code);
        var badSigners = new IAccountDirectoryAdh1WitnessSigner[]
        {
            new GenesisHeadSigner(fixture.Witnesses[0].Id,
                fixture.Witnesses[0].Key.PrivateKey),
            new InvalidGenesisHeadSigner(fixture.Witnesses[1].Id)
        };
        Assert.Equal("InvalidSignerResult",
            (await Assert.ThrowsAsync<AccountDirectoryHeadAuthoringException>(
                async () => await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
                    fixture.Verified, 1_700_000_000, 1_700_010_000,
                    badSigners))).Code);
    }

    [Fact]
    public void Did2Bootstrap_RequiresSignedExactEmptyV2Head()
    {
        var authority = AuthorityFixture.Create();
        var emptyAppend = AccountDirectoryRfc6962.ComputeEmptyTreeHash();
        var valid = authority.Head(0, new byte[32], 0, emptyAppend,
            DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray(),
            minimumReader: 2);
        var exactValid = AccountDirectoryAdh1Codec.Encode(valid);
        var validHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(valid);
        var restored = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(
            authority.Verified, exactValid, validHash);
        Assert.Equal(exactValid, restored.ExactAdh1.ToArray());

        var legacyMap = authority.Head(0, new byte[32], 0, emptyAppend,
            AccountDirectorySparseMap.EmptyMapRoot.ToArray(),
            minimumReader: 2);
        var oldReader = authority.Head(0, new byte[32], 0, emptyAppend,
            DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray(),
            minimumReader: 1);
        foreach (var wrong in new[] { legacyMap, oldReader })
        {
            Assert.Equal("InvalidDid2Bootstrap",
                Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                    DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(
                        authority.Verified, AccountDirectoryAdh1Codec.Encode(wrong),
                        AccountDirectoryCrypto.ComputeAdh1CoreHash(wrong))).Code);
        }
        Assert.Equal("PersistedLkgHashMismatch",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(
                    authority.Verified, exactValid, Bytes(32, 0x55))).Code);
    }

    [Fact]
    public async Task Did2Verifier_RealPqGenesisClosesSignedCurrentProof()
    {
        if (!((OperatingSystem.IsWindows() &&
                RuntimeInformation.ProcessArchitecture is (Architecture.X64 or Architecture.Arm64)) ||
              (OperatingSystem.IsLinux() &&
                RuntimeInformation.ProcessArchitecture == Architecture.X64)))
            return;

        var (admission, checkpoint, binding, authorization) = await
            Dnp1IdentityAuthoringV1Tests.CreateRealDid2DirectoryGenesisWithDcaAsync();
        var authority = AuthorityFixture.Create(
            networkOverride: checkpoint.Checkpoint.NetworkId.ToArray(),
            timeBase: 1_900_000_000);
        var initial = authority.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray(),
            minimumReader: 2);
        var initialLkg = new AccountDirectoryProtectedLkg(
            AccountDirectoryAdh1Codec.Encode(initial));
        var leaf = checkpoint.Checkpoint.DirectoryLeafKey.ToArray();
        var map = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [Convert.ToHexString(leaf)] =
                checkpoint.Checkpoint.ArtifactReference.ToArray()
        };
        var mapRoot = DeepIdV2DirectorySparseMap.ComputeFullMapRoot(map);
        var transition = DeepIdV2DirectoryTransitionCodec.Author(0, leaf,
            new byte[38], checkpoint.Checkpoint.ArtifactReference.Span,
            DeepIdV2DirectorySparseMap.EmptyMapRoot.Span, mapRoot);
        ReadOnlyMemory<byte>[] journal = [transition.CanonicalBytes];
        var head = authority.Head(1, initialLkg.CoreHash.ToArray(), 1,
            DeepIdV2DirectoryJournal.ComputeAppendRoot(journal), mapRoot,
            minimumReader: 2);
        var exactHead = AccountDirectoryAdh1Codec.Encode(head);
        var nonce = Bytes(32, 0x31);
        var material = DeepIdV2DirectoryProofMaterialAuthor.Create(
            new AccountDirectoryProtectedLkg(exactHead), journal,
            [checkpoint], leaf, initialLkg);
        var request = new AccountDirectoryProofAuthoringRequest(
            authority.Network, nonce, Bytes(16, 0x44), 1_000,
            exactHead, authority.CurrentXnv(), 1_900_000_300, 5,
            1_900_000_300, 1_900_000_360,
            AccountDirectoryDtt1IssuanceEpoch.Derive(
                authority.Verified, 1_900_000_300, 5), 2);
        using var pq = DeepMlDsa65NativeProvider.LoadCandidateForCurrentProcess();
        var package = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(
            authority.Verified, request, material,
            authority.Witnesses.Take(2).Select(WitnessSigner.Valid)
                .Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray(),
            1, pq);

        var adl = DeepIdV2AccountDirectoryLookupCodec.Author(
            binding.DeepId, authority.Network,
            initialLkg.LogGeneration, initialLkg.CoreHash.Span,
            1, new byte[38], new byte[32]);
        var query = VerifiedDeepIdV2DirectoryQuery.VerifyBinding(adl, binding);
        var did2Query = VerifiedDeepIdV2DirectoryQuery.VerifyDid2(adl,
            binding.DeepId);
        Assert.Equal(query.DirectoryLeafKey.ToArray(),
            did2Query.DirectoryLeafKey.ToArray());

        var wireRequestBytes = DeepIdV2DirectoryProofWireCodec.EncodeRequest(
            adl, binding.DeepId, nonce, request.BootId.Span,
            request.ClientMonotonicSendSample);
        Assert.Equal(DeepIdV2DirectoryProofWireCodec.RequestLength,
            wireRequestBytes.Length);
        var wireRequest = DeepIdV2DirectoryProofWireCodec.DecodeRequest(
            wireRequestBytes);
        Assert.Equal(leaf, wireRequest.DirectoryLeafKey.ToArray());
        var wireResponseBytes = DeepIdV2DirectoryProofWireCodec.EncodeResponse(
            wireRequest, package);
        var wireResponse = DeepIdV2DirectoryProofWireCodec.DecodeResponse(
            wireResponseBytes, wireRequest);
        Assert.Equal(package.ExactAdp1V2.ToArray(),
            wireResponse.ExactAdp1V2.ToArray());
        var tamperedRequest = wireRequestBytes.ToArray();
        tamperedRequest[4] = 0;
        tamperedRequest[5] = 1;
        Assert.Throws<FormatException>(() =>
            DeepIdV2DirectoryProofWireCodec.DecodeRequest(tamperedRequest));
        tamperedRequest = wireRequestBytes.ToArray();
        tamperedRequest[12 + DeepIdV2AccountDirectoryLookupCodec.CanonicalLength +
            100] ^= 1;
        Assert.Throws<FormatException>(() =>
            DeepIdV2DirectoryProofWireCodec.DecodeRequest(tamperedRequest));
        var tamperedResponse = wireResponseBytes.ToArray();
        tamperedResponse[12 + 16 + 32] ^= 1;
        Assert.Throws<FormatException>(() =>
            DeepIdV2DirectoryProofWireCodec.DecodeResponse(
                tamperedResponse, wireRequest));
        tamperedResponse = wireResponseBytes.ToArray();
        var adpOffset = 116 + 4 + package.ExactAdh1.Length +
            4 + package.ExactDtt1.Length + 4;
        tamperedResponse[adpOffset + 4] = 0;
        tamperedResponse[adpOffset + 5] = 1;
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            DeepIdV2DirectoryProofWireCodec.DecodeResponse(
                tamperedResponse, wireRequest));

        var verified = DeepIdV2DirectoryCurrentProofVerifier.VerifyGenesis(
            authority.Verified, package.ExactAdh1, package.ExactDtt1,
            package.ExactAdp1V2, nonce, query,
            Window(), initialLkg, 1, 2, pq);
        var resolvedByDid2 =
            DeepIdV2DirectoryCurrentProofVerifier.VerifyRequestedDid2(
                authority.Verified, package.ExactAdh1, package.ExactDtt1,
                package.ExactAdp1V2, nonce, did2Query,
                Window(), initialLkg, 1, 2, pq);
        Assert.Equal(binding.DeepId.CanonicalBytes.ToArray(),
            resolvedByDid2.CurrentCheckpoint!.Binding.DeepId.CanonicalBytes.ToArray());

        Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue,
            verified.ResultKind);
        Assert.False(verified.HasRootAuthorizedForwardLineage);
        Assert.Equal(initialLkg.ExactAdh1.ToArray(),
            verified.VerifiedProtectedLkgExactAdh1.ToArray());
        Assert.Equal(checkpoint.Checkpoint.ArtifactHash.ToArray(),
            verified.CurrentCheckpoint!.Checkpoint.ArtifactHash.ToArray());
        Assert.Equal(exactHead, verified.NextProtectedLkg.ExactAdh1.ToArray());
        Assert.Equal(admission.ExactDab2.ToArray(),
            DeepIdV2Adp1Codec.Decode(package.ExactAdp1V2.Span).ExactDab2.ToArray());
        Assert.True(verified.TrustedLowerUnixSeconds <= verified.TrustedUpperUnixSeconds);
        var currentAuthorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(
            verified, authorization, Window().BootId.Span, Window().CurrentSample);
        Assert.Same(authorization, currentAuthorization.Authorization);
        Assert.Equal(verified.TrustedLowerUnixSeconds,
            currentAuthorization.TrustedLowerUnixSeconds);
        var advanced = DeepIdV2CurrentContactAuthorizationVerifier.Verify(
            verified, authorization, Window().BootId.Span,
            Window().CurrentSample + 3);
        Assert.Equal(verified.TrustedLowerUnixSeconds + 3,
            advanced.TrustedLowerUnixSeconds);
        var (_, _, otherBinding, otherAuthorization) = await
            Dnp1IdentityAuthoringV1Tests.CreateRealDid2DirectoryGenesisWithDcaAsync(
                networkOverride: Bytes(16, 0x66),
                mnemonicOverride: Dnp1IdentityAuthoringV1Tests.OtherMnemonic);
        Assert.Throws<AccountDirectoryAdl1FormatException>(() =>
            VerifiedDeepIdV2DirectoryQuery.VerifyDid2(adl,
                otherBinding.DeepId));
        Assert.Equal("AuthorizationIdentityMismatch",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                DeepIdV2CurrentContactAuthorizationVerifier.Verify(
                    verified, otherAuthorization, Window().BootId.Span,
                    Window().CurrentSample)).Code);
        Assert.Equal("DirectoryFreshnessExpired",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                DeepIdV2CurrentContactAuthorizationVerifier.Verify(
                    verified, authorization, Bytes(16, 0x55),
                    Window().CurrentSample)).Code);
        Assert.Equal("DirectoryFreshnessExpired",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                DeepIdV2CurrentContactAuthorizationVerifier.Verify(
                    verified, authorization, Window().BootId.Span,
                    verified.FreshnessDeadlineMonotonicSeconds)).Code);

        var successor = authority.Head(2, verified.NextProtectedLkg.CoreHash.ToArray(),
            1, head.AppendLogMerkleRoot.ToArray(), mapRoot, minimumReader: 2);
        var successorBytes = AccountDirectoryAdh1Codec.Encode(successor);
        var successorNonce = Bytes(32, 0x35);
        var successorMaterial = DeepIdV2DirectoryProofMaterialAuthor.Create(
            new AccountDirectoryProtectedLkg(successorBytes), journal,
            [checkpoint], leaf, verified.NextProtectedLkg);
        var successorRequest = new AccountDirectoryProofAuthoringRequest(
            authority.Network, successorNonce, Bytes(16, 0x44), 1_000,
            successorBytes, authority.CurrentXnv(), 1_900_000_300, 5,
            1_900_000_300, 1_900_000_360,
            AccountDirectoryDtt1IssuanceEpoch.Derive(
                authority.Verified, 1_900_000_300, 5), 2);
        var successorPackage = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(
            authority.Verified, successorRequest, successorMaterial,
            authority.Witnesses.Take(2).Select(WitnessSigner.Valid)
                .Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray(),
            1, pq);
        var successorLookup = DeepIdV2AccountDirectoryLookupCodec.Author(
            binding.DeepId, authority.Network,
            verified.NextProtectedLkg.LogGeneration,
            verified.NextProtectedLkg.CoreHash.Span,
            1, new byte[38], new byte[32]);
        var successorQuery = VerifiedDeepIdV2DirectoryQuery.VerifyBinding(
            successorLookup, binding);
        var verifiedSuccessor = DeepIdV2DirectoryCurrentProofVerifier.VerifyGenesis(
            authority.Verified, successorPackage.ExactAdh1,
            successorPackage.ExactDtt1, successorPackage.ExactAdp1V2,
            successorNonce, successorQuery, Window(), verified.NextProtectedLkg,
            1, 2, pq);
        Assert.Equal(checkpoint.Checkpoint.ArtifactHash.ToArray(),
            verifiedSuccessor.CurrentCheckpoint!.Checkpoint.ArtifactHash.ToArray());
        Assert.Equal((ulong)2, verifiedSuccessor.NextProtectedLkg.LogGeneration);

        // A later signed head changes both committed roots by admitting a
        // second, independently PQ-authorized account. The first account's
        // proof must remain current against the final two-leaf map, and the
        // newly admitted account must resolve from the same protected floor.
        var (_, secondCheckpoint, secondBinding) = await
            Dnp1IdentityAuthoringV1Tests.CreateRealDid2DirectoryGenesisAsync(
                authority.Network, mnemonicOverride:
                Dnp1IdentityAuthoringV1Tests.OtherMnemonic);
        var secondLeaf = secondCheckpoint.Checkpoint.DirectoryLeafKey.ToArray();
        Assert.NotEqual(leaf, secondLeaf);
        var nextMap = new Dictionary<string, byte[]>(map,
            StringComparer.Ordinal)
        {
            [Convert.ToHexString(secondLeaf)] =
                secondCheckpoint.Checkpoint.ArtifactReference.ToArray()
        };
        var nextMapRoot = DeepIdV2DirectorySparseMap.ComputeFullMapRoot(nextMap);
        var secondTransition = DeepIdV2DirectoryTransitionCodec.Author(1,
            secondLeaf, new byte[38],
            secondCheckpoint.Checkpoint.ArtifactReference.Span,
            mapRoot, nextMapRoot);
        ReadOnlyMemory<byte>[] expandedJournal =
            [transition.CanonicalBytes, secondTransition.CanonicalBytes];
        var expandedHead = authority.Head(3,
            verifiedSuccessor.NextProtectedLkg.CoreHash.ToArray(), 2,
            DeepIdV2DirectoryJournal.ComputeAppendRoot(expandedJournal),
            nextMapRoot, minimumReader: 2);
        var expandedHeadBytes = AccountDirectoryAdh1Codec.Encode(expandedHead);
        var expandedLkg = new AccountDirectoryProtectedLkg(expandedHeadBytes);

        async Task<VerifiedDeepIdV2DirectoryFreshness> VerifyExpandedAsync(
            byte[] queriedLeaf, VerifiedDab2 queriedBinding, byte nonceMarker)
        {
            var requestNonce = Bytes(32, nonceMarker);
            var expandedMaterial = DeepIdV2DirectoryProofMaterialAuthor.Create(
                expandedLkg, expandedJournal,
                [checkpoint, secondCheckpoint], queriedLeaf,
                verifiedSuccessor.NextProtectedLkg);
            var expandedRequest = new AccountDirectoryProofAuthoringRequest(
                authority.Network, requestNonce, Bytes(16, 0x44), 1_000,
                expandedHeadBytes, authority.CurrentXnv(), 1_900_000_300, 5,
                1_900_000_300, 1_900_000_360,
                AccountDirectoryDtt1IssuanceEpoch.Derive(
                    authority.Verified, 1_900_000_300, 5), 2);
            var expandedPackage = await DeepIdV2DirectoryProofAuthor
                .IssueGenesisAsync(authority.Verified, expandedRequest,
                    expandedMaterial,
                    authority.Witnesses.Take(2).Select(WitnessSigner.Valid)
                        .Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray(),
                    1, pq);
            var expandedLookup = DeepIdV2AccountDirectoryLookupCodec.Author(
                queriedBinding.DeepId, authority.Network,
                verifiedSuccessor.NextProtectedLkg.LogGeneration,
                verifiedSuccessor.NextProtectedLkg.CoreHash.Span,
                1, new byte[38], new byte[32]);
            var expandedQuery = VerifiedDeepIdV2DirectoryQuery.VerifyBinding(
                expandedLookup, queriedBinding);
            return DeepIdV2DirectoryCurrentProofVerifier.VerifyGenesis(
                authority.Verified, expandedPackage.ExactAdh1,
                expandedPackage.ExactDtt1, expandedPackage.ExactAdp1V2,
                requestNonce, expandedQuery, Window(),
                verifiedSuccessor.NextProtectedLkg, 1, 2, pq);
        }

        var firstAfterMutation = await VerifyExpandedAsync(leaf, binding, 0x36);
        Assert.Equal(checkpoint.Checkpoint.ArtifactHash.ToArray(),
            firstAfterMutation.CurrentCheckpoint!.Checkpoint.ArtifactHash.ToArray());
        Assert.Equal((ulong)2, firstAfterMutation.NextProtectedLkg.TreeSize);
        var secondAfterMutation = await VerifyExpandedAsync(
            secondLeaf, secondBinding, 0x37);
        Assert.Equal(secondCheckpoint.Checkpoint.ArtifactHash.ToArray(),
            secondAfterMutation.CurrentCheckpoint!.Checkpoint.ArtifactHash.ToArray());
        Assert.Equal(firstAfterMutation.NextProtectedLkg.CoreHash.ToArray(),
            secondAfterMutation.NextProtectedLkg.CoreHash.ToArray());

        // A periodic root checkpoint may anchor the first admission while
        // signed direct successors carry a later second account to the sole
        // current DTT1 head, without re-signing an intermediate head as now.
        var tailNonce = Bytes(32, 0x38);
        var tailDtt = authority.Dtt(expandedHead, tailNonce,
            observed: 1_900_000_300);
        var tailDttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(tailDtt);
        var anchorHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
        var sourceLeaf = CoveredHeadLeaf(initialLkg.LogGeneration,
            initialLkg.TreeSize, initialLkg.CoreHash.Span);
        var anchorAdf = authority.SignedAdf(0, new byte[32],
            0, 0, 1, sourceLeaf, anchorHash, head.TreeSize,
            head.AppendLogMerkleRoot.ToArray(),
            head.CurrentValueMapRoot.ToArray(), minimumReader: 2);
        var anchorAfp = AccountDirectoryAfp1Codec.Encode(
            new AccountDirectoryAfp1(authority.Network,
                initialLkg.LogGeneration, initialLkg.TreeSize,
                initialLkg.CoreHash.Span, anchorHash,
                [authority.ExactXna1],
                [AccountDirectoryAdf1Codec.Encode(anchorAdf)],
                [exactHead], 0, [], tailDttHash));
        var sourceMaterial = DeepIdV2DirectoryProofMaterialAuthor.Create(
            expandedLkg, expandedJournal, [checkpoint, secondCheckpoint],
            secondLeaf, initialLkg);
        byte[][] appendLeaves =
            [transition.AppendLogLeafHash.ToArray(),
                secondTransition.AppendLogLeafHash.ToArray()];
        var anchorConsistency = AccountDirectoryProofMaterialAuthor
            .BuildConsistencyProof(
                new AccountDirectoryProtectedLkg(exactHead), expandedLkg,
                appendLeaves);
        var tailAdp = DeepIdV2Adp1Codec.AuthorWithForwardTail(
            sourceMaterial, tailDttHash, anchorAfp,
            initialLkg.ExactAdh1.Span, 0, 0, [],
            [successorBytes, expandedHeadBytes], anchorConsistency);
        var tailLookup = DeepIdV2AccountDirectoryLookupCodec.Author(
            secondBinding.DeepId, authority.Network,
            initialLkg.LogGeneration, initialLkg.CoreHash.Span,
            1, new byte[38], new byte[32]);
        var tailQuery = VerifiedDeepIdV2DirectoryQuery.VerifyBinding(
            tailLookup, secondBinding);
        var tailVerified = DeepIdV2DirectoryCurrentProofVerifier.VerifyGenesis(
            authority.Verified, expandedHeadBytes,
            AccountDirectoryDtt1Codec.Encode(tailDtt),
            tailAdp.CanonicalBytes, tailNonce, tailQuery,
            Window(), initialLkg, 1, 2, pq);
        Assert.Equal(secondCheckpoint.Checkpoint.ArtifactHash.ToArray(),
            tailVerified.CurrentCheckpoint!.Checkpoint.ArtifactHash.ToArray());
        Assert.Equal((ulong)3, tailVerified.NextProtectedLkg.LogGeneration);
        Assert.Equal("InvalidForwardTail",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                DeepIdV2DirectoryCurrentProofVerifier.VerifyGenesis(
                    authority.Verified, expandedHeadBytes,
                    AccountDirectoryDtt1Codec.Encode(tailDtt),
                    DeepIdV2Adp1Codec.AuthorWithForwardTail(sourceMaterial,
                        tailDttHash, anchorAfp,
                        initialLkg.ExactAdh1.Span, 0, 0, [],
                        [successorBytes, expandedHeadBytes], []).CanonicalBytes,
                    tailNonce, tailQuery, Window(), initialLkg,
                    1, 2, pq)).Code);

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            DeepIdV2DirectoryProofMaterialAuthor.Create(expandedLkg,
                journal, [checkpoint, secondCheckpoint], leaf,
                verifiedSuccessor.NextProtectedLkg));

        var badFloorAdl = DeepIdV2AccountDirectoryLookupCodec.Author(
            binding.DeepId, authority.Network,
            initialLkg.LogGeneration, Bytes(32, 0x5b),
            1, new byte[38], new byte[32]);
        var badFloorQuery = VerifiedDeepIdV2DirectoryQuery.VerifyBinding(
            badFloorAdl, binding);
        Assert.Equal("QueryFloorMismatch",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                DeepIdV2DirectoryCurrentProofVerifier.VerifyGenesis(
                    authority.Verified, package.ExactAdh1, package.ExactDtt1,
                    package.ExactAdp1V2, nonce, badFloorQuery,
                    Window(), initialLkg, 1, 2, pq)).Code);
        var otherNetworkAdl = DeepIdV2AccountDirectoryLookupCodec.Author(
            binding.DeepId, Bytes(16, 0x71),
            initialLkg.LogGeneration, initialLkg.CoreHash.Span,
            1, new byte[38], new byte[32]);
        Assert.Equal("QueryNetworkMismatch",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                VerifiedDeepIdV2DirectoryQuery.VerifyBinding(
                    otherNetworkAdl, binding)).Code);

        var wrongHeadRequest = new AccountDirectoryProofAuthoringRequest(
            authority.Network, nonce, Bytes(16, 0x44), 1_000,
            initialLkg.ExactAdh1.Span, authority.CurrentXnv(),
            1_900_000_300, 5, 1_900_000_300, 1_900_000_360,
            request.IssuanceEpoch, 2);
        var signers = authority.Witnesses.Take(2).Select(WitnessSigner.Valid)
            .Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray();
        var wrongHead = await Assert.ThrowsAsync<AccountDirectoryProofAuthoringException>(
            () => DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(
                authority.Verified, wrongHeadRequest, material, signers, 1, pq)
                .AsTask());
        Assert.Equal("ExactAdhMismatch", wrongHead.Code);
        var duplicate = await Assert.ThrowsAsync<AccountDirectoryProofAuthoringException>(
            () => DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(
                authority.Verified, request, material,
                [signers[0], signers[0]], 1, pq).AsTask());
        Assert.Equal("DuplicateOrInvalidSigner", duplicate.Code);
    }

    [Fact]
    public void Did2Verifier_AcceptsExactNonceBoundEmptyMapAndIssuesOnlyV2Lkg()
    {
        var fixture = Did2EmptyFixture.Create();
        var verified = fixture.Verify();

        Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership, verified.ResultKind);
        Assert.Null(verified.CurrentCheckpoint);
        Assert.Equal(fixture.HeadBytes, verified.ExactAdh1.ToArray());
        Assert.Equal(fixture.AdpBytes, verified.ExactAdp1V2.ToArray());
        Assert.Equal((ushort)2, verified.NextProtectedLkg.Head.MinimumReader);
        Assert.True(verified.IsCurrentAtMonotonic(Bytes(16, 0x44), 1_003));
        Assert.False(verified.IsCurrentAtMonotonic(Bytes(16, 0x45), 1_003));
        Assert.False(verified.IsCurrentAtMonotonic(Bytes(16, 0x44),
            verified.FreshnessDeadlineMonotonicSeconds));
    }

    [Fact]
    public void Did2Verifier_RejectsOldReaderAndAllQuerySubstitutions()
    {
        var fixture = Did2EmptyFixture.Create();
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            fixture.Verify(supportedReader: 1));
        Assert.Equal("NonceMismatch",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                fixture.Verify(nonce: Bytes(32, 0x46))).Code);
        Assert.Equal("AdpCrossLinkMismatch",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                fixture.Verify(query: Bytes(32, 0x47))).Code);
        Assert.Equal("LkgMismatch",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                fixture.Verify(lkg: fixture.ProtectedHead)).Code);
    }

    [Fact]
    public void Did2Verifier_AcceptsExactProtectedLkgAndRejectsMissingFloor()
    {
        var fixture = Did2EmptyFixture.Create(withLkg: true);
        var verified = fixture.Verify(lkg: fixture.ProtectedHead);
        Assert.Equal(fixture.ProtectedHead.CoreHash.ToArray(),
            verified.NextProtectedLkg.CoreHash.ToArray());
        Assert.Equal("UnexpectedLkg",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                fixture.Verify()).Code);
    }

    [Fact]
    public void Did2Verifier_AcceptsLaterSignedSuccessorAndRejectsBrokenPredecessor()
    {
        var authority = AuthorityFixture.Create();
        var emptyAppend = AccountDirectoryRfc6962.ComputeEmptyTreeHash();
        var emptyMap = DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray();
        var genesis = authority.Head(0, new byte[32], 0,
            emptyAppend, emptyMap, minimumReader: 2);
        var first = authority.Head(1,
            AccountDirectoryCrypto.ComputeAdh1CoreHash(genesis), 0,
            emptyAppend, emptyMap, minimumReader: 2);
        var protectedFirst = new AccountDirectoryProtectedLkg(
            AccountDirectoryAdh1Codec.Encode(first));
        var nonce = Bytes(32, 0x31);
        var leaf = Bytes(32, 0x32);

        VerifiedDeepIdV2DirectoryFreshness Verify(AccountDirectoryAdh1 head)
        {
            var exactHead = AccountDirectoryAdh1Codec.Encode(head);
            var dtt = authority.Dtt(head, nonce);
            var material = DeepIdV2DirectoryProofMaterialAuthor.Create(
                new AccountDirectoryProtectedLkg(exactHead), [], [], leaf,
                protectedFirst);
            var adp = DeepIdV2Adp1Codec.Author(material,
                AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt));
            return DeepIdV2DirectoryCurrentProofVerifier.VerifyExactLeafForAuthor(
                authority.Verified, exactHead, AccountDirectoryDtt1Codec.Encode(dtt),
                adp.CanonicalBytes, nonce, leaf, Window(), protectedFirst,
                1, 2, new DenyingMlDsa65Verifier());
        }

        var successor = authority.Head(2, protectedFirst.CoreHash.ToArray(), 0,
            emptyAppend, emptyMap, minimumReader: 2);
        var verified = Verify(successor);
        Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership,
            verified.ResultKind);
        Assert.Equal((ulong)2, verified.NextProtectedLkg.LogGeneration);
        Assert.Equal("ForwardCheckpointRequired",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                Verify(authority.Head(2, Bytes(32, 0x71), 0,
                    emptyAppend, emptyMap, minimumReader: 2))).Code);
    }

    [Fact]
    public void Did2Verifier_RequiresExactRootAuthorizedForwardCheckpointForSkippedHeads()
    {
        var authority = AuthorityFixture.Create();
        var appendRoot = AccountDirectoryRfc6962.ComputeEmptyTreeHash();
        var mapRoot = DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray();
        var genesis = authority.Head(0, new byte[32], 0,
            appendRoot, mapRoot, minimumReader: 2);
        var floor = new AccountDirectoryProtectedLkg(
            AccountDirectoryAdh1Codec.Encode(genesis));
        var first = authority.Head(1, floor.CoreHash.ToArray(), 0,
            appendRoot, mapRoot, minimumReader: 2);
        var target = authority.Head(2,
            AccountDirectoryCrypto.ComputeAdh1CoreHash(first), 0,
            appendRoot, mapRoot, minimumReader: 2);
        var exactTarget = AccountDirectoryAdh1Codec.Encode(target);
        var targetHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(target);
        var current = new AccountDirectoryProtectedLkg(exactTarget);
        var leaf = Bytes(32, 0x32);
        var nonce = Bytes(32, 0x31);
        var dtt = authority.Dtt(target, nonce);
        var exactDtt = AccountDirectoryDtt1Codec.Encode(dtt);
        var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
        var material = DeepIdV2DirectoryProofMaterialAuthor.Create(
            current, [], [], leaf, floor);
        var sourceLeaf = CoveredHeadLeaf(floor.LogGeneration,
            floor.TreeSize, floor.CoreHash.Span);

        byte[] ForwardBytes(bool invalidSignature = false,
            bool invalidSource = false, bool legacyReader = false)
        {
            var checkpoint = authority.SignedAdf(0, new byte[32],
                0, 0, 1,
                invalidSource ? Bytes(32, 0x6d) : sourceLeaf,
                targetHash, 0, appendRoot, mapRoot,
                invalidSignature,
                minimumReader: legacyReader ? (ushort)1 : (ushort)2);
            var afp = new AccountDirectoryAfp1(authority.Network,
                floor.LogGeneration, floor.TreeSize, floor.CoreHash.Span,
                targetHash, [authority.ExactXna1],
                [AccountDirectoryAdf1Codec.Encode(checkpoint)],
                [exactTarget], 0, [], dttHash);
            return AccountDirectoryAfp1Codec.Encode(afp);
        }

        var noCheckpoint = DeepIdV2Adp1Codec.Author(material, dttHash);
        Assert.Equal("ForwardCheckpointRequired",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                DeepIdV2DirectoryCurrentProofVerifier.VerifyExactLeafForAuthor(
                    authority.Verified, exactTarget, exactDtt,
                    noCheckpoint.CanonicalBytes, nonce, leaf, Window(),
                    floor, 1, 2, new DenyingMlDsa65Verifier())).Code);

        VerifiedDeepIdV2DirectoryFreshness Verify(byte[] afp)
        {
            var adp = DeepIdV2Adp1Codec.AuthorWithForward(material, dttHash, afp);
            Assert.Equal(AccountDirectoryAdp1HistoryMode.ForwardCheckpoint,
                adp.HistoryMode);
            return DeepIdV2DirectoryCurrentProofVerifier.VerifyExactLeafForAuthor(
                authority.Verified, exactTarget, exactDtt,
                adp.CanonicalBytes, nonce, leaf, Window(), floor,
                1, 2, new DenyingMlDsa65Verifier());
        }

        var verified = Verify(ForwardBytes());
        Assert.Equal((ulong)2, verified.NextProtectedLkg.LogGeneration);

        var anchorHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(first);
        var anchorCheckpoint = authority.SignedAdf(0, new byte[32],
            0, 0, 1, sourceLeaf, anchorHash, 0, appendRoot, mapRoot,
            minimumReader: 2);
        var anchorAfp = AccountDirectoryAfp1Codec.Encode(
            new AccountDirectoryAfp1(authority.Network, floor.LogGeneration,
                floor.TreeSize, floor.CoreHash.Span, anchorHash,
                [authority.ExactXna1],
                [AccountDirectoryAdf1Codec.Encode(anchorCheckpoint)],
                [AccountDirectoryAdh1Codec.Encode(first)], 0, [], dttHash));
        VerifiedDeepIdV2DirectoryFreshness VerifyTail(
            IReadOnlyList<ReadOnlyMemory<byte>> heads)
        {
            var adp = DeepIdV2Adp1Codec.AuthorWithForwardTail(material,
                dttHash, anchorAfp, floor.ExactAdh1.Span,
                0, 0, [], heads, []);
            return DeepIdV2DirectoryCurrentProofVerifier.VerifyExactLeafForAuthor(
                authority.Verified, exactTarget, exactDtt,
                adp.CanonicalBytes, nonce, leaf, Window(), floor,
                1, 2, new DenyingMlDsa65Verifier());
        }
        var verifiedTail = VerifyTail([exactTarget]);
        Assert.Equal((ulong)2,
            verifiedTail.NextProtectedLkg.LogGeneration);
        var tailBytes = DeepIdV2ForwardTailCodec.Encode(anchorAfp,
            floor.ExactAdh1.Span, 0, 0, [], [exactTarget]);
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            DeepIdV2ForwardTailCodec.Decode(tailBytes[..^1]));
        tailBytes[4 + anchorAfp.Length + 4 + floor.ExactAdh1.Length +
            1 + 8 + 1] = 65;
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            DeepIdV2ForwardTailCodec.Decode(tailBytes));
        var substituted = authority.Head(2, Bytes(32, 0x71), 0,
            appendRoot, mapRoot, minimumReader: 2);
        Assert.Equal("InvalidForwardTail",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(
                () => VerifyTail([AccountDirectoryAdh1Codec.Encode(substituted),
                    exactTarget])).Code);

        Assert.Equal("InvalidForwardCheckpoint",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(
                () => Verify(ForwardBytes(invalidSignature: true))).Code);
        Assert.Equal("InvalidForwardCheckpoint",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(
                () => Verify(ForwardBytes(legacyReader: true))).Code);
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            DeepIdV2Adp1Codec.AuthorWithForward(material, dttHash,
                ForwardBytes(invalidSource: true)));
        var wrongDtt = ForwardBytes();
        wrongDtt[^1] ^= 1;
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            DeepIdV2Adp1Codec.AuthorWithForward(material, dttHash, wrongDtt));
        var withoutFloor = DeepIdV2DirectoryProofMaterialAuthor.Create(
            current, [], [], leaf);
        Assert.Throws<ArgumentException>(() =>
            DeepIdV2Adp1Codec.AuthorWithForward(withoutFloor, dttHash,
                ForwardBytes()));
    }

    [Fact]
    public async Task Did2Verifier_RecoversProtectedFloorCreatedAfterFirstRootCheckpoint()
    {
        var authority = AuthorityFixture.Create();
        var appendRoot = AccountDirectoryRfc6962.ComputeEmptyTreeHash();
        var mapRoot = DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray();
        var heads = new AccountDirectoryAdh1[5];
        var hashes = new byte[5][];
        var exactHeads = new byte[5][];
        for (var index = 0; index < heads.Length; index++)
        {
            heads[index] = authority.Head((ulong)index,
                index == 0 ? new byte[32] : hashes[index - 1],
                0, appendRoot, mapRoot, minimumReader: 2);
            hashes[index] = AccountDirectoryCrypto
                .ComputeAdh1CoreHash(heads[index]);
            exactHeads[index] = AccountDirectoryAdh1Codec.Encode(heads[index]);
        }
        var source = new AccountDirectoryProtectedLkg(exactHeads[2]);
        var current = new AccountDirectoryProtectedLkg(exactHeads[4]);
        var chainSource = new AccountDirectoryProtectedLkg(exactHeads[0]);
        var source0Leaf = CoveredHeadLeaf(0, 0, hashes[0]);
        var source1Leaf = CoveredHeadLeaf(1, 0, hashes[1]);
        var source2Leaf = CoveredHeadLeaf(2, 0, hashes[2]);
        var first = authority.SignedAdf(0, new byte[32],
            0, 0, 1, source0Leaf, hashes[1], 0,
            appendRoot, mapRoot, minimumReader: 2);
        var second = authority.SignedAdf(1,
            AccountDirectoryCrypto.ComputeAdf1CoreHash(first),
            1, 2, 2,
            AccountDirectoryRfc6962.ComputeNodeHash(
                source1Leaf, source2Leaf),
            hashes[3], 0, appendRoot, mapRoot,
            minimumReader: 2);
        var nonce = Bytes(32, 0x31);
        var leaf = Bytes(32, 0x32);
        var dtt = authority.Dtt(heads[4], nonce);
        var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
        var afp = AccountDirectoryAfp1Codec.Encode(
            new AccountDirectoryAfp1(authority.Network,
                chainSource.LogGeneration, chainSource.TreeSize,
                chainSource.CoreHash.Span, hashes[3],
                [authority.ExactXna1],
                [AccountDirectoryAdf1Codec.Encode(first),
                    AccountDirectoryAdf1Codec.Encode(second)],
                [exactHeads[1], exactHeads[3]],
                0, [], dttHash));
        var material = DeepIdV2DirectoryProofMaterialAuthor.Create(
            current, [], [], leaf, source);

        VerifiedDeepIdV2DirectoryFreshness Verify(byte checkpointIndex,
            ReadOnlyMemory<byte> sibling)
        {
            var adp = DeepIdV2Adp1Codec.AuthorWithForwardTail(
                material, dttHash, afp, exactHeads[0],
                checkpointIndex, 1, [sibling], [exactHeads[4]], []);
            return DeepIdV2DirectoryCurrentProofVerifier.VerifyExactLeafForAuthor(
                authority.Verified, exactHeads[4],
                AccountDirectoryDtt1Codec.Encode(dtt),
                adp.CanonicalBytes, nonce, leaf, Window(), source,
                1, 2, new DenyingMlDsa65Verifier());
        }

        var verified = Verify(1, source1Leaf);
        Assert.Equal((ulong)4, verified.NextProtectedLkg.LogGeneration);
        var anchorNonce = Bytes(32, 0x33);
        var anchorDtt = authority.Dtt(heads[3], anchorNonce);
        var anchorDttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(
            anchorDtt);
        var currentAnchorAfp = AccountDirectoryAfp1Codec.Encode(
            new AccountDirectoryAfp1(authority.Network,
                chainSource.LogGeneration, chainSource.TreeSize,
                chainSource.CoreHash.Span, hashes[3],
                [authority.ExactXna1],
                [AccountDirectoryAdf1Codec.Encode(first),
                    AccountDirectoryAdf1Codec.Encode(second)],
                [exactHeads[1], exactHeads[3]],
                0, [], anchorDttHash));
        var currentAnchorMaterial = DeepIdV2DirectoryProofMaterialAuthor.Create(
            new AccountDirectoryProtectedLkg(exactHeads[3]),
            [], [], leaf, source);
        var currentAnchorAdp = DeepIdV2Adp1Codec.AuthorWithForwardTail(
            currentAnchorMaterial, anchorDttHash, currentAnchorAfp,
            exactHeads[0], 1, 1, [source1Leaf], [], []);
        Assert.Equal((ulong)3,
            DeepIdV2DirectoryCurrentProofVerifier.VerifyExactLeafForAuthor(
                authority.Verified, exactHeads[3],
                AccountDirectoryDtt1Codec.Encode(anchorDtt),
                currentAnchorAdp.CanonicalBytes, anchorNonce, leaf,
                Window(), source, 1, 2,
                new DenyingMlDsa65Verifier())
                .NextProtectedLkg.LogGeneration);
        var history = exactHeads.Select(static value =>
            new AccountDirectoryProtectedLkg(value)).ToArray();
        var forwardInput = DeepIdV2ForwardTailMaterialAuthor.Create(
            authority.Verified, history,
            [], [], leaf, source,
            [AccountDirectoryAdf1Codec.Encode(first),
                AccountDirectoryAdf1Codec.Encode(second)]);
        Assert.Equal((byte)1, forwardInput.SourceCheckpointIndex);
        Assert.Single(forwardInput.ExactTailHeads);
        var issuedNonce = Bytes(32, 0x34);
        var authorRequest = new AccountDirectoryProofAuthoringRequest(
            authority.Network, issuedNonce, Bytes(16, 0x44), 1_000,
            exactHeads[4], authority.CurrentXnv(), 1_700_000_300, 5,
            1_700_000_300, 1_700_000_360,
            AccountDirectoryDtt1IssuanceEpoch.Derive(
                authority.Verified, 1_700_000_300, 5), 2);
        var issued = await DeepIdV2DirectoryProofAuthor
            .IssueWithForwardTailAsync(authority.Verified, authorRequest,
                material, forwardInput,
                authority.Witnesses.Take(2).Select(WitnessSigner.Valid)
                    .Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray(),
                1, new DenyingMlDsa65Verifier());
        var issuedVerified =
            DeepIdV2DirectoryCurrentProofVerifier.VerifyExactLeafForAuthor(
                authority.Verified, issued.ExactAdh1, issued.ExactDtt1,
                issued.ExactAdp1V2, issuedNonce, leaf, Window(), source,
                1, 2, new DenyingMlDsa65Verifier());
        Assert.Equal((ulong)4, issuedVerified.NextProtectedLkg.LogGeneration);
        Assert.True(issuedVerified.HasRootAuthorizedForwardLineage);
        Assert.Equal(source.ExactAdh1.ToArray(),
            issuedVerified.VerifiedProtectedLkgExactAdh1.ToArray());
        var invalidRootFirst = authority.SignedAdf(0, new byte[32],
            0, 0, 1, source0Leaf, hashes[1], 0,
            appendRoot, mapRoot, invalidSignature: true,
            minimumReader: 2);
        var invalidRootInput = DeepIdV2ForwardTailMaterialAuthor.Create(
            authority.Verified, history, [], [], leaf, source,
            [AccountDirectoryAdf1Codec.Encode(invalidRootFirst),
                AccountDirectoryAdf1Codec.Encode(second)]);
        Assert.Equal("Did2ProofRejected",
            (await Assert.ThrowsAsync<AccountDirectoryProofAuthoringException>(
                async () => await DeepIdV2DirectoryProofAuthor
                    .IssueWithForwardTailAsync(authority.Verified,
                        authorRequest, material, invalidRootInput,
                        authority.Witnesses.Take(2)
                            .Select(WitnessSigner.Valid)
                            .Cast<IAccountDirectoryDtt1WitnessSigner>()
                            .ToArray(),
                        1, new DenyingMlDsa65Verifier()))).Code);
        Assert.Equal("InvalidForwardTail",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(
                () => Verify(0, source1Leaf)).Code);
        Assert.Equal("InvalidForwardTail",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(
                () => Verify(1, Bytes(32, 0x72))).Code);
    }

    [Fact]
    public void Did2Verifier_RejectsV1PacketAndTamperedSignedTime()
    {
        var fixture = Did2EmptyFixture.Create();
        var old = fixture.Authority.NonMembership();
        Assert.Equal("InvalidDid2DirectoryProof",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                fixture.Verify(adp: old.AdpBytes)).Code);

        var alteredDtt = fixture.DttBytes.ToArray();
        alteredDtt[^1] ^= 1;
        Assert.Equal("InvalidWitnessSignature",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                fixture.Verify(dtt: alteredDtt)).Code);
    }

    private sealed class Did2EmptyFixture
    {
        private Did2EmptyFixture(AuthorityFixture authority, byte[] head,
            byte[] dtt, byte[] adp, byte[] nonce, byte[] query)
        {
            Authority = authority;
            HeadBytes = head;
            DttBytes = dtt;
            AdpBytes = adp;
            Nonce = nonce;
            Query = query;
            ProtectedHead = new AccountDirectoryProtectedLkg(head);
        }

        internal AuthorityFixture Authority { get; }
        internal byte[] HeadBytes { get; }
        internal byte[] DttBytes { get; }
        internal byte[] AdpBytes { get; }
        internal byte[] Nonce { get; }
        internal byte[] Query { get; }
        internal AccountDirectoryProtectedLkg ProtectedHead { get; }

        internal static Did2EmptyFixture Create(bool withLkg = false)
        {
            var authority = AuthorityFixture.Create();
            var nonce = Bytes(32, 0x31);
            var query = Bytes(32, 0x32);
            var head = authority.Head(0, new byte[32], 0,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
                DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray(),
                minimumReader: 2);
            var exactHead = AccountDirectoryAdh1Codec.Encode(head);
            var dtt = authority.Dtt(head, nonce);
            var exactDtt = AccountDirectoryDtt1Codec.Encode(dtt);
            var protectedHead = new AccountDirectoryProtectedLkg(exactHead);
            var material = DeepIdV2DirectoryProofMaterialAuthor.Create(
                protectedHead, [], [], query,
                withLkg ? protectedHead : null);
            var adp = DeepIdV2Adp1Codec.Author(material,
                AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt)).CanonicalBytes.ToArray();
            return new Did2EmptyFixture(authority, exactHead, exactDtt,
                adp, nonce, query);
        }

        internal VerifiedDeepIdV2DirectoryFreshness Verify(
            byte[]? nonce = null, byte[]? query = null, byte[]? adp = null,
            byte[]? dtt = null, AccountDirectoryProtectedLkg? lkg = null,
            ushort supportedReader = 2) =>
            DeepIdV2DirectoryCurrentProofVerifier.VerifyExactLeafForAuthor(
                Authority.Verified, HeadBytes, dtt ?? DttBytes, adp ?? AdpBytes,
                nonce ?? Nonce, query ?? Query, Window(), lkg,
                deploymentProfileId: 1, supportedReader, new DenyingMlDsa65Verifier());
    }

    private sealed class DenyingMlDsa65Verifier : IDeepMlDsa65Verifier
    {
        public bool Verify(ReadOnlySpan<byte> publicKey1952,
            ReadOnlySpan<byte> message, ReadOnlySpan<byte> context,
            ReadOnlySpan<byte> signature3309) => false;
    }

    private sealed class GenesisHeadSigner(byte[] id, byte[] privateKey) :
        IAccountDirectoryAdh1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => id.ToArray();

        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                Sodium.PublicKeyAuth.SignDetached(signingInput.ToArray(),
                    privateKey));
        }
    }

    private sealed class InvalidGenesisHeadSigner(byte[] id) :
        IAccountDirectoryAdh1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => id.ToArray();

        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>>(new byte[64]);
    }
}
