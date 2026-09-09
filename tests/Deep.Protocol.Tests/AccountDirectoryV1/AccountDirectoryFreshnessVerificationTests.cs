using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryFreshnessVerificationTests
{
    [Fact]
    public async Task Author_CurrentValueProducesCanonicalNonceBoundPackageWithDeterministicSigners()
    {
        var authority = AuthorityFixture.Create();
        var fixture = authority.CurrentValue();
        var request = AuthoringRequest(fixture, monotonicSend: 7_654);
        var material = AuthoringMaterial(fixture);
        var second = new ObservingWitnessSigner(authority.Witnesses[1]);
        var first = new ObservingWitnessSigner(authority.Witnesses[0]);
        IAccountDirectoryDtt1WitnessSigner[] signers =
        [
            second,
            first,
        ];

        var package = await AccountDirectoryProofAuthor.IssueAsync(
            authority.Verified,
            new AccountDirectoryProtectedLkg(fixture.HeadBytes),
            request,
            material,
            signers);

        var dtt = AccountDirectoryDtt1Codec.Decode(package.ExactDtt1.Span);
        var adp = AccountDirectoryAdp1Codec.Decode(package.ExactAdp1.Span);
        Assert.Equal(fixture.Nonce, dtt.ClientNonce.ToArray());
        Assert.Equal(fixture.Query, package.QueriedDirectoryLeafKey.ToArray());
        Assert.Equal(request.BootId.ToArray(), package.BootId.ToArray());
        Assert.Equal(7_654UL, package.ClientMonotonicSendSample);
        Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue, adp.ResultKind);
        Assert.Equal(AccountDirectoryDtt1Codec.Encode(dtt), package.ExactDtt1.ToArray());
        Assert.Equal(AccountDirectoryAdp1Codec.Encode(adp), package.ExactAdp1.ToArray());
        Assert.True(dtt.Witnesses[0].WitnessId.Span.SequenceCompareTo(dtt.Witnesses[1].WitnessId.Span) < 0);
        Assert.All(first.LastSigningInput!.Value.ToArray(), value => Assert.Equal(0, value));
        Assert.All(second.LastSigningInput!.Value.ToArray(), value => Assert.Equal(0, value));

        var packageCopy = package.ExactAdp1.ToArray();
        var exactPackage = package.ExactAdp1.ToArray();
        packageCopy.AsSpan().Fill(0);
        var requestCopy = request.ExactCurrentAdh1.ToArray();
        requestCopy.AsSpan().Fill(0);
        Assert.Equal(exactPackage, package.ExactAdp1.ToArray());
        Assert.Equal(fixture.HeadBytes, request.ExactCurrentAdh1.ToArray());
    }

    [Fact]
    public async Task Author_NonMembershipBindsExactNonceAndMonotonicEcho()
    {
        var authority = AuthorityFixture.Create();
        var fixture = authority.NonMembership();
        var request = AuthoringRequest(fixture, monotonicSend: 42);

        var package = await AccountDirectoryProofAuthor.IssueAsync(
            authority.Verified,
            new AccountDirectoryProtectedLkg(fixture.HeadBytes),
            request,
            AuthoringMaterial(fixture),
            ValidAuthorSigners(authority));

        var dtt = AccountDirectoryDtt1Codec.Decode(package.ExactDtt1.Span);
        var adp = AccountDirectoryAdp1Codec.Decode(package.ExactAdp1.Span);
        Assert.Equal(request.Nonce.ToArray(), package.Nonce.ToArray());
        Assert.Equal(request.Nonce.ToArray(), dtt.ClientNonce.ToArray());
        Assert.Equal(request.BootId.ToArray(), package.BootId.ToArray());
        Assert.Equal(request.ClientMonotonicSendSample, package.ClientMonotonicSendSample);
        Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership, adp.ResultKind);
        Assert.Null(adp.CurrentValue);
    }

    [Fact]
    public async Task Author_RejectsInsufficientDuplicateUnknownFailingAndWrongSigners()
    {
        var authority = AuthorityFixture.Create();
        var fixture = authority.NonMembership();
        var current = new AccountDirectoryProtectedLkg(fixture.HeadBytes);
        var request = AuthoringRequest(fixture);
        var material = AuthoringMaterial(fixture);
        var valid = WitnessSigner.Valid(authority.Witnesses[0]);

        await AssertAuthorFailure("InsufficientSigners", () => AccountDirectoryProofAuthor.IssueAsync(
            authority.Verified, current, request, material, [valid]).AsTask());
        await AssertAuthorFailure("DuplicateOrInvalidSigner", () => AccountDirectoryProofAuthor.IssueAsync(
            authority.Verified, current, request, material, [valid, valid]).AsTask());
        await AssertAuthorFailure("UnknownSigner", () => AccountDirectoryProofAuthor.IssueAsync(
            authority.Verified, current, request, material,
            [valid, new WitnessSigner(Bytes(32, 0xee), authority.Witnesses[1].Key.PrivateKey)]).AsTask());
        await AssertAuthorFailure("SignerFailed", () => AccountDirectoryProofAuthor.IssueAsync(
            authority.Verified, current, request, material,
            [valid, new FailingWitnessSigner(authority.Witnesses[1].Id)]).AsTask());

        var unrelated = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xef));
        await AssertAuthorFailure("InvalidSignerResult", () => AccountDirectoryProofAuthor.IssueAsync(
            authority.Verified, current, request, material,
            [valid, new WitnessSigner(authority.Witnesses[1].Id, unrelated.PrivateKey)]).AsTask());
    }

    [Fact]
    public async Task Author_RejectsTamperedExactAdhLeafAndSparseProof()
    {
        var authority = AuthorityFixture.Create();
        var fixture = authority.CurrentValue();
        var current = new AccountDirectoryProtectedLkg(fixture.HeadBytes);

        var tamperedAdh = fixture.HeadBytes.ToArray();
        tamperedAdh[^1] ^= 1;
        await AssertAuthorFailure("ExactAdhMismatch", () => AccountDirectoryProofAuthor.IssueAsync(
            authority.Verified,
            current,
            AuthoringRequest(fixture, exactAdh1: tamperedAdh),
            AuthoringMaterial(fixture),
            ValidAuthorSigners(authority)).AsTask());

        var decoded = AccountDirectoryAdp1Codec.Decode(fixture.AdpBytes);
        var tamperedTransition = decoded.CurrentValue!.ExactTransitionBytes.ToArray();
        tamperedTransition[10] ^= 1;
        var wrongLeaf = AccountDirectoryAdp1ProofMaterial.CurrentValue(
            fixture.Checkpoint!, fixture.Lkg, decoded.ConsistencyProofNodes, decoded.ExactAfp1,
            decoded.SparseMapBitmap.Span, decoded.SparseMapSiblings,
            tamperedTransition, decoded.CurrentValue.AppendLogIndex, decoded.CurrentValue.InclusionProofNodes);
        await AssertAuthorFailure("AuthoringRejected", () => AccountDirectoryProofAuthor.IssueAsync(
            authority.Verified, current, AuthoringRequest(fixture), wrongLeaf, ValidAuthorSigners(authority)).AsTask());

        var bitmap = new byte[32];
        bitmap[0] = 1;
        var wrongSparse = AccountDirectoryAdp1ProofMaterial.CurrentValue(
            fixture.Checkpoint!, fixture.Lkg, decoded.ConsistencyProofNodes, decoded.ExactAfp1,
            bitmap, [Bytes(32, 0xdd)], decoded.CurrentValue.ExactTransitionBytes,
            decoded.CurrentValue.AppendLogIndex, decoded.CurrentValue.InclusionProofNodes);
        await AssertAuthorFailure("AuthoringRejected", () => AccountDirectoryProofAuthor.IssueAsync(
            authority.Verified, current, AuthoringRequest(fixture), wrongSparse, ValidAuthorSigners(authority)).AsTask());
    }

    [Fact]
    public void Verify_NonMembershipReturnsDefensiveCurrentCapability()
    {
        var authority = AuthorityFixture.Create();
        var proof = authority.NonMembership();

        var verified = Verify(proof);

        Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership, verified.ResultKind);
        Assert.Empty(verified.ExactAdc1Reference.ToArray());
        Assert.Null(verified.CurrentCheckpoint);
        Assert.Equal(proof.Query, verified.DirectoryLeafKey.ToArray());
        Assert.Equal(proof.Head.LogGeneration, verified.AdhGeneration);
        Assert.Equal(proof.Head.TreeSize, verified.TreeSize);
        Assert.True(verified.TrustedLowerUnixSeconds <= verified.TrustedUpperUnixSeconds);
        Assert.True(verified.IsCurrentAtMonotonic(Window().BootId.Span, Window().CurrentSample));
        Assert.False(verified.IsCurrentAtMonotonic(Bytes(16, 0xfe), Window().CurrentSample));

        var copy = verified.ExactAdp1.ToArray();
        copy.AsSpan().Fill(0);
        Assert.Equal(proof.AdpBytes, verified.ExactAdp1.ToArray());
        Assert.Equal(proof.HeadBytes, verified.NextProtectedLkg.ExactAdh1.ToArray());
    }

    [Fact]
    public void Verify_CurrentValueClosesRealAdcCapabilityAndEmptyTreeLkg()
    {
        var authority = AuthorityFixture.Create();
        var proof = authority.CurrentValue();

        var verified = Verify(proof);

        Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue, verified.ResultKind);
        Assert.Same(proof.Checkpoint, verified.CurrentCheckpoint);
        Assert.Equal(Reference("ADC1", AccountDirectoryCrypto.ComputeAdc1ArtifactHash(
            proof.Checkpoint!.Checkpoint)), verified.ExactAdc1Reference.ToArray());
        Assert.NotNull(proof.Lkg);
        Assert.Equal(0UL, proof.Lkg!.TreeSize);
        Assert.NotEqual(AccountDirectoryRfc6962.ComputeEmptyTreeHash(), proof.Lkg.CoreHash.ToArray());
        Assert.Equal(proof.Lkg.CoreHash.ToArray(),
            AccountDirectoryAdp1Codec.Decode(proof.AdpBytes).CallerLkgAdh1CoreHash.ToArray());
    }

    [Fact]
    public void Verify_RejectsWitnessSignerSubstitutionAndThresholdFailure()
    {
        var authority = AuthorityFixture.Create();
        var baseProof = authority.NonMembership();
        var oneAdh = authority.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray(),
            [WitnessSigner.Valid(authority.Witnesses[0])]);
        Reject(authority.NonMembership(oneAdh), "WrongWitnessThreshold");

        var oneDtt = authority.Dtt(baseProof.Head, baseProof.Nonce,
            [WitnessSigner.Valid(authority.Witnesses[0])]);
        Reject(authority.NonMembership(baseProof.Head, oneDtt), "WrongWitnessThreshold");

        var attackers = new[]
        {
            PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xd0)),
            PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xd1)),
        };
        var invalidAdh = authority.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray(),
            authority.Witnesses.Take(2).Select((witness, index) =>
                new WitnessSigner(witness.Id, attackers[index].PrivateKey)).ToArray());
        Reject(authority.NonMembership(invalidAdh), "InvalidWitnessSignature");
    }

    [Fact]
    public void Verify_RejectsExpiredFutureAndWrongNonceDtt()
    {
        var authority = AuthorityFixture.Create();
        var proof = authority.NonMembership();

        Reject(proof, "NonceMismatch", nonce: Bytes(32, 0xee));
        Reject(proof, "NonceWindowExpired",
            window: new AccountDirectoryMonotonicRequestWindow(Bytes(16, 0x44), 1_000, 1_031, 1_031));
        Reject(proof, "DttExpired",
            window: new AccountDirectoryMonotonicRequestWindow(Bytes(16, 0x44), 1_000, 1_002, 1_058));

        var future = authority.Dtt(proof.Head, proof.Nonce,
            observed: authority.Verified.ExpiresAt + 100);
        Reject(authority.NonMembership(proof.Head, future), "AuthorityTimeMismatch");
    }

    [Fact]
    public void IssuanceEpoch_IsStableWithinOneUtcDayAndBoundToTheVerifiedAuthority()
    {
        var authority = AuthorityFixture.Create();
        var first = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority.Verified, 1_700_000_200, 5);
        var sameDay = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority.Verified, first.ValidFrom + 100, 5);
        var nextDay = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority.Verified, first.ValidUntil + 6, 5);
        var otherAuthority = AuthorityFixture.Create(seedOffset: 1);
        var other = AccountDirectoryDtt1IssuanceEpoch.Derive(
            otherAuthority.Verified, 1_700_000_200, 5);

        Assert.Equal(first.Id.ToArray(), sameDay.Id.ToArray());
        Assert.NotEqual(first.Id.ToArray(), nextDay.Id.ToArray());
        Assert.NotEqual(first.Id.ToArray(), other.Id.ToArray());
    }

    [Fact]
    public void IssuanceEpoch_RejectsTrustedIntervalsThatCrossUtcDayBoundary()
    {
        var authority = AuthorityFixture.Create();
        var epoch = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority.Verified, 1_700_000_200, 5);

        Assert.Throws<CryptographicException>(() =>
            AccountDirectoryDtt1IssuanceEpoch.Derive(
                authority.Verified, epoch.ValidUntil, 1));
        Assert.Throws<CryptographicException>(() =>
            AccountDirectoryDtt1IssuanceEpoch.Derive(
                authority.Verified, epoch.ValidUntil + 1, 1));
    }

    [Fact]
    public void Verify_RejectsAValidlySignedDttFromTheWrongIssuanceEpoch()
    {
        var authority = AuthorityFixture.Create();
        var proof = authority.NonMembership();
        var nextEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority.Verified,
            AccountDirectoryDtt1IssuanceEpoch.Derive(
                authority.Verified, 1_700_000_200, 5).ValidUntil + 6,
            5);
        var wrongEpochDtt = authority.Dtt(
            proof.Head, proof.Nonce, epochId: nextEpoch.Id.ToArray());

        Reject(authority.NonMembership(proof.Head, wrongEpochDtt), "IssuanceEpochMismatch");
    }

    [Fact]
    public void Verify_RejectsHeadAuthorityPolicyAndQueryCrossLinkSubstitution()
    {
        var authority = AuthorityFixture.Create();
        var proof = authority.NonMembership();
        var otherHeadDtt = authority.Dtt(proof.Head, proof.Nonce, adhHash: Bytes(32, 0xa1));
        Reject(authority.NonMembership(proof.Head, otherHeadDtt), "DttHeadMismatch");

        var wrongAuthorityHead = authority.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray(),
            authorityReference: Reference("XNA1", Bytes(32, 0xa2)));
        Reject(authority.NonMembership(wrongAuthorityHead), "AuthorityMismatch");

        var wrongPolicyHead = authority.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray(),
            witnessPolicy: Bytes(32, 0xa3));
        Reject(authority.NonMembership(wrongPolicyHead), "WitnessPolicyMismatch");

        Reject(proof, "AdpCrossLinkMismatch", query: Bytes(32, 0xa4));
    }

    [Fact]
    public void Verify_RejectsLkgRollbackSameGenerationForkAndGenerationGap()
    {
        var authority = AuthorityFixture.Create();
        var current = authority.CurrentValue();
        var currentLkg = new AccountDirectoryProtectedLkg(current.HeadBytes);

        var oldHead = authority.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray());
        Reject(authority.NonMembership(oldHead, lkg: currentLkg), "LkgRollback");

        var forkHead = authority.Head(current.Head.LogGeneration, current.Head.PredecessorAdh1CoreHash.ToArray(),
            current.Head.TreeSize, Bytes(32, 0xb1), AccountDirectorySparseMap.EmptyMapRoot.ToArray());
        Reject(authority.NonMembership(forkHead, lkg: currentLkg), "DirectoryFork");

        var gapHead = authority.Head(3, current.Lkg!.CoreHash.ToArray(), 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray());
        Reject(authority.NonMembership(gapHead, lkg: current.Lkg), "ForwardCheckpointRequired");
    }

    [Fact]
    public void Verify_RejectsMapOrInclusionTamperAndAdcCapabilitySubstitution()
    {
        var authority = AuthorityFixture.Create();
        var current = authority.CurrentValue();
        var transitionTamper = MutateField(current.AdpBytes, 25, value => value[^1] ^= 1);
        Reject(current with { AdpBytes = transitionTamper }, "InvalidAccountDirectoryProof");

        var otherIdentity = AccountDirectoryAdc1VerificationTests.Fixture.Create(0x42);
        ReadOnlyMemory<byte>[] revoked = [];
        var otherAdc = otherIdentity.CreateCheckpoint(revoked);
        var otherCheckpoint = AccountDirectoryAdc1Verifier.Verify(
            otherAdc, otherIdentity.Binding, otherIdentity.Directory, revoked, 1);
        Reject(current, "AdcSubstitution", checkpoint: otherCheckpoint);
    }

    [Fact]
    public void Verify_ForwardCheckpointClosesSourceMembershipAdfChainAndExactTarget()
    {
        var authority = AuthorityFixture.Create();
        var proof = authority.ForwardCheckpoint();

        var verified = Verify(proof);

        Assert.Equal(3UL, verified.AdhGeneration);
        Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership, verified.ResultKind);
        Assert.Equal(proof.HeadBytes, verified.NextProtectedLkg.ExactAdh1.ToArray());
    }

    [Theory]
    [InlineData(ForwardFault.WrongSourceMembership)]
    [InlineData(ForwardFault.WrongFinalTargetTuple)]
    [InlineData(ForwardFault.InvalidRootSignature)]
    [InlineData(ForwardFault.OmittedGenesisCheckpoint)]
    [InlineData(ForwardFault.ExtraCheckpointAfterTarget)]
    public void Verify_RejectsHostileForwardCheckpointClosure(ForwardFault fault)
    {
        var authority = AuthorityFixture.Create();
        var proof = authority.ForwardCheckpoint(fault);
        var error = Assert.Throws<AccountDirectoryFreshnessVerificationException>(() => Verify(proof));
        Assert.Contains(error.Code, new[] { "InvalidForwardCheckpoint", "InvalidAccountDirectoryProof" });
    }

    [Fact]
    public void ProtectedLkgRestore_ReauthenticatesCanonicalOldHeadWithoutCurrentTime()
    {
        var authority = AuthorityFixture.Create();
        var proof = authority.NonMembership();
        var expectedHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(proof.Head);

        var restored = AccountDirectoryProtectedLkgFactory.Restore(
            authority.Verified, proof.HeadBytes, expectedHash);

        Assert.Equal(proof.HeadBytes, restored.ExactAdh1.ToArray());
        Assert.Equal(expectedHash, restored.CoreHash.ToArray());
        Assert.True(proof.Head.ValidUntil < (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    [Fact]
    public void ProtectedLkgRestore_RejectsAlteredBytesAndExpectedHash()
    {
        var authority = AuthorityFixture.Create(); var proof = authority.NonMembership();
        var expectedHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(proof.Head);
        var altered = proof.HeadBytes.ToArray(); altered[^1] ^= 1;

        Assert.Equal("InvalidWitnessSignature", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(authority.Verified, altered, expectedHash)).Code);
        Assert.Equal("PersistedLkgHashMismatch", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(authority.Verified, proof.HeadBytes, Bytes(32, 0xee))).Code);
    }

    [Fact]
    public void ProtectedLkgRestore_RejectsWrongNetworkInsufficientThresholdAndBadSignature()
    {
        var authority = AuthorityFixture.Create(); var proof = authority.NonMembership();
        var expectedHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(proof.Head);
        var wrongNetworkAuthority = AuthorityFixture.Create(networkMarker: 0x12);
        Assert.Equal("NetworkMismatch", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(wrongNetworkAuthority.Verified, proof.HeadBytes, expectedHash)).Code);
        var wrongAuthority = AuthorityFixture.Create(seedOffset: 1);
        Assert.Equal("AuthorityMismatch", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(wrongAuthority.Verified, proof.HeadBytes, expectedHash)).Code);

        var insufficient = authority.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray(),
            [WitnessSigner.Valid(authority.Witnesses[0])]);
        Assert.Equal("WrongWitnessThreshold", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(authority.Verified, AccountDirectoryAdh1Codec.Encode(insufficient),
                AccountDirectoryCrypto.ComputeAdh1CoreHash(insufficient))).Code);

        var unrelated = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xee));
        var badSignature = authority.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray(),
            [new WitnessSigner(authority.Witnesses[0].Id, unrelated.PrivateKey),
             WitnessSigner.Valid(authority.Witnesses[1])]);
        Assert.Equal("InvalidWitnessSignature", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(authority.Verified, AccountDirectoryAdh1Codec.Encode(badSignature),
                AccountDirectoryCrypto.ComputeAdh1CoreHash(badSignature))).Code);
    }

    [Fact]
    public void ProtectedLkgRestore_ThenForwardCheckpointVerificationSucceedsWithoutNullFallback()
    {
        var authority = AuthorityFixture.Create(); var proof = authority.ForwardCheckpoint();
        var persisted = proof.Lkg!;
        var restored = AccountDirectoryProtectedLkgFactory.Restore(
            authority.Verified, persisted.ExactAdh1, persisted.CoreHash.Span);

        var verified = AccountDirectoryCurrentProofVerifier.Verify(
            authority.Verified, proof.HeadBytes, proof.DttBytes, proof.AdpBytes,
            proof.Nonce, proof.Query, Window(), restored, null, 1);

        Assert.Equal(3UL, verified.NextProtectedLkg.LogGeneration);
        Assert.Equal(proof.HeadBytes, verified.NextProtectedLkg.ExactAdh1.ToArray());
    }

    [Fact]
    public void CapabilityHasNoPublicConstructorAndVerifierHasNoCallbackOrKeyMap()
    {
        Assert.Empty(typeof(VerifiedAccountDirectoryFreshness).GetConstructors());
        Assert.Empty(typeof(AccountDirectoryProtectedLkg).GetConstructors());
        Assert.Empty(typeof(AccountDirectoryDtt1IssuanceEpoch).GetConstructors());
        var verify = Assert.Single(typeof(AccountDirectoryCurrentProofVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.DoesNotContain(verify.GetParameters(), parameter =>
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType) ||
            parameter.ParameterType.Name.Contains("Callback", StringComparison.Ordinal) ||
            parameter.ParameterType.Name.Contains("Verifier", StringComparison.Ordinal) ||
            parameter.ParameterType.Name.Contains("KeyMap", StringComparison.Ordinal));
    }

    private static VerifiedAccountDirectoryFreshness Verify(
        ProofFixture proof,
        AccountDirectoryMonotonicRequestWindow? window = null,
        byte[]? nonce = null,
        byte[]? query = null,
        VerifiedAccountDirectoryCheckpoint? checkpoint = null) =>
        AccountDirectoryCurrentProofVerifier.Verify(
            proof.Authority.Verified, proof.HeadBytes, proof.DttBytes, proof.AdpBytes,
            nonce ?? proof.Nonce, query ?? proof.Query, window ?? Window(), proof.Lkg,
            checkpoint ?? proof.Checkpoint, supportedReader: 1);

    private static void Reject(
        ProofFixture proof,
        string code,
        AccountDirectoryMonotonicRequestWindow? window = null,
        byte[]? nonce = null,
        byte[]? query = null,
        VerifiedAccountDirectoryCheckpoint? checkpoint = null)
    {
        var error = Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryCurrentProofVerifier.Verify(
                proof.Authority.Verified, proof.HeadBytes, proof.DttBytes, proof.AdpBytes,
                nonce ?? proof.Nonce, query ?? proof.Query, window ?? Window(), proof.Lkg,
                checkpoint ?? proof.Checkpoint, 1));
        Assert.Equal(code, error.Code);
    }

    private static AccountDirectoryProofAuthoringRequest AuthoringRequest(
        ProofFixture fixture,
        ulong monotonicSend = 1_000,
        byte[]? exactAdh1 = null) =>
        new(
            fixture.Authority.Network,
            fixture.Nonce,
            Bytes(16, 0x44),
            monotonicSend,
            exactAdh1 ?? fixture.HeadBytes,
            fixture.Authority.CurrentXnv(),
            1_700_000_200,
            5,
            1_700_000_200,
            1_700_000_260,
            AccountDirectoryDtt1IssuanceEpoch.Derive(
                fixture.Authority.Verified, 1_700_000_200, 5),
            1);

    private static AccountDirectoryAdp1ProofMaterial AuthoringMaterial(ProofFixture fixture)
    {
        var decoded = AccountDirectoryAdp1Codec.Decode(fixture.AdpBytes);
        if (decoded.ResultKind == AccountDirectoryAdp1ResultKind.NonMembership)
            return AccountDirectoryAdp1ProofMaterial.NonMembership(
                decoded.QueriedDirectoryLeafKey.Span,
                fixture.Lkg,
                decoded.ConsistencyProofNodes,
                decoded.ExactAfp1,
                decoded.SparseMapBitmap.Span,
                decoded.SparseMapSiblings);

        var current = decoded.CurrentValue!;
        return AccountDirectoryAdp1ProofMaterial.CurrentValue(
            fixture.Checkpoint!,
            fixture.Lkg,
            decoded.ConsistencyProofNodes,
            decoded.ExactAfp1,
            decoded.SparseMapBitmap.Span,
            decoded.SparseMapSiblings,
            current.ExactTransitionBytes,
            current.AppendLogIndex,
            current.InclusionProofNodes);
    }

    private static IReadOnlyList<IAccountDirectoryDtt1WitnessSigner> ValidAuthorSigners(
        AuthorityFixture authority) =>
        authority.Witnesses.Take(2).Select(WitnessSigner.Valid)
            .Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray();

    private static async Task AssertAuthorFailure(string code, Func<Task> action)
    {
        var error = await Assert.ThrowsAsync<AccountDirectoryProofAuthoringException>(action);
        Assert.Equal(code, error.Code);
    }

    private static AccountDirectoryMonotonicRequestWindow Window() =>
        new(Bytes(16, 0x44), 1_000, 1_002, 1_003);

    private sealed record Witness(byte[] Id, KeyPair Key, byte[] FailureDomain);
    private sealed record WitnessSigner(byte[] Id, byte[] PrivateKey) : IAccountDirectoryDtt1WitnessSigner
    {
        internal static WitnessSigner Valid(Witness witness) => new(witness.Id, witness.Key.PrivateKey);

        public ReadOnlyMemory<byte> WitnessId => Id.ToArray();

        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(signingInput.ToArray(), PrivateKey));
        }
    }

    private sealed class FailingWitnessSigner(byte[] id) : IAccountDirectoryDtt1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => id.ToArray();

        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken) => throw new IOException("custody unavailable");
    }

    private sealed class ObservingWitnessSigner(Witness witness) : IAccountDirectoryDtt1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => witness.Id.ToArray();
        internal ReadOnlyMemory<byte>? LastSigningInput { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastSigningInput = signingInput;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(signingInput.ToArray(), witness.Key.PrivateKey));
        }
    }

    public enum ForwardFault
    {
        None,
        WrongSourceMembership,
        WrongFinalTargetTuple,
        InvalidRootSignature,
        OmittedGenesisCheckpoint,
        ExtraCheckpointAfterTarget,
    }

    private sealed record ProofFixture(
        AuthorityFixture Authority,
        AccountDirectoryAdh1 Head,
        byte[] HeadBytes,
        AccountDirectoryDtt1 Dtt,
        byte[] DttBytes,
        byte[] AdpBytes,
        byte[] Nonce,
        byte[] Query,
        AccountDirectoryProtectedLkg? Lkg,
        VerifiedAccountDirectoryCheckpoint? Checkpoint);

    private sealed class AuthorityFixture
    {
        private readonly KeyPair root;

        private AuthorityFixture(
            byte[] network,
            KeyPair root,
            Witness[] witnesses,
            byte[] exactXna1,
            VerifiedXPointNetworkAuthority verified)
        {
            Network = network;
            this.root = root;
            Witnesses = witnesses;
            ExactXna1 = exactXna1;
            Verified = verified;
        }

        internal byte[] Network { get; }
        internal Witness[] Witnesses { get; }
        internal byte[] ExactXna1 { get; }
        internal VerifiedXPointNetworkAuthority Verified { get; }

        internal static AuthorityFixture Create(byte networkMarker = 0x11, byte seedOffset = 0)
        {
            var network = Bytes(16, networkMarker);
            var root = PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0x20 + seedOffset))));
            var witnesses = Enumerable.Range(0, 3).Select(index => new Witness(
                Bytes(32, checked((byte)(0x40 + seedOffset + index))),
                PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0x50 + seedOffset + index)))),
                Bytes(32, checked((byte)(0x60 + seedOffset + index))))).ToArray();
            var dts = Dts(network, root);
            var policyHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(AccountDirectoryDts1Codec.Decode(dts));
            var xna = Xna(network, root, witnesses, policyHash);
            var xnaRecord = XPointNetworkCodec.Parse<Xna1Record>(xna);
            var pin = new XPointNetworkGenesisPin(network, xnaRecord.CoreHash.Span);
            var verified = XPointNetworkAuthorityVerifier.Verify(pin, [xna], [dts]);
            return new AuthorityFixture(network, root, witnesses, xna, verified);
        }

        internal AccountDirectoryAdh1 Head(
            ulong generation,
            byte[] predecessor,
            ulong treeSize,
            byte[] appendRoot,
            byte[] mapRoot,
            IReadOnlyList<WitnessSigner>? signers = null,
            byte[]? authorityReference = null,
            byte[]? witnessPolicy = null)
        {
            var selected = (signers ?? Witnesses.Take(2).Select(WitnessSigner.Valid).ToArray())
                .OrderBy(static signer => signer.Id, ByteArrayComparer.Instance).ToArray();
            var placeholders = selected.Select((signer, index) => new AccountDirectoryAdh1WitnessEntry(
                signer.Id, Bytes(64, checked((byte)(0x70 + index))))).ToArray();
            var unsigned = new AccountDirectoryAdh1(
                Network, generation, predecessor, treeSize, appendRoot, mapRoot,
                authorityReference ?? Verified.AuthorityCoreReference.ToArray(),
                witnessPolicy ?? Verified.DirectoryWitnessPolicyHash.ToArray(),
                1_700_000_000, 1_700_010_000, 1, placeholders);
            var signing = AccountDirectoryCrypto.ComputeAdh1SigningInput(unsigned);
            var receipts = selected.Select(signer => new AccountDirectoryAdh1WitnessEntry(
                signer.Id, PublicKeyAuth.SignDetached(signing, signer.PrivateKey))).ToArray();
            return new AccountDirectoryAdh1(
                Network, generation, predecessor, treeSize, appendRoot, mapRoot,
                authorityReference ?? Verified.AuthorityCoreReference.ToArray(),
                witnessPolicy ?? Verified.DirectoryWitnessPolicyHash.ToArray(),
                1_700_000_000, 1_700_010_000, 1, receipts);
        }

        internal AccountDirectoryDtt1 Dtt(
            AccountDirectoryAdh1 head,
            byte[] nonce,
            IReadOnlyList<WitnessSigner>? signers = null,
            ulong observed = 1_700_000_200,
            byte[]? adhHash = null,
            byte[]? epochId = null)
        {
            var selected = (signers ?? Witnesses.Take(2).Select(WitnessSigner.Valid).ToArray())
                .OrderBy(static signer => signer.Id, ByteArrayComparer.Instance).ToArray();
            var placeholders = selected.Select((signer, index) => new AccountDirectoryDtt1WitnessReceipt(
                signer.Id, Bytes(64, checked((byte)(0x80 + index))))).ToArray();
            var headHash = adhHash ?? AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            var epochObserved = observed < Verified.Dts1NotBefore || observed > Verified.Dts1ExpiresAt
                ? Verified.Dts1NotBefore + 100
                : observed;
            var issuanceEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(Verified, epochObserved, 5);
            var selectedEpochId = epochId ?? issuanceEpoch.Id.ToArray();
            var unsigned = new AccountDirectoryDtt1(
                Network, nonce, observed, 5, headHash, head.LogGeneration, Bytes(32, 0x90), 1,
                Verified.AuthorityCoreReference.Span, Verified.DirectoryWitnessPolicyHash.Span,
                observed, checked(observed + 60), selectedEpochId, placeholders);
            var signing = AccountDirectoryCrypto.ComputeDtt1SigningInput(unsigned);
            var receipts = selected.Select(signer => new AccountDirectoryDtt1WitnessReceipt(
                signer.Id, PublicKeyAuth.SignDetached(signing, signer.PrivateKey))).ToArray();
            return new AccountDirectoryDtt1(
                Network, nonce, observed, 5, headHash, head.LogGeneration, Bytes(32, 0x90), 1,
                Verified.AuthorityCoreReference.Span, Verified.DirectoryWitnessPolicyHash.Span,
                observed, checked(observed + 60), selectedEpochId, receipts);
        }

        internal byte[] CurrentXnv()
        {
            ReadOnlyMemory<byte>[] fields =
            [
                Network,
                U64(0),
                new byte[32],
                Bytes(32, 0x91),
                U64(1),
                Bytes(32, 0x92),
                Verified.AuthorityCoreReference,
                Verified.DirectoryWitnessPolicyHash,
                Reference("XVP1", Bytes(32, 0x93)),
                U16(1),
                U16(3),
                Join(
                    Reference("XND1", Bytes(32, 0x94)),
                    Reference("XND1", Bytes(32, 0x95)),
                    Reference("XND1", Bytes(32, 0x96))),
                U16(0),
                Array.Empty<byte>(),
                U16(0),
                Array.Empty<byte>(),
                U16(1),
                Reference("XCB1", Bytes(32, 0x97)),
                U64(1),
                U64(1_699_999_000),
                U64(1_700_010_000),
                U16(1),
                new byte[] { 2 },
                Join(
                    Witnesses[0].Id, Bytes(64, 0xa1),
                    Witnesses[1].Id, Bytes(64, 0xa2)),
            ];
            var provisional = XPointNetworkCodec.Parse<Xnv1Record>(
                XPointNetworkCodec.Write(XPointNetworkRegistry.Xnv1, fields));
            var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
            try
            {
                fields[23] = Join(
                    Witnesses[0].Id, PublicKeyAuth.SignDetached(input, Witnesses[0].Key.PrivateKey),
                    Witnesses[1].Id, PublicKeyAuth.SignDetached(input, Witnesses[1].Key.PrivateKey));
                return XPointNetworkCodec.Write(XPointNetworkRegistry.Xnv1, fields);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }

        internal ProofFixture NonMembership(
            AccountDirectoryAdh1? head = null,
            AccountDirectoryDtt1? dtt = null,
            AccountDirectoryProtectedLkg? lkg = null)
        {
            var nonce = Bytes(32, 0x31);
            var query = Bytes(32, 0x32);
            head ??= Head(0, new byte[32], 0,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray());
            dtt ??= Dtt(head, nonce);
            var headBytes = AccountDirectoryAdh1Codec.Encode(head);
            var dttBytes = AccountDirectoryDtt1Codec.Encode(dtt);
            var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
            var adp = Write("ADP1", 0x0201,
            [
                Network, [2], query, headBytes,
                U64(lkg?.TreeSize ?? 0), lkg?.CoreHash.ToArray() ?? new byte[32],
                [0], [], new byte[32], U16(0), [], [lkg is null ? (byte)0 : (byte)1],
                [0], [], dttHash,
            ]);
            return new ProofFixture(this, head, headBytes, dtt, dttBytes, adp, nonce, query, lkg, null);
        }

        internal ProofFixture CurrentValue()
        {
            var identity = AccountDirectoryAdc1VerificationTests.Fixture.Create();
            ReadOnlyMemory<byte>[] revoked = [];
            var adc = identity.CreateCheckpoint(revoked);
            var checkpoint = AccountDirectoryAdc1Verifier.Verify(
                adc, identity.Binding, identity.Directory, revoked, supportedReader: 1);
            var adcBytes = AccountDirectoryAdc1Codec.Encode(adc);
            var adcReference = Reference("ADC1", AccountDirectoryCrypto.ComputeAdc1ArtifactHash(adc));
            var query = adc.DirectoryLeafKey.ToArray();
            var nonce = Bytes(32, 0x31);
            var oldHead = Head(0, new byte[32], 0,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray());
            var oldBytes = AccountDirectoryAdh1Codec.Encode(oldHead);
            var lkg = new AccountDirectoryProtectedLkg(oldBytes);
            var bitmap = new byte[32];
            var mapRoot = AccountDirectorySparseMap.ComputePresentRoot(query, adcReference, bitmap, []);
            var transition = Join(
                U16(1), U64(0), query, new byte[38], adcReference,
                AccountDirectorySparseMap.EmptyMapRoot.ToArray(), mapRoot);
            var commitment = AccountDirectoryCrypto.Sha256Domain("Deep/AccountDirectory/V1/transition", transition);
            var appendRoot = AccountDirectoryRfc6962.ComputeLeafHash(commitment);
            var head = Head(1, lkg.CoreHash.ToArray(), 1, appendRoot, mapRoot);
            var headBytes = AccountDirectoryAdh1Codec.Encode(head);
            var dtt = Dtt(head, nonce);
            var dttBytes = AccountDirectoryDtt1Codec.Encode(dtt);
            var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
            var devices = identity.Identity.ActiveDevices
                .OrderBy(static device => device.Certificate.DeviceId.ToArray(), ByteArrayComparer.Instance)
                .Select(static device => Lp32(device.Certificate.CanonicalBytes.ToArray())).ToArray();
            var adp = Write("ADP1", 0x0201,
            [
                Network, [1], query, headBytes, U64(0), lkg.CoreHash.ToArray(), [0], [], bitmap, U16(0), [], [1], [0], [], dttHash,
                adcBytes, identity.DeepId.RecordHash.ToArray(), identity.DeepId.AddressPublicKey.ToArray(),
                identity.Binding.Record.CanonicalBytes.ToArray(), identity.Account.Certificate.CanonicalBytes.ToArray(),
                identity.Revocations.Snapshot.CanonicalBytes.ToArray(), identity.Directory.Record.CanonicalBytes.ToArray(),
                [checked((byte)devices.Length)], Join(devices), transition, U64(0), [0], [],
            ]);
            return new ProofFixture(this, head, headBytes, dtt, dttBytes, adp, nonce, query, lkg, checkpoint);
        }

        internal ProofFixture ForwardCheckpoint(ForwardFault fault = ForwardFault.None)
        {
            var nonce = Bytes(32, 0x31);
            var query = Bytes(32, 0x32);
            var sourceHead = Head(0, new byte[32], 0,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray());
            var lkg = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(sourceHead));
            var targetHead = Head(3, Bytes(32, 0xb0), 0,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray());
            var targetBytes = AccountDirectoryAdh1Codec.Encode(targetHead);
            var targetHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(targetHead);
            var intermediateHead = Head(1, lkg.CoreHash.ToArray(), 0,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray());
            var intermediateBytes = AccountDirectoryAdh1Codec.Encode(intermediateHead);
            var intermediateHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(intermediateHead);
            var dtt = Dtt(targetHead, nonce);
            var dttBytes = AccountDirectoryDtt1Codec.Encode(dtt);
            var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);

            var sourceLeaf = CoveredHeadLeaf(lkg.LogGeneration, lkg.TreeSize, lkg.CoreHash.Span);
            var firstTarget = fault is ForwardFault.ExtraCheckpointAfterTarget or ForwardFault.OmittedGenesisCheckpoint
                ? targetHash
                : intermediateHash;
            var first = SignedAdf(
                fault == ForwardFault.OmittedGenesisCheckpoint ? 1UL : 0UL,
                fault == ForwardFault.OmittedGenesisCheckpoint ? Bytes(32, 0xa4) : new byte[32],
                0, 0, 1,
                fault == ForwardFault.WrongSourceMembership ? Bytes(32, 0xa6) : sourceLeaf,
                firstTarget, 0, AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
                AccountDirectorySparseMap.EmptyMapRoot.ToArray(),
                invalidSignature: fault == ForwardFault.InvalidRootSignature);

            var checkpoints = new List<ReadOnlyMemory<byte>> { AccountDirectoryAdf1Codec.Encode(first) };
            if (fault != ForwardFault.OmittedGenesisCheckpoint)
            {
                var second = SignedAdf(
                    1, AccountDirectoryCrypto.ComputeAdf1CoreHash(first), 1, 2, 1, Bytes(32, 0xa7),
                    targetHash, 0, AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
                    AccountDirectorySparseMap.EmptyMapRoot.ToArray());
                checkpoints.Add(AccountDirectoryAdf1Codec.Encode(second));
            }

            var targetHeads = fault == ForwardFault.OmittedGenesisCheckpoint
                ? new ReadOnlyMemory<byte>[] { targetBytes }
                : new ReadOnlyMemory<byte>[]
                {
                    fault == ForwardFault.ExtraCheckpointAfterTarget ? targetBytes : intermediateBytes,
                    targetBytes,
                };
            var afp = new AccountDirectoryAfp1(
                Network, lkg.LogGeneration, lkg.TreeSize, lkg.CoreHash.Span, targetHash,
                [ExactXna1], checkpoints, targetHeads, 0, [], dttHash);
            var afpBytes = AccountDirectoryAfp1Codec.Encode(afp);
            if (fault == ForwardFault.WrongFinalTargetTuple)
            {
                var wrongTarget = MutateField(targetBytes, 6, value => value[^1] ^= 1);
                afpBytes = MutateField(afpBytes, 12, value =>
                {
                    var offset = 0;
                    for (var index = 0; index < targetHeads.Length; index++)
                    {
                        var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(value[offset..]));
                        if (index == targetHeads.Length - 1)
                        {
                            wrongTarget.CopyTo(value[(offset + 4)..]);
                            return;
                        }
                        offset += 4 + length;
                    }
                });
            }
            var adp = Write("ADP1", 0x0201,
            [
                Network, [2], query, targetBytes, U64(lkg.TreeSize), lkg.CoreHash.ToArray(),
                [0], [], new byte[32], U16(0), [], [1], [1], afpBytes, dttHash,
            ]);
            return new ProofFixture(this, targetHead, targetBytes, dtt, dttBytes, adp, nonce, query, lkg, null);
        }

        private AccountDirectoryAdf1 SignedAdf(
            ulong generation,
            byte[] predecessor,
            ulong coveredFirst,
            ulong coveredLast,
            ulong coveredCount,
            byte[] coveredRoot,
            byte[] targetHash,
            ulong targetTreeSize,
            byte[] targetAppendRoot,
            byte[] targetMapRoot,
            bool invalidSignature = false)
        {
            var rootId = Bytes(32, 0x20);
            var placeholder = new[] { new AccountDirectoryAdf1RootReceipt(rootId, Bytes(64, 0xaa)) };
            var unsigned = new AccountDirectoryAdf1(
                Network, generation, predecessor, coveredFirst, coveredLast, coveredCount, coveredRoot,
                Reference("ADH1", targetHash), targetTreeSize, targetAppendRoot, targetMapRoot,
                Verified.AuthorityCoreReference.Span, 1_700_000_150, 1, placeholder);
            var signer = invalidSignature
                ? PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xab)).PrivateKey
                : root.PrivateKey;
            var signature = PublicKeyAuth.SignDetached(
                AccountDirectoryCrypto.ComputeAdf1SigningInput(unsigned), signer);
            return new AccountDirectoryAdf1(
                Network, generation, predecessor, coveredFirst, coveredLast, coveredCount, coveredRoot,
                Reference("ADH1", targetHash), targetTreeSize, targetAppendRoot, targetMapRoot,
                Verified.AuthorityCoreReference.Span, 1_700_000_150, 1,
                [new AccountDirectoryAdf1RootReceipt(rootId, signature)]);
        }

        private static byte[] Dts(byte[] network, KeyPair root)
        {
            var sources = new[]
            {
                new AccountDirectoryDts1Source(Bytes(32, 0x10), Bytes(32, 0x12), 1,
                    "time-a.example", 443, Bytes(32, 0x14), 5),
                new AccountDirectoryDts1Source(Bytes(32, 0x11), Bytes(32, 0x13), 1,
                    "time-b.example", 443, Bytes(32, 0x15), 5),
            };
            var rootId = Bytes(32, 0x20);
            var placeholder = new[] { new AccountDirectoryDts1RootReceipt(rootId, Bytes(64, 0x21)) };
            var unsigned = new AccountDirectoryDts1(
                network, 0, new byte[32], sources, 2, 2, 30, 5,
                1_699_000_000, 1_701_000_000, 1, 0, placeholder);
            var signature = PublicKeyAuth.SignDetached(
                AccountDirectoryCrypto.ComputeDts1SigningInput(unsigned), root.PrivateKey);
            return AccountDirectoryDts1Codec.Encode(new AccountDirectoryDts1(
                network, 0, new byte[32], sources, 2, 2, 30, 5,
                1_699_000_000, 1_701_000_000, 1, 0,
                [new AccountDirectoryDts1RootReceipt(rootId, signature)]));
        }

        private static byte[] Xna(byte[] network, KeyPair root, Witness[] witnesses, byte[] policyHash)
        {
            ReadOnlyMemory<byte>[] fields = new ReadOnlyMemory<byte>[20];
            fields[0] = network; fields[1] = U64(0); fields[2] = new byte[32]; fields[3] = new byte[] { 1 };
            fields[4] = Join(Bytes(32, 0x20), U64(0), root.PublicKey); fields[5] = new byte[] { 1 };
            fields[6] = U64(0); fields[7] = U16(1); fields[8] = new byte[] { 3 };
            fields[9] = Join(witnesses.Select(witness => Join(
                witness.Id, U64(0), witness.Key.PublicKey, witness.FailureDomain)).ToArray());
            fields[10] = new byte[] { 2 }; fields[11] = Reference("DTS1", policyHash); fields[12] = policyHash;
            fields[13] = U32(30); fields[14] = U64(1); fields[15] = U64(1_699_000_000);
            fields[16] = U64(1_699_000_000); fields[17] = U64(1_710_000_000); fields[18] = new byte[] { 1 };
            fields[19] = Join(Bytes(32, 0x20), Bytes(64, 0x22));
            var unsigned = XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
            var signature = PublicKeyAuth.SignDetached(XPointNetworkCrypto.ComputeSigningInput(unsigned), root.PrivateKey);
            fields[19] = Join(Bytes(32, 0x20), signature);
            return XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields);
        }
    }

    private delegate void SpanMutation(Span<byte> value);

    private static byte[] MutateField(byte[] canonical, int tag, SpanMutation mutation)
    {
        var result = canonical.ToArray();
        var offset = 12;
        for (var current = 1; current <= tag; current++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(result.AsSpan(offset + 4, 4)));
            offset += 8;
            if (current == tag) { mutation(result.AsSpan(offset, length)); return result; }
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(tag));
    }

    private static byte[] Write(string magic, ushort suite, IReadOnlyList<byte[]> fields)
    {
        var output = new byte[checked(12 + fields.Sum(static field => 8 + field.Length))];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), suite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(output, offset);
            offset += fields[index].Length;
        }
        return output;
    }

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private static byte[] CoveredHeadLeaf(ulong generation, ulong treeSize, ReadOnlySpan<byte> headHash)
    {
        var input = new byte[49];
        input[0] = 0;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(1), generation);
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(9), treeSize);
        headHash.CopyTo(input.AsSpan(17));
        return SHA256.HashData(input);
    }

    private static byte[] Lp32(byte[] value) => Join(U32(checked((uint)value.Length)), value);
    private static byte[] U16(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    private static byte[] U32(uint value) { var result = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(result, value); return result; }
    private static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] Join(params byte[][] values) { var result = new byte[values.Sum(static value => value.Length)]; var offset = 0; foreach (var value in values) { value.CopyTo(result, offset); offset += value.Length; } return result; }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
