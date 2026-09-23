using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.Tests.Identity;
using System.Runtime.InteropServices;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed partial class AccountDirectoryFreshnessVerificationTests
{
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
        if (!OperatingSystem.IsWindows() ||
            RuntimeInformation.ProcessArchitecture is not
                (Architecture.X64 or Architecture.Arm64))
            return;

        var (admission, checkpoint, binding) = await
            Dnp1IdentityAuthoringV1Tests.CreateRealDid2DirectoryGenesisAsync();
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

        var verified = DeepIdV2DirectoryCurrentProofVerifier.VerifyGenesis(
            authority.Verified, package.ExactAdh1, package.ExactDtt1,
            package.ExactAdp1V2, nonce, query,
            Window(), initialLkg, 1, 2, pq);

        Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue,
            verified.ResultKind);
        Assert.Equal(checkpoint.Checkpoint.ArtifactHash.ToArray(),
            verified.CurrentCheckpoint!.Checkpoint.ArtifactHash.ToArray());
        Assert.Equal(exactHead, verified.NextProtectedLkg.ExactAdh1.ToArray());
        Assert.Equal(admission.ExactDab2.ToArray(),
            DeepIdV2Adp1Codec.Decode(package.ExactAdp1V2.Span).ExactDab2.ToArray());

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
}
