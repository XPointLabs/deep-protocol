using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed partial class AccountDirectoryFreshnessVerificationTests
{
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
            DeepIdV2DirectoryCurrentProofVerifier.VerifyGenesis(
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
