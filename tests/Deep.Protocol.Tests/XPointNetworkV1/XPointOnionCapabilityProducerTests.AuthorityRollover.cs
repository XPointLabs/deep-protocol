using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class XPointOnionCapabilityProducerTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task AuthorityRollover_ExactWarmAndColdHistoryRetainOriginalPmtUnderItsOwnSignatureKeys(bool cold)
    {
        var fixture = Fixture.Create();
        var original = await fixture.VerifyDid2Async();
        var history = OnionNetworkProtectedHistoryCodec.Encode(original);
        var package = fixture.BuildAuthorityRollover();
        var current = await package.VerifyAsync(original, cold, history);
        Assert.Equal(1UL, package.Authority.AuthorityGeneration);
        Assert.Equal(1UL, current.ProtectedLkg!.ViewGeneration);
        Assert.Equal(package.Authority.AuthorityCoreReference.ToArray(), current.ProtectedLkg.AuthorityCoreReference.ToArray());
        Assert.Equal(original.ProtectedLkg!.AuthorityCoreReference.ToArray(), current.PriorProtectedLkg!.AuthorityCoreReference.ToArray());
        Assert.Equal(original.ProtectedLkg.HeadCoreReference.ToArray(), current.PriorProtectedLkg.HeadCoreReference.ToArray());
        Assert.Equal(original.ProtectedLkg.ViewCoreReference.ToArray(), current.PriorProtectedLkg.ViewCoreReference.ToArray());
        Assert.Equal(original.ProtectedLkg.HeadRoot.ToArray(), current.PriorProtectedLkg.HeadRoot.ToArray());
        Assert.Equal(original.Closure!.SelectionEpoch + 1, current.Closure!.SelectionEpoch);
        Assert.Equal(2, current.Closure.RetainedPmts.Length);
        Assert.Equal(original.Closure.Pmt.CanonicalBytes.ToArray(), current.Closure.RetainedPmts[0].CanonicalBytes.ToArray());
        Assert.False(original.ProtectedLkg.AuthorityCoreReference.Span.SequenceEqual(current.ProtectedLkg.AuthorityCoreReference.Span));
        // Only the cold verifier mints an exact stored-capsule binding. Warm
        // verification carries the actual prior capability/floor instead.
        Assert.Equal(cold, OnionNetworkProtectedHistoryCodec.BindsPredecessor(current, history));
    }

    [Theory]
    [InlineData("old-policy-rekey", false)] [InlineData("old-policy-rekey", true)]
    [InlineData("old-view-rekey", false)] [InlineData("old-view-rekey", true)]
    [InlineData("old-head-rekey", false)] [InlineData("old-head-rekey", true)]
    [InlineData("old-pmt-rekey", false)] [InlineData("old-pmt-rekey", true)]
    [InlineData("current-pmt-old-keys", false)] [InlineData("current-pmt-old-keys", true)]
    [InlineData("selection-rollback", false)] [InlineData("selection-rollback", true)]
    [InlineData("stale-terminal", false)] [InlineData("stale-terminal", true)]
    public async Task AuthorityRollover_HistoryCannotBorrowCurrentKeysOrResetSelectionEpoch(string fault, bool cold)
    {
        var fixture = Fixture.Create();
        var original = await fixture.VerifyDid2Async();
        var package = fixture.BuildAuthorityRollover(fault);
        await Assert.ThrowsAsync<OnionBoundaryException>(() => package.VerifyAsync(original, cold,
            OnionNetworkProtectedHistoryCodec.Encode(original)).AsTask());
    }

    [Fact]
    public async Task AuthorityRollover_ColdCapsuleCannotSubstituteCurrentAuthorityForOriginalHead()
    {
        var fixture = Fixture.Create();
        var original = await fixture.VerifyDid2Async();
        var package = fixture.BuildAuthorityRollover();
        var history = OnionNetworkProtectedHistoryCodec.Encode(original);
        // The existing protected framing puts the LKG authority reference at
        // header16 + body140. All actual old policy/view/head records stay old.
        package.Authority.AuthorityCoreReference.Span.CopyTo(history.AsSpan(16 + 140, 38));
        await Assert.ThrowsAsync<OnionBoundaryException>(() => package.VerifyAsync(original, true, history).AsTask());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task AuthorityRollover_SignedPolicyCannotReturnToAncestorBeforeTerminalValidation(bool cold)
    {
        var fixture = Fixture.Create();
        var original = await fixture.VerifyDid2Async();
        var package = fixture.BuildAuthorityRollover("policy-authority-rollback");
        var error = await Assert.ThrowsAsync<OnionBoundaryException>(() => package.VerifyAsync(original, cold,
            OnionNetworkProtectedHistoryCodec.Encode(original)).AsTask());
        Assert.Equal("network-authority-rollback", error.Code);
    }

    internal sealed partial class Fixture
    {
        internal AuthorityRolloverPackage BuildAuthorityRollover(string? fault = null)
        {
            var network = Bytes(16, _networkMarker);
            var nextRoot = new SigningKey(Bytes(32, 0x24), PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x25)), Bytes(32, 0x26));
            var nextWitnesses = Enumerable.Range(0, 3).Select(index => new SigningKey(Bytes(32, checked((byte)(0x44 + index))),
                PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0x54 + index)))), Bytes(32, checked((byte)(0x64 + index))))).ToArray();
            try
            {
                var priorDts = AccountDirectoryDts1Codec.Decode(_dts);
                AccountDirectoryDts1 Policy(IReadOnlyList<AccountDirectoryDts1RootReceipt> receipts) => new(network, 1,
                    AccountDirectoryCrypto.ComputeDts1PolicyHash(priorDts), priorDts.Sources, 2, 2, 30, 5, 100, 900, 1, 1, receipts);
                var unsignedDts = Policy([new(nextRoot.Id, Bytes(64, 1))]);
                var dts = AccountDirectoryDts1Codec.Encode(Policy([new(nextRoot.Id,
                    PublicKeyAuth.SignDetached(AccountDirectoryCrypto.ComputeDts1SigningInput(unsignedDts), nextRoot.Pair.PrivateKey))]));
                var dtsHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(AccountDirectoryDts1Codec.Decode(dts));
                var priorXna = XPointNetworkCodec.Parse<Xna1Record>(_xna);
                var rootFields = Enumerable.Range(1, 20).Select(tag => (ReadOnlyMemory<byte>)priorXna.FieldSpan(tag).ToArray()).ToArray();
                rootFields[1] = U64(1); rootFields[2] = priorXna.CoreHash.ToArray(); rootFields[4] = RootRows([nextRoot]);
                rootFields[6] = U64(1); rootFields[9] = WitnessRows(nextWitnesses);
                rootFields[11] = XPointNetworkCodec.EncodeCoreReference("DTS1", dtsHash); rootFields[12] = dtsHash;
                var nextXna = SignXPoint(XPointNetworkRegistry.Xna1, rootFields, 19, [(_root.Id, _root.Pair.PrivateKey)]);
                var authority = XPointNetworkAuthorityVerifier.Verify(new(network, priorXna.CoreHash.Span), [_xna, nextXna], [_dts, dts]);
                var oldPolicy = XPointNetworkCodec.Parse<Xvp1Record>(_xvp);
                var oldView = XPointNetworkCodec.Parse<Xnv1Record>(_xnv);
                var oldHead = XPointNetworkCodec.Parse<Xnh1Record>(_xnh);
                var oldPmt = ContactCodec.Decode("PMT2", _pmt);
                var policy = BuildXvp(network, authority, nextRoot, 1, oldPolicy.CoreHash.ToArray());
                var view = BuildXnv(network, authority, XPointNetworkCodec.Parse<Xvp1Record>(policy), _nodes,
                    nextWitnesses, 0x71, 2, 1, oldView.CoreHash.ToArray());
                var head = BuildXnh(network, authority, XPointNetworkCodec.Parse<Xnv1Record>(view), nextWitnesses, oldHead);
                var freshness = BuildFreshness(network, authority, XPointNetworkCodec.Parse<Xnv1Record>(view), nextWitnesses);
                var pmt = BuildPmt(network, XPointNetworkCodec.Parse<Xnv1Record>(view), freshness, _nodes,
                    fault == "current-pmt-old-keys" ? _witnesses : nextWitnesses,
                    fault == "selection-rollback" ? _selectionEpoch - 1 : _selectionEpoch + 1, 1, oldPmt.CoreHash.ToArray());
                var prefixPolicy = _xvp.ToArray(); var prefixView = _xnv.ToArray();
                var prefixHead = _xnh.ToArray(); var prefixPmt = _pmt.ToArray();
                if (fault == "old-policy-rekey") prefixPolicy = ResignXPoint(oldPolicy, nextRoot);
                if (fault == "old-view-rekey") prefixView = ResignXPoint(oldView, nextWitnesses[..2]);
                if (fault == "old-head-rekey") prefixHead = ResignXPoint(oldHead, nextWitnesses[..2]);
                if (fault == "old-pmt-rekey")
                {
                    var fields = Enumerable.Range(1, 16).Select(tag => oldPmt.Field(tag)).ToArray();
                    fields[15] = SignatureRows(nextWitnesses.Take(2).Select(key =>
                        (key.Id, PublicKeyAuth.SignDetached(oldPmt.SignatureInput.ToArray(), key.Pair.PrivateKey))).ToArray());
                    prefixPmt = ContactCodec.AuthorForValidation("PMT2", fields).CanonicalBytes.ToArray();
                }
                byte[][] policies = [prefixPolicy, policy];
                if (fault == "policy-authority-rollback")
                    policies = [.. policies, BuildXvp(network, _authority, _root, 2,
                        XPointNetworkCodec.Parse<Xvp1Record>(policy).CoreHash.ToArray())];
                return new(authority, fault == "stale-terminal" ? _freshness : freshness,
                    policies, [prefixView, view], [prefixHead, head], _nodes,
                    [prefixPmt, pmt], fault == "stale-terminal");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nextRoot.Pair.PrivateKey);
                foreach (var key in nextWitnesses) CryptographicOperations.ZeroMemory(key.Pair.PrivateKey);
            }
        }

        private static byte[] ResignXPoint(XPointParsedRecord record, params SigningKey[] keys)
        {
            var fields = Enumerable.Range(1, record.Definition.Fields.Count).Select(tag => (ReadOnlyMemory<byte>)record.FieldSpan(tag).ToArray()).ToArray();
            return SignXPoint(record.Definition, fields, fields.Length - 1, keys.Select(key => (key.Id, key.Pair.PrivateKey)).ToArray());
        }
    }

    internal sealed record AuthorityRolloverPackage(VerifiedXPointNetworkAuthority Authority,
        VerifiedDeepIdV2DirectoryFreshness Freshness, byte[][] Policies, byte[][] Views, byte[][] Heads,
        byte[][] Nodes, byte[][] Pmts, bool StaleTerminal)
    {
        internal async ValueTask<VerifiedOnionNetworkContext> VerifyAsync(VerifiedOnionNetworkContext original, bool cold, byte[] history)
        {
            ReadOnlyMemory<byte>[] Records(byte[][] values) =>
                (StaleTerminal ? values[..1] : values).Select(value => (ReadOnlyMemory<byte>)value).ToArray();
            // Include the exact prefix even in the warm negative probes so
            // old-signature defects cannot hide behind an omitted old record.
            if (cold) return await OnionNetworkContextVerifier.VerifyFromProtectedHistoryAsync(Authority, Freshness,
                Records(Policies), Records(Views), Records(Heads), Nodes.Select(value => (ReadOnlyMemory<byte>)value).ToArray(),
                Records(Pmts), history, new(new FixedClock(Bytes(16, 0xc1), 1_000)), default);
            _ = await OnionNetworkContextVerifier.VerifyAsync(Authority, Freshness, Records(Policies), Records(Views), Records(Heads),
                Nodes.Select(value => (ReadOnlyMemory<byte>)value).ToArray(), Records(Pmts), null,
                new(new FixedClock(Bytes(16, 0xc1), 1_000)), default);
            return await OnionNetworkContextVerifier.VerifyAsync(Authority, Freshness, [Policies[^1]], [Views[^1]], [Heads[^1]],
                Nodes.Select(value => (ReadOnlyMemory<byte>)value).ToArray(), [Pmts[^1]], original,
                new(new FixedClock(Bytes(16, 0xc1), 1_000)), default);
        }
    }
}
