using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class XPointOnionCapabilityProducerTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task OperationalRollover_OfflineThenDelegatedAppendPreservesMixedAuthorityPrefix(bool cold) =>
        await Fixture.Create().CheckOperationalRolloverAsync(cold);

    [Theory]
    [InlineData("old-pma-rekey")] [InlineData("old-policy-rekey")]
    [InlineData("old-view-rekey")] [InlineData("old-head-rekey")]
    [InlineData("old-pmt-rekey")] [InlineData("protected-head")]
    [InlineData("protected-pmt")] [InlineData("old-root-signer")]
    [InlineData("old-witness-signers")] [InlineData("delegated-cross-root")]
    [InlineData("missing-prefix")] [InlineData("forked-prefix")]
    public async Task OperationalRollover_HostilePredecessorOrSignerRejectsBeforeSigning(string fault) =>
        await Fixture.Create().CheckOperationalRolloverAsync(false, fault);

    [Fact]
    public void OperationalRollover_RequestRequiresVerifiedCurrentAuthorityWithoutBootstrapOverload()
    {
        var request = typeof(XPointNetworkOperationalSuccessorRequest);
        var constructor = Assert.Single(request.GetConstructors());
        Assert.Equal(typeof(VerifiedXPointNetworkAuthority), constructor.GetParameters()[1].ParameterType);
        Assert.Equal(typeof(VerifiedXPointNetworkAuthority), request.GetProperty("Authority")!.PropertyType);
        Assert.Null(request.GetProperty("Bootstrap"));
    }

    [Fact]
    public async Task OperationalRollover_SameKeyRenewalProducerPreservesPinnedGenesisAndAllKeyFloors() =>
        await Fixture.Create().CheckSameKeyRenewalAsync();

    [Theory]
    [InlineData("short-root")] [InlineData("root-gap")] [InlineData("dts-gap")]
    [InlineData("oversized-dts")] [InlineData("invalid-predecessor-signature")]
    [InlineData("unknown-signer")] [InlineData("empty-roots")]
    [InlineData("duplicate-root")] [InlineData("canceled")]
    public async Task OperationalRollover_SameKeyRenewalRejectsHostileInputsBeforeSigning(string fault) =>
        await Fixture.Create().CheckSameKeyRenewalAsync(fault);

    internal sealed partial class Fixture
    {
        internal async Task CheckSameKeyRenewalAsync(string? fault = null)
        {
            using var root = new OperationalTestSigner(_root);
            using var unknown = OperationalTestSigner.Create(0x24, 0x25, 0x26);
            var dts = _dts.ToArray();
            if (fault == "invalid-predecessor-signature") dts[^1] ^= 1;
            var rootFrom = fault == "root-gap" ? 1_001UL : 850UL;
            var rootUntil = fault == "short-root" ? 999UL : fault == "oversized-dts" ? 3_100_000UL : 1_500UL;
            var dtsFrom = fault == "dts-gap" ? 900UL : rootFrom;
            var dtsUntil = fault == "oversized-dts" ? dtsFrom + 2_592_001UL : 1_400UL;
            var signers = fault == "unknown-signer" ? new[] { unknown } : fault == "empty-roots" ? [] : fault == "duplicate-root" ? [root, root] : new[] { root };
            using var cancellation = new CancellationTokenSource();
            if (fault == "canceled") cancellation.Cancel();
            async Task<AuthoredXPointNetworkAuthorityRenewal> Renew() => await XPointNetworkBootstrapAuthor.AuthorSameKeyRenewalAsync(
                Bytes(32, 0x19), _authority, [dts], rootFrom, rootFrom, rootUntil, dtsFrom, dtsUntil, signers, cancellation.Token);
            if (fault is not null)
            {
                var error = await Record.ExceptionAsync(Renew);
                Assert.NotNull(error);
                Assert.True(error is ArgumentException or CryptographicException or XPointNetworkAuthorityVerificationException or OperationCanceledException, error.ToString());
                Assert.Equal(0, root.Calls + unknown.Calls); return;
            }
            var first = await Renew();
            var pin = new XPointNetworkGenesisPin(_authority.NetworkId.Span, _authority.AuthorityCoreHash.Span);
            var firstAuthority = XPointNetworkAuthorityVerifier.Verify(pin, [_xna, first.ExactXna1], [_dts, first.ExactDts1]);
            var second = await XPointNetworkBootstrapAuthor.AuthorSameKeyRenewalAsync(Bytes(32, 0x1a), firstAuthority,
                [_dts, first.ExactDts1], 1_350, 1_350, 2_100, 1_350, 2_000, [root]);
            var current = XPointNetworkAuthorityVerifier.Verify(pin, [_xna, first.ExactXna1, second.ExactXna1], [_dts, first.ExactDts1, second.ExactDts1]);
            Assert.Equal(4, root.Calls); Assert.Equal(2UL, current.AuthorityGeneration); Assert.Equal(2UL, current.Dts1PolicyGeneration);
            Assert.Equal(_authority.DirectoryWitnessPolicyGeneration, current.DirectoryWitnessPolicyGeneration);
            Assert.Equal(_authority.MinimumClientGeneration, current.MinimumClientGeneration);
            Assert.Equal(_authority.RootThreshold, current.RootThreshold); Assert.Equal(_authority.WitnessThreshold, current.WitnessThreshold);
            Assert.Equal(_authority.RootKeys.Select(k => k.Ed25519PublicKey.ToArray()), current.RootKeys.Select(k => k.Ed25519PublicKey.ToArray()));
            Assert.Equal(_authority.WitnessKeys.Select(k => k.Ed25519PublicKey.ToArray()), current.WitnessKeys.Select(k => k.Ed25519PublicKey.ToArray()));
            Assert.False(_authority.DirectoryWitnessPolicyHash.Span.SequenceEqual(firstAuthority.DirectoryWitnessPolicyHash.Span));
            Assert.False(firstAuthority.DirectoryWitnessPolicyHash.Span.SequenceEqual(current.DirectoryWitnessPolicyHash.Span));
            Assert.Equal(_authority.AuthorityCoreHash.ToArray(), pin.AuthorityCoreHash.ToArray());
            Assert.Equal(_authority.RootKeys.Select(k => k.Id.ToArray()), current.RootKeys.Select(k => k.Id.ToArray()));
        }

        internal async Task CheckOperationalRolloverAsync(bool cold, string? fault = null)
        {
            var original = await VerifyMailboxAsync();
            var renewed = BuildAuthorityRollover();
            using var root = OperationalTestSigner.Create(0x24, 0x25, 0x26);
            var witnesses = Enumerable.Range(0, 3).Select(index => OperationalTestSigner.Create(
                checked((byte)(0x44 + index)), checked((byte)(0x54 + index)), checked((byte)(0x64 + index)))).ToArray();
            var identities = Enumerable.Range(0, 3).Select(index => OperationalTestSigner.Create(
                checked((byte)(0x10 + index)), checked((byte)(0x90 + index * 8)), 0x7d)).ToArray();
            using var oldRoot = new OperationalTestSigner(_root);
            var oldWitnesses = _witnesses.Select(key => new OperationalTestSigner(key)).ToArray();
            try
            {
                var pma = original.Pma.ToArray();
                var pmt = original.Network.Closure!.Pmt.CanonicalBytes.ToArray();
                var policy = _xvp.ToArray(); var view = _xnv.ToArray(); var head = _xnh.ToArray();
                if (fault == "old-policy-rekey") policy = ResignXPoint(XPointNetworkCodec.Parse<Xvp1Record>(policy), root.Key);
                if (fault == "old-view-rekey") view = ResignXPoint(XPointNetworkCodec.Parse<Xnv1Record>(view), witnesses.Take(2).Select(s => s.Key).ToArray());
                if (fault == "old-head-rekey") head = ResignXPoint(XPointNetworkCodec.Parse<Xnh1Record>(head), witnesses.Take(2).Select(s => s.Key).ToArray());
                if (fault == "old-pma-rekey") pma = ResignContact(ContactCodec.Decode("PMA2", pma), [root.Key]);
                if (fault == "old-pmt-rekey") pmt = ResignContact(ContactCodec.Decode("PMT2", pmt), witnesses.Select(s => s.Key).ToArray());
                var headHash = XPointNetworkCodec.Parse<Xnh1Record>(_xnh).CoreHash.ToArray();
                var pmtHash = original.Network.Closure.Pmt.ArtifactHash.ToArray();
                if (fault == "protected-head") headHash[0] ^= 1;
                if (fault == "protected-pmt") pmtHash[0] ^= 1;
                var prefix = fault == "missing-prefix" ? Array.Empty<ReadOnlyMemory<byte>>() : new ReadOnlyMemory<byte>[] { view };
                if (fault == "forked-prefix") prefix = [XPointNetworkTestRecords.MutateField(view, 6, bytes => bytes[0] ^= 1)];
                XPointNetworkOperationalSuccessorRequest Request() => new(Bytes(32, 0x13), renewed.Authority,
                    fault == "delegated-cross-root" ? [] : new IXPointNetworkBootstrapRootSigner[] { fault == "old-root-signer" ? oldRoot : root },
                    fault == "old-witness-signers" ? oldWitnesses : witnesses,
                    NewRollovers(identities, _nodes, delegated: false), policy,
                    _nodes.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(), prefix,
                    head, pma, pmt, headHash, pmtHash, ContactCodec.Decode("PMT2", _pmt).Field(14).ToArray(), 180, 185, 280);
                if (fault is not null)
                {
                    var rejected = await Record.ExceptionAsync(async () =>
                    {
                        if (fault == "delegated-cross-root") await XPointNetworkOperationalSuccessorAuthor.AuthorDelegatedAsync(Request());
                        else await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(Request());
                    });
                    Assert.NotNull(rejected);
                    Assert.True(fault == "missing-prefix" ? rejected is ArgumentException
                        : rejected is CryptographicException or OnionBoundaryException, rejected.ToString());
                    Assert.Equal(0, root.Calls + oldRoot.Calls + witnesses.Concat(oldWitnesses).Concat(identities).Sum(s => s.Calls));
                    Assert.Equal(original.Network.Closure.Pmt.CanonicalBytes.ToArray(), original.Network.Closure.RetainedPmts[0].CanonicalBytes.ToArray());
                    return;
                }
                // Historical authentication does not mint an old current policy.
                MailboxAuthorityV2Verifier.VerifyHistoricalLineage(renewed.Authority, original.Pma, 100, 101);
                Assert.Throws<CryptographicException>(() => MailboxAuthorityV2Verifier.Verify(renewed.Authority, original.Pma, 200, 201));
                var first = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(Request());
                var delegated = await XPointNetworkOperationalSuccessorAuthor.AuthorDelegatedAsync(new(
                    Bytes(32, 0x14), renewed.Authority, [], witnesses, NewRollovers(identities, first.ExactXnd1.Select(b => b.ToArray()).ToArray(), true),
                    first.ExactXvp1, first.ExactXnd1, [_xnv, first.ExactXnv1], first.ExactXnh1,
                    first.ExactPma2, first.ExactPmt2,
                    XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(first.ExactXnh1.Span),
                    ContactCodec.Decode("PMT2", first.ExactPmt2.Span).ArtifactHash.Span,
                    ContactCodec.Decode("PMT2", first.ExactPmt2.Span).Field(14).ToArray(), 190, 190, 270));
                Assert.Equal(first.ExactXvp1.ToArray(), delegated.ExactXvp1.ToArray());
                Assert.Equal(first.ExactPma2.ToArray(), delegated.ExactPma2.ToArray());
                var currentPma = MailboxAuthorityV2Verifier.Verify(renewed.Authority, delegated.ExactPma2.Span, 195, 205);
                Assert.True(currentPma.BindsProjection(delegated.ExactPmt2.Span));
                Assert.Equal(renewed.Authority.AuthorityCoreReference.ToArray(), ContactCodec.Decode("PMA2", first.ExactPma2.Span).Field(13).ToArray());
                var latest = XPointNetworkCodec.Parse<Xnv1Record>(delegated.ExactXnv1.Span);
                var time = BuildFreshness(renewed.Authority.NetworkId.ToArray(), renewed.Authority, latest, witnesses.Select(s => s.Key).ToArray());
                ReadOnlyMemory<byte>[] policies = [_xvp, first.ExactXvp1];
                ReadOnlyMemory<byte>[] views = [_xnv, first.ExactXnv1, delegated.ExactXnv1];
                ReadOnlyMemory<byte>[] heads = [_xnh, first.ExactXnh1, delegated.ExactXnh1];
                ReadOnlyMemory<byte>[] projections = [original.Network.Closure.Pmt.CanonicalBytes, first.ExactPmt2, delegated.ExactPmt2];
                var clock = new OnionTrustedTimeAuthority(new FixedClock(Bytes(16, 0xc1), 1_000));
                var current = cold
                    ? await OnionNetworkContextVerifier.VerifyFromProtectedHistoryAsync(renewed.Authority, time, policies, views, heads,
                        delegated.ExactXnd1, projections, OnionNetworkProtectedHistoryCodec.Encode(original.Network), clock, default)
                    : await OnionNetworkContextVerifier.VerifyAsync(renewed.Authority, time, policies[1..], views[1..], heads[1..],
                        delegated.ExactXnd1, projections[1..], original.Network, clock, default);
                Assert.Equal(2UL, current.ProtectedLkg!.ViewGeneration);
                Assert.Equal(3UL, current.ProtectedLkg.HeadTreeSize);
                Assert.Equal(_selectionEpoch, current.Closure!.SelectionEpoch);
                Assert.Equal(3, current.Closure.RetainedPmts.Length);
                Assert.Equal(original.Network.Closure.Pmt.CanonicalBytes.ToArray(), current.Closure.RetainedPmts[0].CanonicalBytes.ToArray());
                Assert.Equal(original.Network.ProtectedLkg!.HeadRoot.ToArray(), current.PriorProtectedLkg!.HeadRoot.ToArray());
                var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(current, renewed.Authority, delegated.ExactPma2, clock);
                await host.RequireOriginalNamespaceAsync(original.Pma, original.Network.Closure.Pmt.CanonicalBytes);
                Assert.Equal(_selectionEpoch, host.SelectionEpoch); // Metadata does not establish exclusion.
                await Assert.ThrowsAsync<CryptographicException>(() => host.RequireOriginalNamespaceAsync(
                    delegated.ExactPma2, original.Network.Closure.Pmt.CanonicalBytes).AsTask());
                var badOriginalPolicy = original.Pma.ToArray(); badOriginalPolicy[^1] ^= 1;
                await Assert.ThrowsAsync<CryptographicException>(() => host.RequireOriginalNamespaceAsync(
                    badOriginalPolicy, original.Network.Closure.Pmt.CanonicalBytes).AsTask());
                var rekeyedProjection = ResignContact(original.Network.Closure.Pmt, witnesses.Select(s => s.Key).ToArray());
                await Assert.ThrowsAsync<CryptographicException>(() => host.RequireOriginalNamespaceAsync(original.Pma, rekeyedProjection).AsTask());
            }
            finally { foreach (var signer in witnesses.Concat(oldWitnesses).Concat(identities)) signer.Dispose(); }
        }

        private static XPointNetworkOperationalNodeRollover[] NewRollovers(OperationalTestSigner[] identities, byte[][] nodes, bool delegated) =>
            nodes.Select((bytes, index) =>
            {
                var previous = XPointNetworkCodec.Parse<Xnd1Record>(bytes);
                return new XPointNetworkOperationalNodeRollover(identities[index],
                    delegated ? previous.Origins[0].NextSpki.Span : Bytes(32, checked((byte)(0xc0 + index))),
                    Bytes(32, checked((byte)((delegated ? 0xd8 : 0xc8) + index))),
                    delegated ? previous.FieldSpan(26) : ScalarMult.Base(Bytes(32, checked((byte)(0xd0 + index)))),
                    ScalarMult.Base(Bytes(32, checked((byte)((delegated ? 0xe8 : 0xe0) + index)))));
            }).ToArray();

        private static byte[] ResignContact(ContactRecord record, SigningKey[] signers)
        {
            var fields = Enumerable.Range(1, 16).Select(tag => record.Field(tag)).ToArray();
            fields[14] = new[] { checked((byte)signers.Length) };
            fields[15] = SignatureRows(signers.Select(s => (s.Id, Bytes(64, 1))).ToArray());
            var unsigned = ContactCodec.AuthorForOperationalAuthority(record.Magic, fields);
            fields[15] = SignatureRows(signers.Select(s => (s.Id, PublicKeyAuth.SignDetached(unsigned.SignatureInput.ToArray(), s.Pair.PrivateKey))).ToArray());
            return ContactCodec.AuthorForOperationalAuthority(record.Magic, fields).CanonicalBytes.ToArray();
        }
    }

    private sealed class OperationalTestSigner : IDisposable, IXPointNetworkBootstrapRootSigner, IXPointNetworkWitnessSigner
    {
        internal OperationalTestSigner(SigningKey key) => Key = new(key.Id.ToArray(),
            new KeyPair(key.Pair.PublicKey.ToArray(), key.Pair.PrivateKey.ToArray()), key.FailureDomain.ToArray());
        internal static OperationalTestSigner Create(byte id, byte seed, byte domain)
        {
            var pair = PublicKeyAuth.GenerateKeyPair(Bytes(32, seed));
            try { return new(new SigningKey(Bytes(32, id), pair, Bytes(32, domain))); }
            finally { CryptographicOperations.ZeroMemory(pair.PrivateKey); }
        }
        internal SigningKey Key { get; }
        internal int Calls { get; private set; }
        public ReadOnlyMemory<byte> RootKeyId => Key.Id;
        public ReadOnlyMemory<byte> SignerId => Key.Id;
        public ReadOnlyMemory<byte> WitnessId => Key.Id;
        public ulong KeyGeneration => 0;
        public ReadOnlyMemory<byte> Ed25519PublicKey => Key.Pair.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Key.FailureDomain;
        public ReadOnlyMemory<byte> FailureDomainHash => Key.FailureDomain;
        public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request, Memory<byte> destination, CancellationToken ct) => Sign(request.SigningInput, destination, ct);
        public ValueTask<int> SignAsync(XPointNetworkOperationalSigningRequest request, Memory<byte> destination, CancellationToken ct) => Sign(request.SigningInput, destination, ct);
        private ValueTask<int> Sign(ReadOnlyMemory<byte> input, Memory<byte> destination, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); Calls++; PublicKeyAuth.SignDetached(input.ToArray(), Key.Pair.PrivateKey).CopyTo(destination); return ValueTask.FromResult(64); }
        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(ReadOnlyMemory<byte> input, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); Calls++; return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(input.ToArray(), Key.Pair.PrivateKey)); }
        public void Dispose() => CryptographicOperations.ZeroMemory(Key.Pair.PrivateKey);
    }
}
