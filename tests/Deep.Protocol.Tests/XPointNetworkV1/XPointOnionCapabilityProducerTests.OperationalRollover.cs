using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
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
    [InlineData("policy-under-operational")] [InlineData("policy-over-authority")]
    [InlineData("delegated-policy-extension")]
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
    [InlineData("short-root")] [InlineData("root-time-rollback")] [InlineData("dts-before-root")]
    [InlineData("oversized-dts")] [InlineData("invalid-predecessor-signature")]
    [InlineData("unknown-signer")] [InlineData("empty-roots")]
    [InlineData("duplicate-root")] [InlineData("canceled")]
    public async Task OperationalRollover_SameKeyRenewalRejectsHostileInputsBeforeSigning(string fault) =>
        await Fixture.Create().CheckSameKeyRenewalAsync(fault);

    [Theory]
    [InlineData(1_000UL)] [InlineData(1_001UL)] [InlineData(10_001UL)]
    public async Task OperationalRollover_OfflineRootContinuityAcrossExpiryDoesNotReviveOldPolicy(ulong issuedAt) =>
        await Fixture.Create().CheckSameKeyRenewalAsync(renewalFrom: issuedAt);

    [Fact]
    public async Task OperationalRollover_OfflinePolicyDelegatesBeyondInitialOperationalView() =>
        await Fixture.Create().CheckOperationalRolloverAsync(true, extendRootPolicy: true);

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task OperationalRollover_OfflineMailboxKeysPreserveNamespaceAndDelegatedPolicy(bool cold) =>
        await Fixture.Create().CheckOperationalRolloverAsync(cold, rotateMailbox: true);

    [Theory]
    [InlineData("mailbox-old-deposit")] [InlineData("mailbox-old-retrieve")]
    [InlineData("mailbox-cross-old")] [InlineData("mailbox-floor")]
    [InlineData("mailbox-root-key")] [InlineData("mailbox-witness-key")]
    [InlineData("mailbox-node-key")] [InlineData("mailbox-delegated")]
    public async Task OperationalRollover_InvalidMailboxRolloverRejectsBeforeSigning(string fault) =>
        await Fixture.Create().CheckOperationalRolloverAsync(false, fault, rotateMailbox: true);

    [Fact]
    public void OperationalRollover_MailboxInputIsBoundedCopiedAndRoleSeparated()
    {
        var deposit = Bytes(32, 0x31); var retrieve = Bytes(32, 0x32);
        var input = new XPointNetworkMailboxIssuerRollover(deposit, retrieve, 2);
        deposit[0] ^= 1; retrieve[0] ^= 1;
        Assert.Equal(Bytes(32, 0x31), input.DepositIssuerPublicKey.ToArray());
        Assert.Equal(Bytes(32, 0x32), input.RetrieveIssuerPublicKey.ToArray());
        var copy = input.DepositIssuerPublicKey.ToArray(); copy[0] ^= 1;
        Assert.Equal(Bytes(32, 0x31), input.DepositIssuerPublicKey.ToArray());
        Assert.Throws<ArgumentException>(() => new XPointNetworkMailboxIssuerRollover(new byte[32], retrieve, 2));
        Assert.Throws<ArgumentException>(() => new XPointNetworkMailboxIssuerRollover(deposit, new byte[31], 2));
        Assert.Throws<ArgumentException>(() => new XPointNetworkMailboxIssuerRollover(deposit, deposit, 2));
        Assert.Throws<ArgumentException>(() => new XPointNetworkMailboxIssuerRollover(deposit, retrieve, 0));
    }

    [Fact]
    public async Task OperationalRollover_ExistingPmaLifetimeBoundRejectsBeforeAnySignerCallback() =>
        await Fixture.Create().CheckPmaLifetimeBoundAsync();

    [Theory]
    [InlineData(false, false, false)] [InlineData(true, false, false)]
    [InlineData(false, true, false)] [InlineData(true, true, false)]
    [InlineData(false, false, true)] [InlineData(true, false, true)]
    [InlineData(false, true, true)] [InlineData(true, true, true)]
    public async Task OperationalRollover_OriginRelocationPreservesSignedLineageAndColdNamespace(bool cold, bool delegated, bool ipv6) =>
        await Fixture.Create().CheckOperationalRolloverAsync(cold, relocateOrigins: true, delegatedRelocation: delegated, ipv6Origins: ipv6);

    [Theory]
    [InlineData("unknown-origin")] [InlineData("colliding-origin")]
    public async Task OperationalRollover_HostileOriginRelocationRejectsBeforeAllSigners(string fault) =>
        await Fixture.Create().CheckOperationalRolloverAsync(false, fault);

    [Fact]
    public async Task OperationalRollover_OriginCallerArraysChangedByRootCallbackCannotChangeSignedEndpoints() =>
        await Fixture.Create().CheckOperationalRolloverAsync(true, relocateOrigins: true, mutateOriginCollections: true);

    [Theory]
    [InlineData(-1, false)] [InlineData(17, false)] [InlineData(1, true)]
    public void OperationalRollover_HostileOriginCollectionIsBoundedBeforeEnumeration(int count, bool changeCount)
    {
        using var signer = OperationalTestSigner.Create(0x11, 0x12, 0x13);
        var intent = new XPointNetworkOperationalOriginRelocation(Bytes(32, 0x33), IPAddress.Loopback, 443);
        var list = new HostileOriginList(intent, count, changeCount);
        Assert.Throws<ArgumentException>(() => new XPointNetworkOperationalNodeRollover(signer,
            Bytes(32, 0x31), Bytes(32, 0x32), Bytes(32, 0x41), Bytes(32, 0x42), list));
        Assert.Equal(changeCount ? 1 : 0, list.IndexReads);
        Assert.Equal(0, signer.Calls);
    }

    private sealed class HostileOriginList(XPointNetworkOperationalOriginRelocation value, int count, bool changeCount)
        : IReadOnlyList<XPointNetworkOperationalOriginRelocation>
    {
        internal int IndexReads;
        public int Count => count + (changeCount && IndexReads != 0 ? 1 : 0);
        public XPointNetworkOperationalOriginRelocation this[int index] { get { IndexReads++; return value; } }
        public IEnumerator<XPointNetworkOperationalOriginRelocation> GetEnumerator() => throw new InvalidOperationException("Enumeration forbidden.");
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Fact]
    public void OperationalRollover_OriginIntentAndCollectionAreCopiedBoundedAndCanonical()
    {
        var id = Bytes(32, 0x33);
        var address = IPAddress.Parse("2001:db8::1");
        var intent = new XPointNetworkOperationalOriginRelocation(id, address, 8443);
        id[0] ^= 1; address.ScopeId = 8;
        Assert.Equal(Bytes(32, 0x33), intent.OriginId.ToArray());
        Assert.Equal(IPAddress.Parse("2001:db8::1").GetAddressBytes(), intent.Address.ToArray());
        Assert.Equal(6, intent.AddressFamily); Assert.Equal(8443, intent.Port);
        var exposed = intent.Address;
        Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(exposed, out var array));
        array.Array![array.Offset] ^= 1;
        Assert.Equal(IPAddress.Parse("2001:db8::1").GetAddressBytes(), intent.Address.ToArray());
        using var signer = OperationalTestSigner.Create(0x11, 0x12, 0x13);
        XPointNetworkOperationalNodeRollover Capture(IReadOnlyList<XPointNetworkOperationalOriginRelocation> origins) =>
            new(signer, Bytes(32, 0x31), Bytes(32, 0x32), Bytes(32, 0x41), Bytes(32, 0x42), origins);
        var list = new List<XPointNetworkOperationalOriginRelocation> { intent };
        var captured = Capture(list); list.Clear();
        Assert.Same(intent, Assert.Single(captured.OriginRelocations));
        var maximum = Enumerable.Range(1, 16).Select(index =>
        {
            var unique = Bytes(32, 0x33); unique[^1] = checked((byte)index);
            return new XPointNetworkOperationalOriginRelocation(unique, IPAddress.Loopback, checked((ushort)(443 + index)));
        }).ToArray();
        Assert.Equal(16, Capture(maximum).OriginRelocations.Count);
        Assert.Throws<ArgumentException>(() => Capture(Enumerable.Repeat(intent, 17).ToArray()));
        Assert.Throws<ArgumentException>(() => Capture([intent, intent]));
        Assert.Throws<ArgumentException>(() => Capture([null!]));
        Assert.Throws<ArgumentException>(() => new XPointNetworkOperationalOriginRelocation(new byte[32], IPAddress.Loopback, 443));
        Assert.Throws<ArgumentException>(() => new XPointNetworkOperationalOriginRelocation(new byte[31], IPAddress.Loopback, 443));
        Assert.Throws<ArgumentNullException>(() => new XPointNetworkOperationalOriginRelocation(id, null!, 443));
        Assert.Throws<ArgumentException>(() => new XPointNetworkOperationalOriginRelocation(id, IPAddress.Any, 443));
        Assert.Throws<ArgumentException>(() => new XPointNetworkOperationalOriginRelocation(id, IPAddress.IPv6Any, 443));
        Assert.Throws<ArgumentException>(() => new XPointNetworkOperationalOriginRelocation(id, address, 443));
        Assert.Throws<ArgumentOutOfRangeException>(() => new XPointNetworkOperationalOriginRelocation(id, IPAddress.Loopback, 0));
        var v4 = new XPointNetworkOperationalOriginRelocation(id, IPAddress.Parse("192.0.2.1"), 443);
        Assert.Equal(4, v4.AddressFamily); Assert.Equal(new byte[12], v4.Address.ToArray()[4..]);
        var constructor = Assert.Single(typeof(XPointNetworkOperationalNodeRollover).GetConstructors());
        Assert.Equal(6, constructor.GetParameters().Length);
        Assert.True(constructor.GetParameters()[5].IsOptional);
    }

    internal sealed partial class Fixture
    {
        internal async Task CheckPmaLifetimeBoundAsync()
        {
            var original = await VerifyMailboxAsync();
            using var root = new OperationalTestSigner(_root);
            var renewal = await XPointNetworkBootstrapAuthor.AuthorSameKeyRenewalAsync(Bytes(32, 0x38), _authority,
                [_dts], 850, 850, 2_000_000, 850, 1_500_000, [root]);
            var authority = XPointNetworkAuthorityVerifier.Verify(new(_authority.NetworkId.Span, _authority.AuthorityCoreHash.Span),
                [_xna, renewal.ExactXna1], [_dts, renewal.ExactDts1]);
            var witnesses = _witnesses.Select(key => new OperationalTestSigner(key)).ToArray();
            var identities = Enumerable.Range(0, 3).Select(index => OperationalTestSigner.Create(
                checked((byte)(0x10 + index)), checked((byte)(0x90 + index * 8)), 0x7d)).ToArray();
            try
            {
                var before = root.Calls;
                var request = new XPointNetworkOperationalSuccessorRequest(Bytes(32, 0x39), authority, [root], witnesses,
                    NewRollovers(identities, _nodes, false), _xvp, _nodes.Select(b => (ReadOnlyMemory<byte>)b).ToArray(),
                    [_xnv], _xnh, original.Pma, original.Network.Closure!.Pmt.CanonicalBytes,
                    XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(_xnh), original.Network.Closure.Pmt.ArtifactHash.Span,
                    ContactCodec.Decode("PMT2", _pmt).Field(14).Span, 850, 850, 900, rootPolicyExpiresAtUnixSeconds: 850 + 1_209_601UL);
                await Assert.ThrowsAsync<ArgumentException>(() => XPointNetworkOperationalSuccessorAuthor.AuthorAsync(request).AsTask());
                Assert.Equal(before, root.Calls);
                Assert.All(witnesses.Concat(identities), signer => Assert.Equal(0, signer.Calls));
            }
            finally { foreach (var signer in witnesses.Concat(identities)) signer.Dispose(); }
        }
        internal async Task CheckSameKeyRenewalAsync(string? fault = null, ulong renewalFrom = 850)
        {
            using var root = new OperationalTestSigner(_root);
            using var unknown = OperationalTestSigner.Create(0x24, 0x25, 0x26);
            var dts = _dts.ToArray();
            if (fault == "invalid-predecessor-signature") dts[^1] ^= 1;
            var rootFrom = fault == "root-time-rollback" ? _authority.NotBefore - 1 : renewalFrom;
            var rootUntil = fault == "short-root" ? 999UL : fault == "oversized-dts" ? 3_100_000UL : checked(renewalFrom + 650);
            var dtsFrom = fault == "dts-before-root" ? rootFrom - 1 : rootFrom;
            var dtsUntil = fault == "oversized-dts" ? dtsFrom + 2_592_001UL : checked(renewalFrom + 550);
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
                [_dts, first.ExactDts1], checked(renewalFrom + 500), checked(renewalFrom + 500),
                checked(renewalFrom + 1_250), checked(renewalFrom + 500), checked(renewalFrom + 1_150), [root]);
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
            if (renewalFrom >= _authority.ExpiresAt)
            {
                Assert.Equal(renewalFrom, firstAuthority.IssuedAt);
                Assert.Equal(renewalFrom, firstAuthority.NotBefore);
                Assert.True(AccountDirectoryDts1Codec.Decode(_dts).ExpiresAt < renewalFrom);
                Assert.Equal(_authority.ExpiresAt, current.AuthorityChain[0].ExpiresAt);
                var original = await VerifyMailboxAsync();
                Assert.Throws<CryptographicException>(() => MailboxAuthorityV2Verifier.Verify(
                    _authority, original.Pma.AsSpan(), renewalFrom, renewalFrom + 1));
                Assert.Throws<CryptographicException>(() => MailboxAuthorityV2Verifier.Verify(
                    current, original.Pma.AsSpan(), current.NotBefore, current.NotBefore + 1));
            }
        }

        internal async Task CheckOperationalRolloverAsync(bool cold, string? fault = null, bool extendRootPolicy = false, bool rotateMailbox = false,
            bool relocateOrigins = false, bool delegatedRelocation = false, bool ipv6Origins = false, bool mutateOriginCollections = false)
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
            var callerOriginArrays = new List<XPointNetworkOperationalOriginRelocation[]>();
            if (mutateOriginCollections) root.BeforeSign = () => callerOriginArrays.ForEach(static values => Array.Clear(values));
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
                var oldMailbox = ContactCodec.Decode("PMA2", original.Pma);
                var deposit = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x35)).PublicKey;
                var retrieve = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x36)).PublicKey;
                if (fault == "mailbox-old-deposit") deposit = oldMailbox.Field(5).ToArray();
                if (fault == "mailbox-old-retrieve") retrieve = oldMailbox.Field(6).ToArray();
                if (fault == "mailbox-cross-old") deposit = oldMailbox.Field(6).ToArray();
                if (fault == "mailbox-root-key") deposit = root.Ed25519PublicKey.ToArray();
                if (fault == "mailbox-witness-key") deposit = witnesses[0].Ed25519PublicKey.ToArray();
                if (fault == "mailbox-node-key") deposit = identities[0].Ed25519PublicKey.ToArray();
                var minimum = BinaryPrimitives.ReadUInt64BigEndian(oldMailbox.Field(7).Span);
                Assert.Equal(checked(minimum + 1), XPointNetworkOperationalSuccessorAuthor.ComputeNextMailboxGrantFloor(renewed.Authority, original.Pma));
                var invalidFloorSource = original.Pma.ToArray(); invalidFloorSource[^1] ^= 1;
                Assert.Throws<CryptographicException>(() => XPointNetworkOperationalSuccessorAuthor.ComputeNextMailboxGrantFloor(renewed.Authority, invalidFloorSource));
                XPointNetworkOperationalSuccessorRequest Request() => new(Bytes(32, 0x13), renewed.Authority,
                    fault is "delegated-cross-root" or "delegated-policy-extension" or "mailbox-delegated" ? [] : new IXPointNetworkBootstrapRootSigner[] { fault == "old-root-signer" ? oldRoot : root },
                    fault == "old-witness-signers" ? oldWitnesses : witnesses,
                    NewRollovers(identities, _nodes, delegated: false, relocate: relocateOrigins && !delegatedRelocation,
                        ipv6: ipv6Origins, originFault: fault, callerOriginArrays: mutateOriginCollections ? callerOriginArrays : null), policy,
                    _nodes.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(), prefix,
                    head, pma, pmt, headHash, pmtHash, ContactCodec.Decode("PMT2", _pmt).Field(14).ToArray(), 180, 185, 280,
                    rootPolicyExpiresAtUnixSeconds: fault == "policy-under-operational" ? 279UL
                        : fault == "policy-over-authority" ? checked(renewed.Authority.ExpiresAt + 1)
                        : extendRootPolicy || fault == "delegated-policy-extension" ? 600UL : 0UL,
                    mailboxIssuerRollover: rotateMailbox ? new(deposit, retrieve, fault == "mailbox-floor" ? minimum : checked(minimum + 1)) : null);
                if (fault is not null)
                {
                    var rejected = await Record.ExceptionAsync(async () =>
                    {
                        if (fault is "delegated-cross-root" or "delegated-policy-extension" or "mailbox-delegated") await XPointNetworkOperationalSuccessorAuthor.AuthorDelegatedAsync(Request());
                        else await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(Request());
                    });
                    Assert.NotNull(rejected);
                    Assert.True(fault is "missing-prefix" or "policy-under-operational" or "policy-over-authority" or "delegated-policy-extension" or "mailbox-delegated" ? rejected is ArgumentException
                        : rejected is CryptographicException or OnionBoundaryException, rejected.ToString());
                    Assert.Equal(0, root.Calls + oldRoot.Calls + witnesses.Concat(oldWitnesses).Concat(identities).Sum(s => s.Calls));
                    Assert.Equal(original.Network.Closure.Pmt.CanonicalBytes.ToArray(), original.Network.Closure.RetainedPmts[0].CanonicalBytes.ToArray());
                    return;
                }
                // Historical authentication does not mint an old current policy.
                MailboxAuthorityV2Verifier.VerifyHistoricalLineage(renewed.Authority, original.Pma, 100, 101);
                Assert.Throws<CryptographicException>(() => MailboxAuthorityV2Verifier.Verify(renewed.Authority, original.Pma, 200, 201));
                var first = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(Request());
                if (mutateOriginCollections)
                {
                    Assert.True(root.Calls > 0); Assert.Equal(3, callerOriginArrays.Count);
                    Assert.All(callerOriginArrays, static values => Assert.All(values, static value => Assert.Null(value)));
                }
                if (rotateMailbox)
                {
                    var issuer = MailboxAuthorityV2Verifier.Verify(renewed.Authority, first.ExactPma2.Span, 200, 201);
                    Assert.Equal(deposit, issuer.ResolveIssuer(MailboxCapabilityDomain.Deposit).PublicKey.ToArray());
                    Assert.Equal(retrieve, issuer.ResolveIssuer(MailboxCapabilityDomain.Retrieve).PublicKey.ToArray());
                    Assert.Equal(minimum + 1, issuer.MinimumGrantGeneration);
                    Assert.True(issuer.BindsProjection(first.ExactPmt2.Span));
                    Assert.Equal(oldMailbox.Field(4).ToArray(), ContactCodec.Decode("PMA2", first.ExactPma2.Span).Field(4).ToArray());
                    Assert.Equal(oldMailbox.CoreHash.ToArray(), ContactCodec.Decode("PMA2", first.ExactPma2.Span).Field(3).ToArray());
                }
                if (extendRootPolicy)
                {
                    Assert.Equal(600UL, XPointNetworkCodec.Parse<Xvp1Record>(first.ExactXvp1.Span).ExpiresAt);
                    Assert.Equal(600UL, MailboxAuthorityV2Verifier.Verify(renewed.Authority, first.ExactPma2.Span, 200, 201).ExpiresAtUnixSeconds);
                    Assert.Equal(280UL, XPointNetworkCodec.Parse<Xnv1Record>(first.ExactXnv1.Span).ExpiresAt);
                }
                var delegated = await XPointNetworkOperationalSuccessorAuthor.AuthorDelegatedAsync(new(
                    Bytes(32, 0x14), renewed.Authority, [], witnesses, NewRollovers(identities, first.ExactXnd1.Select(b => b.ToArray()).ToArray(), true,
                        relocate: relocateOrigins && delegatedRelocation, ipv6: ipv6Origins, retainTrafficKeys: relocateOrigins),
                    first.ExactXvp1, first.ExactXnd1, [_xnv, first.ExactXnv1], first.ExactXnh1,
                    first.ExactPma2, first.ExactPmt2,
                    XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(first.ExactXnh1.Span),
                    ContactCodec.Decode("PMT2", first.ExactPmt2.Span).ArtifactHash.Span,
                    ContactCodec.Decode("PMT2", first.ExactPmt2.Span).Field(14).ToArray(), 190, 190, extendRootPolicy ? 400UL : 270UL));
                Assert.Equal(first.ExactXvp1.ToArray(), delegated.ExactXvp1.ToArray());
                Assert.Equal(first.ExactPma2.ToArray(), delegated.ExactPma2.ToArray());
                if (relocateOrigins)
                {
                    for (var index = 0; index < _nodes.Length; index++)
                    {
                        var before = XPointNetworkCodec.Parse<Xnd1Record>(_nodes[index]);
                        var installed = XPointNetworkCodec.Parse<Xnd1Record>(first.ExactXnd1[index].Span);
                        var after = XPointNetworkCodec.Parse<Xnd1Record>(delegated.ExactXnd1[index].Span);
                        Assert.Equal(before.NodeId, after.NodeId); Assert.Equal(before.IdentityPublicKey, after.IdentityPublicKey);
                        Assert.Equal(before.StakingIdentityHash, after.StakingIdentityHash);
                        Assert.Equal(before.Origins[0].Id, after.Origins[0].Id);
                        Assert.Equal(before.Origins[0].Transport, after.Origins[0].Transport);
                        var expected = new byte[16]; RelocationAddress(index, ipv6Origins).GetAddressBytes().CopyTo(expected, 0);
                        Assert.Equal(expected, after.Origins[0].Address.ToArray());
                        Assert.Equal(ipv6Origins ? 6 : 4, after.Origins[0].AddressFamily);
                        Assert.Equal(8443 + index, after.Origins[0].Port);
                        Assert.Equal(installed.FieldSpan(22).ToArray(), after.FieldSpan(22).ToArray());
                        Assert.Equal(installed.FieldSpan(26).ToArray(), after.FieldSpan(26).ToArray());
                        Assert.Equal(installed.Origins[0].CurrentSpki, after.Origins[0].CurrentSpki);
                        Assert.Equal(installed.Origins[0].NextSpki, after.Origins[0].NextSpki);
                        if (!delegatedRelocation) Assert.Equal(installed.Origins[0].Address, after.Origins[0].Address);
                        XPointNetworkVerifier.RequireSuccessor(installed, after);
                        Assert.True(PublicKeyAuth.VerifyDetached(after.FieldSpan(37).ToArray(),
                            XPointNetworkCrypto.ComputeSigningInput(after), after.IdentityPublicKey.ToArray()));
                    }
                }
                if (extendRootPolicy)
                    Assert.Equal(400UL, XPointNetworkCodec.Parse<Xnv1Record>(delegated.ExactXnv1.Span).ExpiresAt);
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

        private static IPAddress RelocationAddress(int index, bool ipv6) =>
            IPAddress.Parse(ipv6 ? $"2001:db8::{index + 1}" : $"192.0.2.{51 + index}");

        private static XPointNetworkOperationalNodeRollover[] NewRollovers(OperationalTestSigner[] identities, byte[][] nodes, bool delegated,
            bool relocate = false, bool ipv6 = false, string? originFault = null, bool retainTrafficKeys = false,
            List<XPointNetworkOperationalOriginRelocation[]>? callerOriginArrays = null) =>
            nodes.Select((bytes, index) =>
            {
                var previous = XPointNetworkCodec.Parse<Xnd1Record>(bytes);
                XPointNetworkOperationalOriginRelocation[] origins = [];
                if (relocate || originFault is "unknown-origin" or "colliding-origin")
                    origins = [new(originFault == "unknown-origin" && index == 0 ? Bytes(32, 0x99) : previous.Origins[0].Id.Span,
                        RelocationAddress(originFault == "colliding-origin" ? 0 : index, ipv6),
                        checked((ushort)(8443 + (originFault == "colliding-origin" ? 0 : index))))];
                callerOriginArrays?.Add(origins);
                return new XPointNetworkOperationalNodeRollover(identities[index],
                    delegated ? retainTrafficKeys ? previous.Origins[0].CurrentSpki.Span : previous.Origins[0].NextSpki.Span : Bytes(32, checked((byte)(0xc0 + index))),
                    retainTrafficKeys ? previous.Origins[0].NextSpki.Span : Bytes(32, checked((byte)((delegated ? 0xd8 : 0xc8) + index))),
                    delegated ? previous.FieldSpan(retainTrafficKeys ? 22 : 26) : ScalarMult.Base(Bytes(32, checked((byte)(0xd0 + index)))),
                    retainTrafficKeys ? previous.FieldSpan(26) : ScalarMult.Base(Bytes(32, checked((byte)((delegated ? 0xe8 : 0xe0) + index)))), origins);
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
        internal Action? BeforeSign;
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
        { ct.ThrowIfCancellationRequested(); Calls++; BeforeSign?.Invoke(); PublicKeyAuth.SignDetached(input.ToArray(), Key.Pair.PrivateKey).CopyTo(destination); return ValueTask.FromResult(64); }
        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(ReadOnlyMemory<byte> input, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); Calls++; return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(input.ToArray(), Key.Pair.PrivateKey)); }
        public void Dispose() => CryptographicOperations.ZeroMemory(Key.Pair.PrivateKey);
    }
}
