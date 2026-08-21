using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class DpcIsolatedTransportTests
{
    [Fact]
    public Task FinalPostTlsSourceMovementClosesBeforeRequestBytes() =>
        PostTlsExpiryOrAuthorityMovement_ClosesWithZeroRequestBytes(moved: true);

    [Fact]
    public Task FinalPostTlsLeaseExpiryClosesBeforeRequestBytes() =>
        PostTlsExpiryOrAuthorityMovement_ClosesWithZeroRequestBytes(moved: false);

    [Fact]
    public Task ProxyRedirectAltSvcRemainDisabledWithOneFreshTransport() =>
        PostTlsExpiryOrAuthorityMovement_ClosesWithZeroRequestBytes(moved: true);

    [Fact]
    public async Task ConnectedRemoteIpOrTlsSpkiOutsideVerifiedDpcRejectsBeforeSend()
    {
        foreach (var wrongRemote in new[] { true, false })
        {
            var fixture = await Fixture.CreateAsync();
            var stable = fixture.Snapshot(1, 1050);
            var reader = new Reader(stable, stable, stable);
            var transport = new Transport(
                wrongRemote ? fixture.Contact.CurrentTlsSpkiSha256.Span : Bytes(0xee, 32),
                wrongRemote ? new CanonicalIpAddress([9,9,9,9]) : new CanonicalIpAddress([8,8,8,8]));
            var connector = new Connector(transport);
            var client = new DpcIsolatedPeerClient(
                TimeSpan.FromSeconds(5), reader, new Resolver(), connector);

            await Assert.ThrowsAsync<RecordException>(() =>
                client.SendAsync(fixture.Request, stable).AsTask());

            Assert.Equal(1, connector.Calls);
            Assert.Equal(0, transport.SendCalls);
            Assert.Equal(1, transport.CloseCalls);
            Assert.Equal(1, transport.DisposeCalls);
        }
    }

    [Fact]
    public async Task DnsPrivateMixedDuplicateOrEmptyAnswersRejectAfterOneResolution()
    {
        IReadOnlyList<CanonicalIpAddress>[] invalidAnswers =
        [
            [new CanonicalIpAddress([10,0,0,1])],
            [new CanonicalIpAddress([8,8,8,8]), new CanonicalIpAddress([192,168,1,1])],
            [new CanonicalIpAddress([8,8,8,8]), new CanonicalIpAddress([8,8,8,8])],
            []
        ];
        foreach (var answers in invalidAnswers)
        {
            var fixture = await Fixture.CreateAsync(dnsEndpoint: true);
            var stable = fixture.Snapshot(1, 1050);
            var resolver = new Resolver(answers);
            var connector = new Connector(new Transport(
                fixture.Contact.CurrentTlsSpkiSha256.Span));
            var client = new DpcIsolatedPeerClient(
                TimeSpan.FromSeconds(5), new Reader(stable), resolver, connector);

            await Assert.ThrowsAsync<RecordException>(() =>
                client.SendAsync(fixture.Request, stable).AsTask());

            Assert.Equal(1, resolver.Calls);
            Assert.Equal(0, connector.Calls);
        }
    }

    [Fact]
    public async Task DnsResolveMovementOrCancellationPreventsConnectorAllocation()
    {
        var fixture = await Fixture.CreateAsync(dnsEndpoint: true);
        var stable = fixture.Snapshot(1, 1050);
        var moved = fixture.Snapshot(2, 1050);
        var resolver = new Resolver([new CanonicalIpAddress([8,8,8,8])]);
        var connector = new Connector(new Transport(
            fixture.Contact.CurrentTlsSpkiSha256.Span));
        var client = new DpcIsolatedPeerClient(
            TimeSpan.FromSeconds(5), new Reader(stable, moved), resolver, connector);

        await Assert.ThrowsAsync<RecordException>(() =>
            client.SendAsync(fixture.Request, stable).AsTask());
        Assert.Equal(1, resolver.Calls);
        Assert.Equal(0, connector.Calls);

        using var cancellation = new CancellationTokenSource();
        var canceling = new CancelingResolver(cancellation);
        connector = new Connector(new Transport(
            fixture.Contact.CurrentTlsSpkiSha256.Span));
        client = new DpcIsolatedPeerClient(
            TimeSpan.FromSeconds(5), new Reader(stable), canceling, connector);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.SendAsync(fixture.Request, stable, cancellation.Token).AsTask());
        Assert.Equal(1, canceling.Calls);
        Assert.Equal(0, connector.Calls);
    }

    [Fact]
    public async Task DnsOwnedSetNormalizesMappedSortsOneThroughSixteenAndPinsMemberSpki()
    {
        foreach (var count in new[] { 1, 16 })
        {
            var fixture = await Fixture.CreateAsync(dnsEndpoint: true);
            var stable = fixture.Snapshot(1, 1050);
            var answers = count == 1
                ? new[] { new CanonicalIpAddress([8,8,8,8]) }
                : SixteenUnsortedAddresses();
            var resolver = new Resolver(answers);
            var remote = count == 1
                ? new CanonicalIpAddress([8,8,8,8])
                : new CanonicalIpAddress([8,8,4,4]);
            var transport = new Transport(
                fixture.Contact.CurrentTlsSpkiSha256.Span, remote,
                fixture.ResponseFrame);
            var connector = new Connector(transport);
            var client = new DpcIsolatedPeerClient(
                TimeSpan.FromSeconds(5), new Reader(stable), resolver, connector);

            var result = await client.SendAsync(fixture.Request, stable);

            Assert.True(result.NoDeliveryOrDurabilityClaim);
            Assert.Equal(1, resolver.Calls);
            Assert.Equal(1, connector.Calls);
            Assert.Equal(count, connector.LastRequest!.Addresses.Count);
            Assert.Equal("router.example"u8.ToArray(),
                connector.LastRequest.CanonicalAsciiSni.ToArray());
            Assert.Contains(connector.LastRequest.Addresses, remote.Equals);
            Assert.Equal(1, transport.SendCalls);
            Assert.Equal(1, transport.CloseCalls);
            Assert.Equal(1, transport.DisposeCalls);
            var ordered = connector.LastRequest.Addresses;
            for (var index = 1; index < ordered.Count; index++)
            {
                var left = ordered[index - 1];
                var right = ordered[index];
                Assert.True(left.Family < right.Family ||
                    left.Family == right.Family &&
                    left.Bytes.Span.SequenceCompareTo(right.Bytes.Span) < 0);
            }
            if (count == 16)
                Assert.Contains(ordered, address =>
                    address.Family == CanonicalAddressFamily.Ipv4 &&
                    address.Bytes.Span.SequenceEqual(new byte[] { 8,8,4,4 }));
        }
    }

    [Fact]
    public async Task EverySendUsesFreshResolveConnectTlsTransportWithoutPoolingOrCoalescing()
    {
        var fixture = await Fixture.CreateAsync(dnsEndpoint: true);
        var stable = fixture.Snapshot(1, 1050);
        var resolver = new Resolver([new CanonicalIpAddress([8,8,8,8])]);
        var connector = new FreshConnector(fixture);
        var client = new DpcIsolatedPeerClient(
            TimeSpan.FromSeconds(5), new Reader(stable), resolver, connector);

        _ = await client.SendAsync(fixture.Request, stable);
        _ = await client.SendAsync(fixture.Request, stable);

        Assert.Equal(2, resolver.Calls);
        Assert.Equal(2, connector.Calls);
        Assert.Equal(2, connector.Transports.Count);
        Assert.NotSame(connector.Transports[0], connector.Transports[1]);
        Assert.All(connector.Transports, transport =>
        {
            Assert.Equal(1, transport.SendCalls);
            Assert.Equal(1, transport.CloseCalls);
            Assert.Equal(1, transport.DisposeCalls);
        });
    }

    private static async Task PostTlsExpiryOrAuthorityMovement_ClosesWithZeroRequestBytes(bool moved)
    {
        var fixture = await Fixture.CreateAsync();
        var final = fixture.Snapshot(
            moved ? 2UL : 1UL,
            moved ? 1050UL : 1200UL);
        var reader = new Reader(fixture.Snapshot(1, 1050), fixture.Snapshot(1, 1050), final);
        var transport = new Transport(fixture.Contact.CurrentTlsSpkiSha256.Span);
        var connector = new Connector(transport);

        var client = new DpcIsolatedPeerClient(
            TimeSpan.FromSeconds(5), reader, new Resolver(), connector);
        await Assert.ThrowsAsync<RecordException>(() =>
            client.SendAsync(fixture.Request, fixture.Snapshot(1, 1050)).AsTask());

        Assert.Equal(0, transport.SendCalls);
        Assert.Equal(1, transport.CloseCalls);
        Assert.Equal(1, transport.DisposeCalls);
        Assert.Equal(1, connector.Calls);
        Assert.Equal(3, reader.Calls);
    }

    private sealed class Fixture
    {
        internal required CurrentCutoverRelative Cutover { get; init; }
        internal required CurrentDnrcRelative Dnrc { get; init; }
        internal required VerifiedMembershipRoutingLkg Membership { get; init; }
        internal required VerifiedRouterContact Contact { get; init; }
        internal required VerifiedNativePeerRequest Request { get; init; }
        internal required byte[] ResponseFrame { get; init; }

        internal DpcTransportAuthoritySnapshot Snapshot(ulong generation, ulong now) =>
            new(Cutover, Dnrc, Membership, Contact, generation, now, protectedKeysHealthy: true);

        internal static async Task<Fixture> CreateAsync(bool dnsEndpoint = false)
        {
            var facts = await MembershipClosureIntegrationTests
                .CreateTransportRoutingFactsAsync(dnsEndpoint);
            var network = facts.Membership.TrustedNetworkId.ToArray();
            var router = facts.Contact.RouterId.ToArray();
            var wire = RequestFor(network, router, facts.Contact);
            return new Fixture
            {
                Cutover = facts.Cutover,
                Dnrc = facts.Dnrc,
                Membership = facts.Membership,
                Contact = facts.Contact,
                Request = wire.Request,
                ResponseFrame = wire.Response
            };
        }
    }

    private sealed class Reader(params DpcTransportAuthoritySnapshot[] values)
        : IDpcTransportAuthorityReader
    {
        private int _index;
        internal int Calls => _index;
        public ValueTask<DpcTransportAuthoritySnapshot> ReadCurrentAsync(
            DpcTransportAuthorityReadRequest request,
            CancellationToken cancellationToken = default)
        {
            var value = values[Math.Min(_index, values.Length - 1)];
            _index++;
            return ValueTask.FromResult(value);
        }
    }

    private sealed class Resolver(IReadOnlyList<CanonicalIpAddress>? answers = null)
        : ITypedDnsResolver
    {
        internal int Calls { get; private set; }
        public ValueTask<IReadOnlyList<CanonicalIpAddress>> ResolveOnceAsync(
            DnsResolutionRequest request,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            if (answers is null)
                throw new Xunit.Sdk.XunitException("Direct DPC1 must not resolve DNS.");
            return ValueTask.FromResult(answers);
        }
    }

    private sealed class CancelingResolver(CancellationTokenSource cancellation)
        : ITypedDnsResolver
    {
        internal int Calls { get; private set; }
        public ValueTask<IReadOnlyList<CanonicalIpAddress>> ResolveOnceAsync(
            DnsResolutionRequest request,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            cancellation.Cancel();
            return ValueTask.FromResult<IReadOnlyList<CanonicalIpAddress>>(
                [new CanonicalIpAddress([8,8,8,8])]);
        }
    }

    private sealed class FreshConnector(Fixture fixture) : ITypedPeerConnector
    {
        internal int Calls { get; private set; }
        internal List<Transport> Transports { get; } = [];

        public ValueTask<IFreshPeerTransport> ConnectTlsAsync(
            IsolatedConnectionRequest request,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            Assert.True(request.FreshConnectionRequired);
            Assert.True(request.OriginCoalescingDisabled);
            Assert.True(request.PoolingDisabled);
            Assert.True(request.ConnectionReuseDisabled);
            var transport = new Transport(
                fixture.Contact.CurrentTlsSpkiSha256.Span,
                new CanonicalIpAddress([8,8,8,8]), fixture.ResponseFrame);
            Transports.Add(transport);
            return ValueTask.FromResult<IFreshPeerTransport>(transport);
        }
    }

    private sealed class Connector(Transport transport) : ITypedPeerConnector
    {
        internal int Calls { get; private set; }
        internal IsolatedConnectionRequest? LastRequest { get; private set; }
        public ValueTask<IFreshPeerTransport> ConnectTlsAsync(
            IsolatedConnectionRequest request,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            LastRequest = request;
            Assert.True(request.SystemProxyDisabled);
            Assert.True(request.UserProxyDisabled);
            Assert.True(request.RedirectsDisabled);
            Assert.True(request.AltSvcDisabled);
            Assert.True(request.OriginCoalescingDisabled);
            Assert.True(request.PoolingDisabled);
            Assert.True(request.ConnectionReuseDisabled);
            var sni = request.CanonicalAsciiSni.ToArray();
            Assert.True(sni.Length == 0 || sni.SequenceEqual("router.example"u8.ToArray()));
            return ValueTask.FromResult<IFreshPeerTransport>(transport);
        }
    }

    private sealed class Transport : IFreshPeerTransport
    {
        private readonly byte[] _spki;
        private readonly byte[] _response;
        internal Transport(
            ReadOnlySpan<byte> spki,
            CanonicalIpAddress? remoteAddress = null,
            ReadOnlySpan<byte> response = default)
        {
            _spki = spki.ToArray();
            _response = response.ToArray();
            RemoteAddress = remoteAddress ?? new CanonicalIpAddress([8, 8, 8, 8]);
        }
        public CanonicalIpAddress RemoteAddress { get; }
        public ReadOnlyMemory<byte> TlsSpkiSha256 => _spki.ToArray();
        internal int SendCalls { get; private set; }
        internal int CloseCalls { get; private set; }
        internal int DisposeCalls { get; private set; }
        public ValueTask<IsolatedPeerResponse> SendNativeMailboxAsync(
            ReadOnlyMemory<byte> exactRequestBody,
            CancellationToken cancellationToken = default)
        {
            SendCalls++;
            return ValueTask.FromResult(_response.Length == 0
                ? new IsolatedPeerResponse(500, [])
                : new IsolatedPeerResponse(200, _response));
        }
        public ValueTask CloseAsync(CancellationToken cancellationToken = default)
        {
            CloseCalls++;
            return ValueTask.CompletedTask;
        }
        public ValueTask DisposeAsync()
        {
            DisposeCalls++;
            return ValueTask.CompletedTask;
        }
    }

    private static (VerifiedNativePeerRequest Request, byte[] Response) RequestFor(
        byte[] network,
        byte[] recipient,
        VerifiedRouterContact contact)
    {
        var recipientSeed = Bytes(0x44, 32);
        var recipientKeys = PublicKeyAuth.GenerateKeyPair(recipientSeed);
        var prq = Bytes(30, 32);
        var fields = RecordDefinitions.Dpr1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        fields[0] = network;
        fields[1] = Bytes(31, 32);
        fields[2] = recipient;
        fields[3] = Reference(ArtifactType.Dpc1, 431, 32);
        fields[4] = contact.ArtifactReference;
        fields[5] = Bytes(33, 32);
        fields[6] = U64(1040);
        fields[7] = U64(1100);
        fields[8] = U16(1);
        fields[9] = CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Prq2, (uint)prq.Length, SHA256.HashData(prq)));
        fields[10] = Bytes(34, 64);
        var dpr = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpr1, fields),
            RecordDefinitions.Dpr1);
        var proof = new MailboxReplicaMembershipProof
        {
            ReplicaId = recipient, SigningPublicKey = recipientKeys.PublicKey, Epoch = 1,
            MembershipCommitment = Bytes(3, 32), CanonicalInclusionProof = new byte[] { 1 }
        };
        var inner = new MailboxPeerWireRequestV2
        {
            Operation = MailboxPeerReplicationOperation.Tombstone,
            Epoch = 1,
            OperationId = Bytes(1, 16), SenderRouterId = fields[1], RecipientRouterId = fields[2],
            MembershipCommitment = Bytes(7, 32), PlacementCommitment = Bytes(8, 32),
            BlindedMailboxId = Bytes(9, 32), Cursor = 1,
            CreatedAtUnixSeconds = 1040, ExpiresAtUnixSeconds = 1100,
            ReplayNonce = fields[5], PayloadDigest = Bytes(10, 32), Payload = Bytes(11, 32),
            SenderMembershipProof = proof, RecipientMembershipProof = proof,
            Signature = Bytes(12, 64)
        };
        var request = new VerifiedNativePeerRequest(
            dpr, prq, inner, Bytes(13, 32), recipientKeys.PublicKey);
        var unsignedReceipt = new MailboxReplicaReceiptV2
        {
            Status = MailboxReceiptStatus.Durable,
            Disposition = MailboxReplicaDisposition.Tombstone,
            ReplicaId = inner.RecipientRouterId,
            OperationId = inner.OperationId,
            Epoch = inner.Epoch,
            Cursor = inner.Cursor,
            AcceptedAtUnixSeconds = 1041,
            DurableAtUnixSeconds = 1042,
            ExpiresAtUnixSeconds = inner.ExpiresAtUnixSeconds,
            BlindedMailboxId = inner.BlindedMailboxId,
            PlacementCommitment = inner.PlacementCommitment,
            MembershipCommitment = inner.MembershipCommitment,
            EnvelopeDigest = inner.Payload,
            Signature = ReadOnlyMemory<byte>.Empty
        };
        var mrr = MailboxReceiptV2Codec.EncodeReplica(
            new SodiumMailboxPeerReplicationCrypto().SignReplicaResponse(
                unsignedReceipt, recipientSeed));
        var dps = ResponseStatus(request, mrr, recipientKeys.PrivateKey);
        var response = new byte[NativePeerVerifier.ResponseLength];
        BinaryPrimitives.WriteUInt32BigEndian(response, checked((uint)dps.Length));
        dps.CopyTo(response, 4);
        BinaryPrimitives.WriteUInt32BigEndian(
            response.AsSpan(4 + dps.Length), checked((uint)mrr.Length));
        mrr.CopyTo(response, 8 + dps.Length);
        return (request, response);
    }

    private static byte[] ResponseStatus(
        VerifiedNativePeerRequest request,
        byte[] mrr,
        byte[] recipientPrivateKey)
    {
        var dpr = CanonicalGrammar.DecodeOwned(
            request.CanonicalDpr1.Span, RecordDefinitions.Dpr1);
        var fields = RecordDefinitions.Dps1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        for (var tag = 1; tag <= 6; tag++) fields[tag - 1] = dpr.FieldCopy(tag);
        fields[6] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dpr1, dpr.CanonicalSpan));
        fields[7] = CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Mrr2, checked((uint)mrr.Length), SHA256.HashData(mrr)));
        fields[8] = U64(1043); fields[9] = U64(1100); fields[10] = new byte[64];
        var unsigned = CanonicalGrammar.Encode(RecordDefinitions.Dps1, fields);
        fields[10] = PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(unsigned, RecordDefinitions.Dps1),
            "Deep/NativeRouting/V1/response"), recipientPrivateKey);
        return CanonicalGrammar.Encode(RecordDefinitions.Dps1, fields);
    }

    private static CanonicalIpAddress[] SixteenUnsortedAddresses()
    {
        var values = new List<CanonicalIpAddress>
        {
            new([0,0,0,0,0,0,0,0,0,0,0xff,0xff,8,8,4,4]),
            new([0x26,0x06,0x47,0x00,0,0,0,0,0,0,0,0,0,0,0,1])
        };
        for (byte suffix = 1; suffix <= 14; suffix++)
            values.Add(new CanonicalIpAddress([8,8,8,suffix]));
        values.Reverse();
        return values.ToArray();
    }

    private static byte[] ContactBytes(byte[] network, byte[] router, byte[] dnr)
    {
        var fields = RecordDefinitions.Dpc1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        fields[0] = network; fields[1] = router; fields[2] = dnr; fields[3] = U64(1);
        fields[4] = new byte[38]; fields[5] = U64(1000); fields[6] = U64(1200);
        fields[7] = U64((ulong)RouterCapabilities.NativePeerMailboxV2);
        fields[8] = new byte[] { (byte)EndpointKind.Ipv4 };
        fields[9] = new byte[] { 8, 8, 8, 8 }; fields[10] = U16(443);
        fields[11] = Bytes(40, 32); fields[12] = new byte[32]; fields[13] = U64(1);
        fields[14] = Bytes(41, 64);
        return CanonicalGrammar.Encode(RecordDefinitions.Dpc1, fields);
    }

    private static byte[] Mrl(byte[] network, byte[] router, byte[] dnr, byte[] dpc)
    {
        var fields = RecordDefinitions.Mrl2.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        fields[0] = network; fields[1] = U64(7); fields[2] = U64(1); fields[3] = router;
        fields[4] = dnr; fields[5] = U64((ulong)RouterRoles.MailboxReplica);
        fields[6] = U64((ulong)RouterCapabilities.NativePeerMailboxV2);
        fields[7] = U64(1); fields[8] = dpc; fields[9] = U64(1000);
        fields[10] = U64(1200); fields[11] = new byte[38];
        return CanonicalGrammar.Encode(RecordDefinitions.Mrl2, fields);
    }

    private static byte[] Reference(ArtifactType type, uint length, byte marker)
    {
        var result = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(result, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(2), length);
        result[6] = marker;
        return result;
    }
    private static byte[] Bytes(byte value, int length) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
}
