using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class OuterPeerJournalTests
{
    [Fact]
    public async Task CrashAfterPrepared_RetryPersistsInnerPendingAndUsesOnlyExactReplay()
    {
        var request = Request(7);
        var store = new Store();
        var inner = new CrashingInner();
        var dependencies = new Dependencies(store, inner);

        await Assert.ThrowsAsync<CrashException>(() => dependencies.Execute(request, 1050).AsTask());
        var prepared = ProtectedStateCodec.DecodeOuterPeerJournal(store.Value!.CanonicalDpj1.Span);
        Assert.Equal(JournalPhase.Prepared, prepared.Phase);
        Assert.Equal(1, inner.FreshCalls);
        Assert.Equal(0, inner.ReplayCalls);

        await Assert.ThrowsAsync<CrashException>(() => dependencies.Execute(request, 1050).AsTask());
        var pending = ProtectedStateCodec.DecodeOuterPeerJournal(store.Value!.CanonicalDpj1.Span);
        Assert.Equal(JournalPhase.InnerPending, pending.Phase);
        Assert.Equal(1, inner.FreshCalls);
        Assert.Equal(1, inner.ReplayCalls);
        Assert.All(store.CasValues, value => Assert.Equal(609, value.Length));
    }

    [Fact]
    public async Task EqualityAtExpiry_IsTerminalAndInvokesNoInnerCallback()
    {
        var store = new Store();
        var inner = new CountingInner();
        var dependencies = new Dependencies(store, inner);

        var result = await dependencies.Execute(Request(8), 1100);

        Assert.Equal(OuterJournalDisposition.TerminalStale, result.Disposition);
        Assert.Equal(0, inner.FreshCalls + inner.ReplayCalls);
        var row = ProtectedStateCodec.DecodeOuterPeerJournal(result.CanonicalDpj1.Span);
        Assert.True(row.TerminalStale);
        Assert.False(row.DeliveryAuthorized);
    }

    [Fact]
    public async Task SameLiveIndexWithChangedRequestHash_LatchesForkBeforeInnerCallback()
    {
        var store = new Store();
        var firstInner = new CrashingInner();
        var first = new Dependencies(store, firstInner);
        await Assert.ThrowsAsync<CrashException>(() => first.Execute(Request(9, 1), 1050).AsTask());

        var secondInner = new CountingInner();
        var second = new Dependencies(store, secondInner);
        var result = await second.Execute(Request(9, 2), 1050);

        Assert.Equal(OuterJournalDisposition.ForkLatched, result.Disposition);
        Assert.Equal(0, secondInner.FreshCalls + secondInner.ReplayCalls);
        var record = CanonicalGrammar.DecodeOwned(
            result.CanonicalDpj1.Span, RecordDefinitions.Dpj1);
        Assert.Equal(1, record.FieldSpan(19)[0]);
    }

    [Fact]
    public async Task StoredMutation_RejectsBeforeInnerCallback()
    {
        var store = new Store();
        var first = new Dependencies(store, new CrashingInner());
        var request = Request(10);
        await Assert.ThrowsAsync<CrashException>(() => first.Execute(request, 1050).AsTask());
        store.Mutate(608);
        var inner = new CountingInner();

        var error = await Assert.ThrowsAsync<RecordException>(() =>
            new Dependencies(store, inner).Execute(request, 1050).AsTask());

        Assert.Equal(RecordError.InvalidSignature, error.Error);
        Assert.Equal(0, inner.FreshCalls + inner.ReplayCalls);
    }

    [Fact]
    public async Task PureTransitionPlans_PreservePreparedPendingStaleAndForkWithoutDurabilityClaim()
    {
        var store = new Store();
        var crash = new CrashingInner();
        var request = Request(11);
        await Assert.ThrowsAsync<CrashException>(() =>
            new Dependencies(store, crash).Execute(request, 1050).AsTask());
        var prepared = ProtectedStateCodec.DecodeOuterPeerJournal(
            store.Value!.CanonicalDpj1.Span);
        Assert.Equal(JournalPhase.Prepared, prepared.Phase);
        Assert.True(store.Value.NoDurabilityClaim);

        await Assert.ThrowsAsync<CrashException>(() =>
            new Dependencies(store, crash).Execute(request, 1050).AsTask());
        var pending = ProtectedStateCodec.DecodeOuterPeerJournal(
            store.Value!.CanonicalDpj1.Span);
        Assert.Equal(JournalPhase.InnerPending, pending.Phase);

        var forkInner = new CountingInner();
        var fork = await new Dependencies(store, forkInner).Execute(Request(11, 2), 1050);
        Assert.Equal(OuterJournalDisposition.ForkLatched, fork.Disposition);
        Assert.True(fork.NoDurabilityClaim);
        Assert.Equal(0, forkInner.FreshCalls + forkInner.ReplayCalls);

        var staleStore = new Store();
        var staleInner = new CountingInner();
        var stale = await new Dependencies(staleStore, staleInner).Execute(Request(12), 1100);
        Assert.Equal(OuterJournalDisposition.TerminalStale, stale.Disposition);
        Assert.True(stale.NoDurabilityClaim);
        Assert.Equal(0, staleInner.FreshCalls + staleInner.ReplayCalls);
    }

    [Fact]
    public void AddressPolicy_NormalizesMappedAndRejectsEveryNamedPrivateBoundary()
    {
        var mapped = new CanonicalIpAddress(
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8]);
        Assert.Equal(CanonicalAddressFamily.Ipv4, mapped.Family);
        Assert.Equal(new byte[] { 8, 8, 8, 8 }, mapped.Bytes.ToArray());
        DpcAddressPolicy.EnsurePublicUnicast(mapped);

        byte[][] denied =
        [
            [0, 1, 1, 1], [10, 0, 0, 1], [100, 64, 0, 1], [127, 0, 0, 1],
            [169, 254, 1, 1], [172, 16, 0, 1], [192, 0, 0, 1], [192, 0, 2, 1],
            [192, 88, 99, 1], [192, 168, 1, 1], [198, 18, 0, 1],
            [198, 51, 100, 1], [203, 0, 113, 1], [224, 0, 0, 1], [240, 0, 0, 1]
        ];
        foreach (var address in denied)
            Assert.Throws<RecordException>(() =>
                DpcAddressPolicy.EnsurePublicUnicast(new CanonicalIpAddress(address)));

        DpcAddressPolicy.EnsurePublicUnicast(new CanonicalIpAddress(
            [0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        byte[][] deniedV6 =
        [
            [0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x3f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        ];
        foreach (var address in deniedV6)
            Assert.Throws<RecordException>(() =>
                DpcAddressPolicy.EnsurePublicUnicast(new CanonicalIpAddress(address)));
    }

    [Fact]
    public void ResolverSet_MixedInvalidDuplicateOrNonCanonicalNameRejects()
    {
        Assert.Throws<RecordException>(() => DpcAddressPolicy.FreezeAndValidate(
            [new CanonicalIpAddress([8, 8, 8, 8]),
             new CanonicalIpAddress([10, 0, 0, 1])]));
        Assert.Throws<RecordException>(() => DpcAddressPolicy.FreezeAndValidate(
            [new CanonicalIpAddress([8, 8, 8, 8]),
             new CanonicalIpAddress([8, 8, 8, 8])]));
        Assert.Throws<RecordException>(() =>
            DpcAddressPolicy.ValidateDnsName("Bad_host.example"u8));
        DpcAddressPolicy.ValidateDnsName("router.example"u8);
    }

    [Fact]
    public void RequestAndOutcomeHashes_UseExactNormativeFrameOrder()
    {
        var request = Request(15);
        var dpr = request.CanonicalDpr1.ToArray();
        var prq = request.CanonicalPrq2.ToArray();
        var requestPayload = Framed(dpr, prq);
        Assert.Equal(
            CanonicalGrammar.Sha256Domain(
                "Deep/NativeRouting/V1/outer-request-hash", requestPayload),
            OuterPeerJournal.ComputeCanonicalRequestHash(request));

        var mrr = Bytes(16, 296);
        var dpsFields = RecordDefinitions.Dps1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        dpsFields[0] = Bytes(1, 16); dpsFields[1] = Bytes(2, 32); dpsFields[2] = Bytes(3, 32);
        dpsFields[3] = Reference(ArtifactType.Dpc1, 431, 4);
        dpsFields[4] = Reference(ArtifactType.Dpc1, 431, 5); dpsFields[5] = Bytes(15, 32);
        dpsFields[6] = Reference(ArtifactType.Dpr1, 408, 6);
        dpsFields[7] = CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Mrr2, 296, SHA256.HashData(mrr)));
        dpsFields[8] = U64(1041); dpsFields[9] = U64(1100); dpsFields[10] = Bytes(17, 64);
        var dps = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dps1, dpsFields),
            RecordDefinitions.Dps1);
        var response = new VerifiedNativePeerResponse(dps, mrr);

        Assert.Equal(
            CanonicalGrammar.Sha256Domain(
                "Deep/NativeRouting/V1/outer-outcome-hash", Framed(mrr, dps.CanonicalSpan)),
            OuterPeerJournal.ComputeInnerOutcomeHash(response));
    }

    private static VerifiedNativePeerRequest Request(byte requestMarker, byte prqMarker = 1)
    {
        var prq = Enumerable.Repeat(prqMarker, 32).ToArray();
        var fields = RecordDefinitions.Dpr1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        fields[0] = Bytes(1, 16);
        fields[1] = Bytes(2, 32);
        fields[2] = Bytes(3, 32);
        fields[3] = Reference(ArtifactType.Dpc1, 431, 4);
        fields[4] = Reference(ArtifactType.Dpc1, 431, 5);
        fields[5] = Bytes(requestMarker, 32);
        fields[6] = U64(1040);
        fields[7] = U64(1100);
        fields[8] = U16(1);
        fields[9] = CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Prq2, (uint)prq.Length, SHA256.HashData(prq)));
        fields[10] = Bytes(6, 64);
        var dpr = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpr1, fields),
            RecordDefinitions.Dpr1);
        var proof = new MailboxReplicaMembershipProof
        {
            ReplicaId = Bytes(1, 32), SigningPublicKey = Bytes(2, 32), Epoch = 1,
            MembershipCommitment = Bytes(3, 32), CanonicalInclusionProof = new byte[] { 1 }
        };
        var inner = new MailboxPeerWireRequestV2
        {
            Operation = MailboxPeerReplicationOperation.Tombstone,
            Epoch = 1,
            OperationId = Bytes(1, 16),
            SenderRouterId = fields[1], RecipientRouterId = fields[2],
            MembershipCommitment = Bytes(7, 32), PlacementCommitment = Bytes(8, 32),
            BlindedMailboxId = Bytes(9, 32), Cursor = 1,
            CreatedAtUnixSeconds = 1040, ExpiresAtUnixSeconds = 1100,
            ReplayNonce = fields[5], PayloadDigest = Bytes(10, 32), Payload = Bytes(11, 32),
            SenderMembershipProof = proof, RecipientMembershipProof = proof,
            Signature = Bytes(12, 64)
        };
        return new VerifiedNativePeerRequest(
            dpr, prq, inner, Bytes(13, 32), Bytes(14, 32));
    }

    private sealed class Dependencies
    {
        private readonly Store _store;
        private readonly IOuterPeerInnerExecutor _inner;
        private readonly byte[] _indexKeyId = Bytes(20, 32);
        private readonly byte[] _hmacKeyId = Bytes(21, 32);
        private readonly IndexProvider _index = new(Bytes(22, 32));
        private readonly HmacProvider _hmac = new(Bytes(23, 32));

        internal Dependencies(Store store, IOuterPeerInnerExecutor inner)
        {
            _store = store;
            _inner = inner;
        }

        internal ValueTask<OuterJournalResult> Execute(
            VerifiedNativePeerRequest request,
            ulong now) => OuterPeerJournal.ExecuteAsync(
                request, _indexKeyId, _hmacKeyId, 1200, now,
                _index, _hmac, _store, _inner, new NeverAuthorize());
    }

    private sealed class Store : IOuterJournalStore
    {
        internal OuterJournalStoredValue? Value { get; private set; }
        internal List<byte[]> CasValues { get; } = [];

        public ValueTask<OuterJournalStoredValue?> ReadAsync(
            ReadOnlyMemory<byte> journalKey32,
            CancellationToken cancellationToken = default) => ValueTask.FromResult(Value);

        public ValueTask<bool> CompareExchangeAsync(
            OuterJournalCompareExchange exchange,
            CancellationToken cancellationToken = default)
        {
            var matches = exchange.ExpectsAbsence
                ? Value is null
                : Value is not null && Value.CanonicalDpj1.Span.SequenceEqual(
                    exchange.ExpectedCanonicalDpj1.Span);
            if (matches)
            {
                Value = new OuterJournalStoredValue(
                    exchange.Replacement.CanonicalDpj1.Span,
                    exchange.Replacement.ResponseFrame.Span);
                CasValues.Add(Value.CanonicalDpj1.ToArray());
            }
            return ValueTask.FromResult(matches);
        }

        internal void Mutate(int offset)
        {
            var bytes = Value!.CanonicalDpj1.ToArray();
            bytes[offset] ^= 1;
            Value = new OuterJournalStoredValue(bytes, Value.ResponseFrame.Span);
        }
    }

    private sealed class IndexProvider(byte[] key) : IOuterJournalIndexProvider
    {
        public ValueTask<ReadOnlyMemory<byte>> ComputeIndexAsync(
            OuterJournalIndexRequest request,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>>(
                HMACSHA256.HashData(key, request.Transcript.Span));
    }

    private sealed class HmacProvider(byte[] key) : IProtectedHmacProvider
    {
        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            var domain = Encoding.ASCII.GetBytes(request.Domain);
            var input = new byte[2 + domain.Length + 2 + 4 + request.UnsignedCanonical.Length];
            BinaryPrimitives.WriteUInt16BigEndian(input, (ushort)domain.Length);
            domain.CopyTo(input, 2);
            var offset = 2 + domain.Length;
            BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset), request.Suite);
            BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(offset + 2),
                (uint)request.UnsignedCanonical.Length);
            request.UnsignedCanonical.Span.CopyTo(input.AsSpan(offset + 6));
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(HMACSHA256.HashData(key, input));
        }
    }

    private class CountingInner : IOuterPeerInnerExecutor
    {
        internal int FreshCalls;
        internal int ReplayCalls;
        public virtual ValueTask<ReadOnlyMemory<byte>> ExecuteFreshAsync(
            VerifiedNativePeerRequest request,
            CancellationToken cancellationToken = default)
        {
            FreshCalls++;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(Array.Empty<byte>());
        }
        public virtual ValueTask<ReadOnlyMemory<byte>> ReplayExactAsync(
            VerifiedNativePeerRequest request,
            CancellationToken cancellationToken = default)
        {
            ReplayCalls++;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(Array.Empty<byte>());
        }
    }

    private sealed class CrashingInner : CountingInner
    {
        public override ValueTask<ReadOnlyMemory<byte>> ExecuteFreshAsync(
            VerifiedNativePeerRequest request,
            CancellationToken cancellationToken = default)
        {
            base.ExecuteFreshAsync(request, cancellationToken);
            throw new CrashException();
        }
        public override ValueTask<ReadOnlyMemory<byte>> ReplayExactAsync(
            VerifiedNativePeerRequest request,
            CancellationToken cancellationToken = default)
        {
            base.ReplayExactAsync(request, cancellationToken);
            throw new CrashException();
        }
    }

    private sealed class NeverAuthorize : IOuterPeerDeliveryAuthorizer
    {
        public ValueTask<bool> RecheckAsync(
            VerifiedNativePeerRequest request,
            VerifiedNativePeerResponse response,
            ulong transactionTimeUnixSeconds,
            CancellationToken cancellationToken = default) => ValueTask.FromResult(false);
    }

    private sealed class CrashException : Exception;

    private static byte[] Reference(ArtifactType type, uint length, byte marker)
    {
        var result = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(result, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(2), length);
        result[6] = marker;
        return result;
    }
    private static byte[] Framed(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var result = new byte[8 + first.Length + second.Length];
        BinaryPrimitives.WriteUInt32BigEndian(result, (uint)first.Length);
        first.CopyTo(result.AsSpan(4));
        var offset = 4 + first.Length;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset), (uint)second.Length);
        second.CopyTo(result.AsSpan(offset + 4));
        return result;
    }
    private static byte[] Bytes(byte value, int length) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
}
