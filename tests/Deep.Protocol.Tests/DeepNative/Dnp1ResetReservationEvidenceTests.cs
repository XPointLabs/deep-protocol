using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

public sealed class ResetReservationEvidenceTests
{
    [Fact]
    public async Task DurableReplay_RestoresOneExactIndexAndReservationWithoutSecondMint()
    {
        var request = Request(1);
        var provider = new DurableProvider();
        var hmac = new MarkerHmac();

        var first = await GenesisReservationVerifier.RestoreResetAsync(
            provider, request, hmac, default);
        var replay = await GenesisReservationVerifier.RestoreResetAsync(
            provider, request, hmac, default);

        Assert.Equal(1, provider.Mutations);
        Assert.Equal(2, provider.Calls);
        Assert.Equal(first.OperationId.ToArray(), replay.OperationId.ToArray());
        Assert.Equal(first.ResetId.ToArray(), replay.ResetId.ToArray());
        Assert.Equal(first.ReservationHash.ToArray(), replay.ReservationHash.ToArray());
        Assert.Equal(first.SourceRevision, replay.SourceRevision);
        Assert.Equal(2, hmac.Domains.Count(static value => value.EndsWith("GRI1")));
        Assert.Equal(2, hmac.Domains.Count(static value => value.EndsWith("GRR1")));
    }

    [Fact]
    public async Task ProviderReturnCrash_RestoresPersistedIdsWithoutSecondMint()
    {
        var request = Request(1);
        var provider = new DurableProvider { ThrowAfterFirstStore = true };

        await Assert.ThrowsAsync<IOException>(() =>
            GenesisReservationVerifier.RestoreResetAsync(
                provider, request, new MarkerHmac(), default).AsTask());

        var replay = await GenesisReservationVerifier.RestoreResetAsync(
            provider, request, new MarkerHmac(), default);
        Assert.Equal(1, provider.Mutations);
        Assert.Equal(2, provider.Calls);
        Assert.Equal(Fill(0x51, 32), replay.OperationId.ToArray());
        Assert.Equal(Fill(0x52, 32), replay.ResetId.ToArray());
    }

    [Fact]
    public async Task CancellationAfterStore_RetainsExactReservationForFreshReplay()
    {
        var request = Request(1);
        using var cancellation = new CancellationTokenSource();
        var provider = new DurableProvider { CancelAfterFirstStore = cancellation };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            GenesisReservationVerifier.RestoreResetAsync(
                provider, request, new MarkerHmac(), cancellation.Token).AsTask());

        var replay = await GenesisReservationVerifier.RestoreResetAsync(
            provider, request, new MarkerHmac(), default);
        Assert.Equal(1, provider.Mutations);
        Assert.Equal(2, provider.Calls);
        Assert.Equal(Fill(0x51, 32), replay.OperationId.ToArray());
        Assert.Equal(Fill(0x52, 32), replay.ResetId.ToArray());
        Assert.DoesNotContain(typeof(GenesisResetReservationProvider).GetMethods(), method =>
            method.Name.Contains("Delete", StringComparison.OrdinalIgnoreCase) ||
            method.Name.Contains("Release", StringComparison.OrdinalIgnoreCase) ||
            method.Name.Contains("Reuse", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ForkNoReuse_LatchesChangedIntentSecondIdOrphanRollbackAndOldIdReuse()
    {
        await ChangedIntent();
        foreach (var corruption in Enum.GetValues<StoredCorruption>())
            await CorruptStored(corruption);

        static async Task ChangedIntent()
        {
            var original = Request(1);
            var provider = new DurableProvider();
            await GenesisReservationVerifier.RestoreResetAsync(
                provider, original, new MarkerHmac(), default);
            var intent = original.Intent.ToArray();
            intent[49] ^= 1;
            var changed = new GenesisResetReservationRequest(intent, original.LogicalKey.Span);

            var before = provider.Mutations;
            await Assert.ThrowsAsync<RecordException>(() =>
                GenesisReservationVerifier.RestoreResetAsync(
                    provider, changed, new MarkerHmac(), default).AsTask());
            Assert.Equal(before + 1, provider.Mutations);
            Assert.True(provider.ForkLatched);
            Assert.Equal(1, provider.RowCount);
            await Assert.ThrowsAsync<RecordException>(() =>
                GenesisReservationVerifier.RestoreResetAsync(
                    provider, original, new MarkerHmac(), default).AsTask());
            Assert.Equal(before + 1, provider.Mutations);
        }

        static async Task CorruptStored(StoredCorruption corruption)
        {
            var request = Request(corruption == StoredCorruption.OldResetIdReuse
                ? (byte)2
                : (byte)1);
            var provider = new DurableProvider();
            await GenesisReservationVerifier.RestoreResetAsync(
                provider, request, new MarkerHmac(), default);
            provider.Corrupt(corruption, request);
            var before = provider.Mutations;

            await Assert.ThrowsAsync<RecordException>(() =>
                GenesisReservationVerifier.RestoreResetAsync(
                    provider, request, new MarkerHmac(), default).AsTask());
            Assert.Equal(before + 1, provider.Mutations);
            Assert.True(provider.ForkLatched);
            Assert.InRange(provider.RowCount, 0, 1);
        }
    }

    private static GenesisResetReservationRequest Request(byte mode)
    {
        var intent = new byte[235];
        intent[0] = mode;
        Fill(0x21, 16).CopyTo(intent, 1);
        Fill(0x22, 32).CopyTo(intent, 49);
        U64(intent, 81, mode == 1 ? 1UL : 2UL);
        Dpa(0x23).CopyTo(intent, 127);
        if (mode == 1)
        {
            var logical = new byte[49];
            logical[0] = 1;
            intent.AsSpan(1, 16).CopyTo(logical.AsSpan(1));
            Fill(0x24, 32).CopyTo(logical, 17);
            return new GenesisResetReservationRequest(intent, logical);
        }

        Fill(0x25, 32).CopyTo(intent, 17);
        Dpa(0x26).CopyTo(intent, 89);
        Fill(0x27, 32).CopyTo(intent, 203);
        var resetLogical = new byte[57];
        resetLogical[0] = 2;
        intent.AsSpan(1, 16).CopyTo(resetLogical.AsSpan(1));
        U64(resetLogical, 17, 1);
        intent.AsSpan(17, 32).CopyTo(resetLogical.AsSpan(25));
        return new GenesisResetReservationRequest(intent, resetLogical);
    }

    private static byte[] Dpa(byte marker) => CanonicalGrammar.EncodeReference(
        new ArtifactReference(ArtifactType.Dpa1, 1, Fill(marker, 32)));

    private static byte[] Fill(byte marker, int length) =>
        Enumerable.Repeat(marker, length).ToArray();

    private static void U64(byte[] value, int offset, ulong number) =>
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(offset, 8), number);

    private enum StoredCorruption
    {
        SecondResetId,
        OrphanIndex,
        RevisionRollback,
        OldResetIdReuse
    }

    private sealed class DurableProvider : GenesisResetReservationProvider
    {
        private byte[]? _gri;
        private byte[]? _grr;
        private byte[]? _baselineGri;
        private byte[]? _baselineGrr;
        private byte[]? _scopeHash;
        private byte[]? _intentHash;
        private bool _crashDelivered;

        internal int Calls { get; private set; }
        internal int Mutations { get; private set; }
        internal bool ForkLatched { get; private set; }
        internal int RowCount => _gri is null || _grr is null ? 0 : 1;
        internal bool ThrowAfterFirstStore { get; init; }
        internal CancellationTokenSource? CancelAfterFirstStore { get; init; }

        public override ValueTask<GenesisResetReservationReadResult> RestoreOrReserveAsync(
            GenesisResetReservationRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            if (ForkLatched)
                return ValueTask.FromResult(new GenesisResetReservationReadResult([], [], false));

            if (_gri is null && _grr is null)
            {
                Create(request);
                Mutations++;
                CancelAfterFirstStore?.Cancel();
                if (ThrowAfterFirstStore && !_crashDelivered)
                {
                    _crashDelivered = true;
                    throw new IOException("Simulated loss of the provider response after fsync.");
                }
            }
            else if (_gri is null || _grr is null ||
                     !_gri.AsSpan().SequenceEqual(_baselineGri) ||
                     !_grr.AsSpan().SequenceEqual(_baselineGrr) ||
                     !_scopeHash!.AsSpan().SequenceEqual(request.LogicalScopeHash.Span) ||
                     !_intentHash!.AsSpan().SequenceEqual(request.IntentHash.Span))
            {
                ForkLatched = true;
                Mutations++;
                return ValueTask.FromResult(new GenesisResetReservationReadResult([], [], false));
            }

            return ValueTask.FromResult(new GenesisResetReservationReadResult(_gri, _grr, true));
        }

        internal void Corrupt(StoredCorruption corruption, GenesisResetReservationRequest request)
        {
            switch (corruption)
            {
                case StoredCorruption.SecondResetId:
                    _grr![275] ^= 1;
                    break;
                case StoredCorruption.OrphanIndex:
                    _gri = null;
                    break;
                case StoredCorruption.RevisionRollback:
                    U64(_gri!, 136, 6);
                    U64(_grr!, 308, 6);
                    break;
                case StoredCorruption.OldResetIdReuse:
                    request.Intent.Span.Slice(203, 32).CopyTo(_grr!.AsSpan(275, 32));
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(corruption));
            }
        }

        private void Create(GenesisResetReservationRequest request)
        {
            _scopeHash = request.LogicalScopeHash.ToArray();
            _intentHash = request.IntentHash.ToArray();
            _grr = new byte[GenesisProtectedRecords.GrrLength];
            "GRR1"u8.CopyTo(_grr); _grr[4] = 1;
            request.Intent.Span.CopyTo(_grr.AsSpan(8));
            Fill(0x51, 32).CopyTo(_grr, 243);
            Fill(0x52, 32).CopyTo(_grr, 275);
            _grr[307] = 1; U64(_grr, 308, 7);
            Fill(0x53, 32).CopyTo(_grr, 317);
            Fill(0x54, 32).CopyTo(_grr, 349);

            _gri = new byte[GenesisProtectedRecords.GriLength];
            "GRI1"u8.CopyTo(_gri); _gri[4] = 1;
            _scopeHash.CopyTo(_gri, 8); _intentHash.CopyTo(_gri, 40);
            _grr.AsSpan(243, 32).CopyTo(_gri.AsSpan(72));
            GenesisProtectedRecords.ReservationHash(_grr).CopyTo(_gri, 104);
            U64(_gri, 136, 7); U64(_gri, 144, 900);
            _grr.AsSpan(317, 32).CopyTo(_gri.AsSpan(153));
            Fill(0x55, 32).CopyTo(_gri, 185);
            _baselineGri = _gri.ToArray();
            _baselineGrr = _grr.ToArray();
        }
    }

    private sealed class MarkerHmac : IProtectedHmacProvider
    {
        internal List<string> Domains { get; } = [];

        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Domains.Add(request.Domain);
            var marker = request.Domain.EndsWith("GRI1", StringComparison.Ordinal)
                ? (byte)0x55
                : (byte)0x54;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(Fill(marker, 32));
        }
    }
}
