using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

public enum OuterJournalDisposition
{
    Delivered,
    CompletedNotAuthorized,
    TerminalStale,
    ForkLatched
}

/// <summary>An owned protected lookup transcript. It never exposes the journal index key.</summary>
public sealed class OuterJournalIndexRequest
{
    private readonly byte[] _keyId;
    private readonly byte[] _transcript;

    internal OuterJournalIndexRequest(
        ReadOnlySpan<byte> keyId,
        ReadOnlySpan<byte> transcript)
    {
        _keyId = keyId.ToArray();
        _transcript = transcript.ToArray();
    }

    public string Domain => "Deep/NativeRouting/V1/outer-journal-key";
    public ReadOnlyMemory<byte> ProtectedIndexKeyId => _keyId.ToArray();
    public ReadOnlyMemory<byte> Transcript => _transcript.ToArray();
    public bool ContainsNoRawKey => true;
}

public interface IOuterJournalIndexProvider
{
    ValueTask<ReadOnlyMemory<byte>> ComputeIndexAsync(
        OuterJournalIndexRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// One defensively owned store value. Completed values include the exact response frame;
/// earlier phases must not. This is a storage observation, not a durability claim.
/// </summary>
public sealed class OuterJournalStoredValue
{
    private readonly byte[] _canonicalDpj1;
    private readonly byte[] _responseFrame;

    public OuterJournalStoredValue(
        ReadOnlySpan<byte> canonicalDpj1,
        ReadOnlySpan<byte> responseFrame = default)
    {
        if (canonicalDpj1.Length != 609)
            throw new RecordException(
                RecordError.InvalidLength,
                "A DPJ1 store value must contain exactly 609 canonical bytes.");
        _canonicalDpj1 = canonicalDpj1.ToArray();
        _responseFrame = responseFrame.ToArray();
    }

    public ReadOnlyMemory<byte> CanonicalDpj1 => _canonicalDpj1.ToArray();
    public ReadOnlyMemory<byte> ResponseFrame => _responseFrame.ToArray();
    public bool NoDurabilityClaim => true;
}

/// <summary>An exact compare/exchange request. Null expected bytes mean absence.</summary>
public sealed class OuterJournalCompareExchange
{
    private readonly byte[] _journalKey;
    private readonly byte[]? _expected;

    internal OuterJournalCompareExchange(
        ReadOnlyMemory<byte> journalKey,
        byte[]? expected,
        OuterJournalStoredValue replacement)
    {
        _journalKey = journalKey.ToArray();
        _expected = expected?.ToArray();
        Replacement = replacement;
    }

    public ReadOnlyMemory<byte> JournalKey => _journalKey.ToArray();
    public bool ExpectsAbsence => _expected is null;
    public ReadOnlyMemory<byte> ExpectedCanonicalDpj1 =>
        _expected?.ToArray() ?? Array.Empty<byte>();
    public OuterJournalStoredValue Replacement { get; }
    public bool NoDurabilityClaim => true;
}

public interface IOuterJournalStore
{
    ValueTask<OuterJournalStoredValue?> ReadAsync(
        ReadOnlyMemory<byte> journalKey32,
        CancellationToken cancellationToken = default);

    ValueTask<bool> CompareExchangeAsync(
        OuterJournalCompareExchange exchange,
        CancellationToken cancellationToken = default);
}

public interface IOuterPeerInnerExecutor
{
    ValueTask<ReadOnlyMemory<byte>> ExecuteFreshAsync(
        VerifiedNativePeerRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<ReadOnlyMemory<byte>> ReplayExactAsync(
        VerifiedNativePeerRequest request,
        CancellationToken cancellationToken = default);
}

public interface IOuterPeerDeliveryAuthorizer
{
    ValueTask<bool> RecheckAsync(
        VerifiedNativePeerRequest request,
        VerifiedNativePeerResponse response,
        ulong transactionTimeUnixSeconds,
        CancellationToken cancellationToken = default);
}

public sealed class OuterJournalResult
{
    private readonly byte[] _canonicalDpj1;
    private readonly byte[] _responseFrame;

    internal OuterJournalResult(
        OuterJournalDisposition disposition,
        ReadOnlySpan<byte> canonicalDpj1,
        ReadOnlySpan<byte> responseFrame)
    {
        Disposition = disposition;
        _canonicalDpj1 = canonicalDpj1.ToArray();
        _responseFrame = responseFrame.ToArray();
    }

    public OuterJournalDisposition Disposition { get; }
    public ReadOnlyMemory<byte> CanonicalDpj1 => _canonicalDpj1.ToArray();
    public ReadOnlyMemory<byte> ResponseFrame => _responseFrame.ToArray();
    public bool DeliveryAuthorized => Disposition == OuterJournalDisposition.Delivered;
    public bool NoDurabilityClaim => true;
}

/// <summary>
/// Relative DPJ1 coordinator. Every trusted row is HMAC-verified, transitions use exact-byte
/// compare/exchange, and a store/provider response never creates a durability claim.
/// </summary>
public static class OuterPeerJournal
{
    private const string IndexDomain = "Deep/NativeRouting/V1/outer-journal-key";
    private const string RequestHashDomain = "Deep/NativeRouting/V1/outer-request-hash";
    private const string OutcomeHashDomain = "Deep/NativeRouting/V1/outer-outcome-hash";
    private const string ProtectedDomain = "Deep/ProtectedState/V1/DPJ1";
    private const int MaximumCasAttempts = 8;

    public static async ValueTask<OuterJournalResult> ExecuteAsync(
        VerifiedNativePeerRequest request,
        ReadOnlyMemory<byte> journalIndexKeyId32,
        ReadOnlyMemory<byte> protectedStateKeyId32,
        ulong retainedUntilUnixSeconds,
        ulong transactionTimeUnixSeconds,
        IOuterJournalIndexProvider indexProvider,
        IProtectedHmacProvider hmacProvider,
        IOuterJournalStore store,
        IOuterPeerInnerExecutor inner,
        IOuterPeerDeliveryAuthorizer deliveryAuthorizer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(indexProvider);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(deliveryAuthorizer);
        ValidateKeyId(journalIndexKeyId32.Span, "journal index");
        ValidateKeyId(protectedStateKeyId32.Span, "protected state");
        if (retainedUntilUnixSeconds < request.ExpiresAtUnixSeconds)
            Invalid(RecordError.InvalidField, "DPJ1 retention ends before request expiry.");

        var dpr = CanonicalGrammar.DecodeOwned(
            request.TrustedDpr, RecordDefinitions.Dpr1);
        var indexTranscript = CreateIndexTranscript(
            dpr.FieldSpan(1), dpr.FieldSpan(2), dpr.FieldSpan(3), dpr.FieldSpan(6));
        var returnedIndex = await indexProvider.ComputeIndexAsync(
            new OuterJournalIndexRequest(journalIndexKeyId32.Span, indexTranscript),
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var journalKey = returnedIndex.ToArray();
        if (journalKey.Length != 32 || CanonicalGrammar.IsZero(journalKey))
            Invalid(RecordError.InvalidField, "The DPJ1 journal index result is invalid.");

        var requestHash = ComputeRequestHash(request.TrustedDpr, request.TrustedPrq);
        var requestDprReference = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dpr1, request.TrustedDpr));
        var requestPrqReference = EncodeRetainedReference(ArtifactType.Prq2, request.TrustedPrq);

        OuterJournalStoredValue current;
        var inserted = false;
        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var observed = await store.ReadAsync(journalKey, cancellationToken).ConfigureAwait(false);
            if (observed is not null)
            {
                current = observed;
                break;
            }
            var prepared = await AuthorAsync(
                CreateFields(
                    dpr, journalKey, requestDprReference, requestPrqReference,
                    retainedUntilUnixSeconds, JournalPhase.Prepared,
                    deliveryAuthorized: false, terminalStale: false, forkLatch: false,
                    requestHash, default, default, default),
                protectedStateKeyId32,
                hmacProvider,
                cancellationToken).ConfigureAwait(false);
            var preparedValue = new OuterJournalStoredValue(prepared);
            if (await store.CompareExchangeAsync(
                    new OuterJournalCompareExchange(journalKey, null, preparedValue),
                    cancellationToken).ConfigureAwait(false))
            {
                current = preparedValue;
                inserted = true;
                break;
            }
            if (attempt + 1 >= MaximumCasAttempts)
                Invalid(RecordError.InvalidTransition, "The DPJ1 insert CAS did not converge.");
        }

        for (var attempt = 0; attempt < MaximumCasAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var verified = await VerifyStoredAsync(
                current, journalKey, protectedStateKeyId32, hmacProvider, cancellationToken)
                .ConfigureAwait(false);

            if (verified.TerminalStale)
                return Result(OuterJournalDisposition.TerminalStale, current);
            if (!Fixed(verified.Record.FieldSpan(14), requestHash))
            {
                if (verified.ForkLatched)
                    return Result(OuterJournalDisposition.ForkLatched, current);
                var forked = await RewriteLatchesAsync(
                    verified.Record, delivery: verified.DeliveryAuthorized, stale: false, fork: true,
                    protectedStateKeyId32, hmacProvider, cancellationToken).ConfigureAwait(false);
                if (await CasAsync(store, journalKey, current, forked, cancellationToken).ConfigureAwait(false))
                    return new OuterJournalResult(
                        OuterJournalDisposition.ForkLatched, forked, current.ResponseFrame.Span);
                current = await RequireReadAsync(store, journalKey, cancellationToken).ConfigureAwait(false);
                inserted = false;
                continue;
            }
            BindExactRequest(
                verified.Record, dpr, journalKey, requestDprReference, requestPrqReference,
                retainedUntilUnixSeconds);
            if (verified.ForkLatched)
                return Result(OuterJournalDisposition.ForkLatched, current);

            if (!verified.DeliveryAuthorized && transactionTimeUnixSeconds >= request.ExpiresAtUnixSeconds)
            {
                var stale = await RewriteLatchesAsync(
                    verified.Record, delivery: false, stale: true, fork: false,
                    protectedStateKeyId32, hmacProvider, cancellationToken).ConfigureAwait(false);
                if (await CasAsync(store, journalKey, current, stale, cancellationToken).ConfigureAwait(false))
                    return new OuterJournalResult(
                        OuterJournalDisposition.TerminalStale, stale, ReadOnlySpan<byte>.Empty);
                current = await RequireReadAsync(store, journalKey, cancellationToken).ConfigureAwait(false);
                inserted = false;
                continue;
            }

            ReadOnlyMemory<byte> responseFrame;
            if (verified.Phase == JournalPhase.Completed)
            {
                responseFrame = current.ResponseFrame;
            }
            else if (inserted && verified.Phase == JournalPhase.Prepared)
            {
                responseFrame = await inner.ExecuteFreshAsync(request, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                if (verified.Phase == JournalPhase.Prepared)
                {
                    var pending = await RewritePhaseAsync(
                        verified.Record, JournalPhase.InnerPending,
                        protectedStateKeyId32, hmacProvider, cancellationToken).ConfigureAwait(false);
                    if (!await CasAsync(store, journalKey, current, pending, cancellationToken).ConfigureAwait(false))
                    {
                        current = await RequireReadAsync(store, journalKey, cancellationToken).ConfigureAwait(false);
                        inserted = false;
                        continue;
                    }
                    current = new OuterJournalStoredValue(pending);
                }
                responseFrame = await inner.ReplayExactAsync(request, cancellationToken).ConfigureAwait(false);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var ownedResponse = responseFrame.ToArray();
            var response = NativePeerVerifier.VerifyResponse(
                ownedResponse, request, transactionTimeUnixSeconds);
            var outcomeHash = ComputeOutcomeHash(response.CanonicalMrr2.Span, response.CanonicalDps1.Span);
            if (verified.Phase != JournalPhase.Completed)
            {
                var completed = await RewriteCompletedAsync(
                    verified.Record, response, outcomeHash,
                    protectedStateKeyId32, hmacProvider, cancellationToken).ConfigureAwait(false);
                var replacement = new OuterJournalStoredValue(completed, ownedResponse);
                if (!await store.CompareExchangeAsync(
                        new OuterJournalCompareExchange(
                            journalKey, current.CanonicalDpj1.ToArray(), replacement),
                        cancellationToken).ConfigureAwait(false))
                {
                    current = await RequireReadAsync(store, journalKey, cancellationToken).ConfigureAwait(false);
                    inserted = false;
                    continue;
                }
                current = replacement;
                verified = await VerifyStoredAsync(
                    current, journalKey, protectedStateKeyId32, hmacProvider, cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                VerifyCompletedOutcome(verified.Record, response, outcomeHash);
            }

            if (verified.DeliveryAuthorized)
                return Result(OuterJournalDisposition.Delivered, current);
            if (!await deliveryAuthorizer.RecheckAsync(
                    request, response, transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false))
                return Result(OuterJournalDisposition.CompletedNotAuthorized, current, includeResponse: false);
            cancellationToken.ThrowIfCancellationRequested();
            var authorized = await RewriteLatchesAsync(
                verified.Record, delivery: true, stale: false, fork: false,
                protectedStateKeyId32, hmacProvider, cancellationToken).ConfigureAwait(false);
            var authorizedValue = new OuterJournalStoredValue(authorized, current.ResponseFrame.Span);
            if (await store.CompareExchangeAsync(
                    new OuterJournalCompareExchange(
                        journalKey, current.CanonicalDpj1.ToArray(), authorizedValue),
                    cancellationToken).ConfigureAwait(false))
                return Result(OuterJournalDisposition.Delivered, authorizedValue);
            current = await RequireReadAsync(store, journalKey, cancellationToken).ConfigureAwait(false);
            inserted = false;
        }
        Invalid(RecordError.InvalidTransition, "The DPJ1 transition CAS did not converge.");
        throw new InvalidOperationException("Unreachable DPJ1 transition state.");
    }

    public static byte[] ComputeCanonicalRequestHash(
        VerifiedNativePeerRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ComputeRequestHash(request.TrustedDpr, request.TrustedPrq);
    }

    public static byte[] ComputeInnerOutcomeHash(
        VerifiedNativePeerResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        return ComputeOutcomeHash(response.CanonicalMrr2.Span, response.CanonicalDps1.Span);
    }

    private static async ValueTask<VerifiedRow> VerifyStoredAsync(
        OuterJournalStoredValue stored,
        ReadOnlyMemory<byte> journalKey,
        ReadOnlyMemory<byte> protectedStateKeyId,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        var record = CanonicalGrammar.DecodeOwned(
            stored.CanonicalDpj1.Span, RecordDefinitions.Dpj1);
        if (!Fixed(record.FieldSpan(5), journalKey.Span))
            Invalid(RecordError.InvalidField, "DPJ1 journal key mismatch.");
        if (CanonicalGrammar.IsZero(record.FieldSpan(14)))
            Invalid(RecordError.InvalidField, "DPJ1 request hash is zero.");
        if (!CanonicalGrammar.IsZero(record.FieldSpan(20)))
            Invalid(RecordError.InvalidField, "DPJ1 reserved bytes are nonzero.");
        var delivery = Bool(record.FieldSpan(12), "delivery");
        var stale = Bool(record.FieldSpan(13), "stale");
        var fork = Bool(record.FieldSpan(19), "fork");
        var phase = (JournalPhase)record.FieldSpan(11)[0];
        if (phase is < JournalPhase.Prepared or > JournalPhase.Completed)
            Invalid(RecordError.InvalidField, "DPJ1 phase is unknown.");
        if (Scalars.UInt64(record.FieldSpan(9)) == 0 ||
            Scalars.UInt64(record.FieldSpan(9)) >= Scalars.UInt64(record.FieldSpan(10)) ||
            Scalars.UInt64(record.FieldSpan(18)) < Scalars.UInt64(record.FieldSpan(10)))
            Invalid(RecordError.InvalidField, "DPJ1 time or retention fields are invalid.");
        var unsigned = EncodeUnsigned(record);
        var computed = await provider.ComputeTagAsync(
            new ProtectedHmacRequest(
                ProtectedDomain, ArtifactRegistry.ProtectedHmacSha256,
                protectedStateKeyId.Span, unsigned),
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var ownedTag = computed.ToArray();
        if (ownedTag.Length != 32 || !Fixed(ownedTag, record.FieldSpan(21)))
            Invalid(RecordError.InvalidSignature, "The DPJ1 protected HMAC is invalid.");
        if (phase == JournalPhase.Completed)
        {
            if (stored.ResponseFrame.Length != NativePeerVerifier.ResponseLength)
                Invalid(RecordError.InvalidLength, "Completed DPJ1 has no exact response frame.");
        }
        else if (!stored.ResponseFrame.IsEmpty)
        {
            Invalid(RecordError.InvalidField, "Pending DPJ1 contains response bytes.");
        }
        return new VerifiedRow(record, phase, delivery, stale, fork);
    }

    private static async ValueTask<byte[]> AuthorAsync(
        ReadOnlyMemory<byte>[] fields,
        ReadOnlyMemory<byte> protectedStateKeyId,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        fields[20] = new byte[32];
        var pending = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpj1, fields),
            RecordDefinitions.Dpj1);
        var unsigned = EncodeUnsigned(pending);
        var returned = await provider.ComputeTagAsync(
            new ProtectedHmacRequest(
                ProtectedDomain, ArtifactRegistry.ProtectedHmacSha256,
                protectedStateKeyId.Span, unsigned),
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var tag = returned.ToArray();
        if (tag.Length != 32)
            Invalid(RecordError.InvalidSignature, "The DPJ1 HMAC provider returned an invalid tag.");
        fields[20] = tag;
        return CanonicalGrammar.Encode(RecordDefinitions.Dpj1, fields);
    }

    private static ReadOnlyMemory<byte>[] CreateFields(
        OwnedRecord dpr,
        ReadOnlySpan<byte> journalKey,
        ReadOnlySpan<byte> dprReference,
        ReadOnlySpan<byte> prqReference,
        ulong retainedUntil,
        JournalPhase phase,
        bool deliveryAuthorized,
        bool terminalStale,
        bool forkLatch,
        ReadOnlySpan<byte> requestHash,
        ReadOnlyMemory<byte> outcomeHash,
        ReadOnlySpan<byte> dpsReference,
        ReadOnlySpan<byte> mrrReference) =>
    [
        dpr.FieldCopy(1), dpr.FieldCopy(2), dpr.FieldCopy(3), dpr.FieldCopy(6),
        journalKey.ToArray(), dprReference.ToArray(), prqReference.ToArray(), U16(1),
        dpr.FieldCopy(7), dpr.FieldCopy(8), new[] { (byte)phase },
        new[] { deliveryAuthorized ? (byte)1 : (byte)0 },
        new[] { terminalStale ? (byte)1 : (byte)0 }, requestHash.ToArray(),
        outcomeHash.IsEmpty ? new byte[32] : outcomeHash.ToArray(),
        dpsReference.IsEmpty ? new byte[38] : dpsReference.ToArray(),
        mrrReference.IsEmpty ? new byte[38] : mrrReference.ToArray(),
        U64(retainedUntil), new[] { forkLatch ? (byte)1 : (byte)0 }, new byte[7], new byte[32]
    ];

    private static async ValueTask<byte[]> RewritePhaseAsync(
        OwnedRecord record,
        JournalPhase phase,
        ReadOnlyMemory<byte> keyId,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        var fields = CopyFields(record);
        fields[10] = new[] { (byte)phase };
        return await AuthorAsync(fields, keyId, provider, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]> RewriteCompletedAsync(
        OwnedRecord record,
        VerifiedNativePeerResponse response,
        ReadOnlyMemory<byte> outcomeHash,
        ReadOnlyMemory<byte> keyId,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        var fields = CopyFields(record);
        fields[10] = new[] { (byte)JournalPhase.Completed };
        fields[14] = outcomeHash.ToArray();
        fields[15] = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(
                ArtifactType.Dps1, response.CanonicalDps1.Span));
        fields[16] = EncodeRetainedReference(ArtifactType.Mrr2, response.CanonicalMrr2.Span);
        return await AuthorAsync(fields, keyId, provider, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]> RewriteLatchesAsync(
        OwnedRecord record,
        bool delivery,
        bool stale,
        bool fork,
        ReadOnlyMemory<byte> keyId,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        var fields = CopyFields(record);
        fields[11] = new[] { delivery ? (byte)1 : (byte)0 };
        fields[12] = new[] { stale ? (byte)1 : (byte)0 };
        fields[18] = new[] { fork ? (byte)1 : (byte)0 };
        return await AuthorAsync(fields, keyId, provider, cancellationToken).ConfigureAwait(false);
    }

    private static void VerifyCompletedOutcome(
        OwnedRecord record,
        VerifiedNativePeerResponse response,
        ReadOnlySpan<byte> outcomeHash)
    {
        if (!Fixed(record.FieldSpan(15), outcomeHash) ||
            !Fixed(record.FieldSpan(16), CanonicalGrammar.EncodeReference(
                CanonicalGrammar.ComputeReference(
                    ArtifactType.Dps1, response.CanonicalDps1.Span))) ||
            !Fixed(record.FieldSpan(17), EncodeRetainedReference(
                ArtifactType.Mrr2, response.CanonicalMrr2.Span)))
            Invalid(RecordError.ForkDetected, "The completed DPJ1 outcome bytes differ.");
    }

    private static void BindExactRequest(
        OwnedRecord row,
        OwnedRecord dpr,
        ReadOnlySpan<byte> journalKey,
        ReadOnlySpan<byte> dprReference,
        ReadOnlySpan<byte> prqReference,
        ulong retainedUntil)
    {
        if (!Fixed(row.FieldSpan(1), dpr.FieldSpan(1)) ||
            !Fixed(row.FieldSpan(2), dpr.FieldSpan(2)) ||
            !Fixed(row.FieldSpan(3), dpr.FieldSpan(3)) ||
            !Fixed(row.FieldSpan(4), dpr.FieldSpan(6)) ||
            !Fixed(row.FieldSpan(5), journalKey) ||
            !Fixed(row.FieldSpan(6), dprReference) ||
            !Fixed(row.FieldSpan(7), prqReference) ||
            BinaryPrimitives.ReadUInt16BigEndian(row.FieldSpan(8)) != 1 ||
            !Fixed(row.FieldSpan(9), dpr.FieldSpan(7)) ||
            !Fixed(row.FieldSpan(10), dpr.FieldSpan(8)) ||
            Scalars.UInt64(row.FieldSpan(18)) != retainedUntil)
            Invalid(RecordError.ForkDetected, "The DPJ1 bound request tuple differs.");
    }

    private static byte[] ComputeRequestHash(ReadOnlySpan<byte> dpr, ReadOnlySpan<byte> prq)
    {
        var payload = new byte[8 + dpr.Length + prq.Length];
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(0, 4), checked((uint)dpr.Length));
        dpr.CopyTo(payload.AsSpan(4));
        var offset = 4 + dpr.Length;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(offset, 4), checked((uint)prq.Length));
        prq.CopyTo(payload.AsSpan(offset + 4));
        return CanonicalGrammar.Sha256Domain(RequestHashDomain, payload);
    }

    private static byte[] ComputeOutcomeHash(ReadOnlySpan<byte> mrr, ReadOnlySpan<byte> dps)
    {
        var payload = new byte[8 + mrr.Length + dps.Length];
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(0, 4), checked((uint)mrr.Length));
        mrr.CopyTo(payload.AsSpan(4));
        var offset = 4 + mrr.Length;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(offset, 4), checked((uint)dps.Length));
        dps.CopyTo(payload.AsSpan(offset + 4));
        return CanonicalGrammar.Sha256Domain(OutcomeHashDomain, payload);
    }

    private static byte[] CreateIndexTranscript(
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> sender,
        ReadOnlySpan<byte> recipient,
        ReadOnlySpan<byte> requestId)
    {
        var domain = System.Text.Encoding.ASCII.GetBytes(IndexDomain);
        var output = new byte[2 + domain.Length + 16 + 32 + 32 + 32];
        BinaryPrimitives.WriteUInt16BigEndian(output, checked((ushort)domain.Length));
        domain.CopyTo(output.AsSpan(2));
        var offset = 2 + domain.Length;
        network.CopyTo(output.AsSpan(offset, 16));
        sender.CopyTo(output.AsSpan(offset + 16, 32));
        recipient.CopyTo(output.AsSpan(offset + 48, 32));
        requestId.CopyTo(output.AsSpan(offset + 80, 32));
        return output;
    }

    private static byte[] EncodeUnsigned(OwnedRecord record)
    {
        var definition = record.Definition with
        {
            Fields = record.Definition.Fields.Take(20).ToArray(),
            OmittedSigningFieldIndexes = new HashSet<int>(),
            MinimumLength = 12,
            MaximumLength = 609
        };
        return CanonicalGrammar.Encode(
            definition,
            Enumerable.Range(1, 20)
                .Select(tag => (ReadOnlyMemory<byte>)record.FieldCopy(tag)).ToArray());
    }

    private static ReadOnlyMemory<byte>[] CopyFields(OwnedRecord record) =>
        Enumerable.Range(1, 21)
            .Select(tag => (ReadOnlyMemory<byte>)record.FieldCopy(tag)).ToArray();

    private static byte[] EncodeRetainedReference(
        ArtifactType type,
        ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(new ArtifactReference(
            type, checked((uint)canonical.Length), SHA256.HashData(canonical)));

    private static async ValueTask<bool> CasAsync(
        IOuterJournalStore store,
        ReadOnlyMemory<byte> key,
        OuterJournalStoredValue current,
        ReadOnlyMemory<byte> replacement,
        CancellationToken cancellationToken) =>
        await store.CompareExchangeAsync(
            new OuterJournalCompareExchange(
                key, current.CanonicalDpj1.ToArray(),
                new OuterJournalStoredValue(replacement.Span, current.ResponseFrame.Span)),
            cancellationToken).ConfigureAwait(false);

    private static async ValueTask<OuterJournalStoredValue> RequireReadAsync(
        IOuterJournalStore store,
        ReadOnlyMemory<byte> key,
        CancellationToken cancellationToken) =>
        await store.ReadAsync(key, cancellationToken).ConfigureAwait(false) ??
        throw new RecordException(
            RecordError.InvalidTransition,
            "A DPJ1 row disappeared during compare/exchange.");

    private static OuterJournalResult Result(
        OuterJournalDisposition disposition,
        OuterJournalStoredValue value,
        bool includeResponse = true) =>
        new(disposition, value.CanonicalDpj1.Span,
            includeResponse ? value.ResponseFrame.Span : ReadOnlySpan<byte>.Empty);

    private static bool Bool(ReadOnlySpan<byte> value, string name)
    {
        if (value[0] > 1)
            Invalid(RecordError.InvalidField, $"DPJ1 {name} latch is invalid.");
        return value[0] == 1;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        CanonicalGrammar.FixedEquals(left, right);

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static void ValidateKeyId(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || CanonicalGrammar.IsZero(value))
            Invalid(RecordError.InvalidField, $"The DPJ1 {name} key ID is invalid.");
    }

    private static void Invalid(RecordError error, string message) =>
        throw new RecordException(error, message);

    private sealed record VerifiedRow(
        OwnedRecord Record,
        JournalPhase Phase,
        bool DeliveryAuthorized,
        bool TerminalStale,
        bool ForkLatched);
}
