using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Current DID2 recipient and both selected signatures for one exact
/// claim transcript. This does not prove remote storage read-back, grant a
/// session or authorize ACK. The authenticated runtime and durable owners
/// remain responsible for completing those independent gates.</summary>
public sealed class VerifiedXpc1V2PreKeyClaimReceipt
{
    private readonly ParsedXpk1V2 request;
    private readonly ParsedXpc1V2 result;
    private readonly byte[] exactReplayHash;
    private readonly byte[][] replicas;

    internal VerifiedXpc1V2PreKeyClaimReceipt(ParsedXpk1V2 request,
        ParsedXpc1V2 result, VerifiedDpk2Offering offering,
        DeepIdV2CurrentContactAuthorization recipientAuthorization,
        ParsedDcr1V2 recipientClosure, VerifiedContactServicePlacement placement)
    {
        this.request = request;
        this.result = result;
        Offering = offering;
        RecipientAuthorization = recipientAuthorization;
        RecipientClosure = recipientClosure;
        exactReplayHash = DeepIdV2PreKeyClaimReceiptVerifier.ComputeExactReplayHash(
            request, result);
        replicas = placement.RankedReplicaNodeIds.Select(id => id.ToArray()).ToArray();
    }

    public VerifiedDpk2Offering Offering { get; }
    public DeepIdV2CurrentContactAuthorization RecipientAuthorization { get; }
    public ParsedDcr1V2 RecipientClosure { get; }
    public ReadOnlyMemory<byte> NetworkId => request.Field(1);
    public ReadOnlyMemory<byte> OperationId => request.Field(2);
    public ReadOnlyMemory<byte> RequestHash => request.RequestHash;
    public ReadOnlyMemory<byte> ClaimReceiptHash => result.Field(18);
    public ReadOnlyMemory<byte> ExactDpk2Hash => Offering.ExactHash;
    public ReadOnlyMemory<byte> Xpi1Hash =>
        DeepIdV2PreKeyManifestCodec.Decode(result.Field(26).Span).ExactHash;
    public ReadOnlyMemory<byte> ExactReplayHash => exactReplayHash.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => request.Field(4);
    public ushort LastResortUseCounter => U16(result.Field(23).Span);
    public ulong ClaimCommitGeneration => U64(result.Field(24).Span);
    public Xpc1V2Status Status => result.Status;
    public IReadOnlyList<ReadOnlyMemory<byte>> ReplicaNodeIds =>
        Array.AsReadOnly(replicas.Select(id => (ReadOnlyMemory<byte>)id.ToArray()).ToArray());

    // The exact transcript may enter a DPH2 payload only after its public
    // claim closure matches. This is a read-only correlation check, not
    // promotion of an initiator proof, handshake or durable session.
    internal (byte[] Xpk1, byte[] Xpc1Wire) CopyEncryptedInitialClaimTranscript(
        Dph2Record dph2)
    {
        RequireMatchesDph2Header(dph2);
        return (request.CanonicalBytes.ToArray(), result.WireBytes.ToArray());
    }

    internal void RequireMatchesDph2Header(Dph2Record dph2)
    {
        ArgumentNullException.ThrowIfNull(dph2);
        // Validate against the retained exact V2 offering, never a V1
        // re-encoding of its projected Dpk2Record.
        Dph2Codec.ValidateSelection(dph2, Offering);
        var commitment = MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(dph2);
        try
        {
            if (!Fixed(request.Field(1).Span, dph2.NetworkId.Span) ||
                !Fixed(request.Field(2).Span, dph2.ClaimOperationId.Span) ||
                !Fixed(request.Field(22).Span, dph2.ClaimOperationId.Span) ||
                !Fixed(request.Field(19).Span, dph2.ResponderDeviceId.Span) ||
                !Fixed(request.Field(21).Span, commitment) ||
                !Fixed(result.Field(18).Span, dph2.ClaimReceiptHash.Span) ||
                !Fixed(result.Field(17).Span,
                    dph2.SelectedPrekey.OneTimeX25519PrekeyIdOrZero.Span) ||
                LastResortUseCounter != dph2.LastResortUseCounter)
                throw new CryptographicException(
                    "The DPH2 header differs from the exact verified DID2 claim.");
        }
        finally { CryptographicOperations.ZeroMemory(commitment); }
    }

    internal static void RequireExactReplay(VerifiedXpc1V2PreKeyClaimReceipt retained,
        VerifiedXpc1V2PreKeyClaimReceipt candidate)
    {
        ArgumentNullException.ThrowIfNull(retained);
        ArgumentNullException.ThrowIfNull(candidate);
        if (!CryptographicOperations.FixedTimeEquals(retained.exactReplayHash,
                candidate.exactReplayHash))
            throw new CryptographicException("The exact DID2 claim replay changed.");
    }

    private static ushort U16(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt16BigEndian(value);
    private static ulong U64(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt64BigEndian(value);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>Closed current-recipient XPC1 V2 verification. No V1 closure,
/// caller signing key or synthetic receipt can satisfy this boundary.</summary>
public static class DeepIdV2PreKeyClaimReceiptVerifier
{
    public static bool RuntimeActivation => false;

    public static async ValueTask<VerifiedXpc1V2PreKeyClaimReceipt> VerifyAsync(
        ParsedXpk1V2 request, ParsedXpc1V2 result,
        VerifiedContactServicePlacement placement,
        DeepIdV2CurrentContactAuthorization recipientAuthorization,
        ParsedDcr1V2 recipientClosure,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(placement);
        ArgumentNullException.ThrowIfNull(recipientAuthorization);
        ArgumentNullException.ThrowIfNull(recipientClosure);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        cancellationToken.ThrowIfCancellationRequested();
        placement.Network.EnsureCurrent();
        var reading = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(
            recipientAuthorization.Freshness, recipientAuthorization.Authorization,
            reading.BootId.Span, reading.SampleSeconds);
        _ = VerifyTime(request, placement, current, reading);
        _ = DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(request, result, placement);
        var manifest = DeepIdV2PreKeyManifestCodec.Decode(result.Field(26).Span);
        var member = DeepIdV2Dpk2Codec.Decode(result.Field(16).Span);
        DeepIdV2Dpk2MemberBinding.Verify(recipientClosure, current, manifest, member,
            reading.BootId.Span, reading.SampleSeconds);
        var service = FindService(recipientClosure.Bundle, request.Field(19).Span);
        if (!Fixed(request.Field(1).Span, current.Freshness.NetworkId.Span) ||
            !Fixed(request.Field(17).Span, recipientClosure.Bundle.ObjectHash.Span) ||
            !Fixed(request.Field(18).Span, manifest.Field(6).Span[6..]) ||
            !Fixed(request.Field(16).Span, manifest.Field(2).Span) ||
            !Fixed(request.Field(19).Span, manifest.Field(3).Span) ||
            member.Kind == Dpk2PrekeyKind.LastResort &&
            U16(result.Field(23).Span) > U16(service.Field(9).Span))
            Reject("The exact DID2 claim does not bind the current recipient service.");
        var offering = DeepIdV2Dpk2PreClaimVerifier.Verify(result.Field(16).Span,
            current.Freshness, reading.BootId.Span, reading.SampleSeconds);
        // Recheck after verification, including a suspended protected-clock read.
        // No result is minted from an interval that expired while verifying.
        reading = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(
            current.Freshness, current.Authorization, reading.BootId.Span,
            reading.SampleSeconds);
        var interval = VerifyTime(request, placement, current, reading);
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(recipientClosure,
            current.Authorization, interval.Lower);
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(recipientClosure,
            current.Authorization, interval.Upper);
        if (U64(manifest.Field(14).Span) > interval.Lower ||
            U64(manifest.Field(15).Span) <= interval.Upper ||
            member.Record.NotBefore > interval.Lower ||
            member.ExpiresAt <= interval.Upper)
            Reject("The complete DID2 claim interval is outside the selected inventory.");
        placement.Network.EnsureCurrent();
        cancellationToken.ThrowIfCancellationRequested();
        return new(request, result, offering, current, recipientClosure, placement);
    }

    private static (ulong Lower, ulong Upper) VerifyTime(ParsedXpk1V2 request,
        VerifiedContactServicePlacement placement,
        DeepIdV2CurrentContactAuthorization current, OnionMonotonicReading reading)
    {
        var network = placement.Network.Closure ??
            throw new CryptographicException("The DID2 claim has no network time closure.");
        if (!Fixed(network.FreshnessBootId, reading.BootId.Span) ||
            reading.SampleSeconds < network.FreshnessMonotonicSample ||
            reading.SampleSeconds >= network.FreshnessDeadlineMonotonicSeconds)
            Reject("The DID2 claim network proof is not current at this operation.");
        ulong lower, upper;
        try
        {
            var elapsed = checked(reading.SampleSeconds - network.FreshnessMonotonicSample);
            lower = Math.Min(checked(network.TrustedLowerUnixSeconds + elapsed),
                current.TrustedLowerUnixSeconds);
            upper = Math.Max(checked(network.TrustedUpperUnixSeconds + elapsed),
                current.TrustedUpperUnixSeconds);
        }
        catch (OverflowException exception)
        {
            throw new CryptographicException("The DID2 claim time interval overflowed.", exception);
        }
        var authorization = current.Authorization.Record;
        if (U64(request.Field(5).Span) > lower ||
            U64(request.Field(6).Span) <= upper ||
            placement.ValidUntilUnixSeconds <= upper ||
            authorization.NotBeforeUnixSeconds > lower ||
            authorization.ExpiresAtUnixSeconds <= upper || lower > upper)
            Reject("The complete DID2 claim interval is outside request, authorization or placement.");
        return (lower, upper);
    }

    private static ParsedXps1V2 FindService(ParsedDcb1V2 bundle,
        ReadOnlySpan<byte> deviceId)
    {
        var list = bundle.FieldSpan(12);
        for (var index = 0; index < list[0]; index++)
        {
            var service = DeepIdV2PreKeyServiceCodec.Decode(list.Slice(5 + 356 * index, 352));
            if (Fixed(service.Field(3).Span, deviceId)) return service;
        }
        throw new CryptographicException("The DID2 claim responder has no current service descriptor.");
    }

    internal static byte[] ComputeExactReplayHash(ParsedXpk1V2 request, ParsedXpc1V2 result)
    {
        var exactRequest = request.CanonicalBytes;
        var exactResult = result.WireBytes;
        var tuple = new byte[checked(8 + exactRequest.Length + exactResult.Length)];
        BinaryPrimitives.WriteUInt32BigEndian(tuple, checked((uint)exactRequest.Length));
        exactRequest.Span.CopyTo(tuple.AsSpan(4));
        var offset = 4 + exactRequest.Length;
        BinaryPrimitives.WriteUInt32BigEndian(tuple.AsSpan(offset), checked((uint)exactResult.Length));
        exactResult.Span.CopyTo(tuple.AsSpan(offset + 4));
        try
        {
            return ApplicationCoreFormat.Sha256Domain(
                "Deep/ContactResolver/V2/exact-prekey-claim-replay", tuple);
        }
        finally { CryptographicOperations.ZeroMemory(tuple); }
    }

    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static ushort U16(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt16BigEndian(value);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static void Reject(string message) => throw new CryptographicException(message);
}
