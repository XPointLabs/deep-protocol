using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public sealed record MailboxAuthenticatedClientRequest
{
    public required MailboxAuthenticatedRequestBinding Binding { get; init; }
    public required MailboxAuthenticatedPresentation Presentation { get; init; }
}

public sealed record VerifiedMailboxAuthenticatedClientRequest
{
    public required MailboxAuthenticatedRequestBinding Binding { get; init; }
    public required VerifiedMailboxAuthenticatedCapability Capability { get; init; }
}

public static class MailboxAuthenticatedClientRequestCodec
{
    private const byte Version = 2;
    public const int HeaderLength = 16;
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.MAU2;

    public static byte[] Encode(MailboxAuthenticatedClientRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Binding);
        ArgumentNullException.ThrowIfNull(request.Presentation);
        if (request.Binding.CanonicalRequest.IsEmpty ||
            request.Binding.Operation != request.Presentation.Operation ||
            !FixedEquals(request.Binding.OperationId.Span, request.Presentation.OperationId.Span) ||
            !FixedEquals(request.Binding.RequestDigest.Span, request.Presentation.RequestDigest.Span))
            throw Error("MAU2 binding and MCP2 presentation disagree.");
        var presentation = MailboxAuthenticatedCapabilityCodec.EncodePresentation(request.Presentation);
        var body = request.Binding.CanonicalRequest;
        if (body.Length > MailboxClientLimits.MaximumPageBytes)
            throw Error("MAU2 body exceeds its strict bound.");
        var output = new byte[HeaderLength + presentation.Length + body.Length];
        Magic.CopyTo(output);
        output[4] = Version;
        output[5] = (byte)request.Binding.Operation;
        BinaryPrimitives.WriteUInt16BigEndian(
            output.AsSpan(8),
            checked((ushort)presentation.Length));
        BinaryPrimitives.WriteUInt32BigEndian(
            output.AsSpan(10),
            checked((uint)body.Length));
        presentation.CopyTo(output, HeaderLength);
        body.Span.CopyTo(output.AsSpan(HeaderLength + presentation.Length));
        return output;
    }

    public static MailboxAuthenticatedClientRequest Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length <
                HeaderLength +
                MailboxAuthenticatedCapabilityLimits.PresentationLength ||
            encoded.Length >
                HeaderLength +
                MailboxAuthenticatedCapabilityLimits.PresentationLength +
                MailboxClientLimits.MaximumPageBytes)
            throw Error("MAU2 length is outside strict bounds.");
        if (!encoded[..4].SequenceEqual(Magic))
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.InvalidMagic,
                "MAU2 magic is invalid.");
        if (encoded[4] != Version)
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.UnsupportedVersion,
                "MAU2 version is unsupported.");
        if (encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            encoded.Slice(14, 2).IndexOfAnyExcept((byte)0) >= 0)
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.ReservedFieldNotZero,
                "MAU2 reserved bytes must be zero.");
        var operation = (MailboxAuthenticatedOperation)encoded[5];
        var presentationLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(8, 2));
        var bodyLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(10, 4));
        if (presentationLength != MailboxAuthenticatedCapabilityLimits.PresentationLength ||
            bodyLength > MailboxClientLimits.MaximumPageBytes ||
            encoded.Length != HeaderLength + presentationLength + bodyLength)
            throw Error("MAU2 nested lengths are invalid.");
        var presentation = MailboxAuthenticatedCapabilityCodec.DecodePresentation(
            encoded.Slice(HeaderLength, presentationLength));
        var binding = MailboxAuthenticatedRequestTranscript.ParseCanonical(
            operation,
            encoded.Slice(HeaderLength + presentationLength, checked((int)bodyLength)));
        if (presentation.Operation != operation ||
            !FixedEquals(presentation.OperationId.Span, binding.OperationId.Span) ||
            !FixedEquals(presentation.RequestDigest.Span, binding.RequestDigest.Span))
            throw Error("MAU2 MCP2 does not authenticate its canonical body.");
        return new MailboxAuthenticatedClientRequest
        {
            Binding = binding,
            Presentation = presentation
        };
    }

    public static VerifiedMailboxAuthenticatedClientRequest Verify(
        ReadOnlySpan<byte> encoded,
        MailboxAuthenticatedVerificationPolicy policy,
        IMailboxAuthenticatedCapabilityCrypto crypto,
        IMailboxCapabilityRevocationSource revocations,
        IMailboxCapabilityReplayJournal replayJournal)
    {
        var decoded = Decode(encoded);
        var verified = MailboxAuthenticatedCapabilityCodec.Verify(
            MailboxAuthenticatedCapabilityCodec.EncodePresentation(decoded.Presentation),
            decoded.Binding,
            policy,
            crypto,
            revocations,
            replayJournal);
        var body = decoded.Binding.CanonicalRequest.Span;
        var epoch = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(8, 8));
        var placementOffset = decoded.Binding.Operation == MailboxAuthenticatedOperation.Store
            ? 48
            : 64;
        var placementId = new BlindedPlacementId(body.Slice(placementOffset, 32));
        if (verified.Grant.Epoch != epoch ||
            !FixedEquals(
                verified.Grant.PlacementCommitment.Span,
                MailboxPlacementCommitment.Compute(placementId)))
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.BindingMismatch,
                "MAU2 body does not match MCP2 epoch/placement authority.");
        return new VerifiedMailboxAuthenticatedClientRequest
        {
            Binding = decoded.Binding,
            Capability = verified
        };
    }

    private static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static MailboxAuthenticatedCapabilityException Error(string message) =>
        new(MailboxAuthenticatedCapabilityError.InvalidLength, message);
}
