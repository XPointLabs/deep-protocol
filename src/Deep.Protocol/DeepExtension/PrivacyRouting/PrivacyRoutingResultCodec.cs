using System.Buffers.Binary;

namespace Deep.Protocol.DeepExtension.PrivacyRouting;

public enum PrivacyRoutingResultKind : byte
{
    Success = 1,
    Failure = 2
}

public enum PrivacyRoutingFailureCode : ushort
{
    MalformedRequest = 1,
    AuthenticationRejected = 2,
    AuthorizationRejected = 3,
    ReplayRejected = 4,
    MailboxNotFound = 5,
    Conflict = 6,
    CapacityExceeded = 7,
    Unavailable = 8,
    OutcomeUnknown = 9,
    InternalFailure = 10
}

public sealed class PrivacyRoutingTerminalResult
{
    private readonly byte[] _body;

    private PrivacyRoutingTerminalResult(
        PrivacyRoutingResultKind kind,
        PrivacyRoutingOperation operation,
        PrivacyRoutingFailureCode? failureCode,
        bool retryable,
        ReadOnlySpan<byte> body)
    {
        Kind = kind;
        Operation = operation;
        FailureCode = failureCode;
        Retryable = retryable;
        _body = body.ToArray();
    }

    public PrivacyRoutingResultKind Kind { get; }

    public PrivacyRoutingOperation Operation { get; }

    public PrivacyRoutingFailureCode? FailureCode { get; }

    public bool Retryable { get; }

    public ReadOnlyMemory<byte> Body => _body.ToArray();

    public static PrivacyRoutingTerminalResult Success(
        PrivacyRoutingOperation operation,
        ReadOnlySpan<byte> canonicalBody)
    {
        PrivacyRoutingWire.ValidateOperation(operation);
        if (canonicalBody.Length > PrivacyRoutingLimits.MaximumTerminalSuccessBodyBytes)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "The terminal success body exceeds the privacy-routing limit.");
        }

        return new PrivacyRoutingTerminalResult(
            PrivacyRoutingResultKind.Success,
            operation,
            null,
            retryable: false,
            canonicalBody);
    }

    public static PrivacyRoutingTerminalResult Failure(
        PrivacyRoutingOperation operation,
        PrivacyRoutingFailureCode failureCode)
    {
        PrivacyRoutingWire.ValidateOperation(operation);
        PrivacyRoutingResultCodec.ValidateFailureCode(failureCode);
        return new PrivacyRoutingTerminalResult(
            PrivacyRoutingResultKind.Failure,
            operation,
            failureCode,
            PrivacyRoutingResultCodec.IsRetryable(failureCode),
            ReadOnlySpan<byte>.Empty);
    }

    private static PrivacyRoutingProtocolException Error(
        PrivacyRoutingProtocolError error,
        string message) => new(error, message);
}

public static class PrivacyRoutingResultCodec
{
    private static readonly byte[] Magic = ProtocolMagicBytes.DPR1.ToArray();
    private const int FixedBytes = 20;

    public static byte[] Encode(PrivacyRoutingTerminalResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        PrivacyRoutingWire.ValidateOperation(result.Operation);
        var body = result.Body;
        var output = new byte[checked(FixedBytes + body.Length)];
        Magic.CopyTo(output, 0);
        output[4] = 1;
        output[5] = 1;
        output[6] = (byte)result.Kind;
        output[7] = (byte)result.Operation;
        if (result.Kind == PrivacyRoutingResultKind.Success)
        {
            if (result.FailureCode is not null || result.Retryable)
            {
                throw Error(PrivacyRoutingProtocolError.InvalidOperation, "A success result cannot carry failure policy.");
            }
        }
        else if (result.Kind == PrivacyRoutingResultKind.Failure && result.FailureCode.HasValue)
        {
            ValidateFailureCode(result.FailureCode.Value);
            if (body.Length != 0 || result.Retryable != IsRetryable(result.FailureCode.Value))
            {
                throw Error(PrivacyRoutingProtocolError.InvalidOperation, "A failure result has a non-canonical body or retry policy.");
            }

            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8, 2), (ushort)result.FailureCode.Value);
            output[10] = result.Retryable ? (byte)1 : (byte)0;
        }
        else
        {
            throw Error(PrivacyRoutingProtocolError.InvalidOperation, "The terminal result kind is unsupported.");
        }

        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(12, 4), checked((uint)body.Length));
        body.Span.CopyTo(output.AsSpan(FixedBytes));
        return output;
    }

    public static PrivacyRoutingTerminalResult Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < FixedBytes || encoded.Length > FixedBytes + PrivacyRoutingLimits.MaximumTerminalSuccessBodyBytes)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "The terminal result is outside strict bounds.");
        }

        if (!encoded[..4].SequenceEqual(Magic) || encoded[4] != 1 || encoded[5] != 1)
        {
            throw Error(PrivacyRoutingProtocolError.UnsupportedVersion, "The terminal result version is unsupported.");
        }

        var kind = (PrivacyRoutingResultKind)encoded[6];
        var operation = (PrivacyRoutingOperation)encoded[7];
        PrivacyRoutingWire.ValidateOperation(operation);
        if (encoded[11] != 0 || !PrivacyRoutingWire.IsZero(encoded.Slice(16, 4)))
        {
            throw Error(PrivacyRoutingProtocolError.InvalidPadding, "A reserved terminal result field is nonzero.");
        }

        var failureCodeValue = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(8, 2));
        var retryableValue = encoded[10];
        var bodyLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(12, 4));
        if (bodyLength != encoded.Length - FixedBytes || bodyLength > PrivacyRoutingLimits.MaximumTerminalSuccessBodyBytes)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidLength, "The terminal result body length is non-canonical.");
        }

        var body = encoded[FixedBytes..];
        if (kind == PrivacyRoutingResultKind.Success)
        {
            if (failureCodeValue != 0 || retryableValue != 0)
            {
                throw Error(PrivacyRoutingProtocolError.InvalidOperation, "A success result carries failure policy.");
            }

            return PrivacyRoutingTerminalResult.Success(operation, body);
        }

        if (kind != PrivacyRoutingResultKind.Failure || retryableValue > 1 || body.Length != 0)
        {
            throw Error(PrivacyRoutingProtocolError.InvalidOperation, "The terminal failure result is non-canonical.");
        }

        var failureCode = (PrivacyRoutingFailureCode)failureCodeValue;
        ValidateFailureCode(failureCode);
        if ((retryableValue == 1) != IsRetryable(failureCode))
        {
            throw Error(PrivacyRoutingProtocolError.InvalidOperation, "The terminal failure retry policy is non-canonical.");
        }

        return PrivacyRoutingTerminalResult.Failure(operation, failureCode);
    }

    internal static bool IsRetryable(PrivacyRoutingFailureCode failureCode) =>
        failureCode is PrivacyRoutingFailureCode.CapacityExceeded or
            PrivacyRoutingFailureCode.Unavailable or
            PrivacyRoutingFailureCode.OutcomeUnknown;

    internal static void ValidateFailureCode(PrivacyRoutingFailureCode failureCode)
    {
        if (failureCode is not (
            PrivacyRoutingFailureCode.MalformedRequest or
            PrivacyRoutingFailureCode.AuthenticationRejected or
            PrivacyRoutingFailureCode.AuthorizationRejected or
            PrivacyRoutingFailureCode.ReplayRejected or
            PrivacyRoutingFailureCode.MailboxNotFound or
            PrivacyRoutingFailureCode.Conflict or
            PrivacyRoutingFailureCode.CapacityExceeded or
            PrivacyRoutingFailureCode.Unavailable or
            PrivacyRoutingFailureCode.OutcomeUnknown or
            PrivacyRoutingFailureCode.InternalFailure))
        {
            throw Error(PrivacyRoutingProtocolError.InvalidOperation, "The terminal failure code is unsupported.");
        }
    }

    private static PrivacyRoutingProtocolException Error(
        PrivacyRoutingProtocolError error,
        string message) => new(error, message);
}
