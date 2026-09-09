using System.Buffers.Binary;

namespace Deep.Protocol.DeepExtension.PrivacyRouting;

internal enum PrivacyRoutingResultKind : byte { Success = 1, Failure = 2 }
internal enum PrivacyRoutingFailureCode : ushort { MalformedRequest = 1, AuthenticationRejected = 2, AuthorizationRejected = 3, ReplayRejected = 4, MailboxNotFound = 5, Conflict = 6, CapacityExceeded = 7, Unavailable = 8, OutcomeUnknown = 9, InternalFailure = 10 }

internal sealed class PrivacyRoutingTerminalResult
{
    private readonly byte[] _body;
    private PrivacyRoutingTerminalResult(PrivacyRoutingResultKind kind, PrivacyRoutingOperation operation, PrivacyRoutingFailureCode? failureCode, bool retryable, ReadOnlySpan<byte> body) { Kind = kind; Operation = operation; FailureCode = failureCode; Retryable = retryable; _body = body.ToArray(); }
    public PrivacyRoutingResultKind Kind { get; }
    public PrivacyRoutingOperation Operation { get; }
    public PrivacyRoutingFailureCode? FailureCode { get; }
    public bool Retryable { get; }
    public ReadOnlyMemory<byte> Body => _body.ToArray();
    public static PrivacyRoutingTerminalResult Success(PrivacyRoutingOperation operation, ReadOnlySpan<byte> body)
    {
        PrivacyRoutingWire.ValidateOperation(operation);
        var maximum = operation switch
        {
            PrivacyRoutingOperation.ContactResolve => PrivacyRoutingLimits.MaximumContactResolverResponseBytes,
            PrivacyRoutingOperation.GroupControl => PrivacyRoutingLimits.MaximumGroupControlResponseBytes,
            _ => PrivacyRoutingLimits.MaximumTerminalSuccessBodyBytes,
        };
        if (body.Length > maximum)
            throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "The terminal success body exceeds its operation limit.");
        return new(PrivacyRoutingResultKind.Success, operation, null, false, body);
    }
    public static PrivacyRoutingTerminalResult Failure(PrivacyRoutingOperation operation, PrivacyRoutingFailureCode code)
    { PrivacyRoutingWire.ValidateOperation(operation); PrivacyRoutingResultCodec.ValidateFailureCode(code); return new(PrivacyRoutingResultKind.Failure, operation, code, PrivacyRoutingResultCodec.IsRetryable(code), ReadOnlySpan<byte>.Empty); }
}

internal static class PrivacyRoutingResultCodec
{
    private static readonly byte[] Magic = ProtocolMagicBytes.XPR1.ToArray();
    private const int Prefix = 20;
    public static byte[] Encode(PrivacyRoutingTerminalResult result)
    {
        ArgumentNullException.ThrowIfNull(result); var body = result.Body.Span; var output = new byte[Prefix + body.Length];
        Magic.CopyTo(output, 0); output[4] = output[5] = 1; output[6] = (byte)result.Kind; output[7] = (byte)result.Operation;
        if (result.Kind == PrivacyRoutingResultKind.Success)
        { if (result.FailureCode is not null || result.Retryable) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "Success result policy is invalid."); }
        else if (result.Kind == PrivacyRoutingResultKind.Failure && result.FailureCode is { } code && body.IsEmpty && result.Retryable == IsRetryable(code))
        { ValidateFailureCode(code); BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8, 2), (ushort)code); output[10] = result.Retryable ? (byte)1 : (byte)0; }
        else throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "Failure result policy is invalid.");
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(12, 4), (uint)body.Length); body.CopyTo(output.AsSpan(Prefix)); return output;
    }
    public static PrivacyRoutingTerminalResult Decode(ReadOnlySpan<byte> value)
    {
        if (value.Length < Prefix || value.Length > PrivacyRoutingLimits.MaximumApplicationPayloadBytes || !value[..4].SequenceEqual(Magic) || value[4] != 1 || value[5] != 1 || value[11] != 0 || !PrivacyRoutingWire.IsZero(value.Slice(16, 4))) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "XPR1 is malformed.");
        var kind = (PrivacyRoutingResultKind)value[6]; var op = (PrivacyRoutingOperation)value[7]; PrivacyRoutingWire.ValidateOperation(op); var length = BinaryPrimitives.ReadUInt32BigEndian(value.Slice(12, 4));
        if (length != value.Length - Prefix) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidLength, "XPR1 body length is non-canonical.");
        var code = (PrivacyRoutingFailureCode)BinaryPrimitives.ReadUInt16BigEndian(value.Slice(8, 2));
        if (kind == PrivacyRoutingResultKind.Success) { if (code != 0 || value[10] != 0) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "XPR1 success policy is invalid."); return PrivacyRoutingTerminalResult.Success(op, value[Prefix..]); }
        if (kind != PrivacyRoutingResultKind.Failure || length != 0 || value[10] > 1) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "XPR1 failure grammar is invalid.");
        ValidateFailureCode(code); if ((value[10] == 1) != IsRetryable(code)) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "XPR1 retry marker is invalid."); return PrivacyRoutingTerminalResult.Failure(op, code);
    }
    internal static bool IsRetryable(PrivacyRoutingFailureCode code) => code is PrivacyRoutingFailureCode.CapacityExceeded or PrivacyRoutingFailureCode.Unavailable or PrivacyRoutingFailureCode.OutcomeUnknown;
    internal static void ValidateFailureCode(PrivacyRoutingFailureCode code) { if (code is < PrivacyRoutingFailureCode.MalformedRequest or > PrivacyRoutingFailureCode.InternalFailure) throw PrivacyRoutingWire.Error(PrivacyRoutingProtocolError.InvalidOperation, "Unknown XPR1 failure code."); }
}
