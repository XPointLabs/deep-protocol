using System.Buffers.Binary;

namespace Deep.Protocol.DeepExtension.ManagedIngress;

public static class ManagedIngressErrorCodec
{
    private static ReadOnlySpan<byte> Magic => "DIE1"u8;
    private const byte Version = 1;
    private const byte MinimumReaderVersion = 1;

    public static byte[] Encode(ManagedIngressErrorFrame frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        Validate(frame);

        var encoded = new byte[ManagedIngressLimits.ErrorFrameBytes];
        Magic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = MinimumReaderVersion;
        encoded[6] = (byte)frame.ErrorClass;
        encoded[7] = (byte)frame.Certainty;
        encoded[8] = frame.Retryable ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(10, 2),
            checked((ushort)frame.RetryAfterSeconds));
        return encoded;
    }

    public static ManagedIngressErrorFrame Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != ManagedIngressLimits.ErrorFrameBytes)
        {
            throw Error(
                ManagedIngressContractError.MalformedErrorFrame,
                "The error frame must be exactly 64 bytes.");
        }

        if (!encoded[..4].SequenceEqual(Magic))
        {
            throw Error(
                ManagedIngressContractError.MalformedErrorFrame,
                "The error frame magic is invalid.");
        }

        if (encoded[4] != Version || encoded[5] != MinimumReaderVersion)
        {
            throw Error(
                ManagedIngressContractError.UnsupportedErrorVersion,
                "The error frame version is unsupported.");
        }

        if (encoded[9] != 0 ||
            encoded[12..].IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Error(
                ManagedIngressContractError.ReservedFieldNotZero,
                "Reserved error bytes must be zero.");
        }

        if (!Enum.IsDefined((ManagedIngressErrorClass)encoded[6]))
        {
            throw Error(
                ManagedIngressContractError.InvalidErrorClass,
                "The error class is invalid.");
        }

        if (!Enum.IsDefined((ManagedIngressOutcomeCertainty)encoded[7]))
        {
            throw Error(
                ManagedIngressContractError.InvalidOutcomeCertainty,
                "The outcome certainty is invalid.");
        }

        if (encoded[8] > 1)
        {
            throw Error(
                ManagedIngressContractError.InvalidRetryPolicy,
                "The retryable marker is invalid.");
        }

        var frame = new ManagedIngressErrorFrame(
            (ManagedIngressErrorClass)encoded[6],
            (ManagedIngressOutcomeCertainty)encoded[7],
            encoded[8] == 1,
            BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(10, 2)));
        Validate(frame);
        return frame;
    }

    private static void Validate(ManagedIngressErrorFrame frame)
    {
        if (!Enum.IsDefined(frame.ErrorClass))
        {
            throw Error(
                ManagedIngressContractError.InvalidErrorClass,
                "The error class is invalid.");
        }

        if (!Enum.IsDefined(frame.Certainty))
        {
            throw Error(
                ManagedIngressContractError.InvalidOutcomeCertainty,
                "The outcome certainty is invalid.");
        }

        var expectedCertainty = frame.ErrorClass is
            ManagedIngressErrorClass.InvalidUpstreamResponse or
            ManagedIngressErrorClass.UpstreamOutcomeUnknown
                ? ManagedIngressOutcomeCertainty.UnknownAfterForward
                : ManagedIngressOutcomeCertainty.BeforeForward;
        var expectedRetryable = frame.ErrorClass is
            ManagedIngressErrorClass.WrongOrigin or
            ManagedIngressErrorClass.EarlyDataRejected or
            ManagedIngressErrorClass.Saturated or
            ManagedIngressErrorClass.InvalidUpstreamResponse or
            ManagedIngressErrorClass.Unavailable or
            ManagedIngressErrorClass.UpstreamOutcomeUnknown;
        var retryAfterRequired = frame.ErrorClass is
            ManagedIngressErrorClass.Saturated or
            ManagedIngressErrorClass.Unavailable;
        if (frame.Certainty != expectedCertainty ||
            frame.Retryable != expectedRetryable ||
            frame.RetryAfterSeconds < 0 ||
            frame.RetryAfterSeconds > ManagedIngressLimits.MaximumRetryAfterSeconds ||
            (!retryAfterRequired && frame.RetryAfterSeconds != 0) ||
            (retryAfterRequired &&
             frame.RetryAfterSeconds < ManagedIngressLimits.MinimumRetryAfterSeconds) ||
            (!frame.Retryable && frame.RetryAfterSeconds != 0))
        {
            throw Error(
                ManagedIngressContractError.InvalidRetryPolicy,
                "The retry policy is not canonical.");
        }
    }

    private static ManagedIngressContractException Error(
        ManagedIngressContractError error,
        string message) => new(error, message);
}
