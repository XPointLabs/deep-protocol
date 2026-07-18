using System.Buffers.Binary;

namespace Deep.Protocol.DeepExtension.NearbyHandshakes;

public static class NearbyHandshakeCodec
{
    private static ReadOnlySpan<byte> AdvertisementMagic => "NRV1"u8;
    private static ReadOnlySpan<byte> FrameMagic => "NHS1"u8;
    private static ReadOnlySpan<byte> BindingMagic => "NBV1"u8;
    private const byte Version = 1;

    public static byte[] EncodeAdvertisement(byte bundleVersion, ReadOnlySpan<byte> hint)
    {
        if (bundleVersion == 0 || hint.Length != NearbyHandshakeLimits.HintLength ||
            hint.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(NearbyHandshakeError.InvalidHint, "Advertisement values are invalid.");
        }

        var encoded = new byte[NearbyHandshakeLimits.AdvertisementLength];
        AdvertisementMagic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = bundleVersion;
        hint.CopyTo(encoded.AsSpan(8));
        return encoded;
    }

    public static NearbyRendezvousMatch DecodeAdvertisement(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != NearbyHandshakeLimits.AdvertisementLength)
        {
            throw Error(
                NearbyHandshakeError.EncodedLengthOutOfRange,
                "Advertisement length is not canonical.");
        }

        RequireMagicVersion(encoded, AdvertisementMagic);
        if (encoded[5] == 0 || encoded[6] != 0 || encoded[7] != 0)
        {
            throw Error(
                NearbyHandshakeError.ReservedFieldNotZero,
                "Advertisement version/reserved fields are invalid.");
        }

        var hint = encoded[8..].ToArray();
        if (hint.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(NearbyHandshakeError.InvalidHint, "Advertisement hint must be nonzero.");
        }

        return new NearbyRendezvousMatch(0, encoded[5], hint);
    }

    public static byte[] EncodeFrame(
        NearbyHandshakeMessageKind kind,
        NearbyHandshakeBinding binding,
        ReadOnlySpan<byte> adapterPayload)
    {
        ValidateBinding(binding);
        if (kind is not (
                NearbyHandshakeMessageKind.InitiatorHello or
                NearbyHandshakeMessageKind.ResponderResponse) ||
            adapterPayload.Length is
                < NearbyHandshakeLimits.MinimumAdapterPayloadLength or
                > NearbyHandshakeLimits.MaximumAdapterPayloadLength)
        {
            throw Error(NearbyHandshakeError.InvalidAdapterOutput, "Frame values are invalid.");
        }

        var encoded = new byte[NearbyHandshakeLimits.FrameHeaderLength + adapterPayload.Length];
        FrameMagic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = (byte)kind;
        encoded[6] = binding.BundleVersion;
        encoded[7] = (byte)binding.Mode;
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(8, 8), binding.Period);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(16, 8), binding.ResumeCounter);
        binding.TransportAttemptId.Span.CopyTo(encoded.AsSpan(24, 16));
        binding.SimultaneousOpenToken.Span.CopyTo(encoded.AsSpan(40, 16));
        BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(56, 2), checked((ushort)adapterPayload.Length));
        adapterPayload.CopyTo(encoded.AsSpan(NearbyHandshakeLimits.FrameHeaderLength));
        return encoded;
    }

    public static NearbyHandshakeFrame DecodeFrame(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is
            < NearbyHandshakeLimits.FrameHeaderLength +
              NearbyHandshakeLimits.MinimumAdapterPayloadLength or
            > NearbyHandshakeLimits.FrameHeaderLength +
              NearbyHandshakeLimits.MaximumAdapterPayloadLength)
        {
            throw Error(
                NearbyHandshakeError.EncodedLengthOutOfRange,
                "Handshake frame length is outside strict bounds.");
        }

        RequireMagicVersion(encoded, FrameMagic);
        if (encoded.Slice(58, 6).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Error(
                NearbyHandshakeError.ReservedFieldNotZero,
                "Reserved handshake bytes must be zero.");
        }

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(56, 2));
        if (payloadLength is
                < NearbyHandshakeLimits.MinimumAdapterPayloadLength or
                > NearbyHandshakeLimits.MaximumAdapterPayloadLength ||
            encoded.Length != NearbyHandshakeLimits.FrameHeaderLength + payloadLength)
        {
            throw Error(
                NearbyHandshakeError.MalformedLength,
                "Handshake payload length is not canonical.");
        }

        var kind = (NearbyHandshakeMessageKind)encoded[5];
        if (kind is not (
            NearbyHandshakeMessageKind.InitiatorHello or
            NearbyHandshakeMessageKind.ResponderResponse))
        {
            throw Error(NearbyHandshakeError.InvalidEnumValue, "Message kind is invalid.");
        }

        var binding = new NearbyHandshakeBinding
        {
            BundleVersion = encoded[6],
            Mode = (NearbyHandshakeMode)encoded[7],
            Period = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8)),
            ResumeCounter = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(16, 8)),
            TransportAttemptId = encoded.Slice(24, 16).ToArray(),
            SimultaneousOpenToken = encoded.Slice(40, 16).ToArray()
        };
        ValidateBinding(binding);
        return new NearbyHandshakeFrame
        {
            Kind = kind,
            Binding = binding,
            AdapterPayload = encoded[NearbyHandshakeLimits.FrameHeaderLength..].ToArray()
        };
    }

    public static byte[] GetBindingBytes(NearbyHandshakeBinding binding)
    {
        ValidateBinding(binding);
        var encoded = new byte[56];
        BindingMagic.CopyTo(encoded);
        encoded[4] = Version;
        encoded[5] = binding.BundleVersion;
        encoded[6] = (byte)binding.Mode;
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(8, 8), binding.Period);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(16, 8), binding.ResumeCounter);
        binding.TransportAttemptId.Span.CopyTo(encoded.AsSpan(24, 16));
        binding.SimultaneousOpenToken.Span.CopyTo(encoded.AsSpan(40, 16));
        return encoded;
    }

    internal static void ValidateBinding(NearbyHandshakeBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (binding.BundleVersion == 0 ||
            binding.Period == 0 ||
            binding.TransportAttemptId.Length != NearbyHandshakeLimits.IdentifierLength ||
            binding.TransportAttemptId.Span.IndexOfAnyExcept((byte)0) < 0 ||
            binding.SimultaneousOpenToken.Length != NearbyHandshakeLimits.IdentifierLength ||
            binding.SimultaneousOpenToken.Span.IndexOfAnyExcept((byte)0) < 0 ||
            binding.Mode is not (NearbyHandshakeMode.Fresh or NearbyHandshakeMode.Resumption))
        {
            throw Error(NearbyHandshakeError.InvalidIdentifier, "Handshake binding is invalid.");
        }

        if (binding.Mode == NearbyHandshakeMode.Fresh && binding.ResumeCounter != 0 ||
            binding.Mode == NearbyHandshakeMode.Resumption && binding.ResumeCounter == 0)
        {
            throw Error(
                NearbyHandshakeError.InvalidResumption,
                "Fresh/resumption marker and counter are inconsistent.");
        }
    }

    private static void RequireMagicVersion(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> magic)
    {
        if (!encoded[..4].SequenceEqual(magic))
        {
            throw Error(NearbyHandshakeError.InvalidMagic, "Nearby handshake magic is invalid.");
        }

        if (encoded[4] != Version)
        {
            throw Error(
                NearbyHandshakeError.UnsupportedVersion,
                "Nearby handshake version is unsupported.");
        }
    }

    private static NearbyHandshakeException Error(
        NearbyHandshakeError error,
        string message) =>
        new(error, message);
}
