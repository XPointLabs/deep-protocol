using System.Security.Cryptography;

namespace Deep.Protocol.Identity;

/// <summary>
/// The permanent, transport-neutral Deep ID. The canonical user-facing form is
/// a 90-character lowercase Bech32m value with HRP <c>deep</c>.
/// </summary>
public sealed class DeepPermanentIdV1 : IEquatable<DeepPermanentIdV1>
{
    public const byte AddressFormatVersion = 1;
    public const int AddressPublicKeySize = 32;
    public const int ResolverReadCapabilitySize = 16;
    public const int PayloadSize = 49;
    public const int CanonicalTextLength = 90;

    private const string HumanReadablePart = "deep";
    private const string CharacterSet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private const uint Bech32mConstant = 0x2bc830a3;
    private static readonly sbyte[] CharacterMap = CreateCharacterMap();

    private readonly byte[] addressPublicKey;
    private readonly byte[] resolverReadCapability;
    private readonly byte[] payload;

    private DeepPermanentIdV1(
        ReadOnlySpan<byte> addressPublicKey,
        ReadOnlySpan<byte> resolverReadCapability,
        ReadOnlySpan<byte> payload,
        string canonicalText)
    {
        this.addressPublicKey = addressPublicKey.ToArray();
        this.resolverReadCapability = resolverReadCapability.ToArray();
        this.payload = payload.ToArray();
        CanonicalText = canonicalText;
    }

    public string CanonicalText { get; }

    public ReadOnlyMemory<byte> AddressPublicKey => addressPublicKey.ToArray();

    public ReadOnlyMemory<byte> ResolverReadCapability => resolverReadCapability.ToArray();

    public ReadOnlyMemory<byte> Payload => payload.ToArray();

    public static DeepPermanentIdV1 FromCapabilities(DeepRecoveryAccountCapabilities capabilities)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        byte[]? publicKey = null;
        byte[]? readCapability = null;
        try
        {
            publicKey = capabilities.AddressSigningPublicKey.ToArray();
            readCapability = capabilities.AddressReadCapability.ToArray();
            return Create(publicKey, readCapability);
        }
        finally
        {
            if (publicKey is not null) CryptographicOperations.ZeroMemory(publicKey);
            if (readCapability is not null) CryptographicOperations.ZeroMemory(readCapability);
        }
    }

    public static DeepPermanentIdV1 Create(
        ReadOnlySpan<byte> addressPublicKey,
        ReadOnlySpan<byte> resolverReadCapability)
    {
        if (addressPublicKey.Length != AddressPublicKeySize)
        {
            throw new ArgumentException($"Address public key must contain exactly {AddressPublicKeySize} bytes.", nameof(addressPublicKey));
        }
        if (resolverReadCapability.Length != ResolverReadCapabilitySize)
        {
            throw new ArgumentException($"Resolver read capability must contain exactly {ResolverReadCapabilitySize} bytes.", nameof(resolverReadCapability));
        }

        Span<byte> payload = stackalloc byte[PayloadSize];
        payload[0] = AddressFormatVersion;
        addressPublicKey.CopyTo(payload[1..]);
        resolverReadCapability.CopyTo(payload[(1 + AddressPublicKeySize)..]);
        var canonicalText = EncodeBech32m(payload);
        return new DeepPermanentIdV1(addressPublicKey, resolverReadCapability, payload, canonicalText);
    }

    public static DeepPermanentIdV1 ParseCanonical(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length != CanonicalTextLength
            || !value.StartsWith(HumanReadablePart + "1", StringComparison.Ordinal)
            || value.Any(static character => character is < (char)33 or > (char)126 || char.IsUpper(character)))
        {
            throw new ArgumentException("Deep ID is not canonical lowercase Bech32m.", nameof(value));
        }

        var separator = value.LastIndexOf('1');
        if (separator != HumanReadablePart.Length)
        {
            throw new ArgumentException("Deep ID has an invalid HRP or separator.", nameof(value));
        }

        var encoded = value.AsSpan(separator + 1);
        Span<byte> symbols = stackalloc byte[encoded.Length];
        for (var index = 0; index < encoded.Length; index++)
        {
            var character = encoded[index];
            if (character >= CharacterMap.Length || CharacterMap[character] < 0)
            {
                throw new ArgumentException("Deep ID contains an invalid Bech32m character.", nameof(value));
            }
            symbols[index] = checked((byte)CharacterMap[character]);
        }

        if (Polymod(HrpExpand(HumanReadablePart), symbols) != Bech32mConstant)
        {
            throw new ArgumentException("Deep ID Bech32m checksum is invalid.", nameof(value));
        }

        Span<byte> payload = stackalloc byte[PayloadSize];
        if (!ConvertBits(symbols[..^6], 5, 8, pad: false, payload, out var bytesWritten)
            || bytesWritten != PayloadSize
            || payload[0] != AddressFormatVersion)
        {
            throw new ArgumentException("Deep ID payload is non-canonical or has an unsupported version.", nameof(value));
        }

        return new DeepPermanentIdV1(
            payload.Slice(1, AddressPublicKeySize),
            payload.Slice(1 + AddressPublicKeySize, ResolverReadCapabilitySize),
            payload,
            value);
    }

    public bool Equals(DeepPermanentIdV1? other) =>
        other is not null && StringComparer.Ordinal.Equals(CanonicalText, other.CanonicalText);

    public override bool Equals(object? obj) => Equals(obj as DeepPermanentIdV1);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(CanonicalText);

    public override string ToString() => CanonicalText;

    private static string EncodeBech32m(ReadOnlySpan<byte> payload)
    {
        Span<byte> data = stackalloc byte[79];
        if (!ConvertBits(payload, 8, 5, pad: true, data, out var dataLength) || dataLength != data.Length)
        {
            throw new CryptographicException("Deep ID Bech32m conversion failed.");
        }

        Span<byte> checksumInput = stackalloc byte[data.Length + 6];
        data.CopyTo(checksumInput);
        var checksum = Polymod(HrpExpand(HumanReadablePart), checksumInput) ^ Bech32mConstant;
        for (var index = 0; index < 6; index++)
        {
            checksumInput[data.Length + index] = (byte)((checksum >> (5 * (5 - index))) & 31);
        }

        return string.Create(CanonicalTextLength, checksumInput.ToArray(), static (destination, symbols) =>
        {
            HumanReadablePart.AsSpan().CopyTo(destination);
            destination[HumanReadablePart.Length] = '1';
            for (var index = 0; index < symbols.Length; index++)
            {
                destination[HumanReadablePart.Length + 1 + index] = CharacterSet[symbols[index]];
            }
        });
    }

    private static bool ConvertBits(
        ReadOnlySpan<byte> input,
        int fromBits,
        int toBits,
        bool pad,
        Span<byte> output,
        out int bytesWritten)
    {
        uint accumulator = 0;
        var bits = 0;
        var maximumOutput = (1u << toBits) - 1;
        var maximumAccumulator = (1u << (fromBits + toBits - 1)) - 1;
        bytesWritten = 0;

        foreach (var value in input)
        {
            if ((value >> fromBits) != 0)
            {
                return false;
            }
            accumulator = ((accumulator << fromBits) | value) & maximumAccumulator;
            bits += fromBits;
            while (bits >= toBits)
            {
                bits -= toBits;
                if (bytesWritten >= output.Length)
                {
                    return false;
                }
                output[bytesWritten++] = (byte)((accumulator >> bits) & maximumOutput);
            }
        }

        if (pad)
        {
            if (bits > 0)
            {
                if (bytesWritten >= output.Length)
                {
                    return false;
                }
                output[bytesWritten++] = (byte)((accumulator << (toBits - bits)) & maximumOutput);
            }
        }
        else if (bits >= fromBits || ((accumulator << (toBits - bits)) & maximumOutput) != 0)
        {
            return false;
        }

        return true;
    }

    private static uint Polymod(ReadOnlySpan<byte> hrp, ReadOnlySpan<byte> values)
    {
        uint checksum = 1;
        foreach (var value in hrp)
        {
            checksum = PolymodStep(checksum, value);
        }
        foreach (var value in values)
        {
            checksum = PolymodStep(checksum, value);
        }
        return checksum;
    }

    private static uint PolymodStep(uint checksum, byte value)
    {
        ReadOnlySpan<uint> generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        var top = checksum >> 25;
        checksum = ((checksum & 0x1ffffff) << 5) ^ value;
        for (var bit = 0; bit < generators.Length; bit++)
        {
            if (((top >> bit) & 1) != 0)
            {
                checksum ^= generators[bit];
            }
        }
        return checksum;
    }

    private static byte[] HrpExpand(string hrp)
    {
        var expanded = new byte[(hrp.Length * 2) + 1];
        for (var index = 0; index < hrp.Length; index++)
        {
            expanded[index] = (byte)(hrp[index] >> 5);
            expanded[hrp.Length + 1 + index] = (byte)(hrp[index] & 31);
        }
        return expanded;
    }

    private static sbyte[] CreateCharacterMap()
    {
        var map = Enumerable.Repeat((sbyte)-1, 128).ToArray();
        for (var index = 0; index < CharacterSet.Length; index++)
        {
            map[CharacterSet[index]] = checked((sbyte)index);
        }
        return map;
    }
}
