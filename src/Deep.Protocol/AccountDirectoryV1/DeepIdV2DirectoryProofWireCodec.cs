using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Shape-only DID2 proof request. Its DID2 and ADL1 V2 are mutually bound,
/// but the sender does not gain identity authority from those public bytes.
/// </summary>
public sealed class DeepIdV2DirectoryProofWireRequest
{
    private readonly byte[] nonce;
    private readonly byte[] bootId;
    private readonly byte[] leaf;

    internal DeepIdV2DirectoryProofWireRequest(ParsedAdl1V2 lookup,
        ParsedDid2 deepId, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> bootId, ulong clientMonotonicSendSample,
        ReadOnlySpan<byte> leaf)
    {
        Lookup = lookup;
        DeepId = deepId;
        this.nonce = nonce.ToArray();
        this.bootId = bootId.ToArray();
        this.leaf = leaf.ToArray();
        ClientMonotonicSendSample = clientMonotonicSendSample;
    }

    public ParsedAdl1V2 Lookup { get; }
    public ParsedDid2 DeepId { get; }
    public ReadOnlyMemory<byte> NetworkId => Lookup.NetworkId;
    public ReadOnlyMemory<byte> Nonce => nonce.ToArray();
    public ReadOnlyMemory<byte> BootId => bootId.ToArray();
    public ReadOnlyMemory<byte> DirectoryLeafKey => leaf.ToArray();
    public ulong ClientMonotonicSendSample { get; }
}

/// <summary>
/// Shape-only response; clients must independently verify XPoint authority,
/// DID2/DAB2 query binding, threshold signatures, PQ admission and freshness.
/// </summary>
public sealed class DeepIdV2DirectoryProofWireResponse
{
    private readonly byte[] exactAdh1;
    private readonly byte[] exactDtt1;
    private readonly byte[] exactAdp1V2;

    internal DeepIdV2DirectoryProofWireResponse(ReadOnlySpan<byte> exactAdh1,
        ReadOnlySpan<byte> exactDtt1, ReadOnlySpan<byte> exactAdp1V2)
    {
        this.exactAdh1 = exactAdh1.ToArray();
        this.exactDtt1 = exactDtt1.ToArray();
        this.exactAdp1V2 = exactAdp1V2.ToArray();
    }

    public ReadOnlyMemory<byte> ExactAdh1 => exactAdh1.ToArray();
    public ReadOnlyMemory<byte> ExactDtt1 => exactDtt1.ToArray();
    public ReadOnlyMemory<byte> ExactAdp1V2 => exactAdp1V2.ToArray();
}

/// <summary>
/// Exact, bounded V2-only HTTP payload framing. No V1 ADL1/ADP1, arbitrary
/// caller leaf or unsourced directory state can be reinterpreted as V2.
/// </summary>
public static class DeepIdV2DirectoryProofWireCodec
{
    public const ushort Version = 2;
    public const int RequestLength = 12 +
        DeepIdV2AccountDirectoryLookupCodec.CanonicalLength +
        DeepIdV2Codec.Did2Length + 32 + 16 + 8;
    public const int MaximumResponseLength = 12 + 16 + 32 + 32 + 16 + 8 +
        3 * 4 + 4096 + 65_535 + DeepIdV2Adp1Codec.MaximumLength;
    public const string RequestMediaType =
        "application/vnd.deep.directory-proof-request.v2+octet-stream";
    public const string ResponseMediaType =
        "application/vnd.deep.directory-proof.v2+octet-stream";
    private static ReadOnlySpan<byte> RequestMagic => ProtocolMagicBytes.DPQ2;
    private static ReadOnlySpan<byte> ResponseMagic => ProtocolMagicBytes.DPP2;

    public static byte[] EncodeRequest(ParsedAdl1V2 lookup,
        ParsedDid2 deepId, ReadOnlySpan<byte> nonce32,
        ReadOnlySpan<byte> bootId16, ulong clientMonotonicSendSample)
    {
        ArgumentNullException.ThrowIfNull(lookup);
        ArgumentNullException.ThrowIfNull(deepId);
        if (nonce32.Length != 32 || nonce32.IndexOfAnyExcept((byte)0) < 0 ||
            bootId16.Length != 16 || bootId16.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("DID2 proof nonce or boot ID is invalid.");
        var bytes = new byte[RequestLength];
        WriteHeader(bytes, RequestMagic);
        var offset = 12;
        lookup.CanonicalBytes.Span.CopyTo(bytes.AsSpan(offset));
        offset += DeepIdV2AccountDirectoryLookupCodec.CanonicalLength;
        deepId.CanonicalBytes.Span.CopyTo(bytes.AsSpan(offset));
        offset += DeepIdV2Codec.Did2Length;
        nonce32.CopyTo(bytes.AsSpan(offset));
        offset += 32;
        bootId16.CopyTo(bytes.AsSpan(offset));
        offset += 16;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset),
            clientMonotonicSendSample);
        _ = DecodeRequest(bytes);
        return bytes;
    }

    public static DeepIdV2DirectoryProofWireRequest DecodeRequest(
        ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != RequestLength)
            throw new FormatException("DID2 proof request length is invalid.");
        VerifyHeader(bytes, RequestMagic);
        var offset = 12;
        var lookup = DeepIdV2AccountDirectoryLookupCodec.Decode(
            bytes.Slice(offset,
                DeepIdV2AccountDirectoryLookupCodec.CanonicalLength));
        offset += DeepIdV2AccountDirectoryLookupCodec.CanonicalLength;
        var deepId = DeepIdV2Codec.DecodeDid2(
            bytes.Slice(offset, DeepIdV2Codec.Did2Length));
        offset += DeepIdV2Codec.Did2Length;
        var nonce = bytes.Slice(offset, 32);
        offset += 32;
        var boot = bytes.Slice(offset, 16);
        offset += 16;
        if (nonce.IndexOfAnyExcept((byte)0) < 0 ||
            boot.IndexOfAnyExcept((byte)0) < 0 ||
            lookup.ServiceProfile != 1)
            throw new FormatException(
                "DID2 proof request nonce, boot ID or service profile is invalid.");
        var expectedLookup = DeepIdV2AccountDirectoryCodec
            .ComputeDirectoryLookupKey(lookup.NetworkId.Span, deepId);
        try
        {
            if (!Fixed(expectedLookup, lookup.DirectoryLookupKey.Span))
                throw new FormatException(
                    "DID2 proof lookup is not bound to the exact DID2.");
        }
        finally { CryptographicOperations.ZeroMemory(expectedLookup); }
        var leaf = DeepIdV2AccountDirectoryCodec.ComputeDirectoryLeafKey(
            lookup.NetworkId.Span, deepId);
        return new DeepIdV2DirectoryProofWireRequest(lookup, deepId, nonce,
            boot, BinaryPrimitives.ReadUInt64BigEndian(bytes[offset..]), leaf);
    }

    public static byte[] EncodeResponse(
        DeepIdV2DirectoryProofWireRequest request,
        AuthoredDeepIdV2DirectoryProofPackage issued)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(issued);
        if (!Fixed(issued.Nonce.Span, request.Nonce.Span) ||
            !Fixed(issued.BootId.Span, request.BootId.Span) ||
            !Fixed(issued.QueriedDirectoryLeafKey.Span,
                request.DirectoryLeafKey.Span) ||
            issued.ClientMonotonicSendSample !=
                request.ClientMonotonicSendSample)
            throw new CryptographicException(
                "DID2 proof issuance is not bound to the request.");
        var head = issued.ExactAdh1.Span;
        var dtt = issued.ExactDtt1.Span;
        var adp = issued.ExactAdp1V2.Span;
        if (head.Length is < 1 or > 4096 ||
            dtt.Length is < 1 or > 65_535 ||
            adp.Length is < 1 or > DeepIdV2Adp1Codec.MaximumLength)
            throw new FormatException("DID2 proof artifact length is invalid.");
        var length = checked(12 + 16 + 32 + 32 + 16 + 8 +
            3 * 4 + head.Length + dtt.Length + adp.Length);
        var bytes = new byte[length];
        WriteHeader(bytes, ResponseMagic);
        var offset = 12;
        request.NetworkId.Span.CopyTo(bytes.AsSpan(offset));
        offset += 16;
        request.DirectoryLeafKey.Span.CopyTo(bytes.AsSpan(offset));
        offset += 32;
        request.Nonce.Span.CopyTo(bytes.AsSpan(offset));
        offset += 32;
        request.BootId.Span.CopyTo(bytes.AsSpan(offset));
        offset += 16;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset),
            request.ClientMonotonicSendSample);
        offset += 8;
        WriteArtifact(bytes, ref offset, head);
        WriteArtifact(bytes, ref offset, dtt);
        WriteArtifact(bytes, ref offset, adp);
        _ = DecodeResponse(bytes, request);
        return bytes;
    }

    public static DeepIdV2DirectoryProofWireResponse DecodeResponse(
        ReadOnlySpan<byte> bytes, DeepIdV2DirectoryProofWireRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (bytes.Length is < 128 or > MaximumResponseLength)
            throw new FormatException("DID2 proof response length is invalid.");
        VerifyHeader(bytes, ResponseMagic);
        var offset = 12;
        if (!Fixed(Read(bytes, ref offset, 16), request.NetworkId.Span) ||
            !Fixed(Read(bytes, ref offset, 32), request.DirectoryLeafKey.Span) ||
            !Fixed(Read(bytes, ref offset, 32), request.Nonce.Span) ||
            !Fixed(Read(bytes, ref offset, 16), request.BootId.Span) ||
            BinaryPrimitives.ReadUInt64BigEndian(Read(bytes, ref offset, 8)) !=
                request.ClientMonotonicSendSample)
            throw new FormatException(
                "DID2 proof response echo differs from the exact request.");
        var headBytes = ReadArtifact(bytes, ref offset, 4096);
        var dttBytes = ReadArtifact(bytes, ref offset, 65_535);
        var adpBytes = ReadArtifact(bytes, ref offset,
            DeepIdV2Adp1Codec.MaximumLength);
        if (offset != bytes.Length)
            throw new FormatException("DID2 proof response has trailing bytes.");
        var head = AccountDirectoryAdh1Codec.Decode(headBytes);
        var dtt = AccountDirectoryDtt1Codec.Decode(dttBytes);
        var adp = DeepIdV2Adp1Codec.Decode(adpBytes);
        var headHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
        var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
        if (head.MinimumReader < 2 ||
            !Fixed(head.NetworkId.Span, request.NetworkId.Span) ||
            !Fixed(dtt.NetworkId.Span, request.NetworkId.Span) ||
            !Fixed(dtt.ClientNonce.Span, request.Nonce.Span) ||
            dtt.CurrentAdh1Generation != head.LogGeneration ||
            !Fixed(dtt.CurrentAdh1CoreHash.Span, headHash) ||
            !Fixed(adp.ExactField(1).Span, request.NetworkId.Span) ||
            !Fixed(adp.QueriedDirectoryLeafKey.Span,
                request.DirectoryLeafKey.Span) ||
            !Fixed(adp.ExactField(4).Span, headBytes) ||
            !Fixed(adp.LiveDtt1CoreHash.Span, dttHash) ||
            (adp.ResultKind == AccountDirectoryAdp1ResultKind.CurrentValue &&
             !Fixed(adp.ExactDid2.Span,
                 request.DeepId.CanonicalBytes.Span)))
            throw new FormatException(
                "DID2 proof response cross-links do not match the request.");
        if (head.LogGeneration < request.Lookup.MinimumAdhGeneration ||
            head.LogGeneration == request.Lookup.MinimumAdhGeneration &&
            !Fixed(headHash, request.Lookup.MinimumAdhHash.Span))
            throw new FormatException("DID2 proof response rolls back the query floor.");
        return new DeepIdV2DirectoryProofWireResponse(headBytes, dttBytes,
            adpBytes);
    }

    private static void WriteHeader(Span<byte> bytes, ReadOnlySpan<byte> magic)
    {
        magic.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes[4..], Version);
        BinaryPrimitives.WriteUInt32BigEndian(bytes[8..],
            checked((uint)bytes.Length));
    }

    private static void VerifyHeader(ReadOnlySpan<byte> bytes,
        ReadOnlySpan<byte> magic)
    {
        if (bytes.Length < 12 || !bytes[..4].SequenceEqual(magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]) != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]) != 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(bytes[8..]) != bytes.Length)
            throw new FormatException("DID2 proof wire header is invalid.");
    }

    private static void WriteArtifact(Span<byte> bytes, ref int offset,
        ReadOnlySpan<byte> value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(bytes[offset..],
            checked((uint)value.Length));
        offset += 4;
        value.CopyTo(bytes[offset..]);
        offset += value.Length;
    }

    private static ReadOnlySpan<byte> ReadArtifact(ReadOnlySpan<byte> bytes,
        ref int offset, int maximum)
    {
        var length = BinaryPrimitives.ReadUInt32BigEndian(
            Read(bytes, ref offset, 4));
        if (length is < 1 || length > maximum)
            throw new FormatException("DID2 proof artifact length is invalid.");
        return Read(bytes, ref offset, checked((int)length));
    }

    private static ReadOnlySpan<byte> Read(ReadOnlySpan<byte> bytes,
        ref int offset, int length)
    {
        if (length < 0 || bytes.Length - offset < length)
            throw new FormatException("DID2 proof wire is truncated.");
        var slice = bytes.Slice(offset, length);
        offset += length;
        return slice;
    }

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) => left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
