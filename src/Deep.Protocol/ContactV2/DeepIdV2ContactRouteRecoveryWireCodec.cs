using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.ContactV2;

public enum DeepIdV2ContactRouteRecoveryMode : byte { ReadRecordedWinner = 1, IssueAfterRecordedHistory = 2 }

/// <summary>Exact untrusted original exchange; parsing does not authenticate history.</summary>
public sealed class DeepIdV2ContactRouteRecordedPair
{
    private readonly byte[] request, response;
    public DeepIdV2ContactRouteRecordedPair(ReadOnlySpan<byte> exactRequest, ReadOnlySpan<byte> exactResponse)
    {
        Request = ContactRouteAuthorityWireCodec.DecodeRequest(exactRequest);
        if (!Request.HasPredecessor) throw new FormatException("Recorded history requires an ordinary successor request.");
        Response = ContactRouteAuthorityWireCodec.DecodeResponse(Request, exactResponse);
        request = exactRequest.ToArray(); response = exactResponse.ToArray();
    }
    public ContactRouteAuthorityWireRequest Request { get; }
    public ContactRouteAuthorityWireResponse Response { get; }
    public ReadOnlyMemory<byte> ExactRequest => request.ToArray();
    public ReadOnlyMemory<byte> ExactResponse => response.ToArray();
}

/// <summary>Signed transport envelope only; never historical or current route authority.</summary>
public sealed class DeepIdV2ContactRouteRecoveryWireRequest
{
    private readonly byte[] exact;
    internal DeepIdV2ContactRouteRecoveryWireRequest(byte[] exact, DeepIdV2ContactRouteRecordedPair[] history)
    { this.exact = exact; History = Array.AsReadOnly(history); }
    public DeepIdV2ContactRouteRecoveryWireRequest(DeepIdV2ContactRouteRecoveryMode mode,
        ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> requestNonce, ReadOnlySpan<byte> directoryLookupKey,
        ulong minimumAdh1Generation, ReadOnlySpan<byte> minimumAdh1CoreHash, ReadOnlySpan<byte> viewHash,
        ulong issuedAtUnixSeconds, ulong expiresAtUnixSeconds, ReadOnlySpan<byte> exactBaseRequest,
        IReadOnlyList<DeepIdV2ContactRouteRecordedPair> history, ReadOnlySpan<byte> deviceSignature)
    {
        var parsed = DeepIdV2ContactRouteRecoveryWireCodec.Create(mode, networkId, requestNonce, directoryLookupKey,
            minimumAdh1Generation, minimumAdh1CoreHash, viewHash, issuedAtUnixSeconds, expiresAtUnixSeconds,
            exactBaseRequest, history, deviceSignature);
        exact = parsed.exact; History = parsed.History;
    }
    public ReadOnlyMemory<byte> CanonicalBytes => exact.ToArray();
    public DeepIdV2ContactRouteRecoveryMode Mode => (DeepIdV2ContactRouteRecoveryMode)exact[2];
    public ReadOnlyMemory<byte> NetworkId => Copy(8, 16);
    public ReadOnlyMemory<byte> RequestNonce => Copy(24, 32);
    public ReadOnlyMemory<byte> DirectoryLookupKey => Copy(56, 32);
    public ulong MinimumAdh1Generation => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(88));
    public ReadOnlyMemory<byte> MinimumAdh1CoreHash => Copy(96, 32);
    public ReadOnlyMemory<byte> ViewHash => Copy(128, 32);
    public ulong IssuedAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(160));
    public ulong ExpiresAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(168));
    public ReadOnlyMemory<byte> ExactBaseRequest => Copy(180, checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(176))));
    public ContactRouteAuthorityWireRequest BaseRequest => ContactRouteAuthorityWireCodec.DecodeRequest(ExactBaseRequest.Span);
    public IReadOnlyList<DeepIdV2ContactRouteRecordedPair> History { get; }
    public ReadOnlyMemory<byte> DeviceSignature => Copy(exact.Length - 64, 64);
    public ReadOnlyMemory<byte> GatewayShard => DeepIdV2ContactRouteRecoveryWireCodec.GatewayShard(NetworkId.Span, RequestNonce.Span);
    private byte[] Copy(int start, int length) => exact.AsSpan(start, length).ToArray();
}

public static class DeepIdV2ContactRouteRecoveryWireCodec
{
    public const int RequestFixedOverheadBytes = 248, MaximumPairBytes = 40_252;
    public const int MinimumRequestBytes = 6_161, MaximumRequestBytes = 146_069;
    public const int MinimumResponseBytes = 2_676, MaximumResponseBytes = 15_271;
    public const string EndpointPath = "/api/v2/contact-route-recovery";
    public const string RequestMediaType = "application/vnd.deep.contact-route-recovery-request.v1+octet-stream";
    public const string ResponseMediaType = "application/vnd.deep.contact-route-recovery-response.v1+octet-stream";
    public const string DeviceSigningDomain = "Deep/ContactResolver/V2/route-recovery-request";
    public const string GatewayShardDomain = "Deep/ContactResolver/V2/route-recovery-gateway";

    public static byte[] EncodeRequest(DeepIdV2ContactRouteRecoveryWireRequest request) => request.CanonicalBytes.ToArray();
    public static byte[] SigningInput(DeepIdV2ContactRouteRecoveryWireRequest request) =>
        ApplicationCoreFormat.SignatureInput(DeviceSigningDomain, request.CanonicalBytes.Span[..^64], DeepIdV2Codec.Suite);
    internal static byte[] GatewayShard(ReadOnlySpan<byte> network, ReadOnlySpan<byte> nonce)
    { var input = new byte[48]; network.CopyTo(input); nonce.CopyTo(input.AsSpan(16)); return ApplicationCoreFormat.Sha256Domain(GatewayShardDomain, input); }

    internal static DeepIdV2ContactRouteRecoveryWireRequest Create(DeepIdV2ContactRouteRecoveryMode mode,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> leaf, ulong generation,
        ReadOnlySpan<byte> hash, ReadOnlySpan<byte> view, ulong issued, ulong expiry, ReadOnlySpan<byte> request,
        IReadOnlyList<DeepIdV2ContactRouteRecordedPair> history, ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(history);
        if (network.Length != 16 || nonce.Length != 32 || leaf.Length != 32 || hash.Length != 32 || view.Length != 32 || signature.Length != 64 || history.Count > 3)
            throw new ArgumentException("Recovery envelope widths/count are invalid.");
        var length = checked(RequestFixedOverheadBytes + request.Length + history.Sum(pair => checked(8 + pair.ExactRequest.Length + pair.ExactResponse.Length)));
        if (length > MaximumRequestBytes) throw new FormatException("Recovery envelope exceeds its bound.");
        var bytes = new byte[length]; Header(bytes, mode); network.CopyTo(bytes.AsSpan(8)); nonce.CopyTo(bytes.AsSpan(24)); leaf.CopyTo(bytes.AsSpan(56));
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(88), generation); hash.CopyTo(bytes.AsSpan(96)); view.CopyTo(bytes.AsSpan(128));
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(160), issued); BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(168), expiry);
        var offset = 176; Write(bytes, ref offset, request); bytes[offset] = checked((byte)history.Count); offset += 4;
        foreach (var pair in history) { Write(bytes, ref offset, pair.ExactRequest.Span); Write(bytes, ref offset, pair.ExactResponse.Span); }
        signature.CopyTo(bytes.AsSpan(offset)); return DecodeRequest(bytes);
    }

    public static DeepIdV2ContactRouteRecoveryWireRequest DecodeRequest(ReadOnlySpan<byte> bytes)
    {
        var mode = ReadHeader(bytes, MinimumRequestBytes, MaximumRequestBytes);
        if (mode == DeepIdV2ContactRouteRecoveryMode.ReadRecordedWinner && bytes.Length > 105_817) throw new FormatException("Recorded read exceeds its bound.");
        foreach (var (start, length) in new[] { (8,16),(24,32),(56,32),(96,32),(128,32),(bytes.Length-64,64) })
            if (bytes.Slice(start, length).IndexOfAnyExcept((byte)0) < 0) throw new FormatException("Recovery envelope has a zero required field.");
        var issued = BinaryPrimitives.ReadUInt64BigEndian(bytes[160..]); var expiry = BinaryPrimitives.ReadUInt64BigEndian(bytes[168..]);
        if (issued == 0 || expiry <= issued || expiry - issued > 120) throw new FormatException("Recovery envelope has an invalid interval.");
        var offset = 176; var baseBytes = Read(bytes, ref offset, ContactRouteAuthorityWireCodec.MaximumRequestBytes);
        var request = ContactRouteAuthorityWireCodec.DecodeRequest(baseBytes);
        if (!request.HasPredecessor || !Fixed(request.NetworkId.Span, bytes.Slice(8,16)) || !Fixed(request.DirectoryLookupKey.Span, bytes.Slice(56,32)))
            throw new FormatException("Recovery envelope differs from its successor request scope.");
        if (offset > bytes.Length - 68) throw new FormatException("Recovery history count is truncated.");
        var count = bytes[offset]; if (bytes.Slice(offset+1,3).IndexOfAnyExcept((byte)0) >= 0 || count > (mode == DeepIdV2ContactRouteRecoveryMode.ReadRecordedWinner ? 2 : 3) ||
            (mode == DeepIdV2ContactRouteRecoveryMode.IssueAfterRecordedHistory && count == 0)) throw new FormatException("Recovery history count/reserved bytes are invalid.");
        offset += 4; var pairs = new DeepIdV2ContactRouteRecordedPair[count];
        for (var index = 0; index < count; index++)
        { var prior = Read(bytes, ref offset, ContactRouteAuthorityWireCodec.MaximumRequestBytes); var response = Read(bytes, ref offset, ContactRouteAuthorityWireCodec.MaximumResponseBytes); pairs[index] = new(prior, response); }
        if (offset != bytes.Length - 64) throw new FormatException("Recovery envelope has trailing bytes.");
        return new(bytes.ToArray(), pairs);
    }
    public static byte[] EncodeResponse(DeepIdV2ContactRouteRecoveryWireRequest request, ContactRouteAuthorityWireResponse response)
    {
        var body = ContactRouteAuthorityWireCodec.EncodeResponse(request.BaseRequest, response);
        var bytes = new byte[92 + body.Length]; Header(bytes, request.Mode); request.NetworkId.Span.CopyTo(bytes.AsSpan(8)); request.RequestNonce.Span.CopyTo(bytes.AsSpan(24));
        SHA256.HashData(request.ExactBaseRequest.Span, bytes.AsSpan(56,32)); var offset = 88; Write(bytes, ref offset, body); return bytes;
    }
    public static ContactRouteAuthorityWireResponse DecodeResponse(DeepIdV2ContactRouteRecoveryWireRequest request, ReadOnlySpan<byte> bytes)
    {
        if (ReadHeader(bytes, MinimumResponseBytes, MaximumResponseBytes) != request.Mode || !Fixed(bytes.Slice(8,16), request.NetworkId.Span) ||
            !Fixed(bytes.Slice(24,32), request.RequestNonce.Span) || !Fixed(bytes.Slice(56,32), SHA256.HashData(request.ExactBaseRequest.Span)))
            throw new FormatException("Recovery response differs from its exact outer request.");
        var offset = 88; var response = Read(bytes, ref offset, ContactRouteAuthorityWireCodec.MaximumResponseBytes, response: true);
        if (offset != bytes.Length) throw new FormatException("Recovery response has trailing bytes.");
        return ContactRouteAuthorityWireCodec.DecodeResponse(request.BaseRequest, response);
    }
    private static DeepIdV2ContactRouteRecoveryMode ReadHeader(ReadOnlySpan<byte> bytes, int minimum, int maximum)
    {
        if (bytes.Length < minimum || bytes.Length > maximum || BinaryPrimitives.ReadUInt16BigEndian(bytes) != 1 || bytes[2] is < 1 or > 2 || bytes[3] != 0 || BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]) != bytes.Length)
            throw new FormatException("Recovery framing is not canonical.");
        return (DeepIdV2ContactRouteRecoveryMode)bytes[2];
    }
    private static void Header(Span<byte> bytes, DeepIdV2ContactRouteRecoveryMode mode)
    { BinaryPrimitives.WriteUInt16BigEndian(bytes, 1); bytes[2] = (byte)mode; BinaryPrimitives.WriteUInt32BigEndian(bytes[4..], checked((uint)bytes.Length)); }
    private static void Write(Span<byte> bytes, ref int offset, ReadOnlySpan<byte> value)
    { BinaryPrimitives.WriteUInt32BigEndian(bytes[offset..], checked((uint)value.Length)); value.CopyTo(bytes[(offset+4)..]); offset += 4 + value.Length; }
    private static ReadOnlySpan<byte> Read(ReadOnlySpan<byte> bytes, ref int offset, int maximum, bool response = false)
    {
        var end = bytes.Length - (response ? 0 : 64);
        if (offset > end - 4) throw new FormatException("Recovery artifact length is truncated.");
        var length = BinaryPrimitives.ReadUInt32BigEndian(bytes[offset..]); offset += 4;
        if (length == 0 || length > maximum || length > end - offset) throw new FormatException("Recovery artifact exceeds its bound.");
        var value = bytes.Slice(offset, checked((int)length)); offset += value.Length; return value;
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left,right);
}
