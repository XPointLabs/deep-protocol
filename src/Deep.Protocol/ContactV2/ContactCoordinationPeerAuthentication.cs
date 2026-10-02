using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using Sodium;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.ContactV2;

public enum ContactCoordinationTarget : byte { Route = 1, Publication = 2 }

public sealed record ContactCoordinationPeerHeaders(
    string NodePublicKeyHex, string TimestampUnixMilliseconds, string NonceHex, string SignatureHex);

// DR48 transport authentication only. Never DID2, NET, witness or ACK authority.
public static class ContactCoordinationPeerAuthentication
{
    public const string NodeHeader = "Deep-Coordination-Node";
    public const string TimestampHeader = "Deep-Coordination-Timestamp";
    public const string NonceHeader = "Deep-Coordination-Nonce";
    public const string SignatureHeader = "Deep-Coordination-Signature";
    public const long MaximumSkewMilliseconds = 30_000;
    private static ReadOnlySpan<byte> Domain => "Deep/ContactResolver/V2/private-coordination-peer"u8;

    public static byte[] GetSigningInput(ReadOnlySpan<byte> networkId16, ContactCoordinationTarget target,
        ReadOnlySpan<byte> nodePublicKey32, long timestampUnixMilliseconds, ReadOnlySpan<byte> nonce16,
        ReadOnlySpan<byte> exactRequest)
    {
        RequireTargetBody(target, exactRequest);
        if (networkId16.Length != 16 || nodePublicKey32.Length != 32 || nonce16.Length != 16 ||
            networkId16.IndexOfAnyExcept((byte)0) < 0 || nodePublicKey32.IndexOfAnyExcept((byte)0) < 0 ||
            nonce16.IndexOfAnyExcept((byte)0) < 0 || timestampUnixMilliseconds <= 0)
            throw new ArgumentException("Private coordination signing fields are not canonical.");
        var result = new byte[Domain.Length + 1 + 2 + 16 + 1 + 32 + 8 + 16 + 32];
        Domain.CopyTo(result); var offset = Domain.Length + 1;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), 2); offset += 2;
        networkId16.CopyTo(result.AsSpan(offset)); offset += 16; result[offset++] = (byte)target;
        nodePublicKey32.CopyTo(result.AsSpan(offset)); offset += 32;
        BinaryPrimitives.WriteInt64BigEndian(result.AsSpan(offset), timestampUnixMilliseconds); offset += 8;
        nonce16.CopyTo(result.AsSpan(offset)); offset += 16;
        SHA256.HashData(exactRequest, result.AsSpan(offset)); return result;
    }

    public static bool IsCanonical(ContactCoordinationPeerHeaders headers)
    {
        ArgumentNullException.ThrowIfNull(headers);
        return Hex(headers.NodePublicKeyHex, 64) && Hex(headers.NonceHex, 32) && Hex(headers.SignatureHex, 128) &&
            headers.TimestampUnixMilliseconds is { Length: > 0 and <= 19 } text &&
            long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp) && timestamp > 0 &&
            text == timestamp.ToString(CultureInfo.InvariantCulture);
    }

    public static bool IsWithinAdmissionWindow(ContactCoordinationPeerHeaders headers, DateTimeOffset now)
    {
        if (!IsCanonical(headers)) return false;
        var timestamp = long.Parse(headers.TimestampUnixMilliseconds, CultureInfo.InvariantCulture);
        var observed = now.ToUnixTimeMilliseconds();
        return timestamp >= observed - MaximumSkewMilliseconds && timestamp <= observed + MaximumSkewMilliseconds;
    }

    public static bool Verify(ContactCoordinationPeerHeaders headers, ReadOnlySpan<byte> networkId16,
        ContactCoordinationTarget target, ReadOnlySpan<byte> exactRequest, DateTimeOffset now)
    {
        if (!IsWithinAdmissionWindow(headers, now)) return false;
        byte[]? input = null;
        try
        {
            var node = Convert.FromHexString(headers.NodePublicKeyHex);
            var nonce = Convert.FromHexString(headers.NonceHex);
            var signature = Convert.FromHexString(headers.SignatureHex);
            input = GetSigningInput(networkId16, target, node,
                long.Parse(headers.TimestampUnixMilliseconds, CultureInfo.InvariantCulture), nonce, exactRequest);
            return PublicKeyAuth.VerifyDetached(signature, input, node);
        }
        catch (Exception error) when (error is ArgumentException or FormatException or CryptographicException) { return false; }
        finally { if (input is not null) CryptographicOperations.ZeroMemory(input); }
    }

    private static bool Hex(string? value, int length) => value is not null && value.Length == length &&
        value.AsSpan().IndexOfAnyExcept("0123456789abcdef") < 0 && value.AsSpan().IndexOfAnyExcept('0') >= 0;

    private static void RequireTargetBody(ContactCoordinationTarget target, ReadOnlySpan<byte> body)
    {
        var valid = target switch
        {
            ContactCoordinationTarget.Route => body.Length >= ContactRouteAuthorityWireCodec.MinimumRequestBytes &&
                body.Length <= ContactRouteAuthorityWireCodec.MaximumRequestBytes,
            ContactCoordinationTarget.Publication => body.Length >= ContactPublicationAuthorityWireCodec.MinimumRequestBytes &&
                body.Length <= ContactPublicationAuthorityWireCodec.MaximumRequestBytes,
            _ => false
        };
        if (!valid) throw new ArgumentException("Private coordination target/body exceeds its frozen bound.");
    }
}
