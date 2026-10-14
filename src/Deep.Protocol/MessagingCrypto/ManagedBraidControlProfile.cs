using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

// DR-0112 internal primitive. No public raw-key author/verifier or dispatch grant.
internal static class ManagedBraidControlProfile
{
    internal static byte[] DeriveRoot(ReadOnlySpan<byte> actualSpqrRoot, ulong linkEpoch)
    {
        MessagingCryptoValidation.NonZeroExact(actualSpqrRoot, 32, nameof(actualSpqrRoot));
        byte[] info = [.. "Deep/MSG-V2/braid-control-root"u8, 0, 0x02, 0x01, .. U64(linkEpoch)];
        return Derive(actualSpqrRoot, info);
    }

    internal static byte[] ComputeAuthenticator(ReadOnlySpan<byte> ownedControlRoot, UnverifiedDbr2Record frame)
    {
        MessagingCryptoValidation.NonZeroExact(ownedControlRoot, 32, nameof(ownedControlRoot));
        byte[] info = [.. "Deep/MSG-V2/braid-control-direction"u8, 0, 0x02, 0x01,
            .. frame.NetworkId.Span, .. frame.SessionId.Span, .. frame.SenderDeviceId.Span,
            .. frame.RecipientDeviceId.Span, .. U64(frame.BraidEpoch - 1)];
        var key = Derive(ownedControlRoot, info);
        var input = Dbr2Codec.GetAuthenticationInput(frame);
        try { return HMACSHA256.HashData(key, input); }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(input); }
    }

    internal static UnverifiedDbr2Record CreateUnsigned(RatchetStateBinding binding, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> operation, ulong braidEpoch, byte slot, Dtr2BraidMessage braid)
    {
        var output = new byte[Dbr2Codec.TotalBytes];
        var writer = new MessagingWireWriter(output, ProtocolMagicBytes.DBR2, 11);
        writer.Write(1, network); writer.Write(2, binding.SessionId.Span);
        writer.Write(3, binding.LocalDeviceId.Span); writer.Write(4, binding.RemoteDeviceId.Span);
        writer.Write(5, operation); writer.Write(6, U64(braidEpoch));
        writer.Write(7, [slot]); writer.Write(8, [(byte)braid.Kind]); writer.Write(9, braid.PayloadSpan);
        writer.Write(10, new byte[3826 - braid.EncodedPayloadLength]); writer.Write(11, new byte[32]);
        writer.Complete();
        return Dbr2Codec.Decode(output);
    }

    internal static byte Slot(Dtr2BraidMessageKind kind) => kind switch
    {
        Dtr2BraidMessageKind.Header or Dtr2BraidMessageKind.Ciphertext1 => 1,
        Dtr2BraidMessageKind.EncapsulationKeyWithCiphertext1Ack or Dtr2BraidMessageKind.Ciphertext2 => 2,
        _ => throw new MessagingCryptoException(MessagingCryptoError.TransitionRejected,
            "Only complete progress-bearing public Braid controls are supported."),
    };

    private static byte[] Derive(ReadOnlySpan<byte> root, byte[] info)
    {
        Span<byte> salt = stackalloc byte[64]; salt.Clear();
        var output = new byte[32];
        try { HKDF.DeriveKey(HashAlgorithmName.SHA512, root, output, salt, info); return output; }
        catch { CryptographicOperations.ZeroMemory(output); throw; }
        finally { CryptographicOperations.ZeroMemory(info); }
    }

    private static byte[] U64(ulong value)
    {
        var encoded = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(encoded, value); return encoded;
    }
}
