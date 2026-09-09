using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

internal enum TripleRatchetDirection : byte
{
    AliceToBob = 1,
    BobToAlice = 2,
}

internal abstract class OwnedRatchetKdfOutput : IDisposable
{
    private readonly SecretBuffer[] values;
    private int disposed;

    protected OwnedRatchetKdfOutput(params ReadOnlyMemory<byte>[] values)
    {
        var owned = new SecretBuffer[values.Length];
        try
        {
            for (var index = 0; index < values.Length; index++)
                owned[index] = SecretBuffer.ImportExact(values[index].Span, 32, $"kdfOutput{index}");
            this.values = owned;
        }
        catch
        {
            foreach (var value in owned) value?.Dispose();
            throw;
        }
    }

    protected TResult Use<TResult>(int index, MessagingSecretFunc<TResult> reader)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return values[index].Use(reader);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        foreach (var value in values) value.Dispose();
    }
}

internal sealed class EcRootKdfOutput(
    ReadOnlyMemory<byte> root,
    ReadOnlyMemory<byte> chain) : OwnedRatchetKdfOutput(root, chain)
{
    internal TResult UseRoot<TResult>(MessagingSecretFunc<TResult> reader) => Use(0, reader);
    internal TResult UseChain<TResult>(MessagingSecretFunc<TResult> reader) => Use(1, reader);
}

internal sealed class EcChainKdfOutput(
    ReadOnlyMemory<byte> nextChain,
    ReadOnlyMemory<byte> messageKey) : OwnedRatchetKdfOutput(nextChain, messageKey)
{
    internal TResult UseNextChain<TResult>(MessagingSecretFunc<TResult> reader) => Use(0, reader);
    internal TResult UseMessageKey<TResult>(MessagingSecretFunc<TResult> reader) => Use(1, reader);
}

internal sealed class SpqrEpochKdfOutput(
    ReadOnlyMemory<byte> root,
    ReadOnlyMemory<byte> aliceToBob,
    ReadOnlyMemory<byte> bobToAlice) : OwnedRatchetKdfOutput(root, aliceToBob, bobToAlice)
{
    internal TResult UseRoot<TResult>(MessagingSecretFunc<TResult> reader) => Use(0, reader);
    internal TResult UseAliceToBob<TResult>(MessagingSecretFunc<TResult> reader) => Use(1, reader);
    internal TResult UseBobToAlice<TResult>(MessagingSecretFunc<TResult> reader) => Use(2, reader);
}

internal sealed class SpqrChainKdfOutput(
    ReadOnlyMemory<byte> nextChain,
    ReadOnlyMemory<byte> messageKey) : OwnedRatchetKdfOutput(nextChain, messageKey)
{
    internal TResult UseNextChain<TResult>(MessagingSecretFunc<TResult> reader) => Use(0, reader);
    internal TResult UseMessageKey<TResult>(MessagingSecretFunc<TResult> reader) => Use(1, reader);
}

/// <summary>
/// Exact application-specific KDF instantiation for the Double Ratchet, SPQR,
/// and their Triple Ratchet composition. It advances no state by itself; the
/// caller must persist successor state before disposing predecessor keys.
/// </summary>
internal static class ManagedTripleRatchetKdfProfile
{
    internal const string DoubleRatchetProtocolInfo =
        "DeepDoubleRatchetV1_X25519_HKDF-SHA-512_HMAC-SHA-256";
    internal const string SpqrProtocolInfo =
        "DeepSparsePqRatchetV1_MLKEM768_HKDF-SHA-512_HMAC-SHA-256";

    internal static EcRootKdfOutput DeriveEcRoot(
        ReadOnlySpan<byte> oldRootKey,
        ReadOnlySpan<byte> x25519Output)
    {
        MessagingCryptoValidation.NonZeroExact(oldRootKey, 32, nameof(oldRootKey));
        MessagingCryptoValidation.NonZeroExact(x25519Output, 32, nameof(x25519Output));
        var expanded = Expand(
            oldRootKey,
            x25519Output,
            Context("Deep/Messaging/V2/ec-root-step", DoubleRatchetProtocolInfo),
            64);
        try { return new EcRootKdfOutput(expanded.AsMemory(0, 32), expanded.AsMemory(32, 32)); }
        finally { CryptographicOperations.ZeroMemory(expanded); }
    }

    internal static EcChainKdfOutput DeriveEcChain(ReadOnlySpan<byte> oldChainKey)
    {
        MessagingCryptoValidation.NonZeroExact(oldChainKey, 32, nameof(oldChainKey));
        var message = Hmac(
            oldChainKey,
            "Deep/Messaging/V2/ec-chain-message",
            DoubleRatchetProtocolInfo);
        var next = Hmac(
            oldChainKey,
            "Deep/Messaging/V2/ec-chain-next",
            DoubleRatchetProtocolInfo);
        try { return new EcChainKdfOutput(next, message); }
        finally
        {
            CryptographicOperations.ZeroMemory(next);
            CryptographicOperations.ZeroMemory(message);
        }
    }

    internal static SpqrEpochKdfOutput InitializeSpqr(ReadOnlySpan<byte> initialSecret)
    {
        MessagingCryptoValidation.NonZeroExact(initialSecret, 32, nameof(initialSecret));
        Span<byte> zeroSalt = stackalloc byte[64];
        var expanded = Expand(
            zeroSalt,
            initialSecret,
            Context("Deep/Messaging/V2/spqr-chain-start", SpqrProtocolInfo),
            96);
        try
        {
            return new SpqrEpochKdfOutput(
                expanded.AsMemory(0, 32),
                expanded.AsMemory(32, 32),
                expanded.AsMemory(64, 32));
        }
        finally { CryptographicOperations.ZeroMemory(expanded); }
    }

    internal static SpqrEpochKdfOutput AdvanceSpqrEpoch(
        ReadOnlySpan<byte> oldRootKey,
        ReadOnlySpan<byte> braidOutputKey,
        ulong epoch)
    {
        MessagingCryptoValidation.NonZeroExact(oldRootKey, 32, nameof(oldRootKey));
        MessagingCryptoValidation.NonZeroExact(braidOutputKey, 32, nameof(braidOutputKey));
        if (epoch == 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "A successor SPQR epoch must be nonzero.");
        var expanded = Expand(
            oldRootKey,
            braidOutputKey,
            Context("Deep/Messaging/V2/spqr-chain-add-epoch", SpqrProtocolInfo, U64(epoch)),
            96);
        try
        {
            return new SpqrEpochKdfOutput(
                expanded.AsMemory(0, 32),
                expanded.AsMemory(32, 32),
                expanded.AsMemory(64, 32));
        }
        finally { CryptographicOperations.ZeroMemory(expanded); }
    }

    internal static SpqrChainKdfOutput DeriveSpqrChain(
        ReadOnlySpan<byte> oldChainKey,
        ulong epoch,
        TripleRatchetDirection direction,
        ulong counter)
    {
        MessagingCryptoValidation.NonZeroExact(oldChainKey, 32, nameof(oldChainKey));
        if (!Enum.IsDefined(direction))
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The SPQR chain direction is invalid.");
        Span<byte> zeroSalt = stackalloc byte[64];
        var expanded = Expand(
            zeroSalt,
            oldChainKey,
            Context(
                "Deep/Messaging/V2/spqr-chain-step",
                SpqrProtocolInfo,
                U64(epoch),
                new byte[] { (byte)direction },
                U64(counter)),
            64);
        try { return new SpqrChainKdfOutput(expanded.AsMemory(0, 32), expanded.AsMemory(32, 32)); }
        finally { CryptographicOperations.ZeroMemory(expanded); }
    }

    private static byte[] Expand(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> ikm,
        byte[] info,
        int length)
    {
        Span<byte> prk = stackalloc byte[64];
        var output = new byte[length];
        try
        {
            if (HKDF.Extract(HashAlgorithmName.SHA512, ikm, salt, prk) != prk.Length)
                throw new CryptographicException("HKDF extract returned an unexpected length.");
            HKDF.Expand(HashAlgorithmName.SHA512, prk, output, info);
            return output;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(output);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(info);
        }
    }

    private static byte[] Hmac(
        ReadOnlySpan<byte> key,
        string label,
        string protocolInfo)
    {
        var input = Context(label, protocolInfo);
        try { return HMACSHA256.HashData(key, input); }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private static byte[] Context(
        string label,
        string protocolInfo,
        params ReadOnlyMemory<byte>[] parts)
    {
        var protocol = Encoding.ASCII.GetBytes(protocolInfo);
        var all = new ReadOnlyMemory<byte>[parts.Length + 1];
        all[0] = protocol;
        parts.CopyTo(all, 1);
        try { return MessagingWireCryptographicInputs.Context(label, all); }
        finally { CryptographicOperations.ZeroMemory(protocol); }
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }
}
