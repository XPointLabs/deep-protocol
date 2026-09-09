using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// Managed implementation of the frozen DeepMlKemBraidFullV1 authenticator and
/// output-key profile. The incremental ML-KEM state machine remains a separate
/// provider boundary because the approved ML-KEM ABI currently exposes only
/// whole Encapsulate/Decapsulate operations.
/// </summary>
internal sealed class ManagedMlKemBraidAuthenticator : IDisposable
{
    private const string ProtocolInfo = "DeepMlKemBraidFullV1_MLKEM768_HMAC-SHA-256";
    private const string LocalStateDomain = "Deep/LocalState/V1/managed-mlkem-braid-auth";
    private const byte SealedStateVersion = 1;
    private const int SealedPlaintextSize = 2 + 8 + 32 + 32;
    private const int SealedStateSize = 1 + 24 + SealedPlaintextSize + 16;
    private const int LocalPlaintextStateSize = 4 + 1 + SealedPlaintextSize;

    private readonly SecretBuffer _rootKey;
    private readonly SecretBuffer _macKey;
    private int _disposed;

    private ManagedMlKemBraidAuthenticator(
        ulong epoch,
        ReadOnlySpan<byte> rootKey,
        ReadOnlySpan<byte> macKey)
    {
        if (epoch == 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The ML-KEM Braid authenticator epoch must be nonzero.");
        MessagingCryptoValidation.NonZeroExact(rootKey, 32, nameof(rootKey));
        MessagingCryptoValidation.NonZeroExact(macKey, 32, nameof(macKey));
        SecretBuffer? root = null;
        SecretBuffer? mac = null;
        try
        {
            root = SecretBuffer.ImportExact(rootKey, 32, nameof(rootKey));
            MessagingCryptoFaultInjection.OwnedSecret("braid.auth.root", root);
            MessagingCryptoFaultInjection.Point("braid.auth.after-root");
            mac = SecretBuffer.ImportExact(macKey, 32, nameof(macKey));
            MessagingCryptoFaultInjection.OwnedSecret("braid.auth.mac", mac);
            Epoch = epoch;
            _rootKey = root;
            _macKey = mac;
            root = null;
            mac = null;
        }
        finally
        {
            root?.Dispose();
            mac?.Dispose();
        }
    }

    internal ulong Epoch { get; }

    internal static ManagedMlKemBraidAuthenticator Initialize(
        ReadOnlySpan<byte> initialSharedSecret,
        ulong epoch = 1)
    {
        MessagingCryptoValidation.NonZeroExact(
            initialSharedSecret,
            MessagingCryptoConstants.MlKem768SharedSecretSize,
            nameof(initialSharedSecret));
        Span<byte> zeroRoot = stackalloc byte[32];
        return Derive(zeroRoot, initialSharedSecret, epoch);
    }

    internal ManagedMlKemBraidAuthenticator PrepareUpdate(
        ReadOnlySpan<byte> freshBraidOutput,
        ulong epoch)
    {
        ThrowIfDisposed();
        MessagingCryptoValidation.NonZeroExact(
            freshBraidOutput,
            MessagingCryptoConstants.MlKem768SharedSecretSize,
            nameof(freshBraidOutput));
        if (epoch < Epoch || epoch - Epoch > 1)
            throw new MessagingCryptoException(
                MessagingCryptoError.TransitionRejected,
                "The authenticator update must remain in the current Braid epoch or advance exactly once.");
        var ownedOutput = freshBraidOutput.ToArray();
        try
        {
            return _rootKey.Use(root => Derive(root, ownedOutput, epoch));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ownedOutput);
        }
    }

    internal ManagedMlKemBraidAuthenticator AdvanceEpoch(ulong epoch)
    {
        ThrowIfDisposed();
        if (Epoch == ulong.MaxValue || epoch != Epoch + 1)
            throw new MessagingCryptoException(
                MessagingCryptoError.TransitionRejected,
                "The Braid authenticator epoch must advance exactly once without wrapping.");
        var root = _rootKey.Copy();
        try
        {
            return _macKey.Use(mac => new ManagedMlKemBraidAuthenticator(epoch, root, mac));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(root);
        }
    }

    internal SecretBuffer DeriveOutputKey(
        ReadOnlySpan<byte> mlKemSharedSecret,
        ulong epoch)
    {
        ThrowIfDisposed();
        MessagingCryptoValidation.NonZeroExact(
            mlKemSharedSecret,
            MessagingCryptoConstants.MlKem768SharedSecretSize,
            nameof(mlKemSharedSecret));
        if (epoch == 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The ML-KEM Braid output epoch must be nonzero.");
        Span<byte> zeroSalt = stackalloc byte[64];
        Span<byte> prk = stackalloc byte[64];
        var output = new byte[32];
        byte[]? info = null;
        try
        {
            if (HKDF.Extract(HashAlgorithmName.SHA512, mlKemSharedSecret, zeroSalt, prk) != prk.Length)
                throw new CryptographicException("HKDF extract returned an unexpected length.");
            info = ProfileContext("Deep/Messaging/V2/braid-output-key", U64(epoch));
            HKDF.Expand(HashAlgorithmName.SHA512, prk, output, info);
            var owned = SecretBuffer.ImportExact(output, 32, "braidOutputKey");
            MessagingCryptoFaultInjection.OwnedSecret("braid.output-key", owned);
            return owned;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(output);
            Zero(info);
        }
    }

    internal Dtr2BraidMessage CreateHeaderMessage(
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyVector)
    {
        ThrowIfDisposed();
        MessagingCryptoValidation.Exact(encapsulationKeySeed, 32, nameof(encapsulationKeySeed));
        MessagingCryptoValidation.Exact(encapsulationKeyVector, 1152, nameof(encapsulationKeyVector));
        var hash = ComputeEncapsulationKeyHash(encapsulationKeySeed, encapsulationKeyVector);
        var mac = ComputeHeaderMac(Epoch, encapsulationKeySeed, hash);
        try
        {
            return Dtr2BraidMessage.Header(encapsulationKeySeed, hash, mac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(mac);
        }
    }

    internal void VerifyHeaderMessage(
        Dtr2BraidMessage message,
        ReadOnlySpan<byte> encapsulationKeyVector,
        ulong expectedEpoch)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(message);
        MessagingCryptoValidation.Exact(encapsulationKeyVector, 1152, nameof(encapsulationKeyVector));
        if (expectedEpoch != Epoch || message.Kind != Dtr2BraidMessageKind.Header)
            RejectAuthentication("The Braid header kind or epoch is invalid.");
        Span<byte> seed = stackalloc byte[32];
        Span<byte> claimedHash = stackalloc byte[32];
        Span<byte> claimedMac = stackalloc byte[32];
        message.CopyHeaderTo(seed, claimedHash, claimedMac);
        var actualHash = ComputeEncapsulationKeyHash(seed, encapsulationKeyVector);
        var actualMac = ComputeHeaderMac(expectedEpoch, seed, actualHash);
        try
        {
            if (!MessagingCryptoValidation.FixedEquals(claimedHash, actualHash) |
                !MessagingCryptoValidation.FixedEquals(claimedMac, actualMac))
                RejectAuthentication("The Braid header hash or authenticator is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(claimedHash);
            CryptographicOperations.ZeroMemory(claimedMac);
            CryptographicOperations.ZeroMemory(actualHash);
            CryptographicOperations.ZeroMemory(actualMac);
        }
    }

    internal void VerifyHeaderAuthenticator(
        Dtr2BraidMessage message,
        ulong expectedEpoch)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(message);
        if (expectedEpoch != Epoch || message.Kind != Dtr2BraidMessageKind.Header)
            RejectAuthentication("The Braid header kind or epoch is invalid.");
        Span<byte> seed = stackalloc byte[32];
        Span<byte> claimedHash = stackalloc byte[32];
        Span<byte> claimedMac = stackalloc byte[32];
        message.CopyHeaderTo(seed, claimedHash, claimedMac);
        var actualMac = ComputeHeaderMac(expectedEpoch, seed, claimedHash);
        try
        {
            if (!MessagingCryptoValidation.FixedEquals(claimedMac, actualMac))
                RejectAuthentication("The Braid header authenticator is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(claimedHash);
            CryptographicOperations.ZeroMemory(claimedMac);
            CryptographicOperations.ZeroMemory(actualMac);
        }
    }

    internal Dtr2BraidMessage CreateCiphertext2Message(
        ReadOnlySpan<byte> ciphertext1,
        ReadOnlySpan<byte> ciphertext2)
    {
        ThrowIfDisposed();
        MessagingCryptoValidation.Exact(ciphertext1, 960, nameof(ciphertext1));
        MessagingCryptoValidation.Exact(ciphertext2, 128, nameof(ciphertext2));
        var mac = ComputeCiphertextMac(Epoch, ciphertext1, ciphertext2);
        try
        {
            return Dtr2BraidMessage.Ciphertext2(ciphertext2, mac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mac);
        }
    }

    internal void VerifyCiphertext2Message(
        Dtr2BraidMessage message,
        ReadOnlySpan<byte> ciphertext1,
        ulong expectedEpoch)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(message);
        MessagingCryptoValidation.Exact(ciphertext1, 960, nameof(ciphertext1));
        if (expectedEpoch != Epoch || message.Kind != Dtr2BraidMessageKind.Ciphertext2)
            RejectAuthentication("The Braid ciphertext kind or epoch is invalid.");
        Span<byte> ciphertext2 = stackalloc byte[128];
        Span<byte> claimedMac = stackalloc byte[32];
        message.CopyCiphertext2To(ciphertext2, claimedMac);
        var actualMac = ComputeCiphertextMac(expectedEpoch, ciphertext1, ciphertext2);
        try
        {
            if (!MessagingCryptoValidation.FixedEquals(claimedMac, actualMac))
                RejectAuthentication("The Braid ciphertext authenticator is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext2);
            CryptographicOperations.ZeroMemory(claimedMac);
            CryptographicOperations.ZeroMemory(actualMac);
        }
    }

    internal byte[] ExportSealed(
        ReadOnlySpan<byte> stateWrappingKey,
        ReadOnlySpan<byte> stateBinding)
    {
        Span<byte> nonce = stackalloc byte[24];
        RandomNumberGenerator.Fill(nonce);
        return ExportSealedCore(stateWrappingKey, stateBinding, nonce);
    }

    /// <summary>
    /// Exports the exact authenticator substate for embedding only inside the
    /// Triple-Ratchet opaque plaintext that the caller seals atomically. The
    /// returned bytes are secret and remain caller-owned.
    /// </summary>
    internal byte[] ExportLocalPlaintextState()
    {
        ThrowIfDisposed();
        var output = new byte[LocalPlaintextStateSize];
        var transferred = false;
        try
        {
            ProtocolMagicBytes.MBA1.CopyTo(output);
            output[4] = SealedStateVersion;
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(5), MessagingCryptoConstants.Suite);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(7), Epoch);
            _rootKey.Use(root => root.CopyTo(output.AsSpan(15, 32)));
            _macKey.Use(mac => mac.CopyTo(output.AsSpan(47, 32)));
            MessagingCryptoFaultInjection.ManagedSecret("braid.auth.local-state", output);
            transferred = true;
            return output;
        }
        finally
        {
            if (!transferred) CryptographicOperations.ZeroMemory(output);
        }
    }

    internal static ManagedMlKemBraidAuthenticator ImportLocalPlaintextState(
        ReadOnlySpan<byte> exactState)
    {
        if (exactState.Length != LocalPlaintextStateSize ||
            !exactState[..4].SequenceEqual(ProtocolMagicBytes.MBA1) ||
            exactState[4] != SealedStateVersion ||
            BinaryPrimitives.ReadUInt16BigEndian(exactState[5..]) != MessagingCryptoConstants.Suite)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The local Braid authenticator state is not one exact MBA1 value.");
        return new ManagedMlKemBraidAuthenticator(
            BinaryPrimitives.ReadUInt64BigEndian(exactState[7..]),
            exactState.Slice(15, 32),
            exactState.Slice(47, 32));
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal byte[] ExportSealedForTests(
        ReadOnlySpan<byte> stateWrappingKey,
        ReadOnlySpan<byte> stateBinding,
        ReadOnlySpan<byte> nonce) =>
        ExportSealedCore(stateWrappingKey, stateBinding, nonce);
#endif

    internal static ManagedMlKemBraidAuthenticator ImportSealed(
        ReadOnlySpan<byte> exactSealedState,
        ReadOnlySpan<byte> stateWrappingKey,
        ReadOnlySpan<byte> stateBinding)
    {
        MessagingCryptoValidation.Exact(exactSealedState, SealedStateSize, nameof(exactSealedState));
        MessagingCryptoValidation.NonZeroExact(stateWrappingKey, 32, nameof(stateWrappingKey));
        MessagingCryptoValidation.NonZeroExact(stateBinding, 32, nameof(stateBinding));
        if (exactSealedState[0] != SealedStateVersion)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The managed Braid sealed-state version is unsupported.");
        var aad = StateAad(stateBinding);
        byte[]? wrappingKey = null;
        byte[]? ciphertext = null;
        byte[]? nonce = null;
        byte[]? plaintext = null;
        try
        {
            wrappingKey = stateWrappingKey.ToArray();
            ciphertext = exactSealedState[25..].ToArray();
            nonce = exactSealedState.Slice(1, 24).ToArray();
            try
            {
                plaintext = SecretAeadXChaCha20Poly1305.Decrypt(
                    ciphertext,
                    nonce,
                    wrappingKey,
                    aad);
            }
            catch (CryptographicException exception)
            {
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "The managed Braid sealed state failed authentication.",
                    exception);
            }
            if (plaintext.Length != SealedPlaintextSize ||
                BinaryPrimitives.ReadUInt16BigEndian(plaintext) != MessagingCryptoConstants.Suite)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "The managed Braid sealed-state suite or length is invalid.");
            var epoch = BinaryPrimitives.ReadUInt64BigEndian(plaintext.AsSpan(2));
            return new ManagedMlKemBraidAuthenticator(
                epoch,
                plaintext.AsSpan(10, 32),
                plaintext.AsSpan(42, 32));
        }
        finally
        {
            Zero(aad);
            Zero(wrappingKey);
            Zero(ciphertext);
            Zero(nonce);
            Zero(plaintext);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _rootKey.Dispose();
        _macKey.Dispose();
    }

    private static ManagedMlKemBraidAuthenticator Derive(
        ReadOnlySpan<byte> oldRootKey,
        ReadOnlySpan<byte> freshBraidOutput,
        ulong epoch)
    {
        if (epoch == 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The ML-KEM Braid authenticator epoch must be nonzero.");
        Span<byte> prk = stackalloc byte[64];
        Span<byte> derived = stackalloc byte[64];
        byte[]? info = null;
        try
        {
            if (HKDF.Extract(HashAlgorithmName.SHA512, freshBraidOutput, oldRootKey, prk) != prk.Length)
                throw new CryptographicException("HKDF extract returned an unexpected length.");
            info = ProfileContext(
                "Deep/Messaging/V2/braid-auth-update",
                U64(epoch));
            HKDF.Expand(HashAlgorithmName.SHA512, prk, derived, info);
            return new ManagedMlKemBraidAuthenticator(epoch, derived[..32], derived[32..]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(derived);
            Zero(info);
        }
    }

    private byte[] ExportSealedCore(
        ReadOnlySpan<byte> stateWrappingKey,
        ReadOnlySpan<byte> stateBinding,
        ReadOnlySpan<byte> nonce)
    {
        ThrowIfDisposed();
        MessagingCryptoValidation.NonZeroExact(stateWrappingKey, 32, nameof(stateWrappingKey));
        MessagingCryptoValidation.NonZeroExact(stateBinding, 32, nameof(stateBinding));
        MessagingCryptoValidation.Exact(nonce, 24, nameof(nonce));
        var aad = StateAad(stateBinding);
        byte[]? wrappingKey = null;
        byte[]? plaintext = null;
        byte[]? ciphertext = null;
        try
        {
            wrappingKey = stateWrappingKey.ToArray();
            plaintext = new byte[SealedPlaintextSize];
            BinaryPrimitives.WriteUInt16BigEndian(plaintext, MessagingCryptoConstants.Suite);
            BinaryPrimitives.WriteUInt64BigEndian(plaintext.AsSpan(2), Epoch);
            _rootKey.Use(root => root.CopyTo(plaintext.AsSpan(10, 32)));
            _macKey.Use(mac => mac.CopyTo(plaintext.AsSpan(42, 32)));
            ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(
                plaintext,
                nonce.ToArray(),
                wrappingKey,
                aad);
            var output = new byte[SealedStateSize];
            output[0] = SealedStateVersion;
            nonce.CopyTo(output.AsSpan(1, 24));
            ciphertext.CopyTo(output, 25);
            return output;
        }
        finally
        {
            Zero(aad);
            Zero(wrappingKey);
            Zero(plaintext);
            Zero(ciphertext);
        }
    }

    private byte[] ComputeHeaderMac(
        ulong epoch,
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyHash)
    {
        var header = new byte[64];
        encapsulationKeySeed.CopyTo(header);
        encapsulationKeyHash.CopyTo(header.AsSpan(32));
        var input = MessagingWireCryptographicInputs.Context(
            "Deep/Messaging/V2/braid-header-auth",
            U64(epoch),
            header);
        try
        {
            return _macKey.Use(key => HMACSHA256.HashData(key, input));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(header);
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private byte[] ComputeCiphertextMac(
        ulong epoch,
        ReadOnlySpan<byte> ciphertext1,
        ReadOnlySpan<byte> ciphertext2)
    {
        var input = MessagingWireCryptographicInputs.Context(
            "Deep/Messaging/V2/braid-ciphertext-auth",
            U64(epoch),
            ciphertext1.ToArray(),
            ciphertext2.ToArray());
        try
        {
            return _macKey.Use(key => HMACSHA256.HashData(key, input));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    internal static byte[] ComputeEncapsulationKeyHash(
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyVector)
        => PortableSha3_256.HashConcat(encapsulationKeyVector, encapsulationKeySeed);

    private static byte[] ProfileContext(string label, params ReadOnlyMemory<byte>[] parts)
    {
        var profileParts = new ReadOnlyMemory<byte>[parts.Length + 1];
        profileParts[0] = Encoding.ASCII.GetBytes(ProtocolInfo);
        parts.CopyTo(profileParts, 1);
        return MessagingWireCryptographicInputs.Context(label, profileParts);
    }

    private static byte[] StateAad(ReadOnlySpan<byte> stateBinding) =>
        MessagingWireCryptographicInputs.Context(
            LocalStateDomain,
            Encoding.ASCII.GetBytes(ProtocolInfo),
            stateBinding.ToArray());

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static void RejectAuthentication(string message) =>
        throw new MessagingCryptoException(MessagingCryptoError.TransitionRejected, message);

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.ObjectDisposed,
                "The managed Braid authenticator has been disposed.");
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}
