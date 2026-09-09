using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

internal enum MessagingCryptoError
{
    InvalidInput,
    ProviderFailure,
    AllZeroSharedSecret,
    PreKeyAlreadyConsumed,
    PreKeyConflict,
    Replay,
    ReplayConflict,
    ForwardGapExceeded,
    SkippedKeyLimitExceeded,
    StateLimitExceeded,
    PqInjectionRequired,
    PqEvidenceRejected,
    RollbackDetected,
    TerminallyLatched,
    CasConflict,
    TransitionRejected,
    CapabilityConsumed,
    ObjectDisposed,
}

internal sealed class MessagingCryptoException : CryptographicException
{
    internal MessagingCryptoException(MessagingCryptoError error, string message)
        : base(message) => Error = error;

    internal MessagingCryptoException(MessagingCryptoError error, string message, Exception innerException)
        : base(message, innerException) => Error = error;

    internal MessagingCryptoError Error { get; }
}

internal delegate void MessagingSecretAction(ReadOnlySpan<byte> secret);
internal delegate TResult MessagingSecretFunc<TResult>(ReadOnlySpan<byte> secret);

internal sealed class SecretBuffer : IDisposable
{
    private readonly object _sync = new();
    private byte[]? _value;

    private SecretBuffer(byte[] ownedValue) => _value = ownedValue;

    ~SecretBuffer() => Dispose();

    internal static SecretBuffer ImportExact(ReadOnlySpan<byte> value, int expectedLength, string name)
    {
        MessagingCryptoValidation.Exact(value, expectedLength, name);
        return new SecretBuffer(value.ToArray());
    }

    internal static SecretBuffer ImportBounded(
        ReadOnlySpan<byte> value,
        int minimumLength,
        int maximumLength,
        string name)
    {
        if (value.Length < minimumLength || value.Length > maximumLength)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                $"{name} must be {minimumLength}..{maximumLength} bytes.");
        return new SecretBuffer(value.ToArray());
    }

    internal int Length
    {
        get { lock (_sync) return GetValue().Length; }
    }

    internal TResult Use<TResult>(MessagingSecretFunc<TResult> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        lock (_sync) return action(GetValue());
    }

    internal void Use(MessagingSecretAction action)
    {
        ArgumentNullException.ThrowIfNull(action);
        lock (_sync) action(GetValue());
    }

    internal byte[] Copy() => Use(static value => value.ToArray());
    internal SecretBuffer Clone() => Use(static value => new SecretBuffer(value.ToArray()));

    internal void CopyTo(Span<byte> destination)
    {
        lock (_sync)
        {
            var value = GetValue();
            if (destination.Length != value.Length)
                throw new MessagingCryptoException(
                    MessagingCryptoError.InvalidInput,
                    "The secret destination has the wrong exact length.");
            value.CopyTo(destination);
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_value is null) return;
            CryptographicOperations.ZeroMemory(_value);
            _value = null;
        }
        GC.SuppressFinalize(this);
    }

    private ReadOnlySpan<byte> GetValue() => _value ?? throw new MessagingCryptoException(
        MessagingCryptoError.ObjectDisposed,
        "The secret owner has been disposed.");
}

internal sealed class MessagingCryptoFaultProbe
{
    internal Action<string>? Point { get; init; }
    internal Action<string, byte[]>? ManagedSecret { get; init; }
    internal Action<string, SecretBuffer>? OwnedSecret { get; init; }
    internal Action<string, IDisposable>? OwnedDisposable { get; init; }
}

internal static class MessagingCryptoFaultInjection
{
    private static readonly AsyncLocal<MessagingCryptoFaultProbe?> Current = new();

    internal static IDisposable InstallDarkForTests(MessagingCryptoFaultProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        var prior = Current.Value;
        Current.Value = probe;
        return new RestoreLease(prior);
    }

    internal static void Point(string name) => Current.Value?.Point?.Invoke(name);
    internal static void ManagedSecret(string name, byte[] value) =>
        Current.Value?.ManagedSecret?.Invoke(name, value);
    internal static void OwnedSecret(string name, SecretBuffer value) =>
        Current.Value?.OwnedSecret?.Invoke(name, value);
    internal static void OwnedDisposable(string name, IDisposable value) =>
        Current.Value?.OwnedDisposable?.Invoke(name, value);

    private sealed class RestoreLease(MessagingCryptoFaultProbe? prior) : IDisposable
    {
        private MessagingCryptoFaultProbe? _prior = prior;
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            Current.Value = _prior;
            _prior = null;
        }
    }
}

internal sealed class MessageKeyLease : IDisposable
{
    private readonly SecretBuffer _key;

    internal MessageKeyLease(ReadOnlySpan<byte> key) =>
        _key = SecretBuffer.ImportExact(key, MessagingCryptoConstants.SecretSize, nameof(key));

    internal void Use(MessagingSecretAction action) => _key.Use(action);
    internal TResult Use<TResult>(MessagingSecretFunc<TResult> action) => _key.Use(action);
    public void Dispose() => _key.Dispose();
}

internal sealed class PersistenceCasExpectation
{
    private readonly byte[] _predecessorCommitment;

    internal PersistenceCasExpectation(ulong expectedGeneration, ReadOnlySpan<byte> predecessorCommitment)
    {
        MessagingCryptoValidation.NonZeroExact(predecessorCommitment, 32, nameof(predecessorCommitment));
        ExpectedGeneration = expectedGeneration;
        _predecessorCommitment = predecessorCommitment.ToArray();
    }

    internal ulong ExpectedGeneration { get; }
    internal ReadOnlyMemory<byte> PredecessorCommitment => _predecessorCommitment.ToArray();
}

internal static class MessagingCryptoConstants
{
    internal const ushort Suite = 0x0201;
    internal const int SecretSize = 32;
    internal const int X25519KeySize = 32;
    internal const int MlKem768EncapsulationKeySize = 1184;
    internal const int MlKem768CiphertextSize = 1088;
    internal const int MlKem768SharedSecretSize = 32;
    internal const int MaximumForwardGap = 2048;
    internal const int MaximumSkippedKeys = 2048;
    internal const int MaximumOpaqueProviderStateBytes = 2 * 1024 * 1024;
    internal const int MaximumDurableRatchetStateBytes = 2 * 1024 * 1024;
}

internal static class MessagingCryptoValidation
{
    internal static void Exact(ReadOnlySpan<byte> value, int expected, string name)
    {
        if (value.Length != expected)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                $"{name} must be exactly {expected} bytes.");
    }

    internal static void NonZeroExact(ReadOnlySpan<byte> value, int expected, string name)
    {
        Exact(value, expected, name);
        if (IsZero(value))
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                $"{name} cannot be all-zero.");
    }

    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        var aggregate = 0;
        foreach (var item in value) aggregate |= item;
        return aggregate == 0;
    }

    internal static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal static class MessagingKdf
{
    internal const string TripleRatchetProtocolInfo =
        "DeepTripleRatchetV1_X25519_MLKEM768_XCHACHA20";
    internal static byte[] Sha256Domain(string label, ReadOnlySpan<byte> value)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(labelBytes);
        hash.AppendData([0]);
        hash.AppendData(length);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    internal static byte[] Sha512Domain(string label, ReadOnlySpan<byte> value)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        hash.AppendData(labelBytes);
        hash.AppendData([0]);
        hash.AppendData(length);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    internal static byte[] DeriveCombinedMessageKey(
        ReadOnlySpan<byte> sessionId,
        ulong ecN,
        ulong sckaEpoch,
        ulong sckaN,
        ReadOnlySpan<byte> headerHash,
        ReadOnlySpan<byte> ecMessageKey,
        ReadOnlySpan<byte> pqMessageKey)
    {
        MessagingCryptoValidation.NonZeroExact(sessionId, 32, nameof(sessionId));
        MessagingCryptoValidation.NonZeroExact(headerHash, 32, nameof(headerHash));
        MessagingCryptoValidation.NonZeroExact(ecMessageKey, 32, nameof(ecMessageKey));
        MessagingCryptoValidation.NonZeroExact(pqMessageKey, 32, nameof(pqMessageKey));

        var salt = Sha512Domain("Deep/Messaging/V2/triple-ratchet-salt", sessionId);
        byte[]? ecOwned = null;
        byte[]? pqOwned = null;
        byte[]? ikm = null;
        byte[]? ecNumber = null;
        byte[]? sckaEpochBytes = null;
        byte[]? sckaNumber = null;
        byte[]? sessionOwned = null;
        byte[]? headerOwned = null;
        byte[]? protocolInfo = null;
        byte[]? info = null;
        Span<byte> prk = stackalloc byte[64];
        var key = new byte[32];
        var ownershipTransferred = false;
        try
        {
            ecOwned = ecMessageKey.ToArray();
            pqOwned = pqMessageKey.ToArray();
            protocolInfo = Encoding.ASCII.GetBytes(TripleRatchetProtocolInfo);
            ikm = MessagingWireCryptographicInputs.Context(
                "Deep/Messaging/V2/hybrid-message-ikm",
                protocolInfo,
                ecOwned,
                pqOwned);
            ecNumber = U64(ecN);
            sckaEpochBytes = U64(sckaEpoch);
            sckaNumber = U64(sckaN);
            sessionOwned = sessionId.ToArray();
            headerOwned = headerHash.ToArray();
            info = MessagingWireCryptographicInputs.Context(
                "Deep/Messaging/V2/message-key",
                protocolInfo,
                sessionOwned,
                ecNumber,
                sckaEpochBytes,
                sckaNumber,
                headerOwned);
            if (HKDF.Extract(HashAlgorithmName.SHA512, ikm, salt, prk) != prk.Length)
                throw new CryptographicException("HKDF extract returned an unexpected length.");
            HKDF.Expand(HashAlgorithmName.SHA512, prk, key, info);
            MessagingCryptoFaultInjection.ManagedSecret("message-kdf.output", key);
            ownershipTransferred = true;
            return key;
        }
        finally
        {
            if (!ownershipTransferred) CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(salt);
            Zero(ecOwned);
            Zero(pqOwned);
            Zero(ikm);
            Zero(ecNumber);
            Zero(sckaEpochBytes);
            Zero(sckaNumber);
            Zero(sessionOwned);
            Zero(headerOwned);
            Zero(protocolInfo);
            CryptographicOperations.ZeroMemory(prk);
            Zero(info);
        }
    }

    private static byte[] U64(ulong value)
    {
        var encoded = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        return encoded;
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}
