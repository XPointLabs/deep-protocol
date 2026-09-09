using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

internal enum ManagedMlKemBraidState : byte
{
    KeysUnsampled = 1,
    KeysSampled = 2,
    HeaderSent = 3,
    Ct1Received = 4,
    EkSentCt1Received = 5,
    NoHeaderReceived = 6,
    HeaderReceived = 7,
    Ct1Sampled = 8,
    EkReceivedCt1Sampled = 9,
    Ct1Acknowledged = 10,
    Ct2Sampled = 11,
}

/// <summary>
/// Deep identity-encoder specialization of Signal SPQR v1.5.3.
/// It retains the closed eleven-state/thirteen-edge logical machine while one
/// complete authenticated Braid payload occupies each DTR2 value.
/// </summary>
internal sealed class ManagedMlKemBraidStateMachine : IDisposable
{
    internal const int StateCount = 11;
    internal const int TransitionCount = 13;

    private const byte Version = 1;
    private const int AuthenticatorBytes = 79;
    private const int SeedBytes = 32;
    private const int HashBytes = 32;
    private const int VectorBytes = DeepMlKemBraidNativeProvider.EncapsulationKeyVectorSize;
    private const int DecapsulationKeyBytes = DeepMlKemBraidNativeProvider.DecapsulationKeySize;
    private const int Ciphertext1Bytes = DeepMlKemBraidNativeProvider.Ciphertext1Size;
    private const int EntropyBytes = DeepMlKemBraidNativeProvider.EncapsulationRandomSize;
    private const int Ciphertext2Bytes = DeepMlKemBraidNativeProvider.Ciphertext2Size;
    private const int MacBytes = 32;
    private const int OutputBytes = DeepMlKemBraidNativeProvider.SharedSecretSize;

    private const ushort HasSeed = 1 << 0;
    private const ushort HasHash = 1 << 1;
    private const ushort HasVector = 1 << 2;
    private const ushort HasDecapsulationKey = 1 << 3;
    private const ushort HasCiphertext1 = 1 << 4;
    private const ushort HasEntropy = 1 << 5;
    private const ushort HasCiphertext2 = 1 << 6;
    private const ushort HasCiphertext2Mac = 1 << 7;
    private const ushort HasPendingOutput = 1 << 8;

    private const int HeaderBytes = 4 + 1 + 2 + 1 + 8 + 2;
    private const int AuthenticatorOffset = HeaderBytes;
    private const int SeedOffset = AuthenticatorOffset + AuthenticatorBytes;
    private const int HashOffset = SeedOffset + SeedBytes;
    private const int VectorOffset = HashOffset + HashBytes;
    private const int DecapsulationKeyOffset = VectorOffset + VectorBytes;
    private const int Ciphertext1Offset = DecapsulationKeyOffset + DecapsulationKeyBytes;
    private const int EntropyOffset = Ciphertext1Offset + Ciphertext1Bytes;
    private const int Ciphertext2Offset = EntropyOffset + EntropyBytes;
    private const int Ciphertext2MacOffset = Ciphertext2Offset + Ciphertext2Bytes;
    private const int PendingOutputOffset = Ciphertext2MacOffset + MacBytes;
    private const int StateBytes = PendingOutputOffset + OutputBytes;

    private readonly object _gate = new();
    private readonly DeepMlKemBraidNativeProvider _provider;
    private ManagedMlKemBraidAuthenticator _authenticator;
    private ManagedMlKemBraidState _state;
    private ulong _epoch;
    private byte[]? _seed;
    private byte[]? _hash;
    private byte[]? _vector;
    private SecretBuffer? _decapsulationKey;
    private byte[]? _ciphertext1;
    private SecretBuffer? _encaps1Entropy;
    private byte[]? _ciphertext2;
    private byte[]? _ciphertext2Mac;
    private SecretBuffer? _pendingOutput;
    private int _disposed;

    private ManagedMlKemBraidStateMachine(
        DeepMlKemBraidNativeProvider provider,
        ManagedMlKemBraidAuthenticator authenticator,
        ManagedMlKemBraidState state,
        ulong epoch)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _authenticator = authenticator ?? throw new ArgumentNullException(nameof(authenticator));
        if (epoch == 0 || authenticator.Epoch != epoch)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The Braid state and authenticator epochs must be the same nonzero value.");
        _state = state;
        _epoch = epoch;
    }

    ~ManagedMlKemBraidStateMachine() => DisposeCore();

    internal ManagedMlKemBraidState State
    {
        get { lock (_gate) { ThrowIfDisposed(); return _state; } }
    }

    internal ulong Epoch
    {
        get { lock (_gate) { ThrowIfDisposed(); return _epoch; } }
    }

    internal static ManagedMlKemBraidStateMachine CreateAlice(
        DeepMlKemBraidNativeProvider provider,
        ReadOnlySpan<byte> initialAuthenticatorSecret) =>
        new(
            provider,
            ManagedMlKemBraidAuthenticator.Initialize(initialAuthenticatorSecret),
            ManagedMlKemBraidState.KeysUnsampled,
            1);

    internal static ManagedMlKemBraidStateMachine CreateBob(
        DeepMlKemBraidNativeProvider provider,
        ReadOnlySpan<byte> initialAuthenticatorSecret) =>
        new(
            provider,
            ManagedMlKemBraidAuthenticator.Initialize(initialAuthenticatorSecret),
            ManagedMlKemBraidState.NoHeaderReceived,
            1);

    internal static bool IsDefinedTransition(
        ManagedMlKemBraidState from,
        ManagedMlKemBraidState to) => (from, to) switch
    {
        (ManagedMlKemBraidState.KeysUnsampled, ManagedMlKemBraidState.KeysSampled) => true,
        (ManagedMlKemBraidState.KeysSampled, ManagedMlKemBraidState.HeaderSent) => true,
        (ManagedMlKemBraidState.HeaderSent, ManagedMlKemBraidState.Ct1Received) => true,
        (ManagedMlKemBraidState.Ct1Received, ManagedMlKemBraidState.EkSentCt1Received) => true,
        (ManagedMlKemBraidState.EkSentCt1Received, ManagedMlKemBraidState.NoHeaderReceived) => true,
        (ManagedMlKemBraidState.NoHeaderReceived, ManagedMlKemBraidState.HeaderReceived) => true,
        (ManagedMlKemBraidState.HeaderReceived, ManagedMlKemBraidState.Ct1Sampled) => true,
        (ManagedMlKemBraidState.Ct1Sampled, ManagedMlKemBraidState.EkReceivedCt1Sampled) => true,
        (ManagedMlKemBraidState.Ct1Sampled, ManagedMlKemBraidState.Ct1Acknowledged) => true,
        (ManagedMlKemBraidState.Ct1Sampled, ManagedMlKemBraidState.Ct2Sampled) => true,
        (ManagedMlKemBraidState.EkReceivedCt1Sampled, ManagedMlKemBraidState.Ct2Sampled) => true,
        (ManagedMlKemBraidState.Ct1Acknowledged, ManagedMlKemBraidState.Ct2Sampled) => true,
        (ManagedMlKemBraidState.Ct2Sampled, ManagedMlKemBraidState.KeysUnsampled) => true,
        _ => false,
    };

    internal Dtr2BraidMessage Send()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            return _state switch
            {
                ManagedMlKemBraidState.KeysUnsampled => SampleAndSendHeader(),
                ManagedMlKemBraidState.KeysSampled =>
                    _authenticator.CreateHeaderMessage(Required(_seed), Required(_vector)),
                ManagedMlKemBraidState.HeaderSent =>
                    Dtr2BraidMessage.EncapsulationKey(Required(_vector)),
                ManagedMlKemBraidState.Ct1Received =>
                    Dtr2BraidMessage.EncapsulationKeyWithCiphertext1Ack(Required(_vector)),
                ManagedMlKemBraidState.EkSentCt1Received => Dtr2BraidMessage.Ciphertext1Ack(),
                ManagedMlKemBraidState.NoHeaderReceived => Dtr2BraidMessage.None(),
                ManagedMlKemBraidState.HeaderReceived => SampleAndSendCiphertext1(),
                ManagedMlKemBraidState.Ct1Sampled or
                ManagedMlKemBraidState.EkReceivedCt1Sampled =>
                    Dtr2BraidMessage.Ciphertext1(Required(_ciphertext1)),
                ManagedMlKemBraidState.Ct1Acknowledged => Dtr2BraidMessage.None(),
                ManagedMlKemBraidState.Ct2Sampled =>
                    _authenticator.CreateCiphertext2Message(
                        Required(_ciphertext1), Required(_ciphertext2)),
                _ => throw InvalidState(),
            };
        }
    }

    internal SecretBuffer? Receive(ulong epoch, Dtr2BraidMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (epoch == 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The Braid message epoch must be nonzero.");
        lock (_gate)
        {
            ThrowIfDisposed();
            if (epoch < _epoch) return null;
            if (epoch > _epoch)
            {
                if (_state == ManagedMlKemBraidState.Ct2Sampled &&
                    _epoch != ulong.MaxValue && epoch == _epoch + 1)
                {
                    AdvanceToNextSendingEpoch();
                    return null;
                }
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "The Braid message epoch is ahead of the only accepted transition.");
            }

            return _state switch
            {
                ManagedMlKemBraidState.KeysUnsampled => null,
                ManagedMlKemBraidState.KeysSampled => ReceiveCompleteCiphertext1(message),
                ManagedMlKemBraidState.HeaderSent => ReceiveCompletedCiphertext1(message),
                ManagedMlKemBraidState.Ct1Received => ReceiveCompleteCiphertext2(message),
                ManagedMlKemBraidState.EkSentCt1Received => ReceiveCompletedCiphertext2(message),
                ManagedMlKemBraidState.NoHeaderReceived => ReceiveHeader(message),
                ManagedMlKemBraidState.HeaderReceived => null,
                ManagedMlKemBraidState.Ct1Sampled => ReceiveEncapsulationKey(message),
                ManagedMlKemBraidState.EkReceivedCt1Sampled => ReceiveCiphertext1Ack(message),
                ManagedMlKemBraidState.Ct1Acknowledged => ReceiveAcknowledgedEncapsulationKey(message),
                ManagedMlKemBraidState.Ct2Sampled => null,
                _ => throw InvalidState(),
            };
        }
    }

    internal byte[] ExportLocalPlaintextState()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            var output = new byte[StateBytes];
            var transferred = false;
            byte[]? authenticator = null;
            try
            {
                ProtocolMagicBytes.MBM1.CopyTo(output);
                output[4] = Version;
                BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(5), MessagingCryptoConstants.Suite);
                output[7] = (byte)_state;
                BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), _epoch);
                BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(16), ExpectedMask(_state));
                authenticator = _authenticator.ExportLocalPlaintextState();
                authenticator.CopyTo(output, AuthenticatorOffset);
                Copy(_seed, output, SeedOffset);
                Copy(_hash, output, HashOffset);
                Copy(_vector, output, VectorOffset);
                _decapsulationKey?.CopyTo(output.AsSpan(DecapsulationKeyOffset, DecapsulationKeyBytes));
                Copy(_ciphertext1, output, Ciphertext1Offset);
                _encaps1Entropy?.CopyTo(output.AsSpan(EntropyOffset, EntropyBytes));
                Copy(_ciphertext2, output, Ciphertext2Offset);
                Copy(_ciphertext2Mac, output, Ciphertext2MacOffset);
                _pendingOutput?.CopyTo(output.AsSpan(PendingOutputOffset, OutputBytes));
                transferred = true;
                return output;
            }
            finally
            {
                if (authenticator is not null) CryptographicOperations.ZeroMemory(authenticator);
                if (!transferred) CryptographicOperations.ZeroMemory(output);
            }
        }
    }

    internal static ManagedMlKemBraidStateMachine ImportLocalPlaintextState(
        DeepMlKemBraidNativeProvider provider,
        ReadOnlySpan<byte> exactState)
    {
        ArgumentNullException.ThrowIfNull(provider);
        if (exactState.Length != StateBytes ||
            !exactState[..4].SequenceEqual(ProtocolMagicBytes.MBM1) ||
            exactState[4] != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(exactState[5..]) != MessagingCryptoConstants.Suite ||
            !Enum.IsDefined((ManagedMlKemBraidState)exactState[7]))
            throw InvalidEncoding();
        var state = (ManagedMlKemBraidState)exactState[7];
        var epoch = BinaryPrimitives.ReadUInt64BigEndian(exactState[8..]);
        var mask = BinaryPrimitives.ReadUInt16BigEndian(exactState[16..]);
        var expectedMask = ExpectedMask(state);
        if (epoch == 0 || mask != expectedMask)
            throw InvalidEncoding();

        ValidateAbsent(mask, HasSeed, exactState.Slice(SeedOffset, SeedBytes));
        ValidateAbsent(mask, HasHash, exactState.Slice(HashOffset, HashBytes));
        ValidateAbsent(mask, HasVector, exactState.Slice(VectorOffset, VectorBytes));
        ValidateAbsent(mask, HasDecapsulationKey,
            exactState.Slice(DecapsulationKeyOffset, DecapsulationKeyBytes));
        ValidateAbsent(mask, HasCiphertext1, exactState.Slice(Ciphertext1Offset, Ciphertext1Bytes));
        ValidateAbsent(mask, HasEntropy, exactState.Slice(EntropyOffset, EntropyBytes));
        ValidateAbsent(mask, HasCiphertext2, exactState.Slice(Ciphertext2Offset, Ciphertext2Bytes));
        ValidateAbsent(mask, HasCiphertext2Mac,
            exactState.Slice(Ciphertext2MacOffset, MacBytes));
        ValidateAbsent(mask, HasPendingOutput,
            exactState.Slice(PendingOutputOffset, OutputBytes));
        ValidateHashBinding(mask, exactState);

        ManagedMlKemBraidAuthenticator? authenticator = null;
        ManagedMlKemBraidStateMachine? machine = null;
        try
        {
            authenticator = ManagedMlKemBraidAuthenticator.ImportLocalPlaintextState(
                exactState.Slice(AuthenticatorOffset, AuthenticatorBytes));
            if (authenticator.Epoch != epoch) throw InvalidEncoding();
            machine = new ManagedMlKemBraidStateMachine(provider, authenticator, state, epoch);
            authenticator = null;
            machine._seed = ImportPublic(mask, HasSeed, exactState.Slice(SeedOffset, SeedBytes));
            machine._hash = ImportPublic(mask, HasHash, exactState.Slice(HashOffset, HashBytes));
            machine._vector = ImportPublic(mask, HasVector, exactState.Slice(VectorOffset, VectorBytes));
            machine._decapsulationKey = ImportSecret(
                mask, HasDecapsulationKey,
                exactState.Slice(DecapsulationKeyOffset, DecapsulationKeyBytes),
                "decapsulationKey");
            machine._ciphertext1 = ImportPublic(
                mask, HasCiphertext1, exactState.Slice(Ciphertext1Offset, Ciphertext1Bytes));
            machine._encaps1Entropy = ImportSecret(
                mask, HasEntropy, exactState.Slice(EntropyOffset, EntropyBytes), "encaps1Entropy");
            machine._ciphertext2 = ImportPublic(
                mask, HasCiphertext2, exactState.Slice(Ciphertext2Offset, Ciphertext2Bytes));
            machine._ciphertext2Mac = ImportPublic(
                mask, HasCiphertext2Mac, exactState.Slice(Ciphertext2MacOffset, MacBytes));
            machine._pendingOutput = ImportSecret(
                mask, HasPendingOutput, exactState.Slice(PendingOutputOffset, OutputBytes),
                "pendingOutput");
            var result = machine;
            machine = null;
            return result;
        }
        finally
        {
            authenticator?.Dispose();
            machine?.Dispose();
        }
    }

    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    private Dtr2BraidMessage SampleAndSendHeader()
    {
        OwnedDeepMlKemBraidKeyPair? generated = null;
        SecretBuffer? decapsulationKey = null;
        byte[]? seed = null;
        byte[]? hash = null;
        byte[]? vector = null;
        byte[]? computedHash = null;
        try
        {
            generated = _provider.GenerateKeyPair();
            seed = generated.EncapsulationKeySeed.ToArray();
            hash = generated.EncapsulationKeyHash.ToArray();
            vector = generated.EncapsulationKeyVector.ToArray();
            generated.UseDecapsulationKey(key =>
                decapsulationKey = SecretBuffer.ImportExact(key, DecapsulationKeyBytes, "decapsulationKey"));
            computedHash = ManagedMlKemBraidAuthenticator.ComputeEncapsulationKeyHash(seed, vector);
            if (!MessagingCryptoValidation.FixedEquals(hash, computedHash))
                throw new MessagingCryptoException(
                    MessagingCryptoError.ProviderFailure,
                    "The native Braid key pair returned an inconsistent public-key commitment.");
            var message = _authenticator.CreateHeaderMessage(seed, vector);
            CommitTransition(ManagedMlKemBraidState.KeysSampled);
            _seed = seed;
            _hash = hash;
            _vector = vector;
            _decapsulationKey = decapsulationKey;
            seed = null;
            hash = null;
            vector = null;
            decapsulationKey = null;
            return message;
        }
        finally
        {
            generated?.Dispose();
            decapsulationKey?.Dispose();
            Zero(seed);
            Zero(hash);
            Zero(vector);
            Zero(computedHash);
        }
    }

    private Dtr2BraidMessage SampleAndSendCiphertext1()
    {
        var entropyBytes = new byte[EntropyBytes];
        var ciphertext1 = new byte[Ciphertext1Bytes];
        SecretBuffer? entropy = null;
        try
        {
            RandomNumberGenerator.Fill(entropyBytes);
            using (var native = _provider.Encapsulate1FromRandom(
                       Required(_seed), Required(_hash), entropyBytes, ciphertext1))
            {
                // The process-local handle is intentionally discarded. Encaps2 recreates
                // it deterministically from the persisted entropy after any restart.
            }
            entropy = SecretBuffer.ImportExact(entropyBytes, EntropyBytes, "encaps1Entropy");
            var message = Dtr2BraidMessage.Ciphertext1(ciphertext1);
            CommitTransition(ManagedMlKemBraidState.Ct1Sampled);
            _ciphertext1 = ciphertext1;
            _encaps1Entropy = entropy;
            ciphertext1 = null!;
            entropy = null;
            return message;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropyBytes);
            entropy?.Dispose();
            Zero(ciphertext1);
        }
    }

    private SecretBuffer? ReceiveCompleteCiphertext1(Dtr2BraidMessage message)
    {
        if (message.Kind != Dtr2BraidMessageKind.Ciphertext1) return null;
        var ciphertext1 = new byte[Ciphertext1Bytes];
        message.CopyCiphertext1To(ciphertext1);
        CommitTransition(ManagedMlKemBraidState.HeaderSent);
        _ciphertext1 = ciphertext1;
        CommitTransition(ManagedMlKemBraidState.Ct1Received);
        return null;
    }

    private SecretBuffer? ReceiveCompletedCiphertext1(Dtr2BraidMessage message)
    {
        if (message.Kind != Dtr2BraidMessageKind.Ciphertext1) return null;
        Span<byte> ciphertext1 = stackalloc byte[Ciphertext1Bytes];
        try
        {
            message.CopyCiphertext1To(ciphertext1);
            if (!MessagingCryptoValidation.FixedEquals(ciphertext1, Required(_ciphertext1)))
                throw ReplayConflict("The repeated complete Ct1 differs from the pending Ct1.");
            CommitTransition(ManagedMlKemBraidState.Ct1Received);
            return null;
        }
        finally { CryptographicOperations.ZeroMemory(ciphertext1); }
    }

    private SecretBuffer? ReceiveCompleteCiphertext2(Dtr2BraidMessage message)
    {
        if (message.Kind != Dtr2BraidMessageKind.Ciphertext2) return null;
        if (_epoch == ulong.MaxValue)
            throw new MessagingCryptoException(
                MessagingCryptoError.TransitionRejected,
                "The Braid epoch cannot wrap.");
        BeginVerifiedDecapsulation(message);
        CommitTransition(ManagedMlKemBraidState.EkSentCt1Received);
        var result = Required(_pendingOutput).Clone();
        var advanced = _authenticator.AdvanceEpoch(_epoch + 1);
        CommitTransition(ManagedMlKemBraidState.NoHeaderReceived);
        ReplaceAuthenticator(advanced);
        _epoch++;
        ClearEpochMaterial();
        return result;
    }

    private SecretBuffer? ReceiveCompletedCiphertext2(Dtr2BraidMessage message)
    {
        if (message.Kind != Dtr2BraidMessageKind.Ciphertext2) return null;
        Span<byte> ciphertext2 = stackalloc byte[Ciphertext2Bytes];
        Span<byte> mac = stackalloc byte[MacBytes];
        ManagedMlKemBraidAuthenticator? advanced = null;
        SecretBuffer? result = null;
        try
        {
            message.CopyCiphertext2To(ciphertext2, mac);
            if (!MessagingCryptoValidation.FixedEquals(ciphertext2, Required(_ciphertext2)) |
                !MessagingCryptoValidation.FixedEquals(mac, Required(_ciphertext2Mac)))
                throw ReplayConflict("The repeated complete Ct2 differs from the verified Ct2.");
            if (_epoch == ulong.MaxValue)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "The Braid epoch cannot wrap.");
            advanced = _authenticator.AdvanceEpoch(_epoch + 1);
            result = Required(_pendingOutput).Clone();
            CommitTransition(ManagedMlKemBraidState.NoHeaderReceived);
            ReplaceAuthenticator(advanced);
            advanced = null;
            _epoch++;
            ClearEpochMaterial();
            return result;
        }
        catch
        {
            result?.Dispose();
            throw;
        }
        finally
        {
            advanced?.Dispose();
            CryptographicOperations.ZeroMemory(ciphertext2);
            CryptographicOperations.ZeroMemory(mac);
        }
    }

    private SecretBuffer? ReceiveHeader(Dtr2BraidMessage message)
    {
        if (message.Kind != Dtr2BraidMessageKind.Header) return null;
        _authenticator.VerifyHeaderAuthenticator(message, _epoch);
        var seed = new byte[SeedBytes];
        var hash = new byte[HashBytes];
        Span<byte> ignoredMac = stackalloc byte[MacBytes];
        try
        {
            message.CopyHeaderTo(seed, hash, ignoredMac);
            CommitTransition(ManagedMlKemBraidState.HeaderReceived);
            _seed = seed;
            _hash = hash;
            return null;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(hash);
            throw;
        }
        finally { CryptographicOperations.ZeroMemory(ignoredMac); }
    }

    private SecretBuffer? ReceiveEncapsulationKey(Dtr2BraidMessage message)
    {
        if (message.Kind is not (
                Dtr2BraidMessageKind.EncapsulationKey or
                Dtr2BraidMessageKind.EncapsulationKeyWithCiphertext1Ack))
            return null;
        var vector = CopyAndValidateVector(message);
        if (message.Kind == Dtr2BraidMessageKind.EncapsulationKey)
        {
            CommitTransition(ManagedMlKemBraidState.EkReceivedCt1Sampled);
            _vector = vector;
            return null;
        }
        try { return CompleteEncapsulation(vector, ManagedMlKemBraidState.Ct2Sampled); }
        finally { CryptographicOperations.ZeroMemory(vector); }
    }

    private SecretBuffer? ReceiveCiphertext1Ack(Dtr2BraidMessage message)
    {
        if (message.Kind == Dtr2BraidMessageKind.EncapsulationKeyWithCiphertext1Ack)
        {
            var received = CopyAndValidateVector(message);
            try
            {
                if (!MessagingCryptoValidation.FixedEquals(received, Required(_vector)))
                    throw ReplayConflict("The acknowledged EK differs from the accepted EK.");
            }
            finally { CryptographicOperations.ZeroMemory(received); }
        }
        else if (message.Kind != Dtr2BraidMessageKind.Ciphertext1Ack)
        {
            return null;
        }
        return CompleteEncapsulation(Required(_vector), ManagedMlKemBraidState.Ct2Sampled);
    }

    private SecretBuffer? ReceiveAcknowledgedEncapsulationKey(Dtr2BraidMessage message)
    {
        if (message.Kind is not (
                Dtr2BraidMessageKind.EncapsulationKey or
                Dtr2BraidMessageKind.EncapsulationKeyWithCiphertext1Ack))
            return null;
        var vector = CopyAndValidateVector(message);
        try { return CompleteEncapsulation(vector, ManagedMlKemBraidState.Ct2Sampled); }
        finally { CryptographicOperations.ZeroMemory(vector); }
    }

    private void BeginVerifiedDecapsulation(Dtr2BraidMessage message)
    {
        var ciphertext = new byte[Ciphertext1Bytes + Ciphertext2Bytes];
        var ciphertext2 = new byte[Ciphertext2Bytes];
        var mac = new byte[MacBytes];
        var shared = new byte[OutputBytes];
        byte[]? outputCopy = null;
        SecretBuffer? output = null;
        ManagedMlKemBraidAuthenticator? updated = null;
        try
        {
            Required(_ciphertext1).CopyTo(ciphertext, 0);
            message.CopyCiphertext2To(ciphertext2, mac);
            ciphertext2.CopyTo(ciphertext, Ciphertext1Bytes);
            Required(_decapsulationKey).Use(key => _provider.Decapsulate(key, ciphertext, shared));
            output = _authenticator.DeriveOutputKey(shared, _epoch);
            outputCopy = output.Copy();
            updated = _authenticator.PrepareUpdate(outputCopy, _epoch);
            updated.VerifyCiphertext2Message(message, Required(_ciphertext1), _epoch);

            ReplaceAuthenticator(updated);
            updated = null;
            _ciphertext2 = ciphertext2;
            _ciphertext2Mac = mac;
            _pendingOutput = output;
            ciphertext2 = null!;
            mac = null!;
            output = null;
            Clear(ref _seed);
            Clear(ref _hash);
            Clear(ref _vector);
            Dispose(ref _decapsulationKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            Zero(ciphertext2);
            Zero(mac);
            CryptographicOperations.ZeroMemory(shared);
            Zero(outputCopy);
            output?.Dispose();
            updated?.Dispose();
        }
    }

    private SecretBuffer CompleteEncapsulation(
        ReadOnlySpan<byte> vector,
        ManagedMlKemBraidState nextState)
    {
        var entropy = Required(_encaps1Entropy).Copy();
        var recreatedCiphertext1 = new byte[Ciphertext1Bytes];
        var ciphertext2 = new byte[Ciphertext2Bytes];
        var shared = new byte[OutputBytes];
        byte[]? outputCopy = null;
        SecretBuffer? output = null;
        ManagedMlKemBraidAuthenticator? updated = null;
        try
        {
            using var recreated = _provider.Encapsulate1FromRandom(
                Required(_seed), Required(_hash), entropy, recreatedCiphertext1);
            if (!MessagingCryptoValidation.FixedEquals(
                    recreatedCiphertext1, Required(_ciphertext1)))
                throw new MessagingCryptoException(
                    MessagingCryptoError.RollbackDetected,
                    "Persisted Encaps1 entropy does not recreate the committed Ct1.");
            _provider.Encapsulate2(
                recreated, Required(_seed), vector, ciphertext2, shared);
            output = _authenticator.DeriveOutputKey(shared, _epoch);
            outputCopy = output.Copy();
            updated = _authenticator.PrepareUpdate(outputCopy, _epoch);
            _ = updated.CreateCiphertext2Message(Required(_ciphertext1), ciphertext2);

            CommitTransition(nextState);
            ReplaceAuthenticator(updated);
            updated = null;
            _ciphertext2 = ciphertext2;
            ciphertext2 = null!;
            Clear(ref _seed);
            Clear(ref _hash);
            Clear(ref _vector);
            Dispose(ref _encaps1Entropy);
            var result = output;
            output = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
            CryptographicOperations.ZeroMemory(recreatedCiphertext1);
            Zero(ciphertext2);
            CryptographicOperations.ZeroMemory(shared);
            Zero(outputCopy);
            output?.Dispose();
            updated?.Dispose();
        }
    }

    private byte[] CopyAndValidateVector(Dtr2BraidMessage message)
    {
        var vector = new byte[VectorBytes];
        byte[]? actualHash = null;
        try
        {
            message.CopyEncapsulationKeyTo(vector);
            actualHash = ManagedMlKemBraidAuthenticator.ComputeEncapsulationKeyHash(
                Required(_seed), vector);
            if (!MessagingCryptoValidation.FixedEquals(actualHash, Required(_hash)))
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "The complete EK does not match the authenticated Braid header.");
            return vector;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(vector);
            throw;
        }
        finally { Zero(actualHash); }
    }

    private void AdvanceToNextSendingEpoch()
    {
        var advanced = _authenticator.AdvanceEpoch(_epoch + 1);
        try
        {
            CommitTransition(ManagedMlKemBraidState.KeysUnsampled);
            ReplaceAuthenticator(advanced);
            advanced = null!;
            _epoch++;
            ClearEpochMaterial();
        }
        finally { advanced?.Dispose(); }
    }

    private void CommitTransition(ManagedMlKemBraidState next)
    {
        if (!IsDefinedTransition(_state, next))
            throw new MessagingCryptoException(
                MessagingCryptoError.TransitionRejected,
                $"The Braid transition {_state}->{next} is not in the frozen state table.");
        _state = next;
    }

    private void ReplaceAuthenticator(ManagedMlKemBraidAuthenticator successor)
    {
        var previous = _authenticator;
        _authenticator = successor;
        previous.Dispose();
    }

    private void ClearEpochMaterial()
    {
        Clear(ref _seed);
        Clear(ref _hash);
        Clear(ref _vector);
        Dispose(ref _decapsulationKey);
        Clear(ref _ciphertext1);
        Dispose(ref _encaps1Entropy);
        Clear(ref _ciphertext2);
        Clear(ref _ciphertext2Mac);
        Dispose(ref _pendingOutput);
    }

    private void DisposeCore()
    {
        lock (_gate)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _authenticator.Dispose();
            ClearEpochMaterial();
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.ObjectDisposed,
                "The managed ML-KEM Braid state machine has been disposed.");
    }

    private static ushort ExpectedMask(ManagedMlKemBraidState state) => state switch
    {
        ManagedMlKemBraidState.KeysUnsampled or
        ManagedMlKemBraidState.NoHeaderReceived => 0,
        ManagedMlKemBraidState.KeysSampled =>
            HasSeed | HasHash | HasVector | HasDecapsulationKey,
        ManagedMlKemBraidState.HeaderSent or
        ManagedMlKemBraidState.Ct1Received =>
            HasSeed | HasHash | HasVector | HasDecapsulationKey | HasCiphertext1,
        ManagedMlKemBraidState.EkSentCt1Received =>
            HasCiphertext1 | HasCiphertext2 | HasCiphertext2Mac | HasPendingOutput,
        ManagedMlKemBraidState.HeaderReceived => HasSeed | HasHash,
        ManagedMlKemBraidState.Ct1Sampled or
        ManagedMlKemBraidState.Ct1Acknowledged =>
            HasSeed | HasHash | HasCiphertext1 | HasEntropy,
        ManagedMlKemBraidState.EkReceivedCt1Sampled =>
            HasSeed | HasHash | HasVector | HasCiphertext1 | HasEntropy,
        ManagedMlKemBraidState.Ct2Sampled => HasCiphertext1 | HasCiphertext2,
        _ => throw InvalidEncoding(),
    };

    private static void ValidateHashBinding(ushort mask, ReadOnlySpan<byte> state)
    {
        if ((mask & (HasSeed | HasHash | HasVector)) !=
            (HasSeed | HasHash | HasVector)) return;
        var actual = ManagedMlKemBraidAuthenticator.ComputeEncapsulationKeyHash(
            state.Slice(SeedOffset, SeedBytes), state.Slice(VectorOffset, VectorBytes));
        try
        {
            if (!MessagingCryptoValidation.FixedEquals(
                    actual, state.Slice(HashOffset, HashBytes)))
                throw InvalidEncoding();
        }
        finally { CryptographicOperations.ZeroMemory(actual); }
    }

    private static void ValidateAbsent(
        ushort mask,
        ushort flag,
        ReadOnlySpan<byte> value)
    {
        if ((mask & flag) == 0 && !MessagingCryptoValidation.IsZero(value))
            throw InvalidEncoding();
    }

    private static byte[]? ImportPublic(
        ushort mask,
        ushort flag,
        ReadOnlySpan<byte> value) => (mask & flag) == 0 ? null : value.ToArray();

    private static SecretBuffer? ImportSecret(
        ushort mask,
        ushort flag,
        ReadOnlySpan<byte> value,
        string name) => (mask & flag) == 0 ? null : SecretBuffer.ImportExact(value, value.Length, name);

    private static MessagingCryptoException InvalidEncoding() =>
        new(MessagingCryptoError.InvalidInput,
            "The local managed Braid state is not one exact canonical MBM1 value.");

    private static MessagingCryptoException InvalidState() =>
        new(MessagingCryptoError.TerminallyLatched, "The managed Braid state is invalid.");

    private static MessagingCryptoException ReplayConflict(string message) =>
        new(MessagingCryptoError.ReplayConflict, message);

    private static byte[] Required(byte[]? value) => value ?? throw InvalidState();
    private static SecretBuffer Required(SecretBuffer? value) => value ?? throw InvalidState();

    private static void Copy(byte[]? value, byte[] destination, int offset)
    {
        if (value is not null) value.CopyTo(destination, offset);
    }

    private static void Clear(ref byte[]? value)
    {
        var owned = value;
        value = null;
        Zero(owned);
    }

    private static void Dispose(ref SecretBuffer? value)
    {
        var owned = value;
        value = null;
        owned?.Dispose();
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}
