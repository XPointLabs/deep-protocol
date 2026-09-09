using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Deep.Protocol.MessagingCrypto;

internal sealed record DeepMlKemBraidApprovedAsset(
    string RuntimeIdentifier,
    string RelativePath,
    long Bytes,
    string Sha256,
    string ProviderIdentifier,
    bool ApprovedForProduction);

/// <summary>
/// Pinned evidence for the incremental ML-KEM Braid provider. Candidate records
/// remain fail-closed until official reproducibility and physical runtime
/// acceptance are complete; the runtime never accepts a caller-selected path
/// or digest.
/// </summary>
internal static class DeepMlKemBraidApprovedAssets
{
    internal const string ManifestProviderIdentifier =
        "libcrux-ml-kem/0.0.10/deep-mlkem-braid-abi-v1";

    internal static DeepMlKemBraidApprovedAsset WindowsX64 { get; } = new(
        "win-x64",
        "runtimes/win-x64/native/deep_mlkem_braid.dll",
        526336,
        "902c80f52221ee2a4da340f01ed7f3c40eb6ea51f7d91584031ac5679d829e74",
        ManifestProviderIdentifier,
        ApprovedForProduction: true);

    internal static DeepMlKemBraidApprovedAsset WindowsArm64 { get; } = new(
        "win-arm64",
        "runtimes/win-arm64/native/deep_mlkem_braid.dll",
        344064,
        "0f4c70bf9a40373d9c8a4bc1af956a7934ec294f83de3c2169d085ddad424309",
        ManifestProviderIdentifier,
        ApprovedForProduction: true);

    internal static DeepMlKemBraidApprovedAsset WindowsX64Candidate { get; } =
        WindowsX64 with { ApprovedForProduction = false };

    internal static DeepMlKemBraidApprovedAsset WindowsArm64Candidate { get; } =
        WindowsArm64 with { ApprovedForProduction = false };

#if DEEP_MLKEM_ANDROID_PROBE
    internal static DeepMlKemBraidApprovedAsset AndroidArm64ProbeCandidate { get; } = new(
        "android-arm64",
        "runtimes/android-arm64/native/libdeep_mlkem_braid.so",
        612344,
        "fa287d90ffff2c6e5b199c7f8ec487e16d989f75e39c2620b07c26e1dccbdf0d",
        ManifestProviderIdentifier,
        ApprovedForProduction: false);
#endif

    internal static DeepMlKemBraidApprovedAsset ForCurrentProcess()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "No release-approved incremental ML-KEM Braid asset exists for this operating system.");
        return RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => WindowsX64,
            Architecture.Arm64 => WindowsArm64,
            _ => throw new PlatformNotSupportedException(
                "No release-approved incremental ML-KEM Braid asset exists for the current process RID."),
        };
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static DeepMlKemBraidApprovedAsset CandidateForCurrentWindowsProcess()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The reviewed Braid candidates are Windows-only.");
        return RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => WindowsX64Candidate,
            Architecture.Arm64 => WindowsArm64Candidate,
            _ => throw new PlatformNotSupportedException(
                "No reviewed Braid candidate exists for the current Windows process architecture."),
        };
    }
#endif
}

internal interface IDeepMlKemBraidAbi : IDisposable
{
    nuint KeygenRandomSize { get; }
    nuint DecapsulationKeySize { get; }
    nuint EncapsulationKeySeedSize { get; }
    nuint EncapsulationKeyHashSize { get; }
    nuint EncapsulationKeyVectorSize { get; }
    nuint EncapsulationRandomSize { get; }
    nuint Ciphertext1Size { get; }
    nuint Ciphertext2Size { get; }
    nuint SharedSecretSize { get; }

    int KeyPairFromRandom(
        ReadOnlySpan<byte> random,
        Span<byte> decapsulationKey,
        Span<byte> encapsulationKeyVector,
        Span<byte> encapsulationKeySeed,
        Span<byte> encapsulationKeyHash);

    int KeyPairGenerate(
        Span<byte> decapsulationKey,
        Span<byte> encapsulationKeyVector,
        Span<byte> encapsulationKeySeed,
        Span<byte> encapsulationKeyHash);

    int Encapsulate1FromRandom(
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyHash,
        ReadOnlySpan<byte> random,
        Span<byte> ciphertext1,
        out ulong ownedState);

    int Encapsulate1Generate(
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyHash,
        Span<byte> ciphertext1,
        out ulong ownedState);

    int Encapsulate2(
        ulong ownedState,
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyVector,
        Span<byte> ciphertext2,
        Span<byte> sharedSecret);

    int Decapsulate(
        ReadOnlySpan<byte> decapsulationKey,
        ReadOnlySpan<byte> ciphertext1,
        ReadOnlySpan<byte> ciphertext2,
        Span<byte> sharedSecret);

    int StateFree(ulong ownedState);
    int Zero(Span<byte> buffer);
}

internal sealed class OwnedDeepMlKemBraidKeyPair : IDisposable
{
    private readonly object _gate = new();
    private readonly SecretBuffer _decapsulationKey;
    private readonly byte[] _encapsulationKeyVector;
    private readonly byte[] _encapsulationKeySeed;
    private readonly byte[] _encapsulationKeyHash;
    private int _disposed;

    internal OwnedDeepMlKemBraidKeyPair(
        ReadOnlySpan<byte> decapsulationKey,
        ReadOnlySpan<byte> encapsulationKeyVector,
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyHash)
    {
        MessagingCryptoValidation.Exact(
            decapsulationKey, DeepMlKemBraidNativeProvider.DecapsulationKeySize, nameof(decapsulationKey));
        MessagingCryptoValidation.Exact(
            encapsulationKeyVector, DeepMlKemBraidNativeProvider.EncapsulationKeyVectorSize,
            nameof(encapsulationKeyVector));
        MessagingCryptoValidation.Exact(
            encapsulationKeySeed, DeepMlKemBraidNativeProvider.EncapsulationKeySeedSize,
            nameof(encapsulationKeySeed));
        MessagingCryptoValidation.Exact(
            encapsulationKeyHash, DeepMlKemBraidNativeProvider.EncapsulationKeyHashSize,
            nameof(encapsulationKeyHash));
        SecretBuffer? ownedDecapsulationKey = null;
        byte[]? ownedVector = null;
        byte[]? ownedSeed = null;
        byte[]? ownedHash = null;
        try
        {
            ownedDecapsulationKey = SecretBuffer.ImportExact(
                decapsulationKey, DeepMlKemBraidNativeProvider.DecapsulationKeySize,
                nameof(decapsulationKey));
            MessagingCryptoFaultInjection.OwnedSecret(
                "braid.native.decapsulation-key", ownedDecapsulationKey);
            ownedVector = encapsulationKeyVector.ToArray();
            ownedSeed = encapsulationKeySeed.ToArray();
            ownedHash = encapsulationKeyHash.ToArray();

            _decapsulationKey = ownedDecapsulationKey;
            _encapsulationKeyVector = ownedVector;
            _encapsulationKeySeed = ownedSeed;
            _encapsulationKeyHash = ownedHash;
        }
        catch
        {
            ownedDecapsulationKey?.Dispose();
            if (ownedVector is not null) CryptographicOperations.ZeroMemory(ownedVector);
            if (ownedSeed is not null) CryptographicOperations.ZeroMemory(ownedSeed);
            if (ownedHash is not null) CryptographicOperations.ZeroMemory(ownedHash);
            throw;
        }
    }

    internal ReadOnlyMemory<byte> EncapsulationKeyVector
    {
        get { lock (_gate) { ThrowIfDisposed(); return _encapsulationKeyVector.ToArray(); } }
    }

    internal ReadOnlyMemory<byte> EncapsulationKeySeed
    {
        get { lock (_gate) { ThrowIfDisposed(); return _encapsulationKeySeed.ToArray(); } }
    }

    internal ReadOnlyMemory<byte> EncapsulationKeyHash
    {
        get { lock (_gate) { ThrowIfDisposed(); return _encapsulationKeyHash.ToArray(); } }
    }

    internal void UseDecapsulationKey(MessagingSecretAction action)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            _decapsulationKey.Use(action);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _decapsulationKey.Dispose();
            CryptographicOperations.ZeroMemory(_encapsulationKeyVector);
            CryptographicOperations.ZeroMemory(_encapsulationKeySeed);
            CryptographicOperations.ZeroMemory(_encapsulationKeyHash);
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.ObjectDisposed,
                "The incremental ML-KEM Braid key pair has been disposed.");
    }
}

internal sealed class OwnedDeepMlKemBraidEncapsulationState : IDisposable
{
    private readonly DeepMlKemBraidNativeProvider _owner;
    private readonly byte[] _encapsulationKeySeed;
    private readonly byte[] _encapsulationKeyHash;
    private ulong _nativeHandle;
    private int _lifecycle;

    internal OwnedDeepMlKemBraidEncapsulationState(
        DeepMlKemBraidNativeProvider owner,
        ulong nativeHandle,
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyHash)
    {
        _owner = owner;
        _nativeHandle = nativeHandle;
        _encapsulationKeySeed = encapsulationKeySeed.ToArray();
        _encapsulationKeyHash = encapsulationKeyHash.ToArray();
    }

    internal ulong Consume(
        DeepMlKemBraidNativeProvider owner,
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyVector)
    {
        if (!ReferenceEquals(_owner, owner))
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The opaque Braid state belongs to another provider instance.");
        var previous = Interlocked.CompareExchange(ref _lifecycle, 1, 0);
        if (previous == 1)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The opaque Braid Encaps1 state is single-use.");
        if (previous != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.ObjectDisposed,
                "The opaque Braid Encaps1 state has been disposed.");

        var handle = Interlocked.Exchange(ref _nativeHandle, 0);
        var actualHash = ManagedMlKemBraidAuthenticator.ComputeEncapsulationKeyHash(
            encapsulationKeySeed,
            encapsulationKeyVector);
        try
        {
            if (!MessagingCryptoValidation.FixedEquals(_encapsulationKeySeed, encapsulationKeySeed) |
                !MessagingCryptoValidation.FixedEquals(_encapsulationKeyHash, actualHash))
            {
                _owner.ReleaseConsumedStateAfterManagedRejection(this, handle);
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "Encaps2 does not bind the seed and vector committed by Encaps1.");
            }
            _owner.UntrackConsumedState(this);
            return handle;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualHash);
            CryptographicOperations.ZeroMemory(_encapsulationKeySeed);
            CryptographicOperations.ZeroMemory(_encapsulationKeyHash);
        }
    }

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _lifecycle, 2, 0) != 0) return;
        var handle = Interlocked.Exchange(ref _nativeHandle, 0);
        CryptographicOperations.ZeroMemory(_encapsulationKeySeed);
        CryptographicOperations.ZeroMemory(_encapsulationKeyHash);
        _owner.ReleaseAbandonedState(this, handle);
    }
}

/// <summary>
/// Managed ownership and validation boundary for deep_mlkem_braid_v1. The
/// native state is never surfaced as an integer and is consumed exactly once.
/// </summary>
internal sealed class DeepMlKemBraidNativeProvider : IDisposable
{
    internal const int KeygenRandomSize = 64;
    internal const int DecapsulationKeySize = 2400;
    internal const int EncapsulationKeySeedSize = 32;
    internal const int EncapsulationKeyHashSize = 32;
    internal const int EncapsulationKeyVectorSize = 1152;
    internal const int EncapsulationRandomSize = 32;
    internal const int Ciphertext1Size = 960;
    internal const int Ciphertext2Size = 128;
    internal const int CiphertextSize = Ciphertext1Size + Ciphertext2Size;
    internal const int SharedSecretSize = 32;
    internal const string Identifier = DeepMlKemBraidApprovedAssets.ManifestProviderIdentifier;

    private const int Ok = 0;
    private readonly object _gate = new();
    private readonly HashSet<OwnedDeepMlKemBraidEncapsulationState> _states = [];
    private readonly IDeepMlKemBraidAbi _abi;
    private int _disposed;

    ~DeepMlKemBraidNativeProvider()
    {
        try { DisposeCore(); }
        catch { }
    }

    internal DeepMlKemBraidNativeProvider(IDeepMlKemBraidAbi abi, string providerIdentifier)
    {
        _abi = abi ?? throw new ArgumentNullException(nameof(abi));
        if (!string.Equals(providerIdentifier, Identifier, StringComparison.Ordinal))
        {
            Interlocked.Exchange(ref _disposed, 1);
            _abi.Dispose();
            throw new CryptographicException("The incremental ML-KEM Braid provider identity is not pinned.");
        }
        try { ValidateAbi(); }
        catch
        {
            Interlocked.Exchange(ref _disposed, 1);
            _abi.Dispose();
            throw;
        }
    }

    internal string ProviderIdentifier => Identifier;

    internal static DeepMlKemBraidNativeProvider LoadApprovedForCurrentProcess()
    {
        var approved = DeepMlKemBraidApprovedAssets.ForCurrentProcess();
        ValidateApprovedAssetIdentity(approved, requireProductionApproval: true);
        return new DeepMlKemBraidNativeProvider(
            DeepMlKemBraidDynamicAbi.LoadApproved(approved),
            approved.ProviderIdentifier);
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static DeepMlKemBraidNativeProvider LoadCandidateForTests(
        DeepMlKemBraidApprovedAsset candidate)
    {
        ValidateApprovedAssetIdentity(candidate, requireProductionApproval: false);
        return new DeepMlKemBraidNativeProvider(
            DeepMlKemBraidDynamicAbi.LoadCandidateForTests(candidate),
            candidate.ProviderIdentifier);
    }
#endif

#if DEEP_MLKEM_ANDROID_PROBE
    internal static DeepMlKemBraidNativeProvider LoadAndroidArm64CandidateForProbe()
    {
        if (!OperatingSystem.IsAndroid() ||
            RuntimeInformation.ProcessArchitecture != Architecture.Arm64)
            throw new PlatformNotSupportedException(
                "The incremental ML-KEM Braid probe requires an Android arm64 process.");
        var candidate = DeepMlKemBraidApprovedAssets.AndroidArm64ProbeCandidate;
        ValidateApprovedAssetIdentity(candidate, requireProductionApproval: false);
        return new DeepMlKemBraidNativeProvider(
            DeepMlKemBraidDynamicAbi.LoadAndroidCandidateForProbe(candidate),
            candidate.ProviderIdentifier);
    }
#endif

    internal static void ValidateApprovedAssetIdentity(
        DeepMlKemBraidApprovedAsset asset,
        bool requireProductionApproval)
    {
        ArgumentNullException.ThrowIfNull(asset);
        if (!string.Equals(asset.ProviderIdentifier, Identifier, StringComparison.Ordinal))
            throw new CryptographicException("The incremental ML-KEM Braid ABI identity is not approved.");
        if (requireProductionApproval && !asset.ApprovedForProduction)
            throw new CryptographicException("The incremental ML-KEM Braid asset is candidate-only.");
        if (asset.Bytes <= 0 || asset.Sha256.Length != 64)
            throw new CryptographicException("The incremental ML-KEM Braid asset evidence is malformed.");
        try
        {
            if (Convert.FromHexString(asset.Sha256).Length != 32)
                throw new CryptographicException("The incremental ML-KEM Braid digest is malformed.");
        }
        catch (FormatException exception)
        {
            throw new CryptographicException("The incremental ML-KEM Braid digest is malformed.", exception);
        }
        if (Path.IsPathRooted(asset.RelativePath) ||
            asset.RelativePath.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries)
                .Any(static segment => segment == ".."))
            throw new CryptographicException("The incremental ML-KEM Braid asset path is not package-relative.");
    }

    internal OwnedDeepMlKemBraidKeyPair GenerateKeyPair()
    {
        var decapsulationKey = new byte[DecapsulationKeySize];
        var vector = new byte[EncapsulationKeyVectorSize];
        var seed = new byte[EncapsulationKeySeedSize];
        var hash = new byte[EncapsulationKeyHashSize];
        try
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                EnsureSuccess(InvokeAbi(() => _abi.KeyPairGenerate(
                    decapsulationKey, vector, seed, hash)));
            }
            return new OwnedDeepMlKemBraidKeyPair(decapsulationKey, vector, seed, hash);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(vector);
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(hash);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decapsulationKey);
        }
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal OwnedDeepMlKemBraidKeyPair GenerateKeyPairFromRandomForTests(ReadOnlySpan<byte> random)
    {
        MessagingCryptoValidation.Exact(random, KeygenRandomSize, nameof(random));
        var ownedRandom = random.ToArray();
        var decapsulationKey = new byte[DecapsulationKeySize];
        var vector = new byte[EncapsulationKeyVectorSize];
        var seed = new byte[EncapsulationKeySeedSize];
        var hash = new byte[EncapsulationKeyHashSize];
        try
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                EnsureSuccess(InvokeAbi(() => _abi.KeyPairFromRandom(
                    ownedRandom, decapsulationKey, vector, seed, hash)));
            }
            return new OwnedDeepMlKemBraidKeyPair(decapsulationKey, vector, seed, hash);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(vector);
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(hash);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ownedRandom);
            CryptographicOperations.ZeroMemory(decapsulationKey);
        }
    }
#endif

    internal OwnedDeepMlKemBraidEncapsulationState Encapsulate1(
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyHash,
        Span<byte> ciphertext1)
    {
        ciphertext1.Clear();
        MessagingCryptoValidation.Exact(
            encapsulationKeySeed, EncapsulationKeySeedSize, nameof(encapsulationKeySeed));
        MessagingCryptoValidation.Exact(
            encapsulationKeyHash, EncapsulationKeyHashSize, nameof(encapsulationKeyHash));
        MessagingCryptoValidation.Exact(ciphertext1, Ciphertext1Size, nameof(ciphertext1));
        RejectOverlap(encapsulationKeySeed, encapsulationKeyHash, ciphertext1);
        ulong handle = 0;
        try
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                int status;
                try
                {
                    status = _abi.Encapsulate1Generate(
                        encapsulationKeySeed, encapsulationKeyHash, ciphertext1, out handle);
                }
                catch (Exception exception)
                {
                    throw MapProviderBoundaryFailure(exception);
                }
                if (status != Ok || handle == 0)
                {
                    if (handle != 0) BestEffortFree(handle);
                    if (status == Ok)
                        throw new MessagingCryptoException(
                            MessagingCryptoError.ProviderFailure,
                            "The incremental ML-KEM Braid provider returned a null state handle.");
                    EnsureSuccess(status);
                }
                var state = new OwnedDeepMlKemBraidEncapsulationState(
                    this, handle, encapsulationKeySeed, encapsulationKeyHash);
                _states.Add(state);
                return state;
            }
        }
        catch
        {
            ciphertext1.Clear();
            throw;
        }
    }

    /// <summary>
    /// Creates an incremental encapsulation state from caller-owned entropy.
    /// A durable ratchet persists that entropy inside its encrypted opaque
    /// state and recreates this process-local native handle after restart;
    /// the handle itself is never serialized.
    /// </summary>
    internal OwnedDeepMlKemBraidEncapsulationState Encapsulate1FromRandom(
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyHash,
        ReadOnlySpan<byte> random,
        Span<byte> ciphertext1)
    {
        ciphertext1.Clear();
        MessagingCryptoValidation.Exact(
            encapsulationKeySeed, EncapsulationKeySeedSize, nameof(encapsulationKeySeed));
        MessagingCryptoValidation.Exact(
            encapsulationKeyHash, EncapsulationKeyHashSize, nameof(encapsulationKeyHash));
        MessagingCryptoValidation.Exact(random, EncapsulationRandomSize, nameof(random));
        MessagingCryptoValidation.Exact(ciphertext1, Ciphertext1Size, nameof(ciphertext1));
        if (encapsulationKeySeed.Overlaps(encapsulationKeyHash) ||
            encapsulationKeySeed.Overlaps(random) || encapsulationKeyHash.Overlaps(random) ||
            encapsulationKeySeed.Overlaps(ciphertext1) ||
            encapsulationKeyHash.Overlaps(ciphertext1) || random.Overlaps(ciphertext1))
            RejectOverlap();
        var ownedRandom = random.ToArray();
        ulong handle = 0;
        try
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                int status;
                try
                {
                    status = _abi.Encapsulate1FromRandom(
                        encapsulationKeySeed, encapsulationKeyHash, ownedRandom, ciphertext1, out handle);
                }
                catch (Exception exception)
                {
                    throw MapProviderBoundaryFailure(exception);
                }
                if (status != Ok || handle == 0)
                {
                    if (handle != 0) BestEffortFree(handle);
                    if (status == Ok)
                        throw new MessagingCryptoException(
                            MessagingCryptoError.ProviderFailure,
                            "The incremental ML-KEM Braid provider returned a null state handle.");
                    EnsureSuccess(status);
                }
                var state = new OwnedDeepMlKemBraidEncapsulationState(
                    this, handle, encapsulationKeySeed, encapsulationKeyHash);
                _states.Add(state);
                return state;
            }
        }
        catch
        {
            ciphertext1.Clear();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ownedRandom);
        }
    }

    internal void Encapsulate2(
        OwnedDeepMlKemBraidEncapsulationState state,
        ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyVector,
        Span<byte> ciphertext2,
        Span<byte> sharedSecret)
    {
        ciphertext2.Clear();
        sharedSecret.Clear();
        if (state is null)
            throw new MessagingCryptoException(MessagingCryptoError.InvalidInput, "Encaps1 state is required.");
        MessagingCryptoValidation.Exact(
            encapsulationKeySeed, EncapsulationKeySeedSize, nameof(encapsulationKeySeed));
        MessagingCryptoValidation.Exact(
            encapsulationKeyVector, EncapsulationKeyVectorSize, nameof(encapsulationKeyVector));
        MessagingCryptoValidation.Exact(ciphertext2, Ciphertext2Size, nameof(ciphertext2));
        MessagingCryptoValidation.Exact(sharedSecret, SharedSecretSize, nameof(sharedSecret));
        if (encapsulationKeySeed.Overlaps(encapsulationKeyVector) ||
            encapsulationKeySeed.Overlaps(ciphertext2) ||
            encapsulationKeySeed.Overlaps(sharedSecret) ||
            encapsulationKeyVector.Overlaps(ciphertext2) ||
            encapsulationKeyVector.Overlaps(sharedSecret) ||
            ciphertext2.Overlaps(sharedSecret))
            RejectOverlap();
        try
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                var handle = state.Consume(this, encapsulationKeySeed, encapsulationKeyVector);
                int status;
                try
                {
                    status = _abi.Encapsulate2(
                        handle, encapsulationKeySeed, encapsulationKeyVector, ciphertext2, sharedSecret);
                }
                catch (Exception exception)
                {
                    // A managed boundary failure can happen before the delegate reaches
                    // native code. If native code did run, Encaps2 already consumed the
                    // handle and StateFree safely reports INVALID_HANDLE.
                    BestEffortFree(handle);
                    throw MapProviderBoundaryFailure(exception);
                }
                EnsureSuccess(status);
            }
        }
        catch
        {
            ciphertext2.Clear();
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw;
        }
    }

    internal void Decapsulate(
        ReadOnlySpan<byte> decapsulationKey,
        ReadOnlySpan<byte> standardCiphertext,
        Span<byte> sharedSecret)
    {
        sharedSecret.Clear();
        MessagingCryptoValidation.Exact(decapsulationKey, DecapsulationKeySize, nameof(decapsulationKey));
        MessagingCryptoValidation.Exact(standardCiphertext, CiphertextSize, nameof(standardCiphertext));
        MessagingCryptoValidation.Exact(sharedSecret, SharedSecretSize, nameof(sharedSecret));
        if (decapsulationKey.Overlaps(standardCiphertext) ||
            decapsulationKey.Overlaps(sharedSecret) || standardCiphertext.Overlaps(sharedSecret))
            RejectOverlap();
        try
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                int status;
                try
                {
                    status = _abi.Decapsulate(
                        decapsulationKey,
                        standardCiphertext[..Ciphertext1Size],
                        standardCiphertext[Ciphertext1Size..],
                        sharedSecret);
                }
                catch (Exception exception)
                {
                    throw MapProviderBoundaryFailure(exception);
                }
                EnsureSuccess(status);
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw;
        }
    }

    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    private void DisposeCore()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        lock (_gate)
        {
            foreach (var state in _states.ToArray()) state.Dispose();
            _states.Clear();
            _abi.Dispose();
        }
    }

    internal void UntrackConsumedState(OwnedDeepMlKemBraidEncapsulationState state)
    {
        _states.Remove(state);
    }

    internal void ReleaseConsumedStateAfterManagedRejection(
        OwnedDeepMlKemBraidEncapsulationState state,
        ulong handle)
    {
        _states.Remove(state);
        BestEffortFree(handle);
    }

    internal void ReleaseAbandonedState(
        OwnedDeepMlKemBraidEncapsulationState state,
        ulong handle)
    {
        lock (_gate)
        {
            _states.Remove(state);
            BestEffortFree(handle);
        }
    }

    private void ValidateAbi()
    {
        try
        {
            if (_abi.KeygenRandomSize != KeygenRandomSize ||
                _abi.DecapsulationKeySize != DecapsulationKeySize ||
                _abi.EncapsulationKeySeedSize != EncapsulationKeySeedSize ||
                _abi.EncapsulationKeyHashSize != EncapsulationKeyHashSize ||
                _abi.EncapsulationKeyVectorSize != EncapsulationKeyVectorSize ||
                _abi.EncapsulationRandomSize != EncapsulationRandomSize ||
                _abi.Ciphertext1Size != Ciphertext1Size ||
                _abi.Ciphertext2Size != Ciphertext2Size ||
                _abi.SharedSecretSize != SharedSecretSize)
                throw new CryptographicException(
                    "The incremental ML-KEM Braid ABI reports unexpected parameter sizes.");
            Span<byte> probe = stackalloc byte[1] { 0xa5 };
            EnsureSuccess(_abi.Zero(probe));
            if (probe[0] != 0)
                throw new CryptographicException(
                    "The incremental ML-KEM Braid zeroization primitive failed its load-time probe.");
        }
        catch (MessagingCryptoException exception)
        {
            throw new CryptographicException("The incremental ML-KEM Braid ABI probe failed.", exception);
        }
    }

    private static int InvokeAbi(Func<int> call)
    {
        try { return call(); }
        catch (MessagingCryptoException) { throw; }
        catch (Exception exception)
        {
            throw new MessagingCryptoException(
                MessagingCryptoError.ProviderFailure,
                "The incremental ML-KEM Braid provider raised an unmanaged boundary failure.",
                exception);
        }
    }

    private static MessagingCryptoException MapProviderBoundaryFailure(Exception exception) =>
        exception as MessagingCryptoException ?? new MessagingCryptoException(
            MessagingCryptoError.ProviderFailure,
            "The incremental ML-KEM Braid provider raised an unmanaged boundary failure.",
            exception);

    private static void EnsureSuccess(int status)
    {
        if (status == Ok) return;
        var error = status switch
        {
            1 or 2 or 3 => MessagingCryptoError.InvalidInput,
            4 => MessagingCryptoError.CapabilityConsumed,
            5 => MessagingCryptoError.TransitionRejected,
            6 or 7 => MessagingCryptoError.ProviderFailure,
            _ => MessagingCryptoError.ProviderFailure,
        };
        var closedStatus = status is >= 1 and <= 7 ? status : -1;
        throw new MessagingCryptoException(
            error,
            $"The incremental ML-KEM Braid provider rejected the operation (closed status {closedStatus}).");
    }

    private void BestEffortFree(ulong handle)
    {
        if (handle == 0) return;
        try { _ = _abi.StateFree(handle); }
        catch { }
    }

    private static void RejectOverlap(
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second,
        Span<byte> output)
    {
        if (first.Overlaps(second) || first.Overlaps(output) || second.Overlaps(output))
            RejectOverlap();
    }

    private static void RejectOverlap() =>
        throw new MessagingCryptoException(
            MessagingCryptoError.InvalidInput,
            "Incremental ML-KEM Braid input and output buffers must not overlap.");

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.ObjectDisposed,
                "The incremental ML-KEM Braid provider has been disposed.");
    }
}

internal sealed unsafe class DeepMlKemBraidDynamicAbi : IDeepMlKemBraidAbi
{
    private readonly SafeNativeLibraryHandle _library;
    private readonly delegate* unmanaged[Cdecl]<nuint> _keygenRandomSize;
    private readonly delegate* unmanaged[Cdecl]<nuint> _decapsulationKeySize;
    private readonly delegate* unmanaged[Cdecl]<nuint> _encapsulationKeySeedSize;
    private readonly delegate* unmanaged[Cdecl]<nuint> _encapsulationKeyHashSize;
    private readonly delegate* unmanaged[Cdecl]<nuint> _encapsulationKeyVectorSize;
    private readonly delegate* unmanaged[Cdecl]<nuint> _encapsulationRandomSize;
    private readonly delegate* unmanaged[Cdecl]<nuint> _ciphertext1Size;
    private readonly delegate* unmanaged[Cdecl]<nuint> _ciphertext2Size;
    private readonly delegate* unmanaged[Cdecl]<nuint> _sharedSecretSize;
    private readonly delegate* unmanaged[Cdecl]<
        byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int> _keyPairFromRandom;
    private readonly delegate* unmanaged[Cdecl]<
        byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int> _keyPairGenerate;
    private readonly delegate* unmanaged[Cdecl]<
        byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, ulong*, int> _encapsulate1FromRandom;
    private readonly delegate* unmanaged[Cdecl]<
        byte*, nuint, byte*, nuint, byte*, nuint, ulong*, int> _encapsulate1Generate;
    private readonly delegate* unmanaged[Cdecl]<
        ulong, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int> _encapsulate2;
    private readonly delegate* unmanaged[Cdecl]<
        byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int> _decapsulate;
    private readonly delegate* unmanaged[Cdecl]<ulong, int> _stateFree;
    private readonly delegate* unmanaged[Cdecl]<byte*, nuint, int> _zero;

    private DeepMlKemBraidDynamicAbi(SafeNativeLibraryHandle library)
    {
        _library = library;
        var handle = _library.DangerousGetHandle();
        _keygenRandomSize = (delegate* unmanaged[Cdecl]<nuint>)Export(handle, "deep_mlkem_braid_v1_keygen_random_size");
        _decapsulationKeySize = (delegate* unmanaged[Cdecl]<nuint>)Export(handle, "deep_mlkem_braid_v1_decapsulation_key_size");
        _encapsulationKeySeedSize = (delegate* unmanaged[Cdecl]<nuint>)Export(handle, "deep_mlkem_braid_v1_encapsulation_key_seed_size");
        _encapsulationKeyHashSize = (delegate* unmanaged[Cdecl]<nuint>)Export(handle, "deep_mlkem_braid_v1_encapsulation_key_hash_size");
        _encapsulationKeyVectorSize = (delegate* unmanaged[Cdecl]<nuint>)Export(handle, "deep_mlkem_braid_v1_encapsulation_key_vector_size");
        _encapsulationRandomSize = (delegate* unmanaged[Cdecl]<nuint>)Export(handle, "deep_mlkem_braid_v1_encapsulation_random_size");
        _ciphertext1Size = (delegate* unmanaged[Cdecl]<nuint>)Export(handle, "deep_mlkem_braid_v1_ciphertext1_size");
        _ciphertext2Size = (delegate* unmanaged[Cdecl]<nuint>)Export(handle, "deep_mlkem_braid_v1_ciphertext2_size");
        _sharedSecretSize = (delegate* unmanaged[Cdecl]<nuint>)Export(handle, "deep_mlkem_braid_v1_shared_secret_size");
        _keyPairFromRandom = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int>)Export(handle, "deep_mlkem_braid_v1_keypair_from_random");
        _keyPairGenerate = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int>)Export(handle, "deep_mlkem_braid_v1_keypair_generate");
        _encapsulate1FromRandom = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, ulong*, int>)Export(handle, "deep_mlkem_braid_v1_encaps1_from_random");
        _encapsulate1Generate = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, ulong*, int>)Export(handle, "deep_mlkem_braid_v1_encaps1_generate");
        _encapsulate2 = (delegate* unmanaged[Cdecl]<ulong, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int>)Export(handle, "deep_mlkem_braid_v1_encaps2");
        _decapsulate = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int>)Export(handle, "deep_mlkem_braid_v1_decapsulate");
        _stateFree = (delegate* unmanaged[Cdecl]<ulong, int>)Export(handle, "deep_mlkem_braid_v1_state_free");
        _zero = (delegate* unmanaged[Cdecl]<byte*, nuint, int>)Export(handle, "deep_mlkem_braid_v1_zero");
    }

    internal static DeepMlKemBraidDynamicAbi LoadApproved(DeepMlKemBraidApprovedAsset asset)
    {
        return Load(asset, requireProductionApproval: true);
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static DeepMlKemBraidDynamicAbi LoadCandidateForTests(DeepMlKemBraidApprovedAsset asset) =>
        Load(asset, requireProductionApproval: false);
#endif

#if DEEP_MLKEM_ANDROID_PROBE
    internal static DeepMlKemBraidDynamicAbi LoadAndroidCandidateForProbe(
        DeepMlKemBraidApprovedAsset asset) =>
        Load(asset, requireProductionApproval: false);
#endif

    private static DeepMlKemBraidDynamicAbi Load(
        DeepMlKemBraidApprovedAsset asset,
        bool requireProductionApproval)
    {
        DeepMlKemBraidNativeProvider.ValidateApprovedAssetIdentity(asset, requireProductionApproval);
        var root = Path.GetFullPath(AppContext.BaseDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var path = Path.GetFullPath(Path.Combine(
            root, asset.RelativePath.Replace('/', Path.DirectorySeparatorChar)));
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("The incremental ML-KEM Braid asset escaped the application root.");
        RejectReparsePoints(root, path);
        using var locked = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        if (locked.Length != asset.Bytes)
            throw new CryptographicException("The incremental ML-KEM Braid asset size is not approved.");
        Span<byte> before = stackalloc byte[32];
        Span<byte> after = stackalloc byte[32];
        var approvedHash = Convert.FromHexString(asset.Sha256);
        try
        {
            SHA256.HashData(locked, before);
            if (!CryptographicOperations.FixedTimeEquals(before, approvedHash))
                throw new CryptographicException("The incremental ML-KEM Braid asset digest is not approved.");
            var handle = new SafeNativeLibraryHandle(NativeLibrary.Load(path));
            try
            {
                locked.Position = 0;
                SHA256.HashData(locked, after);
                if (!CryptographicOperations.FixedTimeEquals(before, after))
                    throw new CryptographicException(
                        "The incremental ML-KEM Braid asset changed while it was loaded.");
                return new DeepMlKemBraidDynamicAbi(handle);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(before);
            CryptographicOperations.ZeroMemory(after);
            CryptographicOperations.ZeroMemory(approvedHash);
        }
    }

    public nuint KeygenRandomSize => _keygenRandomSize();
    public nuint DecapsulationKeySize => _decapsulationKeySize();
    public nuint EncapsulationKeySeedSize => _encapsulationKeySeedSize();
    public nuint EncapsulationKeyHashSize => _encapsulationKeyHashSize();
    public nuint EncapsulationKeyVectorSize => _encapsulationKeyVectorSize();
    public nuint EncapsulationRandomSize => _encapsulationRandomSize();
    public nuint Ciphertext1Size => _ciphertext1Size();
    public nuint Ciphertext2Size => _ciphertext2Size();
    public nuint SharedSecretSize => _sharedSecretSize();

    public unsafe int KeyPairFromRandom(
        ReadOnlySpan<byte> random, Span<byte> decapsulationKey,
        Span<byte> encapsulationKeyVector, Span<byte> encapsulationKeySeed,
        Span<byte> encapsulationKeyHash)
    {
        fixed (byte* r = random) fixed (byte* dk = decapsulationKey)
        fixed (byte* vector = encapsulationKeyVector) fixed (byte* seed = encapsulationKeySeed)
        fixed (byte* hash = encapsulationKeyHash)
            return _keyPairFromRandom(
                r, (nuint)random.Length, dk, (nuint)decapsulationKey.Length,
                vector, (nuint)encapsulationKeyVector.Length, seed, (nuint)encapsulationKeySeed.Length,
                hash, (nuint)encapsulationKeyHash.Length);
    }

    public unsafe int KeyPairGenerate(
        Span<byte> decapsulationKey, Span<byte> encapsulationKeyVector,
        Span<byte> encapsulationKeySeed, Span<byte> encapsulationKeyHash)
    {
        fixed (byte* dk = decapsulationKey) fixed (byte* vector = encapsulationKeyVector)
        fixed (byte* seed = encapsulationKeySeed) fixed (byte* hash = encapsulationKeyHash)
            return _keyPairGenerate(
                dk, (nuint)decapsulationKey.Length, vector, (nuint)encapsulationKeyVector.Length,
                seed, (nuint)encapsulationKeySeed.Length, hash, (nuint)encapsulationKeyHash.Length);
    }

    public unsafe int Encapsulate1FromRandom(
        ReadOnlySpan<byte> encapsulationKeySeed, ReadOnlySpan<byte> encapsulationKeyHash,
        ReadOnlySpan<byte> random, Span<byte> ciphertext1, out ulong ownedState)
    {
        fixed (byte* seed = encapsulationKeySeed) fixed (byte* hash = encapsulationKeyHash)
        fixed (byte* r = random) fixed (byte* ct1 = ciphertext1) fixed (ulong* state = &ownedState)
            return _encapsulate1FromRandom(
                seed, (nuint)encapsulationKeySeed.Length, hash, (nuint)encapsulationKeyHash.Length,
                r, (nuint)random.Length, ct1, (nuint)ciphertext1.Length, state);
    }

    public unsafe int Encapsulate1Generate(
        ReadOnlySpan<byte> encapsulationKeySeed, ReadOnlySpan<byte> encapsulationKeyHash,
        Span<byte> ciphertext1, out ulong ownedState)
    {
        fixed (byte* seed = encapsulationKeySeed) fixed (byte* hash = encapsulationKeyHash)
        fixed (byte* ct1 = ciphertext1) fixed (ulong* state = &ownedState)
            return _encapsulate1Generate(
                seed, (nuint)encapsulationKeySeed.Length, hash, (nuint)encapsulationKeyHash.Length,
                ct1, (nuint)ciphertext1.Length, state);
    }

    public unsafe int Encapsulate2(
        ulong ownedState, ReadOnlySpan<byte> encapsulationKeySeed,
        ReadOnlySpan<byte> encapsulationKeyVector, Span<byte> ciphertext2,
        Span<byte> sharedSecret)
    {
        fixed (byte* seed = encapsulationKeySeed) fixed (byte* vector = encapsulationKeyVector)
        fixed (byte* ct2 = ciphertext2) fixed (byte* secret = sharedSecret)
            return _encapsulate2(
                ownedState, seed, (nuint)encapsulationKeySeed.Length,
                vector, (nuint)encapsulationKeyVector.Length, ct2, (nuint)ciphertext2.Length,
                secret, (nuint)sharedSecret.Length);
    }

    public unsafe int Decapsulate(
        ReadOnlySpan<byte> decapsulationKey, ReadOnlySpan<byte> ciphertext1,
        ReadOnlySpan<byte> ciphertext2, Span<byte> sharedSecret)
    {
        fixed (byte* dk = decapsulationKey) fixed (byte* ct1 = ciphertext1)
        fixed (byte* ct2 = ciphertext2) fixed (byte* secret = sharedSecret)
            return _decapsulate(
                dk, (nuint)decapsulationKey.Length, ct1, (nuint)ciphertext1.Length,
                ct2, (nuint)ciphertext2.Length, secret, (nuint)sharedSecret.Length);
    }

    public int StateFree(ulong ownedState) => _stateFree(ownedState);

    public unsafe int Zero(Span<byte> buffer)
    {
        fixed (byte* value = buffer) return _zero(value, (nuint)buffer.Length);
    }

    public void Dispose() => _library.Dispose();

    private static nint Export(nint library, string name) => NativeLibrary.GetExport(library, name);

    private static void RejectReparsePoints(string root, string assetPath)
    {
        var current = root;
        if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            throw new CryptographicException("The application root must not be a reparse point.");
        foreach (var segment in Path.GetRelativePath(root, assetPath).Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException("The native asset path must not contain reparse points.");
        }
    }

    private sealed class SafeNativeLibraryHandle : SafeHandle
    {
        internal SafeNativeLibraryHandle(nint nativeHandle) : base(0, true) => SetHandle(nativeHandle);
        public override bool IsInvalid => handle == 0 || handle == -1;
        protected override bool ReleaseHandle()
        {
            NativeLibrary.Free(handle);
            handle = 0;
            return true;
        }
    }
}

internal sealed class DeepMlKemBraidProductionRuntime : IDisposable
{
    private DeepMlKemBraidNativeProvider? _provider;
    private DeepMlKemBraidProductionRuntime(DeepMlKemBraidNativeProvider provider) => _provider = provider;
    internal static DeepMlKemBraidProductionRuntime CreateApprovedForCurrentProcess() =>
        new(DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());

    internal ManagedTripleRatchetComponentProvider OpenTripleRatchetComponentProvider()
    {
        var provider = Interlocked.Exchange(ref _provider, null) ??
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The approved Braid runtime was already transferred.");
        try
        {
            return ManagedTripleRatchetComponentProvider.CreateApproved(provider);
        }
        catch
        {
            provider.Dispose();
            throw;
        }
    }

    public void Dispose() => Interlocked.Exchange(ref _provider, null)?.Dispose();
}
