using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class RecoveryProviderTests
{
    [Fact]
    public async Task PublicCandidatePlan_IsDefensiveDataOnlyAndDisposalClosesRows()
    {
        var drm = Manifest();
        var nonce = Bytes(7, 24);
        var drc = Capsule(drm, nonce);
        using var candidate = await RecoveryTestAccess.OpenUnverifiedCandidateAsync(
            drc,
            new GateProvider(nonce),
            new RecordingLatch(RecoveryNonceLatchDecision.Stored),
            default);

        Assert.True(candidate.NoAuthorityClaim);
        Assert.False(candidate.ExactReplay);
        Assert.Equal(6, candidate.Artifacts.Count);
        var artifact = candidate.Artifacts.Single(static item => item.ArtifactType == ArtifactType.Dpa1);
        var first = artifact.CanonicalBytes.ToArray();
        first.AsSpan().Fill(0xff);
        Assert.NotEqual(first, artifact.CanonicalBytes.ToArray());
        Assert.Equal(
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-drm-hash", drm),
            candidate.DrmHash.ToArray());

        candidate.Dispose();
        Assert.Throws<ObjectDisposedException>(() => candidate.Artifacts.ToArray());
        Assert.Throws<ObjectDisposedException>(() => artifact.CanonicalBytes.ToArray());
        Assert.Throws<ObjectDisposedException>(() => candidate.DrmHash.ToArray());
    }

    [Fact]
    public async Task FrozenDrc_UsesTypedProviderAndExactNonceLatch()
    {
        var drm = Manifest();
        var nonce = Bytes(7, 24);
        var drc = Capsule(drm, nonce);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var provider = new GateProvider(nonce, entered, gate);
        var latch = new RecordingLatch(RecoveryNonceLatchDecision.Stored);

        var pending = RecoveryTestAccess.OpenUnverifiedCandidateAsync(drc, provider, latch, default).AsTask();
        await entered.Task;
        drc.AsSpan().Fill(0xff);
        gate.SetResult();
        using var candidate = await pending;

        Assert.False(candidate.ExactReplay);
        Assert.Equal(1, provider.DeriveCalls);
        Assert.Equal(1, provider.OpenCalls);
        Assert.Equal(56, latch.Key!.Length);
        Assert.Equal(32, latch.Value!.Length);
        Assert.Contains(candidate.Artifacts, static item => item.ArtifactType == ArtifactType.Dpa1);
    }

    [Fact]
    public async Task NonceMismatchOrFork_RejectsBeforeOpen()
    {
        var drm = Manifest();
        var nonce = Bytes(7, 24);
        var drc = Capsule(drm, nonce);
        var wrong = new GateProvider(Bytes(8, 24));
        await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryTestAccess.OpenUnverifiedCandidateAsync(
                drc, wrong, new RecordingLatch(RecoveryNonceLatchDecision.Stored), default).AsTask());
        Assert.Equal(0, wrong.OpenCalls);

        var fork = new GateProvider(nonce);
        await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryTestAccess.OpenUnverifiedCandidateAsync(
                drc, fork, new RecordingLatch(RecoveryNonceLatchDecision.ForkLatched), default).AsTask());
        Assert.Equal(0, fork.OpenCalls);
    }

    [Fact]
    public async Task CancellationAfterDerive_YieldsNoOpenOrCandidate()
    {
        var drm = Manifest();
        var nonce = Bytes(7, 24);
        var drc = Capsule(drm, nonce);
        using var cancellation = new CancellationTokenSource();
        var provider = new CancellingProvider(nonce, cancellation);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            RecoveryTestAccess.OpenUnverifiedCandidateAsync(
                drc, provider, new RecordingLatch(RecoveryNonceLatchDecision.Stored),
                cancellation.Token).AsTask());
        Assert.Equal(0, provider.OpenCalls);
    }

    [Fact]
    public async Task CancellationAfterOpen_YieldsNoCandidate()
    {
        var drm = Manifest();
        var nonce = Bytes(7, 24);
        var drc = Capsule(drm, nonce);
        using var cancellation = new CancellationTokenSource();
        var provider = new OpenCancellingProvider(nonce, drm, cancellation);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            RecoveryTestAccess.OpenUnverifiedCandidateAsync(
                drc, provider, new RecordingLatch(RecoveryNonceLatchDecision.Stored),
                cancellation.Token).AsTask());
        Assert.Equal(1, provider.OpenCalls);
    }

    [Fact]
    public async Task MalformedOpenedManifest_RejectsAfterExactlyOneAeadOpen()
    {
        var drm = Manifest();
        drm[^1] ^= 1;
        var nonce = Bytes(7, 24);
        var provider = new GateProvider(nonce);

        await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryTestAccess.OpenUnverifiedCandidateAsync(
                Capsule(drm, nonce), provider,
                new RecordingLatch(RecoveryNonceLatchDecision.Stored), default).AsTask());

        Assert.Equal(1, provider.DeriveCalls);
        Assert.Equal(1, provider.OpenCalls);
    }

    [Fact]
    public async Task Dispose_ZeroesLatchMaterialAndConsumesPlaintext()
    {
        var drm = Manifest();
        var nonce = Bytes(7, 24);
        var candidate = await RecoveryTestAccess.OpenUnverifiedCandidateAsync(
            Capsule(drm, nonce), new GateProvider(nonce),
            new RecordingLatch(RecoveryNonceLatchDecision.ExactReplay), default);
        var key = candidate.LatchKey;
        var value = candidate.LatchValue;

        candidate.Dispose();

        Assert.True(candidate.ExactReplay);
        Assert.All(key, static item => Assert.Equal(0, item));
        Assert.All(value, static item => Assert.Equal(0, item));
        Assert.Throws<ObjectDisposedException>(() => candidate.Manifest.RowBytes(0).ToArray());
    }

    [Fact]
    public async Task RetainingProvider_CannotMutateFrozenRequestOrReturnedCandidate()
    {
        var drm = Manifest();
        var nonce = Bytes(7, 24);
        var provider = new RetainingProvider(nonce);

        using var candidate = await RecoveryTestAccess.OpenUnverifiedCandidateAsync(
            Capsule(drm, nonce), provider,
            new RecordingLatch(RecoveryNonceLatchDecision.Stored), default);
        var before = candidate.DrmHash.ToArray();

        provider.MutateEveryRetainedBuffer();

        Assert.Equal(before, candidate.DrmHash.ToArray());
        Assert.Contains(candidate.Artifacts, static item => item.ArtifactType == ArtifactType.Dpa1);
    }

    private static byte[] Capsule(byte[] drm, byte[] nonce)
    {
        return Drm3Fixture.CreateCapsule(drm, nonce);
    }

    private static byte[] Manifest()
    {
        return Drm3Fixture.Create();
    }

    private static byte[] Ref(ArtifactType type, uint length, byte marker)
    {
        var value = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(2), length);
        value[6] = marker;
        return value;
    }

    private static byte[] Bytes(byte value, int length) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }

    private sealed class GateProvider : RecoveryProtectorProvider
    {
        private readonly byte[] _nonce;
        private readonly TaskCompletionSource? _entered;
        private readonly TaskCompletionSource? _gate;

        internal GateProvider(byte[] nonce, TaskCompletionSource? entered = null, TaskCompletionSource? gate = null)
        {
            _nonce = nonce;
            _entered = entered;
            _gate = gate;
        }

        internal int DeriveCalls { get; private set; }
        internal int OpenCalls { get; private set; }

        public override async ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            DeriveCalls++;
            _entered?.SetResult();
            if (_gate is not null) await _gate.Task.WaitAsync(cancellationToken);
            _nonce.CopyTo(derivedNonce24);
        }

        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            OpenCalls++;
            request.Ciphertext.CopyTo(plaintextDestination);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class CancellingProvider : RecoveryProtectorProvider
    {
        private readonly byte[] _nonce;
        private readonly CancellationTokenSource _cancellation;

        internal CancellingProvider(byte[] nonce, CancellationTokenSource cancellation)
        {
            _nonce = nonce;
            _cancellation = cancellation;
        }

        internal int OpenCalls { get; private set; }

        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            _nonce.CopyTo(derivedNonce24);
            _cancellation.Cancel();
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            OpenCalls++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class OpenCancellingProvider : RecoveryProtectorProvider
    {
        private readonly byte[] _nonce;
        private readonly byte[] _plaintext;
        private readonly CancellationTokenSource _cancellation;

        internal OpenCancellingProvider(
            byte[] nonce,
            byte[] plaintext,
            CancellationTokenSource cancellation)
        {
            _nonce = nonce;
            _plaintext = plaintext;
            _cancellation = cancellation;
        }

        internal int OpenCalls { get; private set; }

        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            _nonce.CopyTo(derivedNonce24);
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            OpenCalls++;
            _plaintext.CopyTo(plaintextDestination);
            _cancellation.Cancel();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RecordingLatch : RecoveryNonceLatch
    {
        private readonly RecoveryNonceLatchDecision _decision;
        internal RecordingLatch(RecoveryNonceLatchDecision decision) => _decision = decision;
        internal byte[]? Key { get; private set; }
        internal byte[]? Value { get; private set; }

        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken)
        {
            Key = request.ExactRequest.Slice(32, 56).ToArray();
            Value = request.LatchValue.ToArray();
            return ValueTask.FromResult(_decision);
        }
    }

    private sealed class RetainingProvider(byte[] nonce) : RecoveryProtectorProvider
    {
        private Memory<byte> _nonceDestination;
        private Memory<byte> _plaintextDestination;
        private readonly List<ArraySegment<byte>> _requestCopies = [];

        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _nonceDestination = derivedNonce24;
            nonce.CopyTo(derivedNonce24);
            Retain(request.StoredNonce);
            Retain(request.TransactionId);
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _plaintextDestination = plaintextDestination;
            request.Ciphertext.CopyTo(plaintextDestination);
            Retain(request.NetworkId);
            Retain(request.ComponentSubject);
            Retain(request.ProtectorKeyId);
            Retain(request.Ciphertext);
            Retain(request.AuthenticationTag);
            return ValueTask.CompletedTask;
        }

        internal void MutateEveryRetainedBuffer()
        {
            _nonceDestination.Span.Fill(0xff);
            _plaintextDestination.Span.Fill(0xff);
            foreach (var segment in _requestCopies)
                segment.AsSpan().Fill(0xff);
        }

        private void Retain(ReadOnlyMemory<byte> memory)
        {
            Assert.True(MemoryMarshal.TryGetArray(memory, out var segment));
            _requestCopies.Add(segment);
        }
    }
}
