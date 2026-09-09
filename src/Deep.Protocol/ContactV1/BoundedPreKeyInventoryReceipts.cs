using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

public enum Xic1BoundedStatus : ushort
{
    ManifestStaged = 1,
    ChunkStaged = 2,
    Committed = 3,
    ExactReplay = 4,
    Incomplete = 5,
    Conflict = 6,
    Expired = 7,
    StaleView = 8,
    RateLimited = 9,
    OutcomeUnknown = 10,
    TemporarilyUnavailable = 11,
}

public enum Xic1BoundedMutationOutcome : byte
{
    None = 0,
    DurablyStaged = 1,
    DurablyActivated = 2,
    DurablyForkLatched = 3,
    OutcomeUnknown = 4,
}

public sealed class Xic1BoundedUnsignedFields
{
    private readonly byte[][] _fields;

    public Xic1BoundedUnsignedFields(
        Xpp1BoundedRequest request,
        Xic1BoundedStatus status,
        Xic1BoundedMutationOutcome mutationOutcome,
        ushort acceptedChunkCount,
        ulong acceptedTotalLength,
        ReadOnlySpan<byte> replicaId32,
        ulong receiptAtUnixSeconds,
        ReadOnlySpan<byte> replicaStateHash32)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (replicaId32.Length != 32 || PreKeyInventoryWire.IsZero(replicaId32))
            throw new ArgumentException("The replica ID must be nonzero 32 bytes.", nameof(replicaId32));
        if (replicaStateHash32.Length != 32 || PreKeyInventoryWire.IsZero(replicaStateHash32))
            throw new ArgumentException("The replica state hash must be nonzero 32 bytes.", nameof(replicaStateHash32));
        _fields =
        [
            [(byte)request.Phase], request.NetworkId.ToArray(), request.PublicationOperationId.ToArray(),
            request.RequestHash.ToArray(), request.PublicationHash.ToArray(), request.Xpi1Hash.ToArray(),
            PreKeyInventoryWire.U16(request.ChunkIndex), PreKeyInventoryWire.U16((ushort)status), [(byte)mutationOutcome],
            PreKeyInventoryWire.U16(acceptedChunkCount), PreKeyInventoryWire.U64(acceptedTotalLength),
            replicaId32.ToArray(), PreKeyInventoryWire.U64(receiptAtUnixSeconds), replicaStateHash32.ToArray(),
        ];
        Xic1BoundedCodec.ValidateFields(_fields, request);
    }

    internal byte[][] EncodeFields() => _fields.Select(static field => field.ToArray()).ToArray();
}

public sealed class Xic1BoundedReceipt
{
    private readonly byte[] _canonical;
    private readonly byte[][] _fields;

    internal Xic1BoundedReceipt(byte[] canonical, byte[][] fields)
    {
        _canonical = canonical;
        _fields = fields;
    }

    public Xpp1BoundedPhase Phase => (Xpp1BoundedPhase)_fields[0][0];
    public ReadOnlyMemory<byte> NetworkId => Field(2);
    public ReadOnlyMemory<byte> PublicationOperationId => Field(3);
    public ReadOnlyMemory<byte> RequestHash => Field(4);
    public ReadOnlyMemory<byte> PublicationHash => Field(5);
    public ReadOnlyMemory<byte> Xpi1Hash => Field(6);
    public ushort ChunkIndex => PreKeyInventoryWire.ReadU16(_fields[6]);
    public Xic1BoundedStatus Status => (Xic1BoundedStatus)PreKeyInventoryWire.ReadU16(_fields[7]);
    public Xic1BoundedMutationOutcome MutationOutcome => (Xic1BoundedMutationOutcome)_fields[8][0];
    public ushort AcceptedChunkCount => PreKeyInventoryWire.ReadU16(_fields[9]);
    public ulong AcceptedTotalLength => PreKeyInventoryWire.ReadU64(_fields[10]);
    public ReadOnlyMemory<byte> ReplicaId => Field(12);
    public ulong ReceiptAtUnixSeconds => PreKeyInventoryWire.ReadU64(_fields[12]);
    public ReadOnlyMemory<byte> ReplicaStateHash => Field(14);
    public ReadOnlyMemory<byte> ReplicaSignature => Field(15);
    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();

    internal ReadOnlySpan<byte> FieldSpan(int tag) => _fields[tag - 1];
    private ReadOnlyMemory<byte> Field(int tag) => _fields[tag - 1].ToArray();
}

public static class Xic1BoundedCodec
{
    public const int TotalBytes = 428;
    public const int SigningProjectionBytes = 356;
    public const string SignatureDomain = "Deep/ContactResolver/V1/bounded-prekey-publication-receipt";
    public const string ActivatedStateHashDomain = "Deep/ContactResolver/V1/prekey-inventory-activated-state";
    private static readonly int[] FieldLengths = [1, 16, 32, 32, 32, 32, 2, 2, 1, 2, 8, 32, 8, 32, 64];

    public static byte[] CreateSignatureInput(Xic1BoundedUnsignedFields fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        var encoded = fields.EncodeFields();
        var projection = PreKeyInventoryWire.Encode(ProtocolMagic.XIC1,
            Enumerable.Range(0, encoded.Length).Select(index => (checked((ushort)(index + 1)), encoded[index])).ToArray(),
            SigningProjectionBytes);
        try { return ContactCodec.SignatureInput(SignatureDomain, projection); }
        finally { CryptographicOperations.ZeroMemory(projection); }
    }

    public static byte[] Encode(Xic1BoundedUnsignedFields fields, ReadOnlySpan<byte> replicaSignature64)
    {
        ArgumentNullException.ThrowIfNull(fields);
        if (replicaSignature64.Length != 64 || PreKeyInventoryWire.IsZero(replicaSignature64))
            throw new ArgumentException("The replica signature must be nonzero 64 bytes.", nameof(replicaSignature64));
        var encoded = fields.EncodeFields().ToList();
        encoded.Add(replicaSignature64.ToArray());
        var canonical = PreKeyInventoryWire.Encode(ProtocolMagic.XIC1,
            Enumerable.Range(0, encoded.Count).Select(index => (checked((ushort)(index + 1)), encoded[index])).ToArray(),
            TotalBytes);
        _ = Decode(canonical);
        return canonical;
    }

    public static Xic1BoundedReceipt Decode(ReadOnlySpan<byte> canonical)
    {
        var layout = PreKeyInventoryWire.Preflight(canonical, ProtocolMagic.XIC1, FieldLengths, TotalBytes, TotalBytes);
        var owned = canonical.ToArray();
        var ownedLayout = PreKeyInventoryWire.Preflight(owned, ProtocolMagic.XIC1, FieldLengths, TotalBytes, TotalBytes);
        var fields = Enumerable.Range(1, FieldLengths.Length)
            .Select(tag => ownedLayout.Value(owned, tag).ToArray()).ToArray();
        ValidateFields(fields, request: null);
        PreKeyInventoryWire.RequireNonZero(fields[14], "Xic1BoundedSignatureInvalid");
        return new Xic1BoundedReceipt(owned, fields);
    }

    public static byte[] ComputeActivatedStateHash(Xpp1CommitRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ContactCodec.Sha256Domain(ActivatedStateHashDomain, Join(
            request.PublicationHash.ToArray(), request.Xpi1Hash.ToArray(),
            PreKeyInventoryWire.U64(request.InventoryTotalLength), request.InventoryHash.ToArray(),
            PreKeyInventoryWire.U16(request.ChunkCount)));
    }

    internal static byte[] SignatureInput(Xic1BoundedReceipt receipt)
    {
        var fields = Enumerable.Range(1, 14)
            .Select(tag => (checked((ushort)tag), receipt.FieldSpan(tag).ToArray())).ToArray();
        var projection = PreKeyInventoryWire.Encode(ProtocolMagic.XIC1, fields, SigningProjectionBytes);
        try { return ContactCodec.SignatureInput(SignatureDomain, projection); }
        finally { CryptographicOperations.ZeroMemory(projection); }
    }

    internal static void ValidateFields(byte[][] fields, Xpp1BoundedRequest? request)
    {
        var phase = (Xpp1BoundedPhase)fields[0][0];
        if (phase is not (Xpp1BoundedPhase.Manifest or Xpp1BoundedPhase.Chunk or Xpp1BoundedPhase.Commit))
            Reject("Xic1BoundedPhaseInvalid");
        foreach (var index in new[] { 1, 2, 3, 4, 5, 11, 13 })
            PreKeyInventoryWire.RequireNonZero(fields[index], $"Xic1BoundedTag{index + 1}");
        var status = (Xic1BoundedStatus)PreKeyInventoryWire.ReadU16(fields[7]);
        var outcome = (Xic1BoundedMutationOutcome)fields[8][0];
        if (!Enum.IsDefined(status) || !Enum.IsDefined(outcome)) Reject("Xic1BoundedStatusInvalid");
        var chunkIndex = PreKeyInventoryWire.ReadU16(fields[6]);
        var acceptedCount = PreKeyInventoryWire.ReadU16(fields[9]);
        var acceptedLength = PreKeyInventoryWire.ReadU64(fields[10]);
        if (phase == Xpp1BoundedPhase.Chunk ? chunkIndex == Xpp1BoundedCodec.NonChunkIndex : chunkIndex != Xpp1BoundedCodec.NonChunkIndex)
            Reject("Xic1BoundedChunkIndexInvalid");
        if (acceptedCount > Xpp1BoundedCodec.MaximumChunkCount) Reject("Xic1BoundedAcceptedCountInvalid");

        var successfulStage =
            phase == Xpp1BoundedPhase.Manifest && status is Xic1BoundedStatus.ManifestStaged or Xic1BoundedStatus.ExactReplay ||
            phase == Xpp1BoundedPhase.Chunk && status is Xic1BoundedStatus.ChunkStaged or Xic1BoundedStatus.ExactReplay;
        var successfulCommit = phase == Xpp1BoundedPhase.Commit && status is Xic1BoundedStatus.Committed or Xic1BoundedStatus.ExactReplay;
        if (status == Xic1BoundedStatus.ManifestStaged && phase != Xpp1BoundedPhase.Manifest ||
            status == Xic1BoundedStatus.ChunkStaged && phase != Xpp1BoundedPhase.Chunk ||
            status == Xic1BoundedStatus.Committed && phase != Xpp1BoundedPhase.Commit)
            Reject("Xic1BoundedPhaseStatusMismatch");
        if (successfulStage && outcome != Xic1BoundedMutationOutcome.DurablyStaged ||
            successfulCommit && outcome != Xic1BoundedMutationOutcome.DurablyActivated ||
            status == Xic1BoundedStatus.Conflict && outcome != Xic1BoundedMutationOutcome.DurablyForkLatched ||
            status == Xic1BoundedStatus.OutcomeUnknown && outcome != Xic1BoundedMutationOutcome.OutcomeUnknown ||
            !successfulStage && !successfulCommit && status is not (Xic1BoundedStatus.Conflict or Xic1BoundedStatus.OutcomeUnknown) &&
            outcome != Xic1BoundedMutationOutcome.None)
            Reject("Xic1BoundedMutationOutcomeInvalid");

        if (request is null) return;
        if (phase != request.Phase ||
            !CryptographicOperations.FixedTimeEquals(fields[1], request.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(fields[2], request.PublicationOperationId.Span) ||
            !CryptographicOperations.FixedTimeEquals(fields[3], request.RequestHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(fields[4], request.PublicationHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(fields[5], request.Xpi1Hash.Span) ||
            chunkIndex != request.ChunkIndex || acceptedCount > request.ChunkCount || acceptedLength > request.InventoryTotalLength)
            Reject("Xic1BoundedRequestBindingMismatch");
        if (successfulCommit && (acceptedCount != request.ChunkCount || acceptedLength != request.InventoryTotalLength))
            Reject("Xic1BoundedCommitCoverageInvalid");
        if (successfulStage && phase == Xpp1BoundedPhase.Manifest &&
            (acceptedCount != 0 || acceptedLength != 0))
            Reject("Xic1BoundedManifestCoverageInvalid");
        if (successfulStage && phase == Xpp1BoundedPhase.Chunk)
        {
            var expectedCount = checked((ushort)(request.ChunkIndex + 1));
            var expectedLength = Math.Min(
                request.InventoryTotalLength,
                checked((ulong)expectedCount * Xpp1BoundedCodec.MaximumChunkPayloadBytes));
            if (acceptedCount != expectedCount || acceptedLength != expectedLength)
                Reject("Xic1BoundedChunkCoverageInvalid");
        }
    }

    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[checked(values.Sum(static value => value.Length))];
        var offset = 0;
        foreach (var value in values) { value.CopyTo(output, offset); offset += value.Length; }
        return output;
    }

    [DoesNotReturn]
    private static void Reject(string code) => PreKeyInventoryWire.Reject(ContactValidationStage.Scalar, code);
}

public enum PreKeyPublicationReplicaDisposition
{
    ManifestAccepted = 1,
    ChunkAccepted = 2,
    ReadyToVerify = 3,
    ExactReplay = 4,
    Incomplete = 5,
    OutOfOrder = 6,
    ScopeRejected = 7,
    ForkLatched = 8,
}

/// <summary>Immutable protocol state. Persist NextState and the exact signed receipt atomically.</summary>
public sealed class PreKeyPublicationReplicaState
{
    private readonly Xpp1ChunkRequest?[] _chunks;
    private readonly byte[]? _commitRequestHash;

    private PreKeyPublicationReplicaState(
        Xpp1ManifestRequest? manifest,
        Xpp1ChunkRequest?[] chunks,
        byte[]? commitRequestHash,
        bool activated,
        bool forkLatched)
    {
        Manifest = manifest;
        _chunks = chunks;
        _commitRequestHash = commitRequestHash?.ToArray();
        IsActivated = activated;
        IsForkLatched = forkLatched;
    }

    public static PreKeyPublicationReplicaState Empty { get; } = new(null, [], null, false, false);
    public Xpp1ManifestRequest? Manifest { get; }
    public ushort AcceptedChunkCount => checked((ushort)_chunks.Count(static chunk => chunk is not null));
    public ulong AcceptedTotalLength => checked((ulong)_chunks.Where(static chunk => chunk is not null).Sum(static chunk => chunk!.Payload.Length));
    public bool IsActivated { get; }
    public bool IsForkLatched { get; }

    public PreKeyPublicationReplicaTransition Apply(Xpp1BoundedRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (IsForkLatched) return Transition(PreKeyPublicationReplicaDisposition.ForkLatched, this, request, true);
        if (Manifest is null)
        {
            if (request is not Xpp1ManifestRequest first)
                return Transition(PreKeyPublicationReplicaDisposition.Incomplete, this, request, false);
            var next = new PreKeyPublicationReplicaState(first, new Xpp1ChunkRequest?[first.ChunkCount], null, false, false);
            return Transition(PreKeyPublicationReplicaDisposition.ManifestAccepted, next, request, false);
        }

        if (request is Xpp1ManifestRequest candidateManifest)
        {
            if (!CryptographicOperations.FixedTimeEquals(candidateManifest.EpochJournalKey.Span, Manifest.EpochJournalKey.Span))
                return Transition(PreKeyPublicationReplicaDisposition.ScopeRejected, this, request, false);
            if (candidateManifest.CanonicalBytes.Span.SequenceEqual(Manifest.CanonicalBytes.Span))
                return Transition(PreKeyPublicationReplicaDisposition.ExactReplay, this, request, true);
            return Fork(request);
        }

        if (!Binds(request)) return Fork(request);
        if (request is Xpp1ChunkRequest chunk)
        {
            var descriptor = Manifest.ChunkDescriptors[chunk.ChunkIndex];
            if (descriptor.Length != chunk.Payload.Length ||
                !CryptographicOperations.FixedTimeEquals(descriptor.Hash.Span, chunk.ChunkHash.Span))
                return Fork(request);
            var existing = _chunks[chunk.ChunkIndex];
            if (existing is not null)
                return existing.CanonicalBytes.Span.SequenceEqual(chunk.CanonicalBytes.Span)
                    ? Transition(PreKeyPublicationReplicaDisposition.ExactReplay, this, request, true)
                    : Fork(request);
            if (chunk.ChunkIndex != AcceptedChunkCount)
                return Transition(PreKeyPublicationReplicaDisposition.OutOfOrder, this, request, false);
            var chunks = _chunks.ToArray();
            chunks[chunk.ChunkIndex] = chunk;
            return Transition(PreKeyPublicationReplicaDisposition.ChunkAccepted,
                new PreKeyPublicationReplicaState(Manifest, chunks, _commitRequestHash, IsActivated, false), request, false);
        }

        var commit = (Xpp1CommitRequest)request;
        if (_commitRequestHash is not null)
        {
            var requestHash = commit.RequestHash.ToArray();
            var exact = CryptographicOperations.FixedTimeEquals(_commitRequestHash, requestHash);
            CryptographicOperations.ZeroMemory(requestHash);
            return exact
                ? Transition(IsActivated ? PreKeyPublicationReplicaDisposition.ExactReplay : PreKeyPublicationReplicaDisposition.ReadyToVerify, this, request, IsActivated)
                : Fork(request);
        }
        if (AcceptedChunkCount != Manifest.ChunkCount)
            return Transition(PreKeyPublicationReplicaDisposition.Incomplete, this, request, false);
        var ordered = _chunks.Select(static chunk => chunk!).ToArray();
        var assembled = BoundedPreKeyInventoryPublication.Assemble(Manifest, ordered);
        var nextState = new PreKeyPublicationReplicaState(Manifest, _chunks, commit.RequestHash.ToArray(), false, false);
        return new PreKeyPublicationReplicaTransition(
            PreKeyPublicationReplicaDisposition.ReadyToVerify, nextState, request, assembled, false);
    }

    public static VerifiedPreKeyInventoryInstallationPlan PrepareActivation(
        PreKeyPublicationReplicaTransition ready,
        VerifiedPreKeyInventoryCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(ready);
        ArgumentNullException.ThrowIfNull(candidate);
        if (ready.Disposition != PreKeyPublicationReplicaDisposition.ReadyToVerify || ready.AssembledPublication is null)
            throw new InvalidOperationException("Only a complete commit transition can activate an inventory.");
        if (!ready.AssembledPublication.CanonicalBytes.Span.SequenceEqual(candidate.LogicalPublication.CanonicalBytes.Span))
            throw new InvalidOperationException("The verified candidate is not the exact assembled publication.");
        var state = ready.NextState;
        var activated = new PreKeyPublicationReplicaState(
            state.Manifest, state._chunks, state._commitRequestHash, true, false);
        return new VerifiedPreKeyInventoryInstallationPlan(
            activated, (Xpp1CommitRequest)ready.Request, candidate.LogicalPublication);
    }

    private bool Binds(Xpp1BoundedRequest request) =>
        CryptographicOperations.FixedTimeEquals(request.NetworkId.Span, Manifest!.NetworkId.Span) &&
        CryptographicOperations.FixedTimeEquals(request.PublicationOperationId.Span, Manifest.PublicationOperationId.Span) &&
        CryptographicOperations.FixedTimeEquals(request.ViewHash.Span, Manifest.ViewHash.Span) &&
        CryptographicOperations.FixedTimeEquals(request.PlacementHash.Span, Manifest.PlacementHash.Span) &&
        request.IssuedAtUnixSeconds == Manifest.IssuedAtUnixSeconds &&
        request.ExpiresAtUnixSeconds == Manifest.ExpiresAtUnixSeconds &&
        CryptographicOperations.FixedTimeEquals(request.PublicationHash.Span, Manifest.PublicationHash.Span) &&
        CryptographicOperations.FixedTimeEquals(request.Xpi1Hash.Span, Manifest.Xpi1Hash.Span) &&
        request.InventoryTotalLength == Manifest.InventoryTotalLength &&
        CryptographicOperations.FixedTimeEquals(request.InventoryHash.Span, Manifest.InventoryHash.Span) &&
        request.ChunkCount == Manifest.ChunkCount;

    private PreKeyPublicationReplicaTransition Fork(Xpp1BoundedRequest request) => Transition(
        PreKeyPublicationReplicaDisposition.ForkLatched,
        new PreKeyPublicationReplicaState(Manifest, _chunks, _commitRequestHash, IsActivated, true), request, false);

    private static PreKeyPublicationReplicaTransition Transition(
        PreKeyPublicationReplicaDisposition disposition,
        PreKeyPublicationReplicaState next,
        Xpp1BoundedRequest request,
        bool requiresStoredReceipt) => new(disposition, next, request, null, requiresStoredReceipt);
}

/// <summary>
/// Non-forgeable atomic persistence input minted only after the complete
/// bounded stream has assembled and the exact XPI1/DPK2 closure has verified.
/// It exposes public offering bytes only. A replica persists this plan and its
/// activated state before signing the final XIC1.
/// </summary>
public sealed class VerifiedPreKeyInventoryInstallationPlan
{
    private readonly byte[] _networkId;
    private readonly byte[] _serviceCapability;
    private readonly byte[] _publicationOperationId;
    private readonly byte[] _publicationHash;
    private readonly byte[] _xpi1Hash;
    private readonly byte[] _exactXpi1;
    private readonly byte[] _commitRequestHash;
    private readonly byte[] _activatedStateHash;
    private readonly VerifiedPreKeyInventoryMember[] _oneTimeMembers;

    internal VerifiedPreKeyInventoryInstallationPlan(
        PreKeyPublicationReplicaState nextState,
        Xpp1CommitRequest commit,
        Xpp1Record publication)
    {
        NextState = nextState;
        _networkId = publication.NetworkId.ToArray();
        _serviceCapability = publication.Manifest.ServiceCapability.ToArray();
        _publicationOperationId = publication.PublicationOperationId.ToArray();
        _publicationHash = commit.PublicationHash.ToArray();
        _xpi1Hash = publication.Manifest.Xpi1Hash.ToArray();
        _exactXpi1 = publication.Manifest.CanonicalBytes.ToArray();
        _commitRequestHash = commit.RequestHash.ToArray();
        _activatedStateHash = Xic1BoundedCodec.ComputeActivatedStateHash(commit);
        _oneTimeMembers = publication.OneTimeDpk2Bytes
            .Select(static exact => new VerifiedPreKeyInventoryMember(exact))
            .ToArray();
        LastResortMember = new VerifiedPreKeyInventoryMember(publication.LastResortDpk2Bytes);
        InventoryEpoch = publication.Manifest.InventoryEpoch;
        IssuedAtUnixSeconds = publication.Manifest.IssuedAtUnixSeconds;
        ExpiresAtUnixSeconds = publication.Manifest.ExpiresAtUnixSeconds;
        ReplicaLineage = new VerifiedPreKeyInventoryReplicaLineage(publication.Manifest);
    }

    public PreKeyPublicationReplicaState NextState { get; }
    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> ServiceCapability => _serviceCapability.ToArray();
    public ReadOnlyMemory<byte> PublicationOperationId => _publicationOperationId.ToArray();
    public ReadOnlyMemory<byte> PublicationHash => _publicationHash.ToArray();
    public ReadOnlyMemory<byte> Xpi1Hash => _xpi1Hash.ToArray();
    public ReadOnlyMemory<byte> ExactXpi1 => _exactXpi1.ToArray();
    public ReadOnlyMemory<byte> CommitRequestHash => _commitRequestHash.ToArray();
    public ReadOnlyMemory<byte> ActivatedStateHash => _activatedStateHash.ToArray();
    public ulong InventoryEpoch { get; }
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public VerifiedPreKeyInventoryReplicaLineage ReplicaLineage { get; }
    public IReadOnlyList<VerifiedPreKeyInventoryMember> OneTimeMembers =>
        Array.AsReadOnly(_oneTimeMembers);
    public VerifiedPreKeyInventoryMember LastResortMember { get; }
}

/// <summary>
/// Minimal durable predecessor authority for one replica. It contains the
/// exact signed XPI1 and its derived hash, never private inventory material.
/// Instances are minted by a verified installation plan or restored by
/// re-verifying persisted exact XPI1 against the current recipient authority.
/// </summary>
public sealed class VerifiedPreKeyInventoryReplicaLineage
{
    private readonly byte[] _networkId;
    private readonly byte[] _serviceCapability;
    private readonly byte[] _responderDeviceId;
    private readonly byte[] _responderDpd1Reference;
    private readonly byte[] _xps1Reference;
    private readonly byte[] _xpi1Hash;
    private readonly byte[] _exactXpi1;

    internal VerifiedPreKeyInventoryReplicaLineage(Xpi1Record manifest)
    {
        Manifest = manifest;
        _networkId = manifest.NetworkId.ToArray();
        _serviceCapability = manifest.ServiceCapability.ToArray();
        _responderDeviceId = manifest.ResponderDeviceId.ToArray();
        _responderDpd1Reference = manifest.ResponderDpd1Reference.ToArray();
        _xps1Reference = manifest.Xps1Reference.ToArray();
        _xpi1Hash = manifest.Xpi1Hash.ToArray();
        _exactXpi1 = manifest.CanonicalBytes.ToArray();
        ServiceGeneration = manifest.ServiceGeneration;
        InventoryEpoch = manifest.InventoryEpoch;
        ExpiresAtUnixSeconds = manifest.ExpiresAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> ServiceCapability => _serviceCapability.ToArray();
    public ReadOnlyMemory<byte> ResponderDeviceId => _responderDeviceId.ToArray();
    public ReadOnlyMemory<byte> ResponderDpd1Reference => _responderDpd1Reference.ToArray();
    public ReadOnlyMemory<byte> Xps1Reference => _xps1Reference.ToArray();
    public ReadOnlyMemory<byte> Xpi1Hash => _xpi1Hash.ToArray();
    public ReadOnlyMemory<byte> ExactXpi1 => _exactXpi1.ToArray();
    public ulong ServiceGeneration { get; }
    public ulong InventoryEpoch { get; }
    public ulong ExpiresAtUnixSeconds { get; }

    internal Xpi1Record Manifest { get; }
    internal PreKeyInventoryPredecessorFacts Facts => new(
        _networkId,
        _serviceCapability,
        Manifest,
        _xpi1Hash,
        InventoryEpoch,
        ExpiresAtUnixSeconds);
}

public sealed class PreKeyPublicationReplicaTransition
{
    internal PreKeyPublicationReplicaTransition(
        PreKeyPublicationReplicaDisposition disposition,
        PreKeyPublicationReplicaState nextState,
        Xpp1BoundedRequest request,
        Xpp1Record? assembledPublication,
        bool requiresStoredReceipt)
    {
        Disposition = disposition;
        NextState = nextState;
        Request = request;
        AssembledPublication = assembledPublication;
        RequiresStoredReceipt = requiresStoredReceipt;
    }

    public PreKeyPublicationReplicaDisposition Disposition { get; }
    public PreKeyPublicationReplicaState NextState { get; }
    public Xpp1BoundedRequest Request { get; }
    public bool RequiresStoredReceipt { get; }
    public bool RequiresDurableWrite => Disposition is PreKeyPublicationReplicaDisposition.ManifestAccepted or
        PreKeyPublicationReplicaDisposition.ChunkAccepted or PreKeyPublicationReplicaDisposition.ReadyToVerify or
        PreKeyPublicationReplicaDisposition.ForkLatched;
    public bool ActivatesInventory => false;
    internal Xpp1Record? AssembledPublication { get; }
}

/// <summary>Non-serializable capability proving full XPI1/inventory verification before replica activation.</summary>
public sealed class VerifiedPreKeyInventoryCandidate
{
    internal VerifiedPreKeyInventoryCandidate(Xpp1Record publication)
    {
        LogicalPublication = publication;
        PublicationOperationId = publication.PublicationOperationId;
        Xpi1Hash = publication.Manifest.Xpi1Hash;
    }

    public ReadOnlyMemory<byte> PublicationOperationId { get; }
    public ReadOnlyMemory<byte> Xpi1Hash { get; }
    internal Xpp1Record LogicalPublication { get; }
}

public static partial class PreKeyInventoryPublicationVerifier
{
    /// <summary>
    /// Replica-side verification bridge. The assembled logical XPP1 remains
    /// inside Protocol and can be reached only from a complete ordered commit
    /// transition; callers receive only the non-forgeable verified candidate.
    /// </summary>
    public static ValueTask<VerifiedPreKeyInventoryCandidate> VerifyCandidateAsync(
        PreKeyPublicationReplicaTransition ready,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        VerifiedPreKeyInventoryPublication? predecessor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ready);
        if (ready.Disposition != PreKeyPublicationReplicaDisposition.ReadyToVerify ||
            ready.Request is not Xpp1CommitRequest ||
            ready.AssembledPublication is null)
        {
            throw new PreKeyInventoryPublicationVerificationException(
                "BoundedCommitNotReady",
                "Only a complete ordered XPP1 commit transition can enter candidate verification.");
        }

        return VerifyCandidateAsync(
            ready.AssembledPublication,
            placement,
            authority,
            recipientBundle,
            trustedTimeAuthority,
            predecessor,
            cancellationToken);
    }

    public static async ValueTask<VerifiedPreKeyInventoryCandidate> VerifyCandidateAsync(
        Xpp1Record publication,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        VerifiedPreKeyInventoryPublication? predecessor,
        CancellationToken cancellationToken)
        => await VerifyCandidateCoreAsync(
            publication,
            placement,
            authority,
            recipientBundle,
            trustedTimeAuthority,
            PreKeyInventoryPredecessorFacts.From(predecessor),
            cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Verifies an epoch successor against the exact lineage retained by the
    /// replica itself; no client-side two-receipt publication handback is
    /// required after activation or restart.
    /// </summary>
    public static ValueTask<VerifiedPreKeyInventoryCandidate> VerifySuccessorCandidateAsync(
        PreKeyPublicationReplicaTransition ready,
        VerifiedPreKeyInventoryReplicaLineage predecessor,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ready);
        ArgumentNullException.ThrowIfNull(predecessor);
        if (ready.Disposition != PreKeyPublicationReplicaDisposition.ReadyToVerify ||
            ready.Request is not Xpp1CommitRequest ||
            ready.AssembledPublication is null)
        {
            throw new PreKeyInventoryPublicationVerificationException(
                "BoundedCommitNotReady",
                "Only a complete ordered XPP1 commit transition can enter successor verification.");
        }

        return VerifyCandidateCoreAsync(
            ready.AssembledPublication,
            placement,
            authority,
            recipientBundle,
            trustedTimeAuthority,
            predecessor.Facts,
            cancellationToken);
    }

    public static ValueTask<VerifiedPreKeyInventoryCandidate> VerifyCandidateAsync(
        PreKeyPublicationReplicaTransition ready,
        VerifiedPreKeyInventoryReplicaLineage predecessor,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken) =>
        VerifySuccessorCandidateAsync(
            ready,
            predecessor,
            placement,
            authority,
            recipientBundle,
            trustedTimeAuthority,
            cancellationToken);

    public static VerifiedPreKeyInventoryReplicaLineage RestoreReplicaLineage(
        ReadOnlySpan<byte> exactXpi1,
        ReadOnlySpan<byte> expectedXpi1Hash32,
        VerifiedContactNetworkAuthority authority,
        VerifiedContactBundleClosure recipientBundle)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(recipientBundle);
        if (expectedXpi1Hash32.Length != 32 || PreKeyInventoryWire.IsZero(expectedXpi1Hash32))
            throw new ArgumentException("The persisted XPI1 hash must be nonzero 32 bytes.", nameof(expectedXpi1Hash32));
        try
        {
            var manifest = Xpi1Codec.Decode(exactXpi1);
            if (!manifest.CanonicalBytes.Span.SequenceEqual(exactXpi1) ||
                !CryptographicOperations.FixedTimeEquals(manifest.Xpi1Hash.Span, expectedXpi1Hash32))
                Fail("ReplicaLineageHashMismatch", "The persisted replica lineage changed its exact XPI1 bytes or hash.");

            var xps1 = FindRecipientXps1(recipientBundle, authority);
            var xpsHash = SHA256.HashData(xps1.CanonicalBytes);
            var xpsReference = new byte[38];
            "XPS1"u8.CopyTo(xpsReference);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(xpsReference.AsSpan(4), 1);
            xpsHash.CopyTo(xpsReference, 6);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(manifest.NetworkId.Span, authority.NetworkId.Span) ||
                    !CryptographicOperations.FixedTimeEquals(manifest.ServiceCapability.Span, xps1.ServiceCapability) ||
                    !CryptographicOperations.FixedTimeEquals(manifest.ResponderDeviceId.Span, authority.RecipientDeviceId.Span) ||
                    !CryptographicOperations.FixedTimeEquals(manifest.ResponderDpd1Reference.Span, authority.RecipientDpd1Reference.Span) ||
                    manifest.ServiceGeneration != xps1.ServiceGeneration ||
                    !CryptographicOperations.FixedTimeEquals(manifest.Xps1Reference.Span, xpsReference) ||
                    !CryptographicOperations.FixedTimeEquals(manifest.CurrentDmd1Hash.Span, authority.RecipientDmd1HashSpan) ||
                    !MatchesApplicationArtifactReference(
                        manifest.CurrentDrs1Reference.Span,
                        ProtocolMagic.DRS1,
                        authority.RecipientDrs1ReferenceSpan))
                    Fail("ReplicaLineageAuthorityMismatch", "The persisted XPI1 is not bound to the exact current service and device authority.");
                ContactCodec.VerifyDeviceSignature(manifest.Record, authority.RecipientDeviceSigningPublicKeySpan);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(xpsHash);
                CryptographicOperations.ZeroMemory(xpsReference);
            }
            return new VerifiedPreKeyInventoryReplicaLineage(manifest);
        }
        catch (PreKeyInventoryPublicationVerificationException) { throw; }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException)
        {
            throw Error(
                "InvalidReplicaLineage",
                "The persisted replica predecessor lineage could not be restored.",
                exception);
        }
    }

    private static async ValueTask<VerifiedPreKeyInventoryCandidate> VerifyCandidateCoreAsync(
        Xpp1Record publication,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        PreKeyInventoryPredecessorFacts? predecessor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publication);
        ArgumentNullException.ThrowIfNull(placement);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(recipientBundle);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var interval = VerifyTrustedTime(
                await trustedTimeAuthority.ReadCurrentAsync(cancellationToken).ConfigureAwait(false),
                publication.Manifest, placement, authority);
            var xps1 = FindRecipientXps1(recipientBundle, authority);
            VerifyPlacementAndManifest(
                publication, placement, authority, recipientBundle, xps1,
                predecessor, interval);
            VerifyInventory(publication, authority, xps1);
            return new VerifiedPreKeyInventoryCandidate(publication);
        }
        catch (PreKeyInventoryPublicationVerificationException) { throw; }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException or OverflowException or OnionBoundaryException)
        {
            throw Error("InvalidPreKeyInventoryCandidate", "The assembled bounded XPP1 candidate is invalid.", exception);
        }
    }

    public static async ValueTask<VerifiedPreKeyInventoryPublication> VerifyBoundedAsync(
        BoundedPreKeyInventoryPublication publication,
        IReadOnlyList<Xic1BoundedReceipt> commitReceipts,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        VerifiedPreKeyInventoryPublication? predecessor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publication);
        ArgumentNullException.ThrowIfNull(commitReceipts);
        var candidate = await VerifyCandidateAsync(
            publication.LogicalPublication, placement, authority, recipientBundle,
            trustedTimeAuthority, predecessor, cancellationToken).ConfigureAwait(false);
        var replicas = placement.ResolveSelectedReplicas();
        VerifyBoundedCommitReceipts(publication.CommitRequest, commitReceipts, replicas);
        return new VerifiedPreKeyInventoryPublication(
            candidate.LogicalPublication, candidate.LogicalPublication.Manifest.Xpi1Hash.Span, replicas);
    }

    private static void VerifyBoundedCommitReceipts(
        Xpp1CommitRequest request,
        IReadOnlyList<Xic1BoundedReceipt> receipts,
        IReadOnlyList<VerifiedNetworkNode> selectedReplicas)
    {
        if (receipts.Count != 2 || selectedReplicas.Count != 2)
            Fail("ReplicaSetMismatch", "Bounded XPP1 activation requires two exact final XIC1 receipts.");
        var replicas = selectedReplicas.OrderBy(static value => value.NodeId, ByteArrayComparer.Instance).ToArray();
        var ordered = receipts.OrderBy(static value => value.ReplicaId.ToArray(), ByteArrayComparer.Instance).ToArray();
        if (CryptographicOperations.FixedTimeEquals(replicas[0].NodeId, replicas[1].NodeId) ||
            CryptographicOperations.FixedTimeEquals(replicas[0].FailureDomainHash, replicas[1].FailureDomainHash))
            Fail("ReplicaDiversityInvalid", "Bounded XPP1 replicas must have distinct identities and failure domains.");
        var expectedStateHash = Xic1BoundedCodec.ComputeActivatedStateHash(request);
        try
        {
            for (var index = 0; index < 2; index++)
            {
                var receipt = ordered[index];
                var replica = replicas[index];
                Xic1BoundedCodec.ValidateFields(
                    Enumerable.Range(1, 14).Select(tag => receipt.FieldSpan(tag).ToArray()).ToArray(), request);
                if (receipt.Phase != Xpp1BoundedPhase.Commit ||
                    receipt.Status is not (Xic1BoundedStatus.Committed or Xic1BoundedStatus.ExactReplay) ||
                    receipt.MutationOutcome != Xic1BoundedMutationOutcome.DurablyActivated ||
                    !CryptographicOperations.FixedTimeEquals(receipt.ReplicaId.Span, replica.NodeId) ||
                    !CryptographicOperations.FixedTimeEquals(receipt.ReplicaStateHash.Span, expectedStateHash) ||
                    receipt.ReceiptAtUnixSeconds < request.IssuedAtUnixSeconds ||
                    receipt.ReceiptAtUnixSeconds >= request.ExpiresAtUnixSeconds ||
                    replica.IdentityPublicKey is not { Length: 32 })
                    Fail("BoundedInventoryReceiptBindingMismatch", "A final XIC1 receipt does not prove exact bounded activation.");
                var input = Xic1BoundedCodec.SignatureInput(receipt);
                try
                {
                    if (!PublicKeyAuth.VerifyDetached(receipt.ReplicaSignature.ToArray(), input, replica.IdentityPublicKey))
                        Fail("BoundedInventoryReceiptSignatureInvalid", "A final XIC1 signature is invalid.");
                }
                finally { CryptographicOperations.ZeroMemory(input); }
            }
        }
        finally { CryptographicOperations.ZeroMemory(expectedStateHash); }
    }
}
