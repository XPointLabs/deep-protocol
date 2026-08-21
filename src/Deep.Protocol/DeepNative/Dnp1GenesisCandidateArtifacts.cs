using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisCutoverSigningRequest
{
    private readonly byte[] _signingBytes;
    private readonly byte[] _expectedPublicKey;
    internal GenesisCutoverSigningRequest(
        ArtifactType artifactType,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> expectedPublicKey)
    {
        ArtifactType = artifactType;
        _signingBytes = signingBytes.ToArray();
        _expectedPublicKey = expectedPublicKey.ToArray();
    }
    public ArtifactType ArtifactType { get; }
    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();
    public ReadOnlyMemory<byte> ExpectedEd25519PublicKey => _expectedPublicKey.ToArray();
}

public abstract class GenesisCutoverSigner
{
    public abstract ValueTask<int> SignAsync(
        GenesisCutoverSigningRequest request,
        Memory<byte> signature64,
        CancellationToken cancellationToken);
}

public sealed class GenesisPreExternalCandidatePlan
{
    private readonly ComponentCheckpoint[] _checkpoints;
    private readonly byte[] _inventoryHash;
    private readonly byte[] _coreFingerprint;
    private readonly byte[] _deploymentSubject;

    internal GenesisPreExternalCandidatePlan(
        SealedGenesisRecoveryCandidate capsule,
        GenesisIdentityContext identity,
        IReadOnlyList<ComponentCheckpoint> checkpoints,
        DeploymentSet deploymentSet,
        CasTranscript transaction,
        ReadOnlySpan<byte> inventoryHash,
        ReadOnlySpan<byte> coreFingerprint,
        ReadOnlySpan<byte> deploymentSubject,
        ulong totalBytes)
    {
        Candidate = capsule;
        Identity = identity;
        _checkpoints = checkpoints.ToArray();
        DeploymentSet = deploymentSet;
        Transaction = transaction;
        _inventoryHash = inventoryHash.ToArray();
        _coreFingerprint = coreFingerprint.ToArray();
        _deploymentSubject = deploymentSubject.ToArray();
        TotalBytes = totalBytes;
    }
    public SealedGenesisRecoveryCandidate Candidate { get; }
    internal GenesisIdentityContext Identity { get; }
    public IReadOnlyList<ComponentCheckpoint> ComponentCheckpoints =>
        Array.AsReadOnly(_checkpoints.ToArray());
    public DeploymentSet DeploymentSet { get; }
    public CasTranscript Transaction { get; }
    public ReadOnlyMemory<byte> ArtifactInventoryHash => _inventoryHash.ToArray();
    public ReadOnlyMemory<byte> CandidateCoreFingerprint => _coreFingerprint.ToArray();
    public ReadOnlyMemory<byte> DeploymentSubject => _deploymentSubject.ToArray();
    public ulong TotalBytes { get; }
    public bool NoAuthorityClaim => true;
}

internal static class GenesisCandidateArtifactAuthor
{
    internal static async ValueTask<GenesisPreExternalCandidatePlan> AuthorAsync(
        SealedGenesisRecoveryCandidate candidate,
        GenesisIdentityContext identity,
        GenesisReleaseContext release,
        GenesisResetReservationResult reservation,
        GenesisCutoverSigner signer,
        ReadOnlyMemory<byte> requestNonce32,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(reservation);
        ArgumentNullException.ThrowIfNull(signer);
        if (requestNonce32.Length != 32 || CanonicalGrammar.IsZero(requestNonce32.Span) ||
            issuedAtUnixSeconds == 0 || expiresAtUnixSeconds <= issuedAtUnixSeconds ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, reservation.ResetId) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.Network, release.Network) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, release.ResetId))
            Invalid("The genesis pre-external authoring axes are invalid.");
        var drc = candidate.Capsule.Record;
        if (!CanonicalGrammar.FixedEquals(drc.FieldSpan(1), identity.BaseIdentity.Network) ||
            !CanonicalGrammar.FixedEquals(drc.FieldSpan(3), identity.Transaction.TransactionId) ||
            Scalars.UInt64(drc.FieldSpan(4)) != identity.BaseIdentity.AccountGeneration ||
            !CanonicalGrammar.FixedEquals(drc.FieldSpan(5), Reference(
                ArtifactType.Dcm1, identity.BaseIdentity.Manifest.Record)) ||
            !CanonicalGrammar.FixedEquals(drc.FieldSpan(6), Reference(
                ArtifactType.Drs1, identity.BaseIdentity.Identity.Revocations.Snapshot.Record)))
            Invalid("The sealed DRC1 differs from the genesis identity before signing.");
        var reset = identity.BaseIdentity.Identity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        if (reset.IsTerminal) Invalid("A terminal ResetControl role cannot sign genesis artifacts.");
        var dcm = identity.BaseIdentity.Manifest.Record;
        var drs = identity.BaseIdentity.Identity.Revocations.Snapshot.Record;
        var dcmRef = Reference(ArtifactType.Dcm1, dcm);
        var drsRef = Reference(ArtifactType.Drs1, drs);
        var drcRef = Reference(ArtifactType.Drc1, drc);
        var checkpoints = new ComponentCheckpoint[4];
        var checkpointRefs = new byte[4][];
        for (var index = 0; index < 4; index++)
        {
            var kind = (ComponentKind)(index + 1);
            var subject = GenesisTransactionScopeContext.ComputeComponentSubject(
                identity.BaseIdentity, kind);
            var schema = dcm.FieldSpan(15).Slice(index * 42, 42);
            var fields = Empty(RecordDefinitions.Dcp1);
            fields[0] = identity.BaseIdentity.Network.ToArray(); fields[1] = subject;
            fields[2] = U16((ushort)kind); fields[3] = U64(1); fields[4] = new byte[38];
            fields[5] = U64(identity.BaseIdentity.AccountGeneration); fields[6] = dcmRef;
            fields[7] = U64(Scalars.UInt64(drs.FieldSpan(4)));
            fields[8] = U64(Scalars.UInt16(drs.FieldSpan(9))); fields[9] = drs.FieldSpan(11).ToArray();
            fields[10] = drsRef; fields[11] = identity.Transaction.TransactionId.ToArray();
            fields[12] = U64(issuedAtUnixSeconds); fields[13] = U64(expiresAtUnixSeconds);
            fields[14] = release.LatestDwdReference.ToArray(); fields[15] = U64(release.LatestWitnessEpoch);
            fields[16] = schema.Slice(10, 32).ToArray(); fields[17] = new byte[38];
            fields[18] = dcm.FieldSpan(11).ToArray(); fields[19] = drcRef;
            fields[20] = await SignAsync(ArtifactType.Dcp1, RecordDefinitions.Dcp1, fields,
                "Deep/Cutover/V1/component-checkpoint", reset.CurrentEd25519PublicKey,
                signer, cancellationToken).ConfigureAwait(false);
            var canonical = CanonicalGrammar.Encode(RecordDefinitions.Dcp1, Memories(fields));
            var record = CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dcp1);
            checkpoints[index] = new ComponentCheckpoint(record);
            checkpointRefs[index] = Reference(ArtifactType.Dcp1, record);
        }

        var dcsFields = Empty(RecordDefinitions.Dcs1);
        dcsFields[0] = identity.BaseIdentity.Network.ToArray();
        dcsFields[1] = U64(identity.BaseIdentity.AccountGeneration);
        dcsFields[2] = identity.BaseIdentity.ResetId.ToArray(); dcsFields[3] = U64(1);
        dcsFields[4] = new byte[38]; dcsFields[5] = dcmRef;
        dcsFields[6] = identity.Transaction.TransactionId.ToArray();
        dcsFields[7] = release.LatestDwdReference.ToArray(); dcsFields[8] = U64(release.LatestWitnessEpoch);
        dcsFields[9] = [4]; var componentRows = new byte[416];
        for (var index = 0; index < 4; index++)
        {
            var row = componentRows.AsSpan(index * 104, 104);
            BinaryPrimitives.WriteUInt16BigEndian(row, checked((ushort)(index + 1)));
            checkpoints[index].ComponentSubject.Span.CopyTo(row.Slice(2, 32));
            checkpointRefs[index].CopyTo(row.Slice(34, 38));
            dcm.FieldSpan(15).Slice(index * 42 + 10, 32).CopyTo(row.Slice(72, 32));
        }
        dcsFields[10] = componentRows; dcsFields[11] = U64(issuedAtUnixSeconds);
        dcsFields[12] = U64(expiresAtUnixSeconds);
        dcsFields[13] = await SignAsync(ArtifactType.Dcs1, RecordDefinitions.Dcs1, dcsFields,
            "Deep/Cutover/V1/deployment-set", reset.CurrentEd25519PublicKey,
            signer, cancellationToken).ConfigureAwait(false);
        var dcsRecord = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dcs1, Memories(dcsFields)), RecordDefinitions.Dcs1);
        var deployment = new DeploymentSet(dcsRecord); var dcsRef = Reference(ArtifactType.Dcs1, dcsRecord);

        Span<byte> deploymentInput = stackalloc byte[80];
        identity.BaseIdentity.Network.CopyTo(deploymentInput[..16]);
        identity.BaseIdentity.AccountHash.CopyTo(deploymentInput.Slice(16,32));
        identity.BaseIdentity.ResetId.CopyTo(deploymentInput.Slice(48,32));
        var deploymentSubject = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/deployment-subject", deploymentInput);
        var dctFields = Empty(RecordDefinitions.Dct1);
        dctFields[0] = identity.BaseIdentity.Network.ToArray(); dctFields[1] = deploymentSubject;
        dctFields[2] = U64(0); dctFields[3] = new byte[38]; dctFields[4] = dcsRef;
        dctFields[5] = identity.Transaction.TransactionId.ToArray(); dctFields[6] = requestNonce32.ToArray();
        dctFields[7] = U64(issuedAtUnixSeconds); dctFields[8] = U64(expiresAtUnixSeconds);
        dctFields[9] = release.LatestDwdReference.ToArray();
        dctFields[10] = await SignAsync(ArtifactType.Dct1, RecordDefinitions.Dct1, dctFields,
            "Deep/Cutover/V1/cas-transcript", reset.CurrentEd25519PublicKey,
            signer, cancellationToken).ConfigureAwait(false);
        var dctRecord = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dct1, Memories(dctFields)), RecordDefinitions.Dct1);
        var transaction = new CasTranscript(dctRecord); var dctRef = Reference(ArtifactType.Dct1, dctRecord);

        var references = new List<byte[]> { drcRef };
        references.AddRange(checkpointRefs);
        references.Add(dcsRef);
        references.Add(dctRef);
        var sorted = references.OrderBy(static value => value, ByteArrayComparer.Instance).ToArray();
        var inventoryInput = new byte[2 + 7 * 38];
        BinaryPrimitives.WriteUInt16BigEndian(inventoryInput, 7);
        for (var index = 0; index < sorted.Length; index++) sorted[index].CopyTo(inventoryInput, 2 + index * 38);
        var inventory = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-artifact-inventory", inventoryInput);
        var total = checked((ulong)(candidate.Capsule.CanonicalBytes.Length +
            checkpoints.Sum(static value => value.CanonicalBytes.Length) +
            deployment.CanonicalBytes.Length + transaction.CanonicalBytes.Length));
        var core = BuildCore(identity, reservation, candidate, drcRef, checkpointRefs,
            dcsRef, dctRef, inventory, total);
        return new GenesisPreExternalCandidatePlan(candidate, identity, checkpoints, deployment,
            transaction, inventory, core, deploymentSubject, total);
    }

    private static async ValueTask<byte[]> SignAsync(
        ArtifactType type,
        RecordDefinition definition,
        byte[][] fields,
        string domain,
        ReadOnlyMemory<byte> publicKey,
        GenesisCutoverSigner signer,
        CancellationToken cancellationToken)
    {
        var unsigned = CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(CanonicalGrammar.Encode(definition, Memories(fields)), definition), domain);
        var output = new byte[64];
        try
        {
            var written = await signer.SignAsync(new GenesisCutoverSigningRequest(
                type, unsigned, publicKey.Span), output, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (written != 64 || output.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !PublicKeyAuth.VerifyDetached(output, unsigned, publicKey.ToArray()))
                throw new RecordException(RecordError.InvalidSignature,
                    "The genesis cutover signer returned an invalid signature.");
            return output.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(output); }
    }

    private static byte[] BuildCore(
        GenesisIdentityContext identity,
        GenesisResetReservationResult reservation,
        SealedGenesisRecoveryCandidate candidate,
        ReadOnlySpan<byte> drcRef,
        IReadOnlyList<byte[]> dcpRefs,
        ReadOnlySpan<byte> dcsRef,
        ReadOnlySpan<byte> dctRef,
        ReadOnlySpan<byte> inventory,
        ulong total)
    {
        var input = new byte[494]; var offset = 0;
        Append(identity.BaseIdentity.Network); Append(identity.BaseIdentity.ResetId);
        U16((ushort)identity.Scope.ComponentKind); Append(identity.Scope.ComponentSubject);
        U64(identity.BaseIdentity.AccountGeneration); Append(identity.Transaction.TransactionId);
        Append(reservation.ReservationHash.Span); Append(candidate.ShadowStateHash.Span);
        Append(drcRef); foreach (var reference in dcpRefs) Append(reference);
        Append(dcsRef); Append(dctRef); U16(7); Append(inventory); U64(total);
        if (offset != input.Length) Invalid("The genesis candidate-core width drifted.");
        return CanonicalGrammar.Sha256Domain("Deep/Cutover/V4/genesis-author-candidate", input);
        void Append(ReadOnlySpan<byte> value) { value.CopyTo(input.AsSpan(offset)); offset += value.Length; }
        void U16(ushort value) { BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset,2),value); offset += 2; }
        void U64(ulong value) { BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset,8),value); offset += 8; }
    }

    private static byte[][] Empty(RecordDefinition definition) => definition.Fields
        .Select(static field => new byte[field.MinimumLength]).ToArray();
    private static IReadOnlyList<ReadOnlyMemory<byte>> Memories(byte[][] fields) =>
        fields.Select(static value => (ReadOnlyMemory<byte>)value).ToArray();
    private static byte[] U16(ushort value) { var output = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(output,value); return output; }
    private static byte[] U64(ulong value) { var output = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(output,value); return output; }
    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? left, byte[]? right) => left is null ? -1 : right is null ? 1 :
            left.AsSpan().SequenceCompareTo(right);
    }
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisPreExternalCandidatePlan> AuthorGenesisPreExternalArtifactsAsync(
        SealedGenesisRecoveryCandidate candidate,
        GenesisIdentityContext identity,
        GenesisReleaseContext release,
        GenesisResetReservationResult reservation,
        GenesisCutoverSigner signer,
        ReadOnlyMemory<byte> requestNonce32,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken = default) =>
        await GenesisCandidateArtifactAuthor.AuthorAsync(candidate, identity, release, reservation,
            signer, requestNonce32, issuedAtUnixSeconds, expiresAtUnixSeconds,
            cancellationToken).ConfigureAwait(false);
}
