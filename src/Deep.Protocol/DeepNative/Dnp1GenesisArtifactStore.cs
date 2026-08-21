using System.Buffers.Binary;
using Sodium;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisArtifactStoreRequest
{
    private readonly byte[] _scope;
    private readonly ReadOnlyMemory<byte>[] _artifacts;

    internal GenesisArtifactStoreRequest(
        ReadOnlySpan<byte> exactScope122,
        IReadOnlyList<ReadOnlyMemory<byte>> artifacts)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        if (exactScope122.Length != 122 || artifacts.Count != 7)
            Invalid("The genesis artifact-store request is not exact.");
        _scope = exactScope122.ToArray();
        _artifacts = artifacts.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
    }

    public ReadOnlyMemory<byte> ExactScope => _scope.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> CanonicalArtifacts =>
        Array.AsReadOnly(_artifacts.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray());

    internal ReadOnlySpan<byte> TrustedScope => _scope;
    internal IReadOnlyList<ReadOnlyMemory<byte>> TrustedArtifacts => _artifacts;

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisArtifactStoreReadResult
{
    private readonly byte[] _receipt;
    private readonly ReadOnlyMemory<byte>[] _artifacts;

    public GenesisArtifactStoreReadResult(
        ReadOnlySpan<byte> canonicalGas285,
        IReadOnlyList<ReadOnlyMemory<byte>> canonicalArtifacts,
        ulong sourceRevision,
        bool healthy)
    {
        ArgumentNullException.ThrowIfNull(canonicalArtifacts);
        _receipt = canonicalGas285.ToArray();
        _artifacts = canonicalArtifacts.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
        SourceRevision = sourceRevision;
        Healthy = healthy;
    }

    public ReadOnlyMemory<byte> CanonicalReceipt => _receipt.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> CanonicalArtifacts =>
        Array.AsReadOnly(_artifacts.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    public ulong SourceRevision { get; }
    public bool Healthy { get; }
}

public abstract class GenesisArtifactStore
{
    public abstract ValueTask<GenesisArtifactStoreReadResult> StoreOrRestoreAsync(
        GenesisArtifactStoreRequest request,
        CancellationToken cancellationToken);

    public virtual ValueTask<GenesisArtifactStoreReadResult> RestoreByScopeAsync(
        GenesisArtifactStoreLookupRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("This store does not support scope-only restore.");
}

public sealed class GenesisArtifactStoreLookupRequest
{
    private readonly byte[] _scope;
    internal GenesisArtifactStoreLookupRequest(ReadOnlySpan<byte> exactAuthorScope122)
    {
        if (exactAuthorScope122.Length != 122)
            throw new RecordException(RecordError.InvalidField,
                "The genesis artifact-store lookup scope is invalid.");
        _scope = exactAuthorScope122.ToArray();
    }
    public ReadOnlyMemory<byte> ExactAuthorScope => _scope.ToArray();
}

public sealed class VerifiedGenesisArtifactSet
{
    private readonly ReadOnlyMemory<byte>[] _artifacts;

    internal VerifiedGenesisArtifactSet(
        GenesisArtifactSetReceipt receipt,
        GenesisArtifactStoreRequest request,
        ulong sourceRevision)
    {
        Receipt = receipt;
        _artifacts = request.TrustedArtifacts.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
        SourceRevision = sourceRevision;
    }

    public GenesisArtifactSetReceipt Receipt { get; }
    public ulong SourceRevision { get; }
    public bool NoAuthorityClaim => true;
    internal IReadOnlyList<ReadOnlyMemory<byte>> Artifacts => _artifacts;
}

internal static class GenesisArtifactSetVerifier
{
    internal static async ValueTask<VerifiedGenesisArtifactSet> StoreOrRestoreAsync(
        GenesisPreExternalCandidatePlan plan,
        GenesisIdentityContext identity,
        GenesisArtifactStore store,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (!ReferenceEquals(plan.Identity, identity))
            Invalid("The genesis artifact set combines different sealed axes.");

        var artifacts = ExactArtifacts(plan);
        var scope = AuthorScope(identity);
        var request = new GenesisArtifactStoreRequest(scope, artifacts);
        var returned = await store.StoreOrRestoreAsync(request, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null || !returned.Healthy || returned.SourceRevision == 0)
            Invalid("The genesis artifact store is absent or unhealthy.");
        var receiptBytes = returned!.CanonicalReceipt.ToArray();
        var returnedArtifacts = returned.CanonicalArtifacts;
        try
        {
            GenesisProtectedRecords.PreflightGas(receiptBytes);
            if (returnedArtifacts.Count != 7 ||
                returned.SourceRevision != BinaryPrimitives.ReadUInt64BigEndian(
                    receiptBytes.AsSpan(204, 8)) ||
                !CanonicalGrammar.FixedEquals(receiptBytes.AsSpan(8, 122), scope) ||
                !CanonicalGrammar.FixedEquals(receiptBytes.AsSpan(132, 32),
                    plan.ArtifactInventoryHash.Span) ||
                !CanonicalGrammar.FixedEquals(receiptBytes.AsSpan(164, 32),
                    plan.CandidateCoreFingerprint.Span) ||
                BinaryPrimitives.ReadUInt64BigEndian(receiptBytes.AsSpan(196, 8)) != plan.TotalBytes ||
                !CanonicalGrammar.FixedEquals(receiptBytes.AsSpan(221, 32),
                    identity.ProtectedStateHmacKeyId))
                Invalid("GAS1 differs from the sealed candidate plan.");
            for (var index = 0; index < artifacts.Count; index++)
                if (!CanonicalGrammar.FixedEquals(
                        artifacts[index].Span, returnedArtifacts[index].Span))
                    Invalid("The genesis artifact store reread different bytes.");
            await GenesisProtectedRecords.VerifyAsync(
                "Deep/ProtectedState/V1/GAS1", receiptBytes,
                GenesisProtectedRecords.GasKeyOffset, hmacProvider, cancellationToken)
                .ConfigureAwait(false);
            return new VerifiedGenesisArtifactSet(
                new GenesisArtifactSetReceipt(receiptBytes), request, returned.SourceRevision);
        }
        finally
        {
            Array.Clear(scope);
            Array.Clear(receiptBytes);
        }
    }

    internal static async ValueTask<VerifiedGenesisArtifactSet> RestoreByScopeAsync(
        GenesisIdentityContext identity,
        GenesisArtifactStore store,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        var scope = AuthorScope(identity);
        var returned = await store.RestoreByScopeAsync(
            new GenesisArtifactStoreLookupRequest(scope), cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null || !returned.Healthy || returned.SourceRevision == 0)
            Invalid("The retained genesis artifact set is absent or unhealthy.");
        var receiptBytes = returned!.CanonicalReceipt.ToArray();
        var artifacts = returned.CanonicalArtifacts
            .Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
        try
        {
            GenesisProtectedRecords.PreflightGas(receiptBytes);
            if (artifacts.Length != 7 ||
                !CanonicalGrammar.FixedEquals(receiptBytes.AsSpan(8, 122), scope) ||
                returned.SourceRevision != BinaryPrimitives.ReadUInt64BigEndian(
                    receiptBytes.AsSpan(204, 8)) ||
                !CanonicalGrammar.FixedEquals(receiptBytes.AsSpan(221, 32),
                    identity.ProtectedStateHmacKeyId))
                Invalid("The retained GAS1 differs from its sealed author scope.");
            var drc = CanonicalGrammar.DecodeOwned(artifacts[0].Span, RecordDefinitions.Drc1);
            var dcps = new OwnedRecord[4];
            for (var index = 0; index < 4; index++)
                dcps[index] = CanonicalGrammar.DecodeOwned(
                    artifacts[index + 1].Span, RecordDefinitions.Dcp1);
            var dcs = CanonicalGrammar.DecodeOwned(artifacts[5].Span, RecordDefinitions.Dcs1);
            var dct = CanonicalGrammar.DecodeOwned(artifacts[6].Span, RecordDefinitions.Dct1);
            VerifyArtifactSignatures(identity, dcps, dcs, dct);
            var references = new List<byte[]> { Reference(ArtifactType.Drc1, drc) };
            references.AddRange(dcps.Select(static value => Reference(ArtifactType.Dcp1, value)));
            references.Add(Reference(ArtifactType.Dcs1, dcs));
            references.Add(Reference(ArtifactType.Dct1, dct));
            var sorted = references.OrderBy(static value => value, ByteArrayComparer.Instance).ToArray();
            var inventoryInput = new byte[2 + 7 * 38];
            BinaryPrimitives.WriteUInt16BigEndian(inventoryInput, 7);
            for (var index = 0; index < sorted.Length; index++)
                sorted[index].CopyTo(inventoryInput, 2 + index * 38);
            var inventory = CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-artifact-inventory", inventoryInput);
            var total = checked((ulong)artifacts.Sum(static value => value.Length));
            var core = RecomputeCore(identity, drc, dcps, dcs, dct, inventory, total);
            if (!CanonicalGrammar.FixedEquals(receiptBytes.AsSpan(132, 32), inventory) ||
                !CanonicalGrammar.FixedEquals(receiptBytes.AsSpan(164, 32), core) ||
                BinaryPrimitives.ReadUInt64BigEndian(receiptBytes.AsSpan(196, 8)) != total)
                Invalid("The retained genesis artifacts differ from GAS1.");
            await GenesisProtectedRecords.VerifyAsync(
                "Deep/ProtectedState/V1/GAS1", receiptBytes,
                GenesisProtectedRecords.GasKeyOffset, hmacProvider, cancellationToken)
                .ConfigureAwait(false);
            var request = new GenesisArtifactStoreRequest(scope, artifacts);
            return new VerifiedGenesisArtifactSet(
                new GenesisArtifactSetReceipt(receiptBytes), request, returned.SourceRevision);
        }
        finally
        {
            Array.Clear(scope);
            Array.Clear(receiptBytes);
        }
    }

    private static byte[] RecomputeCore(
        GenesisIdentityContext identity,
        OwnedRecord drc,
        IReadOnlyList<OwnedRecord> dcps,
        OwnedRecord dcs,
        OwnedRecord dct,
        ReadOnlySpan<byte> inventory,
        ulong total)
    {
        var dcmRef = Reference(ArtifactType.Dcm1, identity.BaseIdentity.Manifest.Record);
        var drcRef = Reference(ArtifactType.Drc1, drc);
        if (dcps.Count != 4 ||
            !CanonicalGrammar.FixedEquals(drc.FieldSpan(1), identity.BaseIdentity.Network) ||
            !CanonicalGrammar.FixedEquals(drc.FieldSpan(3), identity.Transaction.TransactionId) ||
            Scalars.UInt64(drc.FieldSpan(4)) != identity.BaseIdentity.AccountGeneration ||
            !CanonicalGrammar.FixedEquals(drc.FieldSpan(5), dcmRef))
            Invalid("The retained DRC1 differs from the genesis identity.");
        for (var index = 0; index < 4; index++)
        {
            var dcp = dcps[index];
            if (Scalars.UInt16(dcp.FieldSpan(3)) != index + 1 ||
                Scalars.UInt64(dcp.FieldSpan(4)) != 1 ||
                !CanonicalGrammar.IsZero(dcp.FieldSpan(5)) ||
                Scalars.UInt64(dcp.FieldSpan(6)) != identity.BaseIdentity.AccountGeneration ||
                !CanonicalGrammar.FixedEquals(dcp.FieldSpan(7), dcmRef) ||
                !CanonicalGrammar.FixedEquals(dcp.FieldSpan(12), identity.Transaction.TransactionId) ||
                !CanonicalGrammar.FixedEquals(dcp.FieldSpan(20), drcRef))
                Invalid("The retained DCP1 set differs from the genesis candidate.");
        }
        var dcsRef = Reference(ArtifactType.Dcs1, dcs);
        if (!CanonicalGrammar.FixedEquals(dcs.FieldSpan(1), identity.BaseIdentity.Network) ||
            !CanonicalGrammar.FixedEquals(dcs.FieldSpan(3), identity.BaseIdentity.ResetId) ||
            Scalars.UInt64(dcs.FieldSpan(2)) != identity.BaseIdentity.AccountGeneration ||
            Scalars.UInt64(dcs.FieldSpan(4)) != 1 ||
            !CanonicalGrammar.IsZero(dcs.FieldSpan(5)) ||
            !CanonicalGrammar.FixedEquals(dcs.FieldSpan(6), dcmRef) ||
            !CanonicalGrammar.FixedEquals(dcs.FieldSpan(7), identity.Transaction.TransactionId) ||
            !CanonicalGrammar.FixedEquals(dct.FieldSpan(1), identity.BaseIdentity.Network) ||
            Scalars.UInt64(dct.FieldSpan(3)) != 0 ||
            !CanonicalGrammar.IsZero(dct.FieldSpan(4)) ||
            !CanonicalGrammar.FixedEquals(dct.FieldSpan(5), dcsRef) ||
            !CanonicalGrammar.FixedEquals(dct.FieldSpan(6), identity.Transaction.TransactionId))
            Invalid("The retained DCS1/DCT1 tuple differs from genesis.");
        var input = new byte[494]; var offset = 0;
        Append(identity.BaseIdentity.Network); Append(identity.BaseIdentity.ResetId);
        U16((ushort)identity.Scope.ComponentKind); Append(identity.Scope.ComponentSubject);
        U64(identity.BaseIdentity.AccountGeneration); Append(identity.Transaction.TransactionId);
        Append(identity.Scope.ExactScope.Slice(90, 32)); Append(drc.FieldSpan(8));
        Append(drcRef);
        foreach (var dcp in dcps.OrderBy(static value => Scalars.UInt16(value.FieldSpan(3))))
            Append(Reference(ArtifactType.Dcp1, dcp));
        Append(Reference(ArtifactType.Dcs1, dcs)); Append(Reference(ArtifactType.Dct1, dct));
        U16(7); Append(inventory); U64(total);
        if (offset != input.Length) Invalid("The restored genesis candidate-core width drifted.");
        return CanonicalGrammar.Sha256Domain("Deep/Cutover/V4/genesis-author-candidate", input);
        void Append(ReadOnlySpan<byte> value)
        { value.CopyTo(input.AsSpan(offset)); offset += value.Length; }
        void U16(ushort value)
        { BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset, 2), value); offset += 2; }
        void U64(ulong value)
        { BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset, 8), value); offset += 8; }
    }

    private static void VerifyArtifactSignatures(
        GenesisIdentityContext identity,
        IReadOnlyList<OwnedRecord> dcps,
        OwnedRecord dcs,
        OwnedRecord dct)
    {
        var reset = identity.BaseIdentity.Identity.Authority
            .GetKeyAuthority(KeyScope.ResetControl);
        if (reset.IsTerminal || dcps.Count != 4)
            Invalid("A terminal or incomplete ResetControl authority cannot restore genesis artifacts.");
        for (var index = 0; index < dcps.Count; index++)
            VerifySigned(dcps[index], "Deep/Cutover/V1/component-checkpoint",
                dcps[index].FieldSpan(21), reset.CurrentEd25519PublicKey.Span,
                "retained DCP1");
        VerifySigned(dcs, "Deep/Cutover/V1/deployment-set", dcs.FieldSpan(14),
            reset.CurrentEd25519PublicKey.Span, "retained DCS1");
        VerifySigned(dct, "Deep/Cutover/V1/cas-transcript", dct.FieldSpan(11),
            reset.CurrentEd25519PublicKey.Span, "retained DCT1");
    }

    private static void VerifySigned(
        OwnedRecord record,
        string domain,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> publicKey,
        string label)
    {
        var unsigned = CanonicalGrammar.GetSigningBytes(record, domain);
        if (signature.Length != 64 || publicKey.Length != 32 ||
            !PublicKeyAuth.VerifyDetached(signature.ToArray(), unsigned, publicKey.ToArray()))
            throw new RecordException(RecordError.InvalidSignature,
                $"The {label} signature is invalid during authenticated restore.");
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> ExactArtifacts(
        GenesisPreExternalCandidatePlan plan) =>
    [
        plan.Candidate.Capsule.CanonicalBytes,
        .. plan.ComponentCheckpoints.Select(static value => value.CanonicalBytes),
        plan.DeploymentSet.CanonicalBytes,
        plan.Transaction.CanonicalBytes
    ];

    internal static byte[] AuthorScope(GenesisIdentityContext identity)
    {
        var scope = new byte[122];
        identity.BaseIdentity.Network.CopyTo(scope);
        identity.BaseIdentity.ResetId.CopyTo(scope.AsSpan(16));
        BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(48, 2),
            (ushort)identity.Scope.ComponentKind);
        identity.Scope.ComponentSubject.CopyTo(scope.AsSpan(50));
        BinaryPrimitives.WriteUInt64BigEndian(scope.AsSpan(82, 8),
            identity.BaseIdentity.AccountGeneration);
        identity.Transaction.TransactionId.CopyTo(scope.AsSpan(90));
        return scope;
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);

    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? left, byte[]? right) => left is null ? -1 : right is null ? 1 :
            left.AsSpan().SequenceCompareTo(right);
    }
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<VerifiedGenesisArtifactSet> StoreGenesisArtifactSetAsync(
        GenesisPreExternalCandidatePlan plan,
        GenesisIdentityContext identity,
        GenesisArtifactStore store,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisArtifactSetVerifier.StoreOrRestoreAsync(
            plan, identity, store, hmacProvider, cancellationToken).ConfigureAwait(false);

    public static async ValueTask<VerifiedGenesisArtifactSet> RestoreGenesisArtifactSetByScopeAsync(
        GenesisIdentityContext identity,
        GenesisArtifactStore store,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisArtifactSetVerifier.RestoreByScopeAsync(
            identity, store, hmacProvider, cancellationToken).ConfigureAwait(false);
}
