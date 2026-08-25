using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisManifestCommitRequest
{
    private readonly byte[] _gdi;
    private readonly byte[] _dcm;
    private readonly byte[] _authorSetHash;
    private readonly byte[] _branchTranscript;
    private readonly byte[] _gra;
    private readonly byte[] _dra;
    internal GenesisManifestCommitRequest(ReadOnlySpan<byte> gdi, ReadOnlySpan<byte> dcm,
        ReadOnlySpan<byte> authorSetHash, ReadOnlySpan<byte> branchTranscript,
        ReadOnlySpan<byte> gra = default, ReadOnlySpan<byte> dra = default)
    {
        _gdi = gdi.ToArray(); _dcm = dcm.ToArray(); _authorSetHash = authorSetHash.ToArray();
        _branchTranscript = branchTranscript.ToArray();
        _gra = gra.ToArray(); _dra = dra.ToArray();
    }
    public ReadOnlyMemory<byte> SignedGdi => _gdi.ToArray();
    public ReadOnlyMemory<byte> SignedDcm => _dcm.ToArray();
    public ReadOnlyMemory<byte> AuthorSetHash => _authorSetHash.ToArray();
    public ReadOnlyMemory<byte> VerifiedBranchTranscript => _branchTranscript.ToArray();
    public ReadOnlyMemory<byte> SignedGra => _gra.ToArray();
    public ReadOnlyMemory<byte> SignedDra => _dra.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisManifestDistributionReadResult
{
    private readonly byte[] _gmd;
    public GenesisManifestDistributionReadResult(ReadOnlySpan<byte> exactGmd447, bool healthy)
    { _gmd = exactGmd447.ToArray(); Healthy = healthy; }
    public ReadOnlyMemory<byte> ExactGmd => _gmd.ToArray();
    public bool Healthy { get; }
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisManifestDeliveryAdvanceRequest
{
    private readonly byte[] _gmd;
    internal GenesisManifestDeliveryAdvanceRequest(ReadOnlySpan<byte> gmd,
        ComponentKind componentKind, ulong componentSourceRevision)
    { _gmd = gmd.ToArray(); ComponentKind = componentKind; ComponentSourceRevision = componentSourceRevision; }
    public ReadOnlyMemory<byte> CurrentGmd => _gmd.ToArray();
    public ComponentKind ComponentKind { get; }
    public ulong ComponentSourceRevision { get; }
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisManifestDistributionCompleteRequest
{
    private readonly byte[] _gmd;
    internal GenesisManifestDistributionCompleteRequest(ReadOnlySpan<byte> gmd) => _gmd = gmd.ToArray();
    public ReadOnlyMemory<byte> CurrentGmd => _gmd.ToArray();
    public bool NoAuthorityClaim => true;
}

public abstract class GenesisManifestDistributionProvider
{
    public abstract ValueTask<GenesisManifestDistributionReadResult> CommitBranchAndCreateAsync(
        GenesisManifestCommitRequest request, CancellationToken cancellationToken);
    public abstract ValueTask<GenesisManifestDistributionReadResult> AdvanceDeliveryAsync(
        GenesisManifestDeliveryAdvanceRequest request, CancellationToken cancellationToken);
    public abstract ValueTask<GenesisManifestDistributionReadResult> CompleteDistributedAsync(
        GenesisManifestDistributionCompleteRequest request, CancellationToken cancellationToken);
}

public sealed class GenesisComponentManifestRequest
{
    private readonly byte[] _dcm;
    private readonly byte[] _dra;
    internal GenesisComponentManifestRequest(ComponentKind kind, ReadOnlySpan<byte> dcm,
        ReadOnlySpan<byte> dra = default)
    { ComponentKind = kind; _dcm = dcm.ToArray(); _dra = dra.ToArray(); }
    public ComponentKind ComponentKind { get; }
    public ReadOnlyMemory<byte> SignedDcm => _dcm.ToArray();
    public ReadOnlyMemory<byte> SignedDra => _dra.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisComponentManifestResult
{
    public GenesisComponentManifestResult(ulong sourceRevision, bool exactTuplePresent, bool healthy)
    { SourceRevision = sourceRevision; ExactTuplePresent = exactTuplePresent; Healthy = healthy; }
    public ulong SourceRevision { get; }
    public bool ExactTuplePresent { get; }
    public bool Healthy { get; }
    public bool NoAuthorityClaim => true;
}

public abstract class GenesisComponentManifestDistributor
{
    public abstract ValueTask<GenesisComponentManifestResult> DeliverAsync(
        GenesisComponentManifestRequest request, CancellationToken cancellationToken);
    public abstract ValueTask<GenesisComponentManifestResult> RereadAsync(
        GenesisComponentManifestRequest request, CancellationToken cancellationToken);
}

public sealed class GenesisDistributedCutoverManifestPlan
{
    private readonly byte[] _gmd;
    internal GenesisDistributedCutoverManifestPlan(GenesisSignedCutoverManifestPlan signed,
        ReadOnlySpan<byte> gmd)
    { Signed = signed; _gmd = gmd.ToArray(); }
    public GenesisSignedCutoverManifestPlan Signed { get; }
    public ReadOnlyMemory<byte> DistributedReceipt => _gmd.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisDistributedAccountResetPlan
{
    private readonly byte[] _gmd;
    internal GenesisDistributedAccountResetPlan(GenesisSignedAccountResetPlan signed,
        ReadOnlySpan<byte> gmd)
    { Signed = signed; _gmd = gmd.ToArray(); }
    public GenesisSignedAccountResetPlan Signed { get; }
    public ReadOnlyMemory<byte> DistributedReceipt => _gmd.ToArray();
    public bool NoAuthorityClaim => true;
}

internal static class GenesisManifestDistributor
{
    internal static async ValueTask<GenesisDistributedCutoverManifestPlan> DistributeAsync(
        GenesisSignedCutoverManifestPlan signed, GenesisResetReservationProvider reservationProvider,
        GenesisManifestDistributionProvider provider,
        GenesisComponentManifestDistributor components, IProtectedHmacProvider hmacProvider,
        ulong transactionTimeUnixSeconds, CancellationToken cancellationToken)
    {
        var gmd = await DistributeCoreAsync(signed, null, reservationProvider, null, provider,
            components, hmacProvider,
            transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
        return new GenesisDistributedCutoverManifestPlan(signed, gmd);
    }

    internal static async ValueTask<GenesisDistributedAccountResetPlan> DistributeResetAsync(
        GenesisSignedAccountResetPlan reset, GenesisResetReservationProvider reservationProvider,
        AccountResetOriginProvider originProvider,
        GenesisManifestDistributionProvider provider,
        GenesisComponentManifestDistributor components, IProtectedHmacProvider hmacProvider,
        ulong transactionTimeUnixSeconds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reset); ArgumentNullException.ThrowIfNull(originProvider);
        await VerifyOriginAsync(reset, originProvider, hmacProvider, transactionTimeUnixSeconds,
            cancellationToken).ConfigureAwait(false);
        var gmd = await DistributeCoreAsync(reset.SignedDcm, reset, reservationProvider, null,
            provider, components,
            hmacProvider, transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
        await VerifyOriginAsync(reset, originProvider, hmacProvider, transactionTimeUnixSeconds,
            cancellationToken).ConfigureAwait(false);
        return new GenesisDistributedAccountResetPlan(reset, gmd);
    }

    internal static async ValueTask<GenesisDistributedCutoverManifestPlan> DistributeSameAsync(
        GenesisSignedCutoverManifestPlan signed,
        GenesisSameAccountOperationProvider operationProvider,
        GenesisManifestDistributionProvider provider,
        GenesisComponentManifestDistributor components, IProtectedHmacProvider hmacProvider,
        ulong transactionTimeUnixSeconds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operationProvider);
        var gmd = await DistributeCoreAsync(signed, null, null, operationProvider, provider,
            components, hmacProvider, transactionTimeUnixSeconds, cancellationToken)
            .ConfigureAwait(false);
        return new GenesisDistributedCutoverManifestPlan(signed, gmd);
    }

    private static async ValueTask<byte[]> DistributeCoreAsync(
        GenesisSignedCutoverManifestPlan signed, GenesisSignedAccountResetPlan? reset,
        GenesisResetReservationProvider? reservationProvider,
        GenesisSameAccountOperationProvider? sameOperationProvider,
        GenesisManifestDistributionProvider provider,
        GenesisComponentManifestDistributor components, IProtectedHmacProvider hmacProvider,
        ulong transactionTimeUnixSeconds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signed);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(components); ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        var gdi = signed.ExactGdi.ToArray();
        DeploymentGovernanceRecords.PreflightGdi(gdi, transactionTimeUnixSeconds);
        if (gdi[965] != 2) Invalid("Manifest distribution requires Signed GDI1.");
        await VerifyBranchSourceAsync(signed, reservationProvider, sameOperationProvider, hmacProvider,
            cancellationToken).ConfigureAwait(false);
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GDI1", gdi,
            DeploymentGovernanceRecords.GdiKeyOffset, hmacProvider, cancellationToken).ConfigureAwait(false);
        var dcm = signed.Manifest.CanonicalBytes.ToArray();
        var gdiHash = DeploymentGovernanceRecords.SignedGdiHash(gdi);
        var gra = reset?.ExactGra.ToArray() ?? [];
        var dra = reset?.Authorization.CanonicalBytes.ToArray() ?? [];
        var graHash = reset is null ? new byte[32] : DeploymentGovernanceRecords.SignedGraHash(gra);
        var authorSet = DeploymentGovernanceRecords.AuthorSetHash(gdi[8], gdiHash, graHash);
        if (reset is not null)
            await VerifyResetAsync(reset, hmacProvider, transactionTimeUnixSeconds,
                cancellationToken).ConfigureAwait(false);
        var initial = await provider.CommitBranchAndCreateAsync(
            new GenesisManifestCommitRequest(gdi, dcm, authorSet, signed.Branch.ExactTranscript,
                gra, dra),
            cancellationToken).ConfigureAwait(false);
        var current = await VerifyAsync(initial, signed, reset, authorSet, hmacProvider,
            transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
        if (current[381] == 2)
        {
            await VerifyBranchSourceAsync(signed, reservationProvider, sameOperationProvider, hmacProvider,
                cancellationToken).ConfigureAwait(false);
            return current;
        }

        // A restored bit is evidence only after the exact component tuple is already
        // durable at the recorded revision. Validate every existing bit before allowing
        // any new delivery, so a bit-before-store/rollback row cannot trigger later writes.
        for (var index = 0; index < 4; index++)
        {
            var bit = (byte)(1 << index);
            if ((current[300] & bit) == 0) continue;
            var reread = await components.RereadAsync(
                new GenesisComponentManifestRequest((ComponentKind)(index + 1), dcm, dra),
                cancellationToken).ConfigureAwait(false);
            RequireComponent(reread, "restored-bit reread");
            var expected = BinaryPrimitives.ReadUInt64BigEndian(
                current.AsSpan(301 + index * 8, 8));
            if (reread.SourceRevision != expected)
                Invalid("A restored GMD1 bit differs from its durable component revision.");
        }

        for (var index = 0; index < 4; index++)
        {
            var bit = (byte)(1 << index);
            if ((current[300] & bit) != 0) continue;
            var kind = (ComponentKind)(index + 1);
            if (reset is not null)
                await VerifyResetAsync(reset, hmacProvider, transactionTimeUnixSeconds,
                    cancellationToken).ConfigureAwait(false);
            await VerifyBranchSourceAsync(signed, reservationProvider, sameOperationProvider, hmacProvider,
                cancellationToken).ConfigureAwait(false);
            var request = new GenesisComponentManifestRequest(kind, dcm, dra);
            var delivered = await components.DeliverAsync(request, cancellationToken).ConfigureAwait(false);
            RequireComponent(delivered, "delivery");
            var nextResult = await provider.AdvanceDeliveryAsync(
                new GenesisManifestDeliveryAdvanceRequest(current, kind, delivered.SourceRevision),
                cancellationToken).ConfigureAwait(false);
            var next = await VerifyAsync(nextResult, signed, reset, authorSet, hmacProvider,
                transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
            VerifyAdvance(current, next, index, delivered.SourceRevision);
            if (reset is not null)
                await VerifyResetAsync(reset, hmacProvider, transactionTimeUnixSeconds,
                    cancellationToken).ConfigureAwait(false);
            await VerifyBranchSourceAsync(signed, reservationProvider, sameOperationProvider, hmacProvider,
                cancellationToken).ConfigureAwait(false);
            current = next;
        }

        if (current[300] != 0x0f) Invalid("GMD1 did not commit all four delivery bits.");
        for (var index = 0; index < 4; index++)
        {
            var reread = await components.RereadAsync(
                new GenesisComponentManifestRequest((ComponentKind)(index + 1), dcm, dra),
                cancellationToken).ConfigureAwait(false);
            RequireComponent(reread, "final reread");
            var expected = BinaryPrimitives.ReadUInt64BigEndian(current.AsSpan(301 + index * 8, 8));
            if (reread.SourceRevision != expected)
                Invalid("A final component reread moved from its GMD1 revision.");
        }
        var completedResult = await provider.CompleteDistributedAsync(
            new GenesisManifestDistributionCompleteRequest(current), cancellationToken).ConfigureAwait(false);
        var completed = await VerifyAsync(completedResult, signed, reset, authorSet, hmacProvider,
            transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
        VerifyComplete(current, completed);
        await VerifyBranchSourceAsync(signed, reservationProvider, sameOperationProvider, hmacProvider,
            cancellationToken).ConfigureAwait(false);
        return completed;
    }

    private static async ValueTask<byte[]> VerifyAsync(GenesisManifestDistributionReadResult result,
        GenesisSignedCutoverManifestPlan signed, GenesisSignedAccountResetPlan? reset,
        ReadOnlyMemory<byte> authorSet,
        IProtectedHmacProvider hmacProvider, ulong now, CancellationToken cancellationToken)
    {
        if (result is null || !result.Healthy) Invalid("The GMD1 provider is absent or unhealthy.");
        var value = result!.ExactGmd.ToArray();
        DeploymentGovernanceRecords.PreflightGmd(value, now);
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GMD1", value,
            DeploymentGovernanceRecords.GmdKeyOffset, hmacProvider, cancellationToken).ConfigureAwait(false);
        var dcm = signed.Manifest.Record;
        var gdi = signed.ExactGdi.ToArray();
        var dcmRef = Reference(ArtifactType.Dcm1, dcm);
        var expectedBranch = signed.Branch.BranchKind;
        var expectedDraRef = reset is null ? new byte[38] : Reference(
            ArtifactType.Dra1, reset.Authorization.Record);
        var expectedPredecessor = expectedBranch == 2
            ? signed.Branch.CurrentCutover!.TrustedDcmRef.ToArray() : new byte[38];
        var reservation = expectedBranch == 2 ? null : signed.Reservation ??
            throw new RecordException(RecordError.InvalidField,
                "The reserved branch has no verified reset reservation.");
        var operationId = expectedBranch == 3
            ? signed.Branch.AccountResetOrigin!.OperationId.ToArray()
            : reservation is null ? gdi.AsSpan(917, 32).ToArray() : reservation.OperationId.ToArray();
        if (value[8] != expectedBranch || gdi[8] != expectedBranch ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(9, 32), signed.Branch.BranchHash) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(9, 32), gdi.AsSpan(9, 32)) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(41, 32), authorSet.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(73, 8), dcm.FieldSpan(4)) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(81, 32), signed.Branch.NewIdentity.Account.DeepAccountIdHash.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(113, 32), dcm.FieldSpan(2)) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(145, 8), dcm.FieldSpan(3)) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(153, 38), dcmRef) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(191, 38), expectedPredecessor) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(229, 38), expectedDraRef) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(267, 32), signed.Branch.Governance.DeploymentGovernanceBootstrapHash.Span) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(333, 32), operationId) ||
            !CanonicalGrammar.FixedEquals(value.AsSpan(383, 32), gdi.AsSpan(967, 32)))
            Invalid("GMD1 differs from its one verified branch and signed author set.");
        return value;
    }

    private static async ValueTask VerifyResetAsync(GenesisSignedAccountResetPlan reset,
        IProtectedHmacProvider hmacProvider, ulong now, CancellationToken cancellationToken)
    {
        var gra = reset.ExactGra.ToArray();
        DeploymentGovernanceRecords.PreflightGra(gra, now);
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GRA1", gra,
            DeploymentGovernanceRecords.GraKeyOffset, hmacProvider, cancellationToken).ConfigureAwait(false);
        var origin = reset.SignedDcm.Branch.AccountResetOrigin ?? throw new RecordException(
            RecordError.InvalidField, "The signed reset plan has no verified origin.");
        var dcmRef = Reference(ArtifactType.Dcm1, reset.SignedDcm.Manifest.Record);
        if (gra[914] != 2 ||
            !CanonicalGrammar.FixedEquals(gra.AsSpan(8, 32), origin.GarReceiptHash.Span) ||
            !CanonicalGrammar.FixedEquals(gra.AsSpan(40, 38), dcmRef) ||
            !CanonicalGrammar.FixedEquals(gra.AsSpan(78, 788), reset.Authorization.CanonicalBytes.Span) ||
            !CanonicalGrammar.FixedEquals(gra.AsSpan(866, 32), origin.OperationId.Span))
            Invalid("Signed GRA1 moved or differs from the reset author set.");
    }

    private static async ValueTask VerifyOriginAsync(GenesisSignedAccountResetPlan reset,
        AccountResetOriginProvider provider, IProtectedHmacProvider hmacProvider, ulong now,
        CancellationToken cancellationToken)
    {
        var origin = reset.SignedDcm.Branch.AccountResetOrigin ?? throw new RecordException(
            RecordError.InvalidField, "The signed reset plan has no verified origin.");
        var result = await provider.ReadAsync(origin.Request, cancellationToken)
            .ConfigureAwait(false);
        var read = result ?? throw new RecordException(RecordError.InvalidField,
            "The GAR1 provider returned no record.");
        if (!read.Healthy) Invalid("The GAR1 provider is unhealthy.");
        var gar = read.ExactGar.ToArray();
        DeploymentGovernanceRecords.PreflightGar(gar, now);
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GAR1", gar,
            DeploymentGovernanceRecords.GarKeyOffset, hmacProvider, cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(gar, origin.ExactGar.Span))
            Invalid("GAR1 or its retained reset evidence moved during distribution.");
    }

    private static async ValueTask VerifyBranchSourceAsync(GenesisSignedCutoverManifestPlan signed,
        GenesisResetReservationProvider? reservationProvider,
        GenesisSameAccountOperationProvider? sameOperationProvider,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        if (signed.Branch.BranchKind == 2)
        {
            var provider = sameOperationProvider ?? throw new RecordException(
                RecordError.InvalidField, "SameAccount distribution has no operation provider.");
            var request = new GenesisSameAccountOperationRequest(signed.Branch);
            var result = await provider.RestoreOrCreateAsync(request, cancellationToken)
                .ConfigureAwait(false);
            if (result is null || !result.Healthy || result.SourceRevision == 0 ||
                result.OperationId.Length != 32 ||
                !CanonicalGrammar.FixedEquals(result.OperationId.Span, signed.ExactGdi.Slice(917, 32)))
                Invalid("The SameAccount operation moved during distribution.");
            return;
        }
        var resetProvider = reservationProvider ?? throw new RecordException(
            RecordError.InvalidField, "The reserved manifest has no reservation provider.");
        var expected = signed.Reservation ?? throw new RecordException(
            RecordError.InvalidField, "The manifest has no reset reservation to reread.");
        var reread = await GenesisReservationVerifier.RestoreResetAsync(resetProvider,
            signed.Branch.ReservationRequest, hmacProvider, cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(reread.ReservationBytes, expected.ReservationBytes) ||
            !CanonicalGrammar.FixedEquals(reread.ReservationHash.Span,
                expected.ReservationHash.Span))
            Invalid("The reset reservation moved during manifest distribution.");
    }

    private static void VerifyAdvance(ReadOnlySpan<byte> current, ReadOnlySpan<byte> next,
        int index, ulong componentRevision)
    {
        if (componentRevision == 0 || current[381] != 1 || next[381] != 1 ||
            (current[300] & (1 << index)) != 0 || next[300] != (current[300] | (1 << index)) ||
            BinaryPrimitives.ReadUInt64BigEndian(next.Slice(301 + index * 8, 8)) != componentRevision ||
            BinaryPrimitives.ReadUInt64BigEndian(next.Slice(365, 8)) != checked(
                BinaryPrimitives.ReadUInt64BigEndian(current.Slice(365, 8)) + 1))
            Invalid("GMD1 delivery advance is not one exact bit/revision successor.");
        var expected = current.ToArray(); expected[300] = next[300];
        next.Slice(301 + index * 8, 8).CopyTo(expected.AsSpan(301 + index * 8, 8));
        next.Slice(365, 8).CopyTo(expected.AsSpan(365, 8));
        next[^32..].CopyTo(expected.AsSpan(expected.Length - 32));
        if (!CanonicalGrammar.FixedEquals(expected, next)) Invalid("GMD1 delivery advance changed immutable bytes.");
    }

    private static void VerifyComplete(ReadOnlySpan<byte> current, ReadOnlySpan<byte> complete)
    {
        if (current[381] != 1 || current[300] != 0x0f || complete[381] != 2 ||
            BinaryPrimitives.ReadUInt64BigEndian(complete.Slice(365, 8)) != checked(
                BinaryPrimitives.ReadUInt64BigEndian(current.Slice(365, 8)) + 1))
            Invalid("GMD1 Distributed transition is invalid.");
        var expected = current.ToArray(); expected[381] = 2;
        complete.Slice(365, 8).CopyTo(expected.AsSpan(365, 8));
        complete[^32..].CopyTo(expected.AsSpan(expected.Length - 32));
        if (!CanonicalGrammar.FixedEquals(expected, complete)) Invalid("GMD1 Distributed changed immutable bytes.");
    }

    private static void RequireComponent(GenesisComponentManifestResult result, string operation)
    {
        if (result is null || !result.Healthy || !result.ExactTuplePresent || result.SourceRevision == 0)
            Invalid($"A component manifest {operation} did not return the exact durable tuple.");
    }

    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisDistributedCutoverManifestPlan> VerifyDistributedCutoverManifestAsync(
        GenesisSignedCutoverManifestPlan signed, GenesisResetReservationProvider reservationProvider,
        GenesisManifestDistributionProvider provider,
        GenesisComponentManifestDistributor components, IProtectedHmacProvider hmacProvider,
        ulong transactionTimeUnixSeconds, CancellationToken cancellationToken = default) =>
        await GenesisManifestDistributor.DistributeAsync(signed, reservationProvider, provider,
            components, hmacProvider,
            transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);

    public static async ValueTask<GenesisDistributedAccountResetPlan> DistributeAccountResetAsync(
        GenesisSignedAccountResetPlan reset, GenesisResetReservationProvider reservationProvider,
        AccountResetOriginProvider originProvider,
        GenesisManifestDistributionProvider provider,
        GenesisComponentManifestDistributor components, IProtectedHmacProvider hmacProvider,
        ulong transactionTimeUnixSeconds, CancellationToken cancellationToken = default) =>
        await GenesisManifestDistributor.DistributeResetAsync(reset, reservationProvider,
            originProvider,
            provider, components,
            hmacProvider, transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);

    public static async ValueTask<GenesisDistributedCutoverManifestPlan> DistributeSameAccountAsync(
        GenesisSignedCutoverManifestPlan signed,
        GenesisSameAccountOperationProvider operationProvider,
        GenesisManifestDistributionProvider provider,
        GenesisComponentManifestDistributor components, IProtectedHmacProvider hmacProvider,
        ulong transactionTimeUnixSeconds, CancellationToken cancellationToken = default) =>
        await GenesisManifestDistributor.DistributeSameAsync(signed, operationProvider, provider,
            components, hmacProvider, transactionTimeUnixSeconds, cancellationToken)
            .ConfigureAwait(false);
}
