using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

public sealed class VerifiedGenesisBaseIdentityContext
{
    internal VerifiedGenesisBaseIdentityContext(
        VerifiedIdentityRelative identity,
        VerifiedDeviceRelative device,
        VerifiedMailboxRelative mailbox,
        VerifiedGenesisRouterRelative router,
        GenesisSignedCutoverManifestPlan signedManifest,
        ReadOnlySpan<byte> exactDistributedGmd447)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(mailbox);
        ArgumentNullException.ThrowIfNull(router);
        ArgumentNullException.ThrowIfNull(signedManifest);
        DeploymentGovernanceRecords.PreflightGmd(exactDistributedGmd447, 0);
        if (exactDistributedGmd447[381] != 2 ||
            !ReferenceEquals(signedManifest.Branch.NewIdentity, identity) ||
            !CanonicalGrammar.FixedEquals(exactDistributedGmd447.Slice(153, 38),
                Reference(ArtifactType.Dcm1, signedManifest.Manifest.Record)) ||
            !CanonicalGrammar.FixedEquals(exactDistributedGmd447.Slice(9, 32),
                signedManifest.Branch.BranchHash) ||
            !CanonicalGrammar.FixedEquals(exactDistributedGmd447.Slice(267, 32),
                signedManifest.Branch.Governance.DeploymentGovernanceBootstrapHash.Span))
            Invalid("The genesis base identity requires one exact Distributed GMD1 branch.");
        if (identity.IsTerminal || identity.ForkLatched ||
            !ReferenceEquals(device.Identity, identity) ||
            !ReferenceEquals(mailbox.Device, device) ||
            !ReferenceEquals(router.Mailbox, mailbox))
            Invalid("The genesis base identity combines unrelated or unusable facts.");
        var manifest = signedManifest.Manifest;
        var dcm = manifest.Record;
        var account = identity.Account;
        var drs = identity.Revocations.Snapshot;
        if (!CanonicalGrammar.FixedEquals(dcm.FieldSpan(1), account.Certificate.NetworkId.Span) ||
            !CanonicalGrammar.FixedEquals(dcm.FieldSpan(1), drs.NetworkId.Span) ||
            !CanonicalGrammar.FixedEquals(dcm.FieldSpan(5), Reference(
                ArtifactType.Dpa1, account.Certificate.Record)) ||
            Scalars.UInt64(dcm.FieldSpan(4)) != account.Certificate.AccountGeneration ||
            Scalars.UInt64(dcm.FieldSpan(6)) != drs.Revision ||
            Scalars.UInt64(dcm.FieldSpan(7)) != drs.EntryCount ||
            !CanonicalGrammar.FixedEquals(dcm.FieldSpan(8), drs.CurrentHead.Span) ||
            !CanonicalGrammar.FixedEquals(dcm.FieldSpan(9), Reference(
                ArtifactType.Drs1, drs.Record)) ||
            CanonicalGrammar.IsZero(dcm.FieldSpan(2)))
            Invalid("The signed DCM1 differs from the current DPA1/DRS1 identity.");
        var reset = identity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        if (reset.IsTerminal || Scalars.UInt64(dcm.FieldSpan(10)) != reset.Generation ||
            !CanonicalGrammar.FixedEquals(dcm.FieldSpan(11),
                SHA256.HashData(reset.CurrentEd25519PublicKey.Span)) ||
            (reset.Generation == 0
                ? !CanonicalGrammar.IsZero(dcm.FieldSpan(12))
                : !CanonicalGrammar.FixedEquals(dcm.FieldSpan(12),
                    CanonicalGrammar.EncodeReference(reset.TransitionReference))))
            Invalid("The DCM1 ResetControl binding is not the current nonterminal role.");
        foreach (var scope in new[]
                 { KeyScope.DeviceCertificateIssuer, KeyScope.AccountRevocation, KeyScope.ResetControl })
            if (identity.Authority.GetKeyAuthority(scope).IsTerminal)
                Invalid("Genesis authoring cannot use a terminal account role.");
        var components = dcm.FieldSpan(15);
        if (components.Length != 168) Invalid("DCM1 component schema table is malformed.");
        for (var index = 0; index < 4; index++)
        {
            var row = components.Slice(index * 42, 42);
            if (BinaryPrimitives.ReadUInt16BigEndian(row[..2]) != index + 1 ||
                BinaryPrimitives.ReadUInt64BigEndian(row.Slice(2, 8)) == 0 ||
                CanonicalGrammar.IsZero(row.Slice(10, 32)))
                Invalid("DCM1 component schemas are not exact kinds 1 through 4.");
        }
        Identity = identity;
        Device = device;
        Mailbox = mailbox;
        Router = router;
        Manifest = manifest;
    }

    internal VerifiedIdentityRelative Identity { get; }
    internal VerifiedDeviceRelative Device { get; }
    internal VerifiedMailboxRelative Mailbox { get; }
    internal VerifiedGenesisRouterRelative Router { get; }
    internal CutoverManifest Manifest { get; }
    internal ReadOnlySpan<byte> Network => Manifest.Record.FieldSpan(1);
    internal ReadOnlySpan<byte> ResetId => Manifest.Record.FieldSpan(2);
    internal ulong AccountGeneration => Scalars.UInt64(Manifest.Record.FieldSpan(4));
    internal ReadOnlySpan<byte> AccountHash => Identity.Account.DeepAccountIdHash.Span;
    internal IReadOnlyList<(ArtifactType Type, ReadOnlyMemory<byte> Canonical)> RecoveryRows
    {
        get
        {
            var rows = new List<(ArtifactType, ReadOnlyMemory<byte>)>
            {
                (ArtifactType.Dpa1, Identity.Account.Certificate.CanonicalBytes),
                (ArtifactType.Dpd1, Device.Certificate.CanonicalBytes),
                (ArtifactType.Dpm1, Mailbox.Certificate.CanonicalBytes),
                (ArtifactType.Dnr1, Router.Certificate.CanonicalBytes),
                (ArtifactType.Pma1, Router.PmaCanonical.ToArray()),
                (ArtifactType.Pmr1, Router.PmrCanonical.ToArray()),
                (ArtifactType.Dcm1, Manifest.CanonicalBytes),
                (ArtifactType.Drs1, Identity.Revocations.Snapshot.CanonicalBytes)
            };
            foreach (var canonical in Identity.Authority.OrderedTransitionCanonicals)
            {
                var bytes = canonical.ToArray();
                var type = bytes.Length == 412 ? ArtifactType.Krt1 : ArtifactType.Krf1;
                var definition = type == ArtifactType.Krt1
                    ? RecordDefinitions.Krt1 : RecordDefinitions.Krf1;
                var transition = CanonicalGrammar.DecodeOwned(bytes, definition);
                if (transition.FieldSpan(2)[0] == (byte)KeyScope.ReleaseRoot)
                    continue;
                rows.Add((type, bytes));
            }
            return rows;
        }
    }
    public bool NoAuthorityClaim => true;

    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisTransactionScopeContext
{
    private readonly byte[] _scope;
    internal readonly VerifiedGenesisBaseIdentityContext BaseIdentity;
    internal readonly GenesisReleaseContext Release;
    internal readonly GenesisResetReservationResult Reservation;

    internal GenesisTransactionScopeContext(
        VerifiedGenesisBaseIdentityContext identity,
        GenesisReleaseContext release,
        GenesisResetReservationResult reservation,
        ComponentKind componentKind)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(reservation);
        if (!Enum.IsDefined(componentKind) || componentKind == 0 ||
            !CanonicalGrammar.FixedEquals(identity.Network, release.Network) ||
            !CanonicalGrammar.FixedEquals(identity.ResetId, release.ResetId) ||
            !CanonicalGrammar.FixedEquals(identity.ResetId, reservation.ResetId))
            Invalid("The genesis transaction scope combines different authority axes.");
        var componentSubject = ComputeComponentSubject(identity, componentKind);
        _scope = new byte[122];
        identity.Network.CopyTo(_scope);
        identity.ResetId.CopyTo(_scope.AsSpan(16));
        BinaryPrimitives.WriteUInt16BigEndian(_scope.AsSpan(48, 2), (ushort)componentKind);
        componentSubject.CopyTo(_scope, 50);
        BinaryPrimitives.WriteUInt64BigEndian(_scope.AsSpan(82, 8), identity.AccountGeneration);
        reservation.ReservationHash.Span.CopyTo(_scope.AsSpan(90));
        BaseIdentity = identity;
        Release = release;
        Reservation = reservation;
    }

    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> ExactScope => _scope;
    internal ComponentKind ComponentKind =>
        (ComponentKind)BinaryPrimitives.ReadUInt16BigEndian(_scope.AsSpan(48, 2));
    internal ReadOnlySpan<byte> ComponentSubject => _scope.AsSpan(50, 32);

    internal static byte[] ComputeComponentSubject(
        VerifiedGenesisBaseIdentityContext identity,
        ComponentKind componentKind)
        => ComputeComponentSubject(
            identity.Network,
            identity.AccountHash,
            componentKind,
            identity.Identity.Account.Certificate.AccountRevocationHandle.Span);

    internal static byte[] ComputeComponentSubject(
        ReadOnlySpan<byte> network16,
        ReadOnlySpan<byte> accountHash32,
        ComponentKind componentKind,
        ReadOnlySpan<byte> accountRevocationHandle32)
    {
        if (network16.Length != 16 || accountHash32.Length != 32 ||
            accountRevocationHandle32.Length != 32 ||
            componentKind is < ComponentKind.Registry or > ComponentKind.Maui)
            throw new RecordException(RecordError.InvalidField,
                "The component-subject preimage is invalid.");
        Span<byte> input = stackalloc byte[82];
        network16.CopyTo(input[..16]);
        accountHash32.CopyTo(input[16..48]);
        BinaryPrimitives.WriteUInt16BigEndian(input[48..50], (ushort)componentKind);
        accountRevocationHandle32.CopyTo(input[50..]);
        return CanonicalGrammar.Sha256Domain("Deep/Cutover/V1/component-subject", input);
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisIdentityContext
{
    private readonly byte[] _dtc;
    private readonly byte[] _fingerprint;
    internal GenesisIdentityContext(
        VerifiedGenesisBaseIdentityContext baseIdentity,
        GenesisTransactionScopeContext scope,
        GenesisTransactionReservation transaction,
        ReadOnlySpan<byte> exactDtc,
        ReadOnlySpan<byte> fingerprint)
    {
        BaseIdentity = baseIdentity;
        Scope = scope;
        Transaction = transaction;
        _dtc = exactDtc.ToArray();
        _fingerprint = fingerprint.ToArray();
    }
    internal VerifiedGenesisBaseIdentityContext BaseIdentity { get; }
    internal GenesisTransactionScopeContext Scope { get; }
    internal GenesisTransactionReservation Transaction { get; }
    internal ReadOnlySpan<byte> DrtCatalog => _dtc;
    internal ReadOnlySpan<byte> ProtectedStateHmacKeyId => _dtc.AsSpan(_dtc.Length - 64, 32);
    public ReadOnlyMemory<byte> Fingerprint => _fingerprint.ToArray();
    public bool NoAuthorityClaim => true;
    internal bool IsCurrentProtectedStore => true;
}

public sealed class GenesisComponentIntent
{
    private readonly byte[] _schemaFingerprint;
    internal GenesisComponentIntent(GenesisIdentityContext identity)
    {
        Identity = identity;
        ComponentKind = identity.Scope.ComponentKind;
        var row = identity.BaseIdentity.Manifest.Record.FieldSpan(15)
            .Slice(((int)ComponentKind - 1) * 42, 42);
        if (BinaryPrimitives.ReadUInt16BigEndian(row[..2]) != (ushort)ComponentKind)
            Invalid("The genesis component schema kind differs from the sealed identity.");
        SchemaGeneration = BinaryPrimitives.ReadUInt64BigEndian(row.Slice(2, 8));
        _schemaFingerprint = row.Slice(10, 32).ToArray();
        ComponentSubject = identity.Scope.ComponentSubject.ToArray();
    }
    internal GenesisIdentityContext Identity { get; }
    public ComponentKind ComponentKind { get; }
    public ulong SchemaGeneration { get; }
    public ReadOnlyMemory<byte> SchemaFingerprint => _schemaFingerprint.ToArray();
    public ReadOnlyMemory<byte> ComponentSubject { get; }
    public bool NoAuthorityClaim => true;
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static VerifiedGenesisBaseIdentityContext CreateGenesisBaseIdentityContext(
        VerifiedIdentityRelative identity,
        VerifiedDeviceRelative device,
        VerifiedMailboxRelative mailbox,
        VerifiedGenesisRouterRelative router,
        GenesisDistributedCutoverManifestPlan distributedManifest) =>
        new(identity, device, mailbox, router,
            (distributedManifest ?? throw new ArgumentNullException(nameof(distributedManifest))).Signed,
            distributedManifest.DistributedReceipt.Span);

    public static VerifiedGenesisBaseIdentityContext CreateGenesisBaseIdentityContext(
        VerifiedIdentityRelative identity,
        VerifiedDeviceRelative device,
        VerifiedMailboxRelative mailbox,
        VerifiedGenesisRouterRelative router,
        GenesisDistributedAccountResetPlan distributedReset) =>
        new(identity, device, mailbox, router,
            (distributedReset ?? throw new ArgumentNullException(nameof(distributedReset)))
                .Signed.SignedDcm,
            distributedReset.DistributedReceipt.Span);

    public static GenesisTransactionScopeContext CreateGenesisTransactionScopeContext(
        VerifiedGenesisBaseIdentityContext identity,
        GenesisReleaseContext release,
        GenesisResetReservationResult reservation,
        ComponentKind componentKind) =>
        new(identity, release, reservation, componentKind);

    public static async ValueTask<GenesisTransactionReservation>
        RestoreOrReserveGenesisTransactionAsync(
            GenesisTransactionScopeContext scope,
            GenesisTransactionReservationProvider provider,
            IProtectedHmacProvider hmacProvider,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return await GenesisReservationVerifier.RestoreTransactionAsync(provider,
            new GenesisTransactionReservationRequest(scope.ExactScope), hmacProvider,
            cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<GenesisIdentityContext> AuthorGenesisIdentityContextAsync(
        GenesisTransactionScopeContext scope,
        GenesisTransactionReservation transaction,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (!CanonicalGrammar.FixedEquals(scope.ExactScope, transaction.ExactScope))
            GenesisInvalid("The genesis transaction differs from its sealed scope.");
        var baseIdentity = scope.BaseIdentity;
        var catalogEntries = baseIdentity.Identity.Revocations.Catalog.Entries;
        var facts = catalogEntries.Select((entry, index) =>
            CreateDtcTargetFact(baseIdentity, entry, index)).ToArray();
        var histories = facts.Where(static fact => fact.History is not null)
            .Select(static fact => fact.History!).Distinct(ByteArrayComparer.Instance).ToArray();
        Array.Sort(histories, static (left, right) => left.AsSpan().SequenceCompareTo(right));
        if (histories.Length > facts.Length)
            GenesisInvalid("The DTC2 history set exceeds its target set.");
        var unsignedLength = checked(RecoveryManifestParser.DtcFixedLength - 32 +
            facts.Length * RecoveryManifestParser.DrtEntryLength +
            histories.Length * RecoveryManifestParser.DrtHistoryEntryLength);
        var unsigned = new byte[unsignedLength];
        "DTC2"u8.CopyTo(unsigned); unsigned[4] = 2;
        baseIdentity.Network.CopyTo(unsigned.AsSpan(6));
        baseIdentity.ResetId.CopyTo(unsigned.AsSpan(22));
        BinaryPrimitives.WriteUInt16BigEndian(unsigned.AsSpan(54, 2),
            (ushort)scope.ComponentKind);
        BinaryPrimitives.WriteUInt64BigEndian(unsigned.AsSpan(56, 8),
            baseIdentity.AccountGeneration);
        // GenesisCutoverAnchor is the authenticated zero-predecessor branch.
        unsigned.AsSpan(64, 70).Clear();
        transaction.TransactionId.CopyTo(unsigned.AsSpan(134));
        BinaryPrimitives.WriteUInt16BigEndian(unsigned.AsSpan(166, 2),
            checked((ushort)facts.Length));
        BinaryPrimitives.WriteUInt16BigEndian(unsigned.AsSpan(168, 2),
            checked((ushort)histories.Length));
        var offset = 170;
        foreach (var fact in facts)
        {
            var target = fact.Entry.Target;
            var targetRecord = fact.Target;
            var targetKind = (byte)target.TargetKind;
            var targetRef = CanonicalGrammar.EncodeReference(target.CertificateReference);
            var targetSubject = ComputeTargetSubject(targetRecord, targetKind);
            var generation = targetKind switch
            {
                1 => Scalars.UInt64(targetRecord.FieldSpan(5)),
                2 => Scalars.UInt64(targetRecord.FieldSpan(7)),
                3 => Scalars.UInt64(targetRecord.FieldSpan(2)),
                _ => throw new UnreachableException()
            };
            var handle = targetKind switch
            {
                1 => targetRecord.FieldSpan(8),
                2 => targetRecord.FieldSpan(9),
                3 => targetRecord.FieldSpan(9),
                _ => throw new UnreachableException()
            };
            var notAfter = targetKind switch
            {
                1 => Scalars.UInt64(targetRecord.FieldSpan(17)),
                2 => Scalars.UInt64(targetRecord.FieldSpan(15)),
                3 => 0UL,
                _ => throw new UnreachableException()
            };
            fact.DrtReference.CopyTo(unsigned, offset);
            offset += 38;
            target.Record.CanonicalSpan.CopyTo(unsigned.AsSpan(offset)); offset += 179;
            targetRef.CopyTo(unsigned, offset); offset += 38;
            unsigned[offset++] = targetKind;
            baseIdentity.AccountHash.CopyTo(unsigned.AsSpan(offset)); offset += 32;
            targetSubject.CopyTo(unsigned, offset); offset += 32;
            BinaryPrimitives.WriteUInt64BigEndian(unsigned.AsSpan(offset, 8), generation); offset += 8;
            handle.CopyTo(unsigned.AsSpan(offset)); offset += 32;
            BinaryPrimitives.WriteUInt64BigEndian(unsigned.AsSpan(offset, 8), notAfter); offset += 8;
            var ordinal = fact.History is null ? 0 : Array.FindIndex(histories,
                history => CanonicalGrammar.FixedEquals(history, fact.History)) + 1;
            if (fact.History is not null && ordinal == 0)
                GenesisInvalid("The DTC2 target history is absent from the sorted catalog.");
            BinaryPrimitives.WriteUInt16BigEndian(unsigned.AsSpan(offset, 2),
                checked((ushort)ordinal)); offset += 2;
        }
        foreach (var history in histories) { history.CopyTo(unsigned, offset); offset += history.Length; }
        transaction.ProtectedKeyId.CopyTo(unsigned.AsSpan(offset)); offset += 32;
        if (offset != unsigned.Length) GenesisInvalid("The authored genesis DTC2 width drifted.");
        var canonical = await GenesisProtectedRecords.AuthorAsync(
            "Deep/ProtectedState/V1/DTC2", unsigned, transaction.ProtectedKeyId.ToArray(),
            checked(unsigned.Length + 32), hmacProvider, cancellationToken).ConfigureAwait(false);
        RecoveryManifestParser.PreflightDtcContainer(canonical);
        var fingerprint = RecoveryContextFingerprint.GenesisIdentity(
            baseIdentity.Identity, baseIdentity.Device, baseIdentity.Mailbox,
            baseIdentity.Router, baseIdentity.Manifest, canonical);
        return new GenesisIdentityContext(
            baseIdentity, scope, transaction, canonical, fingerprint);
    }

    public static GenesisComponentIntent CreateGenesisComponentIntent(
        GenesisIdentityContext identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (!identity.IsCurrentProtectedStore)
            GenesisInvalid("Recovered DRM20 identity provenance cannot authorize genesis authoring.");
        return new GenesisComponentIntent(identity);
    }

    private static DtcTargetFact CreateDtcTargetFact(
        VerifiedGenesisBaseIdentityContext identity,
        RevocationCatalogEntry entry,
        int currentIndex)
    {
        var target = entry.Target;
        var reference = target.CertificateReference;
        var definition = target.TargetKind switch
        {
            RevocationTargetKind.AccountTerminal => RecordDefinitions.Dpa1,
            RevocationTargetKind.DeviceCertificate => RecordDefinitions.Dpd1,
            RevocationTargetKind.MailboxRoleCertificate => RecordDefinitions.Dpm1,
            _ => throw new UnreachableException()
        };
        var record = CanonicalGrammar.DecodeOwned(entry.CertificateCanonical, definition);
        var expectedType = target.TargetKind switch
        {
            RevocationTargetKind.AccountTerminal => ArtifactType.Dpa1,
            RevocationTargetKind.DeviceCertificate => ArtifactType.Dpd1,
            RevocationTargetKind.MailboxRoleCertificate => ArtifactType.Dpm1,
            _ => throw new UnreachableException()
        };
        var actual = CanonicalGrammar.ComputeReference(expectedType, record.CanonicalSpan);
        if (reference.Type != expectedType || reference.CanonicalLength != actual.CanonicalLength ||
            !CanonicalGrammar.FixedEquals(reference.CanonicalHash.Span, actual.CanonicalHash.Span))
            GenesisInvalid("The DRS target is absent from the sealed genesis identity catalog.");
        var drtReference = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Drt1, target.Record.CanonicalSpan));
        var history = target.TargetKind == RevocationTargetKind.AccountTerminal
            ? null : CreateHistory(identity, entry, record, currentIndex);
        return new DtcTargetFact(entry, record, drtReference, history);
    }

    private static byte[] CreateHistory(VerifiedGenesisBaseIdentityContext identity,
        RevocationCatalogEntry entry, OwnedRecord target, int currentIndex)
    {
        if (entry.PredecessorDrsCanonical.IsEmpty)
            GenesisInvalid("A protected DTC2 target lacks its retained predecessor DRS1.");
        var predecessor = CanonicalGrammar.DecodeOwned(entry.PredecessorDrsCanonical,
            RecordDefinitions.Drs1);
        var current = identity.Identity.Revocations.Snapshot.Record;
        var predecessorRef = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Drs1, predecessor.CanonicalSpan));
        var currentRef = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Drs1, current.CanonicalSpan));
        var revisionTag = entry.Target.TargetKind == RevocationTargetKind.DeviceCertificate ? 12 : 10;
        var referenceTag = entry.Target.TargetKind == RevocationTargetKind.DeviceCertificate ? 13 : 11;
        var countTag = entry.Target.TargetKind == RevocationTargetKind.DeviceCertificate ? 14 : 12;
        var headTag = entry.Target.TargetKind == RevocationTargetKind.DeviceCertificate ? 15 : 13;
        var issuedTag = entry.Target.TargetKind == RevocationTargetKind.DeviceCertificate ? 16 : 14;
        var observedCount = Scalars.UInt64(target.FieldSpan(countTag));
        var currentCount = (ulong)Scalars.UInt16(current.FieldSpan(9));
        if (CanonicalGrammar.FixedEquals(predecessorRef, currentRef) ||
            !CanonicalGrammar.FixedEquals(target.FieldSpan(referenceTag), predecessorRef) ||
            Scalars.UInt64(target.FieldSpan(revisionTag)) != Scalars.UInt64(predecessor.FieldSpan(4)) ||
            observedCount != Scalars.UInt16(predecessor.FieldSpan(9)) ||
            !CanonicalGrammar.FixedEquals(target.FieldSpan(headTag), predecessor.FieldSpan(11)) ||
            !CanonicalGrammar.FixedEquals(predecessor.FieldSpan(1), current.FieldSpan(1)) ||
            !CanonicalGrammar.FixedEquals(predecessor.FieldSpan(2), current.FieldSpan(2)) ||
            !CanonicalGrammar.FixedEquals(predecessor.FieldSpan(3), current.FieldSpan(3)) ||
            Scalars.UInt64(predecessor.FieldSpan(4)) >= Scalars.UInt64(current.FieldSpan(4)) ||
            observedCount > currentCount || observedCount > checked((ulong)currentIndex) ||
            !CanonicalGrammar.FixedEquals(predecessor.FieldSpan(11),
                RecomputeDrsPrefixHead(current, checked((int)observedCount))))
            GenesisInvalid("A protected DTC2 target is not bound to an exact predecessor DRS1 prefix.");
        var predecessorIssued = Scalars.UInt64(predecessor.FieldSpan(5));
        var targetIssued = Scalars.UInt64(target.FieldSpan(issuedTag));
        var currentIssued = Scalars.UInt64(current.FieldSpan(5));
        if (predecessorIssued == 0 || predecessorIssued > targetIssued ||
            targetIssued > entry.RevokedAtUnixSeconds || entry.RevokedAtUnixSeconds > currentIssued)
            GenesisInvalid("The protected DTC2 target chronology is invalid.");

        var publicKey = ResolveHistoricalRevocationKey(identity.Identity,
            predecessor.FieldSpan(6), predecessor.FieldSpan(7));
        var expectedHash = ComputeIdentityKeyHash(predecessor.FieldSpan(1),
            predecessor.FieldSpan(2), predecessor.FieldSpan(3), publicKey);
        if (!CanonicalGrammar.FixedEquals(predecessor.FieldSpan(8), expectedHash) ||
            !PublicKeyAuth.VerifyDetached(predecessor.FieldSpan(12).ToArray(),
                CanonicalGrammar.GetSigningBytes(predecessor,
                    "Deep/IdentityAuth/V1/revocation-snapshot"), publicKey))
            throw new RecordException(RecordError.InvalidSignature,
                "The retained predecessor DRS1 signature is invalid.");

        var history = new byte[RecoveryManifestParser.DrtHistoryEntryLength];
        predecessorRef.CopyTo(history, 0);
        predecessor.FieldSpan(4).CopyTo(history.AsSpan(38));
        BinaryPrimitives.WriteUInt64BigEndian(history.AsSpan(46, 8), observedCount);
        predecessor.FieldSpan(11).CopyTo(history.AsSpan(54));
        predecessor.FieldSpan(5).CopyTo(history.AsSpan(86));
        predecessor.FieldSpan(6).CopyTo(history.AsSpan(94));
        predecessor.FieldSpan(7).CopyTo(history.AsSpan(102));
        predecessor.FieldSpan(8).CopyTo(history.AsSpan(140));
        return history;
    }

    private static byte[] ResolveHistoricalRevocationKey(VerifiedIdentityRelative identity,
        ReadOnlySpan<byte> generationBytes, ReadOnlySpan<byte> transitionBytes)
    {
        var generation = Scalars.UInt64(generationBytes);
        var transition = CanonicalGrammar.DecodeReference(transitionBytes, allowZero: true);
        if (generation == 0)
        {
            if (!transition.IsZero) GenesisInvalid("A generation-zero predecessor DRS1 has a transition.");
            return identity.Account.Certificate.RevocationEd25519PublicKey.ToArray();
        }
        foreach (var canonical in identity.Authority.OrderedTransitionCanonicals)
        {
            if (!canonical.Span[..4].SequenceEqual("KRT1"u8)) continue;
            var rotation = CanonicalGrammar.DecodeOwned(canonical.Span, RecordDefinitions.Krt1);
            if (rotation.FieldSpan(2)[0] != (byte)KeyScope.AccountRevocation ||
                Scalars.UInt64(rotation.FieldSpan(5)) != generation) continue;
            var actual = CanonicalGrammar.ComputeReference(ArtifactType.Krt1, rotation.CanonicalSpan);
            if (transition.Type == actual.Type && transition.CanonicalLength == actual.CanonicalLength &&
                CanonicalGrammar.FixedEquals(transition.CanonicalHash.Span, actual.CanonicalHash.Span))
                return rotation.FieldSpan(8).ToArray();
        }
        GenesisInvalid("The predecessor DRS1 scope-3 authority is absent or terminal.");
        return [];
    }

    private static byte[] ComputeIdentityKeyHash(ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> accountHash, ReadOnlySpan<byte> accountGeneration,
        ReadOnlySpan<byte> publicKey)
    {
        Span<byte> payload = stackalloc byte[89];
        network.CopyTo(payload); payload[16] = (byte)KeyScope.AccountRevocation;
        accountHash.CopyTo(payload[17..]); accountGeneration.CopyTo(payload[49..]);
        publicKey.CopyTo(payload[57..]);
        return CanonicalGrammar.Sha256Domain("Deep/IdentityAuth/V1/key-hash", payload);
    }

    private static byte[] RecomputeDrsPrefixHead(OwnedRecord current, int count)
    {
        if (count < 0 || count > Scalars.UInt16(current.FieldSpan(9)))
            GenesisInvalid("The predecessor DRS1 prefix count is invalid.");
        var head = new byte[32]; var payload = new byte[158];
        var tuple = payload.AsSpan(0, 56);
        current.FieldSpan(1).CopyTo(tuple); current.FieldSpan(2).CopyTo(tuple[16..]);
        current.FieldSpan(3).CopyTo(tuple[48..]);
        for (var index = 0; index < count; index++)
        {
            payload.AsSpan(56).Clear();
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(56, 8), checked((ulong)index));
            head.CopyTo(payload, 64);
            current.FieldSpan(10).Slice(index * 62, 62).CopyTo(payload.AsSpan(96));
            head = CanonicalGrammar.Sha256Domain(
                "Deep/IdentityAuth/V1/revocation-entry-head", payload);
        }
        return head;
    }

    private sealed record DtcTargetFact(RevocationCatalogEntry Entry, OwnedRecord Target,
        byte[] DrtReference, byte[]? History);

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();
        public bool Equals(byte[]? left, byte[]? right) => left is not null && right is not null &&
            CanonicalGrammar.FixedEquals(left, right);
        public int GetHashCode(byte[] value) => BinaryPrimitives.ReadInt32BigEndian(
            SHA256.HashData(value).AsSpan(0, 4));
    }

    private static byte[] ComputeTargetSubject(OwnedRecord target, byte kind)
    {
        using var stream = new MemoryStream();
        void Add(ReadOnlySpan<byte> value) => stream.Write(value);
        string suffix;
        switch (kind)
        {
            case 1:
                suffix = "DPD"; Add(target.FieldSpan(1)); Add(target.FieldSpan(2));
                Add(target.FieldSpan(3)); Add(target.FieldSpan(4)); Add(target.FieldSpan(5)); break;
            case 2:
                suffix = "DPM"; Add(target.FieldSpan(1)); Add(target.FieldSpan(2));
                Add(target.FieldSpan(3)); Add(target.FieldSpan(4)); Add(target.FieldSpan(6));
                Add(target.FieldSpan(7)); break;
            case 3:
                suffix = "DPA"; Add(target.FieldSpan(1));
                Add(ComputeAccountHash(target)); Add(target.FieldSpan(2)); break;
            default: throw new UnreachableException();
        }
        return CanonicalGrammar.Sha256Domain(
            $"Deep/Cutover/V1/recovery-target-subject/{suffix}", stream.ToArray());
    }

    private static byte[] ComputeAccountHash(OwnedRecord account)
    {
        Span<byte> payload = stackalloc byte[56];
        account.FieldSpan(1).CopyTo(payload);
        account.FieldSpan(2).CopyTo(payload[16..]);
        account.FieldSpan(5).CopyTo(payload[24..]);
        return CanonicalGrammar.Sha256Domain("Deep/IdentityAuth/V1/account-id", payload);
    }

    private static void GenesisInvalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
