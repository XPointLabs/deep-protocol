using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// Nonexportable recovery-key provider. Protocol owns both output buffers; implementations must
/// derive the frozen Wave 1 HKDF inputs internally and must not expose key material.
/// </summary>
public abstract class RecoveryProtectorProvider
{
    public abstract ValueTask DeriveNonceAsync(
        RecoveryProviderRequest request,
        Memory<byte> derivedNonce24,
        CancellationToken cancellationToken);

    public abstract ValueTask OpenAsync(
        RecoveryProviderRequest request,
        Memory<byte> plaintextDestination,
        CancellationToken cancellationToken);
}

public enum RecoveryNonceLatchDecision
{
    Stored = 1,
    ExactReplay = 2,
    ForkLatched = 3
}

/// <summary>Durable compare-or-latch seam; its result never conveys commit authority.</summary>
public abstract class RecoveryNonceLatch
{
    public abstract ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
        RecoveryNonceLatchRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Defensively frozen provider input. It exposes no recovery seed, key, or nonce override.</summary>
public sealed class RecoveryProviderRequest
{
    private readonly OwnedRecord _record;
    private readonly byte[] _associatedData;

    internal RecoveryProviderRequest(OwnedRecord record, byte[] associatedData)
    {
        _record = record;
        _associatedData = associatedData.ToArray();
    }

    // A provider is an external callback boundary. Never expose the OwnedRecord backing array:
    // ReadOnlyMemory<byte> can otherwise be recovered as a writable ArraySegment via
    // MemoryMarshal.TryGetArray and mutated after validation.
    public ReadOnlyMemory<byte> NetworkId => _record.FieldCopy(1);
    public ReadOnlyMemory<byte> ComponentSubject => _record.FieldCopy(2);
    public ReadOnlyMemory<byte> TransactionId => _record.FieldCopy(3);
    public ReadOnlyMemory<byte> ProtectorKeyId => _record.FieldCopy(13);
    public ReadOnlyMemory<byte> StoredNonce => _record.FieldCopy(12);
    public ReadOnlyMemory<byte> Ciphertext => _record.FieldCopy(16);
    public ReadOnlyMemory<byte> AuthenticationTag => _record.FieldCopy(17);
    public ReadOnlyMemory<byte> AssociatedData => _associatedData.ToArray();
    public int PlaintextLength => checked((int)Scalars.UInt64(_record.FieldSpan(10)));
}

/// <summary>
/// Decrypted and canonically verified recovery data only. It is not durable state, a commit
/// receipt, or activation authority. Dispose it as soon as the consumer has verified its
/// component-specific restore closure.
/// </summary>
public sealed class RecoveryCandidatePlan : IDisposable
{
    private readonly RecoveryArtifactCandidate[] _artifacts;
    private byte[]? _drmHash;
    private int _disposed;

    internal RecoveryCandidatePlan(
        RecoveryCapsule capsule,
        OwnedRecoveryManifest manifest,
        byte[] latchKey,
        byte[] latchValue,
        bool exactReplay,
        ReadOnlySpan<byte> rfcVerifiedHmac,
        ReadOnlySpan<byte> rahVerifiedHmac,
        ReadOnlySpan<byte> dtcVerifiedHmac,
        ReadOnlySpan<byte> dwhVerifiedHmac)
    {
        Capsule = capsule;
        Manifest = manifest;
        LatchKey = latchKey;
        LatchValue = latchValue;
        ExactReplay = exactReplay;
        _rfcVerifiedHmac = rfcVerifiedHmac.ToArray();
        _rahVerifiedHmac = rahVerifiedHmac.ToArray();
        _dtcVerifiedHmac = dtcVerifiedHmac.ToArray();
        _dwhVerifiedHmac = dwhVerifiedHmac.ToArray();
        _drmHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-drm-hash",
            manifest.CanonicalSpan);
        _artifacts = manifest.Rows
            .Select((row, index) => new RecoveryArtifactCandidate(this, row.Reference, index))
            .ToArray();
    }

    private byte[]? _rfcVerifiedHmac;
    private byte[]? _rahVerifiedHmac;
    private byte[]? _dtcVerifiedHmac;
    private byte[]? _dwhVerifiedHmac;

    public RecoveryCapsule Capsule { get; }
    internal OwnedRecoveryManifest Manifest { get; }
    internal byte[] LatchKey { get; }
    internal byte[] LatchValue { get; }
    public bool ExactReplay { get; }
    public bool NoAuthorityClaim => true;
    public ReadOnlyMemory<byte> DrmHash =>
        (_drmHash ?? throw new ObjectDisposedException(nameof(RecoveryCandidatePlan))).ToArray();
    public ReadOnlyMemory<byte> PinCoreProjection => CopyOwned(Manifest.PinCoreProjection);
    public ReadOnlyMemory<byte> FrontierCheckpoint => CopyOwned(Manifest.FrontierCheckpoint);
    /// <summary>The verified-HMAC, length-framed RFC1 domain hash.</summary>
    public ReadOnlyMemory<byte> FrontierCheckpointHash
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return RecoveryShadow.ComputeFrontierCheckpointHash(Manifest.FrontierCheckpoint);
        }
    }
    public ReadOnlyMemory<byte> PredecessorFrontier => CopyOwned(Manifest.PredecessorFrontier);
    public ReadOnlyMemory<byte> ResetAuthorityHead => CopyOwned(Manifest.ResetAuthorityHead);
    public ReadOnlyMemory<byte> DrtCatalog => CopyOwned(Manifest.DrtCatalog);
    public ReadOnlyMemory<byte> WitnessHeadHistory => CopyOwned(Manifest.WitnessHeadHistory);
    public ReadOnlyMemory<byte> PredecessorFrontierHash => CanonicalGrammar.Sha256Domain(
        "Deep/Cutover/V1/recovery-predecessor-frontier", Manifest.PredecessorFrontier);
    public ReadOnlyMemory<byte> ResetAuthorityHeadHash =>
        RecoveryShadow.ComputeResetAuthorityHeadHash(Manifest.ResetAuthorityHead);
    public ReadOnlyMemory<byte> DrtCatalogHash => CanonicalGrammar.Sha256Domain(
        "Deep/Cutover/V1/recovery-drt-catalog", Manifest.DrtCatalog);
    public ReadOnlyMemory<byte> WitnessHeadHistoryHash =>
        RecoveryShadow.ComputeWitnessHeadHistoryHash(Manifest.WitnessHeadHistory);

    internal ReleaseRootRestoreRelative RestoreReleaseRootAncestry(
        ReleaseRootManifestPin pin,
        ReadOnlyMemory<byte> freshDclCanonical,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(pin);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var manifestBytes = FindArtifact(ArtifactType.Rrm1);
        var transitions = Artifacts
            .Where(static value => value.ArtifactType is ArtifactType.Krt1 or ArtifactType.Krf1)
            .Select(static value => value.CanonicalBytes)
            .Where(static value => Scope(value.Span) == KeyScope.ReleaseRoot)
            .OrderBy(static value => TransitionGeneration(value.Span))
            .ToArray();
        var delegations = Artifacts
            .Where(static value => value.ArtifactType == ArtifactType.Dwd1)
            .Select(static value => value.CanonicalBytes)
            .OrderBy(static value => CutoverCodec.DecodeWitnessDelegation(value.Span)
                .DelegationGeneration)
            .ToArray();
        if (delegations.Length is < 1 or > 65)
            ThrowInvalid("The DRM2 ReleaseRoot ancestry has no bounded DWD1 chain.");
        var dwh = Manifest.WitnessHeadHistory;
        var dwhCount = BinaryPrimitives.ReadUInt16BigEndian(dwh[166..168]);
        if (dwhCount != delegations.Length - 1)
            ThrowInvalid("DWH1 count does not equal the DWD1 ancestry count minus one.");
        var ancestry = new WitnessAncestryInput[delegations.Length];
        ancestry[0] = new WitnessAncestryInput(delegations[0].Span, new byte[288]);
        var previous = CutoverCodec.DecodeWitnessDelegation(delegations[0].Span);
        for (var index = 1; index < delegations.Length; index++)
        {
            var current = CutoverCodec.DecodeWitnessDelegation(delegations[index].Span);
            var entry = dwh.Slice(168 + (index - 1) * 342, 342);
            var currentReference = CanonicalGrammar.EncodeReference(
                CanonicalGrammar.ComputeReference(ArtifactType.Dwd1, delegations[index].Span));
            if (!CanonicalGrammar.FixedEquals(entry[..38], currentReference) ||
                BinaryPrimitives.ReadUInt64BigEndian(entry[38..46]) != current.DelegationGeneration ||
                BinaryPrimitives.ReadUInt64BigEndian(entry[46..54]) != previous.WitnessEpoch)
                ThrowInvalid("A DWH1 entry does not identify its exact successor and predecessor epoch.");
            var heads = entry.Slice(54, 288);
            VerifyDwhHeads(previous, current, heads);
            ancestry[index] = new WitnessAncestryInput(delegations[index].Span, heads);
            previous = current;
        }
        var terminal = Artifacts.SingleOrDefault(static value => value.ArtifactType == ArtifactType.Dwt1);
        var input = new ReleaseRootRestoreInput(
            pin, manifestBytes, transitions, ancestry,
            terminal?.CanonicalBytes ?? default,
            terminal is null ? freshDclCanonical : default);
        return new ReleaseRootRelativeVerifier().RestoreAncestryRelative(
            input, transactionTimeUnixSeconds);

        ReadOnlyMemory<byte> FindArtifact(ArtifactType type)
        {
            var matches = Artifacts.Where(value => value.ArtifactType == type).ToArray();
            if (matches.Length != 1) ThrowInvalid($"The DRM2 requires exactly one {type} row.");
            return matches[0].CanonicalBytes;
        }

        static ulong TransitionGeneration(ReadOnlySpan<byte> canonical) =>
            canonical.Length == 412
                ? IdentityCodec.DecodeKeyRotation(canonical).TransitionGeneration
                : IdentityCodec.DecodeKeyRevocation(canonical).TransitionGeneration;

        static KeyScope Scope(ReadOnlySpan<byte> canonical) => canonical.Length == 412
            ? IdentityCodec.DecodeKeyRotation(canonical).Scope
            : IdentityCodec.DecodeKeyRevocation(canonical).Scope;

        static void ThrowInvalid(string message) =>
            throw new RecordException(RecordError.InvalidField, message);
    }

    internal (ReleaseRootRelativeFact Root, WitnessDelegationRelativeFact[] Delegations)
        RestoreGenesisReleaseAncestry(
            ReleaseRootManifestPin pin,
            ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(pin);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Artifacts.Any(static value => value.ArtifactType is ArtifactType.Krf1 or ArtifactType.Dwt1))
            ThrowInvalid("Genesis release ancestry cannot contain KRF1 or DWT1.");
        var manifests = Artifacts.Where(static value => value.ArtifactType == ArtifactType.Rrm1)
            .Select(static value => value.CanonicalBytes).ToArray();
        if (manifests.Length != 1) ThrowInvalid("Genesis release ancestry requires one RRM1.");
        var transitions = Artifacts
            .Where(static value => value.ArtifactType == ArtifactType.Krt1)
            .Select(static value => value.CanonicalBytes)
            .Where(static value => IdentityCodec.DecodeKeyRotation(value.Span).Scope == KeyScope.ReleaseRoot)
            .OrderBy(static value => IdentityCodec.DecodeKeyRotation(value.Span).TransitionGeneration)
            .ToArray();
        var delegations = Artifacts
            .Where(static value => value.ArtifactType == ArtifactType.Dwd1)
            .Select(static value => value.CanonicalBytes)
            .OrderBy(static value => CutoverCodec.DecodeWitnessDelegation(value.Span).DelegationGeneration)
            .ToArray();
        if (delegations.Length is < 1 or > 65 || transitions.Length > 64)
            ThrowInvalid("Genesis release ancestry exceeds the exact transition or DWD bound.");
        var dwh = Manifest.WitnessHeadHistory;
        var dwhCount = BinaryPrimitives.ReadUInt16BigEndian(dwh[166..168]);
        if (dwhCount != delegations.Length - 1)
            ThrowInvalid("Genesis release DWH1 count differs from DWD ancestry.");

        var verifier = new ReleaseRootRelativeVerifier();
        var root = verifier.VerifyManifest(pin, manifests[0].Span, transactionTimeUnixSeconds);
        var facts = new WitnessDelegationRelativeFact[delegations.Length];
        facts[0] = verifier.VerifyGenesisWitnessDelegation(
            root, delegations[0].Span, new byte[288], transactionTimeUnixSeconds);
        var transitionIndex = 0;
        for (var index = 1; index < delegations.Length; index++)
        {
            var decoded = CutoverCodec.DecodeWitnessDelegation(delegations[index].Span);
            if (!Same(CanonicalGrammar.DecodeReference(decoded.Record.FieldSpan(16)),
                    root.CurrentTransitionReference))
            {
                if (transitionIndex >= transitions.Length)
                    ThrowInvalid("A genesis DWD1 changed root without one paired KRT1.");
                root = verifier.VerifyRotation(root, transitions[transitionIndex].Span,
                    transactionTimeUnixSeconds);
                transitionIndex++;
            }
            var entry = dwh.Slice(168 + (index - 1) * 342, 342);
            facts[index] = verifier.VerifyWitnessSuccessor(
                root, facts[index - 1], delegations[index].Span, entry.Slice(54, 288),
                transactionTimeUnixSeconds);
        }
        if (transitionIndex != transitions.Length || root.IsTerminalCandidate)
            ThrowInvalid("Genesis ReleaseRoot ancestry has a transition tail or terminal state.");
        return (root, facts);

        static bool Same(ArtifactReference left, ArtifactReference right) =>
            left.Type == right.Type && left.CanonicalLength == right.CanonicalLength &&
            CanonicalGrammar.FixedEquals(left.CanonicalHash.Span, right.CanonicalHash.Span);
        static void ThrowInvalid(string message) =>
            throw new RecordException(RecordError.InvalidField, message);
    }

    internal VerifiedIdentityRelative RestoreCurrentIdentity(
        ulong transactionTimeUnixSeconds)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var account = FindByReference(Manifest.PinCoreProjection.Slice(26, 38), ArtifactType.Dpa1);
        var snapshot = FindByReference(Manifest.PinCoreProjection.Slice(190, 38), ArtifactType.Drs1);
        var verifiedAccount = IdentityVerifier.VerifyAccountCertificate(account.Span);
        var accountHash = verifiedAccount.DeepAccountIdHash.ToArray();
        var accountGeneration = verifiedAccount.Certificate.AccountGeneration;
        var transitions = Artifacts
            .Where(static value => value.ArtifactType is ArtifactType.Krt1 or ArtifactType.Krf1)
            .Select(static value => value.CanonicalBytes)
            .Where(value => Scope(value.Span) != KeyScope.ReleaseRoot &&
                CanonicalGrammar.FixedEquals(AccountHash(value.Span), accountHash) &&
                AccountGeneration(value.Span) == accountGeneration)
            .OrderBy(static value => (byte)Scope(value.Span))
            .ThenBy(static value => Generation(value.Span))
            .ToArray();
        var count = BinaryPrimitives.ReadUInt16BigEndian(Manifest.DrtCatalog[166..168]);
        var catalog = new RevocationCatalogSource[count];
        for (var index = 0; index < count; index++)
        {
            var entry = Manifest.DtcEntry(index);
            var targetReference = entry.Slice(217, 38).ToArray();
            var target = Artifacts.Where(value =>
                CanonicalGrammar.FixedEquals(value.ArtifactReference.Span, targetReference)).ToArray();
            if (target.Length != 1)
                ThrowInvalid("A DTC1 target certificate is absent or ambiguous in DRM2.");
            catalog[index] = new RevocationCatalogSource(entry.Slice(38, 179),
                target[0].CanonicalBytes.Span);
        }
        var identity = new IdentityRelativeVerifier().RestoreCurrent(
            account.Span, snapshot.Span, transitions, catalog, transactionTimeUnixSeconds);
        VerifyHistoricalResetAuthorization(identity);
        return identity;

        ReadOnlyMemory<byte> FindByReference(ReadOnlySpan<byte> reference, ArtifactType type)
        {
            var frozenReference = reference.ToArray();
            var matches = Artifacts.Where(value => value.ArtifactType == type &&
                CanonicalGrammar.FixedEquals(value.ArtifactReference.Span, frozenReference)).ToArray();
            if (matches.Length != 1) ThrowInvalid($"DRM20 requires one exact current {type} row.");
            return matches[0].CanonicalBytes;
        }

        static KeyScope Scope(ReadOnlySpan<byte> canonical) => canonical.Length == 412
            ? IdentityCodec.DecodeKeyRotation(canonical).Scope
            : IdentityCodec.DecodeKeyRevocation(canonical).Scope;
        static ulong Generation(ReadOnlySpan<byte> canonical) => canonical.Length == 412
            ? IdentityCodec.DecodeKeyRotation(canonical).TransitionGeneration
            : IdentityCodec.DecodeKeyRevocation(canonical).TransitionGeneration;
        static ReadOnlySpan<byte> AccountHash(ReadOnlySpan<byte> canonical) =>
            CanonicalGrammar.DecodeOwned(canonical, canonical.Length == 412
                ? RecordDefinitions.Krt1 : RecordDefinitions.Krf1).FieldSpan(3);
        static ulong AccountGeneration(ReadOnlySpan<byte> canonical) => Scalars.UInt64(
            CanonicalGrammar.DecodeOwned(canonical, canonical.Length == 412
                ? RecordDefinitions.Krt1 : RecordDefinitions.Krf1).FieldSpan(4));
        static void ThrowInvalid(string message) =>
            throw new RecordException(RecordError.InvalidField, message);
    }

    internal VerifiedRecoveredIdentityContext RestoreRecoveredIdentityContext(
        ulong transactionTimeUnixSeconds)
    {
        var identity = RestoreCurrentIdentity(transactionTimeUnixSeconds);
        var verifier = new IdentityRelativeVerifier();
        var currentDpaReference = Manifest.PinCoreProjection.Slice(26, 38).ToArray();
        var currentDcmReference = Manifest.PinCoreProjection.Slice(72, 38).ToArray();
        var currentDrsReference = Manifest.PinCoreProjection.Slice(190, 38).ToArray();
        var currentDcm = FindExact(currentDcmReference, ArtifactType.Dcm1, RecordDefinitions.Dcm1);
        var currentDrs = FindExact(currentDrsReference, ArtifactType.Drs1, RecordDefinitions.Drs1);
        VerifyCurrentManifest(identity, currentDcm, currentDpaReference, currentDrsReference);

        var devices = new Dictionary<string, VerifiedDeviceRelative>(StringComparer.Ordinal);
        foreach (var group in Records(ArtifactType.Dpd1, RecordDefinitions.Dpd1)
                     .GroupBy(static value => Convert.ToHexString(value.Record.FieldSpan(4))))
        {
            VerifiedDeviceRelative? predecessor = null;
            foreach (var value in group.OrderBy(static value => Scalars.UInt64(value.Record.FieldSpan(5))))
            {
                predecessor = verifier.RestoreDeviceFromRecovery(
                    identity, value.Record.CanonicalSpan, transactionTimeUnixSeconds, predecessor);
                devices.Add(Convert.ToHexString(value.Reference), predecessor);
            }
        }

        var mailboxes = new Dictionary<string, VerifiedMailboxRelative>(StringComparer.Ordinal);
        foreach (var group in Records(ArtifactType.Dpm1, RecordDefinitions.Dpm1)
                     .GroupBy(static value => Convert.ToHexString(value.Record.FieldSpan(6))))
        {
            VerifiedMailboxRelative? predecessor = null;
            foreach (var value in group.OrderBy(static value => Scalars.UInt64(value.Record.FieldSpan(7))))
            {
                if (!devices.TryGetValue(Convert.ToHexString(value.Record.FieldSpan(5)), out var device))
                    ThrowInvalid("A recovered DPM1 does not name an exact verified DPD1.");
                predecessor = verifier.VerifyMailboxRole(
                    identity, value.Record.CanonicalSpan, device!,
                    transactionTimeUnixSeconds, predecessor);
                mailboxes.Add(Convert.ToHexString(value.Reference), predecessor);
            }
        }

        var routers = new List<(OwnedRecord Record, byte[] Reference)>();
        var routingVerifier = new NativeRoutingVerifier();
        foreach (var group in Records(ArtifactType.Dnr1, RecordDefinitions.Dnr1)
                     .GroupBy(static value => Convert.ToHexString(value.Record.FieldSpan(9))))
        {
            byte[]? predecessor = null;
            ulong priorGeneration = 0;
            foreach (var value in group.OrderBy(static value => Scalars.UInt64(value.Record.FieldSpan(10))))
            {
                var generation = Scalars.UInt64(value.Record.FieldSpan(10));
                var predecessorField = value.Record.FieldSpan(18);
                if ((predecessor is null && !CanonicalGrammar.DecodeReference(
                        predecessorField, allowZero: true).IsZero) ||
                    (predecessor is not null && (!CanonicalGrammar.FixedEquals(
                        predecessorField, predecessor) || generation != checked(priorGeneration + 1))))
                    ThrowInvalid("The recovered DNR1 predecessor chain is invalid.");
                if (!mailboxes.TryGetValue(Convert.ToHexString(value.Record.FieldSpan(3)), out var mailbox))
                    ThrowInvalid("A recovered DNR1 does not name an exact verified DPM1.");
                var pma = FindExactBytes(value.Record.FieldSpan(4), ArtifactType.Pma1);
                var pmr = FindExactBytes(value.Record.FieldSpan(6), ArtifactType.Pmr1);
                _ = routingVerifier.VerifyRouterCertificateFromRecovery(
                    mailbox!, pma, pmr,
                    value.Record.CanonicalSpan, transactionTimeUnixSeconds);
                routers.Add((value.Record, value.Reference));
                predecessor = value.Reference;
                priorGeneration = generation;
            }
        }

        var currentTransitions = CurrentTransitions(identity);
        var roleHeads = new[]
        {
            Head(identity, KeyScope.DeviceCertificateIssuer),
            Head(identity, KeyScope.AccountRevocation),
            Head(identity, KeyScope.ResetControl)
        };
        var deviceRows = Records(ArtifactType.Dpd1, RecordDefinitions.Dpd1)
            .OrderBy(static value => Convert.ToHexString(value.Record.FieldSpan(4)), StringComparer.Ordinal)
            .ThenBy(static value => Scalars.UInt64(value.Record.FieldSpan(5))).ToArray();
        var mailboxRows = Records(ArtifactType.Dpm1, RecordDefinitions.Dpm1)
            .OrderBy(static value => Convert.ToHexString(value.Record.FieldSpan(6)), StringComparer.Ordinal)
            .ThenBy(static value => Scalars.UInt64(value.Record.FieldSpan(7))).ToArray();
        var routerRows = routers
            .OrderBy(static value => Convert.ToHexString(value.Record.FieldSpan(9)), StringComparer.Ordinal)
            .ThenBy(static value => Scalars.UInt64(value.Record.FieldSpan(10))).ToArray();
        var deviceHead = UniqueHead(deviceRows, 20);
        var mailboxHead = UniqueHead(mailboxRows, 17);
        var routerHead = UniqueHead(routerRows, 18);
        var catalog = BuildCatalog(currentTransitions, roleHeads, deviceRows, mailboxRows,
            routerRows, currentDrs, currentDrsReference);
        var catalogHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-identity-catalog", catalog);
        var identityTuple = new byte[16 + 32 + 8 + 38 + 38 + 8 + 8 + 32 + 38 + 38 + 38 + 38 + 32];
        var offset = 0;
        Append(identity.Account.Certificate.NetworkId.Span);
        Append(currentDcm.FieldSpan(2));
        U64(identity.Account.Certificate.AccountGeneration);
        Append(currentDpaReference); Append(currentDcmReference);
        U64(Scalars.UInt64(currentDrs.FieldSpan(4)));
        U64(BinaryPrimitives.ReadUInt16BigEndian(currentDrs.FieldSpan(9)));
        Append(currentDrs.FieldSpan(11)); Append(currentDrsReference);
        Append(deviceHead); Append(mailboxHead); Append(routerHead); Append(catalogHash);
        if (offset != identityTuple.Length)
            ThrowInvalid("The recovered identity context width drifted.");
        var fingerprint = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-identity-context", identityTuple);
        return new VerifiedRecoveredIdentityContext(
            identity, fingerprint, catalogHash, deviceHead, mailboxHead, routerHead);

        List<(OwnedRecord Record, byte[] Reference)> Records(
            ArtifactType type, RecordDefinition definition) => Artifacts
            .Where(value => value.ArtifactType == type)
            .Select(value => (CanonicalGrammar.DecodeOwned(value.CanonicalBytes.Span, definition),
                value.ArtifactReference.ToArray())).ToList();

        OwnedRecord FindExact(ReadOnlySpan<byte> reference, ArtifactType type, RecordDefinition definition)
        {
            var frozen = reference.ToArray();
            var matches = Artifacts.Where(value => value.ArtifactType == type &&
                CanonicalGrammar.FixedEquals(value.ArtifactReference.Span, frozen)).ToArray();
            if (matches.Length != 1) ThrowInvalid($"DRM20 omits one exact {type} row.");
            return CanonicalGrammar.DecodeOwned(matches[0].CanonicalBytes.Span, definition);
        }

        byte[] FindExactBytes(ReadOnlySpan<byte> reference, ArtifactType type)
        {
            var frozen = reference.ToArray();
            var matches = Artifacts.Where(value => value.ArtifactType == type &&
                CanonicalGrammar.FixedEquals(value.ArtifactReference.Span, frozen)).ToArray();
            if (matches.Length != 1) ThrowInvalid($"DRM20 omits one exact {type} row.");
            return matches[0].CanonicalBytes.ToArray();
        }

        static byte[] Head(VerifiedIdentityRelative value, KeyScope scope) =>
            CanonicalGrammar.EncodeReference(value.Authority.GetKeyAuthority(scope).TransitionReference);

        List<(ArtifactType Type, KeyScope Scope, ulong Generation, byte[] Reference)> CurrentTransitions(
            VerifiedIdentityRelative value)
        {
            var accountHash = value.Account.DeepAccountIdHash.ToArray();
            var accountGeneration = value.Account.Certificate.AccountGeneration;
            return Artifacts.Where(static item => item.ArtifactType is ArtifactType.Krt1 or ArtifactType.Krf1)
                .Select(item =>
                {
                    var definition = item.ArtifactType == ArtifactType.Krt1
                        ? RecordDefinitions.Krt1 : RecordDefinitions.Krf1;
                    var record = CanonicalGrammar.DecodeOwned(item.CanonicalBytes.Span, definition);
                    return (item.ArtifactType, (KeyScope)record.FieldSpan(2)[0],
                        Scalars.UInt64(record.FieldSpan(5)), item.ArtifactReference.ToArray(), record);
                })
                .Where(item => item.Item2 != KeyScope.ReleaseRoot &&
                    CanonicalGrammar.FixedEquals(item.record.FieldSpan(3), accountHash) &&
                    Scalars.UInt64(item.record.FieldSpan(4)) == accountGeneration)
                .OrderBy(item => (byte)item.Item2).ThenBy(item => item.Item3)
                .Select(item => (item.ArtifactType, item.Item2, item.Item3, item.Item4)).ToList();
        }

        byte[] BuildCatalog(
            IReadOnlyList<(ArtifactType Type, KeyScope Scope, ulong Generation, byte[] Reference)> transitions,
            IReadOnlyList<byte[]> heads,
            IReadOnlyList<(OwnedRecord Record, byte[] Reference)> deviceValues,
            IReadOnlyList<(OwnedRecord Record, byte[] Reference)> mailboxValues,
            IReadOnlyList<(OwnedRecord Record, byte[] Reference)> routerValues,
            OwnedRecord drs,
            ReadOnlySpan<byte> drsReference)
        {
            var length = 16 + 32 + 8 + 32 + 2 + transitions.Count * 48 + 3 * 38 +
                2 + deviceValues.Count * 78 + 2 + mailboxValues.Count * 78 +
                2 + routerValues.Count * 78 + 38 + 8 + 8 + 32 + 32 + 32;
            var output = new byte[length]; var cursor = 0;
            Put(identity.Account.Certificate.NetworkId.Span); Put(currentDcm.FieldSpan(2));
            PutU64(identity.Account.Certificate.AccountGeneration);
            Put(Manifest.DtcProtectedKeyId); PutU16(checked((ushort)transitions.Count));
            foreach (var value in transitions)
            {
                output[cursor++] = value.Type == ArtifactType.Krt1 ? (byte)1 : (byte)2;
                output[cursor++] = (byte)value.Scope; PutU64(value.Generation); Put(value.Reference);
            }
            foreach (var head in heads) Put(head);
            PutU16(checked((ushort)deviceValues.Count));
            foreach (var value in deviceValues)
            { Put(value.Record.FieldSpan(4)); PutU64(Scalars.UInt64(value.Record.FieldSpan(5))); Put(value.Reference); }
            PutU16(checked((ushort)mailboxValues.Count));
            foreach (var value in mailboxValues)
            { Put(value.Record.FieldSpan(6)); PutU64(Scalars.UInt64(value.Record.FieldSpan(7))); Put(value.Reference); }
            PutU16(checked((ushort)routerValues.Count));
            foreach (var value in routerValues)
            { Put(value.Record.FieldSpan(9)); PutU64(Scalars.UInt64(value.Record.FieldSpan(10))); Put(value.Reference); }
            Put(drsReference); PutU64(Scalars.UInt64(drs.FieldSpan(4)));
            PutU64(BinaryPrimitives.ReadUInt16BigEndian(drs.FieldSpan(9)));
            Put(drs.FieldSpan(11)); Put(DrtCatalogHash.Span); Put(Manifest.DtcProtectedKeyId);
            if (cursor != output.Length) ThrowInvalid("The recovery identity catalog width drifted.");
            return output;
            void Put(ReadOnlySpan<byte> value) { value.CopyTo(output.AsSpan(cursor)); cursor += value.Length; }
            void PutU64(ulong value) { BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(cursor, 8), value); cursor += 8; }
            void PutU16(ushort value) { BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(cursor, 2), value); cursor += 2; }
        }

        static byte[] UniqueHead(
            IReadOnlyList<(OwnedRecord Record, byte[] Reference)> rows, int predecessorTag)
        {
            if (rows.Count == 0) return new byte[38];
            var predecessors = rows.Select(value => Convert.ToHexString(
                value.Record.FieldSpan(predecessorTag))).ToHashSet(StringComparer.Ordinal);
            var heads = rows.Where(value => !predecessors.Contains(
                Convert.ToHexString(value.Reference))).ToArray();
            if (heads.Length != 1)
                ThrowInvalid("The recovered identity role head is absent or ambiguous.");
            return heads[0].Reference;
        }

        static void VerifyCurrentManifest(
            VerifiedIdentityRelative value, OwnedRecord dcm,
            ReadOnlySpan<byte> dpaReference, ReadOnlySpan<byte> drsReference)
        {
            var account = value.Account.Certificate.Record;
            if (!CanonicalGrammar.FixedEquals(dcm.FieldSpan(1), account.FieldSpan(1)) ||
                Scalars.UInt64(dcm.FieldSpan(4)) != value.Account.Certificate.AccountGeneration ||
                !CanonicalGrammar.FixedEquals(dcm.FieldSpan(5), dpaReference) ||
                !CanonicalGrammar.FixedEquals(dcm.FieldSpan(9), drsReference))
                ThrowInvalid("The current DCM1 differs from the recovered identity.");
            var signing = CanonicalGrammar.GetSigningBytes(dcm, "Deep/Cutover/V1/manifest");
            VerifySignature(dcm.FieldSpan(18), signing,
                value.Authority.GetKeyAuthority(KeyScope.ResetControl).CurrentEd25519PublicKey.Span);
            VerifySignature(dcm.FieldSpan(19), signing, account.FieldSpan(5));
        }

        static void VerifySignature(
            ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
        {
            if (!Sodium.PublicKeyAuth.VerifyDetached(
                    signature.ToArray(), message.ToArray(), key.ToArray()))
                throw new RecordException(RecordError.InvalidSignature,
                    "A recovered identity signature is invalid.");
        }

        void Append(ReadOnlySpan<byte> value) { value.CopyTo(identityTuple.AsSpan(offset)); offset += value.Length; }
        void U64(ulong value) { BinaryPrimitives.WriteUInt64BigEndian(identityTuple.AsSpan(offset, 8), value); offset += 8; }
        static void ThrowInvalid(string message) =>
            throw new RecordException(RecordError.InvalidField, message);
    }

    private void VerifyHistoricalResetAuthorization(VerifiedIdentityRelative currentIdentity)
    {
        var resetRows = Artifacts.Where(static value => value.ArtifactType == ArtifactType.Dra1).ToArray();
        if (resetRows.Length == 0) return;
        if (resetRows.Length != 1)
            throw new RecordException(RecordError.InvalidField,
                "DRM20 contains duplicate DRA1 rows.");
        var dra = CanonicalGrammar.DecodeOwned(
            resetRows[0].CanonicalBytes.Span, RecordDefinitions.Dra1);
        var rah = Manifest.ResetAuthorityHead;
        var currentAccount = currentIdentity.Account.Certificate.Record;
        var currentDcmReference = Manifest.PinCoreProjection.Slice(72, 38);
        if (!CanonicalGrammar.FixedEquals(dra.FieldSpan(1), currentAccount.FieldSpan(1)) ||
            Scalars.UInt64(dra.FieldSpan(9)) != currentIdentity.Account.Certificate.AccountGeneration ||
            !CanonicalGrammar.FixedEquals(dra.FieldSpan(10), Manifest.PinCoreProjection.Slice(26, 38)) ||
            !CanonicalGrammar.FixedEquals(dra.FieldSpan(12), currentDcmReference) ||
            rah[166] != 1 ||
            !CanonicalGrammar.FixedEquals(rah.Slice(167, 38), resetRows[0].ArtifactReference.Span))
            throw new RecordException(RecordError.InvalidField,
                "DRA1 does not bind the exact current DRM20 identity and RAH1.");
        var signing = CanonicalGrammar.GetSigningBytes(dra, "Deep/Cutover/V1/account-reset");
        VerifyDetached(dra.FieldSpan(19), signing, rah.Slice(297, 32));
        VerifyDetached(dra.FieldSpan(20), signing, currentAccount.FieldSpan(5));
        VerifyDetached(dra.FieldSpan(21), signing,
            currentIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl)
                .CurrentEd25519PublicKey.Span);

        static void VerifyDetached(
            ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
        {
            if (signature.Length != 64 || publicKey.Length != 32 ||
                !Sodium.PublicKeyAuth.VerifyDetached(
                    signature.ToArray(), message.ToArray(), publicKey.ToArray()))
                throw new RecordException(RecordError.InvalidSignature,
                    "The recovered DRA1 signature is invalid.");
        }
    }

    internal static void VerifyDwhHeads(
        WitnessDelegation predecessor,
        WitnessDelegation successor,
        ReadOnlySpan<byte> heads)
    {
        var predecessorRows = predecessor.Record.FieldSpan(14);
        var successorRows = successor.Record.FieldSpan(14);
        var retained = 0;
        for (var index = 0; index < 4; index++)
        {
            var head = heads.Slice(index * 72, 72);
            var priorDescriptor = predecessorRows.Slice(index * 116, 116);
            if (!CanonicalGrammar.FixedEquals(head[..32], priorDescriptor[..32]))
                throw new RecordException(RecordError.InvalidField,
                    "DWH1 predecessor head order differs from the prior DWD1 descriptors.");
            var treeSize = BinaryPrimitives.ReadUInt64BigEndian(head[32..40]);
            if (treeSize > predecessor.MaximumTreeSize)
                throw new RecordException(RecordError.InvalidField,
                    "A DWH1 predecessor head exceeds the prior maximum tree size.");
            if (treeSize == 0)
            {
                var expected = WitnessTreeVerifier.EmptyRoot(
                    predecessor.WitnessEpoch, head[..32], predecessor.MaximumTreeSize);
                if (!CanonicalGrammar.FixedEquals(head[40..72], expected))
                    throw new RecordException(RecordError.InvalidField,
                        "A DWH1 empty predecessor head has the wrong root.");
            }
            else if (CanonicalGrammar.IsZero(head[40..72]))
                throw new RecordException(RecordError.InvalidField,
                    "A nonempty DWH1 predecessor head has a zero root.");

            for (var next = 0; next < 4; next++)
            {
                var successorDescriptor = successorRows.Slice(next * 116, 116);
                if (CanonicalGrammar.FixedEquals(head[..32], successorDescriptor[..32]))
                {
                    if (treeSize > successor.MaximumTreeSize)
                        throw new RecordException(RecordError.InvalidField,
                            "A retained DWH1 head exceeds the successor maximum tree size.");
                    retained++;
                    break;
                }
            }
        }
        Span<byte> payload = stackalloc byte[296];
        BinaryPrimitives.WriteUInt64BigEndian(payload, predecessor.WitnessEpoch);
        heads.CopyTo(payload[8..]);
        if (retained != 3 || !CanonicalGrammar.FixedEquals(
                successor.Record.FieldSpan(12), CanonicalGrammar.Sha256Domain(
                    "Deep/Cutover/V1/witness-heads", payload)))
            throw new RecordException(RecordError.InvalidField,
                "DWH1 does not bind exactly three retained heads and the successor commitment.");
    }
    public IReadOnlyList<RecoveryArtifactCandidate> Artifacts
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return _artifacts.ToArray();
        }
    }

    internal byte[] CopyArtifact(int index)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return Manifest.RowBytes(index).ToArray();
    }

    private byte[] CopyOwned(ReadOnlySpan<byte> value)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return value.ToArray();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Manifest.Dispose();
        CryptographicOperations.ZeroMemory(LatchKey);
        CryptographicOperations.ZeroMemory(LatchValue);
        var drmHash = Interlocked.Exchange(ref _drmHash, null);
        if (drmHash is not null) CryptographicOperations.ZeroMemory(drmHash);
        var rfcHmac = Interlocked.Exchange(ref _rfcVerifiedHmac, null);
        var rahHmac = Interlocked.Exchange(ref _rahVerifiedHmac, null);
        var dtcHmac = Interlocked.Exchange(ref _dtcVerifiedHmac, null);
        var dwhHmac = Interlocked.Exchange(ref _dwhVerifiedHmac, null);
        if (rfcHmac is not null) CryptographicOperations.ZeroMemory(rfcHmac);
        if (rahHmac is not null) CryptographicOperations.ZeroMemory(rahHmac);
        if (dtcHmac is not null) CryptographicOperations.ZeroMemory(dtcHmac);
        if (dwhHmac is not null) CryptographicOperations.ZeroMemory(dwhHmac);
    }
}

/// <summary>One exact, closed-map DRM2 row owned by a recovery candidate plan.</summary>
public sealed class RecoveryArtifactCandidate
{
    private readonly RecoveryCandidatePlan _owner;
    private readonly ArtifactReference _reference;
    private readonly int _index;

    internal RecoveryArtifactCandidate(
        RecoveryCandidatePlan owner,
        ArtifactReference reference,
        int index)
    {
        _owner = owner;
        _reference = reference;
        _index = index;
    }

    public ArtifactType ArtifactType => _reference.Type;
    public uint CanonicalLength => _reference.CanonicalLength;
    public ReadOnlyMemory<byte> CanonicalHash => _reference.CanonicalHash.ToArray();
    public ReadOnlyMemory<byte> ArtifactReference =>
        CanonicalGrammar.EncodeReference(_reference);
    public ReadOnlyMemory<byte> CanonicalBytes => _owner.CopyArtifact(_index);
}

/// <summary>High-level typed recovery entry point; it never accepts raw protector keys.</summary>
public static partial class RecoveryVerifier
{
    /// <summary>
    /// Freezes the sole normal-store recovery branch from exact sealed current facts. It does
    /// not decrypt, commit, publish, or convert relative facts into consumer authority.
    /// </summary>
    public static async ValueTask<VerifiedPredecessorCutoverContext> CreateNormalExpectedCandidateAsync(
        ReadOnlyMemory<byte> canonicalDrc1,
        ReadOnlyMemory<byte> exactRecoveryShadowManifest723,
        CurrentCutoverRelative currentCutover,
        ReleaseRootRestoreRelative releaseRoot,
        VerifiedIdentityRelative identity,
        VerifiedDeviceRelative device,
        VerifiedMailboxRelative mailbox,
        CurrentDnrcRelative router,
        NormalRecoveryStoreInput protectedContainers,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentCutover);
        ArgumentNullException.ThrowIfNull(releaseRoot);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(mailbox);
        ArgumentNullException.ThrowIfNull(router);
        ArgumentNullException.ThrowIfNull(protectedContainers);
        ArgumentNullException.ThrowIfNull(protectedHmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        CanonicalGrammar.Preflight(canonicalDrc1.Span, RecordDefinitions.Drc1);
        RecoveryShadow.Preflight(exactRecoveryShadowManifest723.Span);
        var drc = canonicalDrc1.ToArray();
        var rsm = exactRecoveryShadowManifest723.ToArray();
        var release = new VerifiedCurrentReleaseRootContext(releaseRoot);
        var owned = CanonicalGrammar.DecodeOwned(drc, RecordDefinitions.Drc1);
        var expected = new VerifiedPredecessorCutoverContext(
            currentCutover, owned, rsm, release, identity, device, mailbox, router);
        expected.VerifyNormalAuthority(protectedContainers.Dtc);
        if (!CanonicalGrammar.FixedEquals(protectedContainers.Rfc.Slice(6,160),
                protectedContainers.Rah.Slice(6,160)) ||
            !CanonicalGrammar.FixedEquals(protectedContainers.Rfc.Slice(6,160),
                protectedContainers.Dtc.Slice(6,160)) ||
            !CanonicalGrammar.FixedEquals(protectedContainers.Rfc.Slice(6,160),
                protectedContainers.Dwh.Slice(6,160)) ||
            !CanonicalGrammar.FixedEquals(protectedContainers.Rfc.Slice(6,16),
                currentCutover.TrustedNetwork) ||
            !CanonicalGrammar.FixedEquals(protectedContainers.Rfc.Slice(64,38),
                currentCutover.TrustedDplRef) ||
            !CanonicalGrammar.FixedEquals(protectedContainers.Rfc.Slice(102,32),
                rsm.AsSpan(691,32)) ||
            !CanonicalGrammar.FixedEquals(protectedContainers.Rfc.Slice(134,32),
                owned.FieldSpan(3)) ||
            !CanonicalGrammar.FixedEquals(protectedContainers.Rfc.Slice(protectedContainers.Rfc.Length-64,32),
                protectedContainers.Rah.Slice(protectedContainers.Rah.Length-64,32)) ||
            !CanonicalGrammar.FixedEquals(protectedContainers.Rfc.Slice(protectedContainers.Rfc.Length-64,32),
                protectedContainers.Dtc.Slice(protectedContainers.Dtc.Length-64,32)) ||
            !CanonicalGrammar.FixedEquals(protectedContainers.Rfc.Slice(protectedContainers.Rfc.Length-64,32),
                protectedContainers.Dwh.Slice(protectedContainers.Dwh.Length-64,32)) ||
            !CanonicalGrammar.FixedEquals(protectedContainers.Rfc.Slice(protectedContainers.Rfc.Length-64,32),
                expected.ProtectedStateHmacKeyId))
            throw new RecordException(RecordError.InvalidField,
                "The normal-store RFC1/RAH1/DTC1/DWH1 source or shared HMAC key differs.");
        var rfc = await VerifyContainerAsync("Deep/ProtectedState/V1/RFC1",
            protectedContainers.Rfc.ToArray(), protectedHmacProvider, cancellationToken).ConfigureAwait(false);
        var rah = await VerifyContainerAsync("Deep/ProtectedState/V1/RAH1",
            protectedContainers.Rah.ToArray(), protectedHmacProvider, cancellationToken).ConfigureAwait(false);
        var dtc = await VerifyContainerAsync("Deep/ProtectedState/V1/DTC2",
            protectedContainers.Dtc.ToArray(), protectedHmacProvider, cancellationToken).ConfigureAwait(false);
        var dwh = await VerifyContainerAsync("Deep/ProtectedState/V1/DWH1",
            protectedContainers.Dwh.ToArray(), protectedHmacProvider, cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(rfc); CryptographicOperations.ZeroMemory(rah);
        CryptographicOperations.ZeroMemory(dtc);
        CryptographicOperations.ZeroMemory(dwh);
        cancellationToken.ThrowIfCancellationRequested();
        if (!CanonicalGrammar.FixedEquals(rsm.AsSpan(339,32),
                RecoveryShadow.ComputeFrontierCheckpointHash(protectedContainers.Rfc)) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(403,32),
                RecoveryShadow.ComputeResetAuthorityHeadHash(protectedContainers.Rah)) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(435,32),
                CanonicalGrammar.Sha256Domain("Deep/Cutover/V1/recovery-drt-catalog",protectedContainers.Dtc)) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(467,32),
                RecoveryShadow.ComputeWitnessHeadHistoryHash(protectedContainers.Dwh)))
            throw new RecordException(RecordError.InvalidField,
                "The normal-store protected-container hashes differ from RSM2.");
        return expected;
    }

    private static async ValueTask<byte[]> VerifyContainerAsync(
        string domain, ReadOnlyMemory<byte> canonical, IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        var key = canonical.Slice(canonical.Length-64,32).ToArray();
        var unsigned = canonical[..^32].ToArray();
        var stored = canonical[^32..].ToArray();
        var returned = await provider.ComputeTagAsync(new ProtectedHmacRequest(
            domain,ArtifactRegistry.ProtectedHmacSha256,key,unsigned),cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var result=returned.ToArray();
        if(result.Length!=32 || !CanonicalGrammar.FixedEquals(result,stored))
            throw new RecordException(RecordError.InvalidSignature,
                "A normal-store recovery container HMAC is invalid.");
        return result;
    }

    public static ValueTask<RecoveryCandidatePlan> OpenCandidateAsync(
        ReadOnlyMemory<byte> canonicalDrc1,
        VerifiedPredecessorCutoverContext expected,
        RecoveryProtectorProvider provider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken = default) =>
        RecoveryEngine.OpenCandidateAsync(
            canonicalDrc1,
            expected,
            provider,
            nonceLatch,
            protectedHmacProvider,
            cancellationToken);

    public static ValueTask<RecoveryCandidatePlan> OpenGenesisAuthorReplayCandidateAsync(
        VerifiedGenesisArtifactSet artifactSet,
        GenesisAuthorJournalSnapshot journal,
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisProtectedKeySetContext keySet,
        GenesisRecoveryProtectorContext protector,
        GenesisCutoverSourceContext source,
        RecoveryProtectorProvider provider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken = default) =>
        RecoveryEngine.OpenGenesisAuthorReplayAsync(
            artifactSet, journal, identity, intent, release, keySet, protector, source,
            provider, nonceLatch, protectedHmacProvider, cancellationToken);
}

internal static class RecoveryEngine
{
    private const string LatchDomain = "Deep/Cutover/V1/recovery-aead";

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    // Compiled only into the test-project reference instance. Production builds and packages do
    // not contain this method or any path that can return a candidate before protected HMACs.
    internal static async ValueTask<RecoveryCandidatePlan> OpenUnverifiedCandidateForTestsAsync(
        ReadOnlyMemory<byte> canonicalDrc1,
        RecoveryProtectorProvider provider,
        RecoveryNonceLatch nonceLatch,
        CancellationToken cancellationToken)
    {
        var record = CanonicalGrammar.DecodeOwned(canonicalDrc1.Span, RecordDefinitions.Drc1);
        var opened = await DecryptPayloadAsync(
            record, record.FieldCopy(13), provider, nonceLatch, cancellationToken).ConfigureAwait(false);
        try
        {
            var hmacs = (
                opened.Manifest.RfcStoredHmac.ToArray(),
                opened.Manifest.RahStoredHmac.ToArray(),
                opened.Manifest.DtcStoredHmac.ToArray(),
                opened.Manifest.DwhStoredHmac.ToArray());
            return opened.TakeCandidate(hmacs);
        }
        catch
        {
            opened.Dispose();
            throw;
        }
    }
#endif

    internal static RecoveryProviderRegistryRequest CreateColdProviderRegistryRequest(
        ColdRecoveryInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var record = CanonicalGrammar.DecodeOwned(input.Drc.Span, RecordDefinitions.Drc1);
        VerifyColdPreProvider(record, input.Rsm.Span);
        return new RecoveryProviderRegistryRequest(record);
    }

    internal static async ValueTask<RecoveryCandidatePlan> OpenColdPayloadAsync(
        ColdRecoveryInput input,
        RecoveryProviderRegistryContext providerContext,
        RecoveryProtectorProvider provider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(providerContext);
        ArgumentNullException.ThrowIfNull(protectedHmacProvider);
        var record = CanonicalGrammar.DecodeOwned(input.Drc.Span, RecordDefinitions.Drc1);
        VerifyColdPreProvider(record, input.Rsm.Span);
        if (!providerContext.Matches(new RecoveryProviderRegistryRequest(record)))
            Invalid(RecordError.InvalidField,
                "The sealed recovery provider context differs from the DRC operation selector.");
        var opened = await DecryptPayloadAsync(
            record, providerContext.RecoveryNonceLatchKeyId.ToArray(), provider, nonceLatch,
            cancellationToken).ConfigureAwait(false);
        try
        {
            var hmacs = await VerifyColdManifestAsync(
                opened.Manifest, record, input.Rsm,
                providerContext.ProtectedStateHmacKeyId.ToArray(),
                providerContext.TrustedResetId.ToArray(), protectedHmacProvider,
                cancellationToken).ConfigureAwait(false);
            return opened.TakeCandidate(hmacs);
        }
        catch
        {
            opened.Dispose();
            throw;
        }
    }

    internal static async ValueTask<RecoveryCandidatePlan> OpenCandidateAsync(
        ReadOnlyMemory<byte> canonicalDrc1,
        VerifiedPredecessorCutoverContext expected,
        RecoveryProtectorProvider provider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(protectedHmacProvider);
        var frozen = canonicalDrc1.ToArray();
        var record = CanonicalGrammar.DecodeOwned(frozen, RecordDefinitions.Drc1);
        VerifyPreProvider(record, expected);
        var opened = await DecryptPayloadAsync(
            record, expected.RecoveryNonceLatchKeyId.ToArray(), provider, nonceLatch,
            cancellationToken).ConfigureAwait(false);
        try
        {
            var hmacs = await VerifyContainersAsync(
                opened.Manifest, expected.ProtectedStateHmacKeyId.ToArray(),
                protectedHmacProvider, cancellationToken).ConfigureAwait(false);
            opened.Manifest.VerifyAuthenticatedAuthorityPartitions();
            VerifyPostOpen(record, opened.Manifest, expected);
            return opened.TakeCandidate(hmacs);
        }
        catch
        {
            opened.Dispose();
            throw;
        }
    }

    internal static async ValueTask<RecoveryCandidatePlan> OpenGenesisAuthorReplayAsync(
        VerifiedGenesisArtifactSet artifactSet,
        GenesisAuthorJournalSnapshot journal,
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisProtectedKeySetContext keySet,
        GenesisRecoveryProtectorContext protector,
        GenesisCutoverSourceContext source,
        RecoveryProtectorProvider provider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken) =>
        await OpenGenesisStoredCandidateAsync(
            artifactSet, journal, identity, intent, release, keySet, protector, source,
            provider, nonceLatch, protectedHmacProvider, cancellationToken)
            .ConfigureAwait(false);

    internal static async ValueTask<RecoveryCandidatePlan> OpenGenesisPreJournalAsync(
        VerifiedGenesisArtifactSet artifactSet,
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisProtectedKeySetContext keySet,
        GenesisRecoveryProtectorContext protector,
        GenesisCutoverSourceContext source,
        RecoveryProtectorProvider provider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken) =>
        await OpenGenesisStoredCandidateAsync(
            artifactSet, null, identity, intent, release, keySet, protector, source,
            provider, nonceLatch, protectedHmacProvider, cancellationToken)
            .ConfigureAwait(false);

    private static async ValueTask<RecoveryCandidatePlan> OpenGenesisStoredCandidateAsync(
        VerifiedGenesisArtifactSet artifactSet,
        GenesisAuthorJournalSnapshot? journal,
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisProtectedKeySetContext keySet,
        GenesisRecoveryProtectorContext protector,
        GenesisCutoverSourceContext source,
        RecoveryProtectorProvider provider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(artifactSet);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(keySet);
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(protectedHmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (!ReferenceEquals(intent.Identity, identity) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.Network, release.Network) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, release.ResetId) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.Network, keySet.Network) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, keySet.ResetId) ||
            identity.BaseIdentity.AccountGeneration != keySet.AccountGeneration ||
            intent.ComponentKind != keySet.ComponentKind ||
            !CanonicalGrammar.FixedEquals(intent.ComponentSubject.Span, keySet.ComponentSubject) ||
            !CanonicalGrammar.FixedEquals(identity.Scope.ExactScope, protector.ExactScope))
            Invalid(RecordError.InvalidField,
                "The genesis replay contexts combine different sealed axes.");
        var drcBytes = artifactSet.Artifacts[0].ToArray();
        var record = CanonicalGrammar.DecodeOwned(drcBytes, RecordDefinitions.Drc1);
        var journalBytes = journal?.CanonicalJournal.ToArray();
        if (!CanonicalGrammar.FixedEquals(record.FieldSpan(1), identity.BaseIdentity.Network) ||
            !CanonicalGrammar.FixedEquals(record.FieldSpan(2), intent.ComponentSubject.Span) ||
            !CanonicalGrammar.FixedEquals(record.FieldSpan(3), identity.Transaction.TransactionId) ||
            Scalars.UInt64(record.FieldSpan(4)) != identity.BaseIdentity.AccountGeneration ||
            !CanonicalGrammar.FixedEquals(record.FieldSpan(5), CanonicalGrammar.EncodeReference(
                CanonicalGrammar.ComputeReference(ArtifactType.Dcm1,
                    identity.BaseIdentity.Manifest.CanonicalBytes.Span))) ||
            !CanonicalGrammar.FixedEquals(record.FieldSpan(6), CanonicalGrammar.EncodeReference(
                CanonicalGrammar.ComputeReference(ArtifactType.Drs1,
                    identity.BaseIdentity.Identity.Revocations.Snapshot.CanonicalBytes.Span))) ||
            !CanonicalGrammar.FixedEquals(record.FieldSpan(13), protector.ProtectorKeyId) ||
            (journalBytes is not null &&
             (!CanonicalGrammar.FixedEquals(journalBytes.AsSpan(227, 38),
                  CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                      ArtifactType.Drc1, record.CanonicalSpan))) ||
              !CanonicalGrammar.FixedEquals(journalBytes.AsSpan(493, 32),
                  artifactSet.Receipt.ReceiptHash.Span) ||
              !CanonicalGrammar.FixedEquals(journalBytes.AsSpan(775, 32),
                  artifactSet.Receipt.CanonicalReceipt.Span.Slice(164, 32)))))
            Invalid(RecordError.InvalidField,
                "The stored genesis DRC1/GAS1/GAJ1 tuple differs before provider work.");
        var opened = await DecryptPayloadAsync(
            record, protector.RecoveryNonceLatchKeyId.ToArray(), provider, nonceLatch,
            cancellationToken).ConfigureAwait(false);
        try
        {
            var hmacs = await VerifyContainersAsync(
                opened.Manifest, identity.ProtectedStateHmacKeyId.ToArray(),
                protectedHmacProvider, cancellationToken).ConfigureAwait(false);
            opened.Manifest.VerifyAuthenticatedAuthorityPartitions();
            var rsm = GenesisRecoveryManifestAuthor.BuildRsm(
                identity, intent, release, source, opened.Manifest);
            if (!CanonicalGrammar.FixedEquals(record.FieldSpan(7),
                    CanonicalGrammar.Sha256Domain(
                        "Deep/Cutover/V1/recovery-pin-core", opened.Manifest.PinCoreProjection)) ||
                !CanonicalGrammar.FixedEquals(record.FieldSpan(8),
                    RecoveryShadow.ComputeShadowHash(rsm)) ||
                (journalBytes is not null &&
                 !CanonicalGrammar.FixedEquals(journalBytes.AsSpan(195, 32),
                     RecoveryShadow.ComputeShadowHash(rsm))) ||
                !CanonicalGrammar.FixedEquals(rsm.AsSpan(135, 32), source.GenesisAnchorHash.Span) ||
                !CanonicalGrammar.FixedEquals(rsm.AsSpan(691, 32), source.OldProtectedSource))
                Invalid(RecordError.InvalidField,
                    "The authenticated genesis DRM20 differs from its sealed replay context.");
            return opened.TakeCandidate(hmacs);
        }
        catch
        {
            opened.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(drcBytes);
            if (journalBytes is not null) CryptographicOperations.ZeroMemory(journalBytes);
        }
    }

    private static async ValueTask<(byte[] Rfc, byte[] Rah, byte[] Dtc, byte[] Dwh)> VerifyColdManifestAsync(
        OwnedRecoveryManifest manifest,
        OwnedRecord record,
        ReadOnlyMemory<byte> exactRsm723,
        ReadOnlyMemory<byte> expectedProtectedStateHmacKeyId,
        ReadOnlyMemory<byte> expectedResetId,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(protectedHmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        RecoveryShadow.Preflight(exactRsm723.Span);
        var rsm = exactRsm723.ToArray();
        // Before container HMACs, trust only externally frozen DRC/RSM bindings, public
        // framing and the shared key selectors. Full-container hashes are meaningful only
        // after their stored HMACs have been verified.
        if (!CanonicalGrammar.FixedEquals(record.FieldSpan(7),
                CanonicalGrammar.Sha256Domain("Deep/Cutover/V1/recovery-pin-core",
                    manifest.PinCoreProjection)) ||
            !CanonicalGrammar.FixedEquals(record.FieldSpan(8), RecoveryShadow.ComputeShadowHash(rsm)) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(275,32), CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-drm-hash", manifest.CanonicalSpan)) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(307,32), RecoveryShadow.ComputeInventoryHash(manifest)) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(371,32), CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-predecessor-frontier", manifest.PredecessorFrontier)) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(499,32), manifest.RfcProtectedKeyId) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(531,32), manifest.DtcProtectedKeyId) ||
            !CanonicalGrammar.FixedEquals(manifest.RfcProtectedKeyId, manifest.RahProtectedKeyId) ||
            !CanonicalGrammar.FixedEquals(manifest.RfcProtectedKeyId, manifest.DtcProtectedKeyId) ||
            !CanonicalGrammar.FixedEquals(manifest.RfcProtectedKeyId, manifest.DwhProtectedKeyId) ||
            !CanonicalGrammar.FixedEquals(manifest.RfcProtectedKeyId,
                expectedProtectedStateHmacKeyId.Span) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(563,32), RecoveryShadow.ComputeSchemaFingerprint()))
            Invalid(RecordError.InvalidField,
                "The cold DRM20/RSM2/DRC1 binding or protected key tuple is invalid.");
        var hmacs = await VerifyContainersAsync(
            manifest, expectedProtectedStateHmacKeyId, protectedHmacProvider,
            cancellationToken).ConfigureAwait(false);
        manifest.VerifyAuthenticatedAuthorityPartitions();
        var source = manifest.RfcSourceTuple.ToArray();
        var projection = manifest.PinCoreProjection.ToArray();
        var dcm = FindManifestRecord(manifest, ArtifactType.Dcm1, RecordDefinitions.Dcm1);
        if (!CanonicalGrammar.FixedEquals(dcm.FieldSpan(2), expectedResetId.Span) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(339,32),
                RecoveryShadow.ComputeFrontierCheckpointHash(manifest.FrontierCheckpoint)) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(403,32),
                RecoveryShadow.ComputeResetAuthorityHeadHash(manifest.ResetAuthorityHead)) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(435,32), CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/recovery-drt-catalog", manifest.DrtCatalog)) ||
            !CanonicalGrammar.FixedEquals(rsm.AsSpan(467,32),
                RecoveryShadow.ComputeWitnessHeadHistoryHash(manifest.WitnessHeadHistory)) ||
            !CanonicalGrammar.FixedEquals(source[..16], record.FieldSpan(1)) ||
            !CanonicalGrammar.FixedEquals(source.AsSpan(0,16), rsm.AsSpan(6,16)) ||
            !CanonicalGrammar.FixedEquals(source.AsSpan(16,32), dcm.FieldSpan(2)) ||
            !CanonicalGrammar.FixedEquals(source.AsSpan(48,2), rsm.AsSpan(22,2)) ||
            !CanonicalGrammar.FixedEquals(source.AsSpan(48,2), projection.AsSpan(16,2)) ||
            !CanonicalGrammar.FixedEquals(source.AsSpan(50,8), rsm.AsSpan(88,8)) ||
            !CanonicalGrammar.FixedEquals(source.AsSpan(50,8), projection.AsSpan(18,8)) ||
            !CanonicalGrammar.FixedEquals(source.AsSpan(58,38), rsm.AsSpan(97,38)) ||
            !CanonicalGrammar.FixedEquals(source.AsSpan(96,32), rsm.AsSpan(691,32)) ||
            !CanonicalGrammar.FixedEquals(source.AsSpan(128,32), record.FieldSpan(3)) ||
            !CanonicalGrammar.FixedEquals(source.AsSpan(128,32), rsm.AsSpan(56,32)))
            Invalid(RecordError.InvalidField,
                "The authenticated RFC1 source tuple differs from DRC1/RSM2/DRM20.");
        return hmacs;
    }

    private static void VerifyColdPreProvider(OwnedRecord record, ReadOnlySpan<byte> rsm)
    {
        RecoveryShadow.Preflight(rsm);
        var matches =
            CanonicalGrammar.FixedEquals(record.FieldSpan(1), rsm.Slice(6,16)) &
            CanonicalGrammar.FixedEquals(record.FieldSpan(2), rsm.Slice(24,32)) &
            CanonicalGrammar.FixedEquals(record.FieldSpan(3), rsm.Slice(56,32)) &
            CanonicalGrammar.FixedEquals(record.FieldSpan(4), rsm.Slice(88,8)) &
            CanonicalGrammar.FixedEquals(record.FieldSpan(5), rsm.Slice(167,38)) &
            CanonicalGrammar.FixedEquals(record.FieldSpan(6), rsm.Slice(205,38)) &
            CanonicalGrammar.FixedEquals(record.FieldSpan(7), rsm.Slice(243,32)) &
            CanonicalGrammar.FixedEquals(record.FieldSpan(8), RecoveryShadow.ComputeShadowHash(rsm));
        if (!matches)
            Invalid(RecordError.InvalidField,
                "The frozen cold DRC1 tuple differs from its exact RSM2 before provider work.");
    }

    private static OwnedRecord FindManifestRecord(
        OwnedRecoveryManifest manifest, ArtifactType type, RecordDefinition definition)
    {
        var found = -1;
        for (var index = 0; index < manifest.Rows.Count; index++)
            if (manifest.Rows[index].Reference.Type == type)
            {
                if (found >= 0)
                    Invalid(RecordError.InvalidField, $"DRM2 contains duplicate {type} rows.");
                found = index;
            }
        if (found < 0)
            Invalid(RecordError.InvalidField, $"DRM2 requires exactly one {type} row.");
        return CanonicalGrammar.DecodeOwned(manifest.RowBytes(found), definition);
    }

    private static async ValueTask<OpenedRecoveryPayload> DecryptPayloadAsync(
        OwnedRecord record,
        ReadOnlyMemory<byte> recoveryNonceLatchKeyId,
        RecoveryProtectorProvider provider,
        RecoveryNonceLatch nonceLatch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(nonceLatch);
        cancellationToken.ThrowIfCancellationRequested();

        var capsule = new RecoveryCapsule(record);
        var associatedData = BuildAssociatedData(record);
        var request = new RecoveryProviderRequest(record, associatedData);
        var providerNonce = new byte[24];
        byte[]? nonce = null;
        byte[]? providerPlaintext = null;
        byte[]? ownedPlaintext = null;
        byte[]? latchKey = null;
        byte[]? latchValue = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            await provider.DeriveNonceAsync(request, providerNonce, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            nonce = providerNonce.ToArray();
            if (!CanonicalGrammar.FixedEquals(nonce, record.FieldSpan(12)))
                Invalid(RecordError.InvalidSignature, "The derived recovery nonce is invalid.");

            latchKey = new byte[56];
            record.FieldSpan(13).CopyTo(latchKey);
            nonce.CopyTo(latchKey.AsSpan(32));
            latchValue = ComputeLatchValue(record, associatedData);
            var latchRequest = new RecoveryNonceLatchRequest(
                recoveryNonceLatchKeyId.Span, record.FieldSpan(13), nonce, latchValue);
            var decision = await nonceLatch.CompareOrLatchAsync(
                latchRequest,
                cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (decision == RecoveryNonceLatchDecision.ForkLatched ||
                decision is not (RecoveryNonceLatchDecision.Stored or RecoveryNonceLatchDecision.ExactReplay))
                Invalid(RecordError.ForkDetected, "The recovery nonce is reused for different bytes.");

            providerPlaintext = GC.AllocateUninitializedArray<byte>(request.PlaintextLength);
            await provider.OpenAsync(request, providerPlaintext, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            ownedPlaintext = providerPlaintext.ToArray();
            var manifest = RecoveryManifestParser.TakeOwned(
                ownedPlaintext,
                BinaryPrimitives.ReadUInt16BigEndian(record.FieldSpan(9)));
            ownedPlaintext = null;
            try
            {
                var opened = new OpenedRecoveryPayload(
                    capsule, manifest, latchKey, latchValue,
                    decision == RecoveryNonceLatchDecision.ExactReplay);
                latchKey = null;
                latchValue = null;
                return opened;
            }
            catch
            {
                manifest.Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(providerNonce);
            if (nonce is not null) CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(associatedData);
            if (providerPlaintext is not null) CryptographicOperations.ZeroMemory(providerPlaintext);
            if (ownedPlaintext is not null) CryptographicOperations.ZeroMemory(ownedPlaintext);
            if (latchKey is not null) CryptographicOperations.ZeroMemory(latchKey);
            if (latchValue is not null) CryptographicOperations.ZeroMemory(latchValue);
        }
    }

    private static async ValueTask<(byte[] Rfc, byte[] Rah, byte[] Dtc, byte[] Dwh)> VerifyContainersAsync(
        OwnedRecoveryManifest manifest,
        ReadOnlyMemory<byte> expectedProtectedStateHmacKeyId,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        if (!CanonicalGrammar.FixedEquals(
                manifest.RfcProtectedKeyId, manifest.RahProtectedKeyId) ||
            !CanonicalGrammar.FixedEquals(
                manifest.RfcProtectedKeyId, manifest.DtcProtectedKeyId) ||
            !CanonicalGrammar.FixedEquals(
                manifest.RfcProtectedKeyId, manifest.DwhProtectedKeyId) ||
            !CanonicalGrammar.FixedEquals(
                manifest.RfcProtectedKeyId, expectedProtectedStateHmacKeyId.Span))
            Invalid(RecordError.InvalidField,
                "RFC1, RAH1, DTC1 and DWH1 do not use the sealed shared ProtectedStateHmac key ID.");
        var rfc = await VerifyContainerAsync(
            "Deep/ProtectedState/V1/RFC1",
            manifest.RfcProtectedKeyId.ToArray(),
            manifest.FrontierCheckpoint[..^32].ToArray(),
            manifest.RfcStoredHmac.ToArray(),
            provider,
            cancellationToken).ConfigureAwait(false);
        var rah = await VerifyContainerAsync(
            "Deep/ProtectedState/V1/RAH1",
            manifest.RahProtectedKeyId.ToArray(),
            manifest.ResetAuthorityHead[..^32].ToArray(),
            manifest.RahStoredHmac.ToArray(),
            provider,
            cancellationToken).ConfigureAwait(false);
        var dtc = await VerifyContainerAsync(
            "Deep/ProtectedState/V1/DTC2",
            manifest.DtcProtectedKeyId.ToArray(),
            manifest.DrtCatalog[..^32].ToArray(),
            manifest.DtcStoredHmac.ToArray(),
            provider,
            cancellationToken).ConfigureAwait(false);
        var dwh = await VerifyContainerAsync(
            "Deep/ProtectedState/V1/DWH1",
            manifest.DwhProtectedKeyId.ToArray(),
            manifest.WitnessHeadHistory[..^32].ToArray(),
            manifest.DwhStoredHmac.ToArray(),
            provider,
            cancellationToken).ConfigureAwait(false);
        return (rfc, rah, dtc, dwh);
    }

    private sealed class OpenedRecoveryPayload : IDisposable
    {
        private RecoveryCapsule? _capsule;
        private OwnedRecoveryManifest? _manifest;
        private byte[]? _latchKey;
        private byte[]? _latchValue;

        internal OpenedRecoveryPayload(
            RecoveryCapsule capsule,
            OwnedRecoveryManifest manifest,
            byte[] latchKey,
            byte[] latchValue,
            bool exactReplay)
        {
            _capsule = capsule;
            _manifest = manifest;
            _latchKey = latchKey;
            _latchValue = latchValue;
            ExactReplay = exactReplay;
        }

        internal OwnedRecoveryManifest Manifest =>
            _manifest ?? throw new ObjectDisposedException(nameof(OpenedRecoveryPayload));

        internal bool ExactReplay { get; }

        internal RecoveryCandidatePlan TakeCandidate(
            (byte[] Rfc, byte[] Rah, byte[] Dtc, byte[] Dwh) hmacs)
        {
            var capsule = _capsule ?? throw new ObjectDisposedException(nameof(OpenedRecoveryPayload));
            var manifest = _manifest ?? throw new ObjectDisposedException(nameof(OpenedRecoveryPayload));
            var latchKey = _latchKey ?? throw new ObjectDisposedException(nameof(OpenedRecoveryPayload));
            var latchValue = _latchValue ?? throw new ObjectDisposedException(nameof(OpenedRecoveryPayload));
            try
            {
                var candidate = new RecoveryCandidatePlan(
                    capsule, manifest, latchKey, latchValue, ExactReplay,
                    hmacs.Rfc, hmacs.Rah, hmacs.Dtc, hmacs.Dwh);
                _capsule = null;
                _manifest = null;
                _latchKey = null;
                _latchValue = null;
                return candidate;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hmacs.Rfc);
                CryptographicOperations.ZeroMemory(hmacs.Rah);
                CryptographicOperations.ZeroMemory(hmacs.Dtc);
                CryptographicOperations.ZeroMemory(hmacs.Dwh);
            }
        }

        public void Dispose()
        {
            _manifest?.Dispose();
            if (_latchKey is not null) CryptographicOperations.ZeroMemory(_latchKey);
            if (_latchValue is not null) CryptographicOperations.ZeroMemory(_latchValue);
            _capsule = null;
            _manifest = null;
            _latchKey = null;
            _latchValue = null;
        }
    }

    private static async ValueTask<byte[]> VerifyContainerAsync(
        string domain,
        ReadOnlyMemory<byte> keyId,
        ReadOnlyMemory<byte> unsigned,
        ReadOnlyMemory<byte> stored,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        var request = new ProtectedHmacRequest(
            domain,
            ArtifactRegistry.ProtectedHmacSha256,
            keyId.Span,
            unsigned.Span);
        var returned = await provider.ComputeTagAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var owned = returned.ToArray();
        if (owned.Length != 32 || !CanonicalGrammar.FixedEquals(owned, stored.Span))
        {
            CryptographicOperations.ZeroMemory(owned);
            Invalid(RecordError.InvalidSignature, "A protected recovery container HMAC is invalid.");
        }
        return owned;
    }

    private static void VerifyPreProvider(
        OwnedRecord record,
        VerifiedPredecessorCutoverContext expected)
    {
        if (!expected.HasSealedNormalAuthority)
            Invalid(RecordError.InvalidField,
                "Normal recovery requires the complete sealed authority branch.");
        var frozen = expected.PreProviderTuple;
        var matches =
            CryptographicOperations.FixedTimeEquals(record.FieldSpan(1), frozen[..16]) &
            CryptographicOperations.FixedTimeEquals(record.FieldSpan(2), frozen.Slice(16, 32)) &
            CryptographicOperations.FixedTimeEquals(record.FieldSpan(4), frozen.Slice(48, 8)) &
            CryptographicOperations.FixedTimeEquals(record.FieldSpan(5), frozen.Slice(56, 38)) &
            CryptographicOperations.FixedTimeEquals(record.FieldSpan(6), frozen.Slice(94, 38)) &
            CryptographicOperations.FixedTimeEquals(record.FieldSpan(8), frozen.Slice(132, 32)) &
            CryptographicOperations.FixedTimeEquals(record.FieldSpan(7), frozen.Slice(164, 32)) &
            CryptographicOperations.FixedTimeEquals(record.FieldSpan(13), frozen.Slice(196, 32));
        if (!matches)
            Invalid(RecordError.InvalidField,
                "The recovery capsule differs from its sealed expected context.");
    }

    private static void VerifyPostOpen(
        OwnedRecord record,
        OwnedRecoveryManifest manifest,
        VerifiedPredecessorCutoverContext expected)
    {
        var rsm = expected.ShadowManifest;
        var inventoryHash = RecoveryShadow.ComputeInventoryHash(manifest);
        var rpfHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-predecessor-frontier", manifest.PredecessorFrontier);
        var rahHash = RecoveryShadow.ComputeResetAuthorityHeadHash(
            manifest.ResetAuthorityHead);
        var dtcHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-drt-catalog", manifest.DrtCatalog);
        var dwhHash = RecoveryShadow.ComputeWitnessHeadHistoryHash(
            manifest.WitnessHeadHistory);
        var drmHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-drm-hash", manifest.CanonicalSpan);
        var rfcHash = RecoveryShadow.ComputeFrontierCheckpointHash(
            manifest.FrontierCheckpoint);
        if (!CanonicalGrammar.FixedEquals(record.FieldSpan(7),
                CanonicalGrammar.Sha256Domain(
                    "Deep/Cutover/V1/recovery-pin-core", manifest.PinCoreProjection)) ||
            !CanonicalGrammar.FixedEquals(record.FieldSpan(8),
                RecoveryShadow.ComputeShadowHash(rsm)) ||
            !CanonicalGrammar.FixedEquals(rsm.Slice(275, 32), drmHash) ||
            !CanonicalGrammar.FixedEquals(rsm.Slice(307, 32), inventoryHash) ||
            !CanonicalGrammar.FixedEquals(rsm.Slice(339, 32), rfcHash) ||
            !CanonicalGrammar.FixedEquals(rsm.Slice(371, 32), rpfHash) ||
            !CanonicalGrammar.FixedEquals(rsm.Slice(403, 32), rahHash) ||
            !CanonicalGrammar.FixedEquals(rsm.Slice(435, 32), dtcHash) ||
            !CanonicalGrammar.FixedEquals(rsm.Slice(467, 32), dwhHash) ||
            !CanonicalGrammar.FixedEquals(rsm.Slice(499, 32), manifest.RfcProtectedKeyId) ||
            !CanonicalGrammar.FixedEquals(rsm.Slice(531, 32), manifest.DtcProtectedKeyId) ||
            !CanonicalGrammar.FixedEquals(rsm.Slice(563, 32),
                RecoveryShadow.ComputeSchemaFingerprint()) ||
            !CanonicalGrammar.FixedEquals(manifest.RfcSourceTuple[..16], record.FieldSpan(1)) ||
            !CanonicalGrammar.FixedEquals(manifest.RfcSourceTuple.Slice(58, 38),
                rsm.Slice(97, 38)) ||
            !CanonicalGrammar.FixedEquals(manifest.RfcSourceTuple.Slice(96, 32),
                rsm.Slice(691, 32)) ||
            !CanonicalGrammar.FixedEquals(manifest.RfcSourceTuple.Slice(128, 32),
                record.FieldSpan(3)))
            Invalid(RecordError.InvalidField,
                "The owned DRM20/RSM2 recovery source bindings differ.");
        var dcm = Find(manifest, ArtifactType.Dcm1);
        var drs = Find(manifest, ArtifactType.Drs1);
        var dcmRecord = CanonicalGrammar.DecodeOwned(dcm, RecordDefinitions.Dcm1);
        var drsRecord = CanonicalGrammar.DecodeOwned(drs, RecordDefinitions.Drs1);
        var actual = new byte[expected.PostOpenTuple.Length];
        expected.PreProviderTuple.CopyTo(actual);
        var offset = expected.PreProviderTuple.Length;
        Append(dcmRecord.FieldSpan(3)); Append(drsRecord.FieldSpan(4));
        Span<byte> count = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(count,
            BinaryPrimitives.ReadUInt16BigEndian(drsRecord.FieldSpan(9)));
        Append(count); Append(drsRecord.FieldSpan(11)); Append(expected.PostOpenTuple.Slice(490, 32));
        Append(dcm); Append(drs); Append(manifest.PinCoreProjection);
        if (offset != actual.Length ||
            !CryptographicOperations.FixedTimeEquals(actual, expected.PostOpenTuple))
            Invalid(RecordError.InvalidField,
                "The restored recovery closure differs from its sealed current source.");

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(actual.AsSpan(offset));
            offset += value.Length;
        }

        static ReadOnlySpan<byte> Find(OwnedRecoveryManifest value, ArtifactType type)
        {
            for (var index = 0; index < value.Rows.Count; index++)
                if (value.Rows[index].Reference.Type == type) return value.RowBytes(index);
            throw new RecordException(RecordError.InvalidField,
                $"The DRM2 is missing required {type} recovery state.");
        }
    }

    private static byte[] BuildAssociatedData(OwnedRecord record)
    {
        var metadataLength = CanonicalGrammar.HeaderLength;
        for (var tag = 1; tag <= 15; tag++)
            metadataLength = checked(metadataLength + CanonicalGrammar.FieldHeaderLength + record.FieldSpan(tag).Length);
        var output = new byte[4 + metadataLength];
        BinaryPrimitives.WriteUInt32BigEndian(output, checked((uint)metadataLength));
        record.CanonicalSpan[..CanonicalGrammar.HeaderLength].CopyTo(output.AsSpan(4));
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(12, 2), 15);
        var destination = 4 + CanonicalGrammar.HeaderLength;
        var source = CanonicalGrammar.HeaderLength;
        for (var tag = 1; tag <= 15; tag++)
        {
            var fieldLength = record.FieldSpan(tag).Length;
            var framedLength = CanonicalGrammar.FieldHeaderLength + fieldLength;
            record.CanonicalSpan.Slice(source, framedLength).CopyTo(output.AsSpan(destination));
            source += framedLength;
            destination += framedLength;
        }
        return output;
    }

    private static byte[] ComputeLatchValue(OwnedRecord record, ReadOnlySpan<byte> associatedData)
    {
        var domain = Encoding.ASCII.GetBytes(LatchDomain);
        var payloadLength = checked(32u + 4u + (uint)associatedData.Length + 8u +
            (uint)record.FieldSpan(16).Length + 16u);
        Span<byte> scalar = stackalloc byte[8];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        BinaryPrimitives.WriteUInt16BigEndian(scalar[..2], checked((ushort)domain.Length));
        hash.AppendData(scalar[..2]);
        hash.AppendData(domain);
        BinaryPrimitives.WriteUInt32BigEndian(scalar[..4], payloadLength);
        hash.AppendData(scalar[..4]);
        hash.AppendData(record.FieldSpan(3));
        BinaryPrimitives.WriteUInt32BigEndian(scalar[..4], checked((uint)associatedData.Length));
        hash.AppendData(scalar[..4]);
        hash.AppendData(associatedData);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, checked((ulong)record.FieldSpan(16).Length));
        hash.AppendData(scalar);
        hash.AppendData(record.FieldSpan(16));
        hash.AppendData(record.FieldSpan(17));
        return hash.GetHashAndReset();
    }

    private static void Invalid(RecordError error, string message) =>
        throw new RecordException(error, message);
}
