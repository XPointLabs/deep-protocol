using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

/// <summary>Canonical encrypted recovery capsule bytes only; decoding does not decrypt or authorize restore.</summary>
public sealed class RecoveryCapsule : CanonicalCutoverArtifact
{
    internal RecoveryCapsule(OwnedRecord record) : base(record, ArtifactType.Drc1) { }

    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ReadOnlyMemory<byte> ComponentSubject => Record.FieldCopy(2);
    public ReadOnlyMemory<byte> TransactionId => Record.FieldCopy(3);
    public ulong AccountGeneration => Scalars.UInt64(Record.FieldSpan(4));
    public ushort ArtifactCount => Scalars.UInt16(Record.FieldSpan(9));
    public ulong PlaintextLength => Scalars.UInt64(Record.FieldSpan(10));
    public ReadOnlyMemory<byte> ProtectorKeyId => Record.FieldCopy(13);
    public ulong RetainUntilUnixSeconds => Scalars.UInt64(Record.FieldSpan(15));
}

public static class RecoveryCodec
{
    public static RecoveryCapsule DecodeCapsule(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Drc1));
}

public enum RecoveryProtectedKeyKind : ushort
{
    ProtectedStateHmac = 1,
    RecoveryNonceLatch = 2
}

/// <summary>
/// Current ReleaseRoot fingerprint sealed to one complete verified restore result.
/// It carries no deployment or durability authority.
/// </summary>
public sealed class VerifiedCurrentReleaseRootContext
{
    private const string Domain = "Deep/Cutover/V1/recovery-release-context";
    private readonly byte[] _fingerprint;

    internal VerifiedCurrentReleaseRootContext(ReleaseRootRestoreRelative restored)
    {
        ArgumentNullException.ThrowIfNull(restored);
        if ((!restored.IsUsable && !restored.IsTerminal) || restored.ReleaseRoot.Pin is null ||
            (restored.IsTerminal == (restored.Termination is null)) ||
            (restored.IsTerminal == (restored.FreshLease is not null)))
            Invalid("The current ReleaseRoot restore has an invalid terminal/lease shape.");
        var freshLease = restored.FreshLease;
        var root = restored.ReleaseRoot;
        var dwdCanonicals = restored.OrderedDwdCanonicals;
        if (dwdCanonicals.Count is < 1 or > 65) Invalid("The ReleaseRoot DWD ancestry is out of bounds.");
        var transitions = root.Transitions;
        if (transitions.Count > 64) Invalid("The ReleaseRoot transition ancestry is out of bounds.");
        var payload = new byte[16+32+38+8+32+38+38+1+1+8+38+38+38+8+2+38*transitions.Count+2+38*dwdCanonicals.Count];
        var offset = 0;
        Append(root.Manifest.NetworkId.Span);
        Append(root.Manifest.Record.FieldSpan(3));
        Append(CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Rrm1, root.Manifest.CanonicalBytes.Span)));
        U64(root.CurrentGeneration); Append(root.CurrentEd25519PublicKey.Span);
        Append(CanonicalGrammar.EncodeReference(root.CurrentTransitionReference));
        Append(root.PendingTerminalRevocation is null ? new byte[38] :
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Krf1, root.PendingTerminalRevocation.CanonicalBytes.Span)));
        payload[offset++] = restored.IsTerminal ? (byte)1 : (byte)0;
        payload[offset++] = 0;
        U64(restored.LatestDelegation.Delegation.DelegationGeneration);
        Append(CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dwd1, restored.LatestDelegation.Delegation.CanonicalBytes.Span)));
        Append(restored.Termination is null ? new byte[38] :
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dwt1, restored.Termination.Termination.CanonicalBytes.Span)));
        Append(freshLease is null ? new byte[38] :
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dcl1, freshLease.CanonicalBytes.Span)));
        U64(freshLease?.ExpiresAtUnixSeconds ?? 0);
        U16(checked((ushort)transitions.Count));
        foreach (var transition in transitions) Append(CanonicalGrammar.EncodeReference(transition));
        U16(checked((ushort)dwdCanonicals.Count));
        foreach (var canonical in dwdCanonicals) Append(CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dwd1, canonical)));
        if (offset != payload.Length) Invalid("The ReleaseRoot recovery context width drifted.");
        _fingerprint = CanonicalGrammar.Sha256Domain(Domain, payload);
        Restored = restored;

        void Append(ReadOnlySpan<byte> value) { value.CopyTo(payload.AsSpan(offset)); offset += value.Length; }
        void U64(ulong value) { BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(offset,8),value); offset += 8; }
        void U16(ushort value) { BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(offset,2),value); offset += 2; }
    }

    internal ReleaseRootRestoreRelative Restored { get; init; } = null!;
    public ReadOnlyMemory<byte> Fingerprint => _fingerprint.ToArray();
    public bool NoAuthorityClaim => true;

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>
/// Complete identity catalog reconstructed from one authenticated DRM20 payload. The result is
/// evidence-relative only and cannot authorize persistence, cutover, or publication.
/// </summary>
public sealed class VerifiedRecoveredIdentityContext
{
    private readonly byte[] _fingerprint;
    private readonly byte[] _catalogHash;
    private readonly byte[] _deviceHead;
    private readonly byte[] _mailboxHead;
    private readonly byte[] _routerHead;

    internal VerifiedRecoveredIdentityContext(
        VerifiedIdentityRelative identity,
        ReadOnlySpan<byte> fingerprint,
        ReadOnlySpan<byte> catalogHash,
        ReadOnlySpan<byte> deviceHead,
        ReadOnlySpan<byte> mailboxHead,
        ReadOnlySpan<byte> routerHead)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (fingerprint.Length != 32 || catalogHash.Length != 32 ||
            deviceHead.Length != 38 || mailboxHead.Length != 38 || routerHead.Length != 38)
            throw new RecordException(RecordError.InvalidLength,
                "The recovered identity context has an invalid fixed width.");
        Identity = identity;
        _fingerprint = fingerprint.ToArray();
        _catalogHash = catalogHash.ToArray();
        _deviceHead = deviceHead.ToArray();
        _mailboxHead = mailboxHead.ToArray();
        _routerHead = routerHead.ToArray();
    }

    public VerifiedIdentityRelative Identity { get; }
    public ReadOnlyMemory<byte> Fingerprint => _fingerprint.ToArray();
    public ReadOnlyMemory<byte> CatalogHash => _catalogHash.ToArray();
    public ReadOnlyMemory<byte> DeviceRoleHeadReference => _deviceHead.ToArray();
    public ReadOnlyMemory<byte> MailboxRoleHeadReference => _mailboxHead.ToArray();
    public ReadOnlyMemory<byte> RouterRoleHeadReference => _routerHead.ToArray();
    public bool NoAuthorityClaim => true;
}

/// <summary>Owned exact protected RFC1/RAH1/DTC2/DWH1 copies from the current store.</summary>
public sealed class NormalRecoveryStoreInput
{
    private readonly byte[] _rfc;
    private readonly byte[] _rah;
    private readonly byte[] _dtc;
    private readonly byte[] _dwh;

    public NormalRecoveryStoreInput(
        ReadOnlySpan<byte> exactRfc1,
        ReadOnlySpan<byte> exactRah1,
        ReadOnlySpan<byte> exactDtc2,
        ReadOnlySpan<byte> exactDwh1)
    {
        Preflight(exactRfc1, ProtocolMagicBytes.RFC1, RecoveryManifestParser.RfcFixedLength,
            RecoveryManifestParser.RfcEntryLength, RecoveryManifestParser.MaximumFrontierCount);
        Preflight(exactRah1, ProtocolMagicBytes.RAH1, RecoveryManifestParser.RahFixedLength, 0, 0);
        PreflightDtc2(exactDtc2);
        Preflight(exactDwh1, ProtocolMagicBytes.DWH1, RecoveryManifestParser.DwhFixedLength,
            RecoveryManifestParser.DwhEntryLength, 64);
        _rfc = exactRfc1.ToArray(); _rah = exactRah1.ToArray();
        _dtc = exactDtc2.ToArray(); _dwh = exactDwh1.ToArray();
        Preflight(_rfc, ProtocolMagicBytes.RFC1, RecoveryManifestParser.RfcFixedLength,
            RecoveryManifestParser.RfcEntryLength, RecoveryManifestParser.MaximumFrontierCount);
        Preflight(_rah, ProtocolMagicBytes.RAH1, RecoveryManifestParser.RahFixedLength, 0, 0);
        PreflightDtc2(_dtc);
        Preflight(_dwh, ProtocolMagicBytes.DWH1, RecoveryManifestParser.DwhFixedLength,
            RecoveryManifestParser.DwhEntryLength, 64);
    }

    internal ReadOnlySpan<byte> Rfc => _rfc;
    internal ReadOnlySpan<byte> Rah => _rah;
    internal ReadOnlySpan<byte> Dtc => _dtc;
    internal ReadOnlySpan<byte> Dwh => _dwh;
    public bool NoAuthorityClaim => true;

    private static void Preflight(ReadOnlySpan<byte> value, ReadOnlySpan<byte> magic,
        int fixedLength, int entryLength, int maximumCount)
    {
        if (value.Length < fixedLength || !value[..4].SequenceEqual(magic) ||
            value[4] != 1 || value[5] != 0)
            Invalid("A current recovery protected container header is invalid.");
        var count = entryLength == 0 ? 0 : BinaryPrimitives.ReadUInt16BigEndian(value[166..168]);
        if (count > maximumCount || value.Length != checked(fixedLength + entryLength * count) ||
            CanonicalGrammar.IsZero(value.Slice(value.Length - 64,32)))
            Invalid("A current recovery protected container shape or key ID is invalid.");
    }

    private static void PreflightDtc2(ReadOnlySpan<byte> value)
    {
        if (value.Length < RecoveryManifestParser.DtcFixedLength ||
            !value[..4].SequenceEqual(ProtocolMagicBytes.DTC2) || value[4] != 2 || value[5] != 0)
            Invalid("A current recovery DTC2 header is invalid.");
        var targetCount = BinaryPrimitives.ReadUInt16BigEndian(value[166..168]);
        var historyCount = BinaryPrimitives.ReadUInt16BigEndian(value[168..170]);
        if (targetCount > RecoveryManifestParser.MaximumDrtCount || historyCount > targetCount ||
            value.Length != checked(RecoveryManifestParser.DtcFixedLength +
                RecoveryManifestParser.DrtEntryLength * targetCount +
                RecoveryManifestParser.DrtHistoryEntryLength * historyCount) ||
            CanonicalGrammar.IsZero(value.Slice(value.Length - 64, 32)))
            Invalid("A current recovery DTC2 shape or key ID is invalid.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

internal static class RecoveryContextFingerprint
{
    internal static byte[] Identity(
        VerifiedIdentityRelative identity,
        VerifiedDeviceRelative device,
        VerifiedMailboxRelative mailbox,
        CurrentDnrcRelative router,
        CurrentCutoverRelative cutover,
        ReadOnlySpan<byte> dtc)
    {
        if (!ReferenceEquals(device.Identity, identity) || !ReferenceEquals(mailbox.Device, device) ||
            !ReferenceEquals(router.Mailbox.Mailbox, mailbox) || identity.IsTerminal || identity.ForkLatched)
            Invalid("The recovery identity catalog combines unrelated or unusable sealed facts.");
        var account = identity.Account;
        var revocations = identity.Revocations.Snapshot;
        if (!CanonicalGrammar.FixedEquals(account.Certificate.NetworkId.Span, cutover.TrustedNetwork) ||
            account.Certificate.AccountGeneration != cutover.AccountGeneration ||
            !CanonicalGrammar.FixedEquals(account.DeepAccountIdHash.Span, cutover.TrustedAccountHash) ||
            !CanonicalGrammar.FixedEquals(revocations.Record.CanonicalSpan, cutover.TrustedDrs))
            Invalid("The recovery identity and cutover contexts differ.");
        var dtcHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-drt-catalog", dtc);
        var dtcKeyId = dtc.Slice(dtc.Length - 64,32);
        var authorities = Enum.GetValues<KeyScope>().Where(static scope => scope != KeyScope.ReleaseRoot)
            .Select(scope => identity.Authority.GetKeyAuthority(scope)).OrderBy(static value => value.Scope).ToArray();
        var transitions = identity.Authority.OrderedTransitions
            .Where(static value => value.Scope != KeyScope.ReleaseRoot).ToArray();
        var catalog = new byte[16+32+8+32+2+transitions.Length*48+authorities.Length*38+
            2+78+2+78+2+78+38+8+8+32+32+32];
        var offset=0;
        Append(cutover.TrustedNetwork); Append(cutover.TrustedResetId); U64(cutover.AccountGeneration);
        Append(dtcKeyId); U16(checked((ushort)transitions.Length));
        foreach(var transition in transitions)
        {
            catalog[offset++]=transition.Type==ArtifactType.Krt1?(byte)1:(byte)2;
            catalog[offset++]=(byte)transition.Scope; U64(transition.Generation);
            Append(CanonicalGrammar.EncodeReference(transition.Reference));
        }
        foreach(var authority in authorities)
            Append(CanonicalGrammar.EncodeReference(authority.TransitionReference));
        U16(1); Append(device.Certificate.DeviceId.Span); U64(device.Certificate.DeviceGeneration);
        Append(Ref(ArtifactType.Dpd1,device.Certificate.Record));
        U16(1); Append(mailbox.Certificate.MailboxOwnerId.Span); U64(mailbox.Certificate.RoleGeneration);
        Append(Ref(ArtifactType.Dpm1,mailbox.Certificate.Record));
        U16(1); Append(router.RouterId.Span); U64(router.Certificate.RouterGeneration);
        Append(router.Certificate.ArtifactReference.Span);
        Append(cutover.TrustedDrsRef); U64(cutover.DrsRevision); U64(cutover.DrsCount);
        Append(cutover.TrustedDrsHead); Append(dtcHash); Append(dtcKeyId);
        if(offset!=catalog.Length) Invalid("The recovery identity catalog width drifted.");
        var catalogHash=CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-identity-catalog",catalog);
        var identityTuple=new byte[16+32+8+38+38+8+8+32+38+38+38+38+32]; offset=0;
        AppendIdentity(cutover.TrustedNetwork); AppendIdentity(cutover.TrustedResetId); U64Identity(cutover.AccountGeneration);
        AppendIdentity(Ref(ArtifactType.Dpa1,account.Certificate.Record)); AppendIdentity(cutover.TrustedDcmRef);
        U64Identity(cutover.DrsRevision); U64Identity(cutover.DrsCount); AppendIdentity(cutover.TrustedDrsHead);
        AppendIdentity(cutover.TrustedDrsRef); AppendIdentity(Ref(ArtifactType.Dpd1,device.Certificate.Record));
        AppendIdentity(Ref(ArtifactType.Dpm1,mailbox.Certificate.Record));
        AppendIdentity(router.Certificate.ArtifactReference.Span); AppendIdentity(catalogHash);
        if(offset!=identityTuple.Length) Invalid("The recovery identity context width drifted.");
        return CanonicalGrammar.Sha256Domain("Deep/Cutover/V1/recovery-identity-context",identityTuple);

        void Append(ReadOnlySpan<byte> value){value.CopyTo(catalog.AsSpan(offset));offset+=value.Length;}
        void U64(ulong value){BinaryPrimitives.WriteUInt64BigEndian(catalog.AsSpan(offset,8),value);offset+=8;}
        void U16(ushort value){BinaryPrimitives.WriteUInt16BigEndian(catalog.AsSpan(offset,2),value);offset+=2;}
        void AppendIdentity(ReadOnlySpan<byte> value){value.CopyTo(identityTuple.AsSpan(offset));offset+=value.Length;}
        void U64Identity(ulong value){BinaryPrimitives.WriteUInt64BigEndian(identityTuple.AsSpan(offset,8),value);offset+=8;}
    }

    internal static byte[] GenesisIdentity(
        VerifiedIdentityRelative identity,
        VerifiedDeviceRelative device,
        VerifiedMailboxRelative mailbox,
        VerifiedGenesisRouterRelative router,
        CutoverManifest manifest,
        ReadOnlySpan<byte> dtc)
    {
        if (!ReferenceEquals(device.Identity, identity) || !ReferenceEquals(mailbox.Device, device) ||
            !ReferenceEquals(router.Mailbox, mailbox) || identity.IsTerminal || identity.ForkLatched)
            Invalid("The genesis identity catalog combines unrelated or unusable sealed facts.");
        var account = identity.Account;
        var revocations = identity.Revocations.Snapshot;
        var dcm = manifest.Record;
        var network = dcm.FieldSpan(1);
        var resetId = dcm.FieldSpan(2);
        var accountGeneration = Scalars.UInt64(dcm.FieldSpan(4));
        var dcmReference = Ref(ArtifactType.Dcm1, dcm);
        var drsReference = Ref(ArtifactType.Drs1, revocations.Record);
        if (!CanonicalGrammar.FixedEquals(account.Certificate.NetworkId.Span, network) ||
            account.Certificate.AccountGeneration != accountGeneration ||
            !CanonicalGrammar.FixedEquals(dcm.FieldSpan(5), Ref(ArtifactType.Dpa1,
                account.Certificate.Record)) ||
            Scalars.UInt64(dcm.FieldSpan(6)) != revocations.Revision ||
            Scalars.UInt64(dcm.FieldSpan(7)) != revocations.EntryCount ||
            !CanonicalGrammar.FixedEquals(dcm.FieldSpan(8), revocations.CurrentHead.Span) ||
            !CanonicalGrammar.FixedEquals(dcm.FieldSpan(9), drsReference))
            Invalid("The genesis identity and signed DCM/DRS contexts differ.");
        var dtcHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-drt-catalog", dtc);
        var dtcKeyId = dtc.Slice(dtc.Length - 64, 32);
        var authorities = Enum.GetValues<KeyScope>().Where(static scope => scope != KeyScope.ReleaseRoot)
            .Select(scope => identity.Authority.GetKeyAuthority(scope)).OrderBy(static value => value.Scope).ToArray();
        var transitions = identity.Authority.OrderedTransitions
            .Where(static value => value.Scope != KeyScope.ReleaseRoot).ToArray();
        var catalog = new byte[16+32+8+32+2+transitions.Length*48+authorities.Length*38+
            2+78+2+78+2+78+38+8+8+32+32+32];
        var offset = 0;
        Append(network); Append(resetId); U64(accountGeneration);
        Append(dtcKeyId); U16(checked((ushort)transitions.Length));
        foreach (var transition in transitions)
        {
            catalog[offset++] = transition.Type == ArtifactType.Krt1 ? (byte)1 : (byte)2;
            catalog[offset++] = (byte)transition.Scope; U64(transition.Generation);
            Append(CanonicalGrammar.EncodeReference(transition.Reference));
        }
        foreach (var authority in authorities)
            Append(CanonicalGrammar.EncodeReference(authority.TransitionReference));
        U16(1); Append(device.Certificate.DeviceId.Span); U64(device.Certificate.DeviceGeneration);
        Append(Ref(ArtifactType.Dpd1, device.Certificate.Record));
        U16(1); Append(mailbox.Certificate.MailboxOwnerId.Span); U64(mailbox.Certificate.RoleGeneration);
        Append(Ref(ArtifactType.Dpm1, mailbox.Certificate.Record));
        U16(1); Append(router.Certificate.RouterId.Span); U64(router.Certificate.RouterGeneration);
        Append(router.Certificate.ArtifactReference.Span);
        Append(drsReference); U64(revocations.Revision); U64(revocations.EntryCount);
        Append(revocations.CurrentHead.Span); Append(dtcHash); Append(dtcKeyId);
        if (offset != catalog.Length) Invalid("The genesis identity catalog width drifted.");
        var catalogHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-identity-catalog", catalog);
        var identityTuple = new byte[16+32+8+38+38+8+8+32+38+38+38+38+32]; offset = 0;
        AppendIdentity(network); AppendIdentity(resetId); U64Identity(accountGeneration);
        AppendIdentity(Ref(ArtifactType.Dpa1, account.Certificate.Record)); AppendIdentity(dcmReference);
        U64Identity(revocations.Revision); U64Identity(revocations.EntryCount);
        AppendIdentity(revocations.CurrentHead.Span); AppendIdentity(drsReference);
        AppendIdentity(Ref(ArtifactType.Dpd1, device.Certificate.Record));
        AppendIdentity(Ref(ArtifactType.Dpm1, mailbox.Certificate.Record));
        AppendIdentity(router.Certificate.ArtifactReference.Span); AppendIdentity(catalogHash);
        if (offset != identityTuple.Length) Invalid("The genesis identity context width drifted.");
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-identity-context", identityTuple);

        void Append(ReadOnlySpan<byte> value){value.CopyTo(catalog.AsSpan(offset));offset+=value.Length;}
        void U64(ulong value){BinaryPrimitives.WriteUInt64BigEndian(catalog.AsSpan(offset,8),value);offset+=8;}
        void U16(ushort value){BinaryPrimitives.WriteUInt16BigEndian(catalog.AsSpan(offset,2),value);offset+=2;}
        void AppendIdentity(ReadOnlySpan<byte> value){value.CopyTo(identityTuple.AsSpan(offset));offset+=value.Length;}
        void U64Identity(ulong value){BinaryPrimitives.WriteUInt64BigEndian(identityTuple.AsSpan(offset,8),value);offset+=8;}
    }

    internal static byte[] OldProtectedSource(
        byte predecessorKind,
        ReadOnlySpan<byte> oldDplReference,
        ReadOnlySpan<byte> genesisAnchorHash,
        ReadOnlySpan<byte> releaseFingerprint,
        ReadOnlySpan<byte> identityFingerprint,
        ReadOnlySpan<byte> cutoverFingerprint,
        bool terminal,
        ReadOnlySpan<byte> terminalDwtReference,
        ReadOnlySpan<byte> freshDclReference,
        ulong freshDclExpiresAtUnixSeconds,
        ReadOnlySpan<byte> protectedStateHmacKeyId,
        ReadOnlySpan<byte> recoveryNonceLatchKeyId,
        ReadOnlySpan<byte> protectorKeyId)
    {
        if (oldDplReference.Length != 38 || genesisAnchorHash.Length != 32 ||
            releaseFingerprint.Length != 32 ||
            identityFingerprint.Length != 32 || cutoverFingerprint.Length != 32 ||
            terminalDwtReference.Length != 38 || freshDclReference.Length != 38 ||
            protectedStateHmacKeyId.Length != 32 || recoveryNonceLatchKeyId.Length != 32 ||
            protectorKeyId.Length != 32 ||
            (predecessorKind == 1 && (CanonicalGrammar.IsZero(oldDplReference) ||
                !CanonicalGrammar.IsZero(genesisAnchorHash))) ||
            (predecessorKind == 2 && (!CanonicalGrammar.IsZero(oldDplReference) ||
                CanonicalGrammar.IsZero(genesisAnchorHash))) ||
            (predecessorKind is not (1 or 2)) ||
            CanonicalGrammar.IsZero(releaseFingerprint) ||
            CanonicalGrammar.IsZero(identityFingerprint) ||
            CanonicalGrammar.IsZero(cutoverFingerprint) ||
            CanonicalGrammar.IsZero(protectedStateHmacKeyId) ||
            CanonicalGrammar.IsZero(recoveryNonceLatchKeyId) ||
            CanonicalGrammar.IsZero(protectorKeyId) ||
            CanonicalGrammar.FixedEquals(protectedStateHmacKeyId,recoveryNonceLatchKeyId) ||
            (predecessorKind == 1 && terminal &&
                (CanonicalGrammar.IsZero(terminalDwtReference) ||
                 !CanonicalGrammar.IsZero(freshDclReference) ||
                 freshDclExpiresAtUnixSeconds != 0)) ||
            (predecessorKind == 1 && !terminal &&
                (!CanonicalGrammar.IsZero(terminalDwtReference) ||
                 CanonicalGrammar.IsZero(freshDclReference) ||
                 freshDclExpiresAtUnixSeconds == 0)) ||
            (predecessorKind == 2 &&
                (terminal || !CanonicalGrammar.IsZero(terminalDwtReference) ||
                 !CanonicalGrammar.IsZero(freshDclReference) ||
                 freshDclExpiresAtUnixSeconds != 0)))
            Invalid("The recovery old-protected-source tuple has an invalid branch or width.");

        var source=new byte[348];
        var offset=0;
        source[offset++]=predecessorKind;
        Append(oldDplReference);Append(genesisAnchorHash);
        Append(releaseFingerprint);Append(identityFingerprint);
        Append(cutoverFingerprint);source[offset++]=terminal?(byte)1:(byte)0;
        Append(terminalDwtReference);Append(freshDclReference);
        BinaryPrimitives.WriteUInt64BigEndian(source.AsSpan(offset,8),freshDclExpiresAtUnixSeconds);
        offset+=8;
        Append(protectedStateHmacKeyId);Append(recoveryNonceLatchKeyId);Append(protectorKeyId);
        if(offset!=source.Length) Invalid("The recovery old-protected-source tuple length is invalid.");
        var hash=CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V2/recovery-old-protected-source",source);
        CryptographicOperations.ZeroMemory(source);
        return hash;

        void Append(ReadOnlySpan<byte> value)
        {value.CopyTo(source.AsSpan(offset));offset+=value.Length;}
    }

    private static byte[] Ref(ArtifactType type,OwnedRecord record)=>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type,record.CanonicalSpan));
    private static void Invalid(string message)=>
        throw new RecordException(RecordError.InvalidField,message);
}

/// <summary>
/// Complete cryptographic predecessor context relative to one restored current cutover.
/// It carries no durability or activation authority and has no public raw-tuple constructor.
/// </summary>
public sealed class VerifiedPredecessorCutoverContext
{
    private readonly byte[] _preProvider;
    private readonly byte[] _postOpen;
    private readonly byte[] _deploymentSubject;
    private readonly byte[] _shadowManifest;
    private readonly VerifiedCurrentReleaseRootContext _releaseContext;
    private readonly VerifiedIdentityRelative _identity;
    private readonly VerifiedDeviceRelative _device;
    private readonly VerifiedMailboxRelative _mailbox;
    private readonly CurrentDnrcRelative _router;

    internal VerifiedPredecessorCutoverContext(
        CurrentCutoverRelative current,
        OwnedRecord capsule,
        ReadOnlySpan<byte> exactRsm723,
        VerifiedCurrentReleaseRootContext releaseContext,
        VerifiedIdentityRelative identity,
        VerifiedDeviceRelative device,
        VerifiedMailboxRelative mailbox,
        CurrentDnrcRelative router)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(capsule);
        ArgumentNullException.ThrowIfNull(releaseContext);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(mailbox);
        ArgumentNullException.ThrowIfNull(router);
        if (!current.HasRecoveryClosure)
            Invalid("Recovery expectations require a fully restored current cutover.");
        var dcm = CanonicalGrammar.DecodeOwned(current.TrustedDcm, RecordDefinitions.Dcm1);
        var dcp = CanonicalGrammar.DecodeOwned(current.TrustedDcp, RecordDefinitions.Dcp1);
        var drs = CanonicalGrammar.DecodeOwned(current.TrustedDrs, RecordDefinitions.Drs1);
        var dpl = CanonicalGrammar.DecodeOwned(current.TrustedDpl, RecordDefinitions.Dpl1);
        RecoveryShadow.Preflight(exactRsm723);
        _shadowManifest = exactRsm723.ToArray();
        RecoveryShadow.Preflight(_shadowManifest);
        _releaseContext = releaseContext;
        _identity = identity;
        _device = device;
        _mailbox = mailbox;
        _router = router;
        var projection = CreatePinCoreProjection(dpl);
        var pinHash = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/recovery-pin-core", projection);
        var shadowHash = RecoveryShadow.ComputeShadowHash(_shadowManifest);
        var dcmReference = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dcm1, dcm.CanonicalSpan));
        var dcpReference = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dcp1, dcp.CanonicalSpan));
        var drsReference = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Drs1, drs.CanonicalSpan));
        var exactClosure =
            CanonicalGrammar.FixedEquals(dcm.FieldSpan(1), current.TrustedNetwork) &&
            CanonicalGrammar.FixedEquals(dcm.FieldSpan(2), current.TrustedResetId) &&
            Scalars.UInt64(dcm.FieldSpan(3)) == current.DcmGeneration &&
            Scalars.UInt64(dcm.FieldSpan(4)) == current.AccountGeneration &&
            Scalars.UInt64(dcm.FieldSpan(6)) == current.DrsRevision &&
            Scalars.UInt64(dcm.FieldSpan(7)) == current.DrsCount &&
            CanonicalGrammar.FixedEquals(dcm.FieldSpan(8), current.TrustedDrsHead) &&
            CanonicalGrammar.FixedEquals(dcm.FieldSpan(9), current.TrustedDrsRef) &&
            CanonicalGrammar.FixedEquals(dcmReference, current.TrustedDcmRef) &&
            CanonicalGrammar.FixedEquals(dcp.FieldSpan(1), current.TrustedNetwork) &&
            Scalars.UInt16(dcp.FieldSpan(3)) == (ushort)current.ComponentKind &&
            Scalars.UInt64(dcp.FieldSpan(6)) == current.AccountGeneration &&
            CanonicalGrammar.FixedEquals(dcp.FieldSpan(7), current.TrustedDcmRef) &&
            Scalars.UInt64(dcp.FieldSpan(8)) == current.DrsRevision &&
            Scalars.UInt64(dcp.FieldSpan(9)) == current.DrsCount &&
            CanonicalGrammar.FixedEquals(dcp.FieldSpan(10), current.TrustedDrsHead) &&
            CanonicalGrammar.FixedEquals(dcp.FieldSpan(11), current.TrustedDrsRef) &&
            CanonicalGrammar.FixedEquals(dcpReference, current.TrustedDcpRef) &&
            CanonicalGrammar.FixedEquals(drsReference, current.TrustedDrsRef) &&
            CanonicalGrammar.FixedEquals(dpl.FieldSpan(1), current.TrustedNetwork) &&
            Scalars.UInt16(dpl.FieldSpan(2)) == (ushort)current.ComponentKind &&
            Scalars.UInt64(dpl.FieldSpan(3)) == current.AccountGeneration &&
            Scalars.UInt64(dpl.FieldSpan(5)) == current.DcmGeneration &&
            CanonicalGrammar.FixedEquals(dpl.FieldSpan(6), current.TrustedDcmRef) &&
            Scalars.UInt64(dpl.FieldSpan(8)) == current.DrsRevision &&
            Scalars.UInt64(dpl.FieldSpan(9)) == current.DrsCount &&
            CanonicalGrammar.FixedEquals(dpl.FieldSpan(10), current.TrustedDrsHead) &&
            CanonicalGrammar.FixedEquals(dpl.FieldSpan(11), current.TrustedDrsRef) &&
            CanonicalGrammar.FixedEquals(dpl.FieldSpan(12), current.TrustedDcpRef);
        if (!exactClosure) Invalid("The recovery closure differs from the sealed current cutover.");
        if (!CanonicalGrammar.FixedEquals(capsule.FieldSpan(1), current.TrustedNetwork) ||
            !CanonicalGrammar.FixedEquals(capsule.FieldSpan(2), dcp.FieldSpan(2)) ||
            Scalars.UInt64(capsule.FieldSpan(4)) != current.AccountGeneration ||
            !CanonicalGrammar.FixedEquals(capsule.FieldSpan(5), dpl.FieldSpan(6)) ||
            !CanonicalGrammar.FixedEquals(capsule.FieldSpan(6), current.TrustedDrsRef) ||
            !CanonicalGrammar.FixedEquals(capsule.FieldSpan(7), pinHash) ||
            !CanonicalGrammar.FixedEquals(capsule.FieldSpan(8), shadowHash) ||
            !CanonicalGrammar.FixedEquals(_shadowManifest.AsSpan(6, 16), current.TrustedNetwork) ||
            BinaryPrimitives.ReadUInt16BigEndian(_shadowManifest.AsSpan(22, 2)) != (ushort)current.ComponentKind ||
            !CanonicalGrammar.FixedEquals(_shadowManifest.AsSpan(24, 32), dcp.FieldSpan(2)) ||
            !CanonicalGrammar.FixedEquals(_shadowManifest.AsSpan(56, 32), capsule.FieldSpan(3)) ||
            _shadowManifest[96] != 1 ||
            !CanonicalGrammar.FixedEquals(_shadowManifest.AsSpan(97, 38), current.TrustedDplRef) ||
            !CanonicalGrammar.IsZero(_shadowManifest.AsSpan(135, 32)) ||
            !CanonicalGrammar.FixedEquals(_shadowManifest.AsSpan(167, 38), current.TrustedDcmRef) ||
            !CanonicalGrammar.FixedEquals(_shadowManifest.AsSpan(205, 38), current.TrustedDrsRef) ||
            !CanonicalGrammar.FixedEquals(_shadowManifest.AsSpan(243, 32), pinHash))
            Invalid("The recovery capsule is not sealed to the exact current cutover.");

        _deploymentSubject = ComputeDeploymentSubject(
            current.TrustedNetwork, current.TrustedAccountHash, current.TrustedResetId);
        VerifyDistinctComponentAndDeploymentSubjects(capsule.FieldSpan(2), _deploymentSubject);

        _preProvider = new byte[434];
        var offset = 0;
        Append(capsule.FieldSpan(1)); Append(capsule.FieldSpan(2));
        Append(capsule.FieldSpan(4)); Append(capsule.FieldSpan(5)); Append(capsule.FieldSpan(6));
        Append(capsule.FieldSpan(8)); Append(capsule.FieldSpan(7)); Append(capsule.FieldSpan(13));
        Span<byte> scalar = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(scalar, (ushort)current.ComponentKind); Append(scalar);
        Append(dcp.FieldSpan(2)); Append(current.TrustedAccountHash); Append(current.TrustedResetId);
        Append(current.TrustedDplRef);
        BinaryPrimitives.WriteUInt16BigEndian(scalar, 2); Append(scalar);
        BinaryPrimitives.WriteUInt16BigEndian(scalar,
            (ushort)RecoveryProtectedKeyKind.ProtectedStateHmac); Append(scalar);
        Append(current.TrustedDplKeyId);
        BinaryPrimitives.WriteUInt16BigEndian(scalar,
            (ushort)RecoveryProtectedKeyKind.RecoveryNonceLatch); Append(scalar);
        Append(current.TrustedRecoveryNonceLatchKeyId);
        if (CanonicalGrammar.IsZero(current.TrustedDplKeyId) ||
            CanonicalGrammar.IsZero(current.TrustedRecoveryNonceLatchKeyId) ||
            offset != _preProvider.Length ||
            CanonicalGrammar.FixedEquals(current.TrustedDplKeyId,
                current.TrustedRecoveryNonceLatchKeyId))
            Invalid("The recovery protected-key tuple is invalid.");

        _postOpen = new byte[522 + dcm.CanonicalSpan.Length + drs.CanonicalSpan.Length + projection.Length];
        _preProvider.CopyTo(_postOpen, 0);
        offset = _preProvider.Length;
        Span<byte> scalar8 = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(scalar8,
            Scalars.UInt64(dcm.FieldSpan(3))); AppendPost(scalar8);
        BinaryPrimitives.WriteUInt64BigEndian(scalar8, current.DrsRevision); AppendPost(scalar8);
        BinaryPrimitives.WriteUInt64BigEndian(scalar8, current.DrsCount); AppendPost(scalar8);
        AppendPost(current.TrustedDrsHead); AppendPost(_shadowManifest.AsSpan(691,32));
        AppendPost(dcm.CanonicalSpan); AppendPost(drs.CanonicalSpan); AppendPost(projection);
        if (offset != _postOpen.Length) Invalid("The recovery post-open tuple length is invalid.");

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(_preProvider.AsSpan(offset));
            offset += value.Length;
        }
        void AppendPost(ReadOnlySpan<byte> value)
        {
            value.CopyTo(_postOpen.AsSpan(offset));
            offset += value.Length;
        }
    }

    internal ReadOnlySpan<byte> PreProviderTuple => _preProvider;
    internal ReadOnlySpan<byte> PostOpenTuple => _postOpen;
    internal ReadOnlySpan<byte> ShadowManifest => _shadowManifest;
    internal ReadOnlySpan<byte> ProtectedStateHmacKeyId => _preProvider.AsSpan(368, 32);
    internal ReadOnlySpan<byte> RecoveryNonceLatchKeyId => _preProvider.AsSpan(402, 32);
    internal bool HasSealedNormalAuthority => true;

    internal void VerifyNormalAuthority(ReadOnlySpan<byte> dtc)
    {
        var release = _releaseContext;
        var identity = _identity;
        var device = _device;
        var mailbox = _mailbox;
        var router = _router;
        if (!CanonicalGrammar.FixedEquals(_shadowManifest.AsSpan(595,32),
                release.Fingerprint.Span) ||
            !CanonicalGrammar.FixedEquals(_shadowManifest.AsSpan(627,32),
                RecoveryContextFingerprint.Identity(
                    identity,device,mailbox,router,router.Mailbox.Cutover,dtc)) ||
            !CanonicalGrammar.FixedEquals(_shadowManifest.AsSpan(659,32),
                router.Mailbox.Cutover.SourceFingerprint.Span))
            Invalid("The RSM2 recovery authority fingerprints differ from sealed current facts.");
        var current = router.Mailbox.Cutover;
        var restored = release.Restored;
        var freshLease = restored.FreshLease ?? throw new RecordException(
            RecordError.Expired,"The normal recovery ReleaseRoot lease is absent.");
        var oldSourceHash=RecoveryContextFingerprint.OldProtectedSource(
            predecessorKind:1,current.TrustedDplRef,new byte[32],release.Fingerprint.Span,
            _shadowManifest.AsSpan(627,32),
            current.SourceFingerprint.Span,terminal:false,new byte[38],
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dcl1,freshLease.CanonicalBytes.Span)),freshLease.ExpiresAtUnixSeconds,
            ProtectedStateHmacKeyId,current.TrustedRecoveryNonceLatchKeyId,_preProvider.AsSpan(196,32));
        var oldSourceMatches=CanonicalGrammar.FixedEquals(
            _shadowManifest.AsSpan(691,32),oldSourceHash);
        CryptographicOperations.ZeroMemory(oldSourceHash);
        if(!oldSourceMatches)
            Invalid("The RSM2 old protected source differs from sealed current state.");
    }
    public ReadOnlyMemory<byte> DeploymentSubject => _deploymentSubject.ToArray();
    public bool NoAuthorityClaim => true;

    internal static byte[] ComputeDeploymentSubject(
        ReadOnlySpan<byte> network16,
        ReadOnlySpan<byte> accountHash32,
        ReadOnlySpan<byte> resetId32)
    {
        if (network16.Length != 16 || accountHash32.Length != 32 || resetId32.Length != 32)
            Invalid("The recovery deployment-subject preimage has an invalid width.");

        Span<byte> deploymentInput = stackalloc byte[80];
        network16.CopyTo(deploymentInput[..16]);
        accountHash32.CopyTo(deploymentInput[16..48]);
        resetId32.CopyTo(deploymentInput[48..]);
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/deployment-subject", deploymentInput);
    }

    internal static void VerifyDistinctComponentAndDeploymentSubjects(
        ReadOnlySpan<byte> componentSubject32,
        ReadOnlySpan<byte> deploymentSubject32)
    {
        if (componentSubject32.Length != 32 || deploymentSubject32.Length != 32)
            Invalid("The recovery subject has an invalid width.");
        if (CanonicalGrammar.FixedEquals(componentSubject32, deploymentSubject32))
            Invalid("The recovery component and witness deployment subjects are cross-fed.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);

    private static byte[] CreatePinCoreProjection(OwnedRecord dpl)
    {
        var output = new byte[RecoveryManifestParser.PinCoreLength];
        var offset = 0;
        for (var tag = 1; tag <= 11; tag++) Append(dpl.FieldSpan(tag));
        for (var tag = 15; tag <= 17; tag++) Append(dpl.FieldSpan(tag));
        if (offset != output.Length) Invalid("The DPL pin-core projection length is invalid.");
        return output;

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(output.AsSpan(offset));
            offset += value.Length;
        }
    }
}
