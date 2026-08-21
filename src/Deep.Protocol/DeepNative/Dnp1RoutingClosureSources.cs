using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// Consumer-protected expected head bytes used only as a restore comparison.
/// This carry value is deliberately not a sealed authority or a verifier result.
/// </summary>
public sealed class RoutingHeadRestoreInput
{
    private readonly byte[] _membership;
    private readonly byte[] _mailboxAuthority;

    public RoutingHeadRestoreInput(
        ReadOnlySpan<byte> membershipHeadTuple,
        ReadOnlySpan<byte> mailboxAuthorityHeadTuple)
    {
        if (membershipHeadTuple.Length != 164 || mailboxAuthorityHeadTuple.Length != 204)
            throw new RecordException(RecordError.InvalidLength,
                "The routing head restore tuple length is invalid.");
        _membership = membershipHeadTuple.ToArray();
        _mailboxAuthority = mailboxAuthorityHeadTuple.ToArray();
    }

    internal ReadOnlySpan<byte> MembershipTuple => _membership;
    internal ReadOnlySpan<byte> MailboxAuthorityTuple => _mailboxAuthority;
    public bool NoAuthorityClaim => true;
}

/// <summary>Exact current cutover/DRS tuple, verified relative to its supplied evidence.</summary>
public sealed class CurrentCutoverRelative
{
    private const string Domain = "Deep/NativeRouting/V2/current-cutover-source";
    private readonly byte[] _tuple;
    private readonly byte[] _source;
    private readonly byte[] _dcm;
    private readonly byte[] _dcp;
    private readonly byte[] _drs;
    private readonly byte[] _dpl;

    // Compatibility for internal non-recovery fixtures. Production restore always uses the
    // complete overload below and is the only path that can mint recovery expectations.
    internal CurrentCutoverRelative(
        ReadOnlySpan<byte> network16, ReadOnlySpan<byte> resetId32,
        ComponentKind componentKind, ReadOnlySpan<byte> accountHash32,
        ulong accountGeneration, ulong dcmGeneration, ReadOnlySpan<byte> dcmRef38,
        ReadOnlySpan<byte> dcpRef38, ReadOnlySpan<byte> dcsRef38,
        ReadOnlySpan<byte> dcqRef38, ReadOnlySpan<byte> dwlRef38,
        ReadOnlySpan<byte> dclRef38, ReadOnlySpan<byte> dplRef38,
        ReadOnlySpan<byte> releaseRootAuthorityHead32, ulong drsRevision,
        ulong drsCount, ReadOnlySpan<byte> drsHead32, ReadOnlySpan<byte> drsRef38,
        ulong leaseExpiresAt, ReadOnlySpan<byte> dplKeyId32,
        ReadOnlySpan<byte> dwlKeyId32, ReadOnlySpan<byte> rrlKeyId32,
        ReadOnlySpan<byte> ribKeyId32, ReadOnlySpan<byte> mrlcKeyId32,
        ReadOnlySpan<byte> dxrKeyId32)
        : this(network16, resetId32, componentKind, accountHash32, accountGeneration,
            dcmGeneration, dcmRef38, dcpRef38, dcsRef38, dcqRef38, dwlRef38,
            dclRef38, dplRef38, releaseRootAuthorityHead32, drsRevision, drsCount,
            drsHead32, drsRef38, leaseExpiresAt, dplKeyId32, dwlKeyId32, rrlKeyId32,
            ribKeyId32, mrlcKeyId32, dxrKeyId32, dxrKeyId32,
            default, default, default, default)
    {
    }

    internal CurrentCutoverRelative(
        ReadOnlySpan<byte> network16,
        ReadOnlySpan<byte> resetId32,
        ComponentKind componentKind,
        ReadOnlySpan<byte> accountHash32,
        ulong accountGeneration,
        ulong dcmGeneration,
        ReadOnlySpan<byte> dcmRef38,
        ReadOnlySpan<byte> dcpRef38,
        ReadOnlySpan<byte> dcsRef38,
        ReadOnlySpan<byte> dcqRef38,
        ReadOnlySpan<byte> dwlRef38,
        ReadOnlySpan<byte> dclRef38,
        ReadOnlySpan<byte> dplRef38,
        ReadOnlySpan<byte> releaseRootAuthorityHead32,
        ulong drsRevision,
        ulong drsCount,
        ReadOnlySpan<byte> drsHead32,
        ReadOnlySpan<byte> drsRef38,
        ulong leaseExpiresAt,
        ReadOnlySpan<byte> dplKeyId32,
        ReadOnlySpan<byte> dwlKeyId32,
        ReadOnlySpan<byte> rrlKeyId32,
        ReadOnlySpan<byte> ribKeyId32,
        ReadOnlySpan<byte> mrlcKeyId32,
        ReadOnlySpan<byte> dxrKeyId32,
        ReadOnlySpan<byte> recoveryNonceLatchKeyId32,
        ReadOnlySpan<byte> canonicalDcm,
        ReadOnlySpan<byte> canonicalDcp,
        ReadOnlySpan<byte> canonicalDrs,
        ReadOnlySpan<byte> canonicalDpl)
    {
        Require(network16,16,"network"); Require(resetId32,32,"reset ID");
        Require(accountHash32,32,"account hash"); Require(dcmRef38,38,"DCM ref");
        Require(dcpRef38,38,"DCP ref"); Require(dcsRef38,38,"DCS ref");
        Require(dcqRef38,38,"DCQ ref"); Require(dwlRef38,38,"DWL ref");
        Require(dclRef38,38,"DCL ref"); Require(dplRef38,38,"DPL ref");
        Require(releaseRootAuthorityHead32,32,"ReleaseRoot head");
        if (drsHead32.Length != 32 ||
            (drsCount == 0) != CanonicalGrammar.IsZero(drsHead32))
            Invalid("The current cutover DRS count/head shape is invalid.");
        Require(drsRef38,38,"DRS ref"); Require(dplKeyId32,32,"DPL key ID");
        Require(dwlKeyId32,32,"DWL key ID"); Require(rrlKeyId32,32,"RRL key ID");
        Require(ribKeyId32,32,"RIB key ID"); Require(mrlcKeyId32,32,"MRLC key ID");
        Require(dxrKeyId32,32,"DXR key ID");
        Require(recoveryNonceLatchKeyId32,32,"recovery nonce-latch key ID");
        var hasRecoveryClosure = !canonicalDcm.IsEmpty || !canonicalDcp.IsEmpty ||
            !canonicalDrs.IsEmpty || !canonicalDpl.IsEmpty;
        if (hasRecoveryClosure && (canonicalDcm.IsEmpty || canonicalDcp.IsEmpty ||
            canonicalDrs.IsEmpty || canonicalDpl.IsEmpty))
            Invalid("The current cutover recovery closure is partial.");
        if (hasRecoveryClosure)
        {
            CanonicalGrammar.Preflight(canonicalDcm, RecordDefinitions.Dcm1);
            CanonicalGrammar.Preflight(canonicalDcp, RecordDefinitions.Dcp1);
            CanonicalGrammar.Preflight(canonicalDrs, RecordDefinitions.Drs1);
            CanonicalGrammar.Preflight(canonicalDpl, RecordDefinitions.Dpl1);
        }
        if (!Enum.IsDefined(componentKind) || componentKind == 0 || accountGeneration == 0 ||
            dcmGeneration == 0 || drsRevision == 0 || leaseExpiresAt == 0)
            Invalid("The current cutover scalar tuple is invalid.");

        _tuple = new byte[714];
        var offset = 0;
        Append(network16); Append(resetId32);
        Span<byte> scalar = stackalloc byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(scalar[..2], (ushort)componentKind); Append(scalar[..2]);
        Append(accountHash32);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, accountGeneration); Append(scalar);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, dcmGeneration); Append(scalar);
        Append(dcmRef38); Append(dcpRef38); Append(dcsRef38); Append(dcqRef38); Append(dwlRef38);
        Append(dclRef38); Append(dplRef38); Append(releaseRootAuthorityHead32);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, drsRevision); Append(scalar);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, drsCount); Append(scalar);
        Append(drsHead32); Append(drsRef38);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, leaseExpiresAt); Append(scalar);
        Append(dplKeyId32); Append(dwlKeyId32); Append(rrlKeyId32); Append(ribKeyId32);
        Append(mrlcKeyId32); Append(dxrKeyId32); Append(recoveryNonceLatchKeyId32);
        if (offset != _tuple.Length) Invalid("The current cutover tuple length is invalid.");
        // The public current-cutover fingerprint is the frozen 682-byte tuple ending at
        // DXR key ID. The recovery nonce-latch selector belongs only to the separate
        // recovery-old-protected-source transcript and must never drift this domain.
        _source = CanonicalGrammar.Sha256Domain(Domain, _tuple.AsSpan(0, 682));
        _dcm = canonicalDcm.ToArray();
        _dcp = canonicalDcp.ToArray();
        _drs = canonicalDrs.ToArray();
        _dpl = canonicalDpl.ToArray();
        if (hasRecoveryClosure)
        {
            CanonicalGrammar.Preflight(_dcm, RecordDefinitions.Dcm1);
            CanonicalGrammar.Preflight(_dcp, RecordDefinitions.Dcp1);
            CanonicalGrammar.Preflight(_drs, RecordDefinitions.Drs1);
            CanonicalGrammar.Preflight(_dpl, RecordDefinitions.Dpl1);
        }

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(_tuple.AsSpan(offset));
            offset += value.Length;
        }

        static void Require(ReadOnlySpan<byte> value, int length, string name)
        {
            if (value.Length != length || CanonicalGrammar.IsZero(value))
                Invalid($"The current cutover {name} is invalid.");
        }
    }

    internal ReadOnlySpan<byte> TrustedTuple => _tuple;
    internal ReadOnlySpan<byte> TrustedNetwork => _tuple.AsSpan(0, 16);
    internal ReadOnlySpan<byte> TrustedResetId => _tuple.AsSpan(16, 32);
    internal ComponentKind ComponentKind =>
        (ComponentKind)BinaryPrimitives.ReadUInt16BigEndian(_tuple.AsSpan(48, 2));
    internal ReadOnlySpan<byte> TrustedAccountHash => _tuple.AsSpan(50, 32);
    internal ulong AccountGeneration => BinaryPrimitives.ReadUInt64BigEndian(_tuple.AsSpan(82, 8));
    internal ulong DcmGeneration => BinaryPrimitives.ReadUInt64BigEndian(_tuple.AsSpan(90, 8));
    internal ReadOnlySpan<byte> TrustedDcmRef => _tuple.AsSpan(98, 38);
    internal ReadOnlySpan<byte> TrustedDcpRef => _tuple.AsSpan(136, 38);
    internal ReadOnlySpan<byte> TrustedDcsRef => _tuple.AsSpan(174, 38);
    internal ReadOnlySpan<byte> TrustedDcqRef => _tuple.AsSpan(212, 38);
    internal ReadOnlySpan<byte> TrustedDwlRef => _tuple.AsSpan(250, 38);
    internal ReadOnlySpan<byte> TrustedDclRef => _tuple.AsSpan(288, 38);
    internal ReadOnlySpan<byte> TrustedReleaseRootAuthorityHead => _tuple.AsSpan(364, 32);
    internal ulong DrsRevision => BinaryPrimitives.ReadUInt64BigEndian(_tuple.AsSpan(396, 8));
    internal ulong DrsCount => BinaryPrimitives.ReadUInt64BigEndian(_tuple.AsSpan(404, 8));
    internal ReadOnlySpan<byte> TrustedDrsHead => _tuple.AsSpan(412, 32);
    internal ReadOnlySpan<byte> TrustedDrsRef => _tuple.AsSpan(444, 38);
    internal ulong LeaseExpiresAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(_tuple.AsSpan(482, 8));
    internal ReadOnlySpan<byte> TrustedDplRef => _tuple.AsSpan(326, 38);
    internal ReadOnlySpan<byte> TrustedDplKeyId => _tuple.AsSpan(490, 32);
    internal ReadOnlySpan<byte> TrustedDwlKeyId => _tuple.AsSpan(522, 32);
    internal ReadOnlySpan<byte> TrustedRrlKeyId => _tuple.AsSpan(554, 32);
    internal ReadOnlySpan<byte> TrustedRibKeyId => _tuple.AsSpan(586, 32);
    internal ReadOnlySpan<byte> TrustedMrlcKeyId => _tuple.AsSpan(618, 32);
    internal ReadOnlySpan<byte> TrustedDxrKeyId => _tuple.AsSpan(650, 32);
    internal ReadOnlySpan<byte> TrustedRecoveryNonceLatchKeyId => _tuple.AsSpan(682, 32);
    internal ReadOnlySpan<byte> TrustedDcm => _dcm;
    internal ReadOnlySpan<byte> TrustedDcp => _dcp;
    internal ReadOnlySpan<byte> TrustedDrs => _drs;
    internal ReadOnlySpan<byte> TrustedDpl => _dpl;
    internal bool HasRecoveryClosure => _dcm.Length != 0;
    public ReadOnlyMemory<byte> SourceFingerprint => _source.ToArray();
    public bool NoAuthorityClaim => true;

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>Current nonrevoked mailbox role sealed to its exact protected restore source.</summary>
public sealed class CurrentMailboxRoleRelative
{
    internal CurrentMailboxRoleRelative(
        CurrentCutoverRelative cutover,
        VerifiedMailboxRelative mailbox,
        ReadOnlySpan<byte> dpmcRef38)
    {
        if (dpmcRef38.Length != 38 || CanonicalGrammar.IsZero(dpmcRef38) ||
            !CanonicalGrammar.FixedEquals(cutover.TrustedNetwork, mailbox.Certificate.NetworkId.Span))
            throw new RecordException(RecordError.InvalidField,
                "The current mailbox role source is invalid.");
        Cutover = cutover;
        Mailbox = mailbox;
        DpmcReference = dpmcRef38.ToArray();
    }
    internal CurrentCutoverRelative Cutover { get; }
    internal VerifiedMailboxRelative Mailbox { get; }
    internal byte[] DpmcReference { get; }
    public ReadOnlyMemory<byte> MailboxOwnerId => Mailbox.Certificate.MailboxOwnerId;
    public ReadOnlyMemory<byte> CurrentDpmcReference => DpmcReference.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class MembershipHeadRelative
{
    private const string Domain = "Deep/NativeRouting/V2/membership-head-source";
    private readonly byte[] _tuple;
    private readonly byte[] _source;
    internal MembershipHeadRelative(ReadOnlySpan<byte> tuple)
    {
        if (tuple.Length != 164) throw new RecordException(RecordError.InvalidLength,
            "The membership head tuple length is invalid.");
        _tuple = tuple.ToArray();
        _source = CanonicalGrammar.Sha256Domain(Domain, _tuple);
    }
    internal ReadOnlySpan<byte> TrustedTuple => _tuple;
    internal ReadOnlySpan<byte> Network => _tuple.AsSpan(0,16);
    internal ulong Sequence => BinaryPrimitives.ReadUInt64BigEndian(_tuple.AsSpan(86,8));
    internal ReadOnlySpan<byte> CanonicalHash => _tuple.AsSpan(94,32);
    internal ReadOnlySpan<byte> MsmReference => _tuple.AsSpan(126,38);
    public ReadOnlyMemory<byte> CanonicalTuple => _tuple.ToArray();
    public ReadOnlyMemory<byte> SourceFingerprint => _source.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class MailboxAuthorityHeadRelative
{
    private const string Domain = "Deep/NativeRouting/V2/mailbox-authority-head-source";
    private readonly byte[] _tuple;
    private readonly byte[] _source;
    internal MailboxAuthorityHeadRelative(ReadOnlySpan<byte> tuple)
    {
        if (tuple.Length != 204) throw new RecordException(RecordError.InvalidLength,
            "The mailbox authority head tuple length is invalid.");
        _tuple = tuple.ToArray();
        _source = CanonicalGrammar.Sha256Domain(Domain, _tuple);
    }
    internal ReadOnlySpan<byte> TrustedTuple => _tuple;
    internal ReadOnlySpan<byte> Network => _tuple.AsSpan(0,16);
    internal ulong PmaGeneration => BinaryPrimitives.ReadUInt64BigEndian(_tuple.AsSpan(54,8));
    internal ReadOnlySpan<byte> PmaCanonicalHash => _tuple.AsSpan(62,32);
    internal ulong PmrGeneration => BinaryPrimitives.ReadUInt64BigEndian(_tuple.AsSpan(132,8));
    internal ReadOnlySpan<byte> PmrHead => _tuple.AsSpan(140,32);
    public ReadOnlyMemory<byte> CanonicalTuple => _tuple.ToArray();
    public ReadOnlyMemory<byte> SourceFingerprint => _source.ToArray();
    public bool NoAuthorityClaim => true;
}

/// <summary>Current DNR fact joined to mailbox/PMA-PMR provenance and one Verified Router DXR1.</summary>
public sealed class CurrentDnrcRelative
{
    private const string Domain = "Deep/NativeRouting/V2/dnrc-source";
    private readonly byte[] _source;
    private readonly byte[] _pmaCanonical;
    private readonly byte[] _pmrCanonical;
    internal CurrentDnrcRelative(
        CurrentMailboxRoleRelative mailbox,
        MailboxAuthorityHeadRelative mailboxAuthorityHead,
        ReadOnlySpan<byte> pmaCanonical,
        ReadOnlySpan<byte> pmrCanonical,
        VerifiedRouterCertificateRelative certificate,
        DxpReceiptRelative possession,
        ulong pmaEpoch)
    {
        if (possession.Phase != DxpReceiptPhase.Verified ||
            possession.Role != X25519PossessionRole.Router)
            throw new RecordException(RecordError.InvalidTransition,
                "A current DNRC requires a Verified Router DXR1.");
        Mailbox = mailbox;
        MailboxAuthorityHead = mailboxAuthorityHead;
        Certificate = certificate;
        Possession = possession;
        var record = CanonicalGrammar.DecodeOwned(
            certificate.CanonicalBytes.Span, RecordDefinitions.Dnr1);
        var expectedPma = CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Pma1, checked((uint)pmaCanonical.Length),
            SHA256.HashData(pmaCanonical)));
        var expectedPmr = CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Pmr1, checked((uint)pmrCanonical.Length),
            SHA256.HashData(pmrCanonical)));
        if (!CanonicalGrammar.FixedEquals(record.FieldSpan(4), expectedPma) ||
            !CanonicalGrammar.FixedEquals(record.FieldSpan(6), expectedPmr))
            throw new RecordException(RecordError.InvalidArtifactReference,
                "The current DNRC retained PMA/PMR bytes differ from its certificate.");
        _pmaCanonical = pmaCanonical.ToArray();
        _pmrCanonical = pmrCanonical.ToArray();
        var tuple = new byte[32+32+38+38+8+8+38+8+32+32+38+32+32];
        var offset = 0;
        Append(mailbox.Cutover.SourceFingerprint.Span);
        Append(mailbox.Mailbox.Certificate.MailboxOwnerId.Span);
        Append(mailbox.DpmcReference);
        mailboxAuthorityHead.TrustedTuple.Slice(16,46).CopyTo(tuple.AsSpan(offset)); offset += 46;
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(offset,8), pmaEpoch); offset += 8;
        mailboxAuthorityHead.TrustedTuple.Slice(94,110).CopyTo(tuple.AsSpan(offset)); offset += 110;
        Append(certificate.ArtifactReference.Span);
        Append(possession.TranscriptHash.Span);
        Append(possession.ProtectedStateKeyId.Span);
        if (offset != tuple.Length) throw new RecordException(RecordError.InvalidLength,
            "The DNRC source tuple length is invalid.");
        _source = CanonicalGrammar.Sha256Domain(Domain, tuple);
        void Append(ReadOnlySpan<byte> value) { value.CopyTo(tuple.AsSpan(offset)); offset += value.Length; }
    }
    internal CurrentMailboxRoleRelative Mailbox { get; }
    internal MailboxAuthorityHeadRelative MailboxAuthorityHead { get; }
    internal VerifiedRouterCertificateRelative Certificate { get; }
    internal DxpReceiptRelative Possession { get; }
    internal ReadOnlySpan<byte> PmaCanonical => _pmaCanonical;
    internal ReadOnlySpan<byte> PmrCanonical => _pmrCanonical;
    public ReadOnlyMemory<byte> DnrArtifactReference => Certificate.ArtifactReference;
    public ReadOnlyMemory<byte> RouterId => Certificate.RouterId;
    public ReadOnlyMemory<byte> SourceFingerprint => _source.ToArray();
    public bool NoAuthorityClaim => true;
}

/// <summary>
/// A current router certificate and already HMAC-verified possession receipt joined only to
/// identity/PMA/PMR facts. It deliberately carries no DPL or current-cutover authority.
/// </summary>
public sealed class VerifiedGenesisRouterRelative
{
    private readonly byte[] _pmaCanonical;
    private readonly byte[] _pmrCanonical;

    internal VerifiedGenesisRouterRelative(
        VerifiedMailboxRelative mailbox,
        MailboxAuthorityHeadRelative mailboxAuthorityHead,
        ReadOnlySpan<byte> pmaCanonical,
        ReadOnlySpan<byte> pmrCanonical,
        VerifiedRouterCertificateRelative certificate,
        DxpReceiptRelative possession)
    {
        Mailbox = mailbox;
        MailboxAuthorityHead = mailboxAuthorityHead;
        Certificate = certificate;
        Possession = possession;
        _pmaCanonical = pmaCanonical.ToArray();
        _pmrCanonical = pmrCanonical.ToArray();
    }

    internal VerifiedMailboxRelative Mailbox { get; }
    internal MailboxAuthorityHeadRelative MailboxAuthorityHead { get; }
    internal VerifiedRouterCertificateRelative Certificate { get; }
    internal DxpReceiptRelative Possession { get; }
    internal ReadOnlySpan<byte> PmaCanonical => _pmaCanonical;
    internal ReadOnlySpan<byte> PmrCanonical => _pmrCanonical;
    public bool NoAuthorityClaim => true;
}

/// <summary>Complete data-only MRLC/head transition tuple for a consumer-owned atomic CAS.</summary>
public sealed class CompositeRoutingCommitPlan
{
    private readonly CurrentDnrcRelative[] _dnrc;
    internal CompositeRoutingCommitPlan(
        MembershipHeadRelative currentMembership,
        MembershipHeadRelative nextMembership,
        MailboxAuthorityHeadRelative currentMailboxAuthority,
        MailboxAuthorityHeadRelative nextMailboxAuthority,
        CurrentCutoverRelative cutover,
        IReadOnlyList<CurrentDnrcRelative> dnrc,
        VerifiedMembershipRoutingLkg nextLkg)
    {
        CurrentMembershipHead = currentMembership;
        NextMembershipHead = nextMembership;
        CurrentMailboxAuthorityHead = currentMailboxAuthority;
        NextMailboxAuthorityHead = nextMailboxAuthority;
        CurrentCutover = cutover;
        _dnrc = dnrc.ToArray();
        NextLkg = nextLkg;
    }
    public MembershipHeadRelative CurrentMembershipHead { get; }
    public MembershipHeadRelative NextMembershipHead { get; }
    public MailboxAuthorityHeadRelative CurrentMailboxAuthorityHead { get; }
    public MailboxAuthorityHeadRelative NextMailboxAuthorityHead { get; }
    public CurrentCutoverRelative CurrentCutover { get; }
    public IReadOnlyList<CurrentDnrcRelative> CurrentRouterFacts => _dnrc.ToArray();
    public VerifiedMembershipRoutingLkg NextLkg { get; }
    public bool NoAuthorityClaim => true;
}

/// <summary>Builds sealed continuity sources only from already verified exact artifacts.</summary>
public sealed class RoutingClosureSourceVerifier
{
    public DxpOperationSource CreatePendingRouterDxpSource(
        CurrentCutoverRelative cutover,
        CurrentMailboxRoleRelative mailbox,
        ReadOnlySpan<byte> prePopCanonicalDnr1,
        ReadOnlySpan<byte> identityCatalogKeyId32,
        ReadOnlySpan<byte> nonceIndexKeyId32) =>
        CreateRouterDxpSource(cutover, mailbox, prePopCanonicalDnr1,
            identityCatalogKeyId32, nonceIndexKeyId32, verified: false);

    public DxpOperationSource CreateVerifiedRouterDxpSource(
        CurrentCutoverRelative cutover,
        CurrentMailboxRoleRelative mailbox,
        ReadOnlySpan<byte> canonicalDnr1,
        ReadOnlySpan<byte> identityCatalogKeyId32,
        ReadOnlySpan<byte> nonceIndexKeyId32) =>
        CreateRouterDxpSource(cutover, mailbox, canonicalDnr1,
            identityCatalogKeyId32, nonceIndexKeyId32, verified: true);

    public MailboxAuthorityHeadRelative RestoreCurrentMailboxAuthorityHead(
        RoutingHeadRestoreInput expected,
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocations)
    {
        ArgumentNullException.ThrowIfNull(expected);
        var head = CreateMailboxHead(authority, revocations);
        Equal(head.TrustedTuple, expected.MailboxAuthorityTuple,
            "The mailbox authority restore head differs from protected state.");
        return head;
    }

    public MailboxAuthorityHeadRelative VerifyNextMailboxAuthorityHead(
        MailboxAuthorityHeadRelative current,
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocations)
    {
        ArgumentNullException.ThrowIfNull(current);
        var next = CreateMailboxHead(authority, revocations);
        var pma = authority.Authority;
        var pmr = revocations.Snapshot;
        Equal(current.Network, next.Network, "The mailbox authority network changed.");
        if (current.PmaGeneration == ulong.MaxValue || next.PmaGeneration != current.PmaGeneration + 1 ||
            !CanonicalGrammar.FixedEquals(pma.PreviousAuthorityHash.Span, current.PmaCanonicalHash))
            Invalid("The PMA head does not advance from the exact predecessor.");
        if (next.PmrGeneration == current.PmrGeneration)
        {
            Equal(next.PmrHead, current.PmrHead, "A same-generation PMR head changed.");
            if (!CanonicalGrammar.FixedEquals(
                    next.TrustedTuple.Slice(172, 32), current.TrustedTuple.Slice(172, 32)))
                Invalid("A same-generation PMR snapshot changed.");
        }
        else if (current.PmrGeneration == ulong.MaxValue || next.PmrGeneration != current.PmrGeneration + 1 ||
                 !CanonicalGrammar.FixedEquals(pmr.PreviousRevocationHeadHash.Span, current.PmrHead))
            Invalid("The PMR head neither exactly replays nor advances by one.");
        return next;
    }

    public CurrentMailboxRoleRelative BindCurrentMailboxRole(
        CurrentCutoverRelative cutover,
        VerifiedMailboxRelative mailbox)
    {
        ArgumentNullException.ThrowIfNull(cutover);
        ArgumentNullException.ThrowIfNull(mailbox);
        var certificate = mailbox.Certificate;
        var drs = mailbox.Device.Identity.Revocations.Snapshot;
        Equal(cutover.TrustedNetwork, certificate.NetworkId.Span, "Mailbox/cutover network mismatch.");
        Equal(cutover.TrustedAccountHash, certificate.AccountHash.Span, "Mailbox/cutover account mismatch.");
        if (cutover.AccountGeneration != certificate.AccountGeneration ||
            cutover.DrsRevision != drs.Revision || cutover.DrsCount != drs.EntryCount)
            Invalid("Mailbox/cutover generation or DRS scalar mismatch.");
        Equal(cutover.TrustedDrsHead, drs.CurrentHead.Span, "Mailbox/cutover DRS head mismatch.");
        var drsRef = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Drs1, drs.CanonicalBytes.Span));
        Equal(cutover.TrustedDrsRef, drsRef, "Mailbox/cutover DRS reference mismatch.");
        var dpmcRef = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dpm1, certificate.CanonicalBytes.Span));
        return new CurrentMailboxRoleRelative(cutover, mailbox, dpmcRef);
    }

    internal static MailboxAuthorityHeadRelative CreateMailboxHead(
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocations)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(revocations);
        var pma = authority.Authority;
        var pmr = revocations.Snapshot;
        if (!CanonicalGrammar.FixedEquals(pma.NetworkId.Span, pmr.NetworkId.Span) ||
            pma.AuthorityGeneration != pmr.AuthorityGeneration)
            Invalid("The PMA/PMR head source is inconsistent.");
        var pmaBytes = ProductionMailboxAuthorityCodec.Encode(pma);
        var pmrBytes = ProductionMailboxRevocationSnapshotCodec.Encode(pmr);
        var tuple = new byte[204];
        pma.NetworkId.Span.CopyTo(tuple);
        Retained(ArtifactType.Pma1, pmaBytes).CopyTo(tuple, 16);
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(54, 8), pma.AuthorityGeneration);
        authority.CanonicalAuthorityHash.Span.CopyTo(tuple.AsSpan(62));
        Retained(ArtifactType.Pmr1, pmrBytes).CopyTo(tuple, 94);
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(132, 8), pmr.RevocationGeneration);
        pmr.RevocationHeadHash.Span.CopyTo(tuple.AsSpan(140));
        revocations.CanonicalSnapshotHash.Span.CopyTo(tuple.AsSpan(172));
        return new MailboxAuthorityHeadRelative(tuple);
    }

    private static DxpOperationSource CreateRouterDxpSource(
        CurrentCutoverRelative cutover,
        CurrentMailboxRoleRelative mailbox,
        ReadOnlySpan<byte> canonicalDnr1,
        ReadOnlySpan<byte> identityCatalogKeyId32,
        ReadOnlySpan<byte> nonceIndexKeyId32,
        bool verified)
    {
        ArgumentNullException.ThrowIfNull(cutover);
        ArgumentNullException.ThrowIfNull(mailbox);
        if (!ReferenceEquals(mailbox.Cutover, cutover))
            Invalid("The router DXP source uses a mixed mailbox/cutover tuple.");
        var record = CanonicalGrammar.DecodeOwned(canonicalDnr1, RecordDefinitions.Dnr1);
        Equal(record.FieldSpan(1), cutover.TrustedNetwork, "Router DXP network mismatch.");
        Equal(record.FieldSpan(2), mailbox.Mailbox.Certificate.MailboxOwnerId.Span,
            "Router DXP mailbox owner mismatch.");
        Equal(record.FieldSpan(3), mailbox.DpmcReference, "Router DXP DPMC mismatch.");
        var projection = DxpSubjectProjection.HashRouter(record);
        var transcript = verified ? record.FieldSpan(19).ToArray() : new byte[32];
        var subject = verified
            ? CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dnr1, record.CanonicalSpan))
            : new byte[38];
        if (verified && CanonicalGrammar.IsZero(transcript) ||
            !verified && (!CanonicalGrammar.IsZero(record.FieldSpan(19)) ||
                          !CanonicalGrammar.IsZero(record.FieldSpan(20)) ||
                          !CanonicalGrammar.IsZero(record.FieldSpan(21))))
            Invalid("The router DXP source has the wrong pre-PoP/final shape.");
        return new DxpOperationSource(
            X25519PossessionRole.Router,
            verified ? (byte)1 : (byte)0,
            cutover.SourceFingerprint.Span,
            cutover.DrsRevision,
            cutover.DrsCount,
            cutover.TrustedDrsHead,
            cutover.TrustedDrsRef,
            projection,
            record.FieldSpan(18),
            transcript,
            subject,
            identityCatalogKeyId32,
            cutover.TrustedDxrKeyId,
            nonceIndexKeyId32);
    }

    private static byte[] Retained(ArtifactType type, ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(new ArtifactReference(
            type, checked((uint)canonical.Length), System.Security.Cryptography.SHA256.HashData(canonical)));

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string message)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected)) Invalid(message);
    }
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidTransition, message);
}
