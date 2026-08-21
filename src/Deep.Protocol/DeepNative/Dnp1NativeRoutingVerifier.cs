using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Sodium;

namespace Deep.Protocol.DeepNative;

/// <summary>Verifies exact DPC1 anchor and successor contacts from a sealed MRL2 membership fact.</summary>
public sealed class NativeRoutingVerifier
{
    private const string RouterCertificateDomain = "Deep/NativeRouting/V1/router-certificate";
    private const string RouterIdDomain = "Deep/NativeRouting/V1/router-id";
    private const string ContactDomain = "Deep/NativeRouting/V1/contact";

    public CurrentDnrcRelative VerifyCurrentRouterCertificate(
        CurrentMailboxRoleRelative mailbox,
        VerifiedProductionMailboxAuthority mailboxAuthority,
        VerifiedProductionMailboxRevocationSnapshot revocations,
        MailboxAuthorityHeadRelative mailboxAuthorityHead,
        DxpReceiptRelative routerPossession,
        ReadOnlySpan<byte> canonicalDnr1,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(mailbox);
        ArgumentNullException.ThrowIfNull(mailboxAuthorityHead);
        ArgumentNullException.ThrowIfNull(routerPossession);
        var expectedHead = RoutingClosureSourceVerifier.CreateMailboxHead(
            mailboxAuthority, revocations);
        Equal(expectedHead.TrustedTuple, mailboxAuthorityHead.TrustedTuple,
            "The DNR1 mailbox authority head is not the exact verified PMA/PMR head.");
        var verified = VerifyRouterCertificate(
            mailbox.Mailbox, mailboxAuthority, revocations, canonicalDnr1,
            transactionTimeUnixSeconds);
        VerifyRouterPossession(verified, routerPossession);
        Equal(routerPossession.Record.FieldSpan(16), mailbox.Cutover.TrustedDxrKeyId,
            "DNR1/DXR1 protected key mismatch.");
        return new CurrentDnrcRelative(
            mailbox, mailboxAuthorityHead,
            ProductionMailboxAuthorityCodec.Encode(mailboxAuthority.Authority),
            ProductionMailboxRevocationSnapshotCodec.Encode(revocations.Snapshot),
            verified, routerPossession,
            mailboxAuthority.Authority.CurrentEpoch.Epoch);
    }

    public VerifiedGenesisRouterRelative VerifyGenesisRouterCertificate(
        VerifiedMailboxRelative mailbox,
        VerifiedProductionMailboxAuthority mailboxAuthority,
        VerifiedProductionMailboxRevocationSnapshot revocations,
        MailboxAuthorityHeadRelative mailboxAuthorityHead,
        DxpReceiptRelative routerPossession,
        ReadOnlySpan<byte> canonicalDnr1,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(mailbox);
        ArgumentNullException.ThrowIfNull(mailboxAuthorityHead);
        ArgumentNullException.ThrowIfNull(routerPossession);
        var expectedHead = RoutingClosureSourceVerifier.CreateMailboxHead(
            mailboxAuthority, revocations);
        Equal(expectedHead.TrustedTuple, mailboxAuthorityHead.TrustedTuple,
            "The genesis DNR1 mailbox authority head is not the exact verified PMA/PMR head.");
        var verified = VerifyRouterCertificate(
            mailbox, mailboxAuthority, revocations, canonicalDnr1,
            transactionTimeUnixSeconds);
        VerifyRouterPossession(verified, routerPossession);
        var source = routerPossession.Source;
        var drs = mailbox.Device.Identity.Revocations.Snapshot;
        var drsReference = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Drs1, drs.CanonicalBytes.Span));
        if (source.Role != X25519PossessionRole.Router || source.Stage != 1 ||
            source.DrsRevision != drs.Revision || source.DrsCount != drs.EntryCount ||
            !CanonicalGrammar.FixedEquals(source.DrsHead, drs.CurrentHead.Span) ||
            !CanonicalGrammar.FixedEquals(source.DrsReference, drsReference))
            Invalid("The genesis DNR1 possession source differs from the current identity DRS1.");
        return new VerifiedGenesisRouterRelative(
            mailbox, mailboxAuthorityHead,
            ProductionMailboxAuthorityCodec.Encode(mailboxAuthority.Authority),
            ProductionMailboxRevocationSnapshotCodec.Encode(revocations.Snapshot),
            verified, routerPossession);
    }

    private static void VerifyRouterPossession(
        VerifiedRouterCertificateRelative verified,
        DxpReceiptRelative routerPossession)
    {
        var record = CanonicalGrammar.DecodeOwned(
            verified.CanonicalBytes.Span, RecordDefinitions.Dnr1);
        if (routerPossession.Phase != DxpReceiptPhase.Verified ||
            routerPossession.Role != X25519PossessionRole.Router)
            Invalid("DNR1 requires a Verified Router DXR1.");
        Equal(routerPossession.Record.FieldSpan(3), record.FieldSpan(1),
            "DNR1/DXR1 network mismatch.");
        Equal(routerPossession.Record.FieldSpan(5), DxpSubjectProjection.HashRouter(record),
            "DNR1/DXR1 subject projection mismatch.");
        Equal(routerPossession.Record.FieldSpan(6), record.FieldSpan(12),
            "DNR1/DXR1 holder key mismatch.");
        Equal(routerPossession.Record.FieldSpan(13), record.FieldSpan(19),
            "DNR1/DXR1 transcript mismatch.");
        Equal(routerPossession.Record.FieldSpan(14), verified.ArtifactReference.Span,
            "DNR1/DXR1 subject reference mismatch.");
    }

    internal VerifiedRouterCertificateRelative VerifyRouterCertificate(
        VerifiedMailboxRelative mailbox,
        VerifiedProductionMailboxAuthority mailboxAuthority,
        VerifiedProductionMailboxRevocationSnapshot revocations,
        ReadOnlySpan<byte> canonicalDnr1,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(mailbox);
        ArgumentNullException.ThrowIfNull(mailboxAuthority);
        ArgumentNullException.ThrowIfNull(revocations);
        var record = CanonicalGrammar.DecodeOwned(canonicalDnr1, RecordDefinitions.Dnr1);
        var certificate = mailbox.Certificate;
        var authority = mailboxAuthority.Authority;
        var snapshot = revocations.Snapshot;
        Equal(record.FieldSpan(1), certificate.NetworkId.Span, "DNR1 mailbox network mismatch.");
        Equal(record.FieldSpan(1), authority.NetworkId.Span, "DNR1 PMA network mismatch.");
        Equal(record.FieldSpan(1), snapshot.NetworkId.Span, "DNR1 PMR network mismatch.");
        Equal(record.FieldSpan(2), certificate.MailboxOwnerId.Span, "DNR1 owner mismatch.");
        if ((certificate.Capabilities & MailboxCapabilities.RouterCertificateIssuer) == 0)
            throw new RecordException(RecordError.Revoked,
                "The mailbox role cannot issue router certificates.");
        var mailboxRef = CanonicalGrammar.ComputeReference(
            ArtifactType.Dpm1,
            certificate.CanonicalBytes.Span);
        Equal(record.FieldSpan(3), CanonicalGrammar.EncodeReference(mailboxRef),
            "DNR1 mailbox certificate reference mismatch.");

        var pmaBytes = ProductionMailboxAuthorityCodec.Encode(authority);
        var pmaRef = RetainedReference(ArtifactType.Pma1, pmaBytes);
        Equal(record.FieldSpan(4), CanonicalGrammar.EncodeReference(pmaRef),
            "DNR1 PMA reference mismatch.");
        if (Scalars.UInt64(record.FieldSpan(5)) != authority.AuthorityGeneration)
            Invalid("DNR1 PMA generation mismatch.");
        var pmrBytes = ProductionMailboxRevocationSnapshotCodec.Encode(snapshot);
        var pmrRef = RetainedReference(ArtifactType.Pmr1, pmrBytes);
        Equal(record.FieldSpan(6), CanonicalGrammar.EncodeReference(pmrRef),
            "DNR1 PMR reference mismatch.");
        if (Scalars.UInt64(record.FieldSpan(7)) != snapshot.RevocationGeneration ||
            snapshot.AuthorityGeneration != authority.AuthorityGeneration)
            Invalid("DNR1 PMR generation mismatch.");
        Equal(record.FieldSpan(8), SHA256.HashData(authority.MailboxIssuerEd25519PublicKey.Span),
            "DNR1 issuer-key hash mismatch.");

        Span<byte> routerIdInput = stackalloc byte[16 + 32 + 8 + 32];
        record.FieldSpan(1).CopyTo(routerIdInput[..16]);
        record.FieldSpan(2).CopyTo(routerIdInput[16..48]);
        record.FieldSpan(10).CopyTo(routerIdInput[48..56]);
        record.FieldSpan(11).CopyTo(routerIdInput[56..88]);
        Equal(record.FieldSpan(9), CanonicalGrammar.Sha256Domain(RouterIdDomain, routerIdInput),
            "DNR1 router ID mismatch.");
        var issuedAt = Scalars.UInt64(record.FieldSpan(16));
        var expiresAt = Scalars.UInt64(record.FieldSpan(17));
        var lower = Math.Max(certificate.IssuedAtUnixSeconds,
            Math.Max(authority.CurrentEpoch.NotBeforeUnixSeconds, snapshot.IssuedAtUnixSeconds));
        var upper = Math.Min(certificate.ExpiresAtUnixSeconds,
            Math.Min(authority.CurrentEpoch.NotAfterUnixSeconds, snapshot.ExpiresAtUnixSeconds));
        if (issuedAt >= expiresAt || issuedAt < lower || expiresAt > upper ||
            transactionTimeUnixSeconds < issuedAt || transactionTimeUnixSeconds >= expiresAt)
            throw new RecordException(RecordError.Expired,
                "DNR1 is outside its exact authority window.");
        ValidateRoleCapabilities(
            (RouterRoles)Scalars.UInt64(record.FieldSpan(14)),
            (RouterCapabilities)Scalars.UInt64(record.FieldSpan(15)));
        var signing = CanonicalGrammar.GetSigningBytes(record, RouterCertificateDomain);
        VerifyDetached(record.FieldSpan(20), signing, record.FieldSpan(11), "DNR1 router possession");
        VerifyDetached(record.FieldSpan(21), signing, authority.MailboxIssuerEd25519PublicKey.Span,
            "DNR1 issuer signature");
        return new VerifiedRouterCertificateRelative(record);
    }

    internal VerifiedRouterCertificateRelative VerifyRouterCertificateFromRecovery(
        VerifiedMailboxRelative mailbox,
        ReadOnlySpan<byte> canonicalPma1,
        ReadOnlySpan<byte> canonicalPmr1,
        ReadOnlySpan<byte> canonicalDnr1,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(mailbox);
        var pmaBytes = canonicalPma1.ToArray();
        var pmrBytes = canonicalPmr1.ToArray();
        var pma = ProductionMailboxAuthorityCodec.Decode(pmaBytes);
        var pmr = ProductionMailboxRevocationSnapshotCodec.Decode(pmrBytes);
        if (!PublicKeyAuth.VerifyDetached(
                pma.Signature.ToArray(),
                ProductionMailboxAuthorityCodec.GetSigningBytes(pma),
                pma.MrXApprovalEd25519PublicKey.ToArray()) ||
            !CanonicalGrammar.FixedEquals(
                ProductionMailboxAuthorityCodec.ComputePayloadHash(pma),
                pma.MrXApproval.AuthorityPayloadHash.Span) ||
            !CanonicalGrammar.FixedEquals(pmr.NetworkId.Span, pma.NetworkId.Span) ||
            pmr.AuthorityGeneration != pma.AuthorityGeneration ||
            pmr.RevocationGeneration != pma.Revocation.Generation ||
            !CanonicalGrammar.FixedEquals(pmr.AuthorityBindingHash.Span,
                ProductionMailboxRevocationSnapshotCodec.ComputeAuthorityBindingHash(pma)) ||
            !CanonicalGrammar.FixedEquals(SHA256.HashData(pmrBytes),
                pma.Revocation.SnapshotHash.Span) ||
            !PublicKeyAuth.VerifyDetached(
                pmr.IssuerSignature.ToArray(),
                ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(pmr),
                pma.MailboxIssuerEd25519PublicKey.ToArray()))
            Invalid("The recovered PMA1/PMR1 signature closure is invalid.");
        var verifiedPma = new VerifiedProductionMailboxAuthority(
            pma, SHA256.HashData(pmaBytes), pma.AuthorityGeneration);
        var verifiedPmr = new VerifiedProductionMailboxRevocationSnapshot(
            pmr, SHA256.HashData(pmrBytes), pma.MailboxIssuerEd25519PublicKey.Span);
        return VerifyRouterCertificate(
            mailbox, verifiedPma, verifiedPmr, canonicalDnr1,
            transactionTimeUnixSeconds);
    }

    public VerifiedRouterContact VerifyAnchorContact(
        VerifiedMrl2Membership membership,
        ReadOnlySpan<byte> canonicalDpc1,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(membership);
        var record = CanonicalGrammar.DecodeOwned(canonicalDpc1, RecordDefinitions.Dpc1);
        var mrl = CanonicalGrammar.DecodeOwned(
            membership.TrustedMrl2,
            RecordDefinitions.Mrl2);
        BindCommon(membership, mrl, record, transactionTimeUnixSeconds);
        if (Scalars.UInt64(record.FieldSpan(4)) != Scalars.UInt64(mrl.FieldSpan(8)))
            Invalid("The anchor DPC1 generation does not match MRL2.");
        var reference = CanonicalGrammar.ComputeReference(ArtifactType.Dpc1, record.CanonicalSpan);
        Equal(CanonicalGrammar.EncodeReference(reference), mrl.FieldSpan(9),
            "The anchor DPC1 reference does not match MRL2.");
        VerifySignature(record, membership.TrustedRouterEd25519PublicKey);
        return new VerifiedRouterContact(
            record, mrl.FieldSpan(9), Scalars.UInt64(mrl.FieldSpan(8)));
    }

    public VerifiedRouterContact VerifyContactSuccessor(
        VerifiedMrl2Membership membership,
        VerifiedRouterContact current,
        ReadOnlySpan<byte> canonicalDpc1,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(membership);
        ArgumentNullException.ThrowIfNull(current);
        if (current.Generation == ulong.MaxValue)
            throw new RecordException(RecordError.InvalidTransition,
                "The DPC1 generation is terminal.");
        var mrl = CanonicalGrammar.DecodeOwned(
            membership.TrustedMrl2,
            RecordDefinitions.Mrl2);
        var record = CanonicalGrammar.DecodeOwned(canonicalDpc1, RecordDefinitions.Dpc1);
        BindCommon(membership, mrl, record, transactionTimeUnixSeconds);
        if (Scalars.UInt64(record.FieldSpan(4)) != current.Generation + 1)
            Invalid("DPC1 must advance the exact generation by one.");
        Equal(record.FieldSpan(5), current.TrustedReference,
            "DPC1 predecessor does not match the exact current contact.");
        VerifySignature(record, membership.TrustedRouterEd25519PublicKey);
        return new VerifiedRouterContact(
            record, current.TrustedAnchorReference, current.AnchorGeneration);
    }

    private static void BindCommon(
        VerifiedMrl2Membership membership,
        OwnedRecord mrl,
        OwnedRecord contact,
        ulong now)
    {
        Equal(contact.FieldSpan(1), mrl.FieldSpan(1), "DPC1 network mismatch.");
        Equal(contact.FieldSpan(2), membership.TrustedRouterId, "DPC1 router mismatch.");
        Equal(contact.FieldSpan(3), mrl.FieldSpan(5), "DPC1 DNRC mismatch.");
        if (Scalars.UInt64(contact.FieldSpan(8)) != (ulong)membership.Capabilities)
            Invalid("DPC1 capabilities differ from the exact MRL2 row.");
        var issuedAt = Scalars.UInt64(contact.FieldSpan(6));
        var expiresAt = Scalars.UInt64(contact.FieldSpan(7));
        var mrlFrom = Scalars.UInt64(mrl.FieldSpan(10));
        var mrlUntil = Scalars.UInt64(mrl.FieldSpan(11));
        if (issuedAt >= expiresAt || issuedAt < mrlFrom || expiresAt > mrlUntil ||
            now < issuedAt || now >= expiresAt)
            throw new RecordException(RecordError.Expired,
                "DPC1 is outside its exact MRL2 and transaction-time window.");
        ValidateRoleCapabilities(membership.Roles, membership.Capabilities);
        var currentSpki = contact.FieldSpan(12);
        var nextSpki = contact.FieldSpan(13);
        var noNext = (Scalars.UInt64(contact.FieldSpan(14)) & 1) != 0;
        if (CanonicalGrammar.IsZero(currentSpki) ||
            noNext != CanonicalGrammar.IsZero(nextSpki) ||
            !noNext && CanonicalGrammar.FixedEquals(currentSpki, nextSpki))
            Invalid("DPC1 TLS pin fields are invalid.");
    }

    private static void ValidateRoleCapabilities(
        RouterRoles roles,
        RouterCapabilities capabilities)
    {
        const RouterCapabilities mailboxOnly =
            RouterCapabilities.ClientMailboxIngressV2 |
            RouterCapabilities.ProductionMailboxCacheV2 |
            RouterCapabilities.ProductionMailboxCapacityV1;
        if ((capabilities & mailboxOnly) != 0 && (roles & RouterRoles.MailboxReplica) == 0)
            Invalid("Mailbox capabilities require the MailboxReplica role.");
        if ((capabilities & RouterCapabilities.MembershipCatalogV2) != 0 &&
            (roles & (RouterRoles.PeerIngress | RouterRoles.PeerCore)) == 0)
            Invalid("MembershipCatalogV2 requires a peer role.");
        if ((capabilities & RouterCapabilities.NativePeerMailboxV2) != 0 && roles == 0)
            Invalid("NativePeerMailboxV2 requires a router role.");
    }

    private static void VerifySignature(OwnedRecord record, ReadOnlySpan<byte> publicKey)
    {
        VerifyDetached(
            record.FieldSpan(15),
            CanonicalGrammar.GetSigningBytes(record, ContactDomain),
            publicKey,
            "DPC1 router signature");
    }

    private static void VerifyDetached(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> publicKey,
        string name)
    {
        try
        {
            if (!PublicKeyAuth.VerifyDetached(
                    signature.ToArray(),
                    signingBytes.ToArray(),
                    publicKey.ToArray()))
                throw new CryptographicException();
        }
        catch (CryptographicException)
        {
            throw new RecordException(RecordError.InvalidSignature,
                $"The {name} is invalid.");
        }
    }

    private static ArtifactReference RetainedReference(
        ArtifactType type,
        ReadOnlySpan<byte> canonical) =>
        new(type, checked((uint)canonical.Length), SHA256.HashData(canonical));

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string message)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected)) Invalid(message);
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
