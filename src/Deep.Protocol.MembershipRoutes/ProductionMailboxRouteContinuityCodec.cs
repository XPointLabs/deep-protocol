using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>
/// Strict fixed-size RCD1/RDA1/RCR1/RCH1 codecs. Signing transcripts and sealed ROL1/RHC1
/// operations are internal so raw signing or history capabilities are not exposed publicly.
/// </summary>
public static class ProductionMailboxRouteContinuityCodec
{
    private static ReadOnlySpan<byte> DelegationMagic => "RCD1"u8;
    private static ReadOnlySpan<byte> AcceptanceMagic => "RDA1"u8;
    private static ReadOnlySpan<byte> RevocationMagic => "RCR1"u8;
    private static ReadOnlySpan<byte> CheckpointMagic => "RCH1"u8;
    private static ReadOnlySpan<byte> RouteOriginMagic => "ROL1"u8;
    private static ReadOnlySpan<byte> HistoryCheckpointMagic => "RHC1"u8;
    private static ReadOnlySpan<byte> DelegationDomain =>
        "Deep/production-mailbox/route-continuity-delegation/v1"u8;
    private static ReadOnlySpan<byte> AcceptanceDomain =>
        "Deep/production-mailbox/route-delegation-acceptance/v1"u8;
    private static ReadOnlySpan<byte> RevocationDomain =>
        "Deep/production-mailbox/route-continuity-revocation/v1"u8;
    private static ReadOnlySpan<byte> CheckpointDomain =>
        "Deep/production-mailbox/route-revocation-checkpoint/v1"u8;
    private static ReadOnlySpan<byte> RouteOriginHashDomain =>
        "Deep/production-mailbox/route-origin-lkg/v1"u8;
    private static ReadOnlySpan<byte> HistoryCheckpointHashDomain =>
        "Deep/production-mailbox/route-history-checkpoint-hash/v1"u8;
    private static ReadOnlySpan<byte> HistoryDelegationDomain =>
        "Deep/production-mailbox/route-history-delegation/v1"u8;
    private static ReadOnlySpan<byte> ContinuityCommitmentDomain =>
        "Deep/production-mailbox/continuity-commitment/v1"u8;

    public static byte[] EncodeDelegation(ProductionMailboxRouteContinuityDelegation value)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteContinuityCopy.Clone(value);
        Validate(frozen, requireSignature: true);
        return EncodeCore(frozen, includeSignature: true);
    }

    public static ProductionMailboxRouteContinuityDelegation DecodeDelegation(ReadOnlySpan<byte> encoded)
    {
        var frozen = Snapshot(encoded, ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength, "RCD1");
        Header(frozen, DelegationMagic, ProductionMailboxRouteContinuityConstants.Version, "RCD1");
        var reader = new Reader(frozen, 8);
        var value = new ProductionMailboxRouteContinuityDelegation
        {
            NetworkId = reader.Bytes(16),
            PinnedMrXPublicKeySha256 = reader.Bytes(32),
            RouteDomainHash = reader.Bytes(32),
            MailboxOwnerEd25519PublicKey = reader.Bytes(32),
            BlindedMailboxId = reader.Bytes(32),
            BlindedPlacementId = reader.Bytes(32),
            SelectionInputCommitment = reader.Bytes(32),
            AnchorAuthorityGeneration = reader.UInt64(),
            AnchorCanonicalAuthorityHash = reader.Bytes(32),
            AnchorCanonicalRouteCertificateHash = reader.Bytes(32),
            AnchorAuthorizationKind = (ProductionMailboxRouteAuthorizationKind)reader.Byte(),
            AnchorCanonicalRouteAuthorizationHash = reader.Skip(7).Bytes(32),
            AnchorRouteAuthorizationSequence = reader.UInt64(),
            PreDelegationRouteOriginLkgHash = reader.Bytes(32),
            RouteVerifiedAtUnixSeconds = reader.UInt64(),
            Capability = (ProductionMailboxRouteContinuityCapability)reader.Byte(),
            DelegationSerial = reader.Skip(7).Bytes(16),
            DelegationSequence = reader.UInt64(),
            PreviousCanonicalDelegationHash = reader.Bytes(32),
            MaximumAuthorityGeneration = reader.UInt64(),
            FirstActivationSequence = reader.UInt64(),
            LastActivationSequence = reader.UInt64(),
            IssuedAtUnixSeconds = reader.UInt64(),
            NotBeforeUnixSeconds = reader.UInt64(),
            ExpiresAtUnixSeconds = reader.UInt64(),
            OwnerSignature = reader.Bytes(64)
        };
        reader.End("RCD1");
        Validate(value, requireSignature: true);
        Canonical(frozen, EncodeCore(value, includeSignature: true), "RCD1");
        return value;
    }

    public static byte[] EncodeDelegationAcceptance(ProductionMailboxRouteDelegationAcceptance value)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteContinuityCopy.Clone(value);
        Validate(frozen, requireSignature: true);
        return EncodeCore(frozen, includeSignature: true);
    }

    public static ProductionMailboxRouteDelegationAcceptance DecodeDelegationAcceptance(
        ReadOnlySpan<byte> encoded)
    {
        var frozen = Snapshot(encoded,
            ProductionMailboxRouteContinuityConstants.CanonicalDelegationAcceptanceLength, "RDA1");
        Header(frozen, AcceptanceMagic, ProductionMailboxRouteContinuityConstants.Version, "RDA1");
        var reader = new Reader(frozen, 8);
        var value = new ProductionMailboxRouteDelegationAcceptance
        {
            NetworkId = reader.Bytes(16),
            RouteDomainHash = reader.Bytes(32),
            CanonicalDelegationHash = reader.Bytes(32),
            AnchorAuthorityGeneration = reader.UInt64(),
            AnchorCanonicalAuthorityHash = reader.Bytes(32),
            AnchorCanonicalRouteCertificateHash = reader.Bytes(32),
            AnchorAuthorizationKind = (ProductionMailboxRouteAuthorizationKind)reader.Byte(),
            AnchorCanonicalRouteAuthorizationHash = reader.Skip(7).Bytes(32),
            AnchorRouteAuthorizationSequence = reader.UInt64(),
            PreDelegationRouteOriginLkgHash = reader.Bytes(32),
            RouteVerifiedAtUnixSeconds = reader.UInt64(),
            AcceptedAtUnixSeconds = reader.UInt64(),
            AnchorIssuerSignature = reader.Bytes(64)
        };
        reader.End("RDA1");
        Validate(value, requireSignature: true);
        Canonical(frozen, EncodeCore(value, includeSignature: true), "RDA1");
        return value;
    }

    public static byte[] EncodeRevocation(ProductionMailboxRouteContinuityRevocation value)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteContinuityCopy.Clone(value);
        Validate(frozen, requireSignature: true);
        return EncodeCore(frozen, includeSignature: true);
    }

    public static ProductionMailboxRouteContinuityRevocation DecodeRevocation(ReadOnlySpan<byte> encoded)
    {
        var frozen = Snapshot(encoded, ProductionMailboxRouteContinuityConstants.CanonicalRevocationLength, "RCR1");
        Header(frozen, RevocationMagic, ProductionMailboxRouteContinuityConstants.Version, "RCR1");
        var reader = new Reader(frozen, 8);
        var value = new ProductionMailboxRouteContinuityRevocation
        {
            NetworkId = reader.Bytes(16),
            RouteDomainHash = reader.Bytes(32),
            TargetDelegationSerial = reader.Bytes(16),
            TargetCanonicalDelegationHash = reader.Bytes(32),
            RevocationGeneration = reader.UInt64(),
            PreviousCanonicalRevocationHash = reader.Bytes(32),
            RevokedAtUnixSeconds = reader.UInt64(),
            Reason = (ProductionMailboxRouteContinuityRevocationReason)reader.Byte(),
            OwnerSignature = reader.Skip(7).Bytes(64)
        };
        reader.End("RCR1");
        Validate(value, requireSignature: true);
        Canonical(frozen, EncodeCore(value, includeSignature: true), "RCR1");
        return value;
    }

    public static byte[] EncodeRevocationCheckpoint(ProductionMailboxRouteRevocationCheckpoint value)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteContinuityCopy.Clone(value);
        Validate(frozen, requireSignature: true);
        return EncodeCore(frozen, includeSignature: true);
    }

    public static ProductionMailboxRouteRevocationCheckpoint DecodeRevocationCheckpoint(
        ReadOnlySpan<byte> encoded)
    {
        var frozen = Snapshot(encoded,
            ProductionMailboxRouteContinuityConstants.CanonicalRevocationCheckpointLength, "RCH1");
        Header(frozen, CheckpointMagic, ProductionMailboxRouteContinuityConstants.Version, "RCH1");
        var reader = new Reader(frozen, 8);
        var value = new ProductionMailboxRouteRevocationCheckpoint
        {
            NetworkId = reader.Bytes(16),
            RouteDomainHash = reader.Bytes(32),
            CurrentAuthorityGeneration = reader.UInt64(),
            CurrentCanonicalAuthorityHash = reader.Bytes(32),
            CurrentIssuerEd25519PublicKey = reader.Bytes(32),
            CurrentOwnerRevocationGeneration = reader.UInt64(),
            CurrentOwnerRevocationHeadHash = reader.Bytes(32),
            TransitionSalt = reader.Bytes(32),
            ContinuityTransitionCommitment = reader.Bytes(32),
            Status = (ProductionMailboxRouteRevocationStatus)reader.Byte(),
            IssuedAtUnixSeconds = reader.Skip(7).UInt64(),
            ExpiresAtUnixSeconds = reader.UInt64(),
            CurrentIssuerSignature = reader.Bytes(64)
        };
        reader.End("RCH1");
        Validate(value, requireSignature: true);
        Canonical(frozen, EncodeCore(value, includeSignature: true), "RCH1");
        return value;
    }

    internal static byte[] GetDelegationSigningBytes(ProductionMailboxRouteContinuityDelegation value) =>
        SigningBytes(value, DelegationDomain);

    internal static byte[] GetDelegationAcceptanceSigningBytes(
        ProductionMailboxRouteDelegationAcceptance value) => SigningBytes(value, AcceptanceDomain);

    internal static byte[] GetRevocationSigningBytes(ProductionMailboxRouteContinuityRevocation value) =>
        SigningBytes(value, RevocationDomain);

    internal static byte[] GetRevocationCheckpointSigningBytes(
        ProductionMailboxRouteRevocationCheckpoint value) => SigningBytes(value, CheckpointDomain);

    internal static byte[] ComputeDelegationCanonicalHash(ProductionMailboxRouteContinuityDelegation value) =>
        SHA256.HashData(EncodeDelegation(value));

    internal static byte[] ComputeDelegationAcceptanceCanonicalHash(
        ProductionMailboxRouteDelegationAcceptance value) => SHA256.HashData(EncodeDelegationAcceptance(value));

    internal static byte[] ComputeRevocationCanonicalHash(ProductionMailboxRouteContinuityRevocation value) =>
        SHA256.HashData(EncodeRevocation(value));

    internal static byte[] ComputeRevocationCheckpointCanonicalHash(
        ProductionMailboxRouteRevocationCheckpoint value) => SHA256.HashData(EncodeRevocationCheckpoint(value));

    internal static byte[] EncodeRouteOriginLkg(ProductionMailboxRouteOriginLkg value)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteContinuityCopy.Clone(value);
        Validate(frozen);
        var writer = Writer.Create(ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength,
            RouteOriginMagic, ProductionMailboxRouteContinuityConstants.Version);
        writer.Bytes(frozen.NetworkId.Span);
        writer.Bytes(frozen.RouteDomainHash.Span);
        writer.Byte((byte)frozen.AuthorizationKind).Zero(7);
        writer.Bytes(frozen.CanonicalAuthorizationHash.Span);
        writer.UInt64(frozen.AuthorizationSequence);
        writer.Bytes(frozen.CanonicalDelegationHash.Span);
        writer.Bytes(frozen.CanonicalDelegationAcceptanceHash.Span);
        writer.UInt64(frozen.OwnerRevocationGeneration);
        writer.Bytes(frozen.OwnerRevocationHeadHash.Span);
        writer.UInt64(frozen.RouteVerifiedAtUnixSeconds);
        writer.UInt64(frozen.LocalCommitGeneration);
        return writer.Finish("ROL1");
    }

    internal static ProductionMailboxRouteOriginLkg DecodeRouteOriginLkg(ReadOnlySpan<byte> encoded)
    {
        var frozen = Snapshot(encoded, ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength,
            "ROL1");
        Header(frozen, RouteOriginMagic, ProductionMailboxRouteContinuityConstants.Version, "ROL1");
        var reader = new Reader(frozen, 8);
        var value = new ProductionMailboxRouteOriginLkg
        {
            NetworkId = reader.Bytes(16),
            RouteDomainHash = reader.Bytes(32),
            AuthorizationKind = (ProductionMailboxRouteAuthorizationKind)reader.Byte(),
            CanonicalAuthorizationHash = reader.Skip(7).Bytes(32),
            AuthorizationSequence = reader.UInt64(),
            CanonicalDelegationHash = reader.Bytes(32),
            CanonicalDelegationAcceptanceHash = reader.Bytes(32),
            OwnerRevocationGeneration = reader.UInt64(),
            OwnerRevocationHeadHash = reader.Bytes(32),
            RouteVerifiedAtUnixSeconds = reader.UInt64(),
            LocalCommitGeneration = reader.UInt64()
        };
        reader.End("ROL1");
        Validate(value);
        Canonical(frozen, EncodeRouteOriginLkg(value), "ROL1");
        return value;
    }

    internal static byte[] ComputeRouteOriginLkgHash(ProductionMailboxRouteOriginLkg value) =>
        DomainHash(RouteOriginHashDomain, EncodeRouteOriginLkg(value));

    internal static byte[] EncodeRouteHistoryCheckpoint(ProductionMailboxRouteHistoryCheckpoint value)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteContinuityCopy.Clone(value);
        Validate(frozen);
        var writer = Writer.Create(
            ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength,
            HistoryCheckpointMagic, ProductionMailboxRouteContinuityConstants.Version);
        writer.Bytes(frozen.NetworkId.Span);
        writer.Bytes(frozen.RouteDomainHash.Span);
        writer.Bytes(frozen.DelegationHistoryBinding.Span);
        writer.Byte((byte)frozen.CurrentAuthorizationKind).Zero(7);
        writer.Bytes(frozen.CurrentCanonicalAuthorizationHash.Span);
        writer.UInt64(frozen.CurrentAuthorizationSequence);
        writer.UInt64(frozen.OwnerRevocationGeneration);
        writer.Bytes(frozen.OwnerRevocationHeadHash.Span);
        writer.Bytes(frozen.CurrentRouteOriginLkgHash.Span);
        writer.UInt64(frozen.RouteVerifiedAtUnixSeconds);
        writer.UInt64(frozen.CurrentLocalCommitGeneration);
        writer.Bytes(frozen.PinnedMrXPublicKeySha256.Span);
        writer.UInt64(frozen.CurrentAuthorityGeneration);
        writer.Bytes(frozen.CurrentCanonicalAuthorityHash.Span);
        writer.UInt64(frozen.CurrentRevocationGeneration);
        writer.Bytes(frozen.CurrentRevocationHeadHash.Span);
        writer.Bytes(frozen.CurrentRevocationSnapshotHash.Span);
        writer.UInt64(frozen.LastCommittedBatchSequence);
        writer.UInt64(frozen.CumulativeCommittedBatchCount);
        writer.UInt64(frozen.CumulativeVerifiedRouteLinkCount);
        writer.UInt64(frozen.CumulativeCanonicalPayloadBytes);
        writer.Bytes(frozen.HistoryTranscriptHead.Span);
        writer.Bytes(frozen.LastCommittedBatchHash.Span);
        return writer.Finish("RHC1");
    }

    internal static ProductionMailboxRouteHistoryCheckpoint DecodeRouteHistoryCheckpoint(
        ReadOnlySpan<byte> encoded)
    {
        var frozen = Snapshot(encoded,
            ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength, "RHC1");
        Header(frozen, HistoryCheckpointMagic, ProductionMailboxRouteContinuityConstants.Version, "RHC1");
        var reader = new Reader(frozen, 8);
        var value = new ProductionMailboxRouteHistoryCheckpoint
        {
            NetworkId = reader.Bytes(16),
            RouteDomainHash = reader.Bytes(32),
            DelegationHistoryBinding = reader.Bytes(32),
            CurrentAuthorizationKind = (ProductionMailboxRouteAuthorizationKind)reader.Byte(),
            CurrentCanonicalAuthorizationHash = reader.Skip(7).Bytes(32),
            CurrentAuthorizationSequence = reader.UInt64(),
            OwnerRevocationGeneration = reader.UInt64(),
            OwnerRevocationHeadHash = reader.Bytes(32),
            CurrentRouteOriginLkgHash = reader.Bytes(32),
            RouteVerifiedAtUnixSeconds = reader.UInt64(),
            CurrentLocalCommitGeneration = reader.UInt64(),
            PinnedMrXPublicKeySha256 = reader.Bytes(32),
            CurrentAuthorityGeneration = reader.UInt64(),
            CurrentCanonicalAuthorityHash = reader.Bytes(32),
            CurrentRevocationGeneration = reader.UInt64(),
            CurrentRevocationHeadHash = reader.Bytes(32),
            CurrentRevocationSnapshotHash = reader.Bytes(32),
            LastCommittedBatchSequence = reader.UInt64(),
            CumulativeCommittedBatchCount = reader.UInt64(),
            CumulativeVerifiedRouteLinkCount = reader.UInt64(),
            CumulativeCanonicalPayloadBytes = reader.UInt64(),
            HistoryTranscriptHead = reader.Bytes(32),
            LastCommittedBatchHash = reader.Bytes(32)
        };
        reader.End("RHC1");
        Validate(value);
        Canonical(frozen, EncodeRouteHistoryCheckpoint(value), "RHC1");
        return value;
    }

    internal static byte[] ComputeRouteHistoryCheckpointHash(
        ProductionMailboxRouteHistoryCheckpoint value) =>
        DomainHash(HistoryCheckpointHashDomain, EncodeRouteHistoryCheckpoint(value));

    internal static byte[] ComputeDelegationHistoryBinding(
        ReadOnlySpan<byte> canonicalDelegationHash,
        ReadOnlySpan<byte> canonicalAcceptanceHash)
    {
        if (canonicalDelegationHash.Length != 32 || canonicalAcceptanceHash.Length != 32)
            throw Error(ProductionMailboxRouteContinuityError.InvalidLength,
                "RHC1 delegation binding inputs must be exact SHA-256 values.");
        return DomainHash(HistoryDelegationDomain, canonicalDelegationHash, canonicalAcceptanceHash);
    }

    internal static byte[] ComputeContinuityTransitionCommitment(
        ReadOnlySpan<byte> transitionSalt,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> routeDomainHash,
        ReadOnlySpan<byte> canonicalDelegationHash,
        ReadOnlySpan<byte> canonicalAcceptanceHash,
        ReadOnlySpan<byte> routeOriginLkgHash,
        ulong ownerRevocationGeneration,
        ReadOnlySpan<byte> ownerRevocationHeadHash,
        ReadOnlySpan<byte> currentAuthorityHash,
        ReadOnlySpan<byte> freshRouteCertificateHash,
        ProductionMailboxRouteAuthorizationKind predecessorKind,
        ReadOnlySpan<byte> predecessorHash,
        ulong predecessorSequence,
        ulong newSequence)
    {
        if (transitionSalt.Length != 32 || networkId.Length != 16 || routeDomainHash.Length != 32 ||
            canonicalDelegationHash.Length != 32 || canonicalAcceptanceHash.Length != 32 ||
            routeOriginLkgHash.Length != 32 || ownerRevocationHeadHash.Length != 32 ||
            currentAuthorityHash.Length != 32 || freshRouteCertificateHash.Length != 32 ||
            predecessorHash.Length != 32 || predecessorKind == ProductionMailboxRouteAuthorizationKind.None ||
            !Enum.IsDefined(predecessorKind) || predecessorSequence == 0 ||
            predecessorSequence == ulong.MaxValue || newSequence != predecessorSequence + 1)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "Continuity commitment inputs are incomplete or non-canonical.");
        Span<byte> number = stackalloc byte[8];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(ContinuityCommitmentDomain);
        hash.AppendData(transitionSalt); hash.AppendData(networkId); hash.AppendData(routeDomainHash);
        hash.AppendData(canonicalDelegationHash); hash.AppendData(canonicalAcceptanceHash);
        hash.AppendData(routeOriginLkgHash);
        BinaryPrimitives.WriteUInt64BigEndian(number, ownerRevocationGeneration); hash.AppendData(number);
        hash.AppendData(ownerRevocationHeadHash); hash.AppendData(currentAuthorityHash);
        hash.AppendData(freshRouteCertificateHash); hash.AppendData([(byte)predecessorKind]);
        hash.AppendData(predecessorHash);
        BinaryPrimitives.WriteUInt64BigEndian(number, predecessorSequence); hash.AppendData(number);
        BinaryPrimitives.WriteUInt64BigEndian(number, newSequence); hash.AppendData(number);
        return hash.GetHashAndReset();
    }

    private static byte[] SigningBytes(
        ProductionMailboxRouteContinuityDelegation value, ReadOnlySpan<byte> domain)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteContinuityCopy.Clone(value);
        Validate(frozen, requireSignature: false);
        return [.. domain, .. EncodeCore(frozen, includeSignature: false)];
    }

    private static byte[] SigningBytes(
        ProductionMailboxRouteDelegationAcceptance value, ReadOnlySpan<byte> domain)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteContinuityCopy.Clone(value);
        Validate(frozen, requireSignature: false);
        return [.. domain, .. EncodeCore(frozen, includeSignature: false)];
    }

    private static byte[] SigningBytes(
        ProductionMailboxRouteContinuityRevocation value, ReadOnlySpan<byte> domain)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteContinuityCopy.Clone(value);
        Validate(frozen, requireSignature: false);
        return [.. domain, .. EncodeCore(frozen, includeSignature: false)];
    }

    private static byte[] SigningBytes(
        ProductionMailboxRouteRevocationCheckpoint value, ReadOnlySpan<byte> domain)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteContinuityCopy.Clone(value);
        Validate(frozen, requireSignature: false);
        return [.. domain, .. EncodeCore(frozen, includeSignature: false)];
    }

    private static byte[] EncodeCore(
        ProductionMailboxRouteContinuityDelegation value, bool includeSignature)
    {
        var length = ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength -
            (includeSignature ? 0 : 64);
        var writer = Writer.Create(length, DelegationMagic, ProductionMailboxRouteContinuityConstants.Version);
        writer.Bytes(value.NetworkId.Span);
        writer.Bytes(value.PinnedMrXPublicKeySha256.Span);
        writer.Bytes(value.RouteDomainHash.Span);
        writer.Bytes(value.MailboxOwnerEd25519PublicKey.Span);
        writer.Bytes(value.BlindedMailboxId.Span);
        writer.Bytes(value.BlindedPlacementId.Span);
        writer.Bytes(value.SelectionInputCommitment.Span);
        writer.UInt64(value.AnchorAuthorityGeneration);
        writer.Bytes(value.AnchorCanonicalAuthorityHash.Span);
        writer.Bytes(value.AnchorCanonicalRouteCertificateHash.Span);
        writer.Byte((byte)value.AnchorAuthorizationKind).Zero(7);
        writer.Bytes(value.AnchorCanonicalRouteAuthorizationHash.Span);
        writer.UInt64(value.AnchorRouteAuthorizationSequence);
        writer.Bytes(value.PreDelegationRouteOriginLkgHash.Span);
        writer.UInt64(value.RouteVerifiedAtUnixSeconds);
        writer.Byte((byte)value.Capability).Zero(7);
        writer.Bytes(value.DelegationSerial.Span);
        writer.UInt64(value.DelegationSequence);
        writer.Bytes(value.PreviousCanonicalDelegationHash.Span);
        writer.UInt64(value.MaximumAuthorityGeneration);
        writer.UInt64(value.FirstActivationSequence);
        writer.UInt64(value.LastActivationSequence);
        writer.UInt64(value.IssuedAtUnixSeconds);
        writer.UInt64(value.NotBeforeUnixSeconds);
        writer.UInt64(value.ExpiresAtUnixSeconds);
        if (includeSignature) writer.Bytes(value.OwnerSignature.Span);
        return writer.Finish("RCD1");
    }

    private static byte[] EncodeCore(
        ProductionMailboxRouteDelegationAcceptance value, bool includeSignature)
    {
        var length = ProductionMailboxRouteContinuityConstants.CanonicalDelegationAcceptanceLength -
            (includeSignature ? 0 : 64);
        var writer = Writer.Create(length, AcceptanceMagic, ProductionMailboxRouteContinuityConstants.Version);
        writer.Bytes(value.NetworkId.Span);
        writer.Bytes(value.RouteDomainHash.Span);
        writer.Bytes(value.CanonicalDelegationHash.Span);
        writer.UInt64(value.AnchorAuthorityGeneration);
        writer.Bytes(value.AnchorCanonicalAuthorityHash.Span);
        writer.Bytes(value.AnchorCanonicalRouteCertificateHash.Span);
        writer.Byte((byte)value.AnchorAuthorizationKind).Zero(7);
        writer.Bytes(value.AnchorCanonicalRouteAuthorizationHash.Span);
        writer.UInt64(value.AnchorRouteAuthorizationSequence);
        writer.Bytes(value.PreDelegationRouteOriginLkgHash.Span);
        writer.UInt64(value.RouteVerifiedAtUnixSeconds);
        writer.UInt64(value.AcceptedAtUnixSeconds);
        if (includeSignature) writer.Bytes(value.AnchorIssuerSignature.Span);
        return writer.Finish("RDA1");
    }

    private static byte[] EncodeCore(
        ProductionMailboxRouteContinuityRevocation value, bool includeSignature)
    {
        var length = ProductionMailboxRouteContinuityConstants.CanonicalRevocationLength -
            (includeSignature ? 0 : 64);
        var writer = Writer.Create(length, RevocationMagic, ProductionMailboxRouteContinuityConstants.Version);
        writer.Bytes(value.NetworkId.Span);
        writer.Bytes(value.RouteDomainHash.Span);
        writer.Bytes(value.TargetDelegationSerial.Span);
        writer.Bytes(value.TargetCanonicalDelegationHash.Span);
        writer.UInt64(value.RevocationGeneration);
        writer.Bytes(value.PreviousCanonicalRevocationHash.Span);
        writer.UInt64(value.RevokedAtUnixSeconds);
        writer.Byte((byte)value.Reason).Zero(7);
        if (includeSignature) writer.Bytes(value.OwnerSignature.Span);
        return writer.Finish("RCR1");
    }

    private static byte[] EncodeCore(
        ProductionMailboxRouteRevocationCheckpoint value, bool includeSignature)
    {
        var length = ProductionMailboxRouteContinuityConstants.CanonicalRevocationCheckpointLength -
            (includeSignature ? 0 : 64);
        var writer = Writer.Create(length, CheckpointMagic, ProductionMailboxRouteContinuityConstants.Version);
        writer.Bytes(value.NetworkId.Span);
        writer.Bytes(value.RouteDomainHash.Span);
        writer.UInt64(value.CurrentAuthorityGeneration);
        writer.Bytes(value.CurrentCanonicalAuthorityHash.Span);
        writer.Bytes(value.CurrentIssuerEd25519PublicKey.Span);
        writer.UInt64(value.CurrentOwnerRevocationGeneration);
        writer.Bytes(value.CurrentOwnerRevocationHeadHash.Span);
        writer.Bytes(value.TransitionSalt.Span);
        writer.Bytes(value.ContinuityTransitionCommitment.Span);
        writer.Byte((byte)value.Status).Zero(7);
        writer.UInt64(value.IssuedAtUnixSeconds);
        writer.UInt64(value.ExpiresAtUnixSeconds);
        if (includeSignature) writer.Bytes(value.CurrentIssuerSignature.Span);
        return writer.Finish("RCH1");
    }

    private static void Validate(ProductionMailboxRouteContinuityDelegation value, bool requireSignature)
    {
        Nonzero(value.NetworkId, 16, "network ID");
        Nonzero(value.PinnedMrXPublicKeySha256, 32, "pinned Mr. X hash");
        Nonzero(value.RouteDomainHash, 32, "route-domain hash");
        Nonzero(value.MailboxOwnerEd25519PublicKey, 32, "mailbox owner key");
        Nonzero(value.BlindedMailboxId, 32, "blinded mailbox ID");
        Nonzero(value.BlindedPlacementId, 32, "blinded placement ID");
        Nonzero(value.SelectionInputCommitment, 32, "selection-input commitment");
        Counter(value.AnchorAuthorityGeneration, "anchor authority generation");
        Nonzero(value.AnchorCanonicalAuthorityHash, 32, "anchor PMA1 hash");
        Nonzero(value.AnchorCanonicalRouteCertificateHash, 32, "anchor PRC1 hash");
        if (value.AnchorAuthorizationKind != ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
            throw Error(ProductionMailboxRouteContinuityError.InvalidAuthorizationKind,
                "RCD1 anchor authorization must be OwnerPRA2.");
        Nonzero(value.AnchorCanonicalRouteAuthorizationHash, 32, "anchor PRA2 hash");
        Counter(value.AnchorRouteAuthorizationSequence, "anchor route authorization sequence");
        Nonzero(value.PreDelegationRouteOriginLkgHash, 32, "pre-delegation ROL1 hash");
        Counter(value.RouteVerifiedAtUnixSeconds, "RouteVerifiedAt");
        if (value.Capability != ProductionMailboxRouteContinuityCapability.RouteContinuityOnly)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCD1 capability must be RouteContinuityOnly.");
        Nonzero(value.DelegationSerial, 16, "delegation serial");
        Counter(value.DelegationSequence, "delegation sequence");
        Fixed(value.PreviousCanonicalDelegationHash, 32, "previous RCD1 hash");
        if ((value.DelegationSequence == 1) != IsZero(value.PreviousCanonicalDelegationHash))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCD1 previous hash is zero exactly for delegation sequence one.");
        Counter(value.MaximumAuthorityGeneration, "maximum authority generation");
        if (value.MaximumAuthorityGeneration <= value.AnchorAuthorityGeneration ||
            value.MaximumAuthorityGeneration - value.AnchorAuthorityGeneration >
                ProductionMailboxRouteContinuityConstants.MaximumAuthorityGenerationAdvance)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCD1 authority ceiling is outside the bounded successor range.");
        Counter(value.FirstActivationSequence, "first activation sequence");
        Counter(value.LastActivationSequence, "last activation sequence");
        if (value.AnchorRouteAuthorizationSequence == ulong.MaxValue ||
            value.FirstActivationSequence != value.AnchorRouteAuthorizationSequence + 1 ||
            value.LastActivationSequence < value.FirstActivationSequence ||
            value.LastActivationSequence - value.FirstActivationSequence >=
                ProductionMailboxRouteContinuityConstants.MaximumActivationSequenceCount)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCD1 activation range is not exact-next or exceeds 512 sequences.");
        if (value.IssuedAtUnixSeconds == 0 || value.IssuedAtUnixSeconds == ulong.MaxValue ||
            value.NotBeforeUnixSeconds == 0 || value.NotBeforeUnixSeconds == ulong.MaxValue ||
            value.ExpiresAtUnixSeconds == 0 || value.ExpiresAtUnixSeconds == ulong.MaxValue ||
            value.IssuedAtUnixSeconds > value.NotBeforeUnixSeconds ||
            value.NotBeforeUnixSeconds >= value.ExpiresAtUnixSeconds ||
            value.ExpiresAtUnixSeconds - value.NotBeforeUnixSeconds >
                ProductionMailboxRouteContinuityConstants.MaximumDelegationLifetimeSeconds ||
            value.RouteVerifiedAtUnixSeconds > value.IssuedAtUnixSeconds)
            throw Error(ProductionMailboxRouteContinuityError.InvalidValidityWindow,
                "RCD1 validity or RouteVerifiedAt is invalid.");
        Signature(value.OwnerSignature, requireSignature, "owner signature");
    }

    private static void Validate(ProductionMailboxRouteDelegationAcceptance value, bool requireSignature)
    {
        Nonzero(value.NetworkId, 16, "network ID");
        Nonzero(value.RouteDomainHash, 32, "route-domain hash");
        Nonzero(value.CanonicalDelegationHash, 32, "RCD1 hash");
        Counter(value.AnchorAuthorityGeneration, "anchor authority generation");
        Nonzero(value.AnchorCanonicalAuthorityHash, 32, "anchor PMA1 hash");
        Nonzero(value.AnchorCanonicalRouteCertificateHash, 32, "anchor PRC1 hash");
        if (value.AnchorAuthorizationKind != ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
            throw Error(ProductionMailboxRouteContinuityError.InvalidAuthorizationKind,
                "RDA1 anchor authorization must be OwnerPRA2.");
        Nonzero(value.AnchorCanonicalRouteAuthorizationHash, 32, "anchor PRA2 hash");
        Counter(value.AnchorRouteAuthorizationSequence, "anchor route authorization sequence");
        Nonzero(value.PreDelegationRouteOriginLkgHash, 32, "pre-delegation ROL1 hash");
        Counter(value.RouteVerifiedAtUnixSeconds, "RouteVerifiedAt");
        Counter(value.AcceptedAtUnixSeconds, "accepted-at");
        if (value.RouteVerifiedAtUnixSeconds > value.AcceptedAtUnixSeconds)
            throw Error(ProductionMailboxRouteContinuityError.InvalidValidityWindow,
                "RDA1 accepted-at precedes RouteVerifiedAt.");
        Signature(value.AnchorIssuerSignature, requireSignature, "anchor issuer signature");
    }

    private static void Validate(ProductionMailboxRouteContinuityRevocation value, bool requireSignature)
    {
        Nonzero(value.NetworkId, 16, "network ID");
        Nonzero(value.RouteDomainHash, 32, "route-domain hash");
        Nonzero(value.TargetDelegationSerial, 16, "target delegation serial");
        Nonzero(value.TargetCanonicalDelegationHash, 32, "target RCD1 hash");
        if (value.RevocationGeneration != 1 || !IsZero(value.PreviousCanonicalRevocationHash))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCR1 is the sole terminal 0/zero to 1/exact-hash transition.");
        Fixed(value.PreviousCanonicalRevocationHash, 32, "previous RCR1 hash");
        Counter(value.RevokedAtUnixSeconds, "revoked-at");
        if (!Enum.IsDefined(value.Reason))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCR1 revocation reason is unsupported.");
        Signature(value.OwnerSignature, requireSignature, "owner signature");
    }

    private static void Validate(ProductionMailboxRouteRevocationCheckpoint value, bool requireSignature)
    {
        Nonzero(value.NetworkId, 16, "network ID");
        Nonzero(value.RouteDomainHash, 32, "route-domain hash");
        Counter(value.CurrentAuthorityGeneration, "current authority generation");
        Nonzero(value.CurrentCanonicalAuthorityHash, 32, "current PMA1 hash");
        Nonzero(value.CurrentIssuerEd25519PublicKey, 32, "current issuer key");
        Fixed(value.CurrentOwnerRevocationHeadHash, 32, "current owner RCR1 head");
        if (!Enum.IsDefined(value.Status) ||
            (value.Status == ProductionMailboxRouteRevocationStatus.Active &&
                (value.CurrentOwnerRevocationGeneration != 0 || !IsZero(value.CurrentOwnerRevocationHeadHash))) ||
            (value.Status == ProductionMailboxRouteRevocationStatus.Revoked &&
                (value.CurrentOwnerRevocationGeneration != 1 || IsZero(value.CurrentOwnerRevocationHeadHash))))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RCH1 status does not match the exact per-delegation owner revocation state.");
        Nonzero(value.TransitionSalt, 32, "transition salt");
        Nonzero(value.ContinuityTransitionCommitment, 32, "continuity commitment");
        Window(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds,
            ProductionMailboxRouteContinuityConstants.MaximumCheckpointLifetimeSeconds, "RCH1");
        Signature(value.CurrentIssuerSignature, requireSignature, "current issuer signature");
    }

    private static void Validate(ProductionMailboxRouteOriginLkg value)
    {
        Nonzero(value.NetworkId, 16, "network ID");
        Nonzero(value.RouteDomainHash, 32, "route-domain hash");
        Authorization(value.AuthorizationKind, allowNone: false, "ROL1 authorization");
        Nonzero(value.CanonicalAuthorizationHash, 32, "authorization hash");
        Counter(value.AuthorizationSequence, "authorization sequence");
        Fixed(value.CanonicalDelegationHash, 32, "RCD1 hash");
        Fixed(value.CanonicalDelegationAcceptanceHash, 32, "RDA1 hash");
        if (IsZero(value.CanonicalDelegationHash) != IsZero(value.CanonicalDelegationAcceptanceHash))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "ROL1 RCD1 and RDA1 slots must both be zero or both be present.");
        RevocationState(value.OwnerRevocationGeneration, value.OwnerRevocationHeadHash, "ROL1 owner revocation");
        Counter(value.RouteVerifiedAtUnixSeconds, "RouteVerifiedAt");
        Counter(value.LocalCommitGeneration, "local route commit generation");
    }

    private static void Validate(ProductionMailboxRouteHistoryCheckpoint value)
    {
        Nonzero(value.NetworkId, 16, "network ID");
        Nonzero(value.RouteDomainHash, 32, "route-domain hash");
        Nonzero(value.DelegationHistoryBinding, 32, "delegation history binding");
        Authorization(value.CurrentAuthorizationKind, allowNone: false, "RHC1 authorization");
        Nonzero(value.CurrentCanonicalAuthorizationHash, 32, "current authorization hash");
        Counter(value.CurrentAuthorizationSequence, "current authorization sequence");
        RevocationState(value.OwnerRevocationGeneration, value.OwnerRevocationHeadHash,
            "RHC1 owner revocation");
        Nonzero(value.CurrentRouteOriginLkgHash, 32, "current ROL1 hash");
        Counter(value.RouteVerifiedAtUnixSeconds, "RouteVerifiedAt");
        Counter(value.CurrentLocalCommitGeneration, "current local route commit generation");
        Nonzero(value.PinnedMrXPublicKeySha256, 32, "pinned Mr. X hash");
        Counter(value.CurrentAuthorityGeneration, "current authority generation");
        Nonzero(value.CurrentCanonicalAuthorityHash, 32, "current PMA1 hash");
        Counter(value.CurrentRevocationGeneration, "current PMR1 generation");
        Nonzero(value.CurrentRevocationHeadHash, 32, "current PMR1 head");
        Nonzero(value.CurrentRevocationSnapshotHash, 32, "current PMR1 snapshot hash");
        Fixed(value.HistoryTranscriptHead, 32, "history transcript head");
        Fixed(value.LastCommittedBatchHash, 32, "last committed RHB1 hash");
        if (value.LastCommittedBatchSequence == ulong.MaxValue ||
            value.CumulativeCommittedBatchCount == ulong.MaxValue ||
            value.CumulativeVerifiedRouteLinkCount == ulong.MaxValue ||
            value.CumulativeCanonicalPayloadBytes == ulong.MaxValue ||
            value.CumulativeCommittedBatchCount > ProductionMailboxRouteContinuityConstants.MaximumHistoryBatchCount ||
            value.CumulativeVerifiedRouteLinkCount > ProductionMailboxRouteContinuityConstants.MaximumHistoryRouteLinkCount ||
            value.CumulativeCanonicalPayloadBytes > ProductionMailboxRouteContinuityConstants.MaximumHistoryPayloadBytes)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RHC1 counters are terminal or exceed the bounded refresh limits.");
        var initial = value.CumulativeCommittedBatchCount == 0;
        if (initial != (value.LastCommittedBatchSequence == 0) ||
            initial != (value.CumulativeVerifiedRouteLinkCount == 0) ||
            initial != (value.CumulativeCanonicalPayloadBytes == 0) ||
            initial != IsZero(value.HistoryTranscriptHead) ||
            initial != IsZero(value.LastCommittedBatchHash))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                "RHC1 initial counters and exact-batch hashes are inconsistent.");
    }

    private static void Preflight(ProductionMailboxRouteContinuityDelegation value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Length(value.NetworkId, 16); Length(value.PinnedMrXPublicKeySha256, 32);
        Length(value.RouteDomainHash, 32); Length(value.MailboxOwnerEd25519PublicKey, 32);
        Length(value.BlindedMailboxId, 32); Length(value.BlindedPlacementId, 32);
        Length(value.SelectionInputCommitment, 32); Length(value.AnchorCanonicalAuthorityHash, 32);
        Length(value.AnchorCanonicalRouteCertificateHash, 32);
        Length(value.AnchorCanonicalRouteAuthorizationHash, 32);
        Length(value.PreDelegationRouteOriginLkgHash, 32); Length(value.DelegationSerial, 16);
        Length(value.PreviousCanonicalDelegationHash, 32); Length(value.OwnerSignature, 64);
    }

    private static void Preflight(ProductionMailboxRouteDelegationAcceptance value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Length(value.NetworkId, 16); Length(value.RouteDomainHash, 32);
        Length(value.CanonicalDelegationHash, 32); Length(value.AnchorCanonicalAuthorityHash, 32);
        Length(value.AnchorCanonicalRouteCertificateHash, 32);
        Length(value.AnchorCanonicalRouteAuthorizationHash, 32);
        Length(value.PreDelegationRouteOriginLkgHash, 32); Length(value.AnchorIssuerSignature, 64);
    }

    private static void Preflight(ProductionMailboxRouteContinuityRevocation value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Length(value.NetworkId, 16); Length(value.RouteDomainHash, 32);
        Length(value.TargetDelegationSerial, 16); Length(value.TargetCanonicalDelegationHash, 32);
        Length(value.PreviousCanonicalRevocationHash, 32); Length(value.OwnerSignature, 64);
    }

    private static void Preflight(ProductionMailboxRouteRevocationCheckpoint value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Length(value.NetworkId, 16); Length(value.RouteDomainHash, 32);
        Length(value.CurrentCanonicalAuthorityHash, 32); Length(value.CurrentIssuerEd25519PublicKey, 32);
        Length(value.CurrentOwnerRevocationHeadHash, 32); Length(value.TransitionSalt, 32);
        Length(value.ContinuityTransitionCommitment, 32); Length(value.CurrentIssuerSignature, 64);
    }

    private static void Preflight(ProductionMailboxRouteOriginLkg value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Length(value.NetworkId, 16); Length(value.RouteDomainHash, 32);
        Length(value.CanonicalAuthorizationHash, 32); Length(value.CanonicalDelegationHash, 32);
        Length(value.CanonicalDelegationAcceptanceHash, 32); Length(value.OwnerRevocationHeadHash, 32);
    }

    private static void Preflight(ProductionMailboxRouteHistoryCheckpoint value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Length(value.NetworkId, 16); Length(value.RouteDomainHash, 32);
        Length(value.DelegationHistoryBinding, 32); Length(value.CurrentCanonicalAuthorizationHash, 32);
        Length(value.OwnerRevocationHeadHash, 32); Length(value.CurrentRouteOriginLkgHash, 32);
        Length(value.PinnedMrXPublicKeySha256, 32); Length(value.CurrentCanonicalAuthorityHash, 32);
        Length(value.CurrentRevocationHeadHash, 32); Length(value.CurrentRevocationSnapshotHash, 32);
        Length(value.HistoryTranscriptHead, 32); Length(value.LastCommittedBatchHash, 32);
    }

    private static void Header(byte[] input, ReadOnlySpan<byte> magic, byte version, string name)
    {
        if (!input.AsSpan(0, 4).SequenceEqual(magic))
            throw Error(ProductionMailboxRouteContinuityError.InvalidMagic, $"{name} magic is invalid.");
        if (input[4] != version)
            throw Error(ProductionMailboxRouteContinuityError.UnsupportedVersion,
                $"{name} version is unsupported.");
        if (input.AsSpan(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(ProductionMailboxRouteContinuityError.ReservedFieldNotZero,
                $"{name} header reserved bytes must be zero.");
    }

    private static byte[] Snapshot(ReadOnlySpan<byte> encoded, int exactLength, string name)
    {
        if (encoded.Length != exactLength)
            throw Error(ProductionMailboxRouteContinuityError.InvalidLength,
                $"{name} must have its exact fixed length.");
        return encoded.ToArray();
    }

    private static void Canonical(byte[] original, byte[] encoded, string name)
    {
        if (!original.AsSpan().SequenceEqual(encoded))
            throw Error(ProductionMailboxRouteContinuityError.NonCanonical, $"{name} is not canonical.");
    }

    private static byte[] DomainHash(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> value)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    private static byte[] DomainHash(
        ReadOnlySpan<byte> domain,
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain);
        hash.AppendData(first);
        hash.AppendData(second);
        return hash.GetHashAndReset();
    }

    private static void Authorization(
        ProductionMailboxRouteAuthorizationKind value, bool allowNone, string name)
    {
        if (!Enum.IsDefined(value) || (!allowNone && value == ProductionMailboxRouteAuthorizationKind.None))
            throw Error(ProductionMailboxRouteContinuityError.InvalidAuthorizationKind,
                $"{name} kind is unsupported.");
    }

    private static void RevocationState(ulong generation, ReadOnlyMemory<byte> head, string name)
    {
        Fixed(head, 32, name);
        if ((generation == 0 && !IsZero(head)) || (generation == 1 && IsZero(head)) || generation > 1)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                $"{name} must be exact Active 0/zero or terminal Revoked 1/exact-hash.");
    }

    private static void Counter(ulong value, string name)
    {
        if (value == 0 || value == ulong.MaxValue)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField,
                $"{name} must be non-zero and retain a successor.");
    }

    private static void Window(ulong from, ulong until, ulong maximum, string name)
    {
        if (from == 0 || from == ulong.MaxValue || until == 0 || until == ulong.MaxValue ||
            until <= from || until - from > maximum)
            throw Error(ProductionMailboxRouteContinuityError.InvalidValidityWindow,
                $"{name} validity window is invalid or too long.");
    }

    private static void Signature(ReadOnlyMemory<byte> value, bool required, string name)
    {
        Fixed(value, 64, name);
        if (required && IsZero(value))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField, $"{name} is all zero.");
    }

    private static void Nonzero(ReadOnlyMemory<byte> value, int length, string name)
    {
        Fixed(value, length, name);
        if (IsZero(value))
            throw Error(ProductionMailboxRouteContinuityError.InvalidField, $"{name} is all zero.");
    }

    private static void Fixed(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw Error(ProductionMailboxRouteContinuityError.InvalidField, $"{name} length is invalid.");
    }

    private static bool IsZero(ReadOnlyMemory<byte> value) =>
        value.Span.IndexOfAnyExcept((byte)0) < 0;

    private static void Length(ReadOnlyMemory<byte> value, int exactLength)
    {
        if (value.Length != exactLength)
            throw Error(ProductionMailboxRouteContinuityError.InvalidLength,
                "A fixed field has an invalid length.");
    }

    private static ProductionMailboxRouteContinuityException Error(
        ProductionMailboxRouteContinuityError error, string message) => new(error, message);

    private sealed class Reader(byte[] input, int offset)
    {
        private int _offset = offset;
        public byte Byte() => input[_offset++];
        public ulong UInt64()
        {
            var value = BinaryPrimitives.ReadUInt64BigEndian(input.AsSpan(_offset, 8));
            _offset += 8;
            return value;
        }
        public ReadOnlyMemory<byte> Bytes(int length)
        {
            var value = input.AsSpan(_offset, length).ToArray();
            _offset += length;
            return value;
        }
        public Reader Skip(int length)
        {
            if (input.AsSpan(_offset, length).IndexOfAnyExcept((byte)0) >= 0)
                throw Error(ProductionMailboxRouteContinuityError.ReservedFieldNotZero,
                    "Reserved bytes must be zero.");
            _offset += length;
            return this;
        }
        public void End(string name)
        {
            if (_offset != input.Length)
                throw Error(ProductionMailboxRouteContinuityError.InvalidLength,
                    $"{name} has trailing bytes.");
        }
    }

    private sealed class Writer
    {
        private readonly byte[] _output;
        private int _offset = 8;
        private Writer(int length, ReadOnlySpan<byte> magic, byte version)
        {
            _output = new byte[length];
            magic.CopyTo(_output);
            _output[4] = version;
        }
        public static Writer Create(int length, ReadOnlySpan<byte> magic, byte version) =>
            new(length, magic, version);
        public Writer Byte(byte value) { _output[_offset++] = value; return this; }
        public Writer Zero(int length) { _offset += length; return this; }
        public Writer UInt64(ulong value)
        {
            BinaryPrimitives.WriteUInt64BigEndian(_output.AsSpan(_offset, 8), value);
            _offset += 8;
            return this;
        }
        public Writer Bytes(ReadOnlySpan<byte> value)
        {
            value.CopyTo(_output.AsSpan(_offset));
            _offset += value.Length;
            return this;
        }
        public byte[] Finish(string name)
        {
            if (_offset != _output.Length)
                throw Error(ProductionMailboxRouteContinuityError.InvalidLength,
                    $"Internal {name} layout length is inconsistent.");
            return _output;
        }
    }
}
