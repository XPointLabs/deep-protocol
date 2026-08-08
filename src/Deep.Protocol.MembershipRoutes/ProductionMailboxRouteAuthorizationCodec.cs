using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>
/// Strict fixed-size RTC1/RCA1/PRA2 codecs. Raw signing transcripts remain internal and are
/// consumed only by capability-scoped verifier signing requests.
/// </summary>
public static class ProductionMailboxRouteAuthorizationCodec
{
    private static ReadOnlySpan<byte> TransitionMagic => "RTC1"u8;
    private static ReadOnlySpan<byte> ActivationMagic => "RCA1"u8;
    private static ReadOnlySpan<byte> AdvertisementMagic => "PRA2"u8;
    private static ReadOnlySpan<byte> TransitionHashDomain =>
        "Deep/production-mailbox/route-transition-context/v1"u8;
    private static ReadOnlySpan<byte> ActivationSigningDomain =>
        "Deep/production-mailbox/route-continuity-activation/v1"u8;
    private static ReadOnlySpan<byte> AdvertisementSigningDomain =>
        "Deep/production-mailbox/route-advertisement/v2"u8;

    public static byte[] EncodeTransitionContext(ProductionMailboxRouteTransitionContext value)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteAuthorizationCopy.Clone(value);
        Validate(frozen);
        return EncodeCore(frozen);
    }

    public static ProductionMailboxRouteTransitionContext DecodeTransitionContext(ReadOnlySpan<byte> encoded)
    {
        var frozen = Snapshot(encoded,
            ProductionMailboxRouteAuthorizationConstants.CanonicalTransitionContextLength, "RTC1");
        Header(frozen, TransitionMagic, ProductionMailboxRouteAuthorizationConstants.Version, "RTC1");
        var reader = new Reader(frozen, 5);
        var value = new ProductionMailboxRouteTransitionContext
        {
            Mode = (ProductionMailboxSelectionSuccessorMode)reader.Byte(),
            PredecessorAuthorizationKind = (ProductionMailboxRouteAuthorizationKind)reader.Byte(),
            NewAuthorizationKind = (ProductionMailboxRouteAuthorizationKind)reader.Byte(),
            NetworkId = reader.Bytes(16),
            RouteDomainHash = reader.Bytes(32),
            OldCanonicalSelectionHash = reader.Bytes(32),
            NewCanonicalSelectionHash = reader.Bytes(32),
            PredecessorCanonicalRouteAuthorizationHash = reader.Bytes(32),
            PredecessorRouteAuthorizationSequence = reader.UInt64(),
            FreshCanonicalRouteCertificateHash = reader.Bytes(32),
            NewRouteAuthorizationSequence = reader.UInt64(),
            TransitionSalt = reader.Bytes(32),
            ContinuityTransitionCommitment = reader.Bytes(32),
            CanonicalRevocationCheckpointHash = reader.Bytes(32),
            CurrentCanonicalAuthorityHash = reader.Bytes(32),
            CurrentAuthorityGeneration = reader.UInt64(),
            SealedOldRouteOriginLkgHash = reader.Bytes(32),
            OldRouteVerifiedAtUnixSeconds = reader.UInt64(),
            OldLocalRouteCommitGeneration = reader.UInt64(),
            NotBeforeUnixSeconds = reader.UInt64(),
            ExpiresAtUnixSeconds = reader.UInt64()
        };
        reader.Skip(8);
        reader.End("RTC1");
        Validate(value);
        Canonical(frozen, EncodeCore(value), "RTC1");
        return value;
    }

    public static byte[] EncodeContinuityActivation(ProductionMailboxRouteContinuityActivation value)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteAuthorizationCopy.Clone(value);
        Validate(frozen, requireSignature: true);
        return EncodeCore(frozen, includeSignature: true);
    }

    public static ProductionMailboxRouteContinuityActivation DecodeContinuityActivation(
        ReadOnlySpan<byte> encoded)
    {
        var frozen = Snapshot(encoded,
            ProductionMailboxRouteAuthorizationConstants.CanonicalContinuityActivationLength, "RCA1");
        Header(frozen, ActivationMagic, ProductionMailboxRouteAuthorizationConstants.Version, "RCA1");
        var reader = new Reader(frozen, 8);
        var value = new ProductionMailboxRouteContinuityActivation
        {
            NetworkId = reader.Bytes(16),
            RouteDomainHash = reader.Bytes(32),
            CurrentAuthorityGeneration = reader.UInt64(),
            CurrentCanonicalAuthorityHash = reader.Bytes(32),
            CurrentIssuerEd25519PublicKey = reader.Bytes(32),
            CurrentRevocationGeneration = reader.UInt64(),
            CurrentRevocationHeadHash = reader.Bytes(32),
            CurrentRevocationSnapshotHash = reader.Bytes(32),
            TransitionSalt = reader.Bytes(32),
            ContinuityTransitionCommitment = reader.Bytes(32),
            CanonicalRevocationCheckpointHash = reader.Bytes(32),
            FreshCanonicalRouteCertificateHash = reader.Bytes(32),
            CanonicalTransitionContextHash = reader.Bytes(32),
            PredecessorAuthorizationKind = (ProductionMailboxRouteAuthorizationKind)reader.Byte(),
            PredecessorCanonicalRouteAuthorizationHash = reader.Skip(7).Bytes(32),
            PredecessorRouteAuthorizationSequence = reader.UInt64(),
            ActivationSequence = reader.UInt64(),
            IssuedAtUnixSeconds = reader.UInt64(),
            ExpiresAtUnixSeconds = reader.UInt64(),
            CurrentIssuerSignature = reader.Bytes(64)
        };
        reader.End("RCA1");
        Validate(value, requireSignature: true);
        Canonical(frozen, EncodeCore(value, includeSignature: true), "RCA1");
        return value;
    }

    public static byte[] EncodeAdvertisementV2(ProductionMailboxRouteAdvertisementV2 value)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteAuthorizationCopy.Clone(value);
        Validate(frozen, requireSignature: true);
        return EncodeCore(frozen, includeSignature: true);
    }

    public static ProductionMailboxRouteAdvertisementV2 DecodeAdvertisementV2(ReadOnlySpan<byte> encoded)
    {
        var frozen = Snapshot(encoded,
            ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length, "PRA2");
        Header(frozen, AdvertisementMagic, ProductionMailboxRouteAuthorizationConstants.AdvertisementVersion,
            "PRA2");
        ProductionMailboxRouteCertificate certificate;
        try
        {
            certificate = ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(frozen.AsSpan(8,
                ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength));
        }
        catch (ProductionMailboxRouteAdvertisementException ex)
        {
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                $"PRA2 embedded PRC1 is invalid: {ex.Message}");
        }
        var reader = new Reader(frozen,
            8 + ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength);
        var value = new ProductionMailboxRouteAdvertisementV2
        {
            Certificate = certificate,
            PredecessorAuthorizationKind = (ProductionMailboxRouteAuthorizationKind)reader.Byte(),
            PredecessorCanonicalRouteAuthorizationHash = reader.Skip(7).Bytes(32),
            PredecessorRouteAuthorizationSequence = reader.UInt64(),
            Sequence = reader.UInt64(),
            PublishedAtUnixSeconds = reader.UInt64(),
            ExpiresAtUnixSeconds = reader.UInt64(),
            OwnerSignature = reader.Bytes(64)
        };
        reader.End("PRA2");
        Validate(value, requireSignature: true);
        Canonical(frozen, EncodeCore(value, includeSignature: true), "PRA2");
        return value;
    }

    internal static byte[] ComputeTransitionContextHash(ProductionMailboxRouteTransitionContext value) =>
        DomainHash(TransitionHashDomain, EncodeTransitionContext(value));

    internal static byte[] ComputeContinuityActivationCanonicalHash(
        ProductionMailboxRouteContinuityActivation value) => SHA256.HashData(EncodeContinuityActivation(value));

    internal static byte[] ComputeAdvertisementV2CanonicalHash(
        ProductionMailboxRouteAdvertisementV2 value) => SHA256.HashData(EncodeAdvertisementV2(value));

    internal static byte[] GetContinuityActivationSigningBytes(
        ProductionMailboxRouteContinuityActivation value)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteAuthorizationCopy.Clone(value);
        Validate(frozen, requireSignature: false);
        return [.. ActivationSigningDomain, .. EncodeCore(frozen, includeSignature: false)];
    }

    internal static byte[] GetAdvertisementV2SigningBytes(ProductionMailboxRouteAdvertisementV2 value)
    {
        Preflight(value);
        var frozen = ProductionMailboxRouteAuthorizationCopy.Clone(value);
        Validate(frozen, requireSignature: false);
        return [.. AdvertisementSigningDomain, .. EncodeCore(frozen, includeSignature: false)];
    }

    private static byte[] EncodeCore(ProductionMailboxRouteTransitionContext value)
    {
        var writer = Writer.Create(
            ProductionMailboxRouteAuthorizationConstants.CanonicalTransitionContextLength,
            TransitionMagic, ProductionMailboxRouteAuthorizationConstants.Version, headerLength: 5);
        writer.Byte((byte)value.Mode);
        writer.Byte((byte)value.PredecessorAuthorizationKind);
        writer.Byte((byte)value.NewAuthorizationKind);
        writer.Bytes(value.NetworkId.Span);
        writer.Bytes(value.RouteDomainHash.Span);
        writer.Bytes(value.OldCanonicalSelectionHash.Span);
        writer.Bytes(value.NewCanonicalSelectionHash.Span);
        writer.Bytes(value.PredecessorCanonicalRouteAuthorizationHash.Span);
        writer.UInt64(value.PredecessorRouteAuthorizationSequence);
        writer.Bytes(value.FreshCanonicalRouteCertificateHash.Span);
        writer.UInt64(value.NewRouteAuthorizationSequence);
        writer.Bytes(value.TransitionSalt.Span);
        writer.Bytes(value.ContinuityTransitionCommitment.Span);
        writer.Bytes(value.CanonicalRevocationCheckpointHash.Span);
        writer.Bytes(value.CurrentCanonicalAuthorityHash.Span);
        writer.UInt64(value.CurrentAuthorityGeneration);
        writer.Bytes(value.SealedOldRouteOriginLkgHash.Span);
        writer.UInt64(value.OldRouteVerifiedAtUnixSeconds);
        writer.UInt64(value.OldLocalRouteCommitGeneration);
        writer.UInt64(value.NotBeforeUnixSeconds);
        writer.UInt64(value.ExpiresAtUnixSeconds);
        writer.Zero(8);
        return writer.Finish("RTC1");
    }

    private static byte[] EncodeCore(
        ProductionMailboxRouteContinuityActivation value, bool includeSignature)
    {
        var length = ProductionMailboxRouteAuthorizationConstants.CanonicalContinuityActivationLength -
            (includeSignature ? 0 : 64);
        var writer = Writer.Create(length, ActivationMagic,
            ProductionMailboxRouteAuthorizationConstants.Version);
        writer.Bytes(value.NetworkId.Span);
        writer.Bytes(value.RouteDomainHash.Span);
        writer.UInt64(value.CurrentAuthorityGeneration);
        writer.Bytes(value.CurrentCanonicalAuthorityHash.Span);
        writer.Bytes(value.CurrentIssuerEd25519PublicKey.Span);
        writer.UInt64(value.CurrentRevocationGeneration);
        writer.Bytes(value.CurrentRevocationHeadHash.Span);
        writer.Bytes(value.CurrentRevocationSnapshotHash.Span);
        writer.Bytes(value.TransitionSalt.Span);
        writer.Bytes(value.ContinuityTransitionCommitment.Span);
        writer.Bytes(value.CanonicalRevocationCheckpointHash.Span);
        writer.Bytes(value.FreshCanonicalRouteCertificateHash.Span);
        writer.Bytes(value.CanonicalTransitionContextHash.Span);
        writer.Byte((byte)value.PredecessorAuthorizationKind).Zero(7);
        writer.Bytes(value.PredecessorCanonicalRouteAuthorizationHash.Span);
        writer.UInt64(value.PredecessorRouteAuthorizationSequence);
        writer.UInt64(value.ActivationSequence);
        writer.UInt64(value.IssuedAtUnixSeconds);
        writer.UInt64(value.ExpiresAtUnixSeconds);
        if (includeSignature) writer.Bytes(value.CurrentIssuerSignature.Span);
        return writer.Finish("RCA1");
    }

    private static byte[] EncodeCore(ProductionMailboxRouteAdvertisementV2 value, bool includeSignature)
    {
        var length = ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length -
            (includeSignature ? 0 : 64);
        var writer = Writer.Create(length, AdvertisementMagic,
            ProductionMailboxRouteAuthorizationConstants.AdvertisementVersion);
        writer.Bytes(EncodeCertificate(value.Certificate));
        writer.Byte((byte)value.PredecessorAuthorizationKind).Zero(7);
        writer.Bytes(value.PredecessorCanonicalRouteAuthorizationHash.Span);
        writer.UInt64(value.PredecessorRouteAuthorizationSequence);
        writer.UInt64(value.Sequence);
        writer.UInt64(value.PublishedAtUnixSeconds);
        writer.UInt64(value.ExpiresAtUnixSeconds);
        if (includeSignature) writer.Bytes(value.OwnerSignature.Span);
        return writer.Finish("PRA2");
    }

    private static void Validate(ProductionMailboxRouteTransitionContext value)
    {
        if (!Enum.IsDefined(value.Mode))
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidTransitionMode,
                "RTC1 transition mode is unsupported.");
        Authorization(value.PredecessorAuthorizationKind, allowNone: true, "RTC1 predecessor");
        Authorization(value.NewAuthorizationKind, allowNone: false, "RTC1 new authorization");
        Nonzero(value.NetworkId, 16, "network ID");
        Nonzero(value.RouteDomainHash, 32, "route-domain hash");
        Nonzero(value.OldCanonicalSelectionHash, 32, "old PMS1 hash");
        Nonzero(value.NewCanonicalSelectionHash, 32, "new PMS1 hash");
        Predecessor(value.PredecessorAuthorizationKind,
            value.PredecessorCanonicalRouteAuthorizationHash,
            value.PredecessorRouteAuthorizationSequence,
            value.NewRouteAuthorizationSequence, "RTC1");
        Nonzero(value.FreshCanonicalRouteCertificateHash, 32, "fresh PRC1 hash");
        Fixed(value.TransitionSalt, 32, "transition salt");
        Fixed(value.ContinuityTransitionCommitment, 32, "continuity commitment");
        Fixed(value.CanonicalRevocationCheckpointHash, 32, "RCH1 hash");
        if (value.NewAuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
        {
            if (!IsZero(value.TransitionSalt) || !IsZero(value.ContinuityTransitionCommitment) ||
                !IsZero(value.CanonicalRevocationCheckpointHash))
                throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                    "Owner PRA2 RTC1 must have zero continuity-only fields.");
        }
        else if (IsZero(value.TransitionSalt) || IsZero(value.ContinuityTransitionCommitment) ||
            IsZero(value.CanonicalRevocationCheckpointHash))
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                "Delegated RCA1 RTC1 requires non-zero salt, commitment and RCH1 hash.");
        Nonzero(value.CurrentCanonicalAuthorityHash, 32, "current PMA1 hash");
        Counter(value.CurrentAuthorityGeneration, "current authority generation");
        Nonzero(value.SealedOldRouteOriginLkgHash, 32, "sealed old ROL1 hash");
        Counter(value.OldRouteVerifiedAtUnixSeconds, "old RouteVerifiedAt");
        Counter(value.OldLocalRouteCommitGeneration, "old local route commit generation");
        Window(value.NotBeforeUnixSeconds, value.ExpiresAtUnixSeconds, "RTC1");
    }

    private static void Validate(ProductionMailboxRouteContinuityActivation value, bool requireSignature)
    {
        Nonzero(value.NetworkId, 16, "network ID");
        Nonzero(value.RouteDomainHash, 32, "route-domain hash");
        Counter(value.CurrentAuthorityGeneration, "current authority generation");
        Nonzero(value.CurrentCanonicalAuthorityHash, 32, "current PMA1 hash");
        Nonzero(value.CurrentIssuerEd25519PublicKey, 32, "current issuer key");
        Counter(value.CurrentRevocationGeneration, "current PMR1 generation");
        Nonzero(value.CurrentRevocationHeadHash, 32, "current PMR1 head");
        Nonzero(value.CurrentRevocationSnapshotHash, 32, "current PMR1 snapshot hash");
        Nonzero(value.TransitionSalt, 32, "transition salt");
        Nonzero(value.ContinuityTransitionCommitment, 32, "continuity commitment");
        Nonzero(value.CanonicalRevocationCheckpointHash, 32, "RCH1 hash");
        Nonzero(value.FreshCanonicalRouteCertificateHash, 32, "fresh PRC1 hash");
        Nonzero(value.CanonicalTransitionContextHash, 32, "RTC1 hash");
        Authorization(value.PredecessorAuthorizationKind, allowNone: false, "RCA1 predecessor");
        Predecessor(value.PredecessorAuthorizationKind,
            value.PredecessorCanonicalRouteAuthorizationHash,
            value.PredecessorRouteAuthorizationSequence,
            value.ActivationSequence, "RCA1");
        Window(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds, "RCA1");
        Signature(value.CurrentIssuerSignature, requireSignature, "current issuer signature");
    }

    private static void Validate(ProductionMailboxRouteAdvertisementV2 value, bool requireSignature)
    {
        ArgumentNullException.ThrowIfNull(value.Certificate);
        byte[] certificateBytes;
        try
        {
            certificateBytes = EncodeCertificate(value.Certificate);
        }
        catch (ProductionMailboxRouteAdvertisementException ex)
        {
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                $"PRA2 embedded PRC1 is invalid: {ex.Message}");
        }
        if (certificateBytes.Length != ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidLength,
                "PRA2 embedded PRC1 length is invalid.");
        Authorization(value.PredecessorAuthorizationKind, allowNone: true, "PRA2 predecessor");
        Predecessor(value.PredecessorAuthorizationKind,
            value.PredecessorCanonicalRouteAuthorizationHash,
            value.PredecessorRouteAuthorizationSequence,
            value.Sequence, "PRA2");
        Window(value.PublishedAtUnixSeconds, value.ExpiresAtUnixSeconds, "PRA2");
        if (value.PublishedAtUnixSeconds < value.Certificate.IssuedAtUnixSeconds ||
            value.ExpiresAtUnixSeconds > value.Certificate.ExpiresAtUnixSeconds)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidValidityWindow,
                "PRA2 lifetime must be contained by its exact PRC1.");
        Signature(value.OwnerSignature, requireSignature, "owner signature");
    }

    private static byte[] EncodeCertificate(ProductionMailboxRouteCertificate value) =>
        ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(value);

    private static void Preflight(ProductionMailboxRouteTransitionContext value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Length(value.NetworkId, 16); Length(value.RouteDomainHash, 32);
        Length(value.OldCanonicalSelectionHash, 32); Length(value.NewCanonicalSelectionHash, 32);
        Length(value.PredecessorCanonicalRouteAuthorizationHash, 32);
        Length(value.FreshCanonicalRouteCertificateHash, 32); Length(value.TransitionSalt, 32);
        Length(value.ContinuityTransitionCommitment, 32);
        Length(value.CanonicalRevocationCheckpointHash, 32);
        Length(value.CurrentCanonicalAuthorityHash, 32); Length(value.SealedOldRouteOriginLkgHash, 32);
    }

    private static void Preflight(ProductionMailboxRouteContinuityActivation value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Length(value.NetworkId, 16); Length(value.RouteDomainHash, 32);
        Length(value.CurrentCanonicalAuthorityHash, 32); Length(value.CurrentIssuerEd25519PublicKey, 32);
        Length(value.CurrentRevocationHeadHash, 32); Length(value.CurrentRevocationSnapshotHash, 32);
        Length(value.TransitionSalt, 32); Length(value.ContinuityTransitionCommitment, 32);
        Length(value.CanonicalRevocationCheckpointHash, 32);
        Length(value.FreshCanonicalRouteCertificateHash, 32);
        Length(value.CanonicalTransitionContextHash, 32);
        Length(value.PredecessorCanonicalRouteAuthorizationHash, 32);
        Length(value.CurrentIssuerSignature, 64);
    }

    private static void Preflight(ProductionMailboxRouteAdvertisementV2 value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(value.Certificate);
        Length(value.Certificate.NetworkId, 16); Length(value.Certificate.CanonicalAuthorityHash, 32);
        Length(value.Certificate.IssuerEd25519PublicKey, 32);
        Length(value.Certificate.MailboxOwnerEd25519PublicKey, 32);
        Length(value.Certificate.BlindedMailboxId, 32); Length(value.Certificate.BlindedPlacementId, 32);
        Length(value.Certificate.SelectionInputCommitment, 32); Length(value.Certificate.IssuerSignature, 64);
        Length(value.PredecessorCanonicalRouteAuthorizationHash, 32); Length(value.OwnerSignature, 64);
    }

    private static void Header(byte[] input, ReadOnlySpan<byte> magic, byte version, string name)
    {
        if (!input.AsSpan(0, 4).SequenceEqual(magic))
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidMagic, $"{name} magic is invalid.");
        if (input[4] != version)
            throw Error(ProductionMailboxRouteAuthorizationError.UnsupportedVersion,
                $"{name} version is unsupported.");
        if (name != "RTC1" && input.AsSpan(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(ProductionMailboxRouteAuthorizationError.ReservedFieldNotZero,
                $"{name} header reserved bytes must be zero.");
    }

    private static void Predecessor(
        ProductionMailboxRouteAuthorizationKind kind,
        ReadOnlyMemory<byte> hash,
        ulong sequence,
        ulong nextSequence,
        string name)
    {
        Fixed(hash, 32, "predecessor authorization hash");
        if (kind == ProductionMailboxRouteAuthorizationKind.None)
        {
            if (!IsZero(hash) || sequence != 0 || nextSequence != 1)
                throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                    $"{name} genesis predecessor must be exact None/zero/zero to sequence one.");
            return;
        }
        Counter(sequence, "predecessor authorization sequence");
        Counter(nextSequence, "new authorization sequence");
        if (IsZero(hash) || sequence == ulong.MaxValue || nextSequence != sequence + 1)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                $"{name} predecessor chain must advance exact +1.");
    }

    private static void Authorization(
        ProductionMailboxRouteAuthorizationKind value, bool allowNone, string name)
    {
        if (!Enum.IsDefined(value) || (!allowNone && value == ProductionMailboxRouteAuthorizationKind.None))
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidAuthorizationKind,
                $"{name} kind is unsupported.");
    }

    private static void Counter(ulong value, string name)
    {
        if (value == 0 || value == ulong.MaxValue)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField,
                $"{name} must be non-zero and retain a successor.");
    }

    private static void Window(ulong from, ulong until, string name)
    {
        if (from == 0 || from == ulong.MaxValue || until == 0 || until == ulong.MaxValue ||
            until <= from || until - from > ProductionMailboxRouteAuthorizationConstants.MaximumLifetimeSeconds)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidValidityWindow,
                $"{name} validity window is invalid or too long.");
    }

    private static byte[] Snapshot(ReadOnlySpan<byte> encoded, int exactLength, string name)
    {
        if (encoded.Length != exactLength)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidLength,
                $"{name} must have its exact fixed length.");
        return encoded.ToArray();
    }

    private static void Canonical(byte[] original, byte[] encoded, string name)
    {
        if (!original.AsSpan().SequenceEqual(encoded))
            throw Error(ProductionMailboxRouteAuthorizationError.NonCanonical, $"{name} is not canonical.");
    }

    private static byte[] DomainHash(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> value)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    private static void Signature(ReadOnlyMemory<byte> value, bool required, string name)
    {
        Fixed(value, 64, name);
        if (required && IsZero(value))
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField, $"{name} is all zero.");
    }

    private static void Nonzero(ReadOnlyMemory<byte> value, int length, string name)
    {
        Fixed(value, length, name);
        if (IsZero(value))
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField, $"{name} is all zero.");
    }

    private static void Fixed(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidField, $"{name} length is invalid.");
    }

    private static bool IsZero(ReadOnlyMemory<byte> value) => value.Span.IndexOfAnyExcept((byte)0) < 0;

    private static void Length(ReadOnlyMemory<byte> value, int exactLength)
    {
        if (value.Length != exactLength)
            throw Error(ProductionMailboxRouteAuthorizationError.InvalidLength,
                "A fixed field has an invalid length.");
    }

    private static ProductionMailboxRouteAuthorizationException Error(
        ProductionMailboxRouteAuthorizationError error, string message) => new(error, message);

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
                throw Error(ProductionMailboxRouteAuthorizationError.ReservedFieldNotZero,
                    "Reserved bytes must be zero.");
            _offset += length;
            return this;
        }
        public void End(string name)
        {
            if (_offset != input.Length)
                throw Error(ProductionMailboxRouteAuthorizationError.InvalidLength,
                    $"{name} has trailing bytes.");
        }
    }

    private sealed class Writer
    {
        private readonly byte[] _output;
        private int _offset;
        private Writer(int length, ReadOnlySpan<byte> magic, byte version, int headerLength)
        {
            _output = new byte[length];
            magic.CopyTo(_output);
            _output[4] = version;
            _offset = headerLength;
        }
        public static Writer Create(
            int length, ReadOnlySpan<byte> magic, byte version, int headerLength = 8) =>
            new(length, magic, version, headerLength);
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
                throw Error(ProductionMailboxRouteAuthorizationError.InvalidLength,
                    $"Internal {name} layout length is inconsistent.");
            return _output;
        }
    }
}
