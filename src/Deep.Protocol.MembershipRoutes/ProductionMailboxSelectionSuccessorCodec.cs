using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>Strict PSS1 codec. Public signing helpers return transcripts only.</summary>
public static class ProductionMailboxSelectionSuccessorCodec
{
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.PSS1;
    private static ReadOnlySpan<byte> OldIssuerDomain =>
        "Deep/production-mailbox/selection-successor/old-issuer/v1"u8;
    private static ReadOnlySpan<byte> NewIssuerDomain =>
        "Deep/production-mailbox/selection-successor/new-issuer/v1"u8;

    public static byte[] GetOldIssuerSigningBytes(ProductionMailboxSelectionSuccessorProof value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Mode != ProductionMailboxSelectionSuccessorMode.DirectPromotion)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "Offline checkpoint has no retired-issuer signature transcript.");
        return GetSigningBytes(value, OldIssuerDomain);
    }

    public static byte[] GetNewIssuerSigningBytes(ProductionMailboxSelectionSuccessorProof value) =>
        GetSigningBytes(value, NewIssuerDomain);

    public static byte[] Encode(ProductionMailboxSelectionSuccessorProof value)
    {
        var frozen = Freeze(value);
        Validate(frozen, requireSignatures: true);
        return EncodeCore(frozen, includeSignatures: true);
    }

    public static ProductionMailboxSelectionSuccessorProof Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < ProductionMailboxSelectionSuccessorConstants.FixedCoreLength +
                ProductionMailboxSelectionSuccessorConstants.SignatureBytes ||
            encoded.Length > ProductionMailboxSelectionSuccessorConstants.MaximumArtifactBytes)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                "PSS1 length is outside its strict bounds.");
        var frozen = encoded.ToArray();
        if (!frozen.AsSpan(0, 4).SequenceEqual(Magic))
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidMagic, "PSS1 magic is invalid.");
        if (frozen[4] != ProductionMailboxSelectionSuccessorConstants.Version)
            throw Error(ProductionMailboxSelectionSuccessorError.UnsupportedVersion,
                "PSS1 version is unsupported.");
        if (!Enum.IsDefined((ProductionMailboxSelectionSuccessorMode)frozen[5]))
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "PSS1 transition mode is unsupported.");
        if (frozen.AsSpan(6, 2).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(ProductionMailboxSelectionSuccessorError.ReservedFieldNotZero,
                "PSS1 header reserved bytes must be zero.");
        var offset = 8;
        var network = Read(frozen, ref offset, 16);
        var oldEpoch = ReadUInt64(frozen, ref offset);
        var oldEpochGeneration = ReadUInt64(frozen, ref offset);
        var newEpoch = ReadUInt64(frozen, ref offset);
        var newEpochGeneration = ReadUInt64(frozen, ref offset);
        var owner = Read(frozen, ref offset, 32);
        var mailbox = Read(frozen, ref offset, 32);
        var placement = Read(frozen, ref offset, 32);
        var selectionInput = Read(frozen, ref offset, 32);
        var oldAuthority = Read(frozen, ref offset, 32);
        var newAuthority = Read(frozen, ref offset, 32);
        var oldTopologyGeneration = ReadUInt64(frozen, ref offset);
        var oldTopology = Read(frozen, ref offset, 32);
        var newTopologyGeneration = ReadUInt64(frozen, ref offset);
        var newTopology = Read(frozen, ref offset, 32);
        var oldSelection = Read(frozen, ref offset, 32);
        var newSelection = Read(frozen, ref offset, 32);
        var issued = ReadUInt64(frozen, ref offset);
        var expires = ReadUInt64(frozen, ref offset);
        var authorityLength = ReadUInt16(frozen, ref offset);
        var oldLength = ReadUInt16(frozen, ref offset);
        var newLength = ReadUInt16(frozen, ref offset);
        if (frozen.AsSpan(offset, 2).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(ProductionMailboxSelectionSuccessorError.ReservedFieldNotZero,
                "PSS1 length reserved bytes must be zero.");
        offset += 2;
        if (authorityLength == 0 ||
            authorityLength > ProductionMailboxAuthorityConstants.MaximumArtifactBytes ||
            oldLength == 0 || newLength == 0 ||
            oldLength > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            newLength > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            offset + authorityLength + oldLength + newLength +
                ProductionMailboxSelectionSuccessorConstants.SignatureBytes != frozen.Length)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                "PSS1 embedded PMA1/PMS1 lengths are invalid.");
        var value = new ProductionMailboxSelectionSuccessorProof
        {
            Mode = (ProductionMailboxSelectionSuccessorMode)frozen[5],
            NetworkId = network,
            OldEpoch = oldEpoch,
            OldEpochGeneration = oldEpochGeneration,
            NewEpoch = newEpoch,
            NewEpochGeneration = newEpochGeneration,
            MailboxOwnerEd25519PublicKey = owner,
            BlindedMailboxId = mailbox,
            BlindedPlacementId = placement,
            SelectionInputCommitment = selectionInput,
            OldCanonicalAuthorityHash = oldAuthority,
            NewCanonicalAuthorityHash = newAuthority,
            OldTopologyGeneration = oldTopologyGeneration,
            OldCanonicalTopologyHash = oldTopology,
            NewTopologyGeneration = newTopologyGeneration,
            NewCanonicalTopologyHash = newTopology,
            OldCanonicalSelectionHash = oldSelection,
            NewCanonicalSelectionHash = newSelection,
            IssuedAtUnixSeconds = issued,
            ExpiresAtUnixSeconds = expires,
            CanonicalNewAuthority = Read(frozen, ref offset, authorityLength),
            OldCanonicalSelection = Read(frozen, ref offset, oldLength),
            NewCanonicalSelection = Read(frozen, ref offset, newLength),
            OldIssuerSignature = Read(frozen, ref offset, 64),
            NewIssuerSignature = Read(frozen, ref offset, 64)
        };
        if (offset != frozen.Length)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength, "PSS1 has trailing bytes.");
        Validate(value, requireSignatures: true);
        if (!frozen.AsSpan().SequenceEqual(EncodeCore(value, includeSignatures: true)))
            throw Error(ProductionMailboxSelectionSuccessorError.NonCanonical, "PSS1 is not canonical.");
        return value;
    }

    public static byte[] ComputeCanonicalHash(ProductionMailboxSelectionSuccessorProof value) =>
        SHA256.HashData(Encode(value));

    private static byte[] GetSigningBytes(ProductionMailboxSelectionSuccessorProof value, ReadOnlySpan<byte> domain)
    {
        var frozen = Freeze(value);
        Validate(frozen, requireSignatures: false);
        var core = EncodeCore(frozen, includeSignatures: false);
        return [.. domain, .. core];
    }

    private static byte[] EncodeCore(ProductionMailboxSelectionSuccessorProof value, bool includeSignatures)
    {
        var length = ProductionMailboxSelectionSuccessorConstants.FixedCoreLength +
            value.CanonicalNewAuthority.Length + value.OldCanonicalSelection.Length +
            value.NewCanonicalSelection.Length +
            (includeSignatures ? ProductionMailboxSelectionSuccessorConstants.SignatureBytes : 0);
        var output = new byte[length];
        Magic.CopyTo(output);
        output[4] = ProductionMailboxSelectionSuccessorConstants.Version;
        output[5] = (byte)value.Mode;
        var offset = 8;
        Write(value.NetworkId.Span, output, ref offset);
        WriteUInt64(value.OldEpoch, output, ref offset);
        WriteUInt64(value.OldEpochGeneration, output, ref offset);
        WriteUInt64(value.NewEpoch, output, ref offset);
        WriteUInt64(value.NewEpochGeneration, output, ref offset);
        Write(value.MailboxOwnerEd25519PublicKey.Span, output, ref offset);
        Write(value.BlindedMailboxId.Span, output, ref offset);
        Write(value.BlindedPlacementId.Span, output, ref offset);
        Write(value.SelectionInputCommitment.Span, output, ref offset);
        Write(value.OldCanonicalAuthorityHash.Span, output, ref offset);
        Write(value.NewCanonicalAuthorityHash.Span, output, ref offset);
        WriteUInt64(value.OldTopologyGeneration, output, ref offset);
        Write(value.OldCanonicalTopologyHash.Span, output, ref offset);
        WriteUInt64(value.NewTopologyGeneration, output, ref offset);
        Write(value.NewCanonicalTopologyHash.Span, output, ref offset);
        Write(value.OldCanonicalSelectionHash.Span, output, ref offset);
        Write(value.NewCanonicalSelectionHash.Span, output, ref offset);
        WriteUInt64(value.IssuedAtUnixSeconds, output, ref offset);
        WriteUInt64(value.ExpiresAtUnixSeconds, output, ref offset);
        WriteUInt16(checked((ushort)value.CanonicalNewAuthority.Length), output, ref offset);
        WriteUInt16(checked((ushort)value.OldCanonicalSelection.Length), output, ref offset);
        WriteUInt16(checked((ushort)value.NewCanonicalSelection.Length), output, ref offset);
        offset += 2;
        Write(value.CanonicalNewAuthority.Span, output, ref offset);
        Write(value.OldCanonicalSelection.Span, output, ref offset);
        Write(value.NewCanonicalSelection.Span, output, ref offset);
        if (includeSignatures)
        {
            Write(value.OldIssuerSignature.Span, output, ref offset);
            Write(value.NewIssuerSignature.Span, output, ref offset);
        }
        return output;
    }

    private static void Validate(ProductionMailboxSelectionSuccessorProof value, bool requireSignatures)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!Enum.IsDefined(value.Mode))
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "PSS1 transition mode is unsupported.");
        FixedNonzero(value.NetworkId, 16, "network ID");
        if (value.OldEpoch == 0 || value.OldEpochGeneration == 0 ||
            value.NewEpoch == 0 || value.NewEpochGeneration == 0 ||
            value.OldTopologyGeneration == 0 || value.NewTopologyGeneration == 0)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField,
                "PSS1 epoch and topology generations must be non-zero.");
        FixedNonzero(value.MailboxOwnerEd25519PublicKey, 32, "mailbox owner key");
        FixedNonzero(value.BlindedMailboxId, 32, "blinded mailbox ID");
        FixedNonzero(value.BlindedPlacementId, 32, "blinded placement ID");
        FixedNonzero(value.SelectionInputCommitment, 32, "selection input commitment");
        FixedNonzero(value.OldCanonicalAuthorityHash, 32, "old authority hash");
        FixedNonzero(value.NewCanonicalAuthorityHash, 32, "new authority hash");
        FixedNonzero(value.OldCanonicalTopologyHash, 32, "old topology hash");
        FixedNonzero(value.NewCanonicalTopologyHash, 32, "new topology hash");
        FixedNonzero(value.OldCanonicalSelectionHash, 32, "old selection hash");
        FixedNonzero(value.NewCanonicalSelectionHash, 32, "new selection hash");
        if (value.IssuedAtUnixSeconds == 0 || value.ExpiresAtUnixSeconds <= value.IssuedAtUnixSeconds ||
            value.ExpiresAtUnixSeconds - value.IssuedAtUnixSeconds >
            ProductionMailboxSelectionSuccessorConstants.MaximumLifetimeSeconds)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidValidityWindow,
                "PSS1 validity window is invalid or too long.");
        if (value.CanonicalNewAuthority.Length is 0 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes ||
            value.OldCanonicalSelection.Length is 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            value.NewCanonicalSelection.Length is 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                "PSS1 embedded PMA1/PMS1 length is invalid.");
        ProductionMailboxAuthority authority;
        try
        {
            authority = ProductionMailboxAuthorityCodec.Decode(value.CanonicalNewAuthority.Span);
        }
        catch (ProductionMailboxAuthorityException ex)
        {
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField,
                $"PSS1 embedded PMA1 is invalid: {ex.Message}");
        }
        if (!value.CanonicalNewAuthority.Span.SequenceEqual(
                ProductionMailboxAuthorityCodec.Encode(authority)))
            throw Error(ProductionMailboxSelectionSuccessorError.NonCanonical,
                "PSS1 embedded PMA1 is not canonical.");
        Fixed(value.OldIssuerSignature, 64, "old issuer signature");
        Fixed(value.NewIssuerSignature, 64, "new issuer signature");
        if (requireSignatures)
        {
            var oldIsZero = value.OldIssuerSignature.Span.IndexOfAnyExcept((byte)0) < 0;
            var newIsZero = value.NewIssuerSignature.Span.IndexOfAnyExcept((byte)0) < 0;
            if (newIsZero ||
                (value.Mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion && oldIsZero) ||
                (value.Mode == ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint && !oldIsZero))
                throw Error(ProductionMailboxSelectionSuccessorError.InvalidField,
                    "PSS1 signature slots do not match its transition mode.");
        }
    }

    private static ProductionMailboxSelectionSuccessorProof Freeze(
        ProductionMailboxSelectionSuccessorProof value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return ProductionMailboxSelectionSuccessorCopy.Clone(value);
    }

    private static ReadOnlyMemory<byte> Read(byte[] input, ref int offset, int length)
    {
        var value = input.AsSpan(offset, length).ToArray(); offset += length; return value;
    }

    private static ushort ReadUInt16(byte[] input, ref int offset)
    {
        var value = BinaryPrimitives.ReadUInt16BigEndian(input.AsSpan(offset, 2)); offset += 2; return value;
    }

    private static ulong ReadUInt64(byte[] input, ref int offset)
    {
        var value = BinaryPrimitives.ReadUInt64BigEndian(input.AsSpan(offset, 8)); offset += 8; return value;
    }

    private static void Write(ReadOnlySpan<byte> value, byte[] output, ref int offset)
    {
        value.CopyTo(output.AsSpan(offset)); offset += value.Length;
    }

    private static void WriteUInt16(ushort value, byte[] output, ref int offset)
    {
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2), value); offset += 2;
    }

    private static void WriteUInt64(ulong value, byte[] output, ref int offset)
    {
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset, 8), value); offset += 8;
    }

    private static void FixedNonzero(ReadOnlyMemory<byte> value, int length, string name)
    {
        Fixed(value, length, name);
        if (value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField, $"{name} is all zero.");
    }

    private static void Fixed(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField, $"{name} length is invalid.");
    }

    private static ProductionMailboxSelectionSuccessorException Error(
        ProductionMailboxSelectionSuccessorError error,
        string message) => new(error, message);
}

/// <summary>Strict clean-break PSS2 codec. Signing transcripts remain internal to sealed flows.</summary>
public static class ProductionMailboxSelectionSuccessorV2Codec
{
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.PSS2;
    private static ReadOnlySpan<byte> OldIssuerDomain =>
        "Deep/production-mailbox/selection-successor/v2/old"u8;
    private static ReadOnlySpan<byte> CurrentIssuerDomain =>
        "Deep/production-mailbox/selection-successor/v2/current"u8;

    public static byte[] Encode(ProductionMailboxSelectionSuccessorV2Proof value)
    {
        var frozen = Freeze(value);
        ValidateRoute(frozen);
        var pss1 = ProductionMailboxSelectionSuccessorCodec.Encode(frozen.Selection);
        var variableLength = pss1.Length - ProductionMailboxSelectionSuccessorConstants.FixedCoreLength;
        var output = new byte[checked(pss1.Length + ProductionMailboxSelectionSuccessorV2Constants.RouteBlockLength)];
        pss1.AsSpan(0, ProductionMailboxSelectionSuccessorConstants.FixedCoreLength)
            .CopyTo(output.AsSpan(0, ProductionMailboxSelectionSuccessorV2Constants.RouteBlockOffset));
        Magic.CopyTo(output);
        output[4] = ProductionMailboxSelectionSuccessorV2Constants.Version;
        WriteRouteBlock(frozen, output.AsSpan(ProductionMailboxSelectionSuccessorV2Constants.RouteBlockOffset,
            ProductionMailboxSelectionSuccessorV2Constants.RouteBlockLength));
        pss1.AsSpan(ProductionMailboxSelectionSuccessorConstants.FixedCoreLength, variableLength)
            .CopyTo(output.AsSpan(ProductionMailboxSelectionSuccessorV2Constants.FixedCoreLength));
        return output;
    }

    internal static ProductionMailboxSelectionSuccessorV2Proof FreezeUnsignedForAuthoring(
        ProductionMailboxSelectionSuccessorV2Proof value)
    {
        var frozen = Freeze(value);
        if (frozen.Selection.OldIssuerSignature.Length !=
                ProductionMailboxSelectionSuccessorConstants.Ed25519SignatureLength ||
            frozen.Selection.NewIssuerSignature.Length !=
                ProductionMailboxSelectionSuccessorConstants.Ed25519SignatureLength ||
            frozen.Selection.OldIssuerSignature.Span.IndexOfAnyExcept((byte)0) >= 0 ||
            frozen.Selection.NewIssuerSignature.Span.IndexOfAnyExcept((byte)0) >= 0)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField,
                "PSS2 authoring draft signatures must be canonical zero placeholders.");
        ValidateRoute(frozen);
        if (frozen.Selection.Mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
            _ = GetOldIssuerSigningBytes(frozen);
        _ = GetCurrentIssuerSigningBytes(frozen);
        return frozen;
    }

    public static ProductionMailboxSelectionSuccessorV2Proof Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < ProductionMailboxSelectionSuccessorV2Constants.FixedCoreLength +
                ProductionMailboxSelectionSuccessorV2Constants.SignatureBytes ||
            encoded.Length > ProductionMailboxSelectionSuccessorV2Constants.MaximumArtifactBytes)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                "PSS2 length is outside its strict bounds.");
        if (!encoded[..4].SequenceEqual(Magic))
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidMagic, "PSS2 magic is invalid.");
        if (encoded[4] != ProductionMailboxSelectionSuccessorV2Constants.Version)
            throw Error(ProductionMailboxSelectionSuccessorError.UnsupportedVersion,
                "PSS2 version is unsupported.");
        var frozen = encoded.ToArray();
        var pss1 = new byte[checked(frozen.Length - ProductionMailboxSelectionSuccessorV2Constants.RouteBlockLength)];
        frozen.AsSpan(0, ProductionMailboxSelectionSuccessorV2Constants.RouteBlockOffset)
            .CopyTo(pss1.AsSpan());
        ProtocolMagicBytes.PSS1.CopyTo(pss1);
        pss1[4] = ProductionMailboxSelectionSuccessorConstants.Version;
        frozen.AsSpan(ProductionMailboxSelectionSuccessorV2Constants.FixedCoreLength)
            .CopyTo(pss1.AsSpan(ProductionMailboxSelectionSuccessorConstants.FixedCoreLength));
        var selection = ProductionMailboxSelectionSuccessorCodec.Decode(pss1);
        var route = frozen.AsSpan(ProductionMailboxSelectionSuccessorV2Constants.RouteBlockOffset,
            ProductionMailboxSelectionSuccessorV2Constants.RouteBlockLength);
        if (route.Slice(34, 6).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(ProductionMailboxSelectionSuccessorError.ReservedFieldNotZero,
                "PSS2 route-block reserved bytes must be zero.");
        var value = new ProductionMailboxSelectionSuccessorV2Proof
        {
            Selection = selection,
            CanonicalTransitionContextHash = route[..32].ToArray(),
            PredecessorAuthorizationKind = (ProductionMailboxRouteAuthorizationKind)route[32],
            NewAuthorizationKind = (ProductionMailboxRouteAuthorizationKind)route[33],
            PredecessorCanonicalRouteAuthorizationHash = route.Slice(40, 32).ToArray(),
            PredecessorRouteAuthorizationSequence = BinaryPrimitives.ReadUInt64BigEndian(route.Slice(72, 8)),
            FreshCanonicalRouteCertificateHash = route.Slice(80, 32).ToArray(),
            NewCanonicalRouteAuthorizationHash = route.Slice(112, 32).ToArray(),
            NewRouteAuthorizationSequence = BinaryPrimitives.ReadUInt64BigEndian(route.Slice(144, 8)),
            CanonicalRevocationCheckpointHash = route.Slice(152, 32).ToArray()
        };
        ValidateRoute(value);
        if (!frozen.AsSpan().SequenceEqual(Encode(value)))
            throw Error(ProductionMailboxSelectionSuccessorError.NonCanonical, "PSS2 is not canonical.");
        return value;
    }

    public static byte[] ComputeCanonicalHash(ProductionMailboxSelectionSuccessorV2Proof value) =>
        SHA256.HashData(Encode(value));

    internal static byte[] GetOldIssuerSigningBytes(ProductionMailboxSelectionSuccessorV2Proof value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Selection.Mode != ProductionMailboxSelectionSuccessorMode.DirectPromotion)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "Offline PSS2 has no retired-issuer transcript.");
        return GetSigningBytes(value, OldIssuerDomain);
    }

    internal static byte[] GetCurrentIssuerSigningBytes(ProductionMailboxSelectionSuccessorV2Proof value) =>
        GetSigningBytes(value, CurrentIssuerDomain);

    private static byte[] GetSigningBytes(ProductionMailboxSelectionSuccessorV2Proof value,
        ReadOnlySpan<byte> domain)
    {
        var frozen = Freeze(value);
        ValidateRoute(frozen);
        // Signatures are terminal and excluded from both transcripts. Use deterministic non-zero
        // placeholders only to pass the artifact-shape validator; caller signature memory is never
        // reread and cannot influence the returned transcript.
        var placeholder = Enumerable.Repeat((byte)0xA5,
            ProductionMailboxSelectionSuccessorConstants.Ed25519SignatureLength).ToArray();
        var transcriptValue = frozen with
        {
            Selection = frozen.Selection with
            {
                OldIssuerSignature = frozen.Selection.Mode ==
                    ProductionMailboxSelectionSuccessorMode.DirectPromotion
                        ? placeholder : new byte[ProductionMailboxSelectionSuccessorConstants.Ed25519SignatureLength],
                NewIssuerSignature = placeholder
            }
        };
        var encoded = Encode(transcriptValue);
        var withoutSignatures = encoded.AsSpan(0,
            encoded.Length - ProductionMailboxSelectionSuccessorV2Constants.SignatureBytes);
        return [.. domain, .. withoutSignatures];
    }

    private static ProductionMailboxSelectionSuccessorV2Proof Freeze(
        ProductionMailboxSelectionSuccessorV2Proof value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(value.Selection);
        PreflightSelection(value.Selection);
        PreflightHash(value.CanonicalTransitionContextHash, nameof(value.CanonicalTransitionContextHash));
        PreflightHash(value.PredecessorCanonicalRouteAuthorizationHash,
            nameof(value.PredecessorCanonicalRouteAuthorizationHash));
        PreflightHash(value.FreshCanonicalRouteCertificateHash, nameof(value.FreshCanonicalRouteCertificateHash));
        PreflightHash(value.NewCanonicalRouteAuthorizationHash, nameof(value.NewCanonicalRouteAuthorizationHash));
        PreflightHash(value.CanonicalRevocationCheckpointHash, nameof(value.CanonicalRevocationCheckpointHash));
        return ProductionMailboxSelectionSuccessorCopy.Clone(value);
    }

    private static void PreflightSelection(ProductionMailboxSelectionSuccessorProof value)
    {
        if (value.NetworkId.Length != 16 || value.MailboxOwnerEd25519PublicKey.Length != 32 ||
            value.BlindedMailboxId.Length != 32 || value.BlindedPlacementId.Length != 32 ||
            value.SelectionInputCommitment.Length != 32 ||
            value.OldCanonicalAuthorityHash.Length != 32 || value.NewCanonicalAuthorityHash.Length != 32 ||
            value.OldCanonicalTopologyHash.Length != 32 || value.NewCanonicalTopologyHash.Length != 32 ||
            value.OldCanonicalSelectionHash.Length != 32 || value.NewCanonicalSelectionHash.Length != 32 ||
            value.CanonicalNewAuthority.Length is < 1 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes ||
            value.OldCanonicalSelection.Length is < 1 or >
                ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            value.NewCanonicalSelection.Length is < 1 or >
                ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes ||
            value.OldIssuerSignature.Length != 64 || value.NewIssuerSignature.Length != 64)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidLength,
                "PSS2 nested selection field length is outside its strict bound.");
    }

    private static void ValidateRoute(ProductionMailboxSelectionSuccessorV2Proof value)
    {
        if (value.PredecessorAuthorizationKind is not ProductionMailboxRouteAuthorizationKind.OwnerPRA2 and
            not ProductionMailboxRouteAuthorizationKind.DelegatedRCA1 ||
            value.NewAuthorizationKind is not ProductionMailboxRouteAuthorizationKind.OwnerPRA2 and
            not ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField,
                "PSS2 route authorization kind is invalid.");
        NonzeroHash(value.CanonicalTransitionContextHash, "RTC1 hash");
        NonzeroHash(value.PredecessorCanonicalRouteAuthorizationHash, "predecessor route hash");
        NonzeroHash(value.FreshCanonicalRouteCertificateHash, "fresh PRC1 hash");
        NonzeroHash(value.NewCanonicalRouteAuthorizationHash, "new route authorization hash");
        if (value.PredecessorRouteAuthorizationSequence == 0 ||
            value.PredecessorRouteAuthorizationSequence == ulong.MaxValue ||
            value.NewRouteAuthorizationSequence != value.PredecessorRouteAuthorizationSequence + 1 ||
            value.NewRouteAuthorizationSequence == ulong.MaxValue)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField,
                "PSS2 route sequence is invalid.");
        if (value.NewAuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
        {
            if (value.CanonicalRevocationCheckpointHash.Length != 32 ||
                value.CanonicalRevocationCheckpointHash.Span.IndexOfAnyExcept((byte)0) >= 0)
                throw Error(ProductionMailboxSelectionSuccessorError.InvalidField,
                    "Owner PSS2 must have an all-zero RCH1 slot.");
        }
        else
        {
            NonzeroHash(value.CanonicalRevocationCheckpointHash, "RCH1 hash");
        }
    }

    private static void WriteRouteBlock(ProductionMailboxSelectionSuccessorV2Proof value, Span<byte> route)
    {
        value.CanonicalTransitionContextHash.Span.CopyTo(route[..32]);
        route[32] = (byte)value.PredecessorAuthorizationKind;
        route[33] = (byte)value.NewAuthorizationKind;
        value.PredecessorCanonicalRouteAuthorizationHash.Span.CopyTo(route.Slice(40, 32));
        BinaryPrimitives.WriteUInt64BigEndian(route.Slice(72, 8), value.PredecessorRouteAuthorizationSequence);
        value.FreshCanonicalRouteCertificateHash.Span.CopyTo(route.Slice(80, 32));
        value.NewCanonicalRouteAuthorizationHash.Span.CopyTo(route.Slice(112, 32));
        BinaryPrimitives.WriteUInt64BigEndian(route.Slice(144, 8), value.NewRouteAuthorizationSequence);
        value.CanonicalRevocationCheckpointHash.Span.CopyTo(route.Slice(152, 32));
    }

    private static void PreflightHash(ReadOnlyMemory<byte> value, string name)
    {
        if (value.Length != 32)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField, $"PSS2 {name} length is invalid.");
    }

    private static void NonzeroHash(ReadOnlyMemory<byte> value, string name)
    {
        PreflightHash(value, name);
        if (value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Error(ProductionMailboxSelectionSuccessorError.InvalidField, $"PSS2 {name} is all zero.");
    }

    private static ProductionMailboxSelectionSuccessorException Error(
        ProductionMailboxSelectionSuccessorError error, string message) => new(error, message);
}
