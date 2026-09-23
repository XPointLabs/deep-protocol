using System.Buffers.Binary;

namespace Deep.Protocol.ApplicationCore;

public sealed class ParsedDid2 : ParsedApplicationCoreRecord
{
    private readonly byte[] edPublicKey;
    private readonly byte[] pqPublicKey;
    private readonly byte[] readCapability;

    internal ParsedDid2(
        byte[] canonical, ReadOnlySpan<byte> edPublicKey,
        ReadOnlySpan<byte> pqPublicKey, ReadOnlySpan<byte> readCapability)
        : base(ProtocolMagic.DID2, canonical, hashGeneration: 2)
    {
        this.edPublicKey = edPublicKey.ToArray();
        this.pqPublicKey = pqPublicKey.ToArray();
        this.readCapability = readCapability.ToArray();
        Text = DeepIdText.Encode(2, RecordHash.Span, readCapability);
    }

    public ReadOnlyMemory<byte> RootEd25519PublicKey => edPublicKey.ToArray();
    public ReadOnlyMemory<byte> RootMlDsa65PublicKey => pqPublicKey.ToArray();
    public ReadOnlyMemory<byte> ResolverReadCapability => readCapability.ToArray();
    public string Text { get; }
}

public sealed class ParsedDab2 : ParsedApplicationCoreRecord
{
    private readonly byte[] didHash;
    private readonly byte[] realm;
    private readonly byte[] predecessor;
    private readonly byte[] account;
    private readonly byte[] rootEdSignature;
    private readonly byte[] rootPqSignature;
    private readonly byte[] accountSignature;
    private readonly byte[] unsigned;

    internal ParsedDab2(
        byte[] canonical, ReadOnlySpan<byte> didHash, ReadOnlySpan<byte> realm,
        ulong bindingGeneration, ReadOnlySpan<byte> predecessor,
        ReadOnlySpan<byte> account, ulong accountGeneration,
        ApplicationArtifactReference dpaReference,
        ReadOnlySpan<byte> rootEdSignature, ReadOnlySpan<byte> rootPqSignature,
        ReadOnlySpan<byte> accountSignature, byte[] unsigned)
        : base(ProtocolMagic.DAB2, canonical, hashGeneration: 2)
    {
        this.didHash = didHash.ToArray();
        this.realm = realm.ToArray();
        BindingGeneration = bindingGeneration;
        this.predecessor = predecessor.ToArray();
        this.account = account.ToArray();
        AccountGeneration = accountGeneration;
        Dpa1Reference = dpaReference;
        this.rootEdSignature = rootEdSignature.ToArray();
        this.rootPqSignature = rootPqSignature.ToArray();
        this.accountSignature = accountSignature.ToArray();
        this.unsigned = unsigned;
    }

    public ReadOnlyMemory<byte> ExactDid2Hash => didHash.ToArray();
    public ReadOnlyMemory<byte> IdentityRealmId => realm.ToArray();
    public ulong BindingGeneration { get; }
    public ReadOnlyMemory<byte> PredecessorDab2Hash => predecessor.ToArray();
    public ReadOnlyMemory<byte> DeepAccountId => account.ToArray();
    public ulong AccountGeneration { get; }
    public ApplicationArtifactReference Dpa1Reference { get; }
    public ReadOnlyMemory<byte> RootEd25519Signature => rootEdSignature.ToArray();
    public ReadOnlyMemory<byte> RootMlDsa65Signature => rootPqSignature.ToArray();
    public ReadOnlyMemory<byte> AccountSignature => accountSignature.ToArray();
    public ReadOnlyMemory<byte> UnsignedCanonicalBytes => unsigned.ToArray();
    public ReadOnlyMemory<byte> RootEd25519SignatureInput => ApplicationCoreFormat.SignatureInput(
        "Deep/Application/V2/address-binding/root-ed25519", unsigned, DeepIdV2Codec.Suite);
    public ReadOnlyMemory<byte> RootMlDsa65SignatureInput => ApplicationCoreFormat.SignatureInput(
        "Deep/Application/V2/address-binding/root-mldsa65", unsigned, DeepIdV2Codec.Suite);
    public ReadOnlyMemory<byte> AccountSignatureInput => ApplicationCoreFormat.SignatureInput(
        "Deep/Application/V2/address-binding/account-ed25519", unsigned, DeepIdV2Codec.Suite);
}

/// <summary>
/// Closed DID2/DAB2 shape. This codec never interprets retired DID1/DAB1
/// records; cryptographic promotion requires the separate root verifier.
/// </summary>
public static class DeepIdV2Codec
{
    public const ushort Suite = 0x0301;
    public const int Did2Length = 2036;
    public const int Dab2Length = 3711;
    public const ushort Dab2ArtifactType = 0x1002;
    private static ReadOnlySpan<byte> DidMagic => ProtocolMagicBytes.DID2;
    private static ReadOnlySpan<byte> DabMagic => ProtocolMagicBytes.DAB2;

    public static ParsedDid2 DecodeDid2(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[3];
        ApplicationCoreFormat.Preflight(
            canonical, DidMagic, 3, Did2Length, Did2Length, fields, 2, Suite);
        ApplicationCoreFormat.ExactLength(fields, 1, 32);
        ApplicationCoreFormat.ExactLength(fields, 2, 1952);
        ApplicationCoreFormat.ExactLength(fields, 3, 16);
        for (var tag = 1; tag <= 3; tag++)
            ApplicationCoreFormat.NonZero(ApplicationCoreFormat.Field(canonical, fields, tag),
                "DID2 root field");
        var owned = canonical.ToArray();
        return new ParsedDid2(owned,
            ApplicationCoreFormat.Field(owned, fields, 1),
            ApplicationCoreFormat.Field(owned, fields, 2),
            ApplicationCoreFormat.Field(owned, fields, 3));
    }

    public static ParsedDid2 AuthorDid2(
        ReadOnlySpan<byte> rootEd25519PublicKey32,
        ReadOnlySpan<byte> rootMlDsa65PublicKey1952,
        ReadOnlySpan<byte> resolverReadCapability16)
    {
        RequireLength(rootEd25519PublicKey32, 32, nameof(rootEd25519PublicKey32));
        RequireLength(rootMlDsa65PublicKey1952, 1952, nameof(rootMlDsa65PublicKey1952));
        RequireLength(resolverReadCapability16, 16, nameof(resolverReadCapability16));
        var canonical = new byte[Did2Length];
        var writer = new ApplicationRecordWriter(canonical, DidMagic, 3, 2, Suite);
        writer.Write(1, rootEd25519PublicKey32);
        writer.Write(2, rootMlDsa65PublicKey1952);
        writer.Write(3, resolverReadCapability16);
        writer.Complete();
        return DecodeDid2(canonical);
    }

    /// <summary>Decodes only the compact commitment; it does not fabricate a DID2 credential.</summary>
    public static (byte[] Did2Hash, byte[] ReadCapability) DecodeDeepIdText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var payload = DeepIdText.Decode(text, 2);
        return (payload.AsSpan(1, 32).ToArray(), payload.AsSpan(33, 16).ToArray());
    }

    public static byte[] DeriveIdentityRealmId(
        ReadOnlySpan<byte> networkId16, ushort deploymentProfileId)
    {
        RequireLength(networkId16, 16, nameof(networkId16));
        Span<byte> material = stackalloc byte[18];
        networkId16.CopyTo(material);
        BinaryPrimitives.WriteUInt16BigEndian(material[16..], deploymentProfileId);
        return ApplicationCoreFormat.Sha256Domain(
            "Deep/Application/V2/address-binding-realm", material);
    }

    public static ParsedDab2 DecodeDab2(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[10];
        ApplicationCoreFormat.Preflight(
            canonical, DabMagic, 10, Dab2Length, Dab2Length, fields, 2, Suite);
        ReadOnlySpan<int> lengths = [32, 32, 8, 32, 32, 8, 38, 64, 3309, 64];
        for (var tag = 1; tag <= lengths.Length; tag++)
            ApplicationCoreFormat.ExactLength(fields, tag, lengths[tag - 1]);
        foreach (var tag in new[] { 1, 2, 5, 8, 9, 10 })
            ApplicationCoreFormat.NonZero(ApplicationCoreFormat.Field(canonical, fields, tag),
                "DAB2 required field");
        var generation = BinaryPrimitives.ReadUInt64BigEndian(
            ApplicationCoreFormat.Field(canonical, fields, 3));
        var predecessor = ApplicationCoreFormat.Field(canonical, fields, 4);
        if (ApplicationCoreFormat.IsZero(predecessor) != (generation == 0))
            throw ApplicationCoreFormat.Error(
                ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.InvalidGeneration,
                "DAB2 predecessor must be zero exactly at genesis.");
        var accountGeneration = BinaryPrimitives.ReadUInt64BigEndian(
            ApplicationCoreFormat.Field(canonical, fields, 6));
        if (accountGeneration == 0)
            throw ApplicationCoreFormat.Error(
                ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.InvalidGeneration,
                "DAB2 account generation starts at one.");
        var reference = ApplicationCoreFormat.Field(canonical, fields, 7);
        if (BinaryPrimitives.ReadUInt16BigEndian(reference) != 1 ||
            BinaryPrimitives.ReadUInt32BigEndian(reference[2..]) != 644 ||
            ApplicationCoreFormat.IsZero(reference[6..]))
            throw ApplicationCoreFormat.Error(
                ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.InvalidReference,
                "DAB2 requires one exact DPA1 reference.");
        var owned = canonical.ToArray();
        var dpa = new ApplicationArtifactReference(1, 644, reference[6..]);
        var unsigned = new byte[250];
        var projection = new ApplicationRecordWriter(unsigned, DabMagic, 7, 2, Suite);
        for (ushort tag = 1; tag <= 7; tag++)
            projection.Write(tag, ApplicationCoreFormat.Field(owned, fields, tag));
        projection.Complete();
        return new ParsedDab2(owned,
            ApplicationCoreFormat.Field(owned, fields, 1),
            ApplicationCoreFormat.Field(owned, fields, 2), generation,
            ApplicationCoreFormat.Field(owned, fields, 4),
            ApplicationCoreFormat.Field(owned, fields, 5), accountGeneration,
            dpa,
            ApplicationCoreFormat.Field(owned, fields, 8),
            ApplicationCoreFormat.Field(owned, fields, 9),
            ApplicationCoreFormat.Field(owned, fields, 10), unsigned);
    }

    public static ParsedDab2 AuthorDab2(
        ReadOnlySpan<byte> did2Hash32, ReadOnlySpan<byte> identityRealmId32,
        ulong bindingGeneration, ReadOnlySpan<byte> predecessorDab2Hash32,
        ReadOnlySpan<byte> deepAccountId32, ulong accountGeneration,
        ApplicationArtifactReference exactDpa1Reference,
        ReadOnlySpan<byte> rootEd25519Signature64,
        ReadOnlySpan<byte> rootMlDsa65Signature3309,
        ReadOnlySpan<byte> accountSignature64)
    {
        RequireLength(did2Hash32, 32, nameof(did2Hash32));
        RequireLength(identityRealmId32, 32, nameof(identityRealmId32));
        RequireLength(predecessorDab2Hash32, 32, nameof(predecessorDab2Hash32));
        RequireLength(deepAccountId32, 32, nameof(deepAccountId32));
        RequireLength(rootEd25519Signature64, 64, nameof(rootEd25519Signature64));
        RequireLength(rootMlDsa65Signature3309, 3309, nameof(rootMlDsa65Signature3309));
        RequireLength(accountSignature64, 64, nameof(accountSignature64));
        ArgumentNullException.ThrowIfNull(exactDpa1Reference);
        if (exactDpa1Reference.TypeCode != 1 ||
            exactDpa1Reference.CanonicalLength != 644)
            throw new ArgumentException("DAB2 requires one exact DPA1 reference.", nameof(exactDpa1Reference));
        Span<byte> generationBytes = stackalloc byte[8];
        Span<byte> accountGenerationBytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(generationBytes, bindingGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(accountGenerationBytes, accountGeneration);
        var reference = exactDpa1Reference.CanonicalBytes;
        var canonical = new byte[Dab2Length];
        var writer = new ApplicationRecordWriter(canonical, DabMagic, 10, 2, Suite);
        writer.Write(1, did2Hash32);
        writer.Write(2, identityRealmId32);
        writer.Write(3, generationBytes);
        writer.Write(4, predecessorDab2Hash32);
        writer.Write(5, deepAccountId32);
        writer.Write(6, accountGenerationBytes);
        writer.Write(7, reference.Span);
        writer.Write(8, rootEd25519Signature64);
        writer.Write(9, rootMlDsa65Signature3309);
        writer.Write(10, accountSignature64);
        writer.Complete();
        return DecodeDab2(canonical);
    }

    public static ApplicationArtifactReference CreateDab2ArtifactReference(ParsedDab2 binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        return new ApplicationArtifactReference(Dab2ArtifactType,
            checked((uint)binding.CanonicalBytes.Length), binding.RecordHash.Span);
    }

    private static void RequireLength(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must contain exactly {length} bytes.", name);
    }
}
