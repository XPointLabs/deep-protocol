using System.Buffers.Binary;
using Sodium;

namespace Deep.Protocol.ApplicationCore;

public sealed class ParsedDca1V2 : ParsedApplicationCoreRecord
{
    private readonly byte[] network;
    private readonly byte[] account;
    private readonly byte[] dmdHash;
    private readonly byte[] authorizationId;
    private readonly byte[] publisherDeviceId;
    private readonly byte[] signature;
    private readonly byte[] didHash;
    private readonly byte[] unsigned;

    internal ParsedDca1V2(byte[] canonical, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ApplicationArtifactReference dpaReference,
        ulong dmdGeneration, ReadOnlySpan<byte> dmdHash,
        ReadOnlySpan<byte> authorizationId, ReadOnlySpan<byte> publisherDeviceId,
        byte inviteKindMask, ulong maximumBundleGeneration, ulong notBefore,
        ulong expiresAt, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> didHash,
        ApplicationArtifactReference dabReference, byte[] unsigned)
        : base(ProtocolMagic.DCA1, canonical, hashGeneration: 2)
    {
        this.network = network.ToArray();
        this.account = account.ToArray();
        Dpa1Reference = dpaReference;
        AuthorizedDmd1Generation = dmdGeneration;
        this.dmdHash = dmdHash.ToArray();
        this.authorizationId = authorizationId.ToArray();
        this.publisherDeviceId = publisherDeviceId.ToArray();
        AllowedInviteKindMask = inviteKindMask;
        MaximumBundleGeneration = maximumBundleGeneration;
        NotBeforeUnixSeconds = notBefore;
        ExpiresAtUnixSeconds = expiresAt;
        this.signature = signature.ToArray();
        this.didHash = didHash.ToArray();
        Dab2Reference = dabReference;
        this.unsigned = unsigned;
    }

    public ReadOnlyMemory<byte> NetworkId => network.ToArray();
    public ReadOnlyMemory<byte> DeepAccountId => account.ToArray();
    public ApplicationArtifactReference Dpa1Reference { get; }
    public ulong AuthorizedDmd1Generation { get; }
    public ReadOnlyMemory<byte> AuthorizedDmd1Hash => dmdHash.ToArray();
    public ReadOnlyMemory<byte> AuthorizationId => authorizationId.ToArray();
    public ReadOnlyMemory<byte> PublisherDeviceId => publisherDeviceId.ToArray();
    public byte AllowedInviteKindMask { get; }
    public ulong MaximumBundleGeneration { get; }
    public ulong NotBeforeUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> AccountSignature => signature.ToArray();
    public ReadOnlyMemory<byte> ExactDid2Hash => didHash.ToArray();
    public ApplicationArtifactReference Dab2Reference { get; }
    public ReadOnlyMemory<byte> UnsignedCanonicalBytes => unsigned.ToArray();
    public ReadOnlyMemory<byte> SignatureInput => ApplicationCoreFormat.SignatureInput(
        "Deep/Application/V2/contact-publication-authorization", unsigned,
        DeepIdV2Codec.Suite);
}

public sealed class VerifiedDca1V2
{
    internal VerifiedDca1V2(ParsedDca1V2 record, VerifiedDab2 binding,
        VerifiedDmd1 directory)
    {
        Record = record;
        Binding = binding;
        Directory = directory;
    }

    public ParsedDca1V2 Record { get; }
    public VerifiedDab2 Binding { get; }
    public VerifiedDmd1 Directory { get; }
}

/// <summary>
/// DCA1 V2 is a replacement record, not a dual decoder: same magic/length,
/// but version 2, root suite 0x0301 and an exact DAB2 type/length reference.
/// </summary>
public static class DeepIdV2ContactAuthorizationCodec
{
    public const int CanonicalLength = 473;
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.DCA1;
    private static ReadOnlySpan<int> FieldLengths =>
        [16, 32, 38, 8, 32, 32, 32, 1, 8, 8, 8, 64, 32, 38];

    public static ParsedDca1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[14];
        ApplicationCoreFormat.Preflight(canonical, Magic, 14,
            CanonicalLength, CanonicalLength, fields, 2, DeepIdV2Codec.Suite);
        var lengths = FieldLengths;
        for (var tag = 1; tag <= lengths.Length; tag++)
            ApplicationCoreFormat.ExactLength(fields, tag, lengths[tag - 1]);
        foreach (var tag in new[] { 1, 2, 5, 6, 7, 12, 13 })
            ApplicationCoreFormat.NonZero(
                ApplicationCoreFormat.Field(canonical, fields, tag),
                "DCA1 V2 required field");
        var generation = U64(ApplicationCoreFormat.Field(canonical, fields, 4));
        var mask = ApplicationCoreFormat.Field(canonical, fields, 8)[0];
        var notBefore = U64(ApplicationCoreFormat.Field(canonical, fields, 10));
        var expiresAt = U64(ApplicationCoreFormat.Field(canonical, fields, 11));
        if (generation == 0)
            Invalid(ApplicationCoreRejection.InvalidGeneration,
                "DCA1 V2 DMD1 generation starts at one.");
        if (mask == 0 || (mask & ~0x03) != 0)
            Invalid(ApplicationCoreRejection.InvalidFlags,
                "DCA1 V2 invite mask is empty or unknown.");
        if (expiresAt == 0 || expiresAt <= notBefore)
            Invalid(ApplicationCoreRejection.InvalidTimeRange,
                "DCA1 V2 expiry must follow not-before.");
        var dpa = ParseReference(ApplicationCoreFormat.Field(canonical, fields, 3),
            1, 644, ProtocolMagic.DPA1);
        var dab = ParseReference(ApplicationCoreFormat.Field(canonical, fields, 14),
            DeepIdV2Codec.Dab2ArtifactType, DeepIdV2Codec.Dab2Length,
            ProtocolMagic.DAB2);
        var owned = canonical.ToArray();
        var unsigned = new byte[401];
        var projection = new ApplicationRecordWriter(unsigned, Magic, 13, 2,
            DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 14; tag++)
        {
            if (tag != 12)
                projection.Write(tag, ApplicationCoreFormat.Field(owned, fields, tag));
        }
        projection.Complete();
        return new ParsedDca1V2(owned,
            ApplicationCoreFormat.Field(owned, fields, 1),
            ApplicationCoreFormat.Field(owned, fields, 2), dpa, generation,
            ApplicationCoreFormat.Field(owned, fields, 5),
            ApplicationCoreFormat.Field(owned, fields, 6),
            ApplicationCoreFormat.Field(owned, fields, 7), mask,
            U64(ApplicationCoreFormat.Field(owned, fields, 9)), notBefore,
            expiresAt, ApplicationCoreFormat.Field(owned, fields, 12),
            ApplicationCoreFormat.Field(owned, fields, 13), dab, unsigned);
    }

    public static ParsedDca1V2 Author(ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> deepAccountId32,
        ApplicationArtifactReference exactDpa1Reference,
        ulong authorizedDmd1Generation, ReadOnlySpan<byte> authorizedDmd1Hash32,
        ReadOnlySpan<byte> authorizationId32, ReadOnlySpan<byte> publisherDeviceId32,
        byte allowedInviteKindMask, ulong maximumBundleGeneration,
        ulong notBeforeUnixSeconds, ulong expiresAtUnixSeconds,
        ReadOnlySpan<byte> accountSignature64, ReadOnlySpan<byte> exactDid2Hash32,
        ApplicationArtifactReference exactDab2Reference)
    {
        RequireLength(networkId16, 16, nameof(networkId16));
        RequireLength(deepAccountId32, 32, nameof(deepAccountId32));
        RequireLength(authorizedDmd1Hash32, 32, nameof(authorizedDmd1Hash32));
        RequireLength(authorizationId32, 32, nameof(authorizationId32));
        RequireLength(publisherDeviceId32, 32, nameof(publisherDeviceId32));
        RequireLength(accountSignature64, 64, nameof(accountSignature64));
        RequireLength(exactDid2Hash32, 32, nameof(exactDid2Hash32));
        ArgumentNullException.ThrowIfNull(exactDpa1Reference);
        ArgumentNullException.ThrowIfNull(exactDab2Reference);
        if (exactDpa1Reference.TypeCode != 1 || exactDpa1Reference.CanonicalLength != 644 ||
            exactDab2Reference.TypeCode != DeepIdV2Codec.Dab2ArtifactType ||
            exactDab2Reference.CanonicalLength != DeepIdV2Codec.Dab2Length)
            throw new ArgumentException("DCA1 V2 requires exact DPA1 and DAB2 references.");
        Span<byte> generation = stackalloc byte[8];
        Span<byte> maxGeneration = stackalloc byte[8];
        Span<byte> notBefore = stackalloc byte[8];
        Span<byte> expiresAt = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(generation, authorizedDmd1Generation);
        BinaryPrimitives.WriteUInt64BigEndian(maxGeneration, maximumBundleGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(notBefore, notBeforeUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(expiresAt, expiresAtUnixSeconds);
        var canonical = new byte[CanonicalLength];
        var writer = new ApplicationRecordWriter(canonical, Magic, 14, 2,
            DeepIdV2Codec.Suite);
        writer.Write(1, networkId16);
        writer.Write(2, deepAccountId32);
        writer.Write(3, exactDpa1Reference.CanonicalBytes.Span);
        writer.Write(4, generation);
        writer.Write(5, authorizedDmd1Hash32);
        writer.Write(6, authorizationId32);
        writer.Write(7, publisherDeviceId32);
        writer.Write(8, [allowedInviteKindMask]);
        writer.Write(9, maxGeneration);
        writer.Write(10, notBefore);
        writer.Write(11, expiresAt);
        writer.Write(12, accountSignature64);
        writer.Write(13, exactDid2Hash32);
        writer.Write(14, exactDab2Reference.CanonicalBytes.Span);
        writer.Complete();
        return Decode(canonical);
    }

    public static VerifiedDca1V2 Verify(ParsedDca1V2 parsed,
        VerifiedDab2 binding, VerifiedDmd1 directory)
    {
        ArgumentNullException.ThrowIfNull(parsed);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(directory);
        var account = binding.Identity.Account;
        var certificate = account.Certificate;
        if (!ReferenceEquals(binding.Identity, directory.Identity) ||
            !parsed.NetworkId.Span.SequenceEqual(certificate.NetworkId.Span) ||
            !parsed.DeepAccountId.Span.SequenceEqual(account.DeepAccountIdHash.Span) ||
            parsed.Dpa1Reference.TypeCode != (ushort)certificate.ArtifactType ||
            parsed.Dpa1Reference.CanonicalLength != certificate.CanonicalBytes.Length ||
            !parsed.Dpa1Reference.CanonicalHash.Span.SequenceEqual(certificate.CanonicalHash.Span) ||
            parsed.AuthorizedDmd1Generation != directory.Record.DirectoryGeneration ||
            !parsed.AuthorizedDmd1Hash.Span.SequenceEqual(directory.Record.RecordHash.Span) ||
            !parsed.ExactDid2Hash.Span.SequenceEqual(binding.DeepId.RecordHash.Span) ||
            parsed.Dab2Reference.TypeCode != DeepIdV2Codec.Dab2ArtifactType ||
            parsed.Dab2Reference.CanonicalLength != binding.Record.CanonicalBytes.Length ||
            !parsed.Dab2Reference.CanonicalHash.Span.SequenceEqual(binding.Record.RecordHash.Span) ||
            !directory.Record.ActiveDevices.Any(entry =>
                entry.DeviceId.Span.SequenceEqual(parsed.PublisherDeviceId.Span)))
            Reject("DCA1 V2 does not close over exact DID2/DAB2/DPA1/DMD1 state.");
        if (!PublicKeyAuth.VerifyDetached(parsed.AccountSignature.ToArray(),
                parsed.SignatureInput.ToArray(),
                certificate.AccountEd25519PublicKey.ToArray()))
            Reject("DCA1 V2 account signature is invalid.");
        return new VerifiedDca1V2(parsed, binding, directory);
    }

    public static VerifiedDca1V2 RequireCurrentlyAuthoritative(
        VerifiedDca1V2 verified, ulong trustedUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(verified);
        if (trustedUnixSeconds < verified.Record.NotBeforeUnixSeconds ||
            trustedUnixSeconds >= verified.Record.ExpiresAtUnixSeconds)
            Reject("DCA1 V2 is not authoritative at the trusted instant.");
        return verified;
    }

    private static ApplicationArtifactReference ParseReference(
        ReadOnlySpan<byte> encoded, ushort expectedType, int expectedLength,
        string name)
    {
        var type = BinaryPrimitives.ReadUInt16BigEndian(encoded);
        var length = BinaryPrimitives.ReadUInt32BigEndian(encoded[2..]);
        if (type != expectedType || length != expectedLength ||
            ApplicationCoreFormat.IsZero(encoded[6..]))
            Invalid(ApplicationCoreRejection.InvalidReference,
                $"DCA1 V2 requires one exact {name} reference.");
        return new ApplicationArtifactReference(type, length, encoded[6..]);
    }

    private static ulong U64(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt64BigEndian(value);

    private static void RequireLength(ReadOnlySpan<byte> value, int length,
        string name)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must contain exactly {length} bytes.", name);
    }

    private static void Invalid(ApplicationCoreRejection rejection, string message) =>
        throw ApplicationCoreFormat.Error(
            ApplicationCoreValidationStage.SemanticFields, rejection, message);

    private static void Reject(string message) =>
        throw ApplicationCoreFormat.Error(
            ApplicationCoreValidationStage.CryptographicVerification,
            ApplicationCoreRejection.VerificationFailed, message);
}
