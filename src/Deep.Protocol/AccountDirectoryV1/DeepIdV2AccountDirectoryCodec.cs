using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Sodium;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Candidate ADC1 V2 account-authored checkpoint. Its old magic is retained,
/// but version, suite, DID-derived leaf, binding hash and signature domain all
/// change together. V1 decoders cannot accept these bytes.
/// </summary>
public sealed class ParsedAdc1V2
{
    private readonly byte[] canonical;
    private readonly byte[] unsigned;
    private readonly byte[] network;
    private readonly byte[] leaf;
    private readonly byte[] predecessor;
    private readonly byte[] dpaReference;
    private readonly byte[] drsReference;
    private readonly byte[] dmdHash;
    private readonly byte[] dabHash;
    private readonly byte[] revokedHash;
    private readonly byte[] signature;

    internal ParsedAdc1V2(ReadOnlySpan<byte> canonical, ReadOnlySpan<byte> unsigned,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> leaf,
        ulong accountGeneration, ulong checkpointGeneration,
        ReadOnlySpan<byte> predecessor, ReadOnlySpan<byte> dpaReference,
        ReadOnlySpan<byte> drsReference, ReadOnlySpan<byte> dmdHash,
        ReadOnlySpan<byte> dabHash, ReadOnlySpan<byte> revokedHash,
        ulong issuedAt, ushort minimumReader, ReadOnlySpan<byte> signature)
    {
        this.canonical = canonical.ToArray();
        this.unsigned = unsigned.ToArray();
        this.network = network.ToArray();
        this.leaf = leaf.ToArray();
        AccountGeneration = accountGeneration;
        CheckpointGeneration = checkpointGeneration;
        this.predecessor = predecessor.ToArray();
        this.dpaReference = dpaReference.ToArray();
        this.drsReference = drsReference.ToArray();
        this.dmdHash = dmdHash.ToArray();
        this.dabHash = dabHash.ToArray();
        this.revokedHash = revokedHash.ToArray();
        IssuedAtUnixSeconds = issuedAt;
        MinimumReader = minimumReader;
        this.signature = signature.ToArray();
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> UnsignedCanonicalBytes => unsigned.ToArray();
    public ReadOnlyMemory<byte> ArtifactHash => SHA256.HashData(canonical);
    public ReadOnlyMemory<byte> NetworkId => network.ToArray();
    public ReadOnlyMemory<byte> DirectoryLeafKey => leaf.ToArray();
    public ulong AccountGeneration { get; }
    public ulong CheckpointGeneration { get; }
    public ReadOnlyMemory<byte> PredecessorCheckpointHash => predecessor.ToArray();
    public ReadOnlyMemory<byte> ExactDpa1Reference => dpaReference.ToArray();
    public ReadOnlyMemory<byte> ExactDrs1Reference => drsReference.ToArray();
    public ReadOnlyMemory<byte> ExactDmd1Hash => dmdHash.ToArray();
    public ReadOnlyMemory<byte> ExactDab2Hash => dabHash.ToArray();
    public ReadOnlyMemory<byte> RevokedDcaAuthorizationIdsHash => revokedHash.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ushort MinimumReader { get; }
    public ReadOnlyMemory<byte> DeviceIssuerSignature => signature.ToArray();
    public ReadOnlyMemory<byte> SignatureInput => AccountDirectoryCrypto.SignatureInput(
        "Deep/AccountDirectory/V2/ADC1/account", DeepIdV2AccountDirectoryCodec.Suite,
        unsigned);
    public ReadOnlyMemory<byte> ArtifactReference => AccountDirectoryCrypto.CreateReference(
        ProtocolMagicBytes.ADC1, 2, ArtifactHash.Span);
}

public sealed class VerifiedAdc1V2
{
    private readonly byte[][] revokedDcaAuthorizationIds;

    internal VerifiedAdc1V2(ParsedAdc1V2 checkpoint, VerifiedDab2 binding,
        VerifiedDmd1 directory,
        IReadOnlyList<ReadOnlyMemory<byte>> revokedDcaAuthorizationIds)
    {
        Checkpoint = checkpoint;
        Binding = binding;
        Directory = directory;
        this.revokedDcaAuthorizationIds = revokedDcaAuthorizationIds
            .Select(static value => value.ToArray()).ToArray();
    }

    public ParsedAdc1V2 Checkpoint { get; }
    public VerifiedDab2 Binding { get; }
    public VerifiedDmd1 Directory { get; }
    public int RevokedDcaAuthorizationCount => revokedDcaAuthorizationIds.Length;

    public bool IsDcaAuthorizationRevoked(ReadOnlySpan<byte> authorizationId32)
    {
        if (authorizationId32.Length != 32 ||
            ApplicationCoreFormat.IsZero(authorizationId32))
            throw new ArgumentException("DCA1 authorization ID must be nonzero and 32 bytes.",
                nameof(authorizationId32));
        var revoked = false;
        foreach (var id in revokedDcaAuthorizationIds)
            revoked |= CryptographicOperations.FixedTimeEquals(id, authorizationId32);
        return revoked;
    }
}

public static class DeepIdV2AccountDirectoryCodec
{
    public const ushort Version = 2;
    public const ushort Suite = DeepIdV2Codec.Suite;
    public const int CanonicalLength = 458;
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.ADC1;
    private static ReadOnlySpan<int> Lengths =>
        [16, 32, 8, 8, 32, 38, 38, 32, 32, 32, 8, 2, 64];

    public static ParsedAdc1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[13];
        ApplicationCoreFormat.Preflight(canonical, Magic, 13, CanonicalLength,
            CanonicalLength, fields, Version, Suite);
        var lengths = Lengths;
        for (var tag = 1; tag <= lengths.Length; tag++)
            ApplicationCoreFormat.ExactLength(fields, tag, lengths[tag - 1]);
        foreach (var tag in new[] { 1, 2, 6, 7, 8, 9, 10, 13 })
            ApplicationCoreFormat.NonZero(ApplicationCoreFormat.Field(canonical, fields, tag),
                "ADC1 V2 required field");
        var accountGeneration = U64(ApplicationCoreFormat.Field(canonical, fields, 3));
        var checkpointGeneration = U64(ApplicationCoreFormat.Field(canonical, fields, 4));
        var predecessor = ApplicationCoreFormat.Field(canonical, fields, 5);
        var minimumReader = BinaryPrimitives.ReadUInt16BigEndian(
            ApplicationCoreFormat.Field(canonical, fields, 12));
        if (accountGeneration == 0 || minimumReader < Version ||
            (checkpointGeneration == 0) != ApplicationCoreFormat.IsZero(predecessor))
            throw Format("ADC1 V2 generation, reader or predecessor is invalid.");
        RequireReference(ApplicationCoreFormat.Field(canonical, fields, 6),
            ProtocolMagicBytes.DPA1);
        RequireReference(ApplicationCoreFormat.Field(canonical, fields, 7),
            ProtocolMagicBytes.DRS1);
        var unsigned = new byte[386];
        var writer = new ApplicationRecordWriter(unsigned, Magic, 12, Version, Suite);
        for (ushort tag = 1; tag <= 12; tag++)
            writer.Write(tag, ApplicationCoreFormat.Field(canonical, fields, tag));
        writer.Complete();
        var field = new byte[13][];
        for (var tag = 1; tag <= 13; tag++)
            field[tag - 1] = ApplicationCoreFormat.Field(canonical, fields, tag).ToArray();
        return new ParsedAdc1V2(canonical, unsigned, field[0], field[1],
            accountGeneration, checkpointGeneration, field[4], field[5],
            field[6], field[7], field[8], field[9], U64(field[10]),
            minimumReader, field[12]);
    }

    public static ParsedAdc1V2 Author(ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> directoryLeafKey32, ulong accountGeneration,
        ulong checkpointGeneration, ReadOnlySpan<byte> predecessorHash32,
        ReadOnlySpan<byte> exactDpa1Reference38,
        ReadOnlySpan<byte> exactDrs1Reference38,
        ReadOnlySpan<byte> exactDmd1Hash32,
        ReadOnlySpan<byte> exactDab2Hash32,
        ReadOnlySpan<byte> revokedDcaAuthorizationIdsHash32,
        ulong issuedAtUnixSeconds, ushort minimumReader,
        ReadOnlySpan<byte> deviceIssuerSignature64)
    {
        var fields = new ReadOnlyMemory<byte>[]
        {
            Copy(networkId16, 16), Copy(directoryLeafKey32, 32), U64Bytes(accountGeneration),
            U64Bytes(checkpointGeneration), Copy(predecessorHash32, 32),
            Copy(exactDpa1Reference38, 38), Copy(exactDrs1Reference38, 38),
            Copy(exactDmd1Hash32, 32), Copy(exactDab2Hash32, 32),
            Copy(revokedDcaAuthorizationIdsHash32, 32), U64Bytes(issuedAtUnixSeconds),
            U16Bytes(minimumReader), Copy(deviceIssuerSignature64, 64)
        };
        var canonical = new byte[CanonicalLength];
        var writer = new ApplicationRecordWriter(canonical, Magic, 13, Version, Suite);
        for (ushort tag = 1; tag <= 13; tag++)
            writer.Write(tag, fields[tag - 1].Span);
        writer.Complete();
        return Decode(canonical);
    }

    public static byte[] ComputeDirectoryLeafKey(ReadOnlySpan<byte> networkId16,
        ParsedDid2 exactDid2)
    {
        ArgumentNullException.ThrowIfNull(exactDid2);
        if (networkId16.Length != 16 || ApplicationCoreFormat.IsZero(networkId16))
            throw new ArgumentException("Network ID must be nonzero and exactly 16 bytes.",
                nameof(networkId16));
        var preimage = new byte[16 + DeepIdV2Codec.Did2Length];
        networkId16.CopyTo(preimage);
        exactDid2.CanonicalBytes.Span.CopyTo(preimage.AsSpan(16));
        var lookup = AccountDirectoryCrypto.Sha256Domain(
            "Deep/AccountDirectory/V2/lookup", preimage);
        return AccountDirectoryCrypto.Sha256Domain(
            "Deep/AccountDirectory/V2/leaf", lookup);
    }

    public static byte[] ComputeRevokedDcaAuthorizationIdsHash(
        IReadOnlyList<ReadOnlyMemory<byte>> sortedIds)
    {
        ArgumentNullException.ThrowIfNull(sortedIds);
        if (sortedIds.Count > 4096)
            throw Format("ADC1 V2 revoked DCA list exceeds 4096 IDs.");
        var preimage = new byte[4 + sortedIds.Count * 32];
        BinaryPrimitives.WriteUInt32BigEndian(preimage, (uint)sortedIds.Count);
        for (var index = 0; index < sortedIds.Count; index++)
        {
            var value = sortedIds[index].Span;
            if (value.Length != 32 || ApplicationCoreFormat.IsZero(value) ||
                (index > 0 && sortedIds[index - 1].Span.SequenceCompareTo(value) >= 0))
                throw Format("ADC1 V2 revoked DCA IDs must be nonzero, sorted and unique.");
            value.CopyTo(preimage.AsSpan(4 + index * 32));
        }
        return AccountDirectoryCrypto.Sha256Domain(
            "Deep/AccountDirectory/V2/revoked-DCA-authorization-ids", preimage);
    }

    public static VerifiedAdc1V2 Verify(ParsedAdc1V2 parsed,
        VerifiedDab2 binding, VerifiedDmd1 directory,
        IReadOnlyList<ReadOnlyMemory<byte>> revokedDcaAuthorizationIds,
        ushort supportedReader)
    {
        ArgumentNullException.ThrowIfNull(parsed);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(directory);
        var account = binding.Identity.Account;
        if (supportedReader < Version || parsed.MinimumReader > supportedReader ||
            !ReferenceEquals(binding.Identity, directory.Identity) ||
            !parsed.NetworkId.Span.SequenceEqual(account.Certificate.NetworkId.Span) ||
            parsed.AccountGeneration != account.Certificate.AccountGeneration ||
            parsed.AccountGeneration != binding.Record.AccountGeneration ||
            parsed.AccountGeneration != directory.Record.AccountGeneration ||
            !parsed.DirectoryLeafKey.Span.SequenceEqual(ComputeDirectoryLeafKey(
                parsed.NetworkId.Span, binding.DeepId)) ||
            !parsed.ExactDpa1Reference.Span.SequenceEqual(
                AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.DPA1, 1,
                    account.Certificate.CanonicalHash.Span)) ||
            !parsed.ExactDrs1Reference.Span.SequenceEqual(
                AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.DRS1, 1,
                    binding.Identity.Revocations.Snapshot.CanonicalHash.Span)) ||
            !parsed.ExactDmd1Hash.Span.SequenceEqual(directory.Record.RecordHash.Span) ||
            !parsed.ExactDab2Hash.Span.SequenceEqual(binding.Record.RecordHash.Span) ||
            !parsed.RevokedDcaAuthorizationIdsHash.Span.SequenceEqual(
                ComputeRevokedDcaAuthorizationIdsHash(revokedDcaAuthorizationIds)) ||
            !PublicKeyAuth.VerifyDetached(parsed.DeviceIssuerSignature.ToArray(),
                parsed.SignatureInput.ToArray(),
                account.Certificate.DeviceIssuerEd25519PublicKey.ToArray()))
            throw new AccountDirectoryAdc1VerificationException(
                "ADC1 V2 does not close over exact DID2/DAB2/DPA1/DRS1/DMD1 state.");
        return new VerifiedAdc1V2(parsed, binding, directory,
            revokedDcaAuthorizationIds);
    }

    private static void RequireReference(ReadOnlySpan<byte> reference,
        ReadOnlySpan<byte> magic)
    {
        if (!reference[..4].SequenceEqual(magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(reference[4..]) != 1 ||
            ApplicationCoreFormat.IsZero(reference[6..]))
            throw Format("ADC1 V2 requires exact version-one DPA1/DRS1 references.");
    }

    private static byte[] Copy(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length != length)
            throw new ArgumentException($"ADC1 V2 field must contain {length} bytes.");
        return value.ToArray();
    }

    private static ulong U64(ReadOnlySpan<byte> bytes) =>
        BinaryPrimitives.ReadUInt64BigEndian(bytes);

    private static byte[] U64Bytes(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] U16Bytes(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }

    private static AccountDirectoryAdc1FormatException Format(string message) => new(message);
}
