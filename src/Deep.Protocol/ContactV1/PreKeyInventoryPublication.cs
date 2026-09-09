using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

public sealed class Xpi1UnsignedFields
{
    private readonly byte[] _networkId;
    private readonly byte[] _serviceCapability;
    private readonly byte[] _responderDeviceId;
    private readonly byte[] _responderDpd1Reference;
    private readonly byte[] _xps1Reference;
    private readonly byte[] _predecessorXpi1Hash;
    private readonly byte[] _oneTimeMerkleRoot;
    private readonly byte[] _lastResortDpk2Hash;
    private readonly byte[] _currentDmd1Hash;
    private readonly byte[] _currentDrs1Reference;

    public Xpi1UnsignedFields(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> responderDeviceId32,
        ReadOnlySpan<byte> responderDpd1Reference38,
        ulong serviceGeneration,
        ReadOnlySpan<byte> xps1Reference38,
        ulong inventoryEpoch,
        ReadOnlySpan<byte> predecessorXpi1Hash32,
        ushort oneTimeDpk2Count,
        ReadOnlySpan<byte> oneTimeMerkleRoot32,
        ReadOnlySpan<byte> lastResortDpk2Hash32,
        ReadOnlySpan<byte> currentDmd1Hash32,
        ReadOnlySpan<byte> currentDrs1Reference38,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        _networkId = Own(networkId16, 16, nameof(networkId16));
        _serviceCapability = Own(serviceCapability32, 32, nameof(serviceCapability32));
        _responderDeviceId = Own(responderDeviceId32, 32, nameof(responderDeviceId32));
        _responderDpd1Reference = Own(responderDpd1Reference38, 38, nameof(responderDpd1Reference38));
        ServiceGeneration = serviceGeneration;
        _xps1Reference = Own(xps1Reference38, 38, nameof(xps1Reference38));
        InventoryEpoch = inventoryEpoch;
        _predecessorXpi1Hash = Own(predecessorXpi1Hash32, 32, nameof(predecessorXpi1Hash32), false);
        OneTimeDpk2Count = oneTimeDpk2Count;
        _oneTimeMerkleRoot = Own(oneTimeMerkleRoot32, 32, nameof(oneTimeMerkleRoot32));
        _lastResortDpk2Hash = Own(lastResortDpk2Hash32, 32, nameof(lastResortDpk2Hash32));
        _currentDmd1Hash = Own(currentDmd1Hash32, 32, nameof(currentDmd1Hash32));
        _currentDrs1Reference = Own(currentDrs1Reference38, 38, nameof(currentDrs1Reference38));
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> ServiceCapability => _serviceCapability.ToArray();
    public ReadOnlyMemory<byte> ResponderDeviceId => _responderDeviceId.ToArray();
    public ReadOnlyMemory<byte> ResponderDpd1Reference => _responderDpd1Reference.ToArray();
    public ulong ServiceGeneration { get; }
    public ReadOnlyMemory<byte> Xps1Reference => _xps1Reference.ToArray();
    public ulong InventoryEpoch { get; }
    public ReadOnlyMemory<byte> PredecessorXpi1Hash => _predecessorXpi1Hash.ToArray();
    public ushort OneTimeDpk2Count { get; }
    public ReadOnlyMemory<byte> OneTimeMerkleRoot => _oneTimeMerkleRoot.ToArray();
    public ReadOnlyMemory<byte> LastResortDpk2Hash => _lastResortDpk2Hash.ToArray();
    public ReadOnlyMemory<byte> CurrentDmd1Hash => _currentDmd1Hash.ToArray();
    public ReadOnlyMemory<byte> CurrentDrs1Reference => _currentDrs1Reference.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }

    internal IReadOnlyList<(ushort Tag, byte[] Value)> EncodeFields() =>
    [
        (1, _networkId.ToArray()), (2, _serviceCapability.ToArray()),
        (3, _responderDeviceId.ToArray()), (4, _responderDpd1Reference.ToArray()),
        (5, PreKeyInventoryWire.U64(ServiceGeneration)), (6, _xps1Reference.ToArray()),
        (7, PreKeyInventoryWire.U64(InventoryEpoch)), (8, _predecessorXpi1Hash.ToArray()),
        (9, PreKeyInventoryWire.U16(OneTimeDpk2Count)), (10, _oneTimeMerkleRoot.ToArray()),
        (11, _lastResortDpk2Hash.ToArray()), (12, _currentDmd1Hash.ToArray()),
        (13, _currentDrs1Reference.ToArray()), (14, PreKeyInventoryWire.U64(IssuedAtUnixSeconds)),
        (15, PreKeyInventoryWire.U64(ExpiresAtUnixSeconds)),
    ];

    private static byte[] Own(ReadOnlySpan<byte> value, int length, string name, bool nonzero = true)
    {
        if (value.Length != length) throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
        if (nonzero && PreKeyInventoryWire.IsZero(value)) throw new ArgumentException($"{name} cannot be all-zero.", name);
        return value.ToArray();
    }
}

public sealed class Xpi1Record
{
    private readonly ContactRecord _record;

    internal Xpi1Record(ContactRecord record) => _record = record;

    public ReadOnlyMemory<byte> CanonicalBytes => _record.CanonicalBytes;
    public ReadOnlyMemory<byte> NetworkId => _record.Field(1);
    public ReadOnlyMemory<byte> ServiceCapability => _record.Field(2);
    public ReadOnlyMemory<byte> ResponderDeviceId => _record.Field(3);
    public ReadOnlyMemory<byte> ResponderDpd1Reference => _record.Field(4);
    public ulong ServiceGeneration => PreKeyInventoryWire.ReadU64(_record.FieldSpan(5));
    public ReadOnlyMemory<byte> Xps1Reference => _record.Field(6);
    public ulong InventoryEpoch => PreKeyInventoryWire.ReadU64(_record.FieldSpan(7));
    public ReadOnlyMemory<byte> PredecessorXpi1Hash => _record.Field(8);
    public ushort OneTimeDpk2Count => PreKeyInventoryWire.ReadU16(_record.FieldSpan(9));
    public ReadOnlyMemory<byte> OneTimeMerkleRoot => _record.Field(10);
    public ReadOnlyMemory<byte> LastResortDpk2Hash => _record.Field(11);
    public ReadOnlyMemory<byte> CurrentDmd1Hash => _record.Field(12);
    public ReadOnlyMemory<byte> CurrentDrs1Reference => _record.Field(13);
    public ulong IssuedAtUnixSeconds => PreKeyInventoryWire.ReadU64(_record.FieldSpan(14));
    public ulong ExpiresAtUnixSeconds => PreKeyInventoryWire.ReadU64(_record.FieldSpan(15));
    public ReadOnlyMemory<byte> PublisherSignature => _record.Field(16);
    public ReadOnlyMemory<byte> Xpi1Hash => Xpi1Codec.ComputeHash(CanonicalBytes.Span);

    internal ContactRecord Record => _record;
}

public static class Xpi1Codec
{
    public const int TotalBytes = 560;
    public const int SigningProjectionBytes = 488;
    public const string ExactHashDomain = "Deep/ContactResolver/V1/exact-xpi1";

    public static byte[] CreateSignatureInput(Xpi1UnsignedFields fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        var projection = PreKeyInventoryWire.Encode(ProtocolMagic.XPI1, fields.EncodeFields(), SigningProjectionBytes);
        try { return ContactCodec.SignatureInput("Deep/ContactResolver/V1/prekey-inventory", projection); }
        finally { CryptographicOperations.ZeroMemory(projection); }
    }

    public static byte[] Encode(Xpi1UnsignedFields fields, ReadOnlySpan<byte> publisherSignature64)
    {
        ArgumentNullException.ThrowIfNull(fields);
        if (publisherSignature64.Length != 64 || PreKeyInventoryWire.IsZero(publisherSignature64))
            throw new ArgumentException("The XPI1 publisher signature must be nonzero 64 bytes.", nameof(publisherSignature64));
        var all = fields.EncodeFields().ToList();
        all.Add((16, publisherSignature64.ToArray()));
        var canonical = PreKeyInventoryWire.Encode(ProtocolMagic.XPI1, all, TotalBytes);
        _ = Decode(canonical);
        return canonical;
    }

    public static Xpi1Record Decode(ReadOnlySpan<byte> canonical) =>
        new(ContactCodec.Decode(ProtocolMagic.XPI1, canonical));

    public static byte[] ComputeHash(ReadOnlySpan<byte> exactXpi1)
    {
        _ = Decode(exactXpi1);
        return ContactCodec.Sha256Domain(ExactHashDomain, exactXpi1);
    }
}

public sealed class Xpp1Record
{
    private readonly byte[] _canonical;
    private readonly byte[] _networkId;
    private readonly byte[] _operationId;
    private readonly byte[] _placementHash;
    private readonly byte[][] _oneTimeDpk2;
    private readonly byte[] _lastResortDpk2;

    internal Xpp1Record(
        byte[] canonical,
        Xpi1Record manifest,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> placementHash,
        IEnumerable<byte[]> oneTimeDpk2,
        ReadOnlySpan<byte> lastResortDpk2)
    {
        _canonical = canonical;
        Manifest = manifest;
        _networkId = networkId.ToArray();
        _operationId = operationId.ToArray();
        _placementHash = placementHash.ToArray();
        _oneTimeDpk2 = oneTimeDpk2.Select(static value => value.ToArray()).ToArray();
        _lastResortDpk2 = lastResortDpk2.ToArray();
    }

    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();
    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> PublicationOperationId => _operationId.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => _placementHash.ToArray();
    public Xpi1Record Manifest { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> OneTimeDpk2Records =>
        Array.AsReadOnly(_oneTimeDpk2.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    public ReadOnlyMemory<byte> LastResortDpk2Record => _lastResortDpk2.ToArray();

    internal IReadOnlyList<byte[]> OneTimeDpk2Bytes => _oneTimeDpk2;
    internal ReadOnlySpan<byte> LastResortDpk2Bytes => _lastResortDpk2;
}

public static class Xpp1Codec
{
    public const int MinimumTotalBytes = 67_983;
    public const int MaximumTotalBytes = 8_362_607;

    public static byte[] Encode(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> publicationOperationId32,
        ReadOnlySpan<byte> placementHash32,
        Xpi1Record manifest,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOneTimeDpk2,
        ReadOnlySpan<byte> exactLastResortDpk2)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(exactOneTimeDpk2);
        if (networkId16.Length != 16 || PreKeyInventoryWire.IsZero(networkId16))
            throw new ArgumentException("The XPP1 network ID must be nonzero and exactly 16 bytes.", nameof(networkId16));
        if (publicationOperationId32.Length != 32 || PreKeyInventoryWire.IsZero(publicationOperationId32))
            throw new ArgumentException("The XPP1 operation ID must be nonzero and exactly 32 bytes.", nameof(publicationOperationId32));
        if (placementHash32.Length != 32 || PreKeyInventoryWire.IsZero(placementHash32))
            throw new ArgumentException("The XPP1 placement hash must be nonzero and exactly 32 bytes.", nameof(placementHash32));
        if (exactOneTimeDpk2.Count is < 32 or > 4096 ||
            exactOneTimeDpk2.Count != manifest.OneTimeDpk2Count)
            throw new ArgumentOutOfRangeException(
                nameof(exactOneTimeDpk2),
                "XPP1 must contain exactly the manifest's bounded 32..4096 one-time DPK2 records.");
        foreach (var exact in exactOneTimeDpk2)
        {
            if (exact.Length != Dpk2Codec.OneTimeTotalBytes)
                throw new ArgumentException(
                    $"Every one-time DPK2 must be exactly {Dpk2Codec.OneTimeTotalBytes} bytes.",
                    nameof(exactOneTimeDpk2));
        }
        if (exactLastResortDpk2.Length != Dpk2Codec.LastResortTotalBytes)
            throw new ArgumentException(
                $"The last-resort DPK2 must be exactly {Dpk2Codec.LastResortTotalBytes} bytes.",
                nameof(exactLastResortDpk2));
        var bodyLength = checked(2 + exactOneTimeDpk2.Sum(static value => 4 + value.Length) + 4 + exactLastResortDpk2.Length);
        var body = new byte[bodyLength];
        BinaryPrimitives.WriteUInt16BigEndian(body, checked((ushort)exactOneTimeDpk2.Count));
        var offset = 2;
        foreach (var exact in exactOneTimeDpk2)
        {
            BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(offset), checked((uint)exact.Length));
            offset += 4;
            exact.Span.CopyTo(body.AsSpan(offset));
            offset += exact.Length;
        }
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(offset), checked((uint)exactLastResortDpk2.Length));
        exactLastResortDpk2.CopyTo(body.AsSpan(offset + 4));
        var canonical = PreKeyInventoryWire.Encode(ProtocolMagic.XPP1,
        [
            (1, networkId16.ToArray()), (2, publicationOperationId32.ToArray()),
            (3, placementHash32.ToArray()), (4, manifest.CanonicalBytes.ToArray()), (5, body),
        ], MaximumTotalBytes);
        _ = Decode(canonical);
        return canonical;
    }

    public static Xpp1Record Decode(ReadOnlySpan<byte> canonical)
    {
        var layout = PreKeyInventoryWire.Preflight(
            canonical, ProtocolMagic.XPP1, [16, 32, 32, Xpi1Codec.TotalBytes, -1],
            MinimumTotalBytes, MaximumTotalBytes);
        PreKeyInventoryWire.RequireNonZero(layout.Value(canonical, 1), "Xpp1NetworkId");
        PreKeyInventoryWire.RequireNonZero(layout.Value(canonical, 2), "Xpp1OperationId");
        PreKeyInventoryWire.RequireNonZero(layout.Value(canonical, 3), "Xpp1PlacementHash");

        var manifest = Xpi1Codec.Decode(layout.Value(canonical, 4));
        var body = layout.Value(canonical, 5);
        if (body.Length < 2) PreKeyInventoryWire.Reject(ContactValidationStage.Bounds, "Xpp1InventoryBodyTruncated");
        var count = BinaryPrimitives.ReadUInt16BigEndian(body);
        if (count is < 32 or > 4096 || count != manifest.OneTimeDpk2Count)
            PreKeyInventoryWire.Reject(ContactValidationStage.Scalar, "Xpp1InventoryCountMismatch");

        var owned = canonical.ToArray();
        var ownedLayout = PreKeyInventoryWire.Preflight(
            owned, ProtocolMagic.XPP1, [16, 32, 32, Xpi1Codec.TotalBytes, -1],
            MinimumTotalBytes, MaximumTotalBytes);
        var ownedBody = ownedLayout.Value(owned, 5);
        var oneTime = new byte[count][];
        var offset = 2;
        for (var index = 0; index < count; index++)
        {
            var exact = ReadLp32(ownedBody, ref offset, Dpk2Codec.OneTimeTotalBytes, "Xpp1OneTimeDpk2Length");
            var parsed = DecodeDpk2(exact);
            if (parsed.MlKemKind != Dpk2PrekeyKind.OneTime)
                PreKeyInventoryWire.Reject(ContactValidationStage.Scalar, "Xpp1OneTimeDpk2KindMismatch");
            oneTime[index] = exact.ToArray();
        }
        var lastResort = ReadLp32(ownedBody, ref offset, Dpk2Codec.LastResortTotalBytes, "Xpp1LastResortDpk2Length");
        if (offset != ownedBody.Length)
            PreKeyInventoryWire.Reject(ContactValidationStage.Bounds, "Xpp1InventoryBodyTrailingBytes");
        if (DecodeDpk2(lastResort).MlKemKind != Dpk2PrekeyKind.LastResort)
            PreKeyInventoryWire.Reject(ContactValidationStage.Scalar, "Xpp1LastResortDpk2KindMismatch");

        return new Xpp1Record(
            owned, Xpi1Codec.Decode(ownedLayout.Value(owned, 4)),
            ownedLayout.Value(owned, 1), ownedLayout.Value(owned, 2), ownedLayout.Value(owned, 3),
            oneTime, lastResort);
    }

    private static ReadOnlySpan<byte> ReadLp32(ReadOnlySpan<byte> body, ref int offset, int exactLength, string code)
    {
        if (body.Length - offset < 4) PreKeyInventoryWire.Reject(ContactValidationStage.Bounds, code);
        var declared = BinaryPrimitives.ReadUInt32BigEndian(body.Slice(offset, 4));
        offset += 4;
        if (declared != exactLength || declared > body.Length - offset)
            PreKeyInventoryWire.Reject(ContactValidationStage.Bounds, code);
        var value = body.Slice(offset, exactLength);
        offset += exactLength;
        return value;
    }

    private static Dpk2Record DecodeDpk2(ReadOnlySpan<byte> exact)
    {
        try { return Dpk2Codec.Decode(exact); }
        catch (Exception exception) when (exception is FormatException or ArgumentException or OverflowException)
        {
            throw new ContactFormatException(ContactValidationStage.Bounds, "Xpp1InvalidExactDpk2");
        }
    }
}

public sealed class Xic1UnsignedFields
{
    private readonly byte[] _networkId;
    private readonly byte[] _operationId;
    private readonly byte[] _xpi1Hash;
    private readonly byte[] _placementHash;
    private readonly byte[] _replicaId;

    public Xic1UnsignedFields(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> publicationOperationId32,
        ReadOnlySpan<byte> xpi1Hash32,
        ReadOnlySpan<byte> placementHash32,
        ReadOnlySpan<byte> replicaId32,
        ulong committedAtUnixSeconds)
    {
        _networkId = Own(networkId16, 16, nameof(networkId16));
        _operationId = Own(publicationOperationId32, 32, nameof(publicationOperationId32));
        _xpi1Hash = Own(xpi1Hash32, 32, nameof(xpi1Hash32));
        _placementHash = Own(placementHash32, 32, nameof(placementHash32));
        _replicaId = Own(replicaId32, 32, nameof(replicaId32));
        CommittedAtUnixSeconds = committedAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> PublicationOperationId => _operationId.ToArray();
    public ReadOnlyMemory<byte> Xpi1Hash => _xpi1Hash.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => _placementHash.ToArray();
    public ReadOnlyMemory<byte> ReplicaId => _replicaId.ToArray();
    public ulong CommittedAtUnixSeconds { get; }

    internal IReadOnlyList<(ushort Tag, byte[] Value)> EncodeFields() =>
    [
        (1, _networkId.ToArray()), (2, _operationId.ToArray()), (3, _xpi1Hash.ToArray()),
        (4, _placementHash.ToArray()), (5, _replicaId.ToArray()),
        (6, PreKeyInventoryWire.U64(CommittedAtUnixSeconds)),
    ];

    private static byte[] Own(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || PreKeyInventoryWire.IsZero(value))
            throw new ArgumentException($"{name} must be nonzero and exactly {length} bytes.", name);
        return value.ToArray();
    }
}

public sealed class Xic1Record
{
    private readonly byte[] _canonical;
    private readonly byte[][] _fields;

    internal Xic1Record(byte[] canonical, byte[][] fields)
    {
        _canonical = canonical;
        _fields = fields;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();
    public ReadOnlyMemory<byte> NetworkId => _fields[0].ToArray();
    public ReadOnlyMemory<byte> PublicationOperationId => _fields[1].ToArray();
    public ReadOnlyMemory<byte> Xpi1Hash => _fields[2].ToArray();
    public ReadOnlyMemory<byte> PlacementHash => _fields[3].ToArray();
    public ReadOnlyMemory<byte> ReplicaId => _fields[4].ToArray();
    public ulong CommittedAtUnixSeconds => PreKeyInventoryWire.ReadU64(_fields[5]);
    public ReadOnlyMemory<byte> ReplicaSignature => _fields[6].ToArray();
    internal ReadOnlySpan<byte> FieldSpan(int tag) => _fields[tag - 1];
}

public static class Xic1Codec
{
    public const int TotalBytes = 284;
    public const int SigningProjectionBytes = 212;

    public static byte[] CreateSignatureInput(Xic1UnsignedFields fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        var projection = PreKeyInventoryWire.Encode(ProtocolMagic.XIC1, fields.EncodeFields(), SigningProjectionBytes);
        try { return ContactCodec.SignatureInput("Deep/ContactResolver/V1/prekey-inventory-commit", projection); }
        finally { CryptographicOperations.ZeroMemory(projection); }
    }

    public static byte[] Encode(Xic1UnsignedFields fields, ReadOnlySpan<byte> replicaSignature64)
    {
        ArgumentNullException.ThrowIfNull(fields);
        if (replicaSignature64.Length != 64 || PreKeyInventoryWire.IsZero(replicaSignature64))
            throw new ArgumentException("The XIC1 replica signature must be nonzero 64 bytes.", nameof(replicaSignature64));
        var all = fields.EncodeFields().ToList();
        all.Add((7, replicaSignature64.ToArray()));
        var canonical = PreKeyInventoryWire.Encode(ProtocolMagic.XIC1, all, TotalBytes);
        _ = Decode(canonical);
        return canonical;
    }

    public static Xic1Record Decode(ReadOnlySpan<byte> canonical)
    {
        var layout = PreKeyInventoryWire.Preflight(
            canonical, ProtocolMagic.XIC1, [16, 32, 32, 32, 32, 8, 64], TotalBytes, TotalBytes);
        for (var tag = 1; tag <= 5; tag++)
            PreKeyInventoryWire.RequireNonZero(layout.Value(canonical, tag), $"Xic1Tag{tag}");
        PreKeyInventoryWire.RequireNonZero(layout.Value(canonical, 7), "Xic1Signature");
        var owned = canonical.ToArray();
        var ownedLayout = PreKeyInventoryWire.Preflight(
            owned, ProtocolMagic.XIC1, [16, 32, 32, 32, 32, 8, 64], TotalBytes, TotalBytes);
        var fields = Enumerable.Range(1, 7)
            .Select(tag => ownedLayout.Value(owned, tag).ToArray()).ToArray();
        return new Xic1Record(owned, fields);
    }

    internal static byte[] SignatureInput(Xic1Record receipt)
    {
        var projection = PreKeyInventoryWire.Encode(ProtocolMagic.XIC1,
            Enumerable.Range(1, 6).Select(tag => ((ushort)tag, receipt.FieldSpan(tag).ToArray())).ToArray(),
            SigningProjectionBytes);
        try { return ContactCodec.SignatureInput("Deep/ContactResolver/V1/prekey-inventory-commit", projection); }
        finally { CryptographicOperations.ZeroMemory(projection); }
    }
}

public sealed class PreKeyInventoryPublicationVerificationException : CryptographicException
{
    internal PreKeyInventoryPublicationVerificationException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Non-serializable authority that one complete device-signed XPI1 inventory was
/// durably committed by both exact current PreKeyClaim replicas.
/// </summary>
public sealed class VerifiedPreKeyInventoryPublication
{
    private readonly byte[] _networkId;
    private readonly byte[] _serviceCapability;
    private readonly byte[] _publicationOperationId;
    private readonly byte[] _xpi1Hash;
    private readonly byte[] _exactXpi1;
    private readonly byte[] _predecessorXpi1Hash;
    private readonly byte[][] _replicaNodeIds;
    private readonly VerifiedPreKeyInventoryMember[] _oneTimeMembers;

    internal VerifiedPreKeyInventoryPublication(
        Xpp1Record publication,
        ReadOnlySpan<byte> xpi1Hash,
        IEnumerable<VerifiedNetworkNode> replicas)
    {
        Manifest = publication.Manifest;
        _networkId = publication.NetworkId.ToArray();
        _serviceCapability = publication.Manifest.ServiceCapability.ToArray();
        _publicationOperationId = publication.PublicationOperationId.ToArray();
        _xpi1Hash = xpi1Hash.ToArray();
        _exactXpi1 = publication.Manifest.CanonicalBytes.ToArray();
        _predecessorXpi1Hash = publication.Manifest.PredecessorXpi1Hash.ToArray();
        _replicaNodeIds = replicas.OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance)
            .Select(static replica => replica.NodeId.ToArray()).ToArray();
        _oneTimeMembers = publication.OneTimeDpk2Bytes
            .Select(static exact => new VerifiedPreKeyInventoryMember(exact))
            .ToArray();
        LastResortMember = new VerifiedPreKeyInventoryMember(publication.LastResortDpk2Bytes);
        InventoryEpoch = publication.Manifest.InventoryEpoch;
        OneTimeDpk2Count = publication.Manifest.OneTimeDpk2Count;
        IssuedAtUnixSeconds = publication.Manifest.IssuedAtUnixSeconds;
        ExpiresAtUnixSeconds = publication.Manifest.ExpiresAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> ServiceCapability => _serviceCapability.ToArray();
    public ReadOnlyMemory<byte> PublicationOperationId => _publicationOperationId.ToArray();
    public ReadOnlyMemory<byte> Xpi1Hash => _xpi1Hash.ToArray();
    public ReadOnlyMemory<byte> ExactXpi1 => _exactXpi1.ToArray();
    public ReadOnlyMemory<byte> PredecessorXpi1Hash => _predecessorXpi1Hash.ToArray();
    public ulong InventoryEpoch { get; }
    public ushort OneTimeDpk2Count { get; }
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ReplicaNodeIds =>
        Array.AsReadOnly(_replicaNodeIds.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    public IReadOnlyList<VerifiedPreKeyInventoryMember> OneTimeMembers => Array.AsReadOnly(_oneTimeMembers);
    public VerifiedPreKeyInventoryMember LastResortMember { get; }

    internal Xpi1Record Manifest { get; }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}

/// <summary>
/// Public, immutable handoff for one member of a successfully verified complete
/// XPI1/XPP1/two-XIC1 inventory. It contains public offering material only.
/// </summary>
public sealed class VerifiedPreKeyInventoryMember
{
    private readonly byte[] _exactDpk2;
    private readonly byte[] _exactDpk2Hash;
    private readonly byte[] _claimPreKeyId;
    private readonly byte[] _mlKemPreKeyId;

    internal VerifiedPreKeyInventoryMember(ReadOnlySpan<byte> exactDpk2)
    {
        var parsed = Dpk2Codec.Decode(exactDpk2);
        _exactDpk2 = exactDpk2.ToArray();
        _exactDpk2Hash = ContactCodec.Sha256Domain("Deep/Messaging/V2/exact-dpk2", exactDpk2);
        _claimPreKeyId = parsed.MlKemKind == Dpk2PrekeyKind.OneTime
            ? parsed.OneTimeX25519PrekeyId.ToArray()
            : new byte[32];
        _mlKemPreKeyId = parsed.MlKemPrekeyId.ToArray();
        Kind = parsed.MlKemKind;
        ExpiresAtUnixSeconds = parsed.ExpiresAt;
        ReuseLimit = parsed.ReuseLimit;
    }

    public ReadOnlyMemory<byte> ExactDpk2 => _exactDpk2.ToArray();
    public ReadOnlyMemory<byte> ExactDpk2Hash => _exactDpk2Hash.ToArray();
    public ReadOnlyMemory<byte> ClaimPreKeyId => _claimPreKeyId.ToArray();
    public ReadOnlyMemory<byte> MlKemPreKeyId => _mlKemPreKeyId.ToArray();
    public Dpk2PrekeyKind Kind { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ushort ReuseLimit { get; }
}

internal sealed class PreKeyInventoryPredecessorFacts
{
    internal PreKeyInventoryPredecessorFacts(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> serviceCapability,
        Xpi1Record manifest,
        ReadOnlySpan<byte> xpi1Hash,
        ulong inventoryEpoch,
        ulong expiresAtUnixSeconds)
    {
        NetworkId = networkId.ToArray();
        ServiceCapability = serviceCapability.ToArray();
        Manifest = manifest;
        Xpi1Hash = xpi1Hash.ToArray();
        InventoryEpoch = inventoryEpoch;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    internal byte[] NetworkId { get; }
    internal byte[] ServiceCapability { get; }
    internal Xpi1Record Manifest { get; }
    internal byte[] Xpi1Hash { get; }
    internal ulong InventoryEpoch { get; }
    internal ulong ExpiresAtUnixSeconds { get; }

    internal static PreKeyInventoryPredecessorFacts? From(
        VerifiedPreKeyInventoryPublication? predecessor) => predecessor is null
        ? null
        : new(
            predecessor.NetworkId.Span,
            predecessor.ServiceCapability.Span,
            predecessor.Manifest,
            predecessor.Xpi1Hash.Span,
            predecessor.InventoryEpoch,
            predecessor.ExpiresAtUnixSeconds);
}

public static partial class PreKeyInventoryPublicationVerifier
{
    private const int ReceiptCount = 2;

    public static async ValueTask<VerifiedPreKeyInventoryPublication> VerifyAsync(
        Xpp1Record publication,
        IReadOnlyList<Xic1Record> receipts,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        VerifiedPreKeyInventoryPublication? predecessor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publication);
        ArgumentNullException.ThrowIfNull(receipts);
        ArgumentNullException.ThrowIfNull(placement);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(recipientBundle);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var reading = await trustedTimeAuthority.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            var interval = VerifyTrustedTime(reading, publication.Manifest, placement, authority);
            var xps1 = FindRecipientXps1(recipientBundle, authority);
            VerifyPlacementAndManifest(
                publication, placement, authority, recipientBundle, xps1,
                PreKeyInventoryPredecessorFacts.From(predecessor), interval);
            VerifyInventory(publication, authority, xps1);
            var xpi1Hash = Xpi1Codec.ComputeHash(publication.Manifest.CanonicalBytes.Span);
            var replicas = placement.ResolveSelectedReplicas();
            VerifyReceipts(publication, receipts, replicas, xpi1Hash);
            return new VerifiedPreKeyInventoryPublication(publication, xpi1Hash, replicas);
        }
        catch (PreKeyInventoryPublicationVerificationException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OnionBoundaryException exception)
        {
            throw Error("PlacementNotCurrent", "The exact PreKeyClaim placement is no longer current.", exception);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException or OverflowException)
        {
            throw Error("InvalidPreKeyInventoryPublication", "The exact XPI1/XPP1/XIC1 closure is invalid.", exception);
        }
    }

    private static (ulong Lower, ulong Upper) VerifyTrustedTime(
        OnionMonotonicReading reading,
        Xpi1Record manifest,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority)
    {
        var lease = placement.Network.TrustedTime ??
            throw Error("PlacementTimeMissing", "The verified PreKeyClaim placement has no trusted-time lease.");
        lease.EnsureLive();
        if (!Fixed(reading.BootId.Span, authority.MonotonicBootIdSpan) ||
            reading.SampleSeconds < authority.VerifiedAtMonotonicSeconds ||
            reading.SampleSeconds >= authority.FreshnessDeadlineMonotonicSeconds)
            Fail("TrustedTimeInvalid", "The protected monotonic reading is outside the authority capability.");
        var elapsed = reading.SampleSeconds - authority.VerifiedAtMonotonicSeconds;
        var lower = checked(authority.TrustedLowerUnixSeconds + elapsed);
        var upper = checked(authority.TrustedUpperUnixSeconds + elapsed);
        if (authority.NotBeforeUnixSeconds > lower || upper >= authority.ExpiresAtUnixSeconds ||
            manifest.IssuedAtUnixSeconds > lower || upper >= manifest.ExpiresAtUnixSeconds ||
            upper >= placement.ValidUntilUnixSeconds)
            Fail("InventoryTimeInvalid", "The complete trusted interval is not covered by XPI1, authority and placement.");
        return (lower, upper);
    }

    private static void VerifyPlacementAndManifest(
        Xpp1Record publication,
        VerifiedContactServicePlacement placement,
        VerifiedContactNetworkAuthority authority,
        VerifiedContactBundleClosure bundle,
        ContactCodec.Xps1Record xps1,
        PreKeyInventoryPredecessorFacts? predecessor,
        (ulong Lower, ulong Upper) interval)
    {
        var manifest = publication.Manifest;
        var closure = placement.Network.Closure;
        if (!placement.Binds(ContactServiceRequestKind.PublishPreKeyInventory, manifest.ServiceCapability) ||
            placement.RequestKind != ContactServiceRequestKind.PublishPreKeyInventory ||
            placement.ServiceClass != ContactServiceClass.PreKeyClaim ||
            !Fixed(publication.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(publication.NetworkId.Span, placement.Network.NetworkId.Span) ||
            !Fixed(publication.PlacementHash.Span, placement.PlacementHash.Span) ||
            closure is null || !Fixed(closure.PmtArtifactReference, authority.Pmt2ArtifactReference.Span))
            Fail("PlacementMismatch", "XPP1 is not bound to the exact current ClaimPreKey placement and authority.");

        var xpsHash = SHA256.HashData(xps1.CanonicalBytes);
        var xpsReference = Reference(ProtocolMagic.XPS1, xpsHash);
        try
        {
            if (!Fixed(manifest.NetworkId.Span, authority.NetworkId.Span) ||
                !Fixed(manifest.ServiceCapability.Span, xps1.ServiceCapability) ||
                !Fixed(manifest.ResponderDeviceId.Span, authority.RecipientDeviceId.Span) ||
                !Fixed(manifest.ResponderDeviceId.Span, xps1.DeviceId) ||
                !Fixed(manifest.ResponderDpd1Reference.Span, authority.RecipientDpd1Reference.Span) ||
                !Fixed(manifest.ResponderDpd1Reference.Span, xps1.Dpd1Reference) ||
                manifest.ServiceGeneration != xps1.ServiceGeneration ||
                !Fixed(manifest.Xps1Reference.Span, xpsReference) ||
                manifest.OneTimeDpk2Count < xps1.MinimumOneTimeInventory ||
                !Fixed(manifest.CurrentDmd1Hash.Span, authority.RecipientDmd1HashSpan) ||
                !MatchesApplicationArtifactReference(
                    manifest.CurrentDrs1Reference.Span, ProtocolMagic.DRS1, authority.RecipientDrs1ReferenceSpan) ||
                !Fixed(bundle.Bundle.FieldSpan(1), authority.NetworkId.Span) ||
                !Fixed(bundle.Bundle.FieldSpan(2), authority.RecipientAccountIdSpan) ||
                xps1.IssuedAtUnixSeconds > manifest.IssuedAtUnixSeconds ||
                manifest.ExpiresAtUnixSeconds > xps1.ExpiresAtUnixSeconds ||
                ServiceWire.U64(bundle.Bundle.FieldSpan(17)) > manifest.IssuedAtUnixSeconds ||
                manifest.ExpiresAtUnixSeconds > ServiceWire.U64(bundle.Bundle.FieldSpan(18)) ||
                manifest.IssuedAtUnixSeconds > interval.Lower || interval.Upper >= manifest.ExpiresAtUnixSeconds)
                Fail("InventoryManifestBindingMismatch", "XPI1 does not match the exact verified recipient XPS1/DPD1/DMD1/DRS1 closure.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(xpsHash);
            CryptographicOperations.ZeroMemory(xpsReference);
        }

        if (manifest.InventoryEpoch == 1)
        {
            if (predecessor is not null || !PreKeyInventoryWire.IsZero(manifest.PredecessorXpi1Hash.Span))
                Fail("InventoryLineageMismatch", "The genesis XPI1 inventory cannot have a predecessor.");
        }
        else
        {
            if (predecessor is null)
                Fail("InventoryLineageMismatch", "A successor XPI1 requires the exact accepted predecessor inventory.");
            if (!Fixed(predecessor.NetworkId, manifest.NetworkId.Span) ||
                !Fixed(predecessor.ServiceCapability, manifest.ServiceCapability.Span) ||
                predecessor.Manifest.ServiceGeneration != manifest.ServiceGeneration ||
                !Fixed(predecessor.Manifest.ResponderDeviceId.Span, manifest.ResponderDeviceId.Span) ||
                !Fixed(predecessor.Manifest.ResponderDpd1Reference.Span, manifest.ResponderDpd1Reference.Span) ||
                !Fixed(predecessor.Manifest.Xps1Reference.Span, manifest.Xps1Reference.Span))
                Fail("InventoryLineageScopeMismatch", "XPI1 predecessor and successor do not bind the same service and device authority.");
            if (manifest.InventoryEpoch <= predecessor.InventoryEpoch)
            {
                if (manifest.InventoryEpoch == predecessor.InventoryEpoch &&
                    !Fixed(predecessor.Xpi1Hash, manifest.Xpi1Hash.Span))
                    Fail("InventoryLineageFork", "A changed XPI1 was presented at the already installed inventory epoch.");
                Fail("InventoryLineageRollback", "XPI1 did not advance beyond the installed inventory epoch.");
            }
            if (predecessor.InventoryEpoch + 1 != manifest.InventoryEpoch)
                Fail("InventoryLineageGap", "XPI1 skipped the required append-one inventory epoch.");
            if (!Fixed(predecessor.Xpi1Hash, manifest.PredecessorXpi1Hash.Span))
                Fail("InventoryLineageFork", "XPI1 does not extend the exact installed predecessor hash.");
            if (predecessor.ExpiresAtUnixSeconds > manifest.IssuedAtUnixSeconds)
                Fail("InventoryLineageMismatch", "XPI1 does not extend the exact accepted non-overlapping predecessor inventory.");
        }

        try { ContactCodec.VerifyDeviceSignature(manifest.Record, authority.RecipientDeviceSigningPublicKeySpan); }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException)
        {
            throw Error("InventorySignatureInvalid", "XPI1 is not signed by the exact recipient DPD1 key.", exception);
        }
    }

    private static void VerifyInventory(
        Xpp1Record publication,
        VerifiedContactNetworkAuthority authority,
        ContactCodec.Xps1Record xps1)
    {
        var manifest = publication.Manifest;
        if (publication.OneTimeDpk2Bytes.Count != manifest.OneTimeDpk2Count)
            Fail("InventoryCountMismatch", "XPP1 does not contain the exact XPI1 one-time inventory count.");

        var hashes = new byte[publication.OneTimeDpk2Bytes.Count][];
        var seenHashes = new HashSet<string>(StringComparer.Ordinal);
        ReadOnlySpan<byte> previousId = default;
        for (var index = 0; index < publication.OneTimeDpk2Bytes.Count; index++)
        {
            var exact = publication.OneTimeDpk2Bytes[index];
            var dpk2 = Dpk2Codec.Decode(exact);
            VerifyDpk2Binding(dpk2, Dpk2PrekeyKind.OneTime, manifest, authority, xps1);
            var id = dpk2.OneTimeX25519PrekeyId.Span;
            if ((!previousId.IsEmpty && previousId.SequenceCompareTo(id) >= 0))
                Fail("InventoryOrderInvalid", "One-time DPK2 records are not strictly sorted by pre-key ID.");
            previousId = id;
            hashes[index] = ContactCodec.Sha256Domain("Deep/Messaging/V2/exact-dpk2", exact);
            if (!seenHashes.Add(Convert.ToHexString(hashes[index])))
                Fail("InventoryDuplicateHash", "The XPI1 inventory contains a duplicate exact DPK2 hash.");
            VerifyDpk2Signatures(dpk2, authority.RecipientDeviceSigningPublicKeySpan);
        }

        var lastExact = publication.LastResortDpk2Bytes;
        var last = Dpk2Codec.Decode(lastExact);
        VerifyDpk2Binding(last, Dpk2PrekeyKind.LastResort, manifest, authority, xps1);
        if (last.ReuseLimit > xps1.LastResortReuseLimit)
            Fail("LastResortReuseLimitMismatch", "The last-resort DPK2 exceeds the exact XPS1 reuse limit.");
        VerifyDpk2Signatures(last, authority.RecipientDeviceSigningPublicKeySpan);
        var lastHash = ContactCodec.Sha256Domain("Deep/Messaging/V2/exact-dpk2", lastExact);
        var root = ComputeMerkleRoot(hashes);
        try
        {
            if (!Fixed(root, manifest.OneTimeMerkleRoot.Span) ||
                !Fixed(lastHash, manifest.LastResortDpk2Hash.Span))
                Fail("InventoryCommitmentMismatch", "XPI1 does not commit the exact ordered XPP1 inventory.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(root);
            CryptographicOperations.ZeroMemory(lastHash);
            foreach (var hash in hashes) CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static void VerifyDpk2Binding(
        Dpk2Record dpk2,
        Dpk2PrekeyKind expectedKind,
        Xpi1Record manifest,
        VerifiedContactNetworkAuthority authority,
        ContactCodec.Xps1Record xps1)
    {
        if (dpk2.MlKemKind != expectedKind ||
            !Fixed(dpk2.NetworkId.Span, manifest.NetworkId.Span) ||
            !Fixed(dpk2.ResponderAccountId.Span, authority.RecipientAccountIdSpan) ||
            !Fixed(dpk2.ResponderDeviceId.Span, manifest.ResponderDeviceId.Span) ||
            dpk2.ResponderDeviceGeneration != authority.RecipientDeviceGeneration ||
            !Fixed(dpk2.ResponderDpd1Ref.Span, manifest.ResponderDpd1Reference.Span) ||
            dpk2.DeviceDirectoryGeneration != authority.RecipientDmd1Generation ||
            !Fixed(dpk2.DeviceDirectoryHeadHash.Span, manifest.CurrentDmd1Hash.Span) ||
            !Fixed(dpk2.DeviceAgreementPublicKey.Span, authority.RecipientDeviceAgreementPublicKeySpan) ||
            dpk2.PrekeyServiceGeneration != manifest.ServiceGeneration ||
            dpk2.PrekeyServiceGeneration != xps1.ServiceGeneration ||
            dpk2.InventoryEpoch != manifest.InventoryEpoch ||
            dpk2.NotBefore != manifest.IssuedAtUnixSeconds ||
            dpk2.ExpiresAt != manifest.ExpiresAtUnixSeconds ||
            dpk2.IssuedAt > manifest.IssuedAtUnixSeconds)
            Fail("Dpk2InventoryBindingMismatch", "A DPK2 member is not bound to the exact XPI1 recipient, generation, epoch and frozen time interval.");
    }

    private static void VerifyDpk2Signatures(Dpk2Record dpk2, ReadOnlySpan<byte> signingKey)
    {
        var inputs = new[]
        {
            MessagingWireCryptographicInputs.GetX25519SignedPrekeySignatureInput(dpk2),
            MessagingWireCryptographicInputs.GetMlKemPrekeySignatureInput(dpk2),
            MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(dpk2),
        };
        try
        {
            if (!VerifyEd25519(signingKey, inputs[0], dpk2.SignedX25519PrekeySignature.Span) ||
                !VerifyEd25519(signingKey, inputs[1], dpk2.MlKemPrekeySignature.Span) ||
                !VerifyEd25519(signingKey, inputs[2], dpk2.BundleSignature.Span))
                Fail("Dpk2InventorySignatureInvalid", "A DPK2 inventory member signature is invalid.");
        }
        finally
        {
            foreach (var input in inputs) CryptographicOperations.ZeroMemory(input);
        }
    }

    private static void VerifyReceipts(
        Xpp1Record publication,
        IReadOnlyList<Xic1Record> receipts,
        IReadOnlyList<VerifiedNetworkNode> selectedReplicas,
        ReadOnlySpan<byte> xpi1Hash)
    {
        if (receipts.Count != ReceiptCount || selectedReplicas.Count != ReceiptCount)
            Fail("ReplicaSetMismatch", "XPI1 publication requires exactly two selected replicas and two XIC1 receipts.");
        var replicas = selectedReplicas.OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance).ToArray();
        var orderedReceipts = receipts.OrderBy(static receipt => receipt.ReplicaId.ToArray(), ByteArrayComparer.Instance).ToArray();
        if (Fixed(replicas[0].NodeId, replicas[1].NodeId) ||
            Fixed(replicas[0].FailureDomainHash, replicas[1].FailureDomainHash))
            Fail("ReplicaDiversityInvalid", "The two publication replicas must have distinct identities and failure domains.");

        for (var index = 0; index < ReceiptCount; index++)
        {
            var receipt = orderedReceipts[index];
            var replica = replicas[index];
            if (!Fixed(receipt.NetworkId.Span, publication.NetworkId.Span) ||
                !Fixed(receipt.PublicationOperationId.Span, publication.PublicationOperationId.Span) ||
                !Fixed(receipt.Xpi1Hash.Span, xpi1Hash) ||
                !Fixed(receipt.PlacementHash.Span, publication.PlacementHash.Span) ||
                !Fixed(receipt.ReplicaId.Span, replica.NodeId) ||
                receipt.CommittedAtUnixSeconds < publication.Manifest.IssuedAtUnixSeconds ||
                receipt.CommittedAtUnixSeconds >= publication.Manifest.ExpiresAtUnixSeconds)
                Fail("InventoryReceiptBindingMismatch", "An XIC1 receipt does not bind the exact XPP1/XPI1 placement and validity interval.");
            if (replica.IdentityPublicKey is not { Length: 32 })
                Fail("ReplicaIdentityKeyMissing", "A selected replica has no NETCODEC-verified XND1 identity key.");
            var input = Xic1Codec.SignatureInput(receipt);
            try
            {
                if (!VerifyEd25519(replica.IdentityPublicKey, input, receipt.ReplicaSignature.Span))
                    Fail("InventoryReceiptSignatureInvalid", "An XIC1 signature is invalid under the exact selected replica identity key.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }
    }

    public static byte[] ComputeMerkleRoot(IReadOnlyList<byte[]> exactDpk2Hashes)
    {
        ArgumentNullException.ThrowIfNull(exactDpk2Hashes);
        if (exactDpk2Hashes.Count is < 32 or > 4096)
            throw new ArgumentOutOfRangeException(nameof(exactDpk2Hashes));
        var width = 1;
        while (width < exactDpk2Hashes.Count) width <<= 1;
        var level = new byte[width][];
        for (var index = 0; index < width; index++)
        {
            var position = PreKeyInventoryWire.U16(checked((ushort)index));
            if (index < exactDpk2Hashes.Count)
            {
                if (exactDpk2Hashes[index].Length != 32)
                    throw new ArgumentException("Every exact DPK2 hash must be 32 bytes.", nameof(exactDpk2Hashes));
                level[index] = ContactCodec.Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-leaf",
                    Join(position, exactDpk2Hashes[index]));
            }
            else
            {
                level[index] = ContactCodec.Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-empty", position);
            }
        }
        while (level.Length > 1)
        {
            var next = new byte[level.Length / 2][];
            for (var index = 0; index < next.Length; index++)
                next[index] = ContactCodec.Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-node",
                    Join(level[index * 2], level[(index * 2) + 1]));
            foreach (var hash in level) CryptographicOperations.ZeroMemory(hash);
            level = next;
        }
        return level[0];
    }

    internal static void VerifyClaimMembership(
        Xpi1Record manifest,
        ReadOnlySpan<byte> exactDpk2,
        ushort inventoryIndex,
        ReadOnlySpan<byte> inclusionProof)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var dpk2 = Dpk2Codec.Decode(exactDpk2);
        var exactHash = ContactCodec.Sha256Domain("Deep/Messaging/V2/exact-dpk2", exactDpk2);
        byte[]? node = null;
        try
        {
            if (dpk2.MlKemKind == Dpk2PrekeyKind.LastResort)
            {
                if (inventoryIndex != ushort.MaxValue || !inclusionProof.IsEmpty ||
                    !Fixed(exactHash, manifest.LastResortDpk2Hash.Span))
                    Fail("InventoryMembershipMismatch", "The last-resort DPK2 is not the exact XPI1 tag-11 member.");
                return;
            }

            if (dpk2.MlKemKind != Dpk2PrekeyKind.OneTime || inventoryIndex >= manifest.OneTimeDpk2Count)
                Fail("InventoryMembershipMismatch", "The one-time DPK2 inventory index is outside XPI1.");

            var width = 1;
            var depth = 0;
            while (width < manifest.OneTimeDpk2Count)
            {
                width <<= 1;
                depth++;
            }
            if (inclusionProof.Length != depth * 32)
                Fail("InventoryMembershipMismatch", "The XPI1 Merkle proof has a non-canonical length.");

            var position = PreKeyInventoryWire.U16(inventoryIndex);
            node = ContactCodec.Sha256Domain(
                "Deep/ContactResolver/V1/prekey-inventory-leaf",
                Join(position, exactHash));
            var currentIndex = inventoryIndex;
            for (var level = 0; level < depth; level++)
            {
                var sibling = inclusionProof.Slice(level * 32, 32).ToArray();
                var parentInput = (currentIndex & 1) == 0
                    ? Join(node, sibling)
                    : Join(sibling, node);
                var parent = ContactCodec.Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-node", parentInput);
                CryptographicOperations.ZeroMemory(parentInput);
                CryptographicOperations.ZeroMemory(sibling);
                CryptographicOperations.ZeroMemory(node);
                node = parent;
                currentIndex >>= 1;
            }

            if (!Fixed(node, manifest.OneTimeMerkleRoot.Span))
                Fail("InventoryMembershipMismatch", "The selected DPK2 is not included in the exact XPI1 Merkle root.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactHash);
            if (node is not null) CryptographicOperations.ZeroMemory(node);
        }
    }

    private static ContactCodec.Xps1Record FindRecipientXps1(
        VerifiedContactBundleClosure bundle,
        VerifiedContactNetworkAuthority authority)
    {
        var list = bundle.Bundle.FieldSpan(12);
        var count = list[0];
        var offset = 1;
        ContactCodec.Xps1Record? selected = null;
        for (var index = 0; index < count; index++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(list.Slice(offset, 4)));
            offset += 4;
            var xps = ContactCodec.DecodeXps1(list.Slice(offset, length));
            offset += length;
            if (Fixed(xps.DeviceId, authority.RecipientDeviceId.Span))
            {
                if (selected is not null) Fail("Xps1BindingMismatch", "The verified DCB1 contains duplicate recipient XPS1 records.");
                selected = xps;
            }
        }
        if (offset != list.Length || selected is null)
            Fail("Xps1BindingMismatch", "The verified DCB1 has no exact recipient XPS1.");
        return selected;
    }

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private static bool MatchesApplicationArtifactReference(
        ReadOnlySpan<byte> contactReference,
        string magic,
        ReadOnlySpan<byte> applicationReference) =>
        applicationReference.Length == 38 &&
        contactReference.Length == 38 &&
        contactReference[..4].SequenceEqual(Encoding.ASCII.GetBytes(magic)) &&
        BinaryPrimitives.ReadUInt16BigEndian(contactReference[4..6]) == 1 &&
        Fixed(contactReference[6..], applicationReference[6..]);

    private static bool VerifyEd25519(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
    {
        if (key.Length != 32 || signature.Length != 64) return false;
        try { return PublicKeyAuth.VerifyDetached(signature.ToArray(), input.ToArray(), key.ToArray()); }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException) { return false; }
    }

    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [DoesNotReturn]
    private static void Fail(string code, string message) => throw Error(code, message);

    private static PreKeyInventoryPublicationVerificationException Error(string code, string message, Exception? inner = null) =>
        new(code, message, inner);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}

internal static class PreKeyInventoryWire
{
    private const int HeaderBytes = 12;
    private const int FieldHeaderBytes = 8;

    internal static byte[] Encode(string magic, IReadOnlyList<(ushort Tag, byte[] Value)> fields, int maximumBytes)
    {
        ArgumentNullException.ThrowIfNull(magic);
        ArgumentNullException.ThrowIfNull(fields);
        if (magic.Length != 4 || fields.Count == 0 || fields.Count > ushort.MaxValue)
            throw new ArgumentException("The CONTACT-CODEC record shape is invalid.");
        var total = HeaderBytes;
        ushort prior = 0;
        foreach (var field in fields)
        {
            if (field.Tag <= prior) throw new ArgumentException("Fields must be strictly ordered.", nameof(fields));
            total = checked(total + FieldHeaderBytes + field.Value.Length);
            prior = field.Tag;
        }
        if (total > maximumBytes) Reject(ContactValidationStage.Length, "RecordLengthOutOfRange");
        var output = new byte[total];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = HeaderBytes;
        foreach (var field in fields)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), field.Tag);
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)field.Value.Length));
            offset += FieldHeaderBytes;
            field.Value.CopyTo(output, offset);
            offset += field.Value.Length;
        }
        return output;
    }

    internal static Layout Preflight(
        ReadOnlySpan<byte> canonical,
        string magic,
        IReadOnlyList<int> exactLengths,
        int minimumBytes,
        int maximumBytes)
    {
        if (canonical.Length < minimumBytes || canonical.Length > maximumBytes)
            Reject(ContactValidationStage.Length, "RecordLengthOutOfRange");
        if (!canonical[..4].SequenceEqual(Encoding.ASCII.GetBytes(magic))) Reject(ContactValidationStage.Header, "WrongRecordType");
        if (ReadU16(canonical[4..6]) != 1) Reject(ContactValidationStage.Header, "UnsupportedVersion");
        if (ReadU16(canonical[6..8]) != 0x0201) Reject(ContactValidationStage.Header, "UnknownSuite");
        if (ReadU16(canonical[8..10]) != exactLengths.Count) Reject(ContactValidationStage.Header, "WrongFieldCount");
        if (ReadU16(canonical[10..12]) != 0) Reject(ContactValidationStage.Header, "NonCanonicalReserved");
        var offsets = new int[exactLengths.Count];
        var lengths = new int[exactLengths.Count];
        var offset = HeaderBytes;
        for (var index = 0; index < exactLengths.Count; index++)
        {
            if (canonical.Length - offset < FieldHeaderBytes) Reject(ContactValidationStage.FieldScan, "TruncatedFieldHeader");
            if (ReadU16(canonical.Slice(offset, 2)) != index + 1) Reject(ContactValidationStage.FieldScan, "NonCanonicalTag");
            if (ReadU16(canonical.Slice(offset + 2, 2)) != 0) Reject(ContactValidationStage.FieldScan, "NonCanonicalReserved");
            var declared = BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(offset + 4, 4));
            offset += FieldHeaderBytes;
            if (declared > int.MaxValue || declared > canonical.Length - offset)
                Reject(ContactValidationStage.Bounds, "TruncatedField");
            if (exactLengths[index] >= 0 && declared != exactLengths[index])
                Reject(ContactValidationStage.Bounds, "FieldLengthOutOfRange");
            offsets[index] = offset;
            lengths[index] = (int)declared;
            offset += (int)declared;
        }
        if (offset != canonical.Length) Reject(ContactValidationStage.Bounds, "TrailingBytes");
        return new Layout(offsets, lengths);
    }

    internal static ushort ReadU16(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt16BigEndian(value);
    internal static ulong ReadU64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    internal static byte[] U16(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    internal static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    internal static bool IsZero(ReadOnlySpan<byte> value) { byte aggregate = 0; foreach (var item in value) aggregate |= item; return aggregate == 0; }
    internal static void RequireNonZero(ReadOnlySpan<byte> value, string code) { if (IsZero(value)) Reject(ContactValidationStage.Scalar, code); }

    [DoesNotReturn]
    internal static void Reject(ContactValidationStage stage, string code) => throw new ContactFormatException(stage, code);

    internal sealed class Layout(int[] offsets, int[] lengths)
    {
        internal ReadOnlySpan<byte> Value(ReadOnlySpan<byte> canonical, int tag) =>
            canonical.Slice(offsets[tag - 1], lengths[tag - 1]);
    }
}
