using System.Buffers.Binary;

namespace Deep.Protocol.MessagingWire;

public enum Dpk2PrekeyKind : byte
{
    OneTime = 1,
    LastResort = 2,
}

public sealed class Dpk2Record
{
    private readonly byte[] _networkId;
    private readonly byte[] _responderAccountId;
    private readonly byte[] _responderDeviceId;
    private readonly byte[] _responderDpd1Ref;
    private readonly byte[] _deviceDirectoryHeadHash;
    private readonly byte[] _bundleId;
    private readonly byte[] _deviceAgreementPublicKey;
    private readonly byte[] _signedX25519PrekeyId;
    private readonly byte[] _signedX25519PrekeyPublic;
    private readonly byte[] _signedX25519PrekeySignature;
    private readonly byte[] _oneTimeX25519PrekeyId;
    private readonly byte[] _oneTimeX25519PrekeyPublic;
    private readonly byte[] _mlKemPrekeyId;
    private readonly byte[] _mlKem768EncapsulationKey;
    private readonly byte[] _mlKemPrekeySignature;
    private readonly byte[] _bundleSignature;

    public Dpk2Record(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> responderAccountId,
        ReadOnlySpan<byte> responderDeviceId,
        ulong responderDeviceGeneration,
        ReadOnlySpan<byte> responderDpd1Ref,
        ulong deviceDirectoryGeneration,
        ReadOnlySpan<byte> deviceDirectoryHeadHash,
        ulong prekeyServiceGeneration,
        ulong inventoryEpoch,
        ReadOnlySpan<byte> bundleId,
        ulong policyGeneration,
        ulong notBefore,
        ulong issuedAt,
        ulong expiresAt,
        ReadOnlySpan<byte> deviceAgreementPublicKey,
        ReadOnlySpan<byte> signedX25519PrekeyId,
        ReadOnlySpan<byte> signedX25519PrekeyPublic,
        ReadOnlySpan<byte> signedX25519PrekeySignature,
        ReadOnlySpan<byte> oneTimeX25519PrekeyId,
        ReadOnlySpan<byte> oneTimeX25519PrekeyPublic,
        ReadOnlySpan<byte> mlKemPrekeyId,
        ReadOnlySpan<byte> mlKem768EncapsulationKey,
        Dpk2PrekeyKind mlKemKind,
        ushort reuseLimit,
        ReadOnlySpan<byte> mlKemPrekeySignature,
        ReadOnlySpan<byte> bundleSignature)
    {
        Validate(
            networkId,
            responderAccountId,
            responderDeviceId,
            responderDeviceGeneration,
            responderDpd1Ref,
            deviceDirectoryGeneration,
            deviceDirectoryHeadHash,
            prekeyServiceGeneration,
            inventoryEpoch,
            bundleId,
            policyGeneration,
            notBefore,
            issuedAt,
            expiresAt,
            deviceAgreementPublicKey,
            signedX25519PrekeyId,
            signedX25519PrekeyPublic,
            signedX25519PrekeySignature,
            oneTimeX25519PrekeyId,
            oneTimeX25519PrekeyPublic,
            mlKemPrekeyId,
            mlKem768EncapsulationKey,
            mlKemKind,
            reuseLimit,
            mlKemPrekeySignature,
            bundleSignature);

        _networkId = networkId.ToArray();
        _responderAccountId = responderAccountId.ToArray();
        _responderDeviceId = responderDeviceId.ToArray();
        ResponderDeviceGeneration = responderDeviceGeneration;
        _responderDpd1Ref = responderDpd1Ref.ToArray();
        DeviceDirectoryGeneration = deviceDirectoryGeneration;
        _deviceDirectoryHeadHash = deviceDirectoryHeadHash.ToArray();
        PrekeyServiceGeneration = prekeyServiceGeneration;
        InventoryEpoch = inventoryEpoch;
        _bundleId = bundleId.ToArray();
        PolicyGeneration = policyGeneration;
        NotBefore = notBefore;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        _deviceAgreementPublicKey = deviceAgreementPublicKey.ToArray();
        _signedX25519PrekeyId = signedX25519PrekeyId.ToArray();
        _signedX25519PrekeyPublic = signedX25519PrekeyPublic.ToArray();
        _signedX25519PrekeySignature = signedX25519PrekeySignature.ToArray();
        _oneTimeX25519PrekeyId = oneTimeX25519PrekeyId.ToArray();
        _oneTimeX25519PrekeyPublic = oneTimeX25519PrekeyPublic.ToArray();
        _mlKemPrekeyId = mlKemPrekeyId.ToArray();
        _mlKem768EncapsulationKey = mlKem768EncapsulationKey.ToArray();
        MlKemKind = mlKemKind;
        ReuseLimit = reuseLimit;
        _mlKemPrekeySignature = mlKemPrekeySignature.ToArray();
        _bundleSignature = bundleSignature.ToArray();
    }

    public ReadOnlyMemory<byte> NetworkId => MessagingWireOwned.PublicCopy(_networkId);
    public ReadOnlyMemory<byte> ResponderAccountId => MessagingWireOwned.PublicCopy(_responderAccountId);
    public ReadOnlyMemory<byte> ResponderDeviceId => MessagingWireOwned.PublicCopy(_responderDeviceId);
    public ulong ResponderDeviceGeneration { get; }
    public ReadOnlyMemory<byte> ResponderDpd1Ref => MessagingWireOwned.PublicCopy(_responderDpd1Ref);
    public ulong DeviceDirectoryGeneration { get; }
    public ReadOnlyMemory<byte> DeviceDirectoryHeadHash => MessagingWireOwned.PublicCopy(_deviceDirectoryHeadHash);
    public ulong PrekeyServiceGeneration { get; }
    public ulong InventoryEpoch { get; }
    public ReadOnlyMemory<byte> BundleId => MessagingWireOwned.PublicCopy(_bundleId);
    public ulong PolicyGeneration { get; }
    public ulong NotBefore { get; }
    public ulong IssuedAt { get; }
    public ulong ExpiresAt { get; }
    public ReadOnlyMemory<byte> DeviceAgreementPublicKey => MessagingWireOwned.PublicCopy(_deviceAgreementPublicKey);
    public ReadOnlyMemory<byte> SignedX25519PrekeyId => MessagingWireOwned.PublicCopy(_signedX25519PrekeyId);
    public ReadOnlyMemory<byte> SignedX25519PrekeyPublic => MessagingWireOwned.PublicCopy(_signedX25519PrekeyPublic);
    public ReadOnlyMemory<byte> SignedX25519PrekeySignature => MessagingWireOwned.PublicCopy(_signedX25519PrekeySignature);
    public ReadOnlyMemory<byte> OneTimeX25519PrekeyId => MessagingWireOwned.PublicCopy(_oneTimeX25519PrekeyId);
    public ReadOnlyMemory<byte> OneTimeX25519PrekeyPublic => MessagingWireOwned.PublicCopy(_oneTimeX25519PrekeyPublic);
    public ReadOnlyMemory<byte> MlKemPrekeyId => MessagingWireOwned.PublicCopy(_mlKemPrekeyId);
    public ReadOnlyMemory<byte> MlKem768EncapsulationKey => MessagingWireOwned.PublicCopy(_mlKem768EncapsulationKey);
    public Dpk2PrekeyKind MlKemKind { get; }
    public ushort ReuseLimit { get; }
    public ReadOnlyMemory<byte> MlKemPrekeySignature => MessagingWireOwned.PublicCopy(_mlKemPrekeySignature);
    public ReadOnlyMemory<byte> BundleSignature => MessagingWireOwned.PublicCopy(_bundleSignature);

    internal ReadOnlySpan<byte> NetworkIdSpan => _networkId;
    internal ReadOnlySpan<byte> ResponderAccountIdSpan => _responderAccountId;
    internal ReadOnlySpan<byte> ResponderDeviceIdSpan => _responderDeviceId;
    internal ReadOnlySpan<byte> ResponderDpd1RefSpan => _responderDpd1Ref;
    internal ReadOnlySpan<byte> DeviceDirectoryHeadHashSpan => _deviceDirectoryHeadHash;
    internal ReadOnlySpan<byte> BundleIdSpan => _bundleId;
    internal ReadOnlySpan<byte> DeviceAgreementPublicKeySpan => _deviceAgreementPublicKey;
    internal ReadOnlySpan<byte> SignedX25519PrekeyIdSpan => _signedX25519PrekeyId;
    internal ReadOnlySpan<byte> SignedX25519PrekeyPublicSpan => _signedX25519PrekeyPublic;
    internal ReadOnlySpan<byte> SignedX25519PrekeySignatureSpan => _signedX25519PrekeySignature;
    internal ReadOnlySpan<byte> OneTimeX25519PrekeyIdSpan => _oneTimeX25519PrekeyId;
    internal ReadOnlySpan<byte> OneTimeX25519PrekeyPublicSpan => _oneTimeX25519PrekeyPublic;
    internal ReadOnlySpan<byte> MlKemPrekeyIdSpan => _mlKemPrekeyId;
    internal ReadOnlySpan<byte> MlKem768EncapsulationKeySpan => _mlKem768EncapsulationKey;
    internal ReadOnlySpan<byte> MlKemPrekeySignatureSpan => _mlKemPrekeySignature;
    internal ReadOnlySpan<byte> BundleSignatureSpan => _bundleSignature;

    private static void Validate(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> responderAccountId,
        ReadOnlySpan<byte> responderDeviceId,
        ulong responderDeviceGeneration,
        ReadOnlySpan<byte> responderDpd1Ref,
        ulong deviceDirectoryGeneration,
        ReadOnlySpan<byte> deviceDirectoryHeadHash,
        ulong prekeyServiceGeneration,
        ulong inventoryEpoch,
        ReadOnlySpan<byte> bundleId,
        ulong policyGeneration,
        ulong notBefore,
        ulong issuedAt,
        ulong expiresAt,
        ReadOnlySpan<byte> deviceAgreementPublicKey,
        ReadOnlySpan<byte> signedX25519PrekeyId,
        ReadOnlySpan<byte> signedX25519PrekeyPublic,
        ReadOnlySpan<byte> signedX25519PrekeySignature,
        ReadOnlySpan<byte> oneTimeX25519PrekeyId,
        ReadOnlySpan<byte> oneTimeX25519PrekeyPublic,
        ReadOnlySpan<byte> mlKemPrekeyId,
        ReadOnlySpan<byte> mlKem768EncapsulationKey,
        Dpk2PrekeyKind mlKemKind,
        ushort reuseLimit,
        ReadOnlySpan<byte> mlKemPrekeySignature,
        ReadOnlySpan<byte> bundleSignature)
    {
        NonZeroExact(networkId, 16, nameof(networkId));
        NonZeroExact(responderAccountId, 32, nameof(responderAccountId));
        NonZeroExact(responderDeviceId, 32, nameof(responderDeviceId));
        Generation(responderDeviceGeneration, nameof(responderDeviceGeneration));
        Exact(responderDpd1Ref, 38, nameof(responderDpd1Ref));
        Generation(deviceDirectoryGeneration, nameof(deviceDirectoryGeneration));
        NonZeroExact(deviceDirectoryHeadHash, 32, nameof(deviceDirectoryHeadHash));
        Generation(prekeyServiceGeneration, nameof(prekeyServiceGeneration));
        Generation(inventoryEpoch, nameof(inventoryEpoch));
        NonZeroExact(bundleId, 32, nameof(bundleId));
        Generation(policyGeneration, nameof(policyGeneration));
        NonZeroExact(deviceAgreementPublicKey, 32, nameof(deviceAgreementPublicKey));
        NonZeroExact(signedX25519PrekeyId, 32, nameof(signedX25519PrekeyId));
        NonZeroExact(signedX25519PrekeyPublic, 32, nameof(signedX25519PrekeyPublic));
        Exact(signedX25519PrekeySignature, 64, nameof(signedX25519PrekeySignature));
        NonZeroExact(mlKemPrekeyId, 32, nameof(mlKemPrekeyId));
        NonZeroExact(mlKem768EncapsulationKey, 1184, nameof(mlKem768EncapsulationKey));
        Exact(mlKemPrekeySignature, 64, nameof(mlKemPrekeySignature));
        Exact(bundleSignature, 64, nameof(bundleSignature));

        if (issuedAt > notBefore || notBefore >= expiresAt || expiresAt - notBefore > 2_592_000)
            throw Semantic(MessagingWireRejection.InvalidTimeRange, "The DPK2 validity interval is not canonical.");

        switch (mlKemKind)
        {
            case Dpk2PrekeyKind.OneTime:
                NonZeroExact(oneTimeX25519PrekeyId, 32, nameof(oneTimeX25519PrekeyId));
                NonZeroExact(oneTimeX25519PrekeyPublic, 32, nameof(oneTimeX25519PrekeyPublic));
                if (reuseLimit != 0)
                    throw Semantic(MessagingWireRejection.CrossFieldMismatch, "A one-time offering must have reuseLimit zero.");
                break;
            case Dpk2PrekeyKind.LastResort:
                Exact(oneTimeX25519PrekeyId, 0, nameof(oneTimeX25519PrekeyId));
                Exact(oneTimeX25519PrekeyPublic, 0, nameof(oneTimeX25519PrekeyPublic));
                if (reuseLimit is < 1 or > 64)
                    throw Semantic(MessagingWireRejection.InvalidCounter, "A last-resort reuseLimit must be 1..64.");
                break;
            default:
                throw Semantic(MessagingWireRejection.InvalidEnum, "The ML-KEM prekey kind is unknown.");
        }
    }

    private static void Exact(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
    }

    private static void NonZeroExact(ReadOnlySpan<byte> value, int length, string name)
    {
        Exact(value, length, name);
        if (MessagingWireFraming.IsZero(value))
            throw new ArgumentException($"{name} cannot be all-zero.", name);
    }

    private static void Generation(ulong value, string name)
    {
        if (value == 0)
            throw new ArgumentOutOfRangeException(name, "A generation or epoch must be nonzero.");
    }

    private static MessagingWireFormatException Semantic(MessagingWireRejection rejection, string message) =>
        MessagingWireFraming.Error(MessagingWirePrevalidationStage.SemanticFields, rejection, message);
}

public static class Dpk2Codec
{
    public const int LastResortTotalBytes = 1973;
    public const int OneTimeTotalBytes = 2037;
    private const ushort FieldCount = 26;

    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.DPK2;
    public static ReadOnlySpan<int> AllowedTotalSizes => [LastResortTotalBytes, OneTimeTotalBytes];

    public static byte[] Encode(Dpk2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var encoded = new byte[record.MlKemKind == Dpk2PrekeyKind.OneTime
            ? OneTimeTotalBytes
            : LastResortTotalBytes];
        var writer = new MessagingWireWriter(encoded, Magic, FieldCount);
        WriteFields1To17(ref writer, record);
        writer.Write(18, record.SignedX25519PrekeySignatureSpan);
        writer.Write(19, record.OneTimeX25519PrekeyIdSpan);
        writer.Write(20, record.OneTimeX25519PrekeyPublicSpan);
        WriteFields21To24(ref writer, record);
        writer.Write(25, record.MlKemPrekeySignatureSpan);
        writer.Write(26, record.BundleSignatureSpan);
        writer.Complete();
        return encoded;
    }

    public static Dpk2Record Decode(ReadOnlySpan<byte> encoded)
    {
        Span<MessagingWireFieldSlice> fields = stackalloc MessagingWireFieldSlice[FieldCount];
        MessagingWireFraming.Preflight(encoded, Magic, FieldCount, AllowedTotalSizes, fields);
        ValidateLengths(fields);
        _ = ValidateSemanticFields(encoded, fields);

        var owned = encoded.ToArray();
        MessagingWireFraming.Preflight(owned, Magic, FieldCount, AllowedTotalSizes, fields);
        ValidateLengths(fields);
        var semantic = ValidateSemanticFields(owned, fields);
        return new Dpk2Record(
            Value(owned, fields, 1),
            Value(owned, fields, 2),
            Value(owned, fields, 3),
            U64(owned, fields, 4),
            Value(owned, fields, 5),
            U64(owned, fields, 6),
            Value(owned, fields, 7),
            U64(owned, fields, 8),
            U64(owned, fields, 9),
            Value(owned, fields, 10),
            U64(owned, fields, 11),
            semantic.NotBefore,
            semantic.IssuedAt,
            semantic.ExpiresAt,
            Value(owned, fields, 15),
            Value(owned, fields, 16),
            Value(owned, fields, 17),
            Value(owned, fields, 18),
            Value(owned, fields, 19),
            Value(owned, fields, 20),
            Value(owned, fields, 21),
            Value(owned, fields, 22),
            semantic.Kind,
            semantic.ReuseLimit,
            Value(owned, fields, 25),
            Value(owned, fields, 26));
    }

    private static (Dpk2PrekeyKind Kind, ushort ReuseLimit, ulong NotBefore, ulong IssuedAt, ulong ExpiresAt)
        ValidateSemanticFields(
            ReadOnlySpan<byte> encoded,
            ReadOnlySpan<MessagingWireFieldSlice> fields)
    {
        MessagingWireFraming.RequireNonZero(Value(encoded, fields, 1), "networkId");
        var kindValue = MessagingWireFraming.Value(encoded, fields, 23)[0];
        if (kindValue is not ((byte)Dpk2PrekeyKind.OneTime) and not ((byte)Dpk2PrekeyKind.LastResort))
            throw Semantic(MessagingWireRejection.InvalidEnum, "The DPK2 ML-KEM kind is unknown.");
        var kind = (Dpk2PrekeyKind)kindValue;
        var reuseLimit = BinaryPrimitives.ReadUInt16BigEndian(MessagingWireFraming.Value(encoded, fields, 24));

        RequireNonZero(encoded, fields, 2, "responderAccountId");
        RequireNonZero(encoded, fields, 3, "responderDeviceId");
        RequireGeneration(encoded, fields, 4, "responderDeviceGeneration");
        RequireGeneration(encoded, fields, 6, "deviceDirectoryGeneration");
        RequireNonZero(encoded, fields, 7, "deviceDirectoryHeadHash");
        RequireGeneration(encoded, fields, 8, "prekeyServiceGeneration");
        RequireGeneration(encoded, fields, 9, "inventoryEpoch");
        RequireNonZero(encoded, fields, 10, "bundleId");
        RequireGeneration(encoded, fields, 11, "policyGeneration");
        RequireNonZero(encoded, fields, 15, "deviceAgreementPublicKey");
        RequireNonZero(encoded, fields, 16, "signedX25519PrekeyId");
        RequireNonZero(encoded, fields, 17, "signedX25519PrekeyPublic");
        RequireNonZero(encoded, fields, 21, "mlKemPrekeyId");
        RequireNonZero(encoded, fields, 22, "mlKem768EncapsulationKey");

        var notBefore = U64(encoded, fields, 12);
        var issuedAt = U64(encoded, fields, 13);
        var expiresAt = U64(encoded, fields, 14);
        if (issuedAt > notBefore || notBefore >= expiresAt || expiresAt - notBefore > 2_592_000)
            throw Semantic(MessagingWireRejection.InvalidTimeRange, "The DPK2 validity interval is not canonical.");

        if (kind == Dpk2PrekeyKind.OneTime)
        {
            if (encoded.Length != OneTimeTotalBytes || fields[18].Length != 32 || fields[19].Length != 32 || reuseLimit != 0)
                throw Semantic(MessagingWireRejection.CrossFieldMismatch, "The one-time DPK2 fields do not match their exact kind.");
            RequireNonZero(encoded, fields, 19, "oneTimeX25519PrekeyId");
            RequireNonZero(encoded, fields, 20, "oneTimeX25519PrekeyPublic");
        }
        else if (encoded.Length != LastResortTotalBytes || fields[18].Length != 0 || fields[19].Length != 0 || reuseLimit is < 1 or > 64)
        {
            throw Semantic(MessagingWireRejection.CrossFieldMismatch, "The last-resort DPK2 fields do not match their exact kind.");
        }

        return (kind, reuseLimit, notBefore, issuedAt, expiresAt);
    }

    public static byte[] GetX25519SignedPrekeyProjection(Dpk2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var encoded = new byte[ProjectionLength(record, 17, false, false)];
        var writer = new MessagingWireWriter(encoded, Magic, 17);
        WriteFields1To17(ref writer, record);
        writer.Complete();
        return encoded;
    }

    public static byte[] GetMlKemPrekeyProjection(Dpk2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var encoded = new byte[ProjectionLength(record, 21, true, false)];
        var writer = new MessagingWireWriter(encoded, Magic, 21);
        WriteFields1To17(ref writer, record);
        WriteFields21To24(ref writer, record);
        writer.Complete();
        return encoded;
    }

    public static byte[] GetUnsignedBundleProjection(Dpk2Record record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var full = Encode(record);
        var output = new byte[full.Length - MessagingWireFraming.FieldHeaderLength - 64];
        full.AsSpan(0, output.Length).CopyTo(output);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8, 2), 25);
        return output;
    }

    private static int ProjectionLength(Dpk2Record record, int count, bool includeMlKem, bool unused)
    {
        _ = count;
        _ = unused;
        var prefixValueBytes = 342;
        var fieldCount = includeMlKem ? 21 : 17;
        var valueBytes = prefixValueBytes;
        if (includeMlKem)
            valueBytes += 32 + 1184 + 1 + 2;
        return MessagingWireFraming.RecordHeaderLength + fieldCount * MessagingWireFraming.FieldHeaderLength + valueBytes;
    }

    private static void WriteFields1To17(ref MessagingWireWriter writer, Dpk2Record record)
    {
        Span<byte> u64 = stackalloc byte[8];
        writer.Write(1, record.NetworkIdSpan);
        writer.Write(2, record.ResponderAccountIdSpan);
        writer.Write(3, record.ResponderDeviceIdSpan);
        WriteU64(ref writer, 4, record.ResponderDeviceGeneration, u64);
        writer.Write(5, record.ResponderDpd1RefSpan);
        WriteU64(ref writer, 6, record.DeviceDirectoryGeneration, u64);
        writer.Write(7, record.DeviceDirectoryHeadHashSpan);
        WriteU64(ref writer, 8, record.PrekeyServiceGeneration, u64);
        WriteU64(ref writer, 9, record.InventoryEpoch, u64);
        writer.Write(10, record.BundleIdSpan);
        WriteU64(ref writer, 11, record.PolicyGeneration, u64);
        WriteU64(ref writer, 12, record.NotBefore, u64);
        WriteU64(ref writer, 13, record.IssuedAt, u64);
        WriteU64(ref writer, 14, record.ExpiresAt, u64);
        writer.Write(15, record.DeviceAgreementPublicKeySpan);
        writer.Write(16, record.SignedX25519PrekeyIdSpan);
        writer.Write(17, record.SignedX25519PrekeyPublicSpan);
    }

    private static void WriteFields21To24(ref MessagingWireWriter writer, Dpk2Record record)
    {
        Span<byte> reuse = stackalloc byte[2];
        writer.Write(21, record.MlKemPrekeyIdSpan);
        writer.Write(22, record.MlKem768EncapsulationKeySpan);
        writer.Write(23, [(byte)record.MlKemKind]);
        BinaryPrimitives.WriteUInt16BigEndian(reuse, record.ReuseLimit);
        writer.Write(24, reuse);
    }

    private static void WriteU64(ref MessagingWireWriter writer, ushort tag, ulong value, scoped Span<byte> buffer)
    {
        BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
        writer.Write(tag, buffer);
    }

    private static void ValidateLengths(ReadOnlySpan<MessagingWireFieldSlice> fields)
    {
        ReadOnlySpan<int> exact = [16, 32, 32, 8, 38, 8, 32, 8, 8, 32, 8, 8, 8, 8, 32, 32, 32, 64];
        for (var tag = 1; tag <= exact.Length; tag++)
            MessagingWireFraming.RequireLength(fields, tag, exact[tag - 1]);
        MessagingWireFraming.RequireLength(fields, 19, 0, 32);
        MessagingWireFraming.RequireLength(fields, 20, 0, 32);
        MessagingWireFraming.RequireLength(fields, 21, 32);
        MessagingWireFraming.RequireLength(fields, 22, 1184);
        MessagingWireFraming.RequireLength(fields, 23, 1);
        MessagingWireFraming.RequireLength(fields, 24, 2);
        MessagingWireFraming.RequireLength(fields, 25, 64);
        MessagingWireFraming.RequireLength(fields, 26, 64);
    }

    private static ReadOnlySpan<byte> Value(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields, int tag) =>
        MessagingWireFraming.Value(encoded, fields, tag);

    private static ulong U64(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields, int tag) =>
        BinaryPrimitives.ReadUInt64BigEndian(Value(encoded, fields, tag));

    private static void RequireGeneration(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields, int tag, string name)
    {
        if (U64(encoded, fields, tag) == 0)
            throw Semantic(MessagingWireRejection.InvalidGeneration, $"{name} must be nonzero.");
    }

    private static void RequireNonZero(ReadOnlySpan<byte> encoded, ReadOnlySpan<MessagingWireFieldSlice> fields, int tag, string name) =>
        MessagingWireFraming.RequireNonZero(Value(encoded, fields, tag), name);

    private static MessagingWireFormatException Semantic(MessagingWireRejection rejection, string message) =>
        MessagingWireFraming.Error(MessagingWirePrevalidationStage.SemanticFields, rejection, message);
}
