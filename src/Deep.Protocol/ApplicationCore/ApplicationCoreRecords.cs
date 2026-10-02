using System.Buffers.Binary;
using Deep.Protocol.Identity;

namespace Deep.Protocol.ApplicationCore;

public abstract class ParsedApplicationCoreRecord
{
    private readonly byte[] _canonical;
    private readonly byte[] _recordHash;

    internal ParsedApplicationCoreRecord(string magic, byte[] canonical, int hashGeneration = 1)
    {
        Magic = magic;
        _canonical = canonical;
        _recordHash = ApplicationCoreFormat.Sha256Domain(
            $"Deep/Application/V{hashGeneration}/record-hash/{magic}", _canonical);
    }

    public string Magic { get; }
    public ReadOnlyMemory<byte> CanonicalBytes { get { RequireReadable(); return _canonical.ToArray(); } }
    public ReadOnlyMemory<byte> RecordHash { get { RequireReadable(); return _recordHash.ToArray(); } }
    internal ReadOnlySpan<byte> CanonicalSpan { get { RequireReadable(); return _canonical; } }
    internal ReadOnlySpan<byte> RecordHashSpan { get { RequireReadable(); return _recordHash; } }
    internal virtual void RequireReadable() { }
    internal void EraseOwnedSecretRecord()
    {
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(_canonical);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(_recordHash);
    }
}

public sealed class ApplicationArtifactReference
{
    private readonly byte[] _hash;

    internal ApplicationArtifactReference(ushort typeCode, uint canonicalLength, ReadOnlySpan<byte> hash)
    {
        TypeCode = typeCode;
        CanonicalLength = canonicalLength;
        _hash = hash.ToArray();
    }

    public ushort TypeCode { get; }
    public uint CanonicalLength { get; }
    public ReadOnlyMemory<byte> CanonicalHash => _hash.ToArray();

    public ReadOnlyMemory<byte> CanonicalBytes
    {
        get
        {
            var value = new byte[38];
            BinaryPrimitives.WriteUInt16BigEndian(value, TypeCode);
            BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(2, 4), CanonicalLength);
            _hash.CopyTo(value, 6);
            return value;
        }
    }

    internal ReadOnlySpan<byte> HashSpan => _hash;
}

public sealed class DeviceDirectoryEntry
{
    private readonly byte[] _deviceId;

    public DeviceDirectoryEntry(ReadOnlySpan<byte> deviceId, ApplicationArtifactReference dpd1Reference)
    {
        if (deviceId.Length != 32 || ApplicationCoreFormat.IsZero(deviceId))
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.ZeroForbidden, "A device ID must be a nonzero 32-byte value.");
        ArgumentNullException.ThrowIfNull(dpd1Reference);
        if (dpd1Reference.TypeCode != 2 || dpd1Reference.CanonicalLength != 776)
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.SemanticFields,
                ApplicationCoreRejection.InvalidReference, "A directory entry must reference exact DPD1 bytes.");
        _deviceId = deviceId.ToArray();
        Dpd1Reference = dpd1Reference;
    }

    public ReadOnlyMemory<byte> DeviceId => _deviceId.ToArray();
    public ApplicationArtifactReference Dpd1Reference { get; }
    internal ReadOnlySpan<byte> DeviceIdSpan => _deviceId;
}

public sealed class ParsedDmd1 : ParsedApplicationCoreRecord
{
    private readonly byte[] _network;
    private readonly byte[] _account;
    private readonly byte[] _predecessor;
    private readonly DeviceDirectoryEntry[] _entries;
    private readonly byte[] _signature;
    private readonly byte[] _unsigned;

    internal ParsedDmd1(
        byte[] canonical,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account,
        ulong accountGeneration,
        ApplicationArtifactReference dpaReference,
        ApplicationArtifactReference drsReference,
        ulong directoryGeneration,
        ReadOnlySpan<byte> predecessor,
        DeviceDirectoryEntry[] entries,
        ulong issuedAtUnixSeconds,
        ReadOnlySpan<byte> signature,
        byte[] unsigned)
        : base(ProtocolMagic.DMD1, canonical)
    {
        _network = network.ToArray();
        _account = account.ToArray();
        AccountGeneration = accountGeneration;
        Dpa1Reference = dpaReference;
        Drs1Reference = drsReference;
        DirectoryGeneration = directoryGeneration;
        _predecessor = predecessor.ToArray();
        _entries = entries.ToArray();
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        _signature = signature.ToArray();
        _unsigned = unsigned.ToArray();
    }

    public ReadOnlyMemory<byte> NetworkId => _network.ToArray();
    public ReadOnlyMemory<byte> DeepAccountId => _account.ToArray();
    public ulong AccountGeneration { get; }
    public ApplicationArtifactReference Dpa1Reference { get; }
    public ApplicationArtifactReference Drs1Reference { get; }
    public ulong DirectoryGeneration { get; }
    public ReadOnlyMemory<byte> PredecessorDmd1Hash => _predecessor.ToArray();
    public IReadOnlyList<DeviceDirectoryEntry> ActiveDevices => Array.AsReadOnly(_entries.ToArray());
    public ushort MinimumMessagingSuite => ApplicationCoreFormat.Suite;
    public ulong IssuedAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> DeviceIssuerSignature => _signature.ToArray();
    public ReadOnlyMemory<byte> UnsignedCanonicalBytes => _unsigned.ToArray();
    public ReadOnlyMemory<byte> SignatureInput => ApplicationCoreFormat.SignatureInput(
        "Deep/Application/V1/device-directory", _unsigned);
}

public sealed class ParsedDao1 : ParsedApplicationCoreRecord
{
    private readonly byte[] _network;
    private readonly byte[] _sealingKeyId;
    private readonly byte[] _operationId;
    private readonly byte[] _ephemeralKey;
    private readonly byte[] _nonce;
    private readonly byte[] _sealedRecord;
    private readonly byte[] _header;

    internal ParsedDao1(
        byte[] canonical,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> sealingKeyId,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> ephemeralKey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> sealedRecord,
        byte[] header)
        : base(ProtocolMagic.DAO1, canonical)
    {
        _network = network.ToArray();
        _sealingKeyId = sealingKeyId.ToArray();
        _operationId = operationId.ToArray();
        _ephemeralKey = ephemeralKey.ToArray();
        _nonce = nonce.ToArray();
        _sealedRecord = sealedRecord.ToArray();
        _header = header.ToArray();
    }

    public ReadOnlyMemory<byte> NetworkId => _network.ToArray();
    public ReadOnlyMemory<byte> SealingKeyId => _sealingKeyId.ToArray();
    public ReadOnlyMemory<byte> DepositOperationId => _operationId.ToArray();
    public ReadOnlyMemory<byte> EphemeralX25519PublicKey => _ephemeralKey.ToArray();
    public ReadOnlyMemory<byte> Nonce => _nonce.ToArray();
    public ReadOnlyMemory<byte> SealedRecord => _sealedRecord.ToArray();
    public ReadOnlyMemory<byte> AeadHeader => _header.ToArray();
}
