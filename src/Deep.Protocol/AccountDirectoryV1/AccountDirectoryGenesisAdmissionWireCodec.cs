using System.Buffers.Binary;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryGenesisAdmissionWireRequest
{
    private readonly byte[] operationId;

    public AccountDirectoryGenesisAdmissionWireRequest(
        ReadOnlySpan<byte> operationId,
        AccountDirectoryGenesisAdmissionRequest admission)
    {
        if (operationId.Length != 32 || operationId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                "The admission operation ID must be exactly 32 non-zero bytes.",
                nameof(operationId));
        this.operationId = operationId.ToArray();
        Admission = admission ?? throw new ArgumentNullException(nameof(admission));
    }

    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    public AccountDirectoryGenesisAdmissionRequest Admission { get; }
}

public sealed class AccountDirectoryGenesisAdmissionReceipt
{
    private readonly byte[] operationId;
    private readonly byte[] directoryLeafKey;
    private readonly byte[] exactAdh1;

    public AccountDirectoryGenesisAdmissionReceipt(
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> directoryLeafKey,
        ReadOnlySpan<byte> exactAdh1)
    {
        operationId = Required(operationId, 32, nameof(operationId));
        this.operationId = operationId.ToArray();
        this.directoryLeafKey = Required(
            directoryLeafKey, 32, nameof(directoryLeafKey)).ToArray();
        if (exactAdh1.IsEmpty || exactAdh1.Length > 65_535)
            throw new ArgumentOutOfRangeException(nameof(exactAdh1));
        _ = AccountDirectoryAdh1Codec.Decode(exactAdh1);
        this.exactAdh1 = exactAdh1.ToArray();
    }

    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    public ReadOnlyMemory<byte> DirectoryLeafKey => directoryLeafKey.ToArray();
    public ReadOnlyMemory<byte> ExactAdh1 => exactAdh1.ToArray();

    private static ReadOnlySpan<byte> Required(
        ReadOnlySpan<byte> value,
        int length,
        string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                $"{name} must be exactly {length} non-zero bytes.", name);
        return value;
    }
}

/// <summary>
/// Bounded transport envelope for first account-directory admission. It carries
/// exact client-authored public artifacts only; decoding does not promote them
/// to verified capabilities.
/// </summary>
public static class AccountDirectoryGenesisAdmissionWireCodec
{
    public const string RequestMediaType =
        "application/vnd.deep.account-directory-genesis-admission.v1";
    public const string ResponseMediaType =
        "application/vnd.deep.account-directory-genesis-receipt.v1";
    public const int MaximumRequestLength = 128 * 1024;
    public const int MaximumResponseLength = 128 * 1024;

    private const ushort Version = 1;
    private static ReadOnlySpan<byte> RequestMagic => "DGA1"u8;
    private static ReadOnlySpan<byte> ResponseMagic => "DGR1"u8;

    public static byte[] EncodeRequest(AccountDirectoryGenesisAdmissionWireRequest value)
    {
        ArgumentNullException.ThrowIfNull(value);
        using var stream = new MemoryStream();
        WriteHeader(stream, RequestMagic, 0);
        Write(stream, value.OperationId.Span);
        var admission = value.Admission;
        WriteArtifact(stream, admission.ExactDpa1.Span);
        WriteArtifact(stream, admission.ExactDrs1.Span);
        if (admission.ExactDpd1.Count is < 1 or > 5)
            throw new ArgumentException("The DPD1 set is outside its bound.", nameof(value));
        stream.WriteByte(checked((byte)admission.ExactDpd1.Count));
        foreach (var device in admission.ExactDpd1)
            WriteArtifact(stream, device.Span);
        WriteArtifact(stream, admission.ExactDid1.Span);
        WriteArtifact(stream, admission.ExactDab1.Span);
        WriteArtifact(stream, admission.ExactDmd1.Span);
        WriteArtifact(stream, admission.ExactAdc1.Span);
        WriteU16(stream, checked((ushort)admission.RevokedDcaAuthorizationIds.Count));
        foreach (var authorizationId in admission.RevokedDcaAuthorizationIds)
            Write(stream, authorizationId.Span);
        return Finish(stream, MaximumRequestLength);
    }

    public static AccountDirectoryGenesisAdmissionWireRequest DecodeRequest(
        ReadOnlySpan<byte> encoded)
    {
        var reader = new Reader(encoded, RequestMagic, MaximumRequestLength);
        var operationId = reader.ReadFixed(32);
        var dpa = reader.ReadArtifact(16_384);
        var drs = reader.ReadArtifact(16_384);
        var deviceCount = reader.ReadByte();
        if (deviceCount is < 1 or > 5)
            throw new FormatException("The DPD1 set is outside its bound.");
        var devices = new ReadOnlyMemory<byte>[deviceCount];
        for (var index = 0; index < devices.Length; index++)
            devices[index] = reader.ReadArtifact(16_384);
        var did = reader.ReadArtifact(4_096);
        var dab = reader.ReadArtifact(16_384);
        var dmd = reader.ReadArtifact(57_344);
        var adc = reader.ReadArtifact(16_384);
        var revokedCount = reader.ReadU16();
        if (revokedCount > AccountDirectoryAdc1Verifier.MaximumRevokedDcaAuthorizationIds)
            throw new FormatException("The revoked authorization set is outside its bound.");
        var revoked = new ReadOnlyMemory<byte>[revokedCount];
        for (var index = 0; index < revoked.Length; index++)
            revoked[index] = reader.ReadFixed(32);
        reader.EnsureComplete();
        return new AccountDirectoryGenesisAdmissionWireRequest(
            operationId,
            new AccountDirectoryGenesisAdmissionRequest(
                dpa, drs, devices, did, dab, dmd, adc, revoked));
    }

    public static byte[] EncodeReceipt(AccountDirectoryGenesisAdmissionReceipt value)
    {
        ArgumentNullException.ThrowIfNull(value);
        using var stream = new MemoryStream();
        WriteHeader(stream, ResponseMagic, 0);
        Write(stream, value.OperationId.Span);
        Write(stream, value.DirectoryLeafKey.Span);
        WriteArtifact(stream, value.ExactAdh1.Span);
        return Finish(stream, MaximumResponseLength);
    }

    public static AccountDirectoryGenesisAdmissionReceipt DecodeReceipt(
        ReadOnlySpan<byte> encoded)
    {
        var reader = new Reader(encoded, ResponseMagic, MaximumResponseLength);
        var operationId = reader.ReadFixed(32);
        var leaf = reader.ReadFixed(32);
        var head = reader.ReadArtifact(65_535);
        reader.EnsureComplete();
        return new AccountDirectoryGenesisAdmissionReceipt(operationId, leaf, head);
    }

    private static void WriteHeader(Stream stream, ReadOnlySpan<byte> magic, ushort flags)
    {
        Write(stream, magic);
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(header, Version);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], flags);
        Write(stream, header);
    }

    private static byte[] Finish(MemoryStream stream, int maximum)
    {
        if (stream.Length > maximum)
            throw new ArgumentOutOfRangeException(nameof(stream));
        var result = stream.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8, 4), checked((uint)result.Length));
        return result;
    }

    private static void WriteArtifact(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteU32(stream, checked((uint)value.Length));
        Write(stream, value);
    }

    private static void WriteU16(Stream stream, ushort value)
    {
        Span<byte> encoded = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, value);
        Write(stream, encoded);
    }

    private static void WriteU32(Stream stream, uint value)
    {
        Span<byte> encoded = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(encoded, value);
        Write(stream, encoded);
    }

    private static void Write(Stream stream, ReadOnlySpan<byte> value) => stream.Write(value);

    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> value;
        private int offset;

        internal Reader(ReadOnlySpan<byte> value, ReadOnlySpan<byte> magic, int maximum)
        {
            if (value.Length < 12 || value.Length > maximum || !value[..4].SequenceEqual(magic) ||
                BinaryPrimitives.ReadUInt16BigEndian(value[4..]) != Version ||
                BinaryPrimitives.ReadUInt16BigEndian(value[6..]) != 0 ||
                BinaryPrimitives.ReadUInt32BigEndian(value[8..]) != value.Length)
                throw new FormatException("The admission envelope header is invalid.");
            this.value = value;
            offset = 12;
        }

        internal byte ReadByte() => ReadSpan(1)[0];
        internal ushort ReadU16() => BinaryPrimitives.ReadUInt16BigEndian(ReadSpan(2));
        internal byte[] ReadFixed(int length) => ReadSpan(length).ToArray();

        internal byte[] ReadArtifact(int maximum)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(ReadSpan(4));
            if (length is 0 || length > maximum || length > int.MaxValue)
                throw new FormatException("An admission artifact length is invalid.");
            return ReadSpan(checked((int)length)).ToArray();
        }

        internal void EnsureComplete()
        {
            if (offset != value.Length)
                throw new FormatException("The admission envelope has trailing bytes.");
        }

        private ReadOnlySpan<byte> ReadSpan(int length)
        {
            if (length < 0 || offset > value.Length - length)
                throw new FormatException("The admission envelope is truncated.");
            var result = value.Slice(offset, length);
            offset += length;
            return result;
        }
    }
}
