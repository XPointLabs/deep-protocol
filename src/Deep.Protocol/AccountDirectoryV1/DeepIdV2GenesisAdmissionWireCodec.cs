using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class DeepIdV2GenesisAdmissionWireRequest
{
    private readonly byte[] operationId;

    public DeepIdV2GenesisAdmissionWireRequest(ReadOnlySpan<byte> operationId32,
        DeepIdV2GenesisAdmissionRequest admission)
    {
        this.operationId = Required(operationId32, 32, nameof(operationId32));
        Admission = admission ?? throw new ArgumentNullException(nameof(admission));
    }

    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    public DeepIdV2GenesisAdmissionRequest Admission { get; }

    internal static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.",
                name);
        return value.ToArray();
    }
}

public sealed class DeepIdV2GenesisAdmissionReceipt
{
    private readonly byte[] operationId;
    private readonly byte[] leafKey;
    private readonly byte[] head;

    public DeepIdV2GenesisAdmissionReceipt(ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> directoryLeafKey32, ReadOnlySpan<byte> exactAdh1)
    {
        operationId = DeepIdV2GenesisAdmissionWireRequest.Required(operationId32,
            32, nameof(operationId32));
        leafKey = DeepIdV2GenesisAdmissionWireRequest.Required(directoryLeafKey32,
            32, nameof(directoryLeafKey32));
        if (exactAdh1.IsEmpty || exactAdh1.Length > 65_535)
            throw new ArgumentOutOfRangeException(nameof(exactAdh1));
        var parsed = AccountDirectoryAdh1Codec.Decode(exactAdh1);
        if (parsed.MinimumReader < 2)
            throw new ArgumentException("DID2 admission receipt requires ADH1 reader floor 2.",
                nameof(exactAdh1));
        head = exactAdh1.ToArray();
    }

    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    public ReadOnlyMemory<byte> DirectoryLeafKey => leafKey.ToArray();
    public ReadOnlyMemory<byte> ExactAdh1 => head.ToArray();
}

/// <summary>
/// Candidate DGA1/DGR1 V2 transport envelope. Decoding yields untrusted public
/// artifacts, never an admitted account or a verified witness head.
/// </summary>
public static class DeepIdV2GenesisAdmissionWireCodec
{
    public const string RequestMediaType =
        "application/vnd.deep.account-directory-genesis-admission.v2";
    public const string ResponseMediaType =
        "application/vnd.deep.account-directory-genesis-receipt.v2";
    public const ushort Version = 2;
    public const int MaximumRequestLength = 256 * 1024;
    public const int MaximumResponseLength = 128 * 1024;
    private static ReadOnlySpan<byte> RequestMagic => ProtocolMagicBytes.DGA1;
    private static ReadOnlySpan<byte> ResponseMagic => ProtocolMagicBytes.DGR1;

    public static byte[] EncodeRequest(DeepIdV2GenesisAdmissionWireRequest value)
    {
        ArgumentNullException.ThrowIfNull(value);
        using var stream = new MemoryStream();
        WriteHeader(stream, RequestMagic);
        stream.Write(value.OperationId.Span);
        var request = value.Admission;
        WriteArtifact(stream, request.ExactDpa1.Span);
        WriteArtifact(stream, request.ExactDrs1.Span);
        stream.WriteByte(checked((byte)request.ExactDpd1.Count));
        foreach (var device in request.ExactDpd1)
            WriteArtifact(stream, device.Span);
        WriteArtifact(stream, request.ExactDid2.Span);
        WriteArtifact(stream, request.ExactDab2.Span);
        WriteArtifact(stream, request.ExactDmd1.Span);
        WriteArtifact(stream, request.ExactAdc1V2.Span);
        WriteU16(stream, checked((ushort)request.RevokedDcaAuthorizationIds.Count));
        foreach (var id in request.RevokedDcaAuthorizationIds)
            stream.Write(id.Span);
        return Finish(stream, MaximumRequestLength);
    }

    public static DeepIdV2GenesisAdmissionWireRequest DecodeRequest(
        ReadOnlySpan<byte> encoded)
    {
        var reader = new Reader(encoded, RequestMagic, MaximumRequestLength);
        var operationId = reader.ReadFixed(32);
        var dpa = reader.ReadArtifact(644, exactLength: true);
        var drs = reader.ReadArtifact(16_384);
        var deviceCount = reader.ReadByte();
        if (deviceCount is < 1 or > 5)
            throw new FormatException("DGA1 V2 DPD1 count is outside its bound.");
        var devices = new ReadOnlyMemory<byte>[deviceCount];
        for (var index = 0; index < devices.Length; index++)
            devices[index] = reader.ReadArtifact(776, exactLength: true);
        var did = reader.ReadArtifact(DeepIdV2Codec.Did2Length,
            exactLength: true);
        var dab = reader.ReadArtifact(DeepIdV2Codec.Dab2Length,
            exactLength: true);
        var dmd = reader.ReadArtifact(57_344);
        var adc = reader.ReadArtifact(
            DeepIdV2AccountDirectoryCodec.CanonicalLength, exactLength: true);
        var revokedCount = reader.ReadU16();
        if (revokedCount > 4096)
            throw new FormatException("DGA1 V2 revoked authorization count exceeds 4096.");
        var revoked = new ReadOnlyMemory<byte>[revokedCount];
        for (var index = 0; index < revoked.Length; index++)
            revoked[index] = reader.ReadFixed(32);
        reader.EnsureComplete();
        try
        {
            return new DeepIdV2GenesisAdmissionWireRequest(operationId,
                new DeepIdV2GenesisAdmissionRequest(dpa, drs, devices, did, dab,
                    dmd, adc, revoked));
        }
        catch (ArgumentException exception)
        {
            throw new FormatException("DGA1 V2 request fields are invalid.", exception);
        }
    }

    public static byte[] EncodeReceipt(DeepIdV2GenesisAdmissionReceipt value)
    {
        ArgumentNullException.ThrowIfNull(value);
        using var stream = new MemoryStream();
        WriteHeader(stream, ResponseMagic);
        stream.Write(value.OperationId.Span);
        stream.Write(value.DirectoryLeafKey.Span);
        WriteArtifact(stream, value.ExactAdh1.Span);
        return Finish(stream, MaximumResponseLength);
    }

    public static DeepIdV2GenesisAdmissionReceipt DecodeReceipt(
        ReadOnlySpan<byte> encoded)
    {
        var reader = new Reader(encoded, ResponseMagic, MaximumResponseLength);
        var operationId = reader.ReadFixed(32);
        var leaf = reader.ReadFixed(32);
        var head = reader.ReadArtifact(65_535);
        reader.EnsureComplete();
        try { return new DeepIdV2GenesisAdmissionReceipt(operationId, leaf, head); }
        catch (ArgumentException exception)
        { throw new FormatException("DGR1 V2 receipt fields are invalid.", exception); }
    }

    private static void WriteHeader(Stream stream, ReadOnlySpan<byte> magic)
    {
        stream.Write(magic);
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(header, Version);
        stream.Write(header);
    }

    private static byte[] Finish(MemoryStream stream, int maximum)
    {
        if (stream.Length > maximum)
            throw new ArgumentOutOfRangeException(nameof(stream));
        var bytes = stream.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), checked((uint)bytes.Length));
        return bytes;
    }

    private static void WriteArtifact(Stream stream, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        stream.Write(length);
        stream.Write(value);
    }

    private static void WriteU16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> encoded;
        private int offset;

        internal Reader(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> magic,
            int maximum)
        {
            if (encoded.Length < 12 || encoded.Length > maximum ||
                !encoded[..4].SequenceEqual(magic) ||
                BinaryPrimitives.ReadUInt16BigEndian(encoded[4..]) != Version ||
                BinaryPrimitives.ReadUInt16BigEndian(encoded[6..]) != 0 ||
                BinaryPrimitives.ReadUInt32BigEndian(encoded[8..]) != encoded.Length)
                throw new FormatException("DGA1/DGR1 V2 envelope header is invalid.");
            this.encoded = encoded;
            offset = 12;
        }

        internal byte ReadByte() => Read(1)[0];
        internal ushort ReadU16() => BinaryPrimitives.ReadUInt16BigEndian(Read(2));
        internal byte[] ReadFixed(int length) => Read(length).ToArray();

        internal byte[] ReadArtifact(int maximum, bool exactLength = false)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(Read(4));
            if (length == 0 || length > maximum ||
                (exactLength && length != maximum))
                throw new FormatException("DGA1/DGR1 V2 artifact length is invalid.");
            return Read(checked((int)length)).ToArray();
        }

        internal void EnsureComplete()
        {
            if (offset != encoded.Length)
                throw new FormatException("DGA1/DGR1 V2 contains trailing bytes.");
        }

        private ReadOnlySpan<byte> Read(int length)
        {
            if (length < 0 || offset > encoded.Length - length)
                throw new FormatException("DGA1/DGR1 V2 envelope is truncated.");
            var result = encoded.Slice(offset, length);
            offset += length;
            return result;
        }
    }
}
