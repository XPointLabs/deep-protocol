using System.Buffers.Binary;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryAfp1FormatException(string message) : FormatException(message);

public sealed class AccountDirectoryAfp1
{
    private readonly byte[] networkId;
    private readonly byte[] sourceAdh1CoreHash;
    private readonly byte[] targetAdh1CoreHash;
    private readonly byte[][] authorityChain;
    private readonly byte[][] checkpointChain;
    private readonly byte[][] targetHeadChain;
    private readonly byte[][] membershipNodes;
    private readonly byte[] liveDtt1CoreHash;

    public AccountDirectoryAfp1(
        ReadOnlySpan<byte> networkId,
        ulong sourceAdhGeneration,
        ulong sourceTreeSize,
        ReadOnlySpan<byte> sourceAdh1CoreHash,
        ReadOnlySpan<byte> targetAdh1CoreHash,
        IReadOnlyList<ReadOnlyMemory<byte>> authorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> checkpointChain,
        IReadOnlyList<ReadOnlyMemory<byte>> targetHeadChain,
        ulong sourceLeafIndex,
        IReadOnlyList<ReadOnlyMemory<byte>> membershipNodes,
        ReadOnlySpan<byte> liveDtt1CoreHash)
    {
        this.networkId = Required(networkId, 16, nameof(networkId));
        SourceAdhGeneration = sourceAdhGeneration;
        SourceTreeSize = sourceTreeSize;
        this.sourceAdh1CoreHash = Required(sourceAdh1CoreHash, 32, nameof(sourceAdh1CoreHash));
        this.targetAdh1CoreHash = Required(targetAdh1CoreHash, 32, nameof(targetAdh1CoreHash));
        this.authorityChain = CopyAuthorities(authorityChain, this.networkId);
        this.checkpointChain = CopyCheckpoints(checkpointChain, this.networkId, this.targetAdh1CoreHash);
        this.targetHeadChain = CopyTargetHeads(
            targetHeadChain, this.checkpointChain, this.networkId, this.targetAdh1CoreHash);
        SourceLeafIndex = sourceLeafIndex;
        var first = AccountDirectoryAdf1Codec.Decode(this.checkpointChain[0]);
        if (sourceLeafIndex >= first.CoveredHeadCount || sourceAdhGeneration < first.CoveredFirstAdhGeneration ||
            sourceAdhGeneration > first.CoveredLastAdhGeneration)
            throw new ArgumentException("AFP1 source tuple is outside the first checkpoint coverage.", nameof(sourceLeafIndex));
        ArgumentNullException.ThrowIfNull(membershipNodes);
        if (membershipNodes.Count > 64)
            throw new ArgumentException("AFP1 membership proof exceeds 64 nodes.", nameof(membershipNodes));
        this.membershipNodes = new byte[membershipNodes.Count][];
        for (var index = 0; index < membershipNodes.Count; index++)
            this.membershipNodes[index] = Required(membershipNodes[index].Span, 32, nameof(membershipNodes));
        this.liveDtt1CoreHash = Required(liveDtt1CoreHash, 32, nameof(liveDtt1CoreHash));
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong SourceAdhGeneration { get; }
    public ulong SourceTreeSize { get; }
    public ReadOnlyMemory<byte> SourceAdh1CoreHash => sourceAdh1CoreHash.ToArray();
    public ReadOnlyMemory<byte> TargetAdh1CoreHash => targetAdh1CoreHash.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> AuthorityChain => authorityChain.Select(static item => (ReadOnlyMemory<byte>)item.ToArray()).ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> CheckpointChain => checkpointChain.Select(static item => (ReadOnlyMemory<byte>)item.ToArray()).ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> TargetHeadChain => targetHeadChain.Select(static item => (ReadOnlyMemory<byte>)item.ToArray()).ToArray();
    public ulong SourceLeafIndex { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> MembershipNodes => membershipNodes.Select(static item => (ReadOnlyMemory<byte>)item.ToArray()).ToArray();
    public ReadOnlyMemory<byte> LiveDtt1CoreHash => liveDtt1CoreHash.ToArray();

    private static byte[][] CopyRecords(IReadOnlyList<ReadOnlyMemory<byte>> values, string magic, string name)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count is < 1 or > 64)
            throw new ArgumentException("AFP1 record-list count must be between one and 64.", name);
        var result = new byte[values.Count][];
        for (var index = 0; index < values.Count; index++)
        {
            var item = values[index].ToArray();
            ValidateCanonicalEnvelope(item, magic, name);
            result[index] = item;
        }
        return result;
    }

    private static byte[][] CopyAuthorities(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        ReadOnlySpan<byte> expectedNetwork)
    {
        var result = CopyRecords(values, ProtocolMagic.XNA1, nameof(values));
        Xna1Record? previous = null;
        foreach (var bytes in result)
        {
            Xna1Record current;
            try { current = XPointNetworkCodec.Parse<Xna1Record>(bytes); }
            catch (Exception exception) { throw new ArgumentException("AFP1 contains an invalid XNA1 record.", nameof(values), exception); }
            if (!current.NetworkId.Span.SequenceEqual(expectedNetwork))
                throw new ArgumentException("AFP1 contains an XNA1 for another network.", nameof(values));
            if (previous is not null &&
                (previous.AuthorityGeneration == ulong.MaxValue || current.AuthorityGeneration != previous.AuthorityGeneration + 1 ||
                 !current.PredecessorAuthorityCoreHash.Span.SequenceEqual(previous.CoreHash.Span)))
                throw new ArgumentException("AFP1 XNA1 chain is not exact and predecessor-linked.", nameof(values));
            previous = current;
        }
        return result;
    }

    private static byte[][] CopyCheckpoints(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        ReadOnlySpan<byte> expectedNetwork,
        ReadOnlySpan<byte> targetAdh1CoreHash)
    {
        var result = CopyRecords(values, ProtocolMagic.ADF1, nameof(values));
        AccountDirectoryAdf1? previous = null;
        foreach (var bytes in result)
        {
            AccountDirectoryAdf1 current;
            try { current = AccountDirectoryAdf1Codec.Decode(bytes); }
            catch (FormatException exception) { throw new ArgumentException("AFP1 contains an invalid ADF1 record.", nameof(values), exception); }
            if (!current.NetworkId.Span.SequenceEqual(expectedNetwork))
                throw new ArgumentException("AFP1 contains an ADF1 for another network.", nameof(values));
            if (previous is not null &&
                (previous.CheckpointGeneration == ulong.MaxValue || current.CheckpointGeneration != previous.CheckpointGeneration + 1 ||
                 !current.PredecessorCoreHash.Span.SequenceEqual(AccountDirectoryCrypto.ComputeAdf1CoreHash(previous))))
                throw new ArgumentException("AFP1 ADF1 chain is not exact and predecessor-linked.", nameof(values));
            previous = current;
        }
        if (previous is null || !previous.TargetAdh1CoreReference.Span[6..].SequenceEqual(targetAdh1CoreHash))
            throw new ArgumentException("AFP1 target does not equal the final ADF1 target.", nameof(values));
        return result;
    }

    private static byte[][] CopyTargetHeads(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        IReadOnlyList<byte[]> checkpointBytes,
        ReadOnlySpan<byte> expectedNetwork,
        ReadOnlySpan<byte> finalTargetHash)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count != checkpointBytes.Count)
            throw new ArgumentException(
                "AFP1 requires exactly one target ADH1 for every ADF1 checkpoint.", nameof(values));
        var result = new byte[values.Count][];
        for (var index = 0; index < values.Count; index++)
        {
            var bytes = values[index].ToArray();
            ValidateCanonicalEnvelope(bytes, ProtocolMagic.ADH1, nameof(values));
            AccountDirectoryAdh1 head;
            try { head = AccountDirectoryAdh1Codec.Decode(bytes); }
            catch (FormatException exception)
            { throw new ArgumentException("AFP1 contains an invalid target ADH1 record.", nameof(values), exception); }
            var checkpoint = AccountDirectoryAdf1Codec.Decode(checkpointBytes[index]);
            var hash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            if (!head.NetworkId.Span.SequenceEqual(expectedNetwork) ||
                !checkpoint.TargetAdh1CoreReference.Span[6..].SequenceEqual(hash) ||
                checkpoint.TargetTreeSize != head.TreeSize ||
                !checkpoint.TargetAppendLogRoot.Span.SequenceEqual(head.AppendLogMerkleRoot.Span) ||
                !checkpoint.TargetCurrentValueMapRoot.Span.SequenceEqual(head.CurrentValueMapRoot.Span) ||
                !checkpoint.AuthorityXnaCoreReference.Span.SequenceEqual(head.ExactXnaAuthorityCoreReference.Span) ||
                head.LogGeneration <= checkpoint.CoveredLastAdhGeneration)
                throw new ArgumentException(
                    "AFP1 target ADH1 does not close its positionally paired ADF1.", nameof(values));
            result[index] = bytes;
        }
        if (!AccountDirectoryCrypto.ComputeAdh1CoreHash(
                AccountDirectoryAdh1Codec.Decode(result[^1])).AsSpan().SequenceEqual(finalTargetHash))
            throw new ArgumentException("AFP1 final target ADH1 hash differs.", nameof(values));
        return result;
    }

    private static void ValidateCanonicalEnvelope(ReadOnlySpan<byte> value, ReadOnlySpan<char> magic, string name)
    {
        if (value.Length is < 12 or > 65_535)
            throw new ArgumentException("AFP1 embedded record length is invalid.", name);
        for (var index = 0; index < 4; index++)
            if (value[index] != (byte)magic[index])
                throw new ArgumentException("AFP1 embedded record magic is invalid.", name);
        if (BinaryPrimitives.ReadUInt16BigEndian(value[4..]) != 1 ||
            BinaryPrimitives.ReadUInt16BigEndian(value[8..]) == 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(value[10..]) != 0)
            throw new ArgumentException("AFP1 embedded record header is invalid.", name);
        var count = BinaryPrimitives.ReadUInt16BigEndian(value[8..]);
        var offset = 12;
        for (var tag = 1; tag <= count; tag++)
        {
            if (value.Length - offset < 8 || BinaryPrimitives.ReadUInt16BigEndian(value[offset..]) != tag ||
                BinaryPrimitives.ReadUInt16BigEndian(value[(offset + 2)..]) != 0)
                throw new ArgumentException("AFP1 embedded record fields are not canonical.", name);
            var length = BinaryPrimitives.ReadUInt32BigEndian(value[(offset + 4)..]);
            offset += 8;
            if (length > int.MaxValue || value.Length - offset < (int)length)
                throw new ArgumentException("AFP1 embedded record field is truncated.", name);
            offset += (int)length;
        }
        if (offset != value.Length)
            throw new ArgumentException("AFP1 embedded record contains trailing bytes.", name);
    }

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public static class AccountDirectoryAfp1Codec
{
    public const ushort Version = 1;
    public const ushort Suite = 0x0201;
    public const ushort FieldCount = 12;
    private const int HeaderSize = 12;
    private static readonly int[] FixedLengths = [16, 48, 32, 1, -1, 1, -1, 8, 1, -1, 32, -1];

    public static byte[] Encode(AccountDirectoryAfp1 value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var source = new byte[48];
        BinaryPrimitives.WriteUInt64BigEndian(source, value.SourceAdhGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(source.AsSpan(8), value.SourceTreeSize);
        value.SourceAdh1CoreHash.Span.CopyTo(source.AsSpan(16));
        var authorities = EncodeRecords(value.AuthorityChain);
        var checkpoints = EncodeRecords(value.CheckpointChain);
        var targetHeads = EncodeRecords(value.TargetHeadChain);
        var nodes = new byte[checked(value.MembershipNodes.Count * 32)];
        for (var index = 0; index < value.MembershipNodes.Count; index++)
            value.MembershipNodes[index].Span.CopyTo(nodes.AsSpan(index * 32, 32));
        byte[][] fields =
        [
            value.NetworkId.ToArray(), source, value.TargetAdh1CoreHash.ToArray(), [checked((byte)value.AuthorityChain.Count)], authorities,
            [checked((byte)value.CheckpointChain.Count)], checkpoints, Be64(value.SourceLeafIndex),
            [checked((byte)value.MembershipNodes.Count)], nodes, value.LiveDtt1CoreHash.ToArray(), targetHeads
        ];
        var result = new byte[checked(HeaderSize + fields.Sum(static field => 8 + field.Length))];
        ProtocolMagicBytes.AFP1.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), Version);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), Suite);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), FieldCount);
        var offset = HeaderSize;
        for (var index = 0; index < fields.Length; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(result, offset);
            offset += fields[index].Length;
        }
        return result;
    }

    public static AccountDirectoryAfp1 Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length < HeaderSize || canonical.Length > 4_194_304 || !canonical[..4].SequenceEqual(ProtocolMagicBytes.AFP1) ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[4..]) != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[6..]) != Suite ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[8..]) != FieldCount ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical[10..]) != 0)
            Reject("AFP1 header is invalid.");
        var fields = new byte[FieldCount][];
        var offset = HeaderSize;
        for (var index = 0; index < FieldCount; index++)
        {
            if (canonical.Length - offset < 8 || BinaryPrimitives.ReadUInt16BigEndian(canonical[offset..]) != index + 1 ||
                BinaryPrimitives.ReadUInt16BigEndian(canonical[(offset + 2)..]) != 0)
                Reject("AFP1 field header is invalid.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(canonical[(offset + 4)..]);
            var expected = FixedLengths[index];
            if (expected >= 0 && length != (uint)expected || length > int.MaxValue)
                Reject("AFP1 field length is invalid.");
            if (index == 9 && fields[8] is not null && length != fields[8][0] * 32u)
                Reject("AFP1 membership-node length is invalid.");
            offset += 8;
            if (canonical.Length - offset < (int)length)
                Reject("AFP1 field is truncated.");
            fields[index] = canonical.Slice(offset, (int)length).ToArray();
            offset += (int)length;
        }
        if (offset != canonical.Length)
            Reject("AFP1 contains trailing bytes.");
        try
        {
            var source = fields[1].AsSpan();
            var authorities = DecodeRecords(fields[4], fields[3][0]);
            var checkpoints = DecodeRecords(fields[6], fields[5][0]);
            var targetHeads = DecodeRecords(fields[11], fields[5][0]);
            var nodes = new ReadOnlyMemory<byte>[fields[8][0]];
            for (var index = 0; index < nodes.Length; index++) nodes[index] = fields[9].AsMemory(index * 32, 32);
            return new AccountDirectoryAfp1(fields[0], BinaryPrimitives.ReadUInt64BigEndian(source),
                BinaryPrimitives.ReadUInt64BigEndian(source[8..]), source[16..], fields[2], authorities, checkpoints, targetHeads,
                BinaryPrimitives.ReadUInt64BigEndian(fields[7]), nodes, fields[10]);
        }
        catch (ArgumentException exception)
        {
            throw new AccountDirectoryAfp1FormatException(exception.Message);
        }
    }

    private static byte[] EncodeRecords(IReadOnlyList<ReadOnlyMemory<byte>> records)
    {
        var result = new byte[checked(records.Sum(static record => 4 + record.Length))];
        var offset = 0;
        foreach (var record in records)
        {
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset), checked((uint)record.Length));
            offset += 4;
            record.Span.CopyTo(result.AsSpan(offset));
            offset += record.Length;
        }
        return result;
    }

    private static ReadOnlyMemory<byte>[] DecodeRecords(ReadOnlySpan<byte> encoded, int count)
    {
        if (count is < 1 or > 64)
            Reject("AFP1 record-list count is invalid.");
        var result = new ReadOnlyMemory<byte>[count];
        var offset = 0;
        for (var index = 0; index < count; index++)
        {
            if (encoded.Length - offset < 4)
                Reject("AFP1 embedded record length is truncated.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(encoded[offset..]);
            offset += 4;
            if (length is < 12 or > 65_535 || encoded.Length - offset < (int)length)
                Reject("AFP1 embedded record length is invalid.");
            result[index] = encoded.Slice(offset, (int)length).ToArray();
            offset += (int)length;
        }
        if (offset != encoded.Length)
            Reject("AFP1 record list contains missing or trailing entries.");
        return result;
    }

    private static byte[] Be64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static void Reject(string message) => throw new AccountDirectoryAfp1FormatException(message);
}
