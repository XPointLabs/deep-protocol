using System.Buffers;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Protocol.ProfileCarrier.Tests;

// Copied from the accepted XNode source eff4523 solely as a cross-repository
// byte oracle. Production code must not depend on this test implementation.
internal static class AcceptedXNodeDpf1Oracle
{
    public static byte[] Encode(SyntheticProfileParts parts)
    {
        var components = new List<(byte Kind, byte[] Bytes)>
        {
            (1, parts.CanonicalGenesis.ToArray()),
            (2, EncodeGenesisApprovals(parts.GenesisApprovals)),
            (3, parts.CanonicalSignedDelegation.ToArray())
        };
        components.AddRange(parts.CanonicalSignedBridges.Select(static value =>
            ((byte)4, value.ToArray())));

        var bodyLength = components.Sum(static component =>
            1 + VarUIntLength((uint)component.Bytes.Length) + component.Bytes.Length);
        var writer = new ArrayBufferWriter<byte>(
            6 + VarUIntLength((uint)bodyLength) + bodyLength);
        Write(writer, "DPF1"u8);
        WriteByte(writer, 1);
        WriteByte(writer, checked((byte)components.Count));
        WriteVarUInt(writer, (uint)bodyLength);
        foreach (var component in components)
        {
            WriteByte(writer, component.Kind);
            WriteVarUInt(writer, (uint)component.Bytes.Length);
            Write(writer, component.Bytes);
        }
        return writer.WrittenSpan.ToArray();
    }

    private static byte[] EncodeGenesisApprovals(
        IReadOnlyList<MembershipSignature> signatures)
    {
        var writer = new ArrayBufferWriter<byte>();
        WriteByte(writer, checked((byte)signatures.Count));
        foreach (var signature in signatures
                     .OrderBy(static value => value.SignerId, MemoryComparer.Instance))
        {
            WriteByte(writer, (byte)signature.Domain);
            Write(writer, signature.SignerId.Span);
            WriteVarUInt(writer, checked((uint)signature.Signature.Length));
            Write(writer, signature.Signature.Span);
        }
        return writer.WrittenSpan.ToArray();
    }

    private static int VarUIntLength(uint value)
    {
        var length = 1;
        while (value >= 0x80)
        {
            value >>= 7;
            length++;
        }
        return length;
    }

    private static void WriteVarUInt(IBufferWriter<byte> writer, uint value)
    {
        do
        {
            var next = (byte)(value & 0x7f);
            value >>= 7;
            if (value != 0)
            {
                next |= 0x80;
            }
            WriteByte(writer, next);
        } while (value != 0);
    }

    private static void WriteByte(IBufferWriter<byte> writer, byte value)
    {
        var span = writer.GetSpan(1);
        span[0] = value;
        writer.Advance(1);
    }

    private static void Write(IBufferWriter<byte> writer, ReadOnlySpan<byte> value)
    {
        value.CopyTo(writer.GetSpan(value.Length));
        writer.Advance(value.Length);
    }

    private sealed class MemoryComparer : IComparer<ReadOnlyMemory<byte>>
    {
        public static MemoryComparer Instance { get; } = new();

        public int Compare(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y) =>
            x.Span.SequenceCompareTo(y.Span);
    }
}
