using System.Buffers;

namespace Deep.Protocol.DeepExtension.SelfHostedProfiles;

internal static class ProfileCarrierFraming
{
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.DPF1;
    private const byte Version = 1;

    public static byte[] Encode(IReadOnlyList<ProfileComponent> components)
    {
        if (components.Count is 0 or > ProfileCarrierLimits.MaximumComponents)
        {
            throw ProfileCarrierErrors.Bounds();
        }

        var bodyLength = 0;
        foreach (var component in components)
        {
            if (component.Bytes.Length is 0 or > ProfileCarrierLimits.MaximumComponentBytes)
            {
                throw ProfileCarrierErrors.Bounds();
            }
            bodyLength = checked(
                bodyLength +
                1 +
                VarUIntLength((uint)component.Bytes.Length) +
                component.Bytes.Length);
        }

        var totalLength = checked(
            Magic.Length + 2 + VarUIntLength((uint)bodyLength) + bodyLength);
        if (!ProfileCarrierLimits.IsFilePayloadLengthAllowed(totalLength))
        {
            throw ProfileCarrierErrors.Bounds();
        }

        var writer = new ArrayBufferWriter<byte>(totalLength);
        Write(writer, Magic);
        WriteByte(writer, Version);
        WriteByte(writer, checked((byte)components.Count));
        WriteVarUInt(writer, (uint)bodyLength);
        foreach (var component in components)
        {
            WriteByte(writer, (byte)component.Kind);
            WriteVarUInt(writer, (uint)component.Bytes.Length);
            Write(writer, component.Bytes);
        }
        return writer.WrittenSpan.ToArray();
    }

    public static IReadOnlyList<ProfileComponent> Decode(ReadOnlySpan<byte> encoded)
    {
        if (!ProfileCarrierLimits.IsFilePayloadLengthAllowed(encoded.Length) ||
            encoded.Length < Magic.Length + 3)
        {
            throw ProfileCarrierErrors.Framing();
        }

        var reader = new ProfileReader(encoded);
        if (!reader.ReadFixed(Magic.Length).SequenceEqual(Magic) ||
            reader.ReadByte() != Version)
        {
            throw ProfileCarrierErrors.Framing();
        }
        var count = reader.ReadByte();
        if (count is 0 or > ProfileCarrierLimits.MaximumComponents)
        {
            throw ProfileCarrierErrors.Framing();
        }
        var bodyLength = reader.ReadVarUInt();
        if (bodyLength != reader.Remaining)
        {
            throw ProfileCarrierErrors.Framing();
        }

        var result = new ProfileComponent[count];
        for (var index = 0; index < count; index++)
        {
            var kind = (ProfileComponentKind)reader.ReadByte();
            if (!Enum.IsDefined(kind))
            {
                throw ProfileCarrierErrors.Framing();
            }
            var length = reader.ReadVarUInt();
            if (length is 0 or > ProfileCarrierLimits.MaximumComponentBytes)
            {
                throw ProfileCarrierErrors.Framing();
            }
            result[index] = new(
                kind,
                reader.ReadFixed(checked((int)length)).ToArray());
        }
        if (reader.Remaining != 0)
        {
            throw ProfileCarrierErrors.Framing();
        }
        return result;
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

    private ref struct ProfileReader
    {
        private readonly ReadOnlySpan<byte> source;
        private int offset;

        public ProfileReader(ReadOnlySpan<byte> source)
        {
            this.source = source;
            offset = 0;
        }

        public int Remaining => source.Length - offset;

        public byte ReadByte()
        {
            if (Remaining < 1)
            {
                throw ProfileCarrierErrors.Framing();
            }
            return source[offset++];
        }

        public ReadOnlySpan<byte> ReadFixed(int length)
        {
            if (length < 0 || Remaining < length)
            {
                throw ProfileCarrierErrors.Framing();
            }
            var result = source.Slice(offset, length);
            offset += length;
            return result;
        }

        public uint ReadVarUInt()
        {
            uint value = 0;
            var shift = 0;
            var count = 0;
            while (true)
            {
                if (count == 5)
                {
                    throw ProfileCarrierErrors.Framing();
                }
                var current = ReadByte();
                count++;
                if (count == 5 && (current & 0xf0) != 0)
                {
                    throw ProfileCarrierErrors.Framing();
                }
                value |= (uint)(current & 0x7f) << shift;
                if ((current & 0x80) == 0)
                {
                    if (count != VarUIntLength(value))
                    {
                        throw ProfileCarrierErrors.Framing();
                    }
                    return value;
                }
                shift += 7;
            }
        }
    }
}
