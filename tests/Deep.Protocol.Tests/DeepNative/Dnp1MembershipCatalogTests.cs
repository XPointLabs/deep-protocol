using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class MembershipCatalogTests
{
    [Fact]
    public void ExactEightRowCatalog_PreflightsOwnsAndVerifiesReferences()
    {
        var catalog = Catalog();
        var owned = MembershipCatalogParser.DecodeOwned(catalog, 8, 1);
        catalog.AsSpan().Fill(0xff);

        Assert.Equal(8, owned.Rows.Count);
        Assert.Equal(ArtifactType.Mng1, owned.Rows[0].Type);
        Assert.Equal(ArtifactType.Dpc1, owned.Rows[7].Type);
        Assert.Equal("DPC1", System.Text.Encoding.ASCII.GetString(owned.RowBytes(7)[..4]));
    }

    [Fact]
    public void OrderOrLateHashMutation_Rejects()
    {
        var catalog = Catalog();
        var wrongOrder = catalog.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(wrongOrder.AsSpan(10, 2), (ushort)ArtifactType.Mmc1);
        Assert.Throws<RecordException>(() =>
            MembershipCatalogParser.DecodeOwned(wrongOrder, 8, 1));

        var lateHash = catalog.ToArray();
        lateHash[RowHashOffset(lateHash, 7)] ^= 0x80;
        Assert.Throws<RecordException>(() =>
            MembershipCatalogParser.DecodeOwned(lateHash, 8, 1));
    }

    [Fact]
    public void HostileIntMaxRowLength_IsNormalizedBeforeOwnership()
    {
        var catalog = Catalog();
        BinaryPrimitives.WriteUInt32BigEndian(catalog.AsSpan(12, 4), int.MaxValue);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var exception = Assert.Throws<RecordException>(() =>
            MembershipCatalogParser.DecodeOwned(catalog, 8, 1));

        Assert.Equal(RecordError.InvalidLength, exception.Error);
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before, 0, 64 * 1024);
    }

    internal static byte[] Catalog()
    {
        var rows = new[]
        {
            Row(ArtifactType.Mng1, "MNG1"u8.ToArray()),
            Row(ArtifactType.Mmc1, "MMC1"u8.ToArray()),
            Row(ArtifactType.Msm1, "MSM1"u8.ToArray()),
            Row(ArtifactType.Pma1, "PMA1"u8.ToArray()),
            Row(ArtifactType.Pmr1, "PMR1"u8.ToArray()),
            Row(ArtifactType.Dnr1, Record(RecordDefinitions.Dnr1)),
            Row(ArtifactType.Mrl2, Record(RecordDefinitions.Mrl2)),
            Row(ArtifactType.Dpc1, Record(RecordDefinitions.Dpc1))
        };
        var output = new byte[10 + rows.Sum(static row => row.Length)];
        "MRC1"u8.CopyTo(output);
        output[4] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(6, 4), 8);
        var offset = 10;
        foreach (var row in rows)
        {
            row.CopyTo(output, offset);
            offset += row.Length;
        }
        return output;
    }

    private static byte[] Record(RecordDefinition definition)
    {
        var f = definition.Fields
            .Select(static x => (ReadOnlyMemory<byte>)new byte[x.MinimumLength]).ToArray();
        switch (definition.Magic)
        {
            case "DNR1": f[13] = U64(1); f[14] = U64(1); break;
            case "MRL2":
                f[4] = Ref(ArtifactType.Dnr1, 756, 1);
                f[5] = U64(1);
                f[6] = U64(1);
                f[8] = Ref(ArtifactType.Dpc1, 430, 2);
                break;
            case "DPC1": f[7] = U64(1); f[8] = new byte[] { 1 }; f[9] = new byte[4]; f[10] = U16(1); break;
        }
        return CanonicalGrammar.Encode(definition, f);
    }

    private static byte[] Row(ArtifactType type, byte[] canonical)
    {
        var hash = ArtifactRegistry.IsRetained(type)
            ? SHA256.HashData(canonical)
            : CanonicalGrammar.ComputeReference(type, canonical).CanonicalHash.ToArray();
        var output = new byte[38 + canonical.Length];
        BinaryPrimitives.WriteUInt16BigEndian(output, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(2, 4), checked((uint)canonical.Length));
        hash.CopyTo(output, 6);
        canonical.CopyTo(output, 38);
        return output;
    }

    private static int RowHashOffset(byte[] catalog, int target)
    {
        var offset = 10;
        for (var index = 0; index < target; index++)
            offset += 38 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(catalog.AsSpan(offset + 2, 4)));
        return offset + 6;
    }

    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
    private static byte[] Ref(ArtifactType type, uint length, byte marker)
    {
        var value = new byte[ArtifactReference.Length];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(2), length);
        value[6] = marker;
        return value;
    }
}
