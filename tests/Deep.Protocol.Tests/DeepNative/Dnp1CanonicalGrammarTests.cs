using System.Buffers.Binary;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class CanonicalGrammarTests
{
    [Fact]
    public void ArtifactTypeRegistry_IsClosedAndContiguous()
    {
        Assert.Equal(Enumerable.Range(1, 44).Select(static value => (ushort)value),
            Enum.GetValues<ArtifactType>().Select(static value => (ushort)value));
    }

    [Fact]
    public void MachineRegistry_RecordArithmetic_IsExact()
    {
        var expected = new Dictionary<string, (int Minimum, int Maximum)>(StringComparer.Ordinal)
        {
            ["DPA1"]=(644,644),["DPD1"]=(776,776),["DPM1"]=(670,670),["DRT1"]=(179,179),
            ["DRS1"]=(356,63844),["KRT1"]=(412,412),["KRF1"]=(300,300),["DCM1"]=(812,812),
            ["DRA1"]=(788,788),["DWD1"]=(1217,1217),["DCP1"]=(706,706),["DCS1"]=(839,839),
            ["DCT1"]=(414,414),["DCN1"]=(758,2806),["DCQ1"]=(375,8805),["DHL1"]=(710,1734),
            ["DCL1"]=(409,5623),["DWL1"]=(708,708),["DRC1"]=(482,33554914),["DPL1"]=(576,576),
            ["DBG1"]=(296,296),["RIB1"]=(772,772),["XIB1"]=(452,452),["DNR1"]=(756,756),
            ["MRL2"]=(326,326),["RIP2"]=(573,957),["DPC1"]=(430,680),["DPR1"]=(408,408),
            ["DPS1"]=(444,444),["MRLC"]=(898,16778114),["DPJ1"]=(609,609),["RRM1"]=(332,332),
            ["RRL1"]=(502,502),["DWT1"]=(714,714),["DXR1"]=(573,573)
        };
        var definitions = typeof(RecordDefinitions).GetProperties(
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)
            .Where(static property => property.PropertyType == typeof(RecordDefinition))
            .Select(static property => (RecordDefinition)property.GetValue(null)!)
            .ToDictionary(static definition => definition.Magic, StringComparer.Ordinal);
        Assert.Equal(expected.Count, definitions.Count);
        foreach (var pair in expected)
        {
            Assert.Equal(pair.Value.Minimum, definitions[pair.Key].MinimumLength);
            Assert.Equal(pair.Value.Maximum, definitions[pair.Key].MaximumLength);
        }
    }

    [Fact]
    public void RegistryDefinitions_EncodeCanonicalMinimumShapes()
    {
        var definitions = new[]
        {
            RecordDefinitions.Dpa1,RecordDefinitions.Dpd1,RecordDefinitions.Dpm1,
            RecordDefinitions.Drt1,RecordDefinitions.Drs1,RecordDefinitions.Krt1,
            RecordDefinitions.Krf1,RecordDefinitions.Dcm1,RecordDefinitions.Dra1,
            RecordDefinitions.Dwd1,RecordDefinitions.Dcp1,RecordDefinitions.Dcs1,
            RecordDefinitions.Dct1,RecordDefinitions.Dcn1,RecordDefinitions.Dcq1,
            RecordDefinitions.Dhl1,RecordDefinitions.Dcl1,RecordDefinitions.Dwl1,
            RecordDefinitions.Drc1,RecordDefinitions.Dpl1,RecordDefinitions.Dbg1,
            RecordDefinitions.Rib1,RecordDefinitions.Xib1,RecordDefinitions.Dnr1,
            RecordDefinitions.Mrl2,RecordDefinitions.Rip2,RecordDefinitions.Dpc1,
            RecordDefinitions.Dpr1,RecordDefinitions.Dps1,RecordDefinitions.Mrlc,
            RecordDefinitions.Dpj1,RecordDefinitions.Rrm1,RecordDefinitions.Rrl1,
            RecordDefinitions.Dwt1,RecordDefinitions.Dxr1
        };

        foreach (var definition in definitions)
        {
            var fields = MinimumFields(definition);
            var canonical = CanonicalGrammar.Encode(definition, fields);
            CanonicalGrammar.Preflight(canonical, definition);
            Assert.InRange(canonical.Length, definition.MinimumLength, definition.MaximumLength);
        }
    }

    [Theory]
    [InlineData(4, 0)]
    [InlineData(6, 0x0101)]
    [InlineData(8, 0)]
    [InlineData(10, 1)]
    [InlineData(12, 2)]
    [InlineData(14, 1)]
    public void HeaderTagSuiteAndTrailingMutations_Reject(int offset, int value)
    {
        var canonical = CanonicalGrammar.Encode(
            RecordDefinitions.Drt1,
            MinimumFields(RecordDefinitions.Drt1));
        var mutated = canonical.ToArray();
        if (offset == canonical.Length)
            mutated = [.. canonical, checked((byte)value)];
        else if (offset is 4 or 6 or 8 or 10 or 12 or 14)
            BinaryPrimitives.WriteUInt16BigEndian(mutated.AsSpan(offset, 2), checked((ushort)value));
        Assert.Throws<RecordException>(() =>
            CanonicalGrammar.Preflight(mutated, RecordDefinitions.Drt1));
    }

    [Fact]
    public void OuterValidLateVariableLengthMismatch_RejectsBeforeOwnership()
    {
        var fields = MinimumFields(RecordDefinitions.Drs1);
        fields[8] = U16(1024);
        fields[9] = DrsEntries(1024);
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Drs1, fields);
        var mutated = canonical.ToArray();
        var entries = RecordDefinitions.Field(mutated, 10);
        Assert.Equal(62 * 1024, entries.Length);
        var countOffset = FieldOffset(mutated, 9);
        BinaryPrimitives.WriteUInt16BigEndian(mutated.AsSpan(countOffset, 2), 1023);

        Assert.Throws<RecordException>(() =>
            CanonicalGrammar.DecodeOwned(mutated, RecordDefinitions.Drs1));
    }

    [Fact]
    public void AccountCertificate_RealSodiumSignatures_VerifiesAndOwns()
    {
        var keys = Enumerable.Range(0, 4).Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        var fields = MinimumFields(RecordDefinitions.Dpa1);
        fields[0] = Enumerable.Repeat((byte)0x11, 16).ToArray();
        fields[1] = U64(1);
        fields[2] = U64(1);
        fields[4] = keys[0].PublicKey;
        fields[5] = keys[1].PublicKey;
        fields[6] = keys[2].PublicKey;
        fields[7] = keys[3].PublicKey;
        fields[8] = Enumerable.Repeat((byte)0x22, 32).ToArray();
        fields[9] = U64(123);
        fields[10] = U64(1);
        fields[11] = U16(1);
        var unsignedCarrier = CanonicalGrammar.Encode(RecordDefinitions.Dpa1, fields);
        var owned = CanonicalGrammar.DecodeOwned(unsignedCarrier, RecordDefinitions.Dpa1);
        var signing = CanonicalGrammar.GetSigningBytes(
            owned, "Deep/IdentityAuth/V1/account-certificate");
        for (var index = 0; index < 4; index++)
            fields[12 + index] = PublicKeyAuth.SignDetached(signing, keys[index].PrivateKey);
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Dpa1, fields);

        var verified = IdentityVerifier.VerifyAccountCertificate(canonical);
        canonical[0] ^= 0xff;

        Assert.Equal(32, verified.DeepAccountIdHash.Length);
        Assert.Equal("DPA1", System.Text.Encoding.ASCII.GetString(
            verified.Certificate.CanonicalBytes.Span[..4]));
    }

    [Fact]
    public void AccountRoleKeyReuse_RejectsBeforeSignatureVerification()
    {
        var fields = MinimumFields(RecordDefinitions.Dpa1);
        fields[0] = Enumerable.Repeat((byte)1, 16).ToArray();
        fields[1] = U64(1); fields[2] = U64(1); fields[11] = U16(1);
        fields[4] = fields[5] = fields[6] = fields[7] = Enumerable.Repeat((byte)2, 32).ToArray();
        fields[8] = Enumerable.Repeat((byte)3, 32).ToArray();
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Dpa1, fields);
        var error = Assert.Throws<RecordException>(() =>
            IdentityVerifier.VerifyAccountCertificate(canonical));
        Assert.Equal(RecordError.InvalidField, error.Error);
    }

    [Fact]
    public void ProtectedHmac_IsExactDomainSeparatedAndMutationFails()
    {
        var fields = MinimumFields(RecordDefinitions.Dpl1);
        var unsignedCarrier = CanonicalGrammar.Encode(RecordDefinitions.Dpl1, fields);
        var record = CanonicalGrammar.DecodeOwned(unsignedCarrier, RecordDefinitions.Dpl1);
        var key = Enumerable.Repeat((byte)0x5a, 32).ToArray();
        fields[^1] = CanonicalGrammar.ComputeProtectedHmac(record, key);
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Dpl1, fields);
        var verified = CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dpl1);
        CanonicalGrammar.VerifyProtectedHmac(verified, key);

        canonical[FieldOffset(canonical, 3)] ^= 1;
        var mutated = CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dpl1);
        Assert.Throws<RecordException>(() =>
            CanonicalGrammar.VerifyProtectedHmac(mutated, key));
    }

    [Fact]
    public void OuterValidLateLargeDrcInvalidCount_RejectsWithBoundedAllocation()
    {
        var fields = MinimumFields(RecordDefinitions.Drc1);
        fields[9] = U64(8 * 1024 * 1024);
        fields[10] = U64(8 * 1024 * 1024);
        fields[15] = new byte[8 * 1024 * 1024];
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Drc1, fields);
        BinaryPrimitives.WriteUInt16BigEndian(canonical.AsSpan(FieldOffset(canonical, 9), 2), 0);
        var before = GC.GetAllocatedBytesForCurrentThread();
        Assert.Throws<RecordException>(() =>
            CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Drc1));
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before, 0, 256 * 1024);
    }

    [Theory]
    [InlineData("DRT1", 2, 0UL)]
    [InlineData("KRT1", 2, 0UL)]
    [InlineData("DCP1", 3, 5UL)]
    [InlineData("DCN1", 26, 2UL)]
    [InlineData("DPL1", 2, 0UL)]
    [InlineData("DNR1", 14, 8UL)]
    [InlineData("DNR1", 15, 32UL)]
    [InlineData("DPC1", 9, 4UL)]
    [InlineData("DPR1", 9, 2UL)]
    [InlineData("DPJ1", 8, 2UL)]
    [InlineData("DWD1", 10, 14UL)]
    [InlineData("RRM1", 7, 14UL)]
    public void ClosedWireScalarMutation_RejectsBeforeCrypto(string magic, int tag, ulong value)
    {
        var definition = Definition(magic);
        var canonical = CanonicalGrammar.Encode(definition, MinimumFields(definition));
        var offset = FieldOffset(canonical, tag);
        var length = definition.Fields[tag - 1].MinimumLength;
        switch (length)
        {
            case 1:
                canonical[offset] = checked((byte)value);
                break;
            case 2:
                BinaryPrimitives.WriteUInt16BigEndian(canonical.AsSpan(offset, 2), checked((ushort)value));
                break;
            case 8:
                BinaryPrimitives.WriteUInt64BigEndian(canonical.AsSpan(offset, 8), value);
                break;
            default:
                throw new InvalidOperationException($"Unsupported scalar length {length}.");
        }

        Assert.Throws<RecordException>(() =>
            CanonicalGrammar.Preflight(canonical, definition));
    }

    private static ReadOnlyMemory<byte>[] MinimumFields(RecordDefinition definition)
    {
        var fields = definition.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength])
            .ToArray();
        switch (definition.Magic)
        {
            case "DPA1": fields[11] = U16(1); break;
            case "DPD1": fields[17] = U64(1); fields[18] = U16(1); break;
            case "DPM1": fields[15] = U64(1); break;
            case "DRT1": fields[1] = new byte[] { 1 }; break;
            case "KRT1": fields[1] = new byte[] { 1 }; fields[9] = new byte[] { 1 }; break;
            case "KRF1": fields[1] = new byte[] { 1 }; fields[8] = new byte[] { 2 }; break;
            case "DRA1": fields[14] = U16(1); break;
            case "DWD1":
                fields[9] = U64(15); fields[12] = new byte[] { 4 };
                fields[13] = WitnessDescriptors(); break;
            case "DCP1": fields[2] = U16(1); break;
            case "DCS1": fields[9] = new byte[] { 4 }; fields[10] = ComponentRows(); break;
            case "DCN1": fields[25] = new byte[] { 1 }; break;
            case "DCQ1": fields[8] = new byte[] { 3 }; fields[9] = ReceiptBlob(758); break;
            case "DCL1": fields[9] = new byte[] { 3 }; fields[10] = ReceiptBlob(710); break;
            case "DRC1": fields[8] = U16(1); break;
            case "DPL1": fields[1] = U16(1); break;
            case "DBG1": fields[1] = U16(1); break;
            case "DNR1": fields[13] = U64(1); fields[14] = U64(1); break;
            case "MRL2":
                fields[4] = Ref(ArtifactType.Dnr1, 756);
                fields[5] = U64(1);
                fields[6] = U64(1);
                fields[8] = Ref(ArtifactType.Dpc1, 430);
                break;
            case "RIP2":
                fields[4] = U16(2); fields[5] = U64(1);
                fields[6] = U32(1); fields[7] = U32(1); fields[10] = U32(326);
                var mrlFields = MinimumFields(RecordDefinitions.Mrl2);
                mrlFields[2] = U64(1);
                fields[11] = CanonicalGrammar.Encode(RecordDefinitions.Mrl2,mrlFields);
                break;
            case "DPC1":
                fields[7] = U64(1); fields[8] = new byte[] { 1 }; fields[9] = new byte[4];
                fields[10] = U16(1); break;
            case "DPR1": fields[8] = U16(1); break;
            case "DPJ1": fields[7] = U16(1); break;
            case "MRLC": fields[22] = U32(8); break;
            case "RRM1":
                fields[2] = Enumerable.Repeat((byte)1, 32).ToArray();
                fields[4] = Enumerable.Repeat((byte)2, 32).ToArray();
                fields[6] = U64(15);
                fields[7] = Enumerable.Repeat((byte)3, 32).ToArray();
                fields[8] = Enumerable.Repeat((byte)4, 32).ToArray(); break;
            case "RRL1":
                fields[1] = Ref(ArtifactType.Rrm1, 332); fields[3] = Enumerable.Repeat((byte)1, 32).ToArray();
                fields[4] = Ref(ArtifactType.Rrm1, 332); fields[9] = Ref(ArtifactType.Dwd1, 1217);
                fields[10] = U64(1); fields[12] = Enumerable.Repeat((byte)2, 32).ToArray();
                fields[14] = Enumerable.Repeat((byte)3, 32).ToArray(); break;
            case "DWT1":
                fields[1] = Ref(ArtifactType.Dwd1, 1217); fields[4] = Ref(ArtifactType.Rrm1, 332);
                fields[5] = Ref(ArtifactType.Krf1, 300); fields[7] = new byte[] { 3 };
                fields[8] = TerminalWitnessRows(); break;
            case "DXR1":
                fields[1] = new byte[] { 1 };
                foreach (var index in new[] { 2,3,4,5,6,7,8,14,15 })
                    fields[index] = Enumerable.Repeat((byte)(index + 1), fields[index].Length).ToArray();
                fields[10] = U64(1); fields[17] = U64(1); break;
        }
        return fields;
    }

    private static RecordDefinition Definition(string magic) => magic switch
    {
        "DRT1" => RecordDefinitions.Drt1,
        "KRT1" => RecordDefinitions.Krt1,
        "DCP1" => RecordDefinitions.Dcp1,
        "DCN1" => RecordDefinitions.Dcn1,
        "DPL1" => RecordDefinitions.Dpl1,
        "DNR1" => RecordDefinitions.Dnr1,
        "DPC1" => RecordDefinitions.Dpc1,
        "DPR1" => RecordDefinitions.Dpr1,
        "DPJ1" => RecordDefinitions.Dpj1,
        "DWD1" => RecordDefinitions.Dwd1,
        "RRM1" => RecordDefinitions.Rrm1,
        _ => throw new ArgumentOutOfRangeException(nameof(magic))
    };

    private static byte[] WitnessDescriptors()
    {
        var value = new byte[464];
        for (var index = 0; index < 4; index++)
        {
            value[index * 116] = checked((byte)(index + 1));
            value[index * 116 + 32] = checked((byte)(index + 1));
            value[index * 116 + 64] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(index * 116 + 82, 2), 1);
        }
        return value;
    }

    private static byte[] DrsEntries(int count)
    {
        var value = new byte[62 * count];
        for (var index = 0; index < count; index++)
        {
            var entry = value.AsSpan(index * 62, 62);
            var terminal = index == count - 1 && count == 1024;
            entry[0] = terminal ? (byte)3 : (byte)1;
            Ref(ArtifactType.Drt1, 179).CopyTo(entry[1..39]);
            BinaryPrimitives.WriteUInt64BigEndian(entry[39..47], 1);
            BinaryPrimitives.WriteUInt64BigEndian(entry[47..55], 1);
            BinaryPrimitives.WriteUInt16BigEndian(entry[55..57], terminal ? (ushort)4 : (ushort)1);
        }
        return value;
    }

    private static byte[] ComponentRows()
    {
        var value = new byte[416];
        for (var index = 0; index < 4; index++)
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(index * 104, 2), checked((ushort)(index + 1)));
        return value;
    }

    private static byte[] TerminalWitnessRows()
    {
        var value = new byte[435];
        for (var index = 0; index < 3; index++)
        {
            value[index * 145] = checked((byte)(index + 1));
            value[index * 145 + 72] = 1;
        }
        return value;
    }

    private static byte[] ReceiptBlob(int length)
    {
        var blob = new byte[3 * (4 + length)];
        for (var index = 0; index < 3; index++)
            BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(index * (4 + length), 4), checked((uint)length));
        return blob;
    }

    private static int FieldOffset(ReadOnlySpan<byte> encoded, int tag)
    {
        var offset = 12;
        for (var current = 1; current <= tag; current++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset + 4, 4)));
            offset += 8;
            if (current == tag) return offset;
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(tag));
    }

    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U32(uint value) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
    private static byte[] Ref(ArtifactType type, uint length)
    {
        var value = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(2), length);
        value[6] = 1;
        return value;
    }
}
