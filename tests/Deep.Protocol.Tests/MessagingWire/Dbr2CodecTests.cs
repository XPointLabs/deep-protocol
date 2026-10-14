using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text.Json;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Tests.XPointNetworkV1;

namespace Deep.Protocol.Tests.MessagingWire;

public sealed class Dbr2CodecTests
{
    public static IEnumerable<object[]> PositiveCases()
    {
        using var vectors = ReadSpec("braid-recovery-v2.vectors.json");
        foreach (var row in vectors.RootElement.GetProperty("positive").EnumerateArray())
            yield return [row.GetProperty("name").GetString()!, row.GetProperty("kind").GetByte(),
                row.GetProperty("payloadBytes").GetInt32(), row.GetProperty("encodedHex").GetString()!];
    }

    public static IEnumerable<object[]> NegativeCases()
    {
        using var vectors = ReadSpec("braid-recovery-v2.vectors.json");
        foreach (var row in vectors.RootElement.GetProperty("negative").EnumerateArray())
            yield return [row.GetProperty("name").GetString()!, row.GetProperty("mutation").GetString()!,
                Enum.Parse<MessagingWireRejection>(row.GetProperty("rejection").GetString()!)];
    }

    [Theory]
    [MemberData(nameof(PositiveCases))]
    public void FrozenPublicVectorsMatchIndependentManualWitness(string name, byte kind, int payloadBytes, string encodedHex)
    {
        Assert.Equal(name, ((Dtr2BraidMessageKind)kind).ToString());
        var manual = ManualMessagingWire.Record("DBR2", Fields(kind, payloadBytes));
        Assert.Equal(Convert.FromHexString(encodedHex), manual);
        var parsed = Dbr2Codec.Decode(manual);
        Assert.Equal(4112, manual.Length);
        Assert.Equal((ulong)1, parsed.BraidEpoch);
        Assert.Equal((byte)1, parsed.ControlCounter);
        Assert.Equal((Dtr2BraidMessageKind)kind, parsed.BraidMessage.Kind);
        Assert.Equal(payloadBytes, parsed.BraidMessage.EncodedPayloadLength);
        Assert.Equal(manual, Dbr2Codec.Encode(parsed));
    }

    [Theory]
    [MemberData(nameof(NegativeCases))]
    public void AllFrozenMutationsRejectBeforeOwnedCopy(string name, string mutation, MessagingWireRejection rejection)
    {
        Assert.False(string.IsNullOrWhiteSpace(name));
        var changed = Mutate(ManualMessagingWire.Record("DBR2", Fields()), mutation);
        var failure = Assert.Throws<MessagingWireFormatException>(() => Dbr2Codec.Decode(changed));
        Assert.Equal(rejection, failure.Rejection);
        Assert.True(failure.Stage < MessagingWirePrevalidationStage.OwnedCopy);
    }

    [Fact]
    public void AuthenticationProjectionIncludesExactScopeAndPaddingButOmitsMac()
    {
        var fields = Fields();
        var projection = ManualMessagingWire.Record("DBR2", fields[..10]);
        // DBR2's frozen MAC projection is not the existing signed-record helper,
        // which additionally prefixes a suite and record length.
        byte[] expected = [.. "Deep/MSG-V2/braid-recovery-auth"u8, 0, .. projection];
        var parsed = Dbr2Codec.Decode(ManualMessagingWire.Record("DBR2", fields));
        Assert.Equal(4072, projection.Length);
        Assert.Equal(expected, Dbr2Codec.GetAuthenticationInput(parsed));
        fields[10].Value.AsSpan().Clear();
        Assert.Equal(expected, Dbr2Codec.GetAuthenticationInput(Dbr2Codec.Decode(ManualMessagingWire.Record("DBR2", fields))));
        foreach (var tag in new[] { 1, 2, 3, 4, 5, 6, 7, 9 })
        {
            var alternate = Fields();
            alternate[tag - 1].Value[^1] ^= 3; // epoch1 -> 2, counter1 -> 2; other fields remain valid.
            Assert.NotEqual(expected, Dbr2Codec.GetAuthenticationInput(Dbr2Codec.Decode(ManualMessagingWire.Record("DBR2", alternate))));
        }
        // A projection is not a network frame and must not be accepted as one.
        Assert.Equal(MessagingWireRejection.InvalidTotalSize,
            Assert.Throws<MessagingWireFormatException>(() => Dbr2Codec.Decode(projection)).Rejection);
    }

    [Fact]
    public void OwnedSnapshotDoesNotAliasCallerOrPublicGetters()
    {
        var caller = ManualMessagingWire.Record("DBR2", Fields());
        var original = caller.ToArray();
        var parsed = Dbr2Codec.Decode(caller);
        caller.AsSpan().Fill(0xff);
        foreach (var getter in new[] { parsed.NetworkId, parsed.SessionId, parsed.SenderDeviceId,
                     parsed.RecipientDeviceId, parsed.OperationId, parsed.Authenticator, parsed.CanonicalBytes })
        {
            Assert.True(MemoryMarshal.TryGetArray(getter, out var owned));
            owned.AsSpan().Clear();
        }
        var encoded = Dbr2Codec.Encode(parsed);
        encoded.AsSpan().Clear();
        Assert.Equal(original, Dbr2Codec.Encode(parsed));
        Assert.Equal((byte)1, parsed.ControlCounter);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void EveryIdentifierMustBeNonzero(int tag)
    {
        var fields = Fields();
        fields[tag - 1].Value.AsSpan().Clear();
        Assert.Equal(MessagingWireRejection.ZeroForbidden, Assert.Throws<MessagingWireFormatException>(
            () => Dbr2Codec.Decode(ManualMessagingWire.Record("DBR2", fields))).Rejection);
    }

    [Fact]
    public void LargestNonwrappingEpochAndSecondControlSlotRemainStructuralOnly()
    {
        var fields = Fields();
        fields[5].Value = ManualMessagingWire.U64(ulong.MaxValue - 1);
        fields[6].Value[0] = 2;
        fields[10].Value.AsSpan().Clear(); // A parser must not pretend to verify the MAC.
        var parsed = Dbr2Codec.Decode(ManualMessagingWire.Record("DBR2", fields));
        Assert.Equal(ulong.MaxValue - 1, parsed.BraidEpoch);
        Assert.Equal((byte)2, parsed.ControlCounter);
        Assert.False(Dbr2Codec.ProductionActive);
    }

    [Fact]
    public void MachineRegistryAndVectorScopeMatchParserOnlyTarget()
    {
        using var registry = ReadSpec("braid-recovery-v2.registry.json");
        var root = registry.RootElement;
        Assert.Equal(Dbr2Codec.CodecStatus, root.GetProperty("status").GetString());
        Assert.False(root.GetProperty("productionActive").GetBoolean());
        Assert.Equal("DBR2", root.GetProperty("magic").GetString());
        Assert.Equal(1, root.GetProperty("version").GetInt32());
        Assert.Equal(0x0201, root.GetProperty("suite").GetInt32());
        Assert.Equal(Dbr2Codec.TotalBytes, root.GetProperty("totalBytes").GetInt32());
        Assert.Equal(11, root.GetProperty("fieldCount").GetInt32());
        Assert.Equal(Enumerable.Range(1, 11), root.GetProperty("fields").EnumerateArray().Select(row => row.GetProperty("tag").GetInt32()));
        Assert.Equal(new[] { 16, 32, 32, 32, 32, 8, 1, 1, -1, -1, 32 },
            root.GetProperty("fields").EnumerateArray().Select(row => row.GetProperty("bytes").GetInt32()));
        Assert.Equal(new[] { 1, 3, 5, 6 }, root.GetProperty("payloadKinds").EnumerateArray().Select(row => row.GetProperty("kind").GetInt32()));
        Assert.Equal(new[] { 96, 1152, 960, 160 }, root.GetProperty("payloadKinds").EnumerateArray().Select(row => row.GetProperty("bytes").GetInt32()));
        Assert.Equal(4072, root.GetProperty("authenticationInput").GetProperty("projectionBytes").GetInt32());
        Assert.StartsWith("braid-recovery-v2.native.registry.json#controlKdf;",
            root.GetProperty("authenticationInput").GetProperty("keyDerivation").GetString());
        Assert.Equal(4, PositiveCases().Count());
        Assert.Equal(22, NegativeCases().Count());
    }

    private static (ushort Tag, byte[] Value)[] Fields(byte kind = 1, int payloadBytes = 96) =>
    [
        (1, Pattern(16, 1)), (2, Pattern(32, 17)), (3, Pattern(32, 33)),
        (4, Pattern(32, 49)), (5, Pattern(32, 65)), (6, ManualMessagingWire.U64(1)),
        (7, [1]), (8, [kind]), (9, Pattern(payloadBytes, 81)),
        (10, new byte[3826 - payloadBytes]), (11, Pattern(32, 97)),
    ];

    private static byte[] Pattern(int length, int seed) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index * 17))).ToArray();

    private static byte[] Mutate(byte[] source, string mutation)
    {
        // Walk only the independent, valid manual fixture, never a hostile length.
        var header = new int[12];
        var offset = 12;
        for (var tag = 1; tag <= 11; tag++)
        {
            header[tag] = offset;
            offset += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(source.AsSpan(offset + 4, 4)));
        }
        switch (mutation)
        {
            case "remove final byte": return source[..^1];
            case "append zero byte": return [.. source, 0];
            case "change byte0": source[0] ^= 1; break;
            case "set version2": source[5] = 2; break;
            case "set suite0x0202": source[7] = 2; break;
            case "set fieldCount10": source[9] = 10; break;
            case "set header reserved1": source[11] = 1; break;
            case "set tag2=1": source[header[2] + 1] = 1; break;
            case "set tag11=12": source[header[11] + 1] = 12; break;
            case "set tag9 length=u32max": source.AsSpan(header[9] + 4, 4).Fill(0xff); break;
            case "zero tag1": source.AsSpan(header[1] + 8, 16).Clear(); break;
            case "copy tag3 to tag4": source.AsSpan(header[3] + 8, 32).CopyTo(source.AsSpan(header[4] + 8, 32)); break;
            case "zero tag6": source.AsSpan(header[6] + 8, 8).Clear(); break;
            case "set tag6=u64max": source.AsSpan(header[6] + 8, 8).Fill(0xff); break;
            case "set tag7=0": source[header[7] + 8] = 0; break;
            case "set tag7=3": source[header[7] + 8] = 3; break;
            case "set tag8=0": source[header[8] + 8] = 0; break;
            case "set tag8=2": source[header[8] + 8] = 2; break;
            case "set tag8=4": source[header[8] + 8] = 4; break;
            case "set tag8=255": source[header[8] + 8] = 255; break;
            case "set Header tag8=5": source[header[8] + 8] = 5; break;
            case "set first padding byte1": source[header[10] + 8] = 1; break;
            default: throw new InvalidOperationException("Frozen mutation lacks an executable witness.");
        }
        return source;
    }

    private static JsonDocument ReadSpec(string file) => JsonDocument.Parse(
        File.ReadAllBytes(XPointNetworkFrozenVectorManifest.FindSpec(file)));
}
