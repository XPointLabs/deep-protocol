using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class ApplicationCoreIndependentVectorTests
{
    [Fact]
    public void EveryActiveRecord_MatchesManualCanonicalConstruction()
    {
        var did = ApplicationCoreCodec.AuthorDid1(B(32, 0x11), B(16, 0x12));
        Assert.Equal(ManualRecord("DID1", B(32, 0x11), B(16, 0x12)), did.CanonicalBytes.ToArray());

        var dpa = ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpa1, 644, 0x21);
        var dab = ApplicationCoreCodec.AuthorDab1(B(32, 0x13), B(32, 0x14), 0, new byte[32],
            B(32, 0x15), 1, dpa, B(64, 0x16), B(64, 0x17));
        Assert.Equal(ManualRecord("DAB1", B(32, 0x13), B(32, 0x14), U64(0), new byte[32],
            B(32, 0x15), U64(1), dpa.CanonicalBytes.ToArray(), B(64, 0x16), B(64, 0x17)),
            dab.CanonicalBytes.ToArray());

        var network = B(16, 0x31);
        var account = B(32, 0x32);
        var drs = ApplicationCoreFixture.Revocations(network, account);
        var drsRef = ApplicationCoreCodec.CreateArtifactReference((ushort)ArtifactType.Drs1,
            checked((uint)drs.CanonicalBytes.Length), drs.CanonicalHash.Span);
        var dpdRef = ApplicationCoreFixture.Reference((ushort)ArtifactType.Dpd1, 776, 0x33);
        var entry = new DeviceDirectoryEntry(B(32, 0x34), dpdRef);
        var dmd = ApplicationCoreCodec.AuthorDmd1(network, account, 1, dpa, drsRef, 1,
            new byte[32], [entry], 100, B(64, 0x35));
        var entryBytes = Concat(B(32, 0x34), dpdRef.CanonicalBytes.ToArray());
        Assert.Equal(ManualRecord("DMD1", network, account, U64(1), dpa.CanonicalBytes.ToArray(),
            drsRef.CanonicalBytes.ToArray(), U64(1), new byte[32], U16(1), entryBytes, U16(0x0201),
            U64(100), B(64, 0x35)), dmd.CanonicalBytes.ToArray());

        var dabRef = ApplicationCoreFixture.Reference(ApplicationCoreCodec.Dab1ArtifactTypeCode, 394, 0x41);
        var dca = ApplicationCoreCodec.AuthorDca1(network, account, dpa, 1, B(32, 0x42), B(32, 0x43),
            B(32, 0x44), 3, 10, 20, 30, B(64, 0x45), B(32, 0x46), dabRef);
        Assert.Equal(ManualRecord("DCA1", network, account, dpa.CanonicalBytes.ToArray(), U64(1),
            B(32, 0x42), B(32, 0x43), B(32, 0x44), [3], U64(10), U64(20), U64(30),
            B(64, 0x45), B(32, 0x46), dabRef.CanonicalBytes.ToArray()), dca.CanonicalBytes.ToArray());

        var dao = ApplicationCoreCodec.AuthorDao1(network, B(32, 0x51), B(32, 0x52), B(32, 0x53),
            B(24, 0x54), B(4529, 0x55));
        var manualDao = ManualRecord("DAO1", network, B(32, 0x51), B(32, 0x52), B(32, 0x53),
            B(24, 0x54), B(4529, 0x55));
        Assert.Equal("1344FC49FF76F7039E59ADF524E303A61DCA52977D2EE09199B8B21B3ACE03C6",
            Convert.ToHexString(SHA256.HashData(manualDao)));
        Assert.Equal(manualDao, dao.CanonicalBytes.ToArray());
    }

    [Fact]
    public void EveryActiveDmc2Kind_MatchesManualPayloadAndRecordVectors()
    {
        var network = B(16, 0x61);
        var account = B(32, 0x62);
        var device = B(32, 0x63);
        var drs = ApplicationCoreFixture.Revocations(network, account);
        var directory = ApplicationCoreFixture.Directory(network, account, device, drs);
        var id1 = B(32, 0x71);
        var id2 = B(32, 0x72);
        var nonce = B(32, 0x73);
        var target = B(32, 0x74);
        var activity = B(32, 0x75);
        var payloads = new (Dmc2Payload Payload, byte[] Manual)[]
        {
            (ApplicationCoreCodec.CreateSessionInitPayload(nonce, directory,
                SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl),
                Concat(nonce, directory.RecordHash.ToArray(), Lp32(directory.CanonicalBytes.ToArray()), U32(3))),
            (ApplicationCoreCodec.CreateMessageCreatePayload("hello"), Lp16("hello"u8.ToArray())),
            (ApplicationCoreCodec.CreateMessageEditPayload(target, "edited"),
                Concat(target, Lp16("edited"u8.ToArray()))),
            (ApplicationCoreCodec.CreateMessageDeletePayload(target, MessageDeleteScope.ConversationTombstone),
                Concat(target, [(byte)MessageDeleteScope.ConversationTombstone])),
            (ApplicationCoreCodec.CreateReactionSetPayload(target, ReactionOperation.Add, "👍"),
                Concat(target, [(byte)ReactionOperation.Add], Lp16(Encoding.UTF8.GetBytes("👍")))),
            (ApplicationCoreCodec.CreateReceiptDeliveredPayload([
                new Dmc2DeliveryReceiptEntry(id1, DeliveryReceiptStatus.StoreAccepted),
                new Dmc2DeliveryReceiptEntry(id2, DeliveryReceiptStatus.Materialized)]),
                Concat([2], id1, [(byte)DeliveryReceiptStatus.StoreAccepted], id2,
                    [(byte)DeliveryReceiptStatus.Materialized])),
            (ApplicationCoreCodec.CreateReceiptReadPayload([
                new Dmc2LogicalMessageReference(id1), new Dmc2LogicalMessageReference(id2)]),
                Concat([2], id1, id2)),
            (ApplicationCoreCodec.CreateTypingPayload(TypingOperation.Start, activity),
                Concat([(byte)TypingOperation.Start], activity)),
            (ApplicationCoreCodec.CreateDeviceListUpdatePayload(directory),
                Lp32(directory.CanonicalBytes.ToArray())),
            (ApplicationCoreCodec.CreateDeviceRevocationPayload(drs, directory),
                Concat(Lp32(drs.CanonicalBytes.ToArray()), Lp32(directory.CanonicalBytes.ToArray()))),
        };

        foreach (var (payload, manualPayload) in payloads)
        {
            Assert.Equal(manualPayload, payload.CanonicalBytes.ToArray());
            var expires = payload.Kind is Dmc2ContentKind.SessionInit or Dmc2ContentKind.Typing ? 2_000UL : 0UL;
            var flags = payload.Kind == Dmc2ContentKind.Typing ? Dmc2Flags.Silent : Dmc2Flags.None;
            var authored = ApplicationCoreCodec.AuthorDmc2(network, B(32, 0x81), B(32, 0x82),
                account, device, 1, 1_000, expires, flags, [], payload);
            var manualRecord = ManualRecord("DMC2", network, B(32, 0x81), B(32, 0x82), account, device,
                U64(1), U64(1_000), U64(expires), U16((ushort)payload.Kind), U32((uint)flags), [], manualPayload);
            Assert.Equal(manualRecord, authored.CanonicalBytes.ToArray());
            Assert.Equal(Convert.ToHexString(SHA256.HashData(manualRecord)),
                Convert.ToHexString(SHA256.HashData(authored.CanonicalBytes.Span)));
        }
    }

    private static byte[] ManualRecord(string magic, params byte[][] fields)
    {
        var total = checked(12 + fields.Sum(field => 8 + field.Length));
        var result = new byte[total];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6, 2), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8, 2), checked((ushort)fields.Length));
        var offset = 12;
        for (var index = 0; index < fields.Length; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset, 2), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset + 4, 4), checked((uint)fields[index].Length));
            fields[index].CopyTo(result, offset + 8);
            offset += 8 + fields[index].Length;
        }
        return result;
    }

    private static byte[] B(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U32(uint value) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
    private static byte[] Lp16(byte[] value) => Concat(U16(checked((ushort)value.Length)), value);
    private static byte[] Lp32(byte[] value) => Concat(U32(checked((uint)value.Length)), value);
    private static byte[] Concat(params byte[][] values)
    {
        var output = new byte[values.Sum(value => value.Length)];
        var offset = 0;
        foreach (var value in values) { value.CopyTo(output, offset); offset += value.Length; }
        return output;
    }
}
