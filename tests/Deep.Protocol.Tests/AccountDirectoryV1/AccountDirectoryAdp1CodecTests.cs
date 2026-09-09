using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Tests.XPointNetworkV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryAdp1CodecTests
{
    [Fact]
    public void NonMembership_DecodesExactClosedShapeAndKeepsDefensiveCopies()
    {
        var canonical = NonMembership();
        var decoded = AccountDirectoryAdp1Codec.Decode(canonical);

        Assert.Equal(719, canonical.Length);
        Assert.Equal(ExpectedLength(Fields(canonical)), canonical.Length);
        Assert.Equal((ushort)15, BinaryPrimitives.ReadUInt16BigEndian(canonical.AsSpan(8)));
        Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership, decoded.ResultKind);
        Assert.Null(decoded.CurrentValue);
        Assert.False(decoded.HasLkg);
        Assert.Empty(decoded.ConsistencyProofNodes);
        Assert.Empty(decoded.SparseMapSiblings);
        Assert.Equal(canonical, AccountDirectoryAdp1Codec.Encode(decoded));

        var networkCopy = decoded.NetworkId.ToArray();
        networkCopy[0] ^= 1;
        canonical[ValueOffset(canonical, 1)] ^= 1;
        Assert.NotEqual(networkCopy, decoded.NetworkId.ToArray());
        Assert.NotEqual(canonical, decoded.CanonicalBytes.ToArray());
    }

    [Fact]
    public void CurrentValue_DecodesFullTypedClosureTransitionAndProof()
    {
        var fixture = CurrentValue(deviceCount: 2);
        var decoded = AccountDirectoryAdp1Codec.Decode(fixture.Canonical);
        var current = Assert.IsType<AccountDirectoryAdp1CurrentValue>(decoded.CurrentValue);

        Assert.Equal(4_987, fixture.Canonical.Length);
        Assert.Equal(ExpectedLength(Fields(fixture.Canonical)), fixture.Canonical.Length);
        Assert.Equal((ushort)28, BinaryPrimitives.ReadUInt16BigEndian(fixture.Canonical.AsSpan(8)));
        Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue, decoded.ResultKind);
        Assert.Equal(2, current.Devices.Count);
        Assert.Equal(2, current.ExactDpd1Records.Count);
        Assert.Equal(fixture.DidHash, current.ExactDid1Hash.ToArray());
        Assert.Equal(fixture.DidAddress, current.Did1AddressPublicKey.ToArray());
        Assert.Equal(0UL, current.AppendLogIndex);
        Assert.Equal(fixture.LeafKey, current.Transition.DirectoryLeafKey.ToArray());
        Assert.Equal(fixture.Canonical, AccountDirectoryAdp1Codec.Encode(decoded));
    }

    [Fact]
    public void Decode_RejectsEnvelopeUnknownTrailingAndEveryCommonShapeViolation()
    {
        var canonical = NonMembership();
        Action<byte[]>[] mutations =
        [
            value => value[0] = (byte)'X',
            value => BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 2),
            value => BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(6), 0x0202),
            value => BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(8), 14),
            value => BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(10), 1),
            value => BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(FieldHeader(value, 1)), 2),
            value => BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(FieldHeader(value, 1) + 2), 1),
            value => BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(FieldHeader(value, 3) + 4), 31),
            value => value[ValueOffset(value, 2)] = 1,
            value => Array.Clear(value, ValueOffset(value, 1), 16),
            value => Array.Clear(value, ValueOffset(value, 3), 32),
            value => Array.Clear(value, ValueOffset(value, 15), 32),
        ];

        foreach (var mutation in mutations)
        {
            var candidate = canonical.ToArray();
            mutation(candidate);
            Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(candidate));
        }
        Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(canonical[..^1]));
        Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(canonical.Concat([byte.MinValue]).ToArray()));
        Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(new byte[65_536]));
    }

    [Fact]
    public void Decode_RejectsEveryMalformedDeclaredFieldLengthInBothClosedVariants()
    {
        foreach (var canonical in new[] { NonMembership(), CurrentValue(deviceCount: 1).Canonical })
        {
            var count = BinaryPrimitives.ReadUInt16BigEndian(canonical.AsSpan(8));
            for (var tag = 1; tag <= count; tag++)
            {
                var candidate = canonical.ToArray();
                var header = FieldHeader(candidate, tag);
                var length = BinaryPrimitives.ReadUInt32BigEndian(candidate.AsSpan(header + 4));
                BinaryPrimitives.WriteUInt32BigEndian(candidate.AsSpan(header + 4), length == 0 ? 1u : length - 1);
                Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(candidate));
            }
        }
    }

    [Fact]
    public void Decode_RejectsLkgModeCountBitmapAndSparseCanonicalityViolations()
    {
        var canonical = NonMembership();
        var cases = new List<byte[]>
        {
            Mutate(canonical, value => BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(ValueOffset(value, 5)), 1)),
            Mutate(canonical, value => value[ValueOffset(value, 6)] = 1),
            Mutate(canonical, value => value[ValueOffset(value, 12)] = 2),
            Mutate(canonical, value => value[ValueOffset(value, 13)] = 1),
            Mutate(canonical, value => value[ValueOffset(value, 7)] = 1),
            Mutate(canonical, value => value[ValueOffset(value, 9)] = 0x80),
            Mutate(canonical, value => BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(ValueOffset(value, 10)), 1)),
        };

        var fields = Fields(canonical);
        fields[8] = new byte[32]; fields[8][0] = 0x80;
        fields[9] = U16(1);
        fields[10] = IndependentEmptyLeaf();
        cases.Add(Write("ADP1", 0x0201, fields));

        foreach (var candidate in cases)
            Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(candidate));
    }

    [Fact]
    public void EmptyTreeLkg_IsDistinctFromNoLkgAndCarriesProtectedAdhCoreHash()
    {
        var fields = Fields(NonMembership());
        fields[4] = U64(0);
        fields[5] = Bytes(32, 0x6a);
        fields[11] = [1];
        var canonical = Write("ADP1", 0x0201, fields);

        var decoded = AccountDirectoryAdp1Codec.Decode(canonical);
        Assert.True(decoded.HasLkg);
        Assert.Equal(0UL, decoded.CallerLkgTreeSize);
        Assert.Equal(Bytes(32, 0x6a), decoded.CallerLkgAdh1CoreHash.ToArray());

        fields[5] = new byte[32];
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            AccountDirectoryAdp1Codec.Decode(Write("ADP1", 0x0201, fields)));

        fields[5] = Bytes(32, 0x6a);
        fields[6] = [1]; fields[7] = Bytes(32, 0x7a);
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            AccountDirectoryAdp1Codec.Decode(Write("ADP1", 0x0201, fields)));
    }

    [Fact]
    public void ModeZeroConsistencyProof_EnforcesInclusiveSixtyFourNodeBound()
    {
        var fields = Fields(NonMembership());
        fields[4] = U64(1); fields[5] = Bytes(32, 0x7b); fields[11] = [1];
        fields[6] = [64]; fields[7] = Bytes(64 * 32, 0x7c);
        var decoded = AccountDirectoryAdp1Codec.Decode(Write("ADP1", 0x0201, fields));
        Assert.Equal(64, decoded.ConsistencyProofNodes.Count);

        fields[6] = [65]; fields[7] = Bytes(65 * 32, 0x7d);
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            AccountDirectoryAdp1Codec.Decode(Write("ADP1", 0x0201, fields)));
    }

    [Fact]
    public void CurrentValue_AcceptsMaximumFiveDeviceClosure()
    {
        var decoded = AccountDirectoryAdp1Codec.Decode(CurrentValue(deviceCount: 5).Canonical);
        Assert.Equal(5, decoded.CurrentValue!.Devices.Count);
    }

    [Fact]
    public void CurrentValue_RejectsArtifactListIdentifierAndTransitionMismatches()
    {
        var fixture = CurrentValue(deviceCount: 2);
        var canonical = fixture.Canonical;
        Action<byte[]>[] mutations =
        [
            value => value[ValueOffset(value, 16) + 20] ^= 1,
            value => value[ValueOffset(value, 17)] ^= 1,
            value => Array.Clear(value, ValueOffset(value, 18), 32),
            value => value[ValueOffset(value, 19)] = (byte)'X',
            value => value[ValueOffset(value, 20)] = (byte)'X',
            value => value[ValueOffset(value, 21)] = (byte)'X',
            value => value[ValueOffset(value, 22)] = (byte)'X',
            value => value[ValueOffset(value, 23)] = 1,
            value => BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(ValueOffset(value, 24)), 775),
            value => value[ValueOffset(value, 24) + 4 + 100] ^= 1,
            value => value[ValueOffset(value, 25) + 42] = (byte)'A',
            value => value[ValueOffset(value, 25) + 80 + 6] ^= 1,
            value => value[ValueOffset(value, 25) + 150] ^= 1,
            value => BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(ValueOffset(value, 26)), 1),
            value => value[ValueOffset(value, 27)] = 1,
        ];

        foreach (var mutation in mutations)
        {
            var candidate = canonical.ToArray();
            mutation(candidate);
            Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(candidate));
        }

        var reordered = Fields(canonical);
        var list = reordered[23];
        var firstLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(list));
        var secondOffset = 4 + firstLength;
        reordered[23] = Join(list.AsSpan(secondOffset).ToArray(), list.AsSpan(0, secondOffset).ToArray());
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            AccountDirectoryAdp1Codec.Decode(Write("ADP1", 0x0201, reordered)));

        var tooMany = Fields(canonical);
        tooMany[22] = [6];
        Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
            AccountDirectoryAdp1Codec.Decode(Write("ADP1", 0x0201, tooMany)));
    }

    [Fact]
    public void CurrentValue_SuccessorTransitionRequiresExactPreviousAdcReference()
    {
        var fixture = CurrentValue(deviceCount: 1, successor: true);
        var decoded = AccountDirectoryAdp1Codec.Decode(fixture.Canonical);
        Assert.True(decoded.CurrentValue!.Transition.PreviousAdc1Reference.Span.IndexOfAnyExcept((byte)0) >= 0);

        var candidate = fixture.Canonical.ToArray();
        candidate[ValueOffset(candidate, 25) + 42 + 6] ^= 1;
        Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(candidate));

        var genesis = CurrentValue(deviceCount: 1).Canonical;
        var genesisWithPrevious = genesis.ToArray();
        Reference("ADC1", Bytes(32, 0x7b)).CopyTo(genesisWithPrevious, ValueOffset(genesisWithPrevious, 25) + 42);
        Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(genesisWithPrevious));
    }

    [Fact]
    public void ModeOne_RequiresCanonicalBoundedAfpWithExactCrossLinksAndMembership()
    {
        var network = XPointNetworkTestRecords.Id(1, 16);
        var key = Bytes(32, 0x31);
        var dtt = Bytes(32, 0x32);
        var lkgHash = Bytes(32, 0x33);
        var lkgTuple = Join(U64(0), U64(1), lkgHash);
        var mapRoot = AccountDirectorySparseMap.EmptyMapRoot.ToArray();
        var xnaBytes = XPointNetworkTestRecords.CreateXna(1, 1, 1);
        var xna = XPointNetworkCodec.Parse<Xna1Record>(xnaBytes);
        var xnaReference = Reference("XNA1", xna.CoreHash.Span);
        var provisionalHead = Head(network, 1, 1, Bytes(32, 0x34), mapRoot, xnaReference);
        var headReference = Reference("ADH1", AccountDirectoryCrypto.ComputeAdh1CoreHash(provisionalHead));
        var sourceLeafInput = Join([0], lkgTuple);
        var sourceRoot = SHA256.HashData(sourceLeafInput);
        var adf = new AccountDirectoryAdf1(network, 0, new byte[32], 0, 0, 1,
            sourceRoot, headReference, provisionalHead.TreeSize, provisionalHead.AppendLogMerkleRoot.Span,
            provisionalHead.CurrentValueMapRoot.Span, xnaReference, 10, 1,
            [new AccountDirectoryAdf1RootReceipt(Bytes(32, 0x35), Bytes(64, 0x36))]);
        var afp = Write("AFP1", 0x0201,
        [
            network, lkgTuple, AccountDirectoryCrypto.ComputeAdh1CoreHash(provisionalHead), [1],
            Lp32(xnaBytes), [1], Lp32(AccountDirectoryAdf1Codec.Encode(adf)), U64(0), [0], [], dtt,
            Lp32(AccountDirectoryAdh1Codec.Encode(provisionalHead)),
        ]);
        var canonical = Write("ADP1", 0x0201,
        [
            network, [2], key, AccountDirectoryAdh1Codec.Encode(provisionalHead), U64(1), lkgHash,
            [0], [], new byte[32], U16(0), [], [1], [1], afp, dtt,
        ]);

        var decoded = AccountDirectoryAdp1Codec.Decode(canonical);
        Assert.Equal(AccountDirectoryAdp1HistoryMode.ForwardCheckpoint, decoded.HistoryMode);
        Assert.Equal(afp, decoded.ExactAfp1.ToArray());

        var opaque = Fields(canonical); opaque[13] = Bytes(12, 0x44);
        Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(Write("ADP1", 0x0201, opaque)));
        var wrongDtt = Fields(canonical); wrongDtt[14][0] ^= 1;
        Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(Write("ADP1", 0x0201, wrongDtt)));
        var wrongLkg = Fields(canonical); BinaryPrimitives.WriteUInt64BigEndian(wrongLkg[4], 2);
        Assert.Throws<AccountDirectoryAdp1FormatException>(() => AccountDirectoryAdp1Codec.Decode(Write("ADP1", 0x0201, wrongLkg)));

        foreach (var mutateAfp in new Action<byte[][]>[]
        {
            fields => fields[3] = [0],
            fields => fields[3] = [65],
            fields => fields[5] = [0],
            fields => fields[5] = [65],
            fields => fields[7] = U64(1),
            fields => fields[8] = [1],
            fields => BinaryPrimitives.WriteUInt32BigEndian(fields[4], uint.MaxValue),
            fields => BinaryPrimitives.WriteUInt32BigEndian(fields[6], uint.MaxValue),
        })
        {
            var outer = Fields(canonical);
            var afpFields = Fields(outer[13]);
            mutateAfp(afpFields);
            outer[13] = Write("AFP1", 0x0201, afpFields);
            Assert.Throws<AccountDirectoryAdp1FormatException>(() =>
                AccountDirectoryAdp1Codec.Decode(Write("ADP1", 0x0201, outer)));
        }
    }

    private static byte[] NonMembership()
    {
        var network = Bytes(16, 0x11);
        var root = AccountDirectorySparseMap.EmptyMapRoot.ToArray();
        var head = Head(network, 0, 1, Bytes(32, 0x12), root, Reference("XNA1", Bytes(32, 0x13)));
        return Write("ADP1", 0x0201,
        [
            network, [2], Bytes(32, 0x14), AccountDirectoryAdh1Codec.Encode(head), U64(0), new byte[32],
            [0], [], new byte[32], U16(0), [], [0], [0], [], Bytes(32, 0x15),
        ]);
    }

    private static CurrentFixture CurrentValue(int deviceCount, bool successor = false)
    {
        var network = Bytes(16, 0x21);
        var account = Bytes(32, 0x22);
        var leafKey = Bytes(32, 0x23);
        var dpaBytes = Dpa(network);
        var dpa = IdentityCodec.DecodeAccountCertificate(dpaBytes);
        var drsBytes = Drs(network, account);
        var drs = IdentityCodec.DecodeRevocationSnapshot(drsBytes);
        var dpaReference = ApplicationCoreCodec.CreateArtifactReference(1, 644, dpa.CanonicalHash.Span);
        var drsReference = ApplicationCoreCodec.CreateArtifactReference(4, checked((uint)drsBytes.Length), drs.CanonicalHash.Span);

        var devices = Enumerable.Range(0, deviceCount).Select(index => Bytes(32, checked((byte)(0x30 + index)))).ToArray();
        var dpdBytes = devices.Select((device, index) => Dpd(network, account, device, drsReference, checked((byte)(0x40 + index)))).ToArray();
        var dpdReferences = dpdBytes.Select(bytes =>
        {
            var parsed = IdentityCodec.DecodeDeviceCertificate(bytes);
            return ApplicationCoreCodec.CreateArtifactReference(2, 776, parsed.CanonicalHash.Span);
        }).ToArray();
        var entries = devices.Select((device, index) => new DeviceDirectoryEntry(device, dpdReferences[index])).ToArray();
        var dmd = ApplicationCoreCodec.AuthorDmd1(network, account, 1, dpaReference, drsReference,
            1, new byte[32], entries, 100, Bytes(64, 0x50));
        var did = ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x51), Bytes(16, 0x52));
        var dab = ApplicationCoreCodec.AuthorDab1(did.RecordHash.Span, Bytes(32, 0x53), 0,
            new byte[32], account, 1, dpaReference, Bytes(64, 0x54), Bytes(64, 0x55));
        var predecessorHash = successor ? Bytes(32, 0x5a) : new byte[32];
        var checkpointGeneration = successor ? 1UL : 0UL;
        var adc = new AccountDirectoryAdc1(network, leafKey, 1, checkpointGeneration, predecessorHash,
            Reference("DPA1", dpa.CanonicalHash.Span), Reference("DRS1", drs.CanonicalHash.Span),
            dmd.RecordHash.Span, dab.RecordHash.Span, Bytes(32, 0x56), 100, 1, Bytes(64, 0x57));
        var adcBytes = AccountDirectoryAdc1Codec.Encode(adc);
        var adcReference = Reference("ADC1", SHA256.HashData(adcBytes));
        var bitmap = new byte[32];
        var mapRoot = AccountDirectorySparseMap.ComputePresentRoot(leafKey, adcReference, bitmap, []);
        var previousReference = successor ? Reference("ADC1", predecessorHash) : new byte[38];
        var transition = Join(U16(1), U64(0), leafKey, previousReference, adcReference,
            AccountDirectorySparseMap.EmptyMapRoot.ToArray(), mapRoot);
        var commitment = DomainHash("Deep/AccountDirectory/V1/transition", transition);
        var appendRoot = AccountDirectoryRfc6962.ComputeLeafHash(commitment);
        var head = Head(network, 0, 1, appendRoot, mapRoot, Reference("XNA1", Bytes(32, 0x58)));
        var list = Join(dpdBytes.Select(Lp32).ToArray());
        var canonical = Write("ADP1", 0x0201,
        [
            network, [1], leafKey, AccountDirectoryAdh1Codec.Encode(head), U64(0), new byte[32],
            [0], [], bitmap, U16(0), [], [0], [0], [], Bytes(32, 0x59), adcBytes,
            did.RecordHash.ToArray(), did.AddressPublicKey.ToArray(), dab.CanonicalBytes.ToArray(), dpaBytes, drsBytes, dmd.CanonicalBytes.ToArray(),
            [checked((byte)deviceCount)], list, transition, U64(0), [0], [],
        ]);
        return new(canonical, leafKey, did.RecordHash.ToArray(), did.AddressPublicKey.ToArray());
    }

    private static AccountDirectoryAdh1 Head(byte[] network, ulong generation, ulong treeSize, byte[] appendRoot, byte[] mapRoot, byte[] xnaReference) =>
        new(network, generation, generation == 0 ? new byte[32] : Bytes(32, 0x70), treeSize,
            appendRoot, mapRoot, xnaReference, Bytes(32, 0x71), 10, 20, 1,
            [new AccountDirectoryAdh1WitnessEntry(Bytes(32, 0x72), Bytes(64, 0x73))]);

    private static byte[] Dpa(byte[] network)
    {
        var fields = Minimum(RecordDefinitions.Dpa1);
        fields[0] = network; fields[1] = U64(1); fields[2] = U64(1);
        fields[4] = Bytes(32, 0x81); fields[5] = Bytes(32, 0x82); fields[6] = Bytes(32, 0x83);
        fields[7] = Bytes(32, 0x84); fields[8] = Bytes(32, 0x85); fields[9] = U64(1);
        fields[10] = U64(1); fields[11] = U16(1);
        return CanonicalGrammar.Encode(RecordDefinitions.Dpa1, fields);
    }

    private static byte[] Drs(byte[] network, byte[] account)
    {
        var fields = Minimum(RecordDefinitions.Drs1);
        fields[0] = network; fields[1] = account; fields[2] = U64(1); fields[3] = U64(1);
        fields[4] = U64(100); fields[7] = Bytes(32, 0x86);
        return CanonicalGrammar.Encode(RecordDefinitions.Drs1, fields);
    }

    private static byte[] Dpd(
        byte[] network,
        byte[] account,
        byte[] device,
        ApplicationArtifactReference drsReference,
        byte seed)
    {
        var fields = Minimum(RecordDefinitions.Dpd1);
        fields[0] = network; fields[1] = account; fields[2] = U64(1); fields[3] = device; fields[4] = U64(1);
        fields[5] = Bytes(32, seed); fields[6] = Bytes(32, checked((byte)(seed + 1))); fields[7] = Bytes(32, checked((byte)(seed + 2)));
        fields[10] = Bytes(32, checked((byte)(seed + 3))); fields[11] = U64(1); fields[12] = drsReference.CanonicalBytes;
        fields[13] = U64(0); fields[15] = U64(100); fields[16] = U64(1_000); fields[17] = U64(1); fields[18] = U16(1);
        fields[20] = Bytes(32, checked((byte)(seed + 4))); fields[21] = Bytes(64, checked((byte)(seed + 5))); fields[22] = Bytes(64, checked((byte)(seed + 6)));
        return CanonicalGrammar.Encode(RecordDefinitions.Dpd1, fields);
    }

    private static ReadOnlyMemory<byte>[] Minimum(RecordDefinition definition) =>
        definition.Fields.Select(field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

    private static byte[] Write(string magic, ushort suite, IReadOnlyList<byte[]> fields)
    {
        var result = new byte[12 + fields.Sum(static field => 8 + field.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), suite);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(result, offset);
            offset += fields[index].Length;
        }
        return result;
    }

    private static byte[][] Fields(byte[] canonical)
    {
        var count = BinaryPrimitives.ReadUInt16BigEndian(canonical.AsSpan(8));
        var result = new byte[count][];
        for (var index = 0; index < count; index++)
        {
            var offset = ValueOffset(canonical, index + 1);
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.AsSpan(offset - 4)));
            result[index] = canonical.AsSpan(offset, length).ToArray();
        }
        return result;
    }

    private static int ExpectedLength(IEnumerable<byte[]> fields) => 12 + fields.Sum(static value => 8 + value.Length);
    private static int FieldHeader(ReadOnlySpan<byte> canonical, int tag) { var offset = 12; for (var current = 1; current < tag; current++) offset += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical[(offset + 4)..])); return offset; }
    private static int ValueOffset(ReadOnlySpan<byte> canonical, int tag) => FieldHeader(canonical, tag) + 8;
    private static byte[] Mutate(byte[] source, Action<byte[]> mutation) { var result = source.ToArray(); mutation(result); return result; }
    private static byte[] Lp32(byte[] value) => Join(U32(checked((uint)value.Length)), value);
    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash) => Join(Encoding.ASCII.GetBytes(magic), U16(1), hash.ToArray());
    private static byte[] U16(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    private static byte[] U32(uint value) { var result = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(result, value); return result; }
    private static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static byte[] Bytes(int length, byte seed) { var result = new byte[length]; for (var index = 0; index < length; index++) result[index] = unchecked((byte)(seed + index)); return result; }
    private static byte[] Join(params byte[][] values) { var result = new byte[values.Sum(static value => value.Length)]; var offset = 0; foreach (var value in values) { value.CopyTo(result, offset); offset += value.Length; } return result; }
    private static byte[] IndependentEmptyLeaf() => DomainHash("Deep/AccountDirectory/V1/map-empty-leaf", []);
    private static byte[] DomainHash(string domain, ReadOnlySpan<byte> payload) { var label = Encoding.ASCII.GetBytes(domain); var input = new byte[label.Length + 5 + payload.Length]; label.CopyTo(input, 0); BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(label.Length + 1), checked((uint)payload.Length)); payload.CopyTo(input.AsSpan(label.Length + 5)); return SHA256.HashData(input); }

    private sealed record CurrentFixture(byte[] Canonical, byte[] LeafKey, byte[] DidHash, byte[] DidAddress);
}
