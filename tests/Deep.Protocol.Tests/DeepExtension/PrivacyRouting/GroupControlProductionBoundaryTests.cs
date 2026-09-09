using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.DeepExtension.PrivacyRouting;

public sealed class GroupControlProductionBoundaryTests
{
    [Fact]
    public void PublicFactoryMintsExactGroupControlPathAndTerminalCapabilities()
    {
        var fixture = PlacementFixture.Create();
        var placement = GroupControlPlacementVerifier.Verify(fixture.Network, fixture.Rendezvous);
        Assert.Empty(typeof(VerifiedGroupControlPlacement).GetConstructors());
        Assert.Equal(2, placement.ReplicaNodeIds.Count);

        var path = OnionPathContextFactory.CreateGroupControl(
            fixture.Network, placement, fixture.Ingress.NodeId, fixture.Core.NodeId,
            placement.ReplicaNodeIds[0]);
        var requestBytes = GroupWrite(fixture.Network.NetworkId.Span);
        var request = OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Network, OnionOperation.GroupControl, requestBytes);
        path.EnsureUsable(request);
        Assert.Equal(OnionOperation.GroupControl, request.Operation);

        var resultBytes = GroupWriteResult(requestBytes);
        var result = OnionTerminalPayloadVerifierV1.VerifySuccess(request, resultBytes);
        Assert.Equal(OnionOperation.GroupControl, result.Operation);
        Assert.Equal(resultBytes, result.Body.ToArray());
    }

    [Fact]
    public void PublicFactoryRejectsOperationPathExitAndContextSmuggling()
    {
        var fixture = PlacementFixture.Create();
        var placement = GroupControlPlacementVerifier.Verify(fixture.Network, fixture.Rendezvous);
        var path = OnionPathContextFactory.CreateGroupControl(
            fixture.Network, placement, fixture.Ingress.NodeId, fixture.Core.NodeId,
            placement.ReplicaNodeIds[0]);

        var contact = OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Network, OnionOperation.ContactResolve,
            ContactQuery(fixture.Network.NetworkId.Span));
        Assert.Equal("request-path-mismatch",
            Assert.Throws<OnionBoundaryException>(() => path.EnsureUsable(contact)).Code);
        Assert.Equal("path-exit-placement-mismatch",
            Assert.Throws<OnionBoundaryException>(() => OnionPathContextFactory.CreateGroupControl(
                fixture.Network, placement, fixture.Ingress.NodeId, fixture.Core.NodeId,
                fixture.NonReplicaExit.NodeId)).Code);
        Assert.Equal("path-role-invalid",
            Assert.Throws<OnionBoundaryException>(() => OnionPathContextFactory.CreateGroupControl(
                fixture.Network, placement, fixture.Ingress.NodeId, fixture.Core.NodeId,
                fixture.Core.NodeId)).Code);
        Assert.Equal("path-node-duplicate",
            Assert.Throws<OnionBoundaryException>(() => OnionPathContextFactory.CreateGroupControl(
                fixture.Network, placement, fixture.Ingress.NodeId, fixture.Ingress.NodeId,
                placement.ReplicaNodeIds[0])).Code);

        var other = fixture.CloneNetworkContext();
        Assert.Equal("placement-context-mismatch",
            Assert.Throws<OnionBoundaryException>(() => OnionPathContextFactory.CreateGroupControl(
                other, placement, fixture.Ingress.NodeId, fixture.Core.NodeId,
                placement.ReplicaNodeIds[0])).Code);
    }

    [Fact]
    public void GroupPlacementRejectsChangedPmtAndTerminalPairingSubstitution()
    {
        var fixture = PlacementFixture.Create();
        var wrongClosure = fixture.CloneNetworkContext(changedPmt: true);
        Assert.Equal("group-placement-pmt-mismatch",
            Assert.Throws<OnionBoundaryException>(() =>
                GroupControlPlacementVerifier.Verify(wrongClosure, fixture.Rendezvous)).Code);

        var requestBytes = GroupWrite(fixture.Network.NetworkId.Span);
        var request = OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Network, OnionOperation.GroupControl, requestBytes);
        var changed = GroupWriteResult(requestBytes);
        changed[FieldOffset(changed, 3)] ^= 0x80;
        Assert.Throws<PrivacyRoutingProtocolException>(() =>
            OnionTerminalPayloadVerifierV1.VerifySuccess(request, changed));
        Assert.Throws<PrivacyRoutingProtocolException>(() =>
            OnionTerminalPayloadVerifierV1.VerifyRequest(
                fixture.Network, OnionOperation.ContactResolve, requestBytes));

        var queryBytes = GroupQuery(fixture.Network.NetworkId.Span);
        var query = OnionTerminalPayloadVerifierV1.VerifyRequest(
            fixture.Network, OnionOperation.GroupControl, queryBytes);
        var fetchResult = GroupFetchResult(queryBytes);
        Assert.Equal(fetchResult, OnionTerminalPayloadVerifierV1.VerifySuccess(query, fetchResult).Body.ToArray());
        Assert.Throws<PrivacyRoutingProtocolException>(() =>
            OnionTerminalPayloadVerifierV1.VerifySuccess(query, GroupWriteResult(requestBytes)));
    }

    [Fact]
    public async Task ProductionClientAuthorsExactWriteAndVerifiesTwoReplicaReceiptSet()
    {
        var fixture = PlacementFixture.Create();
        var group = await fixture.CreateGroupAsync();
        var placement = GroupControlPlacementVerifier.Verify(fixture.Network, fixture.Rendezvous);
        var sealedGcf1 = Fill(0x81, 64);
        var request = GroupControlProductionClient.AuthorWrite(new GroupControlWriteAuthoringRequest(
            group, placement, Fill(0x91, 32), 20, 40, 1, new byte[32], sealedGcf1, 80));

        Assert.Equal("GSW1", request.Record.Magic);
        Assert.Equal(group.Commit.Field(2).ToArray(), request.GroupId.ToArray());
        Assert.Equal(placement.ViewHash.ToArray(), request.Record.Field(3).ToArray());
        Assert.Equal(placement.PlacementHash.ToArray(), request.Record.Field(4).ToArray());
        Assert.Equal(fixture.Rendezvous.Record.Field(2).ToArray(), request.Record.Field(16).ToArray());
        Assert.Equal(fixture.Rendezvous.Record.ArtifactHash.ToArray(), request.Record.Field(17).ToArray());

        var exactResult = SignedGroupWriteResult(request, fixture);
        var verified = GroupControlProductionClient.VerifyResult(request, exactResult);
        Assert.Equal(GroupControlResultStatus.Committed, verified.Status);
        Assert.Equal(exactResult, verified.CanonicalBytes.ToArray());
    }

    [Fact]
    public async Task ProductionClientAuthorsExactQueryAndRejectsReceiptOrContextSubstitution()
    {
        var fixture = PlacementFixture.Create();
        var group = await fixture.CreateGroupAsync();
        var placement = GroupControlPlacementVerifier.Verify(fixture.Network, fixture.Rendezvous);
        var query = GroupControlProductionClient.AuthorQuery(new GroupControlQueryAuthoringRequest(
            group, placement, Fill(0x92, 32), 20, 40, 0, 64, 4));
        var fetched = GroupControlProductionClient.VerifyResult(query, GroupFetchResult(query.CanonicalBytes.Span));
        Assert.Equal(GroupControlResultStatus.Events, fetched.Status);

        var write = GroupControlProductionClient.AuthorWrite(new GroupControlWriteAuthoringRequest(
            group, placement, Fill(0x93, 32), 20, 40, 1, new byte[32], Fill(0x82, 64), 80));
        Assert.Equal("receipt-verification-failed", Assert.Throws<GroupControlClientException>(() =>
            GroupControlProductionClient.VerifyResult(write, SignedGroupWriteResult(write, fixture, tamperSignature: true))).Code);
        Assert.Equal("result-invalid", Assert.Throws<GroupControlClientException>(() =>
            GroupControlProductionClient.VerifyResult(query, SignedGroupWriteResult(write, fixture))).Code);

        var foreign = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create(2);
        var foreignOwner = foreign.Promote(foreign.Dcr);
        var foreignDevice = foreignOwner.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
        var foreignGroup = (await GroupProductionAuthor.AuthorGenesisAsync(new GroupGenesisAuthoringRequest(
            Fill(0xa0, 32), foreignOwner, foreignDevice.Span, "foreign", false, 60, 30,
            foreign.BootId, foreign.CurrentMonotonicSample), new CustodySigner(foreign.Device, foreignDevice.Span))).Transition;
        Assert.Equal("group-placement-mismatch", Assert.Throws<GroupControlClientException>(() =>
            GroupControlProductionClient.AuthorQuery(new GroupControlQueryAuthoringRequest(
                foreignGroup, placement, Fill(0x94, 32), 20, 40, 0, 1, 0))).Code);

        foreach (var type in new[] { typeof(VerifiedGroupControlWriteRequest),
                     typeof(VerifiedGroupControlQueryRequest), typeof(VerifiedGroupControlResult) })
            Assert.Empty(type.GetConstructors());
    }

    private sealed class PlacementFixture
    {
        private PlacementFixture() { }
        internal required VerifiedOnionNetworkContext Network { get; init; }
        internal required VerifiedGroupControlRendezvous Rendezvous { get; init; }
        internal required VerifiedNetworkNode Ingress { get; init; }
        internal required VerifiedNetworkNode Core { get; init; }
        internal required VerifiedNetworkNode NonReplicaExit { get; init; }
        internal required VerifiedNetworkNode[] Nodes { get; init; }
        internal required byte[] PmtReference { get; init; }
        internal required XPointNetworkProtectedLkg Lkg { get; init; }
        internal required OnionTrustedTimeLease Time { get; init; }
        internal required VerifiedContactBundleClosure Owner { get; init; }
        internal required KeyPair OwnerDeviceKey { get; init; }
        internal required byte[] BootId { get; init; }
        internal required ulong CurrentMonotonicSample { get; init; }
        internal required IReadOnlyDictionary<string, KeyPair> NodeIdentityKeys { get; init; }

        internal static PlacementFixture Create()
        {
            var contactFixture = Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create();
            var owner = contactFixture.Promote(contactFixture.Dcr);
            var networkId = owner.Directory.Record.NetworkId.ToArray();
            var ingressKey = PublicKeyAuth.GenerateKeyPair(Fill(0x91, 32));
            var coreKey = PublicKeyAuth.GenerateKeyPair(Fill(0x92, 32));
            var replicaAKey = PublicKeyAuth.GenerateKeyPair(Fill(0x93, 32));
            var replicaBKey = PublicKeyAuth.GenerateKeyPair(Fill(0x94, 32));
            var nonReplicaKey = PublicKeyAuth.GenerateKeyPair(Fill(0x95, 32));
            var ingress = Node(0x11, 0xa1, 0x31, 0x0003, 0xd1, ingressKey.PublicKey);
            var core = Node(0x22, 0xa2, 0x32, 0x0002, 0xd2, coreKey.PublicKey);
            var replicaA = Node(0x33, 0xa3, 0x33, 0x0004, 0xd3, replicaAKey.PublicKey);
            var replicaB = Node(0x44, 0xa4, 0x34, 0x0004, 0xd4, replicaBKey.PublicKey);
            var nonReplica = Node(0x55, 0xa5, 0x35, 0x0004, 0xd5, nonReplicaKey.PublicKey);
            var nodes = new[] { ingress, core, replicaA, replicaB, nonReplica };
            var pmtReference = Ref("PMT2", Fill(0x72, 32));
            var lkg = new XPointNetworkProtectedLkg(
                networkId, Ref("XNH1", Fill(0x73, 32)), 1, Fill(0x74, 32),
                Ref("XNV1", Fill(0x75, 32)), 0, Ref("XNA1", Fill(0x76, 32)));
            var time = new OnionTrustedTimeLease(TimeProvider.System, TimeSpan.FromMinutes(5), Fill(0xf0, 32));
            var closure = Closure(networkId, pmtReference, replicaA.NodeId, replicaB.NodeId);
            var network = new VerifiedOnionNetworkContext(networkId, time, nodes, closure, lkg, null);

            var device = owner.Directory.Identity.ActiveDevices.Single();
            var fields = new ReadOnlyMemory<byte>[]
            {
                networkId, Fill(0x61,32), Fill(0x62,32), U64(0), new byte[32], pmtReference,
                Fill(0x63,32), Fill(0x64,32), Fill(0x65,32), device.Certificate.DeviceId,
                Ref("DPD1", device.Certificate.CanonicalHash.Span), U64(20), U64(90), Fill(0x01,64)
            };
            var unsigned = (GroupControlRendezvousRecord)GroupCodec.Decode("GSR1", GroupRecord("GSR1", null, fields));
            fields[13] = PublicKeyAuth.SignDetached(unsigned.SignatureInput.ToArray(), contactFixture.Device.PrivateKey);
            var gsr = (GroupControlRendezvousRecord)GroupCodec.Decode("GSR1", GroupRecord("GSR1", null, fields));
            var rendezvous = GroupCodec.VerifyControlRendezvous(
                gsr, owner, contactFixture.BootId, contactFixture.CurrentMonotonicSample);
            return new PlacementFixture
            {
                Network = network, Rendezvous = rendezvous, Ingress = ingress, Core = core,
                NonReplicaExit = nonReplica, Nodes = nodes, PmtReference = pmtReference,
                Lkg = lkg, Time = time, Owner = owner, OwnerDeviceKey = contactFixture.Device,
                BootId = contactFixture.BootId, CurrentMonotonicSample = contactFixture.CurrentMonotonicSample,
                NodeIdentityKeys = new Dictionary<string, KeyPair>(StringComparer.Ordinal)
                {
                    [Convert.ToHexString(ingress.NodeId)] = ingressKey,
                    [Convert.ToHexString(core.NodeId)] = coreKey,
                    [Convert.ToHexString(replicaA.NodeId)] = replicaAKey,
                    [Convert.ToHexString(replicaB.NodeId)] = replicaBKey,
                    [Convert.ToHexString(nonReplica.NodeId)] = nonReplicaKey,
                }
            };
        }

        internal async Task<VerifiedGroupTransition> CreateGroupAsync()
        {
            var deviceId = Owner.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId;
            return (await GroupProductionAuthor.AuthorGenesisAsync(new GroupGenesisAuthoringRequest(
                Fill(0x60, 32), Owner, deviceId.Span, "control", false, 60, 30,
                BootId, CurrentMonotonicSample), new CustodySigner(OwnerDeviceKey, deviceId.Span))).Transition;
        }

        internal VerifiedOnionNetworkContext CloneNetworkContext(bool changedPmt = false)
        {
            var pmt = changedPmt ? Ref("PMT2", Fill(0x79, 32)) : PmtReference;
            return new VerifiedOnionNetworkContext(Network.NetworkId.Span, Time, Nodes,
                Closure(Network.NetworkId.ToArray(), pmt, Nodes[2].NodeId, Nodes[3].NodeId), Lkg, null);
        }

        private static VerifiedOnionNetworkClosure Closure(
            byte[] networkId, byte[] pmtReference, byte[] firstReplica, byte[] secondReplica) => new()
        {
            NetworkId = networkId, Policy = null!, View = null!, Head = null!, Pmt = null!,
            ViewCoreHash = Fill(0x70, 32), ViewCoreReference = Ref("XNV1", Fill(0x75, 32)),
            PmtArtifactReference = pmtReference, PmtNodeIds = [firstReplica, secondReplica],
            SelectionEpoch = 7, ReplicaCount = 2, HardUpperUnixSeconds = 90,
            Adh1CoreReference = Ref("ADH1", Fill(0x77, 32)), Dtt1CoreHash = Fill(0x78, 32),
            FreshnessBootId = Fill(0x79, 16), TrustedLowerUnixSeconds = 29,
            TrustedUpperUnixSeconds = 31, FreshnessMonotonicSample = 1,
            FreshnessDeadlineMonotonicSeconds = 60
        };
    }

    private static byte[] GroupWrite(ReadOnlySpan<byte> network)
    {
        var sealedRecord = Fill(0x81, 64);
        return GroupRecord("GSW1", [1,2,3,4,5,6,16,17,18,19,20,21,22],
            [network.ToArray(),Fill(0x21,32),Fill(0x41,32),Fill(0x61,32),U64(10),U64(20),
             Fill(0x81,32),Fill(0xa1,32),U64(1),new byte[32],SHA256.HashData(sealedRecord),
             Lp32(sealedRecord),U64(30)]);
    }

    private static byte[] GroupWriteResult(ReadOnlySpan<byte> request)
    {
        var decoded = (GroupControlWriteRecord)GroupCodec.Decode(request);
        return GroupRecord("GSS1", [1,2,3,4,5,6,7,8,16,17,18,19,20],
            [decoded.Field(1).ToArray(),decoded.Field(2).ToArray(),
             ContactCodec.Sha256Domain("Deep/ContactResolver/V1/request",request),U16(1),new byte[]{1},
             U64(15),U32(0),U16(4),new byte[]{1},decoded.Field(18).ToArray(),
             decoded.Field(20).ToArray(),U64(1),Fill(0xc0,96)]);
    }

    private static byte[] GroupQuery(ReadOnlySpan<byte> network) =>
        GroupRecord("GSQ1", [1,2,3,4,5,6,16,17,18,19,20],
            [network.ToArray(),Fill(0x31,32),Fill(0x41,32),Fill(0x51,32),U64(10),U64(20),
             Fill(0x61,32),Fill(0x71,32),U64(0),U16(64),U16(4)]);

    private static byte[] GroupFetchResult(ReadOnlySpan<byte> request)
    {
        var decoded = (GroupControlQueryRecord)GroupCodec.Decode(request);
        var body = Fill(0x91, 64); var bodyHash = SHA256.HashData(body);
        var events = Join(U64(1),new byte[32],bodyHash,U64(30),Lp32(body));
        return GroupRecord("GSS1", [1,2,3,4,5,6,7,8,16,17,18,19,20],
            [decoded.Field(1).ToArray(),decoded.Field(2).ToArray(),
             ContactCodec.Sha256Domain("Deep/ContactResolver/V1/request",request),U16(3),new byte[]{0},
             U64(15),U32(0),U16(4),new byte[]{2},U16(1),events,U64(1),new byte[]{0}]);
    }

    private static byte[] ContactQuery(ReadOnlySpan<byte> network) => Xiq1Codec.Encode(
        network, Fill(0x21,32), Fill(0x22,32), Fill(0x23,32), 10, 100,
        Fill(0x24,32), 0, Xiq1AntiSpamTokenType.None, [], ContactServicePaddingClass.Bytes256);

    private static byte[] GroupRecord(string magic, IReadOnlyList<int>? tags, IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        tags ??= Enumerable.Range(1, fields.Count).ToArray();
        var bytes = new byte[12 + fields.Sum(static field => 8 + field.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)tags[index]));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8; fields[index].Span.CopyTo(bytes.AsSpan(offset)); offset += fields[index].Length;
        }
        return GroupCodec.Decode(magic, bytes).CanonicalBytes.ToArray();
    }

    private static int FieldOffset(ReadOnlySpan<byte> record, ushort tag)
    {
        var offset = 12;
        for (var index = 0; index < BinaryPrimitives.ReadUInt16BigEndian(record[8..10]); index++)
        {
            var current = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(record.Slice(offset + 4, 4)));
            offset += 8; if (current == tag) return offset; offset += length;
        }
        throw new InvalidOperationException();
    }

    private static VerifiedNetworkNode Node(byte node, byte key, byte scalar, ushort roles, byte failure,
        ReadOnlySpan<byte> identityPublicKey) =>
        new(Fill(node,32),Fill(node,32),Fill((byte)(node+1),32),Fill(failure,32),Fill((byte)(node+2),32),
            1,4,Ipv4((byte)(node+3)),443,Fill((byte)(node+4),32),roles,1,1,1,7,Fill(key,32),
            ScalarMult.Base(Fill(scalar,32)),identityPublicKey.ToArray());

    private static byte[] SignedGroupWriteResult(VerifiedGroupControlWriteRequest request,
        PlacementFixture fixture, bool tamperSignature = false)
    {
        var requestHash = ContactCodec.Sha256Domain("Deep/ContactResolver/V1/request", request.CanonicalBytes.Span);
        var commitGeneration = U64(1);
        var tuple = Join(requestHash, request.Record.Field(18).ToArray(), request.Record.Field(20).ToArray(), commitGeneration);
        var signingInput = GroupCodec.SignatureInput("Deep/Group/V1/control-store-commit", tuple);
        var receipts = request.Placement.ReplicaNodeIds.OrderBy(static value => value, MemoryComparer.Instance)
            .Select(nodeId =>
            {
                var signature = PublicKeyAuth.SignDetached(signingInput,
                    fixture.NodeIdentityKeys[Convert.ToHexString(nodeId.Span)].PrivateKey);
                return Join(nodeId.ToArray(), signature);
            }).ToArray();
        var encodedReceipts = Join(receipts);
        if (tamperSignature) encodedReceipts[32] ^= 0x80;
        return GroupRecord("GSS1", [1,2,3,4,5,6,7,8,16,17,18,19,20],
            [request.Record.Field(1),request.Record.Field(2),requestHash,U16(1),new byte[]{1},
             U64(30),U32(0),U16(4),new byte[]{1},request.Record.Field(18),
             request.Record.Field(20),commitGeneration,encodedReceipts]);
    }

    private sealed class CustodySigner(KeyPair key, ReadOnlySpan<byte> deviceId) : IGroupDeviceCustodySigner
    {
        private readonly byte[] id = deviceId.ToArray();
        public ReadOnlyMemory<byte> DeviceId => id.ToArray();
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Fill(0xd0, 32);
        public ValueTask<int> SignAsync(GroupDeviceSigningRequest request, Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var signature = PublicKeyAuth.SignDetached(request.SigningInput.ToArray(), key.PrivateKey);
            signature.CopyTo(signature64); return ValueTask.FromResult(signature.Length);
        }
    }

    private sealed class MemoryComparer : IComparer<ReadOnlyMemory<byte>>
    {
        internal static readonly MemoryComparer Instance = new();
        public int Compare(ReadOnlyMemory<byte> left, ReadOnlyMemory<byte> right) => left.Span.SequenceCompareTo(right.Span);
    }
    private static byte[] Ref(string magic, ReadOnlySpan<byte> hash)
    { var value=new byte[38]; Encoding.ASCII.GetBytes(magic).CopyTo(value,0); BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4),1); hash.CopyTo(value.AsSpan(6)); return value; }
    private static byte[] Lp32(ReadOnlySpan<byte> value)
    { var output=new byte[4+value.Length]; BinaryPrimitives.WriteUInt32BigEndian(output,checked((uint)value.Length)); value.CopyTo(output.AsSpan(4)); return output; }
    private static byte[] Join(params byte[][] values)
    { var output=new byte[values.Sum(static value=>value.Length)];var offset=0;foreach(var value in values){value.CopyTo(output,offset);offset+=value.Length;}return output; }
    private static byte[] Ipv4(byte value)
    { var output=new byte[16]; output.AsSpan(0,4).Fill(value); return output; }
    private static byte[] Fill(byte value,int length)=>Enumerable.Repeat(value,length).ToArray();
    private static byte[] U16(ushort value){var output=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(output,value);return output;}
    private static byte[] U32(uint value){var output=new byte[4];BinaryPrimitives.WriteUInt32BigEndian(output,value);return output;}
    private static byte[] U64(ulong value){var output=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(output,value);return output;}
}
