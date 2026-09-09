using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.GroupV1;
using Deep.Protocol.Tests.ApplicationCore;
using Sodium;

namespace Deep.Protocol.Tests.GroupV1;

public sealed class GroupCodecTests
{
    [Fact]
    public void InvitationAndAcceptanceAreCanonicalAndProductionAuthoringIsClosed()
    {
        var invitation = Record("GIV1", InvitationFields());
        var decoded = Assert.IsType<GroupInvitationRecord>(GroupCodec.Decode(invitation.CanonicalBytes.Span));
        Assert.Equal(invitation.CanonicalBytes.ToArray(), decoded.CanonicalBytes.ToArray());
        Assert.False(GroupCodec.RuntimeActivation);
        Assert.True(GroupCodec.AccountDirectoryCapabilityAvailable);
        Assert.Throws<InvalidOperationException>(() => GroupCodec.Author("GIV1", InvitationFields()));
        Assert.DoesNotContain(typeof(GroupCodec).GetMethods(System.Reflection.BindingFlags.Public|System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static),method=>method.Name.Contains("ForValidation",StringComparison.Ordinal));
        Assert.True(typeof(VerifiedGroupTransition).IsAbstract);
        Assert.Empty(typeof(VerifiedGroupTransition).GetConstructors());

        var acceptance = Record("GIA1", AcceptanceFields(invitation));
        Assert.IsType<GroupInvitationAcceptanceRecord>(GroupCodec.Decode(acceptance.CanonicalBytes.Span));
    }

    [Fact]
    public void GroupApplicationDmc2RequiresAuthenticatedAuthorAndClosedEmission()
    {
        var network = B(16, 1); var account = B(32, 2); var device = B(32, 3);
        var message = Record("DGM1",
        [network, B(32,4), U64(1), B(32,5), B(32,6), account, device, U64(1), U64(1000), U64(2000), U16(1), Array.Empty<byte>()]);
        var payload = GroupCodec.DecodeDmc2Payload(Dmc2ContentKind.GroupApplicationMessage, Lp(message.CanonicalBytes.Span));
        Assert.Throws<InvalidOperationException>(() => ApplicationCoreCodec.AuthorDmc2(network, B(32,7), B(32,8), account, device, 1, 1, 0, Dmc2Flags.None, [], payload));
        var dmc = ApplicationCoreCodec.AuthorDmc2ForValidation(network, B(32,7), B(32,8), account, device, 1, 1, 0, Dmc2Flags.None, [], payload);
        Assert.IsType<GroupDmc2Payload>(dmc.ParsedPayload);

        var altered = dmc.CanonicalBytes.ToArray();
        var senderOffset = FieldOffset(altered, 4); altered[senderOffset] ^= 0x80;
        var error = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(altered));
        Assert.Equal(ApplicationCoreRejection.CrossFieldMismatch, error.Rejection);
    }

    [Fact]
    public void ChunkGeometryOverflowAndChangedChunkForkLatch()
    {
        var one = new byte[] { 0xA5 };
        var chunk = Record("GCF1", [GroupCodec.RecordHash("GCP1", one), U32(1), U32(24576), U32(0), U32(1), SHA256.HashData(one), Lp(one)]);
        var assembler = GroupCodec.NewChunkAssembler();
        Assert.True(assembler.TryAdd(Assert.IsType<GroupCommitChunkRecord>(chunk), out var complete));
        Assert.Equal(one, complete.ToArray());

        var changed = chunk.CanonicalBytes.ToArray();
        changed[FieldOffset(changed, 7)] ^= 0x01;
        var malformed = Assert.Throws<GroupFormatException>(() => GroupCodec.Decode(changed));
        Assert.Equal("InvalidLp32", malformed.Code);

        var overflow = chunk.CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(overflow.AsSpan(16, 4), uint.MaxValue);
        var bounded = Assert.Throws<GroupFormatException>(() => GroupCodec.Decode(overflow));
        Assert.Equal(GroupValidationStage.Bounds, bounded.Stage);
    }

    [Fact]
    public void UnknownMagicAndNonCanonicalMemberTableRejectBeforeClosure()
    {
        var unknown = new byte[12]; Encoding.ASCII.GetBytes("ZZZ1").CopyTo(unknown, 0);
        BinaryPrimitives.WriteUInt16BigEndian(unknown.AsSpan(4), 1); BinaryPrimitives.WriteUInt16BigEndian(unknown.AsSpan(6), 0x0201);
        Assert.Equal("UnsupportedRecord", Assert.Throws<GroupFormatException>(() => GroupCodec.Decode(unknown)).Code);

        var members = Member(B(32,2), GroupRole.Owner, B(32,3));
        var commit = Record("DGC1",
        [B(16,1),B(32,2),U16(1),U64(0),new byte[32],B(32,2),B(32,3),Ref("DPD1",4),U16(0),Array.Empty<byte>(),U16(1),members,Encoding.UTF8.GetBytes("g"),new byte[]{0},U32(1),U64(1),B(64,5)]);
        Assert.IsType<GroupCommitRecord>(commit);
        var bad = commit.CanonicalBytes.ToArray();
        var memberOffset = FieldOffset(bad, 12); bad[memberOffset + 2 + 32] = 0;
        Assert.Equal("NonCanonicalMemberTable", Assert.Throws<GroupFormatException>(() => GroupCodec.Decode(bad)).Code);
    }

    [Fact]
    public void ExternalCanonicalVectorHasLiteralDigestPinAndExecutes()
    {
        var path = FindSpec("group-codec-v1.vectors.json");
        var text = File.ReadAllText(path);
        using var document = System.Text.Json.JsonDocument.Parse(text);
        var canonical = text.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace("\r", "\n", StringComparison.Ordinal);
        Assert.Equal("dca069d80c506c2fe5da5b1c14073d784a875666484f83f7deb13662dd60147e", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant());
        var vectors=document.RootElement.GetProperty("records").EnumerateArray().ToArray();
        Assert.Equal(12,vectors.Length);Assert.Equal(12,vectors.Select(item=>item.GetProperty("target").GetString()).Distinct(StringComparer.Ordinal).Count());
        foreach(var vector in vectors){var bytes=Convert.FromHexString(vector.GetProperty("fixtureBytesHex").GetString()!);var record=GroupCodec.Decode(bytes);Assert.Equal(vector.GetProperty("target").GetString(),record.Magic);Assert.Equal(vector.GetProperty("recordHash32").GetString(),Convert.ToHexString(record.ArtifactHash.Span).ToLowerInvariant());var key=vector.GetProperty("signerPublicKeyHex");if(key.ValueKind!=System.Text.Json.JsonValueKind.Null)Assert.True(PublicKeyAuth.VerifyDetached(record.Field(SignatureTag(record.Magic)).ToArray(),record.SignatureInput.ToArray(),Convert.FromHexString(key.GetString()!)));}
        foreach(var hostile in document.RootElement.GetProperty("hostileCases").EnumerateArray()){var bytes=Convert.FromHexString(hostile.GetProperty("fixtureBytesHex").GetString()!);var code=hostile.GetProperty("expectedCode").GetString();if(code=="NonCanonicalReserved")Assert.Equal(code,Assert.Throws<GroupFormatException>(()=>GroupCodec.Decode(bytes)).Code);else{var record=GroupCodec.Decode(bytes);Assert.False(PublicKeyAuth.VerifyDetached(record.Field(SignatureTag(record.Magic)).ToArray(),record.SignatureInput.ToArray(),Convert.FromHexString(hostile.GetProperty("signerPublicKeyHex").GetString()!)));}}
    }

    [Fact]
    public void CommitPackageRequiresExactNoExtraClosure()
    {
        var network=B(16,1); var group=B(32,2); var support=Enumerable.Range(1,6).Select(kind => (Kind:(ushort)kind, Magic:new[]{"ADC1","ADH1","ADP1","DMD1","DRS1","DPD1"}[kind-1], Bytes:Encoding.ASCII.GetBytes($"support-{kind}"))).ToArray();
        var refs=support.ToDictionary(item=>item.Kind,item=>HashRef(item.Magic,item.Bytes));
        var member=Member(B(32,3),GroupRole.Owner,B(32,4),refs[1],refs[2],refs[3].AsSpan(6).ToArray(),refs[4].AsSpan(6).ToArray(),refs[5],refs[6]);
        var commit=Record("DGC1",[network,group,U16(1),U64(0),new byte[32],B(32,3),B(32,4),refs[6],U16(0),Array.Empty<byte>(),U16(1),member,Encoding.UTF8.GetBytes("g"),new byte[]{0},U32(1),U64(1),B(64,5)]);
        var supportBytes=SupportEntries(support,refs);
        var package=Assert.IsType<GroupCommitPackageRecord>(Record("GCP1",[network,group,U64(0),Lp(commit.CanonicalBytes.Span),U16(0),Array.Empty<byte>(),U32(6),supportBytes,U16(0),Array.Empty<byte>(),Array.Empty<byte>()]));

        var extra=supportBytes.Concat(new byte[]{0}).ToArray();
        var malformedPackage=Assert.IsType<GroupCommitPackageRecord>(Record("GCP1",[network,group,U64(0),Lp(commit.CanonicalBytes.Span),U16(0),Array.Empty<byte>(),U32(6),extra,U16(0),Array.Empty<byte>(),Array.Empty<byte>()]));
        Assert.Equal(extra,malformedPackage.Field(8).ToArray());
    }

    [Fact]
    public void VerifiedTransitionAndIdentityCapabilitiesAreNotCallerForgeable()
    {
        Assert.Empty(typeof(VerifiedGroupTransition).GetConstructors());
        Assert.Empty(typeof(GroupIdentityClosure).GetConstructors());
        Assert.Single(typeof(GroupIdentityClosure).GetMethods(), method =>
            method.IsPublic && method.IsStatic && method.ReturnType == typeof(GroupIdentityClosure));
        Assert.DoesNotContain(typeof(GroupSuccessorLatch).GetMethods(), method => method.Name == "Observe");
    }

    [Fact]
    public void ClosedActionGrammarAndSecurityLimitsRejectBeforeTransition()
    {
        var invalidAction=ProfileAction("x",0,1);invalidAction[0]=0;invalidAction[1]=0;
        var fields=new ReadOnlyMemory<byte>[] {B(16,1),B(32,2),U64(0),B(32,3),B(32,4),B(32,5),B(32,6),Ref("DPD1",7),U16(6),invalidAction,U64(1),U64(2),B(64,8)};
        Assert.Equal("InvalidActionPayload",Assert.Throws<GroupFormatException>(()=>Record("DGP1",fields)).Code);

        var sixDevices=Enumerable.Range(0,6).Select(index=>(Id:B(32,(byte)(20+index)),Ref:Ref("DPD1",(byte)(40+index)))).ToArray();
        var member=MemberWithDevices(B(32,2),GroupRole.Owner,sixDevices);
        Assert.Equal("NonCanonicalMemberTable",Assert.Throws<GroupFormatException>(()=>Record("DGC1",[B(16,1),B(32,2),U16(1),U64(0),new byte[32],B(32,2),sixDevices[0].Id,sixDevices[0].Ref,U16(0),Array.Empty<byte>(),U16(1),member,Encoding.UTF8.GetBytes("g"),new byte[]{0},U32(1),U64(1),B(64,5)])).Code);

        var hashes=Enumerable.Range(0,65).Select(index=>SHA256.HashData(U32((uint)index))).OrderBy(hash=>hash,ByteComparer.Instance).SelectMany(hash=>hash).ToArray();
        Assert.Equal("InvalidCommitShape",Assert.Throws<GroupFormatException>(()=>Record("DGC1",[B(16,1),B(32,2),U16(1),U64(0),new byte[32],B(32,2),B(32,3),Ref("DPD1",4),U16(65),hashes,U16(1),Member(B(32,2),GroupRole.Owner,B(32,3)),Encoding.UTF8.GetBytes("g"),new byte[]{0},U32(1),U64(1),B(64,5)])).Code);

        var accounts=Enumerable.Range(0,6).Select(index=>B(32,checked((byte)(30+index)))).ToArray();var devices=Enumerable.Range(0,6).Select(index=>B(32,checked((byte)(60+index)))).ToArray();var tooManyAdmins=Enumerable.Range(0,6).SelectMany(index=>Member(accounts[index],index==0?GroupRole.Owner:GroupRole.Admin,devices[index])).ToArray();
        Assert.Equal("AdminLimitExceeded",Assert.Throws<GroupFormatException>(()=>Record("DGC1",[B(16,1),B(32,2),U16(1),U64(0),new byte[32],accounts[0],devices[0],Ref("DPD1",9),U16(0),Array.Empty<byte>(),U16(6),tooManyAdmins,Encoding.UTF8.GetBytes("g"),new byte[]{0},U32(1),U64(1),B(64,5)])).Code);
    }

    [Fact]
    public void ExactHundredAccountFiveHundredDeviceBoundaryIsAcceptedAndNextAccountRejects()
    {
        var accounts=Enumerable.Range(0,101).Select(index=>B(32,checked((byte)(index+1)))).OrderBy(x=>x,ByteComparer.Instance).ToArray();
        byte[] Entry(int index){var devices=Enumerable.Range(0,5).Select(device=>(Id:B(32,checked((byte)(device+1))),Ref:Ref("DPD1",checked((byte)(index+device+1))))).ToArray();return MemberWithDevices(accounts[index],index==0?GroupRole.Owner:index<5?GroupRole.Admin:GroupRole.Member,devices);}
        var exact=Enumerable.Range(0,100).SelectMany(Entry).ToArray();var ownerDevice=B(32,1);
        Assert.IsType<GroupCommitRecord>(Record("DGC1",[B(16,1),B(32,2),U16(1),U64(0),new byte[32],accounts[0],ownerDevice,Ref("DPD1",1),U16(0),Array.Empty<byte>(),U16(100),exact,Encoding.UTF8.GetBytes("g"),new byte[]{0},U32(1),U64(1),B(64,5)]));
        var tooMany=Enumerable.Range(0,101).SelectMany(Entry).ToArray();
        Assert.Equal("InvalidCommitShape",Assert.Throws<GroupFormatException>(()=>Record("DGC1",[B(16,1),B(32,2),U16(1),U64(0),new byte[32],accounts[0],ownerDevice,Ref("DPD1",1),U16(0),Array.Empty<byte>(),U16(101),tooMany,Encoding.UTF8.GetBytes("g"),new byte[]{0},U32(1),U64(1),B(64,5)])).Code);
    }

    [Fact]
    public void AllEightProposalActionsHaveOneClosedCanonicalGrammar()
    {
        var activate=new byte[287];Ref("GIV1",1).CopyTo(activate,0);Ref("GIA1",2).CopyTo(activate,38);B(32,3).CopyTo(activate,76);activate[108]=3;Ref("ADC1",4).CopyTo(activate,109);Ref("ADH1",5).CopyTo(activate,147);B(32,6).CopyTo(activate,185);B(32,7).CopyTo(activate,217);Ref("DRS1",8).CopyTo(activate,249);
        var remove=new byte[66];B(32,9).CopyTo(remove,0);B(32,10).CopyTo(remove,32);remove[65]=1;
        var role=new byte[66];B(32,11).CopyTo(role,0);role[32]=3;role[33]=2;B(32,12).CopyTo(role,34);
        var add=new byte[204];B(32,13).CopyTo(add,0);B(32,14).CopyTo(add,32);Ref("DPD1",15).CopyTo(add,64);B(32,16).CopyTo(add,102);Ref("DRS1",17).CopyTo(add,134);B(32,18).CopyTo(add,172);
        var removeDevice=new byte[172];B(32,19).CopyTo(removeDevice,0);B(32,20).CopyTo(removeDevice,32);Ref("DPD1",21).CopyTo(removeDevice,64);B(32,22).CopyTo(removeDevice,102);Ref("DRS1",23).CopyTo(removeDevice,134);
        var transfer=removeDevice.ToArray();
        var actions=new Dictionary<ushort,byte[]>{{1,activate},{2,remove},{3,role},{4,add},{5,removeDevice},{6,ProfileAction("canonical",1,3600)},{7,transfer},{8,remove.ToArray()}};
        foreach(var pair in actions){var fields=new ReadOnlyMemory<byte>[]{B(16,1),B(32,2),U64(0),B(32,3),B(32,4),B(32,5),B(32,6),Ref("DPD1",7),U16(pair.Key),pair.Value,U64(1),U64(2),B(64,8)};Assert.IsType<GroupProposalRecord>(Record("DGP1",fields));fields[9]=pair.Value[..^1];Assert.Throws<GroupFormatException>(()=>Record("DGP1",fields));}
    }

    [Fact]
    public void ArtifactHashUsesIndependentLiteralDomainSeparatedRecordHash()
    {
        var record=Record("DGM1",[B(16,1),B(32,2),U64(0),B(32,3),B(32,4),B(32,5),B(32,6),U64(1),U64(2),U64(3),U16(1),Encoding.UTF8.GetBytes("hello")]);
        var label=Encoding.ASCII.GetBytes("Deep/Application/V1/record-hash/DGM1");
        var canonical=record.CanonicalBytes.ToArray();var preimage=new byte[label.Length+5+canonical.Length];label.CopyTo(preimage,0);
        BinaryPrimitives.WriteUInt32BigEndian(preimage.AsSpan(label.Length+1),checked((uint)canonical.Length));canonical.CopyTo(preimage,label.Length+5);
        var expected=SHA256.HashData(preimage);
        Assert.Equal(expected,record.ArtifactHash.ToArray());
        Assert.NotEqual(SHA256.HashData(canonical),record.ArtifactHash.ToArray());
        Assert.Equal(expected,GroupCodec.ArtifactReference("DGM1",record).Hash.ToArray());
    }

    [Fact]
    public void EveryActionIdentifierIsValidatedIndependently()
    {
        static ReadOnlyMemory<byte>[] Proposal(ushort action,byte[] payload)=>[B(16,1),B(32,2),U64(0),B(32,3),B(32,4),B(32,5),B(32,6),Ref("DPD1",7),U16(action),payload,U64(1),U64(2),B(64,8)];
        var remove=new byte[66];B(32,1).CopyTo(remove,0);B(32,2).CopyTo(remove,32);remove[64]=1;remove[65]=1;
        foreach(var action in new ushort[]{2,8})foreach(var offset in new[]{0,32}){var hostile=remove.ToArray();Array.Clear(hostile,offset,32);Assert.Equal("InvalidActionPayload",Assert.Throws<GroupFormatException>(()=>Record("DGP1",Proposal(action,hostile))).Code);}
        var role=new byte[66];B(32,2).CopyTo(role,0);role[32]=3;role[33]=2;B(32,3).CopyTo(role,34);
        foreach(var offset in new[]{0,34}){var hostile=role.ToArray();Array.Clear(hostile,offset,32);Assert.Equal("InvalidActionPayload",Assert.Throws<GroupFormatException>(()=>Record("DGP1",Proposal(3,hostile))).Code);}
        var add=new byte[204];B(32,3).CopyTo(add,0);B(32,4).CopyTo(add,32);Ref("DPD1",5).CopyTo(add,64);B(32,6).CopyTo(add,102);Ref("DRS1",7).CopyTo(add,134);B(32,8).CopyTo(add,172);
        foreach(var offset in new[]{0,32,102,172}){var hostile=add.ToArray();Array.Clear(hostile,offset,32);Assert.Equal("InvalidActionPayload",Assert.Throws<GroupFormatException>(()=>Record("DGP1",Proposal(4,hostile))).Code);}
        var deviceMutation=add[..172];foreach(var action in new ushort[]{5,7})foreach(var offset in new[]{0,32,102}){var hostile=deviceMutation.ToArray();Array.Clear(hostile,offset,32);Assert.Equal("InvalidActionPayload",Assert.Throws<GroupFormatException>(()=>Record("DGP1",Proposal(action,hostile))).Code);}
        var activate=new byte[287];Ref("GIV1",1).CopyTo(activate,0);Ref("GIA1",2).CopyTo(activate,38);B(32,3).CopyTo(activate,76);activate[108]=3;Ref("ADC1",4).CopyTo(activate,109);Ref("ADH1",5).CopyTo(activate,147);B(32,6).CopyTo(activate,185);B(32,7).CopyTo(activate,217);Ref("DRS1",8).CopyTo(activate,249);
        foreach(var offset in new[]{76,185,217}){var hostile=activate.ToArray();Array.Clear(hostile,offset,32);Assert.Equal("ZeroForbidden",Assert.Throws<GroupFormatException>(()=>Record("DGP1",Proposal(1,hostile))).Code);}
    }

    [Fact]
    public void GroupControlFamilyHasFrozenSparseTagGrammarAndInactiveRuntime()
    {
        var gsr=Assert.IsType<GroupControlRendezvousRecord>(Record("GSR1",[B(16,1),B(32,2),B(32,3),U64(0),new byte[32],Ref("PMT2",4),B(32,5),B(32,6),B(32,7),B(32,8),Ref("DPD1",9),U64(10),U64(20),B(64,10)]));
        Assert.Equal(14,gsr.Tags.Count);
        var sealedChunk=B(64,20);var write=RecordTagged("GSW1",[1,2,3,4,5,6,16,17,18,19,20,21,22],[B(16,1),B(32,2),B(32,3),B(32,4),U64(10),U64(20),B(32,5),B(32,6),U64(1),new byte[32],SHA256.HashData(sealedChunk),Lp(sealedChunk),U64(30)]);
        Assert.IsType<GroupControlWriteRecord>(write);
        Assert.IsType<GroupControlQueryRecord>(RecordTagged("GSQ1",[1,2,3,4,5,6,16,17,18,19,20],[B(16,1),B(32,2),B(32,3),B(32,4),U64(10),U64(20),B(32,5),B(32,6),U64(0),U16(64),U16(4)]));
        Assert.IsType<GroupControlResultRecord>(RecordTagged("GSS1",[1,2,3,4,5,6,7,8,16,17,18,19,20],[B(16,1),B(32,2),B(32,3),U16(1),new byte[]{1},U64(10),U32(0),U16(4),new byte[]{1},U64(1),B(32,9),U64(1),B(96,10)]));
        Assert.False(GroupCodec.RuntimeActivation);
    }

    [Fact]
    public void GroupControlFamilyEnforcesIdentifiersCasAndClosedResultMatrix()
    {
        var gsrFields=new ReadOnlyMemory<byte>[] {B(16,1),B(32,2),B(32,3),U64(0),new byte[32],Ref("PMT2",4),B(32,5),B(32,6),B(32,7),B(32,8),Ref("DPD1",9),U64(10),U64(20),B(64,10)};
        gsrFields[1]=new byte[32];
        Assert.Equal("ZeroForbidden",Assert.Throws<GroupFormatException>(()=>Record("GSR1",gsrFields)).Code);

        var sealedChunk=B(64,20);
        var writeFields=new ReadOnlyMemory<byte>[] {B(16,1),B(32,2),B(32,3),B(32,4),U64(10),U64(20),B(32,5),B(32,6),U64(2),new byte[32],SHA256.HashData(sealedChunk),Lp(sealedChunk),U64(30)};
        Assert.Equal("InvalidControlWrite",Assert.Throws<GroupFormatException>(()=>RecordTagged("GSW1",[1,2,3,4,5,6,16,17,18,19,20,21,22],writeFields)).Code);

        ReadOnlyMemory<byte>[] Result(ushort status,byte outcome,byte operation,byte[] p17,byte[] p18,byte[] p19,byte[] p20,uint retry=0) =>
            [B(16,1),B(32,2),B(32,3),U16(status),new[]{outcome},U64(10),U32(retry),U16(4),new[]{operation},p17,p18,p19,p20];
        Assert.Equal("InvalidControlResultMatrix",Assert.Throws<GroupFormatException>(()=>RecordTagged("GSS1",[1,2,3,4,5,6,7,8,16,17,18,19,20],Result(4,0,1,[],[],[],[]))).Code);
        Assert.IsType<GroupControlResultRecord>(RecordTagged("GSS1",[1,2,3,4,5,6,7,8,16,17,18,19,20],Result(8,0,2,B(32,9),[],[],[])));

        var body=B(32,40);var eventHash=SHA256.HashData(body);var eventRow=Join(U64(1),new byte[32],eventHash,U64(20),Lp(body));
        var events=Result(3,0,2,U16(1),eventRow,U64(1),new byte[]{0});
        Assert.IsType<GroupControlResultRecord>(RecordTagged("GSS1",[1,2,3,4,5,6,7,8,16,17,18,19,20],events));
        var corrupt=eventRow.ToArray();corrupt[^1]^=1;events[10]=corrupt;
        Assert.Equal("InvalidControlResultMatrix",Assert.Throws<GroupFormatException>(()=>RecordTagged("GSS1",[1,2,3,4,5,6,7,8,16,17,18,19,20],events)).Code);
    }

    [Fact]
    public void ForkLatchSnapshotIsCanonicalAndRestartRestorable()
    {
        var empty=GroupSuccessorLatch.CreateEmpty();var restored=GroupSuccessorLatch.Restore(empty.Snapshot.Span);
        Assert.Equal(empty.Snapshot.ToArray(),restored.Snapshot.ToArray());Assert.False(restored.ForkLatched);
        var hostile=empty.Snapshot.ToArray();hostile[7]=2;
        Assert.Equal("InvalidPersistedGroupLineage",Assert.Throws<GroupFormatException>(()=>GroupSuccessorLatch.Restore(hostile)).Code);
        var impossibleRevision=empty.Snapshot.ToArray();BinaryPrimitives.WriteUInt64BigEndian(impossibleRevision.AsSpan(8),1);
        Assert.Equal("InvalidPersistedGroupLineage",Assert.Throws<GroupFormatException>(()=>GroupSuccessorLatch.Restore(impossibleRevision)).Code);
        Assert.Contains(typeof(GroupSuccessorLatch).GetMethod("ObserveAndPersist")!.GetParameters(),parameter=>parameter.ParameterType==typeof(IGroupSuccessorStateStore));
    }

    [Fact]
    public void CryptoVerifiedGenesisSuccessorReducerAndDurableForkExecuteEndToEnd()
    {
        var fixture=Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create();
        var contact=fixture.Promote(fixture.Dcr);
        var identities=GroupIdentityClosure.FromVerifiedContactDirectories([], [contact],fixture.BootId,fixture.CurrentMonotonicSample);
        var baseAndCurrent=GroupIdentityClosure.FromVerifiedContactDirectories([contact], [contact],fixture.BootId,fixture.CurrentMonotonicSample);
        var support=VerifiedSupport(fixture,contact);
        var resolver=new Resolver(support.ToDictionary(item=>Convert.ToHexString(item.Ref),item=>item.Bytes,StringComparer.Ordinal));
        var network=contact.Directory.Record.NetworkId.ToArray();var account=contact.Directory.Record.DeepAccountId.ToArray();
        var device=contact.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId.ToArray();
        var dpdRef=RefHash("DPD1",contact.Directory.Identity.ActiveDevices.Single().Certificate.CanonicalHash.Span);
        var member=Member(account,GroupRole.Owner,device,contact.Freshness.ExactAdc1Reference.ToArray(),contact.Freshness.ExactAdh1CoreReference.ToArray(),contact.Freshness.ExactAdp1Hash.ToArray(),contact.Directory.Record.RecordHash.ToArray(),RefHash("DRS1",contact.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span),dpdRef);

        var genesis=SignedRecord("DGC1",[network,B(32,0x30),U16(1),U64(0),new byte[32],account,device,dpdRef,U16(0),Array.Empty<byte>(),U16(1),member,Encoding.UTF8.GetBytes("genesis"),new byte[]{0},U32(3600),U64(30),B(64,0xa0)],17,fixture.Device);
        var genesisPackage=Package(genesis,[],support);
        var verifiedGenesis=GroupCodec.VerifyCommitPackage(genesisPackage,null,identities,resolver);
        var expectedPackageHash=SHA256.HashData(genesisPackage.CanonicalBytes.Span);
        Assert.Equal(expectedPackageHash,verifiedGenesis.ExactVerifiedGcp1Sha256.ToArray());
        Assert.True(verifiedGenesis.BindsExactGcp1(genesisPackage.CanonicalBytes.Span));

        var exposedHash=verifiedGenesis.ExactVerifiedGcp1Sha256.ToArray();
        exposedHash[0]^=0xff;
        Assert.Equal(expectedPackageHash,verifiedGenesis.ExactVerifiedGcp1Sha256.ToArray());

        var changedPackageBytes=genesisPackage.CanonicalBytes.ToArray();
        changedPackageBytes[FieldOffset(changedPackageBytes,1)]^=0x01;
        Assert.False(verifiedGenesis.BindsExactGcp1(changedPackageBytes));
        var changedPackage=Assert.IsType<GroupCommitPackageRecord>(GroupCodec.Decode(changedPackageBytes));
        Assert.Equal("CommitHeaderMismatch",Assert.Throws<GroupFormatException>(()=>
            GroupCodec.VerifyCommitPackage(changedPackage,null,identities,resolver)).Code);

        var first=Successor(verifiedGenesis,fixture,contact,support,resolver,baseAndCurrent,"next",1);
        var second=Successor(verifiedGenesis,fixture,contact,support,resolver,baseAndCurrent,"fork",2);
        Assert.Equal("next",Encoding.UTF8.GetString(first.Commit.Field(13).Span));

        var invalidProposal=Proposal(verifiedGenesis.Commit,fixture,contact,"expected",3);
        var invalidCommit=CommitFor(verifiedGenesis.Commit,invalidProposal,fixture,contact,"different");
        var invalidPackage=Package(invalidCommit,[invalidProposal],support);
        Assert.Equal("ResultStateMismatch",Assert.Throws<GroupFormatException>(()=>GroupCodec.VerifyCommitPackage(invalidPackage,verifiedGenesis,baseAndCurrent,resolver)).Code);

        var store=new MemoryGroupStore();var latch=GroupSuccessorLatch.CreateEmpty();
        Assert.Equal(GroupLineageDisposition.AcceptedGenesis,latch.ObserveAndPersist(verifiedGenesis,store));
        Assert.Equal(GroupLineageDisposition.AcceptedSuccessor,latch.ObserveAndPersist(first,store));
        Assert.Equal(GroupLineageDisposition.ForkLatched,latch.ObserveAndPersist(second,store));
        var restored=GroupSuccessorLatch.Restore(store.Value.Span);Assert.True(restored.ForkLatched);
        Assert.Equal(GroupLineageDisposition.ForkLatched,restored.ObserveAndPersist(first,store));
    }

    [Fact]
    public void AcceptedInvitationActivatesOnlyInsideBothSignedExpiryWindows()
    {
        var ownerFixture=Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create();
        var inviteeFixture=Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture.Create(1);
        var owner=ownerFixture.Promote(ownerFixture.Dcr);var invitee=inviteeFixture.Promote(inviteeFixture.Dcr);
        var ownerSupport=VerifiedSupport(ownerFixture,owner);var allSupport=ownerSupport.Concat(VerifiedSupport(inviteeFixture,invitee)).OrderBy(x=>x.Kind).ThenBy(x=>x.Ref,ByteComparer.Instance).ToArray();
        var resolver=new Resolver(allSupport.ToDictionary(item=>Convert.ToHexString(item.Ref),item=>item.Bytes,StringComparer.Ordinal));
        var ownerOnly=GroupIdentityClosure.FromVerifiedContactDirectories([], [owner],ownerFixture.BootId,ownerFixture.CurrentMonotonicSample);
        var genesisCommit=Genesis(ownerFixture,owner);
        var genesis=GroupCodec.VerifyCommitPackage(Package(genesisCommit,[],ownerSupport),null,ownerOnly,new Resolver(ownerSupport.ToDictionary(item=>Convert.ToHexString(item.Ref),item=>item.Bytes,StringComparer.Ordinal)));

        var ownerAccount=owner.Directory.Record.DeepAccountId.ToArray();var ownerDevice=owner.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId.ToArray();var ownerDpd=RefHash("DPD1",owner.Directory.Identity.ActiveDevices.Single().Certificate.CanonicalHash.Span);
        var inviteeAccount=invitee.Directory.Record.DeepAccountId.ToArray();var inviteeDevice=invitee.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId.ToArray();var inviteeDpd=RefHash("DPD1",invitee.Directory.Identity.ActiveDevices.Single().Certificate.CanonicalHash.Span);
        var invitation=SignedRecord("GIV1",[owner.Directory.Record.NetworkId,B(32,0x30),B(32,0x44),U64(0),genesis.Commit.ArtifactHash,ownerAccount,ownerDevice,ownerDpd,inviteeAccount,new byte[]{3},invitee.Freshness.ExactAdc1Reference,invitee.Freshness.ExactAdh1CoreReference,invitee.Freshness.ExactAdp1Hash,invitee.Directory.Record.RecordHash,RefHash("DRS1",invitee.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span),U64(20),U64(40),B(64,0xa0)],18,ownerFixture.Device);
        var acceptance=SignedRecord("GIA1",[invitation.Field(1),invitation.Field(2),invitation.Field(3),GroupCodec.ArtifactReference("GIV1",invitation).CanonicalBytes,inviteeAccount,inviteeDevice,inviteeDpd,invitee.Freshness.ExactAdc1Reference,invitee.Freshness.ExactAdh1CoreReference,invitee.Freshness.ExactAdp1Hash,invitee.Directory.Record.RecordHash,RefHash("DRS1",invitee.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span),U64(25),U64(31),B(64,0xa0)],15,inviteeFixture.Device);
        var payload=Join(GroupCodec.ArtifactReference("GIV1",invitation).CanonicalBytes.ToArray(),GroupCodec.ArtifactReference("GIA1",acceptance).CanonicalBytes.ToArray(),inviteeAccount,new byte[]{3},invitee.Freshness.ExactAdc1Reference.ToArray(),invitee.Freshness.ExactAdh1CoreReference.ToArray(),invitee.Freshness.ExactAdp1Hash.ToArray(),invitee.Directory.Record.RecordHash.ToArray(),RefHash("DRS1",invitee.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span));
        var proposal=SignedRecord("DGP1",[owner.Directory.Record.NetworkId,B(32,0x30),U64(0),genesis.Commit.ArtifactHash,B(32,0x45),ownerAccount,ownerDevice,ownerDpd,U16(1),payload,U64(20),U64(60),B(64,0xa0)],13,ownerFixture.Device);
        var members=new[]{MemberFrom(owner,GroupRole.Owner),MemberFrom(invitee,GroupRole.Member)}.OrderBy(x=>x.AsSpan(2,32).ToArray(),ByteComparer.Instance).SelectMany(x=>x).ToArray();
        var current=GroupIdentityClosure.FromVerifiedContactDirectories([owner],[owner,invitee],ownerFixture.BootId,ownerFixture.CurrentMonotonicSample);
        var validCommit=ActivationCommit(genesis.Commit,proposal,ownerFixture,owner,members,30);
        var pair=(Invitation:invitation,Acceptance:acceptance);
        var verified=GroupCodec.VerifyCommitPackage(Package(validCommit,[proposal],allSupport,[pair]),genesis,current,resolver);
        Assert.Equal((ulong)1,BinaryPrimitives.ReadUInt64BigEndian(verified.Commit.Field(4).Span));

        var expiredCommit=ActivationCommit(genesis.Commit,proposal,ownerFixture,owner,members,31);
        Assert.Equal("InvitationBaseMismatch",Assert.Throws<GroupFormatException>(()=>GroupCodec.VerifyCommitPackage(Package(expiredCommit,[proposal],allSupport,[pair]),genesis,current,resolver)).Code);
    }

    private static VerifiedGroupTransition Successor(VerifiedGroupTransition genesis,Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture fixture,VerifiedContactBundleClosure contact,(ushort Kind,byte[] Ref,byte[] Bytes)[] support,Resolver resolver,GroupIdentityClosure identities,string name,byte proposalSeed)
    { var proposal=Proposal(genesis.Commit,fixture,contact,name,proposalSeed);var commit=CommitFor(genesis.Commit,proposal,fixture,contact,name);return GroupCodec.VerifyCommitPackage(Package(commit,[proposal],support),genesis,identities,resolver); }
    private static GroupRecord Proposal(GroupCommitRecord genesis,Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture fixture,VerifiedContactBundleClosure contact,string name,byte seed)
    { var account=contact.Directory.Record.DeepAccountId.ToArray();var device=contact.Directory.Identity.ActiveDevices.Single().Certificate.DeviceId.ToArray();var dpd=RefHash("DPD1",contact.Directory.Identity.ActiveDevices.Single().Certificate.CanonicalHash.Span);return SignedRecord("DGP1",[contact.Directory.Record.NetworkId,B(32,0x30),U64(0),genesis.ArtifactHash,B(32,seed),account,device,dpd,U16(6),ProfileAction(name,1,7200),U64(20),U64(60),B(64,0xa0)],13,fixture.Device); }
    private static GroupRecord CommitFor(GroupCommitRecord genesis,GroupRecord proposal,Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture fixture,VerifiedContactBundleClosure contact,string name)
    { var account=contact.Directory.Record.DeepAccountId.ToArray();var active=contact.Directory.Identity.ActiveDevices.Single();var device=active.Certificate.DeviceId.ToArray();var dpd=RefHash("DPD1",active.Certificate.CanonicalHash.Span);var member=Member(account,GroupRole.Owner,device,contact.Freshness.ExactAdc1Reference.ToArray(),contact.Freshness.ExactAdh1CoreReference.ToArray(),contact.Freshness.ExactAdp1Hash.ToArray(),contact.Directory.Record.RecordHash.ToArray(),RefHash("DRS1",contact.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span),dpd);return SignedRecord("DGC1",[contact.Directory.Record.NetworkId,B(32,0x30),U16(1),U64(1),genesis.ArtifactHash,account,device,dpd,U16(1),proposal.ArtifactHash,U16(1),member,Encoding.UTF8.GetBytes(name),new byte[]{1},U32(7200),U64(30),B(64,0xa0)],17,fixture.Device); }
    private static GroupRecord Genesis(Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture fixture,VerifiedContactBundleClosure contact)
    { var account=contact.Directory.Record.DeepAccountId.ToArray();var active=contact.Directory.Identity.ActiveDevices.Single();var device=active.Certificate.DeviceId.ToArray();var dpd=RefHash("DPD1",active.Certificate.CanonicalHash.Span);return SignedRecord("DGC1",[contact.Directory.Record.NetworkId,B(32,0x30),U16(1),U64(0),new byte[32],account,device,dpd,U16(0),Array.Empty<byte>(),U16(1),MemberFrom(contact,GroupRole.Owner),Encoding.UTF8.GetBytes("genesis"),new byte[]{0},U32(3600),U64(30),B(64,0xa0)],17,fixture.Device); }
    private static GroupRecord ActivationCommit(GroupCommitRecord genesis,GroupRecord proposal,Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture fixture,VerifiedContactBundleClosure owner,byte[] members,ulong issuedAt)
    { var active=owner.Directory.Identity.ActiveDevices.Single();return SignedRecord("DGC1",[owner.Directory.Record.NetworkId,B(32,0x30),U16(1),U64(1),genesis.ArtifactHash,owner.Directory.Record.DeepAccountId,active.Certificate.DeviceId,RefHash("DPD1",active.Certificate.CanonicalHash.Span),U16(1),proposal.ArtifactHash,U16(2),members,Encoding.UTF8.GetBytes("genesis"),new byte[]{0},U32(3600),U64(issuedAt),B(64,0xa0)],17,fixture.Device); }
    private static byte[] MemberFrom(VerifiedContactBundleClosure contact,GroupRole role){var active=contact.Directory.Identity.ActiveDevices.Single();return Member(contact.Directory.Record.DeepAccountId.ToArray(),role,active.Certificate.DeviceId.ToArray(),contact.Freshness.ExactAdc1Reference.ToArray(),contact.Freshness.ExactAdh1CoreReference.ToArray(),contact.Freshness.ExactAdp1Hash.ToArray(),contact.Directory.Record.RecordHash.ToArray(),RefHash("DRS1",contact.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span),RefHash("DPD1",active.Certificate.CanonicalHash.Span));}
    private static GroupCommitPackageRecord Package(GroupRecord commit,IReadOnlyList<GroupRecord> proposals,(ushort Kind,byte[] Ref,byte[] Bytes)[] support,IReadOnlyList<(GroupRecord Invitation,GroupRecord Acceptance)>? pairs=null)
    { pairs??=[];var proposalBytes=proposals.SelectMany(p=>Lp(p.CanonicalBytes.Span)).ToArray();var supportBytes=SupportEntriesExact(support);var pairBytes=pairs.SelectMany(pair=>Join(GroupCodec.ArtifactReference("GIV1",pair.Invitation).CanonicalBytes.ToArray(),Lp(pair.Invitation.CanonicalBytes.Span),GroupCodec.ArtifactReference("GIA1",pair.Acceptance).CanonicalBytes.ToArray(),Lp(pair.Acceptance.CanonicalBytes.Span))).ToArray();return Assert.IsType<GroupCommitPackageRecord>(Record("GCP1",[commit.Field(1),commit.Field(2),commit.Field(4),Lp(commit.CanonicalBytes.Span),U16(checked((ushort)proposals.Count)),proposalBytes,U32(checked((uint)support.Length)),supportBytes,U16(checked((ushort)pairs.Count)),pairBytes,Array.Empty<byte>()])); }
    private static (ushort Kind,byte[] Ref,byte[] Bytes)[] VerifiedSupport(Deep.Protocol.Tests.ContactV1.ContactCodecSecurityTests.CryptoDcrFixture fixture,VerifiedContactBundleClosure contact)=>
    [(1,contact.Freshness.ExactAdc1Reference.ToArray(),fixture.Adc),(2,contact.Freshness.ExactAdh1CoreReference.ToArray(),fixture.Adh),(3,RefHash("ADP1",contact.Freshness.ExactAdp1Hash.Span),fixture.Adp),(4,RefHash("DMD1",contact.Directory.Record.RecordHash.Span),contact.Directory.Record.CanonicalBytes.ToArray()),(5,RefHash("DRS1",contact.Directory.Identity.Revocations.Snapshot.CanonicalHash.Span),fixture.Drs),(6,RefHash("DPD1",contact.Directory.Identity.ActiveDevices.Single().Certificate.CanonicalHash.Span),fixture.Dpd)];
    private static byte[] SupportEntriesExact(IEnumerable<(ushort Kind,byte[] Ref,byte[] Bytes)> support){var bytes=new List<byte>();foreach(var item in support.OrderBy(x=>x.Kind).ThenBy(x=>x.Ref,ByteComparer.Instance)){bytes.AddRange(U16(item.Kind));bytes.AddRange(item.Ref);bytes.AddRange(Lp(item.Bytes));}return bytes.ToArray();}
    private static byte[] Join(params byte[][] parts){var result=new byte[parts.Sum(x=>x.Length)];var at=0;foreach(var part in parts){part.CopyTo(result,at);at+=part.Length;}return result;}
    private sealed class MemoryGroupStore:IGroupSuccessorStateStore{private byte[] value=GroupSuccessorLatch.CreateEmpty().Snapshot.ToArray();public ReadOnlyMemory<byte> Value=>value.ToArray();public bool CompareExchange(ReadOnlyMemory<byte> expected,ReadOnlyMemory<byte> replacement){if(!value.AsSpan().SequenceEqual(expected.Span))return false;value=replacement.ToArray();return true;}}

    private static ReadOnlyMemory<byte>[] InvitationFields() =>
    [B(16,1),B(32,2),B(32,3),U64(0),B(32,4),B(32,5),B(32,6),Ref("DPD1",7),B(32,8),new byte[]{3},Ref("ADC1",9),Ref("ADH1",10),B(32,11),B(32,12),Ref("DRS1",13),U64(1),U64(2),B(64,14)];
    private static ReadOnlyMemory<byte>[] AcceptanceFields(GroupRecord invitation) =>
    [invitation.Field(1),invitation.Field(2),invitation.Field(3),GroupCodec.ArtifactReference("GIV1", invitation).CanonicalBytes,B(32,8),B(32,15),Ref("DPD1",16),Ref("ADC1",17),Ref("ADH1",18),B(32,19),B(32,20),Ref("DRS1",21),U64(1),U64(2),B(64,22)];
    private static byte[] Member(byte[] account, GroupRole role, byte[] device) => Member(account,role,device,Ref("ADC1",4),Ref("ADH1",5),B(32,6),B(32,7),Ref("DRS1",8),Ref("DPD1",9));
    private static byte[] Member(byte[] account, GroupRole role, byte[] device, byte[] adc, byte[] adh, byte[] adp, byte[] dmd, byte[] drs, byte[] dpd)
    { var body=new byte[290]; account.CopyTo(body,0);body[32]=(byte)role;adc.CopyTo(body,33);adh.CopyTo(body,71);adp.CopyTo(body,109);U64(1).CopyTo(body,141);dmd.CopyTo(body,149);drs.CopyTo(body,181);body[219]=1;device.CopyTo(body,220);dpd.CopyTo(body,252);var r=new byte[292];BinaryPrimitives.WriteUInt16BigEndian(r,290);body.CopyTo(r,2);return r; }
    private static byte[] MemberWithDevices(byte[] account,GroupRole role,(byte[] Id,byte[] Ref)[] devices){var ordered=devices.OrderBy(item=>item.Id,ByteComparer.Instance).ToArray();var body=new byte[220+70*ordered.Length];account.CopyTo(body,0);body[32]=(byte)role;Ref("ADC1",4).CopyTo(body,33);Ref("ADH1",5).CopyTo(body,71);B(32,6).CopyTo(body,109);U64(1).CopyTo(body,141);B(32,7).CopyTo(body,149);Ref("DRS1",8).CopyTo(body,181);body[219]=checked((byte)ordered.Length);for(var i=0;i<ordered.Length;i++){ordered[i].Id.CopyTo(body,220+70*i);ordered[i].Ref.CopyTo(body,252+70*i);}var result=new byte[body.Length+2];BinaryPrimitives.WriteUInt16BigEndian(result,checked((ushort)body.Length));body.CopyTo(result,2);return result;}
    private static byte[] HashRef(string magic,byte[] bytes){var r=new byte[38];Encoding.ASCII.GetBytes(magic).CopyTo(r,0);r[5]=1;SHA256.HashData(bytes).CopyTo(r,6);return r;}
    private static byte[] RefHash(string magic,ReadOnlySpan<byte> hash){var r=new byte[38];Encoding.ASCII.GetBytes(magic).CopyTo(r,0);r[5]=1;hash.CopyTo(r.AsSpan(6));return r;}
    private static byte[] Lp(ReadOnlySpan<byte> bytes){var r=new byte[4+bytes.Length];BinaryPrimitives.WriteUInt32BigEndian(r,(uint)bytes.Length);bytes.CopyTo(r.AsSpan(4));return r;}
    private static GroupRecord Record(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields) => GroupCodec.Decode(magic, Encode(magic, fields));
    private static GroupRecord RecordTagged(string magic,IReadOnlyList<int> tags,IReadOnlyList<ReadOnlyMemory<byte>> fields)=>GroupCodec.Decode(magic,EncodeTagged(magic,tags,fields));
    private static byte[] Encode(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
        => EncodeTagged(magic,Enumerable.Range(1,fields.Count).ToArray(),fields);
    private static byte[] EncodeTagged(string magic,IReadOnlyList<int> tags,IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        Assert.Equal(tags.Count,fields.Count);
        var size=checked(12+fields.Sum(field=>8+field.Length));var bytes=new byte[size];Encoding.ASCII.GetBytes(magic).CopyTo(bytes,0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4),1);BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6),0x0201);BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8),checked((ushort)fields.Count));
        var at=12;for(var i=0;i<fields.Count;i++){BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(at),checked((ushort)tags[i]));BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(at+4),checked((uint)fields[i].Length));at+=8;fields[i].Span.CopyTo(bytes.AsSpan(at));at+=fields[i].Length;}return bytes;
    }
    private static byte[] SupportEntries((ushort Kind,string Magic,byte[] Bytes)[] support,Dictionary<ushort,byte[]> refs){var bytes=new List<byte>();foreach(var item in support){bytes.AddRange(U16(item.Kind));bytes.AddRange(refs[item.Kind]);bytes.AddRange(Lp(item.Bytes));}return bytes.ToArray();}
    private static int FieldOffset(ReadOnlySpan<byte> bytes, int wanted) { var at=12;for(var i=1;i<=BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(8,2));i++){var length=checked((int)BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(at+4,4)));at+=8;if(i==wanted)return at;at+=length;}throw new InvalidOperationException(); }
    private static int SignatureTag(string magic)=>magic switch{"GIV1"=>18,"GIA1"=>15,"DGP1"=>13,"DGC1"=>17,"DGT1"=>14,"GSR1"=>14,_=>throw new InvalidOperationException()};
    private static byte[] B(int n,byte seed)=>Enumerable.Range(0,n).Select(i=>(byte)(seed+i)).ToArray();
    private static byte[] U16(ushort n){var b=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(b,n);return b;}
    private static byte[] U32(uint n){var b=new byte[4];BinaryPrimitives.WriteUInt32BigEndian(b,n);return b;}
    private static byte[] U64(ulong n){var b=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(b,n);return b;}
    private static byte[] Ref(string magic,byte seed){var b=new byte[38];Encoding.ASCII.GetBytes(magic).CopyTo(b,0);b[5]=1;B(32,seed).CopyTo(b,6);return b;}
    private static byte[] ProfileAction(string name,byte policy,uint expiry){var text=Encoding.UTF8.GetBytes(name);var result=new byte[2+text.Length+5];BinaryPrimitives.WriteUInt16BigEndian(result,checked((ushort)text.Length));text.CopyTo(result,2);result[2+text.Length]=policy;BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(3+text.Length),expiry);return result;}
    private static GroupRecord SignedRecord(string magic,IReadOnlyList<ReadOnlyMemory<byte>> original,int signatureTag,KeyPair key)
    {
        var fields=original.Select(field=>(ReadOnlyMemory<byte>)field.ToArray()).ToArray();fields[signatureTag-1]=B(64,0xa0);var placeholder=Record(magic,fields);
        fields[signatureTag-1]=PublicKeyAuth.SignDetached(placeholder.SignatureInput.ToArray(),key.PrivateKey);return Record(magic,fields);
    }
    private static string FindSpec(string name) { var path=Directory.GetCurrentDirectory();while(path is not null){var candidate=Path.Combine(path,"..","docs","survival-program","releases","v3.0.0","specs",name);if(File.Exists(candidate))return candidate;path=Directory.GetParent(path)?.FullName;}throw new FileNotFoundException(name); }
    private sealed class Resolver(Dictionary<string,byte[]> values) : IGroupClosureResolver { public ReadOnlyMemory<byte>? Resolve(GroupArtifactReference reference) => values.TryGetValue(Convert.ToHexString(reference.CanonicalBytes.Span),out var value) ? value : null; }
    private sealed class ByteComparer:IComparer<byte[]>{internal static readonly ByteComparer Instance=new();public int Compare(byte[]? left,byte[]? right)=>(left??[]).AsSpan().SequenceCompareTo(right??[]);}

}
