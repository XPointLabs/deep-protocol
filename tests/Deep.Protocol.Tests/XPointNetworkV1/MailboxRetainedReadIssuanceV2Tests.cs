using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Tests.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Fixture = Deep.Protocol.Tests.XPointNetworkV1.XPointOnionCapabilityProducerTests.Fixture;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class MailboxRetainedReadIssuanceV2Tests
{
    [Fact]
    public void FrozenTupleMatchesIndependentExactBytesAndRealSignature()
    {
        using var document = ReadSpec("mailbox-retained-read-v2.vectors.json");
        var vector = document.RootElement.GetProperty("positive");
        var tuple = MailboxRetainedReadEvidenceAuthentication.CreateTuple(Hex(vector,"requestHashHex"),
            Hex(vector,"locatorHashHex"), Hex(vector,"retrieveCapabilityDigestHex"), Hex(vector,"originalRouteHashHex"),
            vector.GetProperty("readUntil").GetUInt64());
        Assert.Equal(Hex(vector,"tupleHex"), tuple);
        var signing = MailboxRetainedReadEvidenceAuthentication.GetSigningBytes(tuple);
        Assert.Equal(Hex(vector,"signingInputHex"), signing);
        var pair = PublicKeyAuth.GenerateKeyPair(B(32,0x55));
        var signature = PublicKeyAuth.SignDetached(Hex(vector,"signingInputHex"), pair.PrivateKey);
        Assert.True(PublicKeyAuth.VerifyDetached(signature, signing, pair.PublicKey));
        Assert.False(PublicKeyAuth.VerifyDetached(signature,
            MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(new byte[139]), pair.PublicKey));
    }

    [Theory]
    [InlineData(0)] [InlineData(135)] [InlineData(137)] [InlineData(139)]
    public void TupleWrongExactLengthCannotCrossFeedCurrentEvidence(int length) =>
        Assert.Throws<ArgumentException>(() => MailboxRetainedReadEvidenceAuthentication.GetSigningBytes(new byte[length]));

    [Theory]
    [InlineData(0)] [InlineData(32)] [InlineData(64)] [InlineData(96)] [InlineData(128)]
    public void TupleRejectsMissingScopeOrHorizon(int offset)
    {
        var tuple = MailboxRetainedReadEvidenceAuthentication.CreateTuple(B(32,1),B(32,2),B(32,3),B(32,4),300);
        tuple.AsSpan(offset, offset == 128 ? 8 : 32).Clear();
        Assert.Throws<ArgumentException>(() => MailboxRetainedReadEvidenceAuthentication.GetSigningBytes(tuple));
    }

    [Fact]
    public void MachineAndSchemaRemainClosedAndBindActualCodec()
    {
        using var registry = ReadSpec("mailbox-retained-read-v2.registry.json");
        using var schema = ReadSpec("mailbox-retained-read-v2.registry.schema.json");
        var value = registry.RootElement; var contract = schema.RootElement;
        Assert.False(contract.GetProperty("additionalProperties").GetBoolean());
        Assert.Equal(value.EnumerateObject().Select(p=>p.Name).Order(),
            contract.GetProperty("required").EnumerateArray().Select(p=>p.GetString()).Order());
        foreach (var field in value.EnumerateObject())
            Assert.True(JsonElement.DeepEquals(field.Value, contract.GetProperty("properties").GetProperty(field.Name).GetProperty("const")));
        Assert.Equal("DR-0104",value.GetProperty("decision").GetString());
        Assert.False(value.GetProperty("runtimeActivation").GetBoolean());
        Assert.Empty(value.GetProperty("newMagic").EnumerateArray());
        Assert.Equal(MailboxRetainedReadEvidenceAuthentication.TupleLength,value.GetProperty("tupleBytes").GetInt32());
        Assert.Equal(MailboxRetainedReadEvidenceAuthentication.SigningDomain,value.GetProperty("signingDomain").GetString());
        Assert.Equal(MailboxRetainedReadAuthorityAuthentication.SigningDomain,value.GetProperty("forwardingSigningDomain").GetString());
        Assert.Equal(VerifiedMailboxHostAuthorityV2.MaximumRetainedObjectHorizonSeconds,value.GetProperty("objectHorizonMaximumSeconds").GetUInt64());
        Assert.False(value.GetProperty("storeAllowed").GetBoolean());
        Assert.False(value.GetProperty("rerankAllowed").GetBoolean());
        Assert.Equal(18, value.GetProperty("privateReadRpcOperation").GetInt32());
        Assert.Equal(7, value.GetProperty("privateReceiptKind").GetInt32());
        Assert.Equal(2, value.GetProperty("authorityEvidenceKind").GetInt32());
        Assert.Empty(typeof(VerifiedMailboxRetainedReadIssuanceV2).GetConstructors());
        Assert.Empty(typeof(VerifiedMailboxRetainedReadGrantV2).GetConstructors());
        Assert.All(typeof(VerifiedMailboxRetainedReadGrantV2).GetProperties(),p=>Assert.False(p.CanWrite));
    }

    [Theory]
    [InlineData(false,false)] [InlineData(false,true)] [InlineData(true,false)] [InlineData(true,true)]
    public async Task SignedHistoryAndTwoDistinctCurrentKeysIssueAfterOriginalRouteExpiry(bool cold,bool unchangedEpoch)
    {
        var f = await State.Create(cold,unchangedEpoch);
        Assert.True(f.Route.Projection.Field(12).Span.SequenceEqual(U64(210)));
        var current = await f.Host.VerifyRetainedReadRequestAsync(f.Request);
        Assert.Equal(230UL,(await current.ReadCurrentTimeAsync()).UpperUnixSeconds);
        var issuance = await f.Issuance();
        var response = (await issuance.AuthorSuccessAsync(new Issuer())).ToArray();
        await issuance.VerifySuccessAsync(response);
        var verified = await f.Host.VerifyRetainedReadSuccessAsync(f.Route.ExactBytes,f.Request,response);
        await verified.EnsureCurrentAsync();
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(verified.ExactGrant.Span);
        Assert.Equal(MailboxCapabilityDomain.Retrieve,grant.Domain);
        Assert.True(grant.ExpiresAtUnixSeconds > 210);
        Assert.Equal(f.Route.Projection.ArtifactHash.ToArray(),grant.MembershipCommitment.ToArray());
        Assert.Equal(f.Route.Selection.Field(3).ToArray(),grant.SelectionInput.ToArray());
        Assert.Equal(f.Route.Projection.Field(6).ToArray(),U64(grant.Epoch));
        Assert.Equal(2,(await f.Host.GetSelectedRetainedReadReplicasAsync(verified.ExactGrant)).Count);
        if (!unchangedEpoch)
            await Assert.ThrowsAsync<CryptographicException>(()=>f.Host.ResolveGrantReplicasAsync(verified.ExactGrant).AsTask());
        response[^1] ^= 1;
        Assert.NotNull(await Record.ExceptionAsync(()=>f.Host.VerifyRetainedReadSuccessAsync(f.Route.ExactBytes,f.Request,response).AsTask()));
    }

    [Theory]
    [InlineData("signature")] [InlineData("duplicate")] [InlineData("wrong-key")]
    [InlineData("current-purpose")] [InlineData("horizon")] [InlineData("missing")]
    public async Task EvidenceCannotSubstituteEitherStorePurposeOrHorizon(string defect)
    {
        var f = await State.Create(); var evidence = f.Evidence(); var horizon = f.Horizon;
        if (defect == "signature") { var bytes=evidence[1].Signature.ToArray();bytes[1]^=1;evidence[1]=new(evidence[1].NodeId.Span,bytes); }
        if (defect == "duplicate") evidence[1]=evidence[0];
        if (defect == "wrong-key") evidence[1]=new(evidence[1].NodeId.Span,PublicKeyAuth.SignDetached(f.Signing(),PublicKeyAuth.GenerateKeyPair(B(32,0xef)).PrivateKey));
        if (defect == "current-purpose") evidence=f.Evidence(currentPurpose:true);
        if (defect == "horizon") horizon++;
        if (defect == "missing") evidence=evidence[..1];
        await Assert.ThrowsAsync<CryptographicException>(()=>f.Host.VerifyRetainedReadIssuanceAsync(f.Request,f.Route.ExactBytes,horizon,evidence).AsTask());
    }

    [Theory]
    [InlineData("deposit")] [InlineData("route")] [InlineData("ceiling")] [InlineData("expired")]
    public async Task BoundRoleExactRouteAndIndependentHorizonReject(string defect)
    {
        var f = await State.Create(); var request=f.Request; var horizon=f.Horizon;
        if (defect == "deposit") request=f.AuthorRequest(MailboxCapabilityDomain.Deposit);
        if (defect == "route") request=f.AuthorRequest(routeHash:B(32,0xab));
        if (defect == "ceiling") horizon=210+VerifiedMailboxHostAuthorityV2.MaximumRetainedObjectHorizonSeconds+1;
        if (defect == "expired") horizon=230;
        await Assert.ThrowsAsync<CryptographicException>(()=>f.Host.VerifyRetainedReadIssuanceAsync(request,f.Route.ExactBytes,horizon,f.Evidence(request,horizon)).AsTask());
    }

    [Fact]
    public async Task FreshRequestAuthorAndRestoreDoNotRequireOldRouteToBeLive()
    {
        var f=await State.Create();var holder=new Holder();
        var request=await f.Host.AuthorRetainedReadRequestAsync(f.Route.ExactBytes,B(32,0x66),B(32,0x67),holder);
        var restored=await f.Host.RestoreRetainedReadRequestAsync(f.Route.ExactBytes,B(32,0x66),B(32,0x67),holder.Ed25519PublicKey,request.ExactXmg2);
        Assert.Equal(request.ExactXmg2.ToArray(),restored.ExactXmg2.ToArray());
        Assert.Equal(f.Route.ExactHash.ToArray(),request.Record.Field(11).ToArray());
        Assert.Equal(1,holder.Calls);
        await Assert.ThrowsAsync<CryptographicException>(()=>f.Host.RestoreRetainedReadRequestAsync(f.Route.ExactBytes,B(32,0x66),B(32,0x68),holder.Ed25519PublicKey,request.ExactXmg2).AsTask());
        var issuance=await f.Host.VerifyRetainedReadIssuanceAsync(request.ExactXmg2,f.Route.ExactBytes,f.Horizon,f.Evidence(request.ExactXmg2.ToArray()));
        _=await issuance.AuthorSuccessAsync(new Issuer());
    }

    [Theory]
    [InlineData("expiry")] [InlineData("rollback")] [InlineData("boot")] [InlineData("cancel")]
    public async Task IssuerCallbackCannotReleaseSuccessAfterCurrentAuthorityLoss(string defect)
    {
        var f=await State.Create();var issuance=await f.Issuance();using var cancellation=new CancellationTokenSource();
        var issuer=new Issuer { OnSign=()=>{
            if(defect=="expiry")f.Clock.Sample=1_300;
            if(defect=="rollback")f.Clock.Sample=1_024;
            if(defect=="boot")f.Clock.Boot=B(16,0xef);
            if(defect=="cancel")cancellation.Cancel();
        }};
        if(defect=="cancel")await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>issuance.AuthorSuccessAsync(issuer,cancellation.Token).AsTask());
        else await Assert.ThrowsAsync<CryptographicException>(()=>issuance.AuthorSuccessAsync(issuer,cancellation.Token).AsTask());
        Assert.Equal(1,issuer.Calls);
    }

    [Fact]
    public async Task WrongIssuerRejectsBeforeSignAndInvalidReturnedSignatureRejects()
    {
        var f=await State.Create();var issuance=await f.Issuance();var wrong=new Issuer { KeyMarker=0xe1 };
        await Assert.ThrowsAsync<CryptographicException>(()=>issuance.AuthorSuccessAsync(wrong).AsTask());Assert.Equal(0,wrong.Calls);
        var bad=new Issuer { SignatureMarker=0xe1 };
        await Assert.ThrowsAsync<CryptographicException>(()=>issuance.AuthorSuccessAsync(bad).AsTask());Assert.Equal(1,bad.Calls);
    }

    [Fact]
    public async Task CancellationBeforeSigningDoesNotInvokeIssuer()
    {
        var f = await State.Create();
        var issuance = await f.Issuance();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var issuer = new Issuer();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            issuance.AuthorSuccessAsync(issuer, cancellation.Token).AsTask());
        Assert.Equal(0, issuer.Calls);
    }

    [Fact]
    public async Task ColdWinnerPastRequestExpiryRequiresStillCurrentGrantAndNeverRenews()
    {
        var f = await State.Create();
        var request = f.AuthorRequest(expires: 232);
        var issuance = await f.Host.VerifyRetainedReadIssuanceAsync(request, f.Route.ExactBytes,
            245, f.Evidence(request, 245));
        var result = await issuance.AuthorSuccessAsync(new Issuer());
        // Interval233..243 is past XMG2 expiry232, before MCG3 expiry245,
        // and still within the independent signed freshness deadline1050.
        f.Clock.Sample = 1_038;
        var verified = await f.Host.VerifyRetainedReadSuccessAsync(f.Route.ExactBytes, request, result);
        var before = verified.ExactGrant.ToArray();
        await verified.EnsureCurrentAsync();
        Assert.Equal(before, verified.ExactGrant.ToArray());
        await Assert.ThrowsAsync<CryptographicException>(() => f.Host.RestoreRetainedReadRequestAsync(
            f.Route.ExactBytes, B(32, 0x66), B(32, 0x67), new Holder().Ed25519PublicKey, request).AsTask());
        // The entire uncertainty interval must fit. Reaching its expiry is not renewal.
        f.Clock.Sample = 1_040;
        await Assert.ThrowsAsync<CryptographicException>(() => verified.EnsureCurrentAsync().AsTask());
        await Assert.ThrowsAsync<CryptographicException>(() => f.Host.VerifyRetainedReadSuccessAsync(
            f.Route.ExactBytes, request, result).AsTask());
    }

    [Fact]
    public async Task ResultRouteFieldSubstitutionRejectsEvenWithValidIssuerGrant()
    {
        var f = await State.Create();
        var exact = await (await f.Issuance()).AuthorSuccessAsync(new Issuer());
        var parsed = ContactCodec.Decode("XMC2", exact.Span);
        var fields = Enumerable.Range(1, 8).Select(parsed.Field).ToArray();
        fields[6] = B(32, 0xef);
        var changed = ContactCodec.AuthorForOperationalAuthority("XMC2", fields);
        Assert.Equal(parsed.Field(8).ToArray(), changed.Field(8).ToArray());
        var error = await Assert.ThrowsAsync<ContactFormatException>(() => f.Host.VerifyRetainedReadSuccessAsync(
            f.Route.ExactBytes, f.Request, changed.CanonicalBytes).AsTask());
        Assert.Equal("MailboxGrantResultRouteIntentMismatch", error.Message);
    }

    [Theory]
    [InlineData("expiry")] [InlineData("rollback")] [InlineData("boot")] [InlineData("cancel")]
    public async Task HolderCallbackCannotAuthorAfterAuthorityLoss(string defect)
    {
        var f = await State.Create();
        using var cancellation = new CancellationTokenSource();
        var holder = new Holder { OnSign = () => {
            if (defect == "expiry") f.Clock.Sample = 1_300;
            if (defect == "rollback") f.Clock.Sample = 1_024;
            if (defect == "boot") f.Clock.Boot = B(16, 0xef);
            if (defect == "cancel") cancellation.Cancel();
        }};
        var call = () => f.Host.AuthorRetainedReadRequestAsync(f.Route.ExactBytes,
            B(32, 0x66), B(32, 0x67), holder, cancellation.Token).AsTask();
        if (defect == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(call);
        else await Assert.ThrowsAsync<CryptographicException>(call);
        Assert.Equal(1, holder.Calls);
    }

    [Fact]
    public async Task MissingHistoryAndRemovedOriginalReplicaNeverRerank()
    {
        var f=await State.Create();var fixture=Fixture.Create();var plain=await fixture.VerifyMailboxAsync();
        var omitted=await MailboxHostAuthorityV2Verifier.VerifyAsync(plain.Network,fixture.Authority,plain.Pma,new(new Time()));
        await Assert.ThrowsAsync<CryptographicException>(()=>omitted.VerifyRetainedReadIssuanceAsync(f.Request,f.Route.ExactBytes,f.Horizon,f.Evidence()).AsTask());
        var selected=f.Route.Selection.Field(6).ToArray()[..32];
        var index=fixture.NodeIds.Select((id,i)=>(id,i)).Single(x=>x.id.AsSpan().SequenceEqual(selected)).i;
        var removed=await fixture.VerifyMailboxHistoryAsync(removedMailboxNode:index);
        var host=await MailboxHostAuthorityV2Verifier.VerifyAsync(removed.Network,fixture.Authority,removed.Pma,new(new Time()));
        await Assert.ThrowsAsync<CryptographicException>(()=>host.VerifyRetainedReadIssuanceAsync(f.Request,f.Route.ExactBytes,f.Horizon,f.Evidence()).AsTask());
    }

    [Fact]
    public async Task InputsAreCapturedBeforeCallbacksAndCopiesCannotRedirectIssuer()
    {
        var f=await State.Create();var request=f.Request.ToArray();var route=f.Route.ExactBytes.ToArray();var evidence=f.Evidence();
        f.Clock.OnRead=()=>{Array.Clear(request);Array.Clear(route);};
        var issuance=await f.Host.VerifyRetainedReadIssuanceAsync(request,route,f.Horizon,evidence);
        Assert.Equal(f.Request,issuance.ExactXmg2.ToArray());Assert.Equal(f.Route.ExactBytes.ToArray(),issuance.ExactRouteClosure.ToArray());
        f.Clock.OnRead=null;
        var copy=issuance.ExactRouteClosure.ToArray();Array.Clear(copy);
        _=await issuance.AuthorSuccessAsync(new Issuer());
    }

    [Fact]
    public async Task PrivateForwardingBindsNewPurposeHorizonAndOriginalDeadline()
    {
        var f=await State.Create();var route=f.Route.ExactBytes.ToArray();var expiry=ContactCodec.Decode("XMG2",f.Request).Field(10).ToArray();
        var input=MailboxRetainedReadAuthorityAuthentication.GetSigningBytes(f.Request,route,f.Horizon,BinaryPrimitives.ReadUInt64BigEndian(expiry),B(32,0x11),220,B(32,0x12));
        var changed=MailboxRetainedReadAuthorityAuthentication.GetSigningBytes(f.Request,route,f.Horizon-1,BinaryPrimitives.ReadUInt64BigEndian(expiry),B(32,0x11),220,B(32,0x12));
        Assert.NotEqual(input,changed);
        Assert.True(input.AsSpan(0,MailboxRetainedReadAuthorityAuthentication.SigningDomain.Length).SequenceEqual(Encoding.ASCII.GetBytes(MailboxRetainedReadAuthorityAuthentication.SigningDomain)));
        Assert.Throws<ArgumentException>(()=>MailboxRetainedReadAuthorityAuthentication.GetSigningBytes(f.Request,route,f.Horizon,299,B(32,0x11),220,B(32,0x12)));
    }

    private sealed class State
    {
        internal required VerifiedMailboxHostAuthorityV2 Host; internal required VerifiedOnionNetworkContext Network;
        internal required ParsedContactRouteClosure Route; internal required Time Clock; internal required byte[] Request;
        internal ulong Horizon=>300;
        internal static async Task<State> Create(bool cold=false,bool unchangedEpoch=false)
        {
            var fixture=Fixture.Create();var input=await fixture.VerifyMailboxHistoryAsync(cold,unchangedEpoch);var clock=new Time();
            var state=new State {Host=await MailboxHostAuthorityV2Verifier.VerifyAsync(input.Network,fixture.Authority,input.Pma,new(clock)),Network=input.Network,
                Route=MakeRoute(input.Network.Closure!.RetainedPmts[0]),Clock=clock,Request=[]};
            state.Request=state.AuthorRequest();return state;
        }
        internal byte[] AuthorRequest(MailboxCapabilityDomain role=MailboxCapabilityDomain.Retrieve,byte[]? routeHash=null,ulong expires=250)
        {
            var holder=PublicKeyAuth.GenerateKeyPair(B(32,0xa4));var placeholder=B(64,1);
            ReadOnlyMemory<byte>[] fields=[Network.NetworkId,B(32,0x65),B(32,0x66),B(32,0x67),holder.PublicKey,new byte[] { (byte)role },
                ContactCodec.ArtifactReference("PMT2",Route.Projection).CanonicalBytes,Route.Selection.ArtifactHash,U64(220),U64(expires),routeHash??Route.ExactHash.ToArray(),placeholder];
            var unsigned=ContactCodec.AuthorForOperationalAuthority("XMG2",fields);fields[11]=PublicKeyAuth.SignDetached(unsigned.SignatureInput.ToArray(),holder.PrivateKey);
            return ContactCodec.AuthorForOperationalAuthority("XMG2",fields).CanonicalBytes.ToArray();
        }
        internal byte[] Signing(byte[]? request=null,ulong? horizon=null) => MailboxRetainedReadEvidenceAuthentication.GetSigningBytes(
            MailboxRetainedReadEvidenceAuthentication.CreateTuple(SHA256.HashData(request??Request),B(32,0x66),
                MailboxGrantCapabilityDigest.Compute(B(32,0x67),MailboxCapabilityDomain.Retrieve),Route.ExactHash.Span,horizon??Horizon));
        internal DeepIdV2MailboxGrantReplicaEvidence[] Evidence(byte[]? request=null,ulong? horizon=null,bool currentPurpose=false)
        {
            var input=Signing(request,horizon);
            if(currentPurpose)input=MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(MailboxGrantRouteEvidenceAuthentication.CreateTuple(
                SHA256.HashData(request??Request),B(32,0x66),MailboxGrantCapabilityDigest.Compute(B(32,0x67),MailboxCapabilityDomain.Retrieve),2,1,Route.ExactHash.Span,horizon??Horizon));
            return ContactServicePlacementFactory.Create(Network,ContactServiceRequestKind.ResolveInvite,B(32,0x66)).RankedReplicaNodeIds.Select(id=>{
                var index=id.Span[0]-0x10;var pair=PublicKeyAuth.GenerateKeyPair(B(32,(byte)(0x90+index*8)));
                Assert.Equal(Network.ResolveNodeIdentityPublicKey(id).ToArray(),pair.PublicKey);
                return new DeepIdV2MailboxGrantReplicaEvidence(id.Span,PublicKeyAuth.SignDetached(input,pair.PrivateKey));
            }).ToArray();
        }
        internal ValueTask<VerifiedMailboxRetainedReadIssuanceV2> Issuance()=>Host.VerifyRetainedReadIssuanceAsync(Request,Route.ExactBytes,Horizon,Evidence());
    }

    // Canonical opaque historical graph, deliberately not a native XPA custody
    // fixture. Actual signed PMT lineage and two distinct current descriptor-key
    // attestations exercise this Protocol trust boundary; native read-back and
    // original publication admission must be proved by the coupled Node tests.
    private static ParsedContactRouteClosure MakeRoute(ContactRecord pmt)
    {
        var template=ContactCodecTests.Records.RouteClosure;
        ReadOnlyMemory<byte>[] Fields(ContactRecord record,int count)=>Enumerable.Range(1,count).Select(record.Field).ToArray();
        var xraFields=Fields(template.Xra,16);xraFields[0]=pmt.Field(1);xraFields[4]=ContactCodec.ArtifactReference("PMT2",pmt).CanonicalBytes;
        xraFields[11]=U64(100);xraFields[12]=U64(210);var xra=ContactCodec.AuthorForOperationalAuthority("XRA1",xraFields);
        var ranked=ContactRouteThresholdAuthor.RankReplicas(pmt.Field(1).Span,ContactCodec.ArtifactReference("PMT2",pmt).CanonicalBytes.Span,pmt.Field(6).Span,xra.Field(6).Span,pmt.Field(9).Span,2);
        var pmsFields=Fields(template.Pms,11);pmsFields[0]=pmt.Field(1);pmsFields[1]=ContactCodec.ArtifactReference("PMT2",pmt).CanonicalBytes;
        pmsFields[2]=xra.Field(6);pmsFields[3]=pmt.Field(6);pmsFields[5]=ranked;pmsFields[7]=U64(100);pmsFields[8]=U64(210);
        pmsFields[6]=ContactCodec.Sha256Domain("Deep/XPoint/V1/PMS2/selection",ProjectPms(pmsFields.Take(6).ToArray()));
        var pms=ContactCodec.AuthorForOperationalAuthority("PMS2",pmsFields);
        var replicaRows=new byte[128];for(var i=0;i<2;i++){ranked.AsSpan(i*32,32).CopyTo(replicaRows.AsSpan(i*64));B(32,(byte)(0x80+i)).CopyTo(replicaRows,i*64+32);}
        var xrcFields=Fields(template.Xrc,21);xrcFields[0]=pmt.Field(1);xrcFields[4]=ContactCodec.ArtifactReference("XRA1",xra).CanonicalBytes;
        xrcFields[5]=ContactCodec.ArtifactReference("PMT2",pmt).CanonicalBytes;xrcFields[6]=pms.ArtifactHash;xrcFields[7]=pmt.Field(5);xrcFields[14]=replicaRows;
        xrcFields[16]=U64(100);xrcFields[17]=U64(210);xrcFields[18]=pmt.Field(14);var xrc=ContactCodec.AuthorForOperationalAuthority("XRC1",xrcFields);
        var xssFields=Fields(template.Xss,14);xssFields[0]=pmt.Field(1);xssFields[3]=xrc.CoreHash;xssFields[4]=ContactCodec.ArtifactReference("XRC1",xrc).CanonicalBytes;
        xssFields[5]=xssFields[4];xssFields[6]=ContactCodec.ArtifactReference("PMT2",pmt).CanonicalBytes;xssFields[7]=pmt.Field(5);xssFields[8]=pms.ArtifactHash;
        xssFields[9]=U64(100);xssFields[10]=U64(210);xssFields[11]=pmt.Field(14);var xss=ContactCodec.AuthorForOperationalAuthority("XSS1",xssFields);
        var xrrFields=Fields(template.Xrr,20);xrrFields[0]=pmt.Field(1);xrrFields[4]=ContactCodec.ArtifactReference("XRA1",xra).CanonicalBytes;
        xrrFields[5]=ContactCodec.ArtifactReference("XRC1",xrc).CanonicalBytes;xrrFields[6]=ContactCodec.ArtifactReference("XSS1",xss).CanonicalBytes;
        xrrFields[7]=ContactCodec.ArtifactReference("PMT2",pmt).CanonicalBytes;xrrFields[8]=pms.ArtifactHash;xrrFields[15]=U64(100);xrrFields[16]=U64(210);
        var xrr=ContactCodec.AuthorForOperationalAuthority("XRR1",xrrFields);
        return ContactRouteClosureCodec.Decode(ContactRouteClosureCodec.EncodeRecords([xrr,xra,xrc,xss,pmt,pms]));
    }
    private static byte[] ProjectPms(ReadOnlyMemory<byte>[] fields)
    {
        var result=new byte[12+fields.Sum(f=>8+f.Length)];Encoding.ASCII.GetBytes("PMS2").CopyTo(result,0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4),1);BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6),0x0201);BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8),6);
        var offset=12;for(var i=0;i<fields.Length;i++){BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset),(ushort)(i+1));BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset+4),(uint)fields[i].Length);offset+=8;fields[i].Span.CopyTo(result.AsSpan(offset));offset+=fields[i].Length;}return result;
    }
    private sealed class Time:IOnionMonotonicClock
    { internal ulong Sample=1_025;internal byte[] Boot=B(16,0xc1);internal Action? OnRead;public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct){ct.ThrowIfCancellationRequested();OnRead?.Invoke();return ValueTask.FromResult(new OnionMonotonicReading(Boot,Sample));} }
    private sealed class Issuer:IMailboxGrantIssuerSigner
    { internal byte KeyMarker=0xe2,SignatureMarker=0xe2;internal int Calls;internal Action? OnSign;public ReadOnlyMemory<byte> Ed25519PublicKey=>PublicKeyAuth.GenerateKeyPair(B(32,KeyMarker)).PublicKey;public ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> input,CancellationToken ct){Calls++;OnSign?.Invoke();return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(input.ToArray(),PublicKeyAuth.GenerateKeyPair(B(32,SignatureMarker)).PrivateKey));} }
    private sealed class Holder:IReachabilityMailboxHolderSigner
    { internal int Calls;internal Action? OnSign;public ReadOnlyMemory<byte> Ed25519PublicKey=>PublicKeyAuth.GenerateKeyPair(B(32,0xa4)).PublicKey;public ValueTask<int> SignMailboxGrantRequestAsync(ReadOnlyMemory<byte> input,Memory<byte> signature,CancellationToken ct){ct.ThrowIfCancellationRequested();Calls++;OnSign?.Invoke();PublicKeyAuth.SignDetached(input.ToArray(),PublicKeyAuth.GenerateKeyPair(B(32,0xa4)).PrivateKey).CopyTo(signature);return ValueTask.FromResult(64);} }
    private static byte[] B(int length,byte marker)=>Enumerable.Repeat(marker,length).ToArray();
    private static byte[] U64(ulong value){var bytes=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(bytes,value);return bytes;}
    private static JsonDocument ReadSpec(string file)=>JsonDocument.Parse(File.ReadAllText(XPointNetworkFrozenVectorManifest.FindSpec(file)));
    private static byte[] Hex(JsonElement element,string field)=>Convert.FromHexString(element.GetProperty(field).GetString()!);
}
