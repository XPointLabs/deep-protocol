using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class XPointNetworkVerificationTests
{
    [Fact]
    public void XnaSuccessorUsesAcceptedPredecessorThresholdNotSuccessorThreshold()
    {
        var predecessor=XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkTestRecords.CreateXna(8,5,5));
        var successor=XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkTestRecords.CreateXna(1,1,1,1,predecessor.CoreHash));
        var resolver=new Resolver();
        resolver.ExternalCore=new XPointExternalEvidence("DTS1",successor.NetworkId,default,0,0,successor.FieldBytes(13),30,default);
        var verifier=new AcceptingVerifier();

        var error=Assert.Throws<XPointValidationException>(()=>XPointNetworkVerifier.Verify(successor,
            new XPointVerificationContext(resolver,verifier,predecessor)));

        Assert.Equal(XPointValidationStage.Closure,error.Stage);
        Assert.Equal("WrongAuthorizingThreshold",error.Error);
        Assert.Equal(1,verifier.Calls);
    }

    [Fact]
    public void XnaOneOfOneToTwoOfThreeUsesOnePredecessorReceipt()
    {
        var predecessor=XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkTestRecords.CreateXna(1,1,1));
        var successor=XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkTestRecords.CreateXna(3,2,1,1,predecessor.CoreHash));
        var resolver=new Resolver
        {
            ExternalCore=new XPointExternalEvidence("DTS1",successor.NetworkId,default,0,0,successor.FieldBytes(13),30,default),
        };
        var verifier=new AcceptingVerifier();
        XPointNetworkVerifier.Verify(successor,new XPointVerificationContext(resolver,verifier,predecessor));
        Assert.Equal(1,verifier.Calls);
    }

    [Fact]
    public void XcdKeysAndGenerationsBindToExactTargetAndReplicaCallRelayRoles()
    {
        var target=XPointNetworkCodec.Parse<Xnd1Record>(XPointNetworkTestRecords.CreateCallRelayXnd(2,40,50));
        var first=XPointNetworkCodec.Parse<Xnd1Record>(XPointNetworkTestRecords.CreateCallRelayXnd(3,41,51));
        var second=XPointNetworkCodec.Parse<Xnd1Record>(XPointNetworkTestRecords.CreateCallRelayXnd(4,42,52));
        var encoded=XPointNetworkTestRecords.CreateXcdBound(target,first,second);
        var record=XPointNetworkCodec.Parse<Xcd1Record>(encoded);
        var resolver=new Resolver(target,first,second);
        var signatures=new AcceptingVerifier();

        XPointNetworkVerifier.Verify(record,new XPointVerificationContext(resolver,signatures));
        Assert.Equal(3,signatures.Calls);

        var changed=XPointNetworkTestRecords.MutateField(encoded,5,value=>value[0]^=0x40);
        var mismatch=XPointNetworkCodec.Parse<Xcd1Record>(changed);
        var error=Assert.Throws<XPointValidationException>(()=>
            XPointNetworkVerifier.Verify(mismatch,new XPointVerificationContext(resolver,signatures)));
        Assert.Equal("CallRelayRoleKeyMismatch",error.Error);

        var wrongDomain=XPointNetworkTestRecords.MutateField(encoded,8,value=>value[104]^=1);
        Assert.Equal("InvalidCallRelayAuthority",Assert.Throws<XPointValidationException>(()=>
            XPointNetworkVerifier.Verify(XPointNetworkCodec.Parse<Xcd1Record>(wrongDomain),new XPointVerificationContext(resolver,new AcceptingVerifier()))).Error);

        Assert.Equal("InvalidCallRelayProofOfPossession",Assert.Throws<XPointValidationException>(()=>
            XPointNetworkVerifier.Verify(record,new XPointVerificationContext(resolver,new AcceptingVerifier(false)))).Error);

        resolver.Active=false;
        Assert.Equal("InvalidCallRelayReplicaClosure",Assert.Throws<XPointValidationException>(()=>
            XPointNetworkVerifier.Verify(record,new XPointVerificationContext(resolver,new AcceptingVerifier()))).Error);
    }

    [Fact]
    public void TransitionClassifierAndErrorsFreezeForkGapMismatchAndOverflow()
    {
        var prior=XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkTestRecords.CreateXna(1,1,1));
        var sameChanged=XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkTestRecords.MutateField(prior.CanonicalCopy(),13,v=>v[0]^=1));
        Assert.Equal(XPointTransitionClassification.Fork,XPointNetworkVerifier.Classify(prior,sameChanged));
        Assert.Equal("ForkDetected",Assert.Throws<XPointValidationException>(()=>XPointNetworkVerifier.RequireSuccessor(prior,sameChanged)).Error);

        var gap=XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkTestRecords.CreateXna(1,1,1,2,prior.CoreHash));
        Assert.Equal("GenerationGap",Assert.Throws<XPointValidationException>(()=>XPointNetworkVerifier.RequireSuccessor(prior,gap)).Error);

        var wrong=XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkTestRecords.CreateXna(1,1,1,1,new XPointBytes(XPointNetworkTestRecords.Id(99))));
        Assert.Equal("PredecessorMismatch",Assert.Throws<XPointValidationException>(()=>XPointNetworkVerifier.RequireSuccessor(prior,wrong)).Error);

        var maximum=XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkTestRecords.CreateXna(1,1,1,ulong.MaxValue,new XPointBytes(XPointNetworkTestRecords.Id(98))));
        Assert.Equal("ArithmeticOverflow",Assert.Throws<XPointValidationException>(()=>XPointNetworkVerifier.RequireSuccessor(maximum,wrong)).Error);
    }

    [Fact]
    public void XnhGenesisCannotRollbackWhenCallerAlreadyHasAnAcceptedHead()
    {
        var genesis = XPointNetworkCodec.Parse<Xnh1Record>(XPointNetworkTestRecords.Create(XPointNetworkRegistry.Xnh1));
        var acceptedBytes = XPointNetworkTestRecords.MutateField(genesis.CanonicalCopy(), 2,
            value => System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(value, 1));
        acceptedBytes = XPointNetworkTestRecords.MutateField(acceptedBytes, 3, value => XPointNetworkTestRecords.Id(77).CopyTo(value));
        var accepted = XPointNetworkCodec.Parse<Xnh1Record>(acceptedBytes);
        var resolver = new NeverCalledResolver();
        var signatures = new NeverCalledSignatureVerifier();

        var error = Assert.Throws<XPointValidationException>(() => XPointNetworkVerifier.Verify(genesis,
            new XPointVerificationContext(resolver, signatures, accepted)));

        Assert.Equal(XPointValidationStage.Transition, error.Stage);
        Assert.Equal("PredecessorMismatch", error.Error);
        Assert.Equal(0, resolver.Calls);
        Assert.Equal(0, signatures.Calls);
    }

    private sealed class AcceptingVerifier : IXPointSignatureVerifier
    {
        private readonly bool _result;
        internal AcceptingVerifier(bool result=true)=>_result=result;
        internal int Calls { get; private set; }
        public bool VerifyEd25519(ReadOnlySpan<byte> publicKey,ReadOnlySpan<byte> message,ReadOnlySpan<byte> signature)
        { Calls++; return _result; }
    }

    private sealed class Resolver : IXPointClosureResolver
    {
        private readonly Dictionary<string,Xnd1Record> _nodes=[];
        internal Resolver(params Xnd1Record[] nodes)
        { foreach(var node in nodes)_nodes[Convert.ToHexString(node.NodeId.Span)]=node; }
        internal XPointExternalEvidence ExternalCore { get; set; } = new("",default,default,0,0,default,0,default);
        internal bool Active { get; set; } = true;
        public XPointParsedRecord ResolveCore(XPointCoreReference reference)=>throw new InvalidOperationException();
        public XPointParsedRecord ResolveArtifact(XPointArtifactReference reference)=>throw new InvalidOperationException();
        public Xnd1Record ResolveNodeDescriptor(XPointBytes nodeId)=>_nodes[Convert.ToHexString(nodeId.Span)];
        public bool IsNodeActiveAndUnrevoked(XPointBytes nodeId)=>Active && _nodes.ContainsKey(Convert.ToHexString(nodeId.Span));
        public XPointExternalEvidence ResolveExternalCore(XPointCoreReference reference)=>ExternalCore;
        public XPointExternalEvidence ResolveExternalArtifact(XPointArtifactReference reference)=>throw new InvalidOperationException();
    }

    private sealed class NeverCalledSignatureVerifier : IXPointSignatureVerifier
    {
        internal int Calls { get; private set; }
        public bool VerifyEd25519(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            Calls++;
            throw new InvalidOperationException("A rejected genesis must not reach signature verification.");
        }
    }

    private sealed class NeverCalledResolver : IXPointClosureResolver
    {
        internal int Calls { get; private set; }
        private T Reject<T>()
        {
            Calls++;
            throw new InvalidOperationException("A rejected genesis must not resolve closure material.");
        }
        public XPointParsedRecord ResolveCore(XPointCoreReference reference) => Reject<XPointParsedRecord>();
        public XPointParsedRecord ResolveArtifact(XPointArtifactReference reference) => Reject<XPointParsedRecord>();
        public Xnd1Record ResolveNodeDescriptor(XPointBytes nodeId) => Reject<Xnd1Record>();
        public bool IsNodeActiveAndUnrevoked(XPointBytes nodeId) => Reject<bool>();
        public XPointExternalEvidence ResolveExternalCore(XPointCoreReference reference) => Reject<XPointExternalEvidence>();
        public XPointExternalEvidence ResolveExternalArtifact(XPointArtifactReference reference) => Reject<XPointExternalEvidence>();
    }
}
