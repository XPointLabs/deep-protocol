using System.Buffers.Binary;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class VectorAuthorityRecoveryCoverageTests
{
    [Fact]
    public async Task ApiRecoveryFreezeProviderNonce()
    {
        await new RecoveryProviderTests().FrozenDrc_UsesTypedProviderAndExactNonceLatch();
    }

    [Fact]
    public async Task ApiRecoveryNonceReuseLatch()
    {
        await new RecoveryProviderTests().NonceMismatchOrFork_RejectsBeforeOpen();
    }

    [Fact]
    public async Task ApiRecoveryCancelPlaintextZero()
    {
        var tests = new RecoveryProviderTests();
        await tests.CancellationAfterDerive_YieldsNoOpenOrCandidate();
        await tests.CancellationAfterOpen_YieldsNoCandidate();
        await tests.Dispose_ZeroesLatchMaterialAndConsumesPlaintext();
    }

    [Fact]
    public void ApiRecoveryComponentDeploymentSubjectCrossFeed()
    {
        var network = Bytes(1, 16);
        var accountHash = Bytes(2, 32);
        var resetId = Bytes(3, 32);
        var componentSubject = Bytes(4, 32);

        Span<byte> exactPreimage = stackalloc byte[80];
        network.CopyTo(exactPreimage[..16]);
        accountHash.CopyTo(exactPreimage[16..48]);
        resetId.CopyTo(exactPreimage[48..]);
        var independentlyComputed = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/deployment-subject", exactPreimage);
        var deploymentSubject = VerifiedPredecessorCutoverContext.ComputeDeploymentSubject(
            network, accountHash, resetId);

        Assert.Equal(independentlyComputed, deploymentSubject);
        VerifiedPredecessorCutoverContext.VerifyDistinctComponentAndDeploymentSubjects(
            componentSubject, deploymentSubject);
        Assert.NotEqual(deploymentSubject,
            VerifiedPredecessorCutoverContext.ComputeDeploymentSubject(
                Bytes(5, 16), accountHash, resetId));
        Assert.NotEqual(deploymentSubject,
            VerifiedPredecessorCutoverContext.ComputeDeploymentSubject(
                network, Bytes(5, 32), resetId));
        Assert.NotEqual(deploymentSubject,
            VerifiedPredecessorCutoverContext.ComputeDeploymentSubject(
                network, accountHash, Bytes(5, 32)));

        var crossFeed = Assert.Throws<RecordException>(() =>
            VerifiedPredecessorCutoverContext.VerifyDistinctComponentAndDeploymentSubjects(
                deploymentSubject, deploymentSubject));
        Assert.Equal(RecordError.InvalidField, crossFeed.Error);
        Assert.Throws<RecordException>(() =>
            VerifiedPredecessorCutoverContext.ComputeDeploymentSubject(
                network.AsSpan(1), accountHash, resetId));
        Assert.Throws<RecordException>(() =>
            VerifiedPredecessorCutoverContext.VerifyDistinctComponentAndDeploymentSubjects(
                componentSubject.AsSpan(1), deploymentSubject));
    }

    [Fact]
    public async Task RecoveryDrmRowReversed()
    {
        var first = RowKey(ArtifactType.Dpa1, 12, 1);
        var second = RowKey(ArtifactType.Dpd1, 12, 2);
        await RejectAfterOneOpen(Manifest((second, Bytes(2,12)), (first, Bytes(1,12))));
    }

    [Fact]
    public async Task RecoveryDrmRowEqualDuplicate()
    {
        var key = RowKey(ArtifactType.Dpa1, 12, 1);
        await RejectAfterOneOpen(Manifest((key, Bytes(1,12)), (key, Bytes(1,12))));
    }

    [Fact]
    public async Task RecoveryDrmRowRefCollisionShaped()
    {
        var key = RowKey(ArtifactType.Dpa1, 12, 1);
        await RejectAfterOneOpen(Manifest((key, Bytes(1,12)), (key, Bytes(2,12))));
    }

    [Fact]
    public void RecoveryDrmDirectPlaintextParser()
    {
        var first = RowKey(ArtifactType.Dpa1, 12, 1);
        var second = RowKey(ArtifactType.Dpd1, 12, 2);
        var reversed = Manifest((second, Bytes(2,12)), (first, Bytes(1,12)));
        Assert.Throws<RecordException>(() =>
            RecoveryManifestParser.DecodeOwned(reversed,2));
    }

    [Fact]
    public async Task RecoveryDrmRefRuleMissingCrossClass()
    {
        var unknown = new byte[ArtifactReference.Length];
        BinaryPrimitives.WriteUInt16BigEndian(unknown,ushort.MaxValue);
        BinaryPrimitives.WriteUInt32BigEndian(unknown.AsSpan(2),12);
        unknown.AsSpan(6).Fill(1);
        await RejectAfterOneOpen(Manifest((unknown, Bytes(1,12))));
    }

    private static async Task RejectAfterOneOpen(byte[] plaintext)
    {
        var nonce = Bytes(7,24);
        var provider = new PlaintextProvider(nonce,plaintext);
        var latch = new StoredLatch();
        await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryTestAccess.OpenUnverifiedCandidateAsync(
                Capsule(plaintext,nonce),provider,latch,default).AsTask());
        Assert.Equal(1,provider.DeriveCalls);
        Assert.Equal(1,provider.OpenCalls);
        Assert.Equal(1,latch.Calls);
    }

    private static byte[] Manifest(params (byte[] Key,byte[] Canonical)[] rows)
    {
        var output = new byte[8 + rows.Sum(static row => row.Key.Length + row.Canonical.Length)];
        "DRM1"u8.CopyTo(output);
        output[4]=1;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6),checked((ushort)rows.Length));
        var offset=8;
        foreach(var row in rows)
        {
            row.Key.CopyTo(output,offset);offset+=row.Key.Length;
            row.Canonical.CopyTo(output,offset);offset+=row.Canonical.Length;
        }
        return output;
    }

    private static byte[] RowKey(ArtifactType type,uint length,byte hashMarker)
    {
        var output=new byte[ArtifactReference.Length];
        BinaryPrimitives.WriteUInt16BigEndian(output,(ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(2),length);
        output.AsSpan(6).Fill(hashMarker);
        return output;
    }

    private static byte[] Capsule(byte[] plaintext,byte[] nonce)
    {
        var fields=RecordDefinitions.Drc1.Fields
            .Select(static field=>(ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        fields[0]=Bytes(1,16);fields[1]=Bytes(2,32);fields[2]=Bytes(3,32);fields[3]=U64(1);
        fields[4]=Reference(ArtifactType.Dcm1,812,4);
        fields[5]=Reference(ArtifactType.Drs1,356,5);
        fields[6]=Bytes(6,32);fields[7]=Bytes(7,32);
        fields[8]=U16(BinaryPrimitives.ReadUInt16BigEndian(plaintext.AsSpan(6,2)));
        fields[9]=U64(checked((ulong)plaintext.Length));
        fields[10]=U64(checked((ulong)plaintext.Length));
        fields[11]=nonce;fields[12]=Bytes(8,32);fields[13]=U64(1);fields[14]=U64(100);
        fields[15]=plaintext;fields[16]=Bytes(9,16);
        return CanonicalGrammar.Encode(RecordDefinitions.Drc1,fields);
    }

    private static byte[] Reference(ArtifactType type,uint length,byte marker)
    {
        var output=new byte[ArtifactReference.Length];
        BinaryPrimitives.WriteUInt16BigEndian(output,(ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(2),length);
        output[6]=marker;
        return output;
    }

    private static byte[] Bytes(byte value,int length)=>Enumerable.Repeat(value,length).ToArray();
    private static byte[] U16(ushort value){var b=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(b,value);return b;}
    private static byte[] U64(ulong value){var b=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(b,value);return b;}

    private sealed class PlaintextProvider(byte[] nonce,byte[] plaintext):RecoveryProtectorProvider
    {
        internal int DeriveCalls { get; private set; }
        internal int OpenCalls { get; private set; }
        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,Memory<byte> destination,CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();DeriveCalls++;nonce.CopyTo(destination);return ValueTask.CompletedTask;
        }
        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,Memory<byte> destination,CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();OpenCalls++;plaintext.CopyTo(destination);return ValueTask.CompletedTask;
        }
    }

    private sealed class StoredLatch:RecoveryNonceLatch
    {
        internal int Calls { get; private set; }
        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();Calls++;
            return ValueTask.FromResult(RecoveryNonceLatchDecision.Stored);
        }
    }
}
