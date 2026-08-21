using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class DxpReceiptTests
{
    private static readonly byte[] Key = Bytes(0x91, 32);

    [Fact]
    public async Task PendingAndVerified_ExactHmacAndFullTupleCas()
    {
        var projection = Bytes(0x31, 32);
        var transcript = Bytes(0x32, 32);
        var subject = Ref(ArtifactType.Dnr1, 756, 0x33);
        var pendingSource = Source(0, projection, new byte[32], new byte[38]);
        var verifiedSource = Source(1, projection, transcript, subject);
        var immutable = ImmutableFields();
        var pendingBytes = Receipt(0, immutable, pendingSource, new byte[32], new byte[38], 0);
        var verifiedBytes = Receipt(1, immutable, verifiedSource, transcript, subject, 150);
        var provider = new HmacProvider(Key);
        var verifier = new DxpReceiptVerifier();

        var pending = await verifier.RestoreAsync(pendingBytes, pendingSource, provider);
        var verified = await verifier.RestoreAsync(verifiedBytes, verifiedSource, provider);
        var plan = verifier.VerifyFinalCas(pending, verified, pendingSource, verifiedSource);

        Assert.Equal(DxpReceiptPhase.Pending, plan.Current.Phase);
        Assert.Equal(DxpReceiptPhase.Verified, plan.Next.Phase);
        Assert.Equal(2, provider.Calls);
        Assert.True(plan.NoAuthorityClaim);
    }

    [Fact]
    public async Task WrongSourceOrHmac_RejectsBeforeResult()
    {
        var projection = Bytes(0x41, 32);
        var source = Source(0, projection, new byte[32], new byte[38]);
        var bytes = Receipt(0, ImmutableFields(), source, new byte[32], new byte[38], 0);
        var wrong = Source(0, Bytes(0x42, 32), new byte[32], new byte[38]);
        var provider = new HmacProvider(Key);
        var verifier = new DxpReceiptVerifier();

        await Assert.ThrowsAsync<RecordException>(async () =>
            await verifier.RestoreAsync(bytes, wrong, provider));
        Assert.Equal(0, provider.Calls);

        bytes[^1] ^= 1;
        await Assert.ThrowsAsync<RecordException>(async () =>
            await verifier.RestoreAsync(bytes, source, provider));
        Assert.Equal(1, provider.Calls);
    }

    [Fact]
    public void SubjectProjection_ZeroesOnlyTranscriptAndOmitsBothSignatures()
    {
        var fields = Minimum(RecordDefinitions.Dnr1);
        fields[0] = Bytes(1,16); fields[1] = Bytes(2,32);
        fields[2] = Ref(ArtifactType.Dpm1,670,3);
        fields[3] = Ref(ArtifactType.Pma1,1,4); fields[4] = U64(1);
        fields[5] = Ref(ArtifactType.Pmr1,1,5); fields[6] = U64(1);
        fields[7] = Bytes(6,32); fields[8] = Bytes(7,32); fields[9] = U64(1);
        fields[10] = Bytes(8,32); fields[11] = Bytes(9,32); fields[12] = Bytes(10,32);
        fields[13] = U64(1); fields[14] = U64(1); fields[15] = U64(100); fields[16] = U64(200);
        fields[18] = Bytes(11,32); fields[19] = Bytes(12,64); fields[20] = Bytes(13,64);
        var record = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dnr1, fields),
            RecordDefinitions.Dnr1);
        var hash = DxpSubjectProjection.HashRouter(record);
        fields[18] = new byte[32];
        var projectedDefinition = RecordDefinitions.Dnr1 with
        {
            Fields = RecordDefinitions.Dnr1.Fields.Take(19).ToArray(),
            MinimumLength = 612, MaximumLength = 612,
            OmittedSigningFieldIndexes = new HashSet<int>()
        };
        var projection = CanonicalGrammar.Encode(projectedDefinition, fields.Take(19).ToArray());
        var payload = new byte[1+4+projection.Length]; payload[0]=2;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1,4),(uint)projection.Length);
        projection.CopyTo(payload,5);
        Assert.Equal(CanonicalGrammar.Sha256Domain(
            "Deep/IdentityAuth/V1/x25519-pop-subject", payload), hash);
    }

    [Fact]
    public void RouterAndComponentSubjectsExcludeContainingReferencesAndSelfDerivedHashes()
    {
        var fields = Minimum(RecordDefinitions.Dnr1);
        fields[0] = Bytes(1, 16); fields[1] = Bytes(2, 32);
        fields[2] = Ref(ArtifactType.Dpm1, 670, 3);
        fields[3] = Ref(ArtifactType.Pma1, 1, 4); fields[4] = U64(1);
        fields[5] = Ref(ArtifactType.Pmr1, 1, 5); fields[6] = U64(1);
        fields[7] = Bytes(6, 32); fields[8] = Bytes(7, 32); fields[9] = U64(1);
        fields[10] = Bytes(8, 32); fields[11] = Bytes(9, 32);
        fields[12] = Bytes(10, 32); fields[13] = U64(1); fields[14] = U64(1);
        fields[15] = U64(100); fields[16] = U64(200);
        fields[18] = Bytes(11, 32); fields[19] = Bytes(12, 64);
        fields[20] = Bytes(13, 64);
        var original = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dnr1, fields),
            RecordDefinitions.Dnr1);
        var subject = DxpSubjectProjection.HashRouter(original);

        fields[18] = Bytes(0xee, 32);
        fields[19] = Bytes(0xef, 64);
        fields[20] = Bytes(0xf0, 64);
        var selfFieldsChanged = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dnr1, fields),
            RecordDefinitions.Dnr1);
        Assert.Equal(subject, DxpSubjectProjection.HashRouter(selfFieldsChanged));
        Assert.NotEqual(
            CanonicalGrammar.ComputeReference(ArtifactType.Dnr1, original.CanonicalSpan),
            CanonicalGrammar.ComputeReference(ArtifactType.Dnr1,
                selfFieldsChanged.CanonicalSpan));

        var network = Bytes(0x21, 16);
        var accountHash = Bytes(0x22, 32);
        var revocation = Bytes(0x23, 32);
        var component = GenesisTransactionScopeContext.ComputeComponentSubject(
            network, accountHash, ComponentKind.Registry, revocation);
        var preimage = new byte[82];
        network.CopyTo(preimage, 0);
        accountHash.CopyTo(preimage, 16);
        BinaryPrimitives.WriteUInt16BigEndian(preimage.AsSpan(48, 2),
            (ushort)ComponentKind.Registry);
        revocation.CopyTo(preimage, 50);
        Assert.Equal(CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/component-subject", preimage), component);

        Assert.NotEqual(component,
            GenesisTransactionScopeContext.ComputeComponentSubject(
                Change(network), accountHash, ComponentKind.Registry, revocation));
        Assert.NotEqual(component,
            GenesisTransactionScopeContext.ComputeComponentSubject(
                network, Change(accountHash), ComponentKind.Registry, revocation));
        Assert.NotEqual(component,
            GenesisTransactionScopeContext.ComputeComponentSubject(
                network, accountHash, ComponentKind.XNode, revocation));
        Assert.NotEqual(component,
            GenesisTransactionScopeContext.ComputeComponentSubject(
                network, accountHash, ComponentKind.Registry, Change(revocation)));
    }

    [Fact]
    public async Task SubjectProjectionSubstitution_RejectsCallerRoleAndFullRecordBeforeAgreement()
    {
        var fields = Minimum(RecordDefinitions.Dnr1);
        fields[0] = Bytes(1,16); fields[1] = Bytes(2,32);
        fields[2] = Ref(ArtifactType.Dpm1,670,3);
        fields[3] = Ref(ArtifactType.Pma1,1,4); fields[4] = U64(1);
        fields[5] = Ref(ArtifactType.Pmr1,1,5); fields[6] = U64(1);
        fields[7] = Bytes(6,32); fields[8] = Bytes(7,32); fields[9] = U64(1);
        fields[10] = Bytes(8,32); fields[11] = Bytes(9,32); fields[12] = Bytes(10,32);
        fields[13] = U64(1); fields[14] = U64(1); fields[15] = U64(100);
        fields[16] = U64(200); fields[18] = Bytes(11,32);
        fields[19] = Bytes(12,64); fields[20] = Bytes(13,64);
        var full = CanonicalGrammar.Encode(RecordDefinitions.Dnr1, fields);
        var record = CanonicalGrammar.DecodeOwned(full, RecordDefinitions.Dnr1);
        var trustedProjection = DxpSubjectProjection.HashRouter(record);

        fields[18] = new byte[32];
        fields[19] = new byte[64];
        fields[20] = new byte[64];
        var cleared = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dnr1, fields),
            RecordDefinitions.Dnr1);
        Assert.Equal(trustedProjection, DxpSubjectProjection.HashRouter(cleared));
        Assert.Throws<RecordException>(() => DxpSubjectProjection.HashDevice(record));
        Assert.Empty(typeof(DxpOperationSource).GetConstructors(
            System.Reflection.BindingFlags.Public |
            System.Reflection.BindingFlags.Instance));

        var expected = Source(0, trustedProjection, new byte[32], new byte[38]);
        var receipt = Receipt(0, ImmutableFields(), expected, new byte[32], new byte[38], 0);
        var fullRecordHash = CanonicalGrammar.Sha256Domain(
            "Deep/IdentityAuth/V1/x25519-pop-subject", full);
        var substitutions = new[]
        {
            Source(0, Bytes(0xee, 32), new byte[32], new byte[38]),
            Source(0, fullRecordHash, new byte[32], new byte[38]),
            new DxpOperationSource(
                X25519PossessionRole.Device, 0, Bytes(0x11,32), 1, 0,
                Bytes(0x12,32), Ref(ArtifactType.Drs1,356,0x13), trustedProjection,
                new byte[38], new byte[32], new byte[38], Bytes(0x14,32),
                Bytes(0x15,32), Bytes(0x16,32))
        };
        foreach (var substitution in substitutions)
        {
            var provider = new HmacProvider(Key);
            await Assert.ThrowsAsync<RecordException>(() =>
                new DxpReceiptVerifier().RestoreAsync(
                    receipt, substitution, provider).AsTask());
            Assert.Equal(0, provider.Calls);
        }
    }

    private static DxpOperationSource Source(
        byte stage, byte[] projection, byte[] transcript, byte[] subject) =>
        new(X25519PossessionRole.Router, stage, Bytes(0x11,32), 1, 0,
            Bytes(0x12,32), Ref(ArtifactType.Drs1,356,0x13), projection,
            new byte[38], transcript, subject, Bytes(0x14,32), Bytes(0x15,32), Bytes(0x16,32));

    private static byte[][] ImmutableFields() =>
    [
        new byte[] { 2 }, Bytes(0x21,16), Bytes(0x22,32), Bytes(0x23,32),
        Bytes(0x24,32), Bytes(0x25,32), Bytes(0x26,32), Bytes(0x27,32)
    ];

    private static byte[] Receipt(
        byte phase, byte[][] immutable, DxpOperationSource source,
        byte[] transcript, byte[] subject, ulong verifiedAt)
    {
        var fields = Minimum(RecordDefinitions.Dxr1);
        fields[0]=new byte[]{phase}; fields[1]=immutable[0]; fields[2]=immutable[1];
        fields[3]=immutable[2]; fields[4]=immutable[3]; fields[5]=immutable[4];
        fields[6]=immutable[5]; fields[7]=immutable[6]; fields[8]=immutable[7];
        fields[9]=U64(100); fields[10]=U64(200); fields[11]=U64(verifiedAt);
        fields[12]=transcript; fields[13]=subject; fields[14]=source.Fingerprint.ToArray();
        fields[15]=Bytes(0x15,32); fields[16]=new byte[]{0}; fields[17]=U64(300);
        var unsignedDefinition = RecordDefinitions.Dxr1 with
        {
            Fields=RecordDefinitions.Dxr1.Fields.Take(18).ToArray(),
            MinimumLength=12, MaximumLength=573, OmittedSigningFieldIndexes=new HashSet<int>()
        };
        var unsigned=CanonicalGrammar.Encode(unsignedDefinition,fields.Take(18).ToArray());
        fields[18]=Tag("Deep/ProtectedState/V1/DXP1-verified-receipt",unsigned);
        return CanonicalGrammar.Encode(RecordDefinitions.Dxr1,fields);
    }

    private static byte[] Tag(string domain, byte[] unsigned)
    {
        var d=Encoding.ASCII.GetBytes(domain); var input=new byte[2+d.Length+2+4+unsigned.Length];
        BinaryPrimitives.WriteUInt16BigEndian(input,(ushort)d.Length); d.CopyTo(input,2);
        var o=2+d.Length; BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(o),0x8001);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(o+2),(uint)unsigned.Length);
        unsigned.CopyTo(input,o+6); return HMACSHA256.HashData(Key,input);
    }

    private sealed class HmacProvider(byte[] key) : IProtectedHmacProvider
    {
        internal int Calls;
        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request, CancellationToken cancellationToken)
        {
            Calls++;
            var d=Encoding.ASCII.GetBytes(request.Domain);
            var input=new byte[2+d.Length+2+4+request.UnsignedCanonical.Length];
            BinaryPrimitives.WriteUInt16BigEndian(input,(ushort)d.Length); d.CopyTo(input,2);
            var o=2+d.Length; BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(o),request.Suite);
            BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(o+2),(uint)request.UnsignedCanonical.Length);
            request.UnsignedCanonical.Span.CopyTo(input.AsSpan(o+6));
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(HMACSHA256.HashData(key,input));
        }
    }

    private static ReadOnlyMemory<byte>[] Minimum(RecordDefinition d) =>
        d.Fields.Select(f=>(ReadOnlyMemory<byte>)new byte[f.MinimumLength]).ToArray();
    private static byte[] Ref(ArtifactType type,uint length,byte value) =>
        CanonicalGrammar.EncodeReference(new ArtifactReference(type,length,Bytes(value,32)));
    private static byte[] Bytes(byte value,int length)=>Enumerable.Repeat(value,length).ToArray();
    private static byte[] Change(byte[] value){var copy=value.ToArray();copy[0]^=0xff;return copy;}
    private static byte[] U64(ulong value){var b=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(b,value);return b;}
}
