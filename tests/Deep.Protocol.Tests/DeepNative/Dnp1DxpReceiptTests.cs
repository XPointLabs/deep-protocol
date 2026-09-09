using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepNative;
using Sodium;

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
        var immutable = ImmutableFields(projection);
        var pendingBytes = Receipt(0, immutable, pendingSource, new byte[32], new byte[38], 0);
        var verifiedBytes = Receipt(1, immutable, verifiedSource, transcript, subject, 150);
        var provider = new HmacProvider(Key);
        var verifier = new DxpReceiptVerifier();

        var pending = await verifier.RestoreAsync(pendingBytes, pendingSource, provider);
        var verified = await verifier.RestoreAsync(verifiedBytes, verifiedSource, provider);
        var plan = verifier.VerifyFinalCas(pending, verified, pendingSource, verifiedSource);

        Assert.Equal(389, pendingSource.TrustedCanonical.Length);
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
        var bytes = Receipt(0, ImmutableFields(projection), source, new byte[32], new byte[38], 0);
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
    public async Task FinalEvidenceSubstitution_RejectsBeforeHmacAndRetentionMovementRejectsCas()
    {
        var projection = Bytes(0x51, 32);
        var transcript = Bytes(0x52, 32);
        var subject = Ref(ArtifactType.Dnr1, 756, 0x53);
        var pendingSource = Source(0, projection, new byte[32], new byte[38]);
        var verifiedSource = Source(1, projection, transcript, subject);
        var immutable = ImmutableFields(projection);
        var provider = new HmacProvider(Key);
        var verifier = new DxpReceiptVerifier();

        var substituted = Receipt(
            1, immutable, verifiedSource, Change(transcript), subject, 150);
        await Assert.ThrowsAsync<RecordException>(() =>
            verifier.RestoreAsync(substituted, verifiedSource, provider).AsTask());
        Assert.Equal(0, provider.Calls);

        var pending = await verifier.RestoreAsync(
            Receipt(0, immutable, pendingSource, new byte[32], new byte[38], 0),
            pendingSource, provider);
        var verified = await verifier.RestoreAsync(
            Receipt(1, immutable, verifiedSource, transcript, subject, 150, retainedUntil: 301),
            verifiedSource, provider);
        Assert.Throws<RecordException>(() =>
            verifier.VerifyFinalCas(pending, verified, pendingSource, verifiedSource));
    }

    [Fact]
    public void OfflineGenesisSourceAndNonceLedger_AreSealedRestartStableAndCleanBreak()
    {
        var firstIdentity = GenesisIdentity();
        var restoredIdentity = GenesisIdentity();
        var sourceVerifier = new DxpIdentityIssuanceSourceVerifier();
        var first = sourceVerifier.CreateOfflineAccountDeviceGenesis(firstIdentity);
        var restored = sourceVerifier.CreateOfflineAccountDeviceGenesis(restoredIdentity);
        var nonce = Bytes(0x71, 32);
        var indexKey = Bytes(0x72, 32);
        var ledger = new DxpNonceLedgerVerifier();
        var firstBinding = ledger.Derive(first, nonce, indexKey);
        var restoredBinding = ledger.Derive(restored, nonce, indexKey);

        Assert.Equal(first.IdentityIssuanceSource, restored.IdentityIssuanceSource);
        Assert.Equal(first.IssuanceScope, restored.IssuanceScope);
        Assert.Equal(firstBinding.LedgerKey, restoredBinding.LedgerKey);
        Assert.Equal(firstBinding.IndexKeyId, restoredBinding.IndexKeyId);
        Assert.NotEqual(firstBinding.LedgerKey,
            ledger.Derive(restored, Change(nonce), indexKey).LedgerKey);
        Assert.NotEqual(firstBinding.IndexKeyId,
            ledger.Derive(restored, nonce, Change(indexKey)).IndexKeyId);

        var legacyDomain = Encoding.ASCII.GetBytes(
            "Deep/ProtectedState/V1/DXP1-nonce-ledger-key");
        var legacy = new byte[2 + legacyDomain.Length + 16 + 32 + 1 + 32];
        BinaryPrimitives.WriteUInt16BigEndian(legacy, (ushort)legacyDomain.Length);
        legacyDomain.CopyTo(legacy, 2);
        var offset = 2 + legacyDomain.Length;
        Bytes(0x21, 16).CopyTo(legacy, offset); offset += 16;
        Bytes(0x73, 32).CopyTo(legacy, offset); offset += 32;
        legacy[offset++] = (byte)X25519PossessionRole.Device;
        nonce.CopyTo(legacy, offset);
        Assert.NotEqual(HMACSHA256.HashData(indexKey, legacy), firstBinding.LedgerKey);

        Assert.Empty(typeof(DxpIdentityIssuanceSource).GetConstructors());
        Assert.Empty(typeof(DxpNonceLedgerBinding).GetConstructors());
        Assert.True(first.NoAuthorityClaim);
        Assert.True(firstBinding.NoAuthorityClaim);
    }

    [Fact]
    public void OfflineGenesisSource_RejectsNonGenesisAndCannotCrossFeedCutoverCas()
    {
        var verifier = new DxpIdentityIssuanceSourceVerifier();
        Assert.Throws<RecordException>(() =>
            verifier.CreateOfflineAccountDeviceGenesis(GenesisIdentity(drsRevision: 2)));

        var projection = Bytes(0x31, 32);
        var pending = Source(0, projection, new byte[32], new byte[38],
            DxpIdentityIssuanceSourceKind.OfflineAccountDeviceGenesis,
            X25519PossessionRole.Device);
        var verified = Source(1, projection, Bytes(0x32, 32),
            Ref(ArtifactType.Dpd1, 776, 0x33),
            DxpIdentityIssuanceSourceKind.CurrentCutoverRouter,
            X25519PossessionRole.Router);

        Assert.False(verified.IsFinalSuccessorOf(pending));
        Assert.Throws<RecordException>(() => new DxpIdentityIssuanceSource(
            DxpIdentityIssuanceSourceKind.OfflineAccountDeviceGenesis,
            X25519PossessionRole.Router,
            Bytes(0x21, 16), Bytes(0x22, 32), 1, Bytes(0x11, 32),
            Bytes(0x10, 32), 1, 0, new byte[32],
            Ref(ArtifactType.Drs1, 356, 0x13)));
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
    public void DeviceSubjectProjection_IsExact632AndIndependentOfPopAndSignatures()
    {
        var fields = Minimum(RecordDefinitions.Dpd1);
        fields[0] = Bytes(0x11, 16); fields[1] = Bytes(0x12, 32);
        fields[2] = U64(1); fields[3] = Bytes(0x13, 32); fields[4] = U64(1);
        fields[5] = Bytes(0x14, 32); fields[6] = Bytes(0x15, 32);
        fields[7] = Bytes(0x16, 32); fields[8] = U64(0); fields[9] = new byte[38];
        fields[10] = Bytes(0x17, 32); fields[11] = U64(1);
        fields[12] = Ref(ArtifactType.Drs1, 356, 0x18); fields[13] = U64(0);
        fields[14] = new byte[32]; fields[15] = U64(100); fields[16] = U64(200);
        fields[17] = U64((ulong)DeviceCapabilities.MailboxRoleIssuer);
        fields[18] = new byte[] { 0, 1 }; fields[19] = new byte[38];
        fields[20] = Bytes(0x19, 32); fields[21] = Bytes(0x1a, 64);
        fields[22] = Bytes(0x1b, 64);
        var original = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpd1, fields),
            RecordDefinitions.Dpd1);

        var projection = DxpSubjectProjection.EncodeDevice(original);
        var hash = DxpSubjectProjection.HashDevice(original);
        Assert.Equal(632, projection.Length);

        fields[20] = Bytes(0xe1, 32); fields[21] = Bytes(0xe2, 64);
        fields[22] = Bytes(0xe3, 64);
        var changed = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpd1, fields),
            RecordDefinitions.Dpd1);
        Assert.Equal(projection, DxpSubjectProjection.EncodeDevice(changed));
        Assert.Equal(hash, DxpSubjectProjection.HashDevice(changed));

        var payload = new byte[1 + 4 + projection.Length];
        payload[0] = (byte)X25519PossessionRole.Device;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), (uint)projection.Length);
        projection.CopyTo(payload, 5);
        Assert.Equal(CanonicalGrammar.Sha256Domain(
            "Deep/IdentityAuth/V1/x25519-pop-subject", payload), hash);
    }

    [Fact]
    public void Dpd1SigningProjection_BindsTranscriptHashAndOmitsOnlyBothSignatures()
    {
        var fields = Minimum(RecordDefinitions.Dpd1);
        fields[0] = Bytes(0x11, 16); fields[1] = Bytes(0x12, 32);
        fields[2] = U64(1); fields[3] = Bytes(0x13, 32); fields[4] = U64(1);
        fields[5] = Bytes(0x14, 32); fields[6] = Bytes(0x15, 32);
        fields[7] = Bytes(0x16, 32); fields[10] = Bytes(0x17, 32);
        fields[11] = U64(1); fields[12] = Ref(ArtifactType.Drs1, 356, 0x18);
        fields[15] = U64(100); fields[16] = U64(200);
        fields[17] = U64((ulong)DeviceCapabilities.MailboxRoleIssuer);
        fields[18] = new byte[] { 0, 1 }; fields[20] = Bytes(0x19, 32);
        var original = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpd1, fields),
            RecordDefinitions.Dpd1);
        var signing = CanonicalGrammar.GetSigningBytes(
            original, "Deep/IdentityAuth/V1/device-certificate");
        var signer = PublicKeyAuth.GenerateKeyPair();
        var signature = PublicKeyAuth.SignDetached(signing, signer.PrivateKey);

        fields[20] = Bytes(0xe1, 32);
        var transcriptSubstitution = CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(
                CanonicalGrammar.Encode(RecordDefinitions.Dpd1, fields),
                RecordDefinitions.Dpd1),
            "Deep/IdentityAuth/V1/device-certificate");
        Assert.NotEqual(signing, transcriptSubstitution);
        Assert.False(PublicKeyAuth.VerifyDetached(
            signature, transcriptSubstitution, signer.PublicKey));

        fields[20] = Bytes(0x19, 32);
        fields[21] = Bytes(0xe2, 64);
        fields[22] = Bytes(0xe3, 64);
        var signatureSubstitution = CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(
                CanonicalGrammar.Encode(RecordDefinitions.Dpd1, fields),
                RecordDefinitions.Dpd1),
            "Deep/IdentityAuth/V1/device-certificate");
        Assert.Equal(signing, signatureSubstitution);
        Assert.True(PublicKeyAuth.VerifyDetached(
            signature, signatureSubstitution, signer.PublicKey));
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
        var receipt = Receipt(0, ImmutableFields(trustedProjection), expected, new byte[32], new byte[38], 0);
        var fullRecordHash = CanonicalGrammar.Sha256Domain(
            "Deep/IdentityAuth/V1/x25519-pop-subject", full);
        var substitutions = new[]
        {
            Source(0, Bytes(0xee, 32), new byte[32], new byte[38]),
            Source(0, fullRecordHash, new byte[32], new byte[38]),
            new DxpOperationSource(
                Issuance(DxpIdentityIssuanceSourceKind.OfflineAccountDeviceGenesis,
                    X25519PossessionRole.Device), 0, trustedProjection,
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
        byte stage, byte[] projection, byte[] transcript, byte[] subject,
        DxpIdentityIssuanceSourceKind kind = DxpIdentityIssuanceSourceKind.CurrentCutoverRouter,
        X25519PossessionRole role = X25519PossessionRole.Router) =>
        new(Issuance(kind, role), stage, projection,
            new byte[38], transcript, subject, Bytes(0x14,32), Bytes(0x15,32), Bytes(0x16,32));

    private static DxpIdentityIssuanceSource Issuance(
        DxpIdentityIssuanceSourceKind kind,
        X25519PossessionRole role) =>
        new(kind, role, Bytes(0x21, 16), Bytes(0x22, 32), 1,
            Bytes(0x11, 32), Bytes(0x10, 32), 1, 0, new byte[32],
            Ref(ArtifactType.Drs1, 356, 0x13));

    private static VerifiedIdentityRelative GenesisIdentity(ulong drsRevision = 1)
    {
        var dpaFields = Minimum(RecordDefinitions.Dpa1);
        dpaFields[0] = Bytes(0x21, 16);
        dpaFields[1] = U64(1);
        dpaFields[2] = U64(1);
        dpaFields[4] = Bytes(0x31, 32);
        dpaFields[5] = Bytes(0x32, 32);
        dpaFields[6] = Bytes(0x33, 32);
        dpaFields[7] = Bytes(0x34, 32);
        dpaFields[8] = Bytes(0x35, 32);
        dpaFields[9] = U64(1);
        dpaFields[10] = U64(1);
        dpaFields[11] = new byte[] { 0, 1 };
        var dpaRecord = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpa1, dpaFields),
            RecordDefinitions.Dpa1);
        var account = new VerifiedAccount(
            new AccountCertificate(dpaRecord), Bytes(0x22, 32));

        var drsFields = Minimum(RecordDefinitions.Drs1);
        drsFields[0] = account.Certificate.NetworkId;
        drsFields[1] = account.DeepAccountIdHash;
        drsFields[2] = U64(1);
        drsFields[3] = U64(drsRevision);
        drsFields[4] = U64(1);
        drsFields[7] = Bytes(0x36, 32);
        drsFields[8] = new byte[2];
        drsFields[9] = Array.Empty<byte>();
        drsFields[10] = new byte[32];
        var drsRecord = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Drs1, drsFields),
            RecordDefinitions.Drs1);
        var revocations = new VerifiedRevocationState(
            account, new RevocationSnapshot(drsRecord), new RevocationCatalog([]));
        return new VerifiedIdentityRelative(
            new VerifiedIdentityAuthority(account, revocations, []));
    }

    private static byte[][] ImmutableFields(byte[] projection) =>
    [
        new byte[] { 2 }, Bytes(0x21,16), Bytes(0x22,32), projection,
        Bytes(0x24,32), Bytes(0x25,32), Bytes(0x26,32), Bytes(0x27,32)
    ];

    private static byte[] Receipt(
        byte phase, byte[][] immutable, DxpOperationSource source,
        byte[] transcript, byte[] subject, ulong verifiedAt, ulong retainedUntil = 300)
    {
        var fields = Minimum(RecordDefinitions.Dxr1);
        fields[0]=new byte[]{phase}; fields[1]=immutable[0]; fields[2]=immutable[1];
        fields[3]=immutable[2]; fields[4]=immutable[3]; fields[5]=immutable[4];
        fields[6]=immutable[5]; fields[7]=immutable[6]; fields[8]=immutable[7];
        fields[9]=U64(100); fields[10]=U64(200); fields[11]=U64(verifiedAt);
        fields[12]=transcript; fields[13]=subject; fields[14]=source.Fingerprint.ToArray();
        fields[15]=Bytes(0x15,32); fields[16]=new byte[]{0}; fields[17]=U64(retainedUntil);
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
