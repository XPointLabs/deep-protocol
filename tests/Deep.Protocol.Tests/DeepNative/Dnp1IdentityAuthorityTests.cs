using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class IdentityAuthorityTests
{
    [Fact]
    public void GenesisAccountAndEmptyDrs_CreateSealedOwnedAuthority()
    {
        var fixture = AccountFixture.Create();
        var account = IdentityVerifier.VerifyAccountCertificate(fixture.AccountCanonical);
        var drs = CreateDrs(fixture, account, [], 1, 100);
        var verifier = new IdentityAuthorityVerifier();

        var authority = verifier.CreateGenesisAuthority(
            fixture.AccountCanonical,
            drs,
            [],
            100);
        fixture.AccountCanonical[0] ^= 0xff;
        drs[0] ^= 0xff;

        Assert.False(authority.ForkLatched);
        Assert.False(authority.IsAccountTerminal);
        Assert.Equal((ulong)1, authority.Revocations.Snapshot.Revision);
        Assert.Equal("DPA1", Encoding.ASCII.GetString(authority.Account.Certificate.CanonicalBytes.Span[..4]));
        Assert.Equal("DRS1", Encoding.ASCII.GetString(authority.Revocations.Snapshot.CanonicalBytes.Span[..4]));
    }

    [Fact]
    public void AccountTerminalCatalog_BindsExactDpaAndClosedReason()
    {
        var fixture = AccountFixture.Create();
        var account = IdentityVerifier.VerifyAccountCertificate(fixture.AccountCanonical);
        var targetFields = MinimumFields(RecordDefinitions.Drt1);
        targetFields[0] = account.DeepAccountIdHash;
        targetFields[1] = new byte[] { (byte)RevocationTargetKind.AccountTerminal };
        targetFields[2] = account.Certificate.AccountRevocationHandle;
        targetFields[3] = U64(account.Certificate.AccountGeneration);
        targetFields[4] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dpa1,
            account.Certificate.CanonicalBytes.Span));
        targetFields[5] = U64(0);
        var target = CanonicalGrammar.Encode(RecordDefinitions.Drt1, targetFields);
        var targetRef = CanonicalGrammar.ComputeReference(ArtifactType.Drt1, target);
        var row = new byte[62];
        row[0] = (byte)RevocationTargetKind.AccountTerminal;
        CanonicalGrammar.EncodeReference(targetRef).CopyTo(row, 1);
        BinaryPrimitives.WriteUInt64BigEndian(row.AsSpan(39), account.Certificate.AccountGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(row.AsSpan(47), 99);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(55), (ushort)RevocationReason.AccountShutdown);
        var drs = CreateDrs(fixture, account, [row], 1, 100);
        var verifier = new IdentityAuthorityVerifier();

        var authority = verifier.CreateGenesisAuthority(
            fixture.AccountCanonical,
            drs,
            [new RevocationCatalogSource(target, fixture.AccountCanonical)],
            100);

        Assert.True(authority.IsAccountTerminal);
        Assert.Single(authority.Revocations.Catalog.Entries);
        Assert.Equal(RevocationReason.AccountShutdown, authority.Revocations.Catalog.Entries[0].Reason);

        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(55), (ushort)RevocationReason.RoleRetired);
        var error = Assert.Throws<RecordException>(() =>
        {
            var invalid = CreateDrs(fixture, account, [row], 1, 100);
            verifier.CreateGenesisAuthority(
                fixture.AccountCanonical,
                invalid,
                [new RevocationCatalogSource(target, fixture.AccountCanonical)],
                100);
        });
        Assert.Equal(RecordError.InvalidField, error.Error);
    }

    [Fact]
    public void MaximumRevocationSnapshot_RestoresZeroThrough1024PrefixHeadsWithOneSnapshotSignature()
    {
        var fixture = AccountFixture.Create();
        var account = IdentityVerifier.VerifyAccountCertificate(fixture.AccountCanonical);
        var (rows, catalog) = CreateMaximumRevocationCatalog(fixture, account);

        var prefixHeads = PrefixHeads(account, rows);
        var snapshot = CreateDrs(fixture, account, rows, revision: 1, issuedAt: 100);
        var identity = new IdentityRelativeVerifier().VerifyGenesis(
            fixture.AccountCanonical, snapshot, catalog, transactionTimeUnixSeconds: 100);

        Assert.Equal(1025, prefixHeads.Count);
        Assert.All(prefixHeads[0], static value => Assert.Equal(0, value));
        Assert.Equal(1024, identity.Revocations.Snapshot.EntryCount);
        Assert.Equal(1024, identity.Revocations.Catalog.Entries.Count);
        Assert.Equal(prefixHeads[^1], identity.Revocations.Snapshot.CurrentHead.ToArray());
        Assert.True(identity.IsTerminal);
        Assert.True(identity.NoAuthorityClaim);
    }

    [Fact]
    public void AccountTerminal_IsAcceptedAsFinalEntryAtEveryIndexOneThrough1024()
    {
        var fixture = AccountFixture.Create();
        var account = IdentityVerifier.VerifyAccountCertificate(fixture.AccountCanonical);
        var (maximumRows, maximumCatalog) = CreateMaximumRevocationCatalog(fixture, account);
        var terminalRow = maximumRows[^1];
        var terminalInput = maximumCatalog[^1];
        var verifier = new IdentityRelativeVerifier();

        for (var count = 1; count <= 1024; count++)
        {
            var rows = new List<byte[]>(count);
            var catalog = new List<RevocationCatalogInput>(count);
            for (var index = 0; index < count - 1; index++)
            {
                rows.Add(maximumRows[index]);
                catalog.Add(maximumCatalog[index]);
            }
            rows.Add(terminalRow);
            catalog.Add(terminalInput);

            var snapshot = CreateDrs(
                fixture, account, rows, revision: 1, issuedAt: 100);
            var identity = verifier.VerifyGenesis(
                fixture.AccountCanonical, snapshot, catalog,
                transactionTimeUnixSeconds: 100);

            Assert.Equal((ulong)count, identity.Revocations.Snapshot.EntryCount);
            Assert.Equal(Head(account, rows),
                identity.Revocations.Snapshot.CurrentHead.ToArray());
            Assert.True(identity.IsTerminal);
        }
    }

    [Fact]
    public void Dxp1_ExactX25519HkdfHmacRoundTripAndDefensiveOwnership()
    {
        var holderPrivate = SodiumCore.GetRandomBytes(32);
        var issuerPrivate = SodiumCore.GetRandomBytes(32);
        var holderPublic = ScalarMult.Base(holderPrivate);
        var issuerPublic = ScalarMult.Base(issuerPrivate);
        var transcript = CreateTranscript(holderPublic, issuerPublic, 100, 200);
        var created = X25519PossessionVerifier.CreateProof(transcript, holderPrivate);
        var reference = ReferenceDxp(transcript, holderPrivate);

        Assert.Equal(reference.Proof, created.Proof);
        Assert.Equal(reference.TranscriptHash, created.TranscriptHash);

        var verified = X25519PossessionVerifier.Verify(
            transcript,
            created.Proof,
            issuerPrivate,
            X25519PossessionRole.Device,
            transcript.AsSpan(8, 16),
            transcript.AsSpan(24, 32),
            holderPublic,
            150);
        transcript[0] ^= 0xff;
        created.TranscriptHash[0] ^= 0xff;

        Assert.Equal(X25519PossessionRole.Device, verified.Role);
        Assert.Equal(32, verified.TranscriptHash.Length);
        Assert.NotEqual(created.TranscriptHash, verified.TranscriptHash.ToArray());
    }

    [Fact]
    public void Dxp1_DeviceAndRouterEachDeriveTheSamePossessionProof()
    {
        var holderPrivate = SodiumCore.GetRandomBytes(32);
        var issuerPrivate = SodiumCore.GetRandomBytes(32);
        var holderPublic = ScalarMult.Base(holderPrivate);
        var issuerPublic = ScalarMult.Base(issuerPrivate);
        var proofs = new List<byte[]>();

        foreach (var role in new[]
                 {
                     X25519PossessionRole.Device,
                     X25519PossessionRole.Router
                 })
        {
            var transcript = CreateTranscript(
                holderPublic, issuerPublic, 100, 200, role);
            var created = X25519PossessionVerifier.CreateProof(transcript, holderPrivate);
            if (role == X25519PossessionRole.Device)
            {
                var reference = ReferenceDxp(transcript, holderPrivate);
                Assert.Equal(reference.Proof, created.Proof);
                Assert.Equal(reference.TranscriptHash, created.TranscriptHash);
            }
            var verified = X25519PossessionVerifier.Verify(
                transcript,
                created.Proof,
                issuerPrivate,
                role,
                transcript.AsSpan(8, 16),
                transcript.AsSpan(24, 32),
                holderPublic,
                150);
            Assert.Equal(role, verified.Role);
            Assert.Equal(created.TranscriptHash, verified.TranscriptHash.ToArray());
            proofs.Add(created.Proof.ToArray());
        }

        Assert.NotEqual(proofs[0], proofs[1]);
    }

    [Theory]
    [InlineData(4, 2)]
    [InlineData(5, 0)]
    [InlineData(5, 3)]
    [InlineData(6, 1)]
    [InlineData(7, 1)]
    public void Dxp1_ClosedHeaderMutationsRejectBeforeAgreement(int offset, byte value)
    {
        var holderPrivate = SodiumCore.GetRandomBytes(32);
        var issuerPrivate = SodiumCore.GetRandomBytes(32);
        var transcript = CreateTranscript(
            ScalarMult.Base(holderPrivate),
            ScalarMult.Base(issuerPrivate),
            100,
            200);
        var proof = X25519PossessionVerifier.CreateProof(transcript, holderPrivate).Proof;
        transcript[offset] = value;

        var error = Assert.Throws<RecordException>(() => X25519PossessionVerifier.Verify(
            transcript,
            proof,
            issuerPrivate,
            X25519PossessionRole.Device,
            transcript.AsSpan(8, 16),
            transcript.AsSpan(24, 32),
            transcript.AsSpan(56, 32),
            150));

        Assert.Equal(RecordError.InvalidField, error.Error);
    }

    [Fact]
    public void Dxp1_ExpiryAndWindowOver300Reject()
    {
        var holderPrivate = SodiumCore.GetRandomBytes(32);
        var issuerPrivate = SodiumCore.GetRandomBytes(32);
        var transcript = CreateTranscript(
            ScalarMult.Base(holderPrivate),
            ScalarMult.Base(issuerPrivate),
            100,
            401);
        var proof = new byte[32];

        var error = Assert.Throws<RecordException>(() => X25519PossessionVerifier.Verify(
            transcript,
            proof,
            issuerPrivate,
            X25519PossessionRole.Device,
            transcript.AsSpan(8, 16),
            transcript.AsSpan(24, 32),
            transcript.AsSpan(56, 32),
            150));

        Assert.Equal(RecordError.Expired, error.Error);
    }

    [Fact]
    public void ReleaseRootManifestAndRotation_AreSealedRelativeFactsOnly()
    {
        var signer = PublicKeyAuth.GenerateKeyPair();
        var root = PublicKeyAuth.GenerateKeyPair();
        var next = PublicKeyAuth.GenerateKeyPair();
        var network = Enumerable.Repeat((byte)0x51, 16).ToArray();
        var fields = MinimumFields(RecordDefinitions.Rrm1);
        fields[0] = network;
        fields[1] = U64(0);
        fields[2] = Enumerable.Repeat((byte)0x52, 32).ToArray();
        fields[3] = U64(0);
        fields[4] = root.PublicKey;
        fields[5] = U64(100);
        fields[6] = U64(15);
        fields[7] = Enumerable.Repeat((byte)0x53, 32).ToArray();
        fields[8] = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/release-manifest-key-id",
            signer.PublicKey);
        var carrier = CanonicalGrammar.Encode(RecordDefinitions.Rrm1, fields);
        fields[9] = PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(carrier, RecordDefinitions.Rrm1),
            "Deep/Cutover/V1/release-root-manifest"), signer.PrivateKey);
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Rrm1, fields);
        var manifestReference = CanonicalGrammar.ComputeReference(ArtifactType.Rrm1, canonical);
        var pin = new ReleaseRootManifestPin(
            network,
            fields[8].Span,
            signer.PublicKey,
            0,
            manifestReference);
        var verifier = new ReleaseRootRelativeVerifier();
        var genesis = verifier.VerifyManifest(pin, canonical, 100);

        Assert.True(genesis.NoAuthorityClaim);
        Assert.Equal((ulong)0, genesis.CurrentGeneration);
        Assert.Equal(root.PublicKey, genesis.CurrentEd25519PublicKey.ToArray());

        var rotationFields = MinimumFields(RecordDefinitions.Krt1);
        rotationFields[0] = network;
        rotationFields[1] = new byte[] { (byte)KeyScope.ReleaseRoot };
        rotationFields[2] = new byte[32];
        rotationFields[3] = U64(0);
        rotationFields[4] = U64(1);
        rotationFields[5] = CanonicalGrammar.EncodeReference(manifestReference);
        rotationFields[6] = RootKeyHash(network, root.PublicKey);
        rotationFields[7] = next.PublicKey;
        rotationFields[8] = U64(100);
        rotationFields[9] = new byte[] { (byte)KeyAction.Rotate };
        var rotationCarrier = CanonicalGrammar.Encode(RecordDefinitions.Krt1, rotationFields);
        var rotationSigning = CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(rotationCarrier, RecordDefinitions.Krt1),
            "Deep/IdentityAuth/V1/key-rotation");
        rotationFields[10] = PublicKeyAuth.SignDetached(rotationSigning, root.PrivateKey);
        rotationFields[11] = PublicKeyAuth.SignDetached(rotationSigning, next.PrivateKey);
        var rotation = CanonicalGrammar.Encode(RecordDefinitions.Krt1, rotationFields);
        var rotated = verifier.VerifyRotation(genesis, rotation, 100);

        Assert.True(rotated.NoAuthorityClaim);
        Assert.Equal((ulong)1, rotated.CurrentGeneration);
        Assert.Equal(next.PublicKey, rotated.CurrentEd25519PublicKey.ToArray());
    }

    [Fact]
    public void ReleaseRootRotation_PredecessorTypeCrossFeedRejectsBeforeSignatures()
    {
        var release = CreateReleaseRootFact();
        var next = PublicKeyAuth.GenerateKeyPair();
        var fields = MinimumFields(RecordDefinitions.Krt1);
        fields[0] = release.Network;
        fields[1] = new byte[] { (byte)KeyScope.ReleaseRoot };
        fields[2] = new byte[32];
        fields[3] = U64(0);
        fields[4] = U64(1);
        fields[5] = CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Krt1, 412, release.Reference.CanonicalHash.Span));
        fields[6] = RootKeyHash(release.Network, release.Root.PublicKey);
        fields[7] = next.PublicKey;
        fields[8] = U64(100);
        fields[9] = new byte[] { (byte)KeyAction.Rotate };
        fields[10] = Enumerable.Repeat((byte)0x71, 64).ToArray();
        fields[11] = Enumerable.Repeat((byte)0x72, 64).ToArray();
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Krt1, fields);

        var error = Assert.Throws<RecordException>(() =>
            new ReleaseRootRelativeVerifier().VerifyRotation(release.Fact, canonical, 100));
        Assert.Equal(RecordError.InvalidField, error.Error);
    }

    [Fact]
    public void ReleaseRootGenesisPin_IsSoleFirstKrtAndDwdPredecessorBeforeTheirSignatures()
    {
        // Creating the sealed generation-zero pin verifies the one external RRM signature.
        var release = CreateReleaseRootFact();
        var verifier = new ReleaseRootRelativeVerifier();

        var rotationFields = MinimumFields(RecordDefinitions.Krt1);
        rotationFields[0] = release.Network;
        rotationFields[1] = new byte[] { (byte)KeyScope.ReleaseRoot };
        rotationFields[2] = new byte[32];
        rotationFields[3] = U64(0);
        rotationFields[4] = U64(1);
        rotationFields[5] = DummyReference(ArtifactType.Krt1, 412, 0x71);
        rotationFields[6] = RootKeyHash(release.Network, release.Root.PublicKey);
        rotationFields[7] = PublicKeyAuth.GenerateKeyPair().PublicKey;
        rotationFields[8] = U64(100);
        rotationFields[9] = new byte[] { (byte)KeyAction.Rotate };
        rotationFields[10] = Enumerable.Repeat((byte)0x72, 64).ToArray();
        rotationFields[11] = Enumerable.Repeat((byte)0x73, 64).ToArray();
        var crossedRotation = CanonicalGrammar.Encode(
            RecordDefinitions.Krt1, rotationFields);
        Assert.Equal(RecordError.InvalidField, Assert.Throws<RecordException>(() =>
            verifier.VerifyRotation(release.Fact, crossedRotation, 100)).Error);

        var witnesses = Enumerable.Range(0, 4)
            .Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        var validDwd = CanonicalGrammar.DecodeOwned(
            CreateGenesisDwd(
                release.Fact, release.Root, release.Network, witnesses, new byte[288]),
            RecordDefinitions.Dwd1);
        var dwdFields = Enumerable.Range(1, RecordDefinitions.Dwd1.Fields.Count)
            .Select(tag => (ReadOnlyMemory<byte>)validDwd.FieldCopy(tag)).ToArray();
        dwdFields[15] = DummyReference(ArtifactType.Krt1, 412, 0x74);
        var crossedDwd = CanonicalGrammar.Encode(RecordDefinitions.Dwd1, dwdFields);
        Assert.Equal(RecordError.InvalidField, Assert.Throws<RecordException>(() =>
            verifier.VerifyGenesisWitnessDelegation(
                release.Fact, crossedDwd, new byte[288], 100)).Error);
    }

    [Fact]
    public async Task RrlHmacTranscriptAndCasPlan_ExposeOnlyExactTuples()
    {
        var key = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var verifier = new ReleaseRootRelativeVerifier();
        var oldCanonical = CreateRrl(verifier, key, 0x61);
        var oldTranscript = verifier.CreateLkgHmacTranscript(oldCanonical);
        var provider = new TestHmacProvider(key);
        var oldMatch = await verifier.VerifyLkgHmacAsync(oldCanonical, provider);
        var oldTuple = verifier.CreateAuthorityTuple(oldCanonical, oldMatch);
        var newCanonical = CreateRrl(verifier, key, 0x62);
        var newTranscript = verifier.CreateLkgHmacTranscript(newCanonical);
        var newMatch = await verifier.VerifyLkgHmacAsync(newCanonical, provider);
        var newTuple = verifier.CreateAuthorityTuple(newCanonical, newMatch);
        var plan = verifier.CreateTransitionPlan(oldTuple, newTuple);

        Assert.True(oldTranscript.NoAuthorityClaim);
        Assert.True(plan.NoAuthorityClaim);
        Assert.Equal(282, plan.OldTuple.CanonicalTuple.Length);
        Assert.NotEqual(plan.OldTuple.CanonicalTuple.ToArray(), plan.NewTuple.CanonicalTuple.ToArray());
        Assert.Equal(
            ["NewTuple", "NoAuthorityClaim", "OldTuple"],
            typeof(ReleaseRootTransitionPlan).GetProperties()
                .Select(static property => property.Name)
                .Order(StringComparer.Ordinal));
    }

    [Fact]
    public void PublicRelativeDeviceAndMailbox_VerifyExactDxpDrsAndOwnerId()
    {
        var fixture = AccountFixture.Create();
        var account = IdentityVerifier.VerifyAccountCertificate(fixture.AccountCanonical);
        var drs = CreateDrs(fixture, account, [], 1, 100);
        var verifier = new IdentityRelativeVerifier();
        var identity = verifier.VerifyGenesis(fixture.AccountCanonical, drs, [], 100);
        var deviceEd = PublicKeyAuth.GenerateKeyPair();
        var deviceXPrivate = SodiumCore.GetRandomBytes(32);
        var deviceXPublic = ScalarMult.Base(deviceXPrivate);
        var ephemeralPrivate = SodiumCore.GetRandomBytes(32);
        var ephemeralPublic = ScalarMult.Base(ephemeralPrivate);
        var deviceFields = MinimumFields(RecordDefinitions.Dpd1);
        deviceFields[0] = account.Certificate.NetworkId;
        deviceFields[1] = account.DeepAccountIdHash;
        deviceFields[2] = U64(1);
        deviceFields[3] = Enumerable.Repeat((byte)0x81, 32).ToArray();
        deviceFields[4] = U64(1);
        deviceFields[5] = deviceEd.PublicKey;
        deviceFields[6] = deviceXPublic;
        deviceFields[7] = Enumerable.Repeat((byte)0x82, 32).ToArray();
        deviceFields[8] = U64(0);
        deviceFields[9] = new byte[38];
        deviceFields[10] = KeyHash(account, KeyScope.DeviceCertificateIssuer,
            fixture.DeviceIssuer.PublicKey);
        deviceFields[11] = U64(1);
        deviceFields[12] = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Drs1, drs));
        deviceFields[13] = U64(0);
        deviceFields[14] = new byte[32];
        deviceFields[15] = U64(100);
        deviceFields[16] = U64(200);
        deviceFields[17] = U64(1);
        deviceFields[18] = U16(1);
        deviceFields[19] = new byte[38];
        deviceFields[20] = new byte[32];
        var deviceCarrier = CanonicalGrammar.Encode(RecordDefinitions.Dpd1, deviceFields);
        var deviceRecord = CanonicalGrammar.DecodeOwned(deviceCarrier, RecordDefinitions.Dpd1);
        var deviceSigning = CanonicalGrammar.GetSigningBytes(
            deviceRecord,
            "Deep/IdentityAuth/V1/device-certificate");
        var unsignedHash = DxpSubjectProjection.HashDevice(deviceRecord);
        var transcript = CreateTranscript(deviceXPublic, ephemeralPublic, 100, 200);
        account.Certificate.NetworkId.Span.CopyTo(transcript.AsSpan(8));
        unsignedHash.CopyTo(transcript, 24);
        var possession = X25519PossessionVerifier.CreateProof(transcript, deviceXPrivate);
        deviceFields[20] = possession.TranscriptHash;
        deviceCarrier = CanonicalGrammar.Encode(RecordDefinitions.Dpd1, deviceFields);
        deviceSigning = CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(deviceCarrier, RecordDefinitions.Dpd1),
            "Deep/IdentityAuth/V1/device-certificate");
        deviceFields[21] = PublicKeyAuth.SignDetached(deviceSigning, deviceEd.PrivateKey);
        deviceFields[22] = PublicKeyAuth.SignDetached(deviceSigning, fixture.DeviceIssuer.PrivateKey);
        var deviceCanonical = CanonicalGrammar.Encode(RecordDefinitions.Dpd1, deviceFields);
        var device = verifier.VerifyDevice(identity, deviceCanonical, transcript, possession.Proof,
            ephemeralPrivate, 150);

        var mailbox = PublicKeyAuth.GenerateKeyPair();
        var mailboxFields = MinimumFields(RecordDefinitions.Dpm1);
        mailboxFields[0] = account.Certificate.NetworkId;
        mailboxFields[1] = account.DeepAccountIdHash;
        mailboxFields[2] = U64(1);
        mailboxFields[3] = device.Certificate.DeviceId;
        mailboxFields[4] = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dpd1, deviceCanonical));
        var ownerPayload = new byte[80];
        account.Certificate.NetworkId.Span.CopyTo(ownerPayload);
        account.DeepAccountIdHash.Span.CopyTo(ownerPayload.AsSpan(16));
        mailbox.PublicKey.CopyTo(ownerPayload, 48);
        mailboxFields[5] = CanonicalGrammar.Sha256Domain(
            "Deep/IdentityAuth/V1/mailbox-owner-id", ownerPayload);
        mailboxFields[6] = U64(1);
        mailboxFields[7] = mailbox.PublicKey;
        mailboxFields[8] = Enumerable.Repeat((byte)0x83, 32).ToArray();
        mailboxFields[9] = U64(1);
        mailboxFields[10] = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Drs1, drs));
        mailboxFields[11] = U64(0);
        mailboxFields[12] = new byte[32];
        mailboxFields[13] = U64(100);
        mailboxFields[14] = U64(200);
        mailboxFields[15] = U64(3);
        mailboxFields[16] = new byte[38];
        var mailboxCarrier = CanonicalGrammar.Encode(RecordDefinitions.Dpm1, mailboxFields);
        var mailboxSigning = CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(mailboxCarrier, RecordDefinitions.Dpm1),
            "Deep/IdentityAuth/V1/mailbox-role-certificate");
        mailboxFields[17] = PublicKeyAuth.SignDetached(mailboxSigning, deviceEd.PrivateKey);
        mailboxFields[18] = PublicKeyAuth.SignDetached(mailboxSigning, mailbox.PrivateKey);
        var mailboxCanonical = CanonicalGrammar.Encode(RecordDefinitions.Dpm1, mailboxFields);
        var verifiedMailbox = verifier.VerifyMailboxRole(identity, mailboxCanonical, device, 150);

        Assert.True(device.NoAuthorityClaim);
        Assert.True(verifiedMailbox.NoAuthorityClaim);
        Assert.Equal(mailboxFields[5].ToArray(), verifiedMailbox.Certificate.MailboxOwnerId.ToArray());

        mailboxCanonical[FieldOffset(mailboxCanonical, 6)] ^= 1;
        var error = Assert.Throws<RecordException>(() =>
            verifier.VerifyMailboxRole(identity, mailboxCanonical, device, 150));
        Assert.Equal(RecordError.InvalidField, error.Error);
    }

    [Fact]
    public void GenesisDwdAndTerminalDwt_VerifyRelativeWitnessChain()
    {
        var release = CreateReleaseRootFact();
        var witnesses = Enumerable.Range(0, 4).Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        var heads = new byte[288];
        var dwd = CreateGenesisDwd(release.Fact, release.Root, release.Network, witnesses, heads);
        var verifier = new ReleaseRootRelativeVerifier();
        var delegation = verifier.VerifyGenesisWitnessDelegation(release.Fact, dwd, heads, 100);

        var krfFields = MinimumFields(RecordDefinitions.Krf1);
        krfFields[0] = release.Network;
        krfFields[1] = new byte[] { (byte)KeyScope.ReleaseRoot };
        krfFields[2] = new byte[32];
        krfFields[3] = U64(0);
        krfFields[4] = U64(1);
        krfFields[5] = CanonicalGrammar.EncodeReference(release.Reference);
        krfFields[6] = RootKeyHash(release.Network, release.Root.PublicKey);
        krfFields[7] = U64(100);
        krfFields[8] = new byte[] { (byte)KeyAction.Revoke };
        var krfCarrier = CanonicalGrammar.Encode(RecordDefinitions.Krf1, krfFields);
        krfFields[9] = PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(krfCarrier, RecordDefinitions.Krf1),
            "Deep/IdentityAuth/V1/key-revocation"), release.Root.PrivateKey);
        var krf = CanonicalGrammar.Encode(RecordDefinitions.Krf1, krfFields);
        var terminalRoot = verifier.VerifyRevocation(release.Fact, krf, 100);
        var dwt = CreateDwt(terminalRoot, delegation, krf, witnesses, 100);
        var terminal = verifier.VerifyWitnessTermination(terminalRoot, delegation, dwt, 100);
        var restoreVerifier = new ReleaseRootRelativeVerifier();
        var restoreInput = new ReleaseRootRestoreInput(
            release.Fact.Pin,
            release.Fact.Manifest.CanonicalBytes,
            [(ReadOnlyMemory<byte>)krf],
            [new WitnessAncestryInput(dwd, heads)],
            terminalDwtCanonical: dwt);
        var restored = restoreVerifier.RestoreAncestryRelative(restoreInput, 100);
        var replay = restoreVerifier.RestoreAncestryRelative(restoreInput, 100);

        Assert.True(delegation.NoAuthorityClaim);
        Assert.Equal(4, delegation.Descriptors.Count);
        Assert.True(terminal.NoAuthorityClaim);
        Assert.Equal((ulong)1, terminal.Termination.WitnessEpoch);
        Assert.True(restored.IsTerminal);
        Assert.False(restored.IsUsable);
        Assert.Equal(282, restored.AuthorityTuple.CanonicalTuple.Length);
        Assert.True(restored.NoAuthorityClaim);
        Assert.False(restored.IsExactReplay);
        Assert.True(replay.IsExactReplay);
    }

    [Fact]
    public void WitnessSubjectPolicyClosed_RejectsZeroCallerAndLimitSubstitutionBeforeSignature()
    {
        var release = CreateReleaseRootFact();
        var witnesses = Enumerable.Range(0, 4)
            .Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        var canonical = CreateGenesisDwd(
            release.Fact, release.Root, release.Network, witnesses, new byte[288]);
        var owned = CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dwd1);
        var verifier = new ReleaseRootRelativeVerifier();

        foreach (var mutation in new[]
        {
            (Field: 11, Value: (ReadOnlyMemory<byte>)new byte[32]),
            (Field: 11, Value: (ReadOnlyMemory<byte>)Enumerable.Repeat((byte)0xe1, 32).ToArray()),
            (Field: 7, Value: (ReadOnlyMemory<byte>)U64(11)),
            (Field: 8, Value: (ReadOnlyMemory<byte>)U64(11)),
            (Field: 9, Value: (ReadOnlyMemory<byte>)U64(101)),
            (Field: 10, Value: (ReadOnlyMemory<byte>)U64(14))
        })
        {
            var fields = Enumerable.Range(1, RecordDefinitions.Dwd1.Fields.Count)
                .Select(tag => (ReadOnlyMemory<byte>)owned.FieldCopy(tag)).ToArray();
            fields[mutation.Field - 1] = mutation.Value;
            // Reaching crypto would produce InvalidSignature. InvalidField proves that
            // the signed-network policy and each exact limit are recomputed first.
            for (var tag = 17; tag <= 21; tag++) fields[tag - 1] = new byte[64];
            var error = Assert.IsType<RecordException>(Record.Exception(() =>
            {
                var changed = CanonicalGrammar.Encode(RecordDefinitions.Dwd1, fields);
                verifier.VerifyGenesisWitnessDelegation(
                    release.Fact, changed, new byte[288], 100);
            }));
            Assert.Equal(RecordError.InvalidField, error.Error);
        }
    }

    [Fact]
    public void WitnessSuccessor_RetainedKeyChangeAndAllFourReplacementRejectBeforeSignatures()
    {
        var release = CreateReleaseRootFact();
        var witnesses = Enumerable.Range(0, 4)
            .Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        var zeroHeads = new byte[288];
        var genesisDwd = CreateGenesisDwd(
            release.Fact, release.Root, release.Network, witnesses, zeroHeads);
        var verifier = new ReleaseRootRelativeVerifier();
        var predecessor = verifier.VerifyGenesisWitnessDelegation(
            release.Fact, genesisDwd, zeroHeads, 100);
        var predecessorHeads = PredecessorHeads(predecessor);

        var changedKeyWitnesses = witnesses.ToArray();
        changedKeyWitnesses[0] = PublicKeyAuth.GenerateKeyPair();
        var retainedKeyChange = CreateUnsignedWitnessSuccessor(
            release.Fact, predecessor, release.Network, changedKeyWitnesses,
            predecessorHeads, replaceAllIds: false);
        var changedKey = Assert.Throws<RecordException>(() =>
            verifier.VerifyWitnessSuccessor(
                release.Fact, predecessor, retainedKeyChange, predecessorHeads, 101));
        Assert.Equal(RecordError.InvalidTransition, changedKey.Error);

        var replacements = Enumerable.Range(0, 4)
            .Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        var allFour = CreateUnsignedWitnessSuccessor(
            release.Fact, predecessor, release.Network, replacements,
            predecessorHeads, replaceAllIds: true);
        var replaced = Assert.Throws<RecordException>(() =>
            verifier.VerifyWitnessSuccessor(
                release.Fact, predecessor, allFour, predecessorHeads, 101));
        Assert.Equal(RecordError.InvalidTransition, replaced.Error);
    }

    [Fact]
    public void WitnessSuccessor_AllFourReplacementRejectsBeforeSignatures() =>
        WitnessSuccessor_RetainedKeyChangeAndAllFourReplacementRejectBeforeSignatures();

    [Fact]
    public void ReleaseRotationAndWitnessSuccessor_RemainInactiveUntilBothActivationTimes()
    {
        var release = CreateReleaseRootFact();
        var witnesses = Enumerable.Range(0, 4)
            .Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        var heads = new byte[288];
        var verifier = new ReleaseRootRelativeVerifier();
        var genesisDwd = CreateGenesisDwd(
            release.Fact, release.Root, release.Network, witnesses, heads);
        var predecessor = verifier.VerifyGenesisWitnessDelegation(
            release.Fact, genesisDwd, heads, 100);

        var nextRoot = PublicKeyAuth.GenerateKeyPair();
        var rotationFields = MinimumFields(RecordDefinitions.Krt1);
        rotationFields[0] = release.Network;
        rotationFields[1] = new byte[] { (byte)KeyScope.ReleaseRoot };
        rotationFields[2] = new byte[32];
        rotationFields[3] = U64(0);
        rotationFields[4] = U64(1);
        rotationFields[5] = CanonicalGrammar.EncodeReference(release.Reference);
        rotationFields[6] = RootKeyHash(release.Network, release.Root.PublicKey);
        rotationFields[7] = nextRoot.PublicKey;
        rotationFields[8] = U64(101);
        rotationFields[9] = new byte[] { (byte)KeyAction.Rotate };
        var rotationCarrier = CanonicalGrammar.Encode(RecordDefinitions.Krt1, rotationFields);
        var rotationSigning = CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(rotationCarrier, RecordDefinitions.Krt1),
            "Deep/IdentityAuth/V1/key-rotation");
        rotationFields[10] = PublicKeyAuth.SignDetached(
            rotationSigning, release.Root.PrivateKey);
        rotationFields[11] = PublicKeyAuth.SignDetached(
            rotationSigning, nextRoot.PrivateKey);
        var rotation = CanonicalGrammar.Encode(RecordDefinitions.Krt1, rotationFields);

        var earlyRotation = Assert.Throws<RecordException>(() =>
            verifier.VerifyRotation(release.Fact, rotation, 100));
        Assert.Equal(RecordError.Expired, earlyRotation.Error);
        var rotated = verifier.VerifyRotation(release.Fact, rotation, 101);

        var successor = CreateUnsignedWitnessSuccessor(
            rotated, predecessor, release.Network, witnesses,
            PredecessorHeads(predecessor), replaceAllIds: false);
        var successorRecord = CanonicalGrammar.DecodeOwned(
            successor, RecordDefinitions.Dwd1);
        var successorFields = Enumerable.Range(1, RecordDefinitions.Dwd1.Fields.Count)
            .Select(tag => (ReadOnlyMemory<byte>)successorRecord.FieldCopy(tag)).ToArray();
        successorFields[4] = U64(102);
        var inactiveSuccessor = CanonicalGrammar.Encode(
            RecordDefinitions.Dwd1, successorFields);

        var earlyDelegation = Assert.Throws<RecordException>(() =>
            verifier.VerifyWitnessSuccessor(
                rotated, predecessor, inactiveSuccessor,
                PredecessorHeads(predecessor), 101));
        Assert.Equal(RecordError.Expired, earlyDelegation.Error);
        Assert.True(rotated.NoAuthorityClaim);
    }

    private static byte[] PredecessorHeads(WitnessDelegationRelativeFact predecessor)
    {
        var heads = new byte[288];
        for (var index = 0; index < 4; index++)
        {
            var row = heads.AsSpan(index * 72, 72);
            predecessor.Descriptors[index].WitnessId.Span.CopyTo(row);
            WitnessTreeVerifier.EmptyRoot(
                predecessor.Delegation.WitnessEpoch,
                predecessor.Descriptors[index].WitnessId.Span,
                predecessor.Delegation.MaximumTreeSize).CopyTo(row[40..]);
        }
        return heads;
    }

    private static byte[] CreateUnsignedWitnessSuccessor(
        ReleaseRootRelativeFact root,
        WitnessDelegationRelativeFact predecessor,
        ReadOnlySpan<byte> network,
        IReadOnlyList<KeyPair> witnesses,
        ReadOnlySpan<byte> predecessorHeads,
        bool replaceAllIds)
    {
        var fields = MinimumFields(RecordDefinitions.Dwd1);
        fields[0] = network.ToArray();
        fields[1] = U64(predecessor.Delegation.DelegationGeneration + 1);
        fields[2] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dwd1, predecessor.Delegation.CanonicalBytes.Span));
        fields[3] = U64(predecessor.Delegation.WitnessEpoch + 1);
        fields[4] = U64(100); fields[5] = U64(2000);
        fields[6] = U64(10); fields[7] = U64(10);
        fields[8] = U64(predecessor.Delegation.MaximumTreeSize);
        fields[9] = U64(15);
        fields[10] = SubjectPolicy(network, 10, 10,
            predecessor.Delegation.MaximumTreeSize);
        var headsPayload = new byte[296];
        U64(predecessor.Delegation.WitnessEpoch).CopyTo(headsPayload, 0);
        predecessorHeads.CopyTo(headsPayload.AsSpan(8));
        fields[11] = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/witness-heads", headsPayload);
        fields[12] = new byte[] { 4 };
        var descriptors = new byte[464];
        for (var index = 0; index < 4; index++)
        {
            var row = descriptors.AsSpan(index * 116, 116);
            row[..32].Fill(replaceAllIds
                ? checked((byte)(index + 5))
                : checked((byte)(index + 1)));
            witnesses[index].PublicKey.CopyTo(row[32..64]);
            row[64] = (byte)WitnessEndpointKind.Ipv4;
            row[66] = 1; row[67] = 2; row[68] = 3;
            row[69] = checked((byte)(index + 1));
            BinaryPrimitives.WriteUInt16BigEndian(
                row[82..84], checked((ushort)(8100 + index)));
            row[84..116].Fill(checked((byte)(0xb0 + index)));
        }
        fields[13] = descriptors;
        var setRootPayload = new byte[473];
        fields[3].Span.CopyTo(setRootPayload);
        setRootPayload[8] = 4;
        descriptors.CopyTo(setRootPayload, 9);
        fields[14] = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/witness-set-root", setRootPayload);
        fields[15] = CanonicalGrammar.EncodeReference(root.CurrentTransitionReference);
        // Signature slots remain zero deliberately. InvalidTransition therefore proves
        // that cross-epoch continuity is rejected before any signature verification.
        return CanonicalGrammar.Encode(RecordDefinitions.Dwd1, fields);
    }

    [Fact]
    public void FullRestore_NonterminalRequiresFreshExactDclTail()
    {
        var release = CreateReleaseRootFact();
        var witnesses = Enumerable.Range(0, 4).Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        var heads = new byte[288];
        var dwd = CreateGenesisDwd(release.Fact, release.Root, release.Network, witnesses, heads);
        var relativeVerifier = new ReleaseRootRelativeVerifier();
        var delegation = relativeVerifier.VerifyGenesisWitnessDelegation(release.Fact, dwd, heads, 101);
        var tuple = GenesisAuthorityTuple(release.Fact, delegation);
        var dcl = CreateFreshDcl(release.Fact, delegation, witnesses, tuple, 100, 105);
        var input = new ReleaseRootRestoreInput(
            release.Fact.Pin,
            release.Fact.Manifest.CanonicalBytes,
            [],
            [new WitnessAncestryInput(dwd, heads)],
            freshDclCanonical: dcl);

        var restored = new ReleaseRootRelativeVerifier()
            .RestoreAncestryRelative(input, 101);

        Assert.False(restored.IsTerminal);
        Assert.True(restored.IsUsable);
        Assert.NotNull(restored.FreshLease);
        Assert.True(restored.NoAuthorityClaim);
        Assert.Throws<RecordException>(() => new ReleaseRootRestoreInput(
            release.Fact.Pin,
            release.Fact.Manifest.CanonicalBytes,
            [],
            [new WitnessAncestryInput(dwd, heads)]));
    }

    [Fact]
    public void ReleaseRootRestoreInput_EnforcesExactTransitionAncestryAndTailBoundsBeforeCrypto()
    {
        var pin = new ReleaseRootManifestPin(
            Enumerable.Repeat((byte)0x61, 16).ToArray(),
            Enumerable.Repeat((byte)0x62, 32).ToArray(),
            Enumerable.Repeat((byte)0x63, 32).ToArray(),
            0,
            new ArtifactReference(
                ArtifactType.Rrm1, 332,
                Enumerable.Repeat((byte)0x64, 32).ToArray()));
        var manifest = new byte[332];
        var transitions = Enumerable.Range(0, 64)
            .Select(static index => (ReadOnlyMemory<byte>)new byte[index % 2 == 0 ? 300 : 412])
            .ToArray();
        var ancestry = Enumerable.Range(0, 65)
            .Select(static _ => new WitnessAncestryInput(new byte[1217], new byte[288]))
            .ToArray();
        var dcl = new byte[409];

        var maximum = new ReleaseRootRestoreInput(
            pin, manifest, transitions, ancestry, freshDclCanonical: dcl);

        Assert.Equal(64, maximum.RootTransitions.Count);
        Assert.Equal(65, maximum.WitnessDelegations.Count);
        Assert.False(maximum.IsTerminal);
        Assert.True(maximum.NoAuthorityClaim);

        AssertInvalid(transitions.Append((ReadOnlyMemory<byte>)new byte[300]).ToArray(), ancestry,
            default, dcl);
        AssertInvalid(transitions, [], default, dcl);
        AssertInvalid(transitions, ancestry.Append(
            new WitnessAncestryInput(new byte[1217], new byte[288])).ToArray(), default, dcl);
        AssertInvalid([(ReadOnlyMemory<byte>)new byte[301]], ancestry[..1], default, dcl);
        AssertInvalid(transitions, ancestry, default, default);
        AssertInvalid(transitions, ancestry, new byte[714], dcl);
        AssertInvalid(transitions, ancestry, new byte[713], default);
        AssertInvalid(transitions, ancestry, default, new byte[408]);
        Assert.Throws<RecordException>(() =>
            new WitnessAncestryInput(new byte[1216], new byte[288]));
        Assert.Throws<RecordException>(() =>
            new WitnessAncestryInput(new byte[1217], new byte[287]));

        void AssertInvalid(
            IReadOnlyList<ReadOnlyMemory<byte>> roots,
            IReadOnlyList<WitnessAncestryInput> witnesses,
            ReadOnlyMemory<byte> dwt,
            ReadOnlyMemory<byte> freshDcl)
        {
            var error = Assert.Throws<RecordException>(() => new ReleaseRootRestoreInput(
                pin, manifest, roots, witnesses, dwt, freshDcl));
            Assert.Equal(RecordError.InvalidLength, error.Error);
        }
    }

    [Fact]
    public void WitnessMaximumTreeFence_RejectsOversizedLeaseBeforeSignature()
    {
        var release = CreateReleaseRootFact();
        var witnesses = Enumerable.Range(0, 4)
            .Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        var heads = new byte[288];
        var dwd = CreateGenesisDwd(release.Fact, release.Root, release.Network, witnesses, heads);
        var delegation = new ReleaseRootRelativeVerifier().VerifyGenesisWitnessDelegation(
            release.Fact, dwd, heads, 101);
        var tuple = GenesisAuthorityTuple(release.Fact, delegation);
        var dcl = CreateFreshDcl(release.Fact, delegation, witnesses, tuple, 100, 105);

        var dclRecord = CanonicalGrammar.DecodeOwned(dcl, RecordDefinitions.Dcl1);
        var dclFields = Enumerable.Range(1, RecordDefinitions.Dcl1.Fields.Count)
            .Select(tag => (ReadOnlyMemory<byte>)dclRecord.FieldCopy(tag)).ToArray();
        var rows = dclFields[10].ToArray();
        var firstLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(rows));
        var first = CanonicalGrammar.DecodeOwned(
            rows.AsSpan(4, firstLength), RecordDefinitions.Dhl1);
        var firstFields = Enumerable.Range(1, RecordDefinitions.Dhl1.Fields.Count)
            .Select(tag => (ReadOnlyMemory<byte>)first.FieldCopy(tag)).ToArray();
        firstFields[15] = U64(checked(delegation.Delegation.MaximumTreeSize + 1));
        var oversized = CanonicalGrammar.Encode(RecordDefinitions.Dhl1, firstFields);
        Assert.Equal(firstLength, oversized.Length);
        oversized.CopyTo(rows, 4);
        dclFields[10] = rows;
        var changedDcl = CanonicalGrammar.Encode(RecordDefinitions.Dcl1, dclFields);

        var error = Assert.Throws<RecordException>(() =>
            new ReleaseRootRelativeVerifier().RestoreAncestryRelative(
                new ReleaseRootRestoreInput(
                    release.Fact.Pin,
                    release.Fact.Manifest.CanonicalBytes,
                    [],
                    [new WitnessAncestryInput(dwd, heads)],
                    freshDclCanonical: changedDcl),
                101));

        Assert.Equal(RecordError.InvalidField, error.Error);
    }

    [Fact]
    public async Task WitnessHeadHistoryLkg_ExactGenesisRoundTripAndKeyMismatchIsPreCallback()
    {
        var release = CreateReleaseRootFact();
        var witnesses = Enumerable.Range(0, 4).Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        var predecessorHeads = new byte[288];
        var dwd = CreateGenesisDwd(
            release.Fact, release.Root, release.Network, witnesses, predecessorHeads);
        var delegation = new ReleaseRootRelativeVerifier().VerifyGenesisWitnessDelegation(
            release.Fact, dwd, predecessorHeads, 101);
        var authorityTuple = GenesisAuthorityTuple(release.Fact, delegation);
        var dcl = CreateFreshDcl(release.Fact, delegation, witnesses, authorityTuple, 100, 105);
        var restored = new ReleaseRootRelativeVerifier().RestoreAncestryRelative(
            new ReleaseRootRestoreInput(
                release.Fact.Pin,
                release.Fact.Manifest.CanonicalBytes,
                [],
                [new WitnessAncestryInput(dwd, predecessorHeads)],
                freshDclCanonical: dcl),
            101);
        var authorityHead = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/release-root-authority-head",
            restored.AuthorityTuple.CanonicalTuple.Span);
        var reset = Enumerable.Repeat((byte)0xd1, 32).ToArray();
        var account = Enumerable.Repeat((byte)0xd2, 32).ToArray();
        var keyId = Enumerable.Repeat((byte)0xd3, 32).ToArray();
        var cutover = new CurrentCutoverRelative(
            release.Network, reset, ComponentKind.Shared, account, 1, 1,
            DummyReference(ArtifactType.Dcm1, 812, 0xd4),
            DummyReference(ArtifactType.Dcp1, 706, 0xd5),
            DummyReference(ArtifactType.Dcs1, 839, 0xd6),
            DummyReference(ArtifactType.Dcq1, 375, 0xd7),
            DummyReference(ArtifactType.Dwl1, 708, 0xd8),
            DummyReference(ArtifactType.Dcl1, 409, 0xd9),
            DummyReference(ArtifactType.Dpl1, 576, 0xda),
            authorityHead, 1, 0, new byte[32],
            DummyReference(ArtifactType.Drs1, 356, 0xdc), 105,
            keyId, keyId, keyId, keyId, keyId, keyId);
        var whl = new byte[222];
        "WHL1"u8.CopyTo(whl);
        whl[4] = 1;
        release.Network.CopyTo(whl, 6);
        reset.CopyTo(whl, 22);
        Span<byte> deployment = stackalloc byte[80];
        release.Network.CopyTo(deployment);
        account.CopyTo(deployment[16..]);
        reset.CopyTo(deployment[48..]);
        CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/deployment-subject", deployment).CopyTo(whl, 54);
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dwd1, dwd)).CopyTo(whl, 86);
        authorityHead.CopyTo(whl, 124);
        keyId.CopyTo(whl, 158);
        var provider = new TestHmacProvider(keyId);
        var tag = await provider.ComputeTagAsync(new ProtectedHmacRequest(
            "Deep/ProtectedState/V1/WHL1", ArtifactRegistry.ProtectedHmacSha256,
            keyId, whl.AsSpan(0, 190)), default);
        tag.CopyTo(whl.AsMemory(190));

        var verified = await new WitnessHeadHistoryLkgVerifier().VerifyCurrentAsync(
            new WitnessHeadHistoryLkgInput(whl), cutover, restored, provider);

        Assert.Equal((ushort)0, verified.EntryCount);
        Assert.True(verified.NoAuthorityClaim);
        var badKey = whl.ToArray();
        badKey[158] ^= 1;
        var callbacksBefore = provider.Calls;
        await Assert.ThrowsAsync<RecordException>(() =>
            new WitnessHeadHistoryLkgVerifier().VerifyCurrentAsync(
                new WitnessHeadHistoryLkgInput(badKey), cutover, restored, provider).AsTask());
        Assert.Equal(callbacksBefore, provider.Calls);

        var authenticatedWrongSource = whl.ToArray();
        authenticatedWrongSource[6] ^= 1;
        var wrongSourceTag = await provider.ComputeTagAsync(new ProtectedHmacRequest(
            "Deep/ProtectedState/V1/WHL1", ArtifactRegistry.ProtectedHmacSha256,
            keyId, authenticatedWrongSource.AsSpan(0, 190)), default);
        wrongSourceTag.CopyTo(authenticatedWrongSource.AsMemory(190));
        callbacksBefore = provider.Calls;
        await Assert.ThrowsAsync<RecordException>(() =>
            new WitnessHeadHistoryLkgVerifier().VerifyCurrentAsync(
                new WitnessHeadHistoryLkgInput(authenticatedWrongSource),
                cutover, restored, provider).AsTask());
        Assert.Equal(callbacksBefore + 1, provider.Calls);
    }

    [Fact]
    public async Task StandaloneDwhRelative_GenesisMatchesVerifiedAncestryAndHasNoAuthoritySurface()
    {
        var verified = await VerifyGenesisDwhRelativeForEvidenceAsync();

        Assert.Equal((ushort)0, verified.EntryCount);
        Assert.True(verified.NoAuthorityClaim);
        Assert.Equal(32, verified.WitnessHeadHistoryHash.Length);
        Assert.Empty(typeof(VerifiedWitnessHeadHistoryRelative).GetConstructors());
        Assert.DoesNotContain(typeof(VerifiedWitnessHeadHistoryRelative).GetMethods(), method =>
            method.Name.Contains("Commit", StringComparison.OrdinalIgnoreCase) ||
            method.Name.Contains("Persist", StringComparison.OrdinalIgnoreCase) ||
            method.Name.Contains("Activate", StringComparison.OrdinalIgnoreCase));
    }

    internal static async Task<VerifiedWitnessHeadHistoryRelative>
        VerifyGenesisDwhRelativeForEvidenceAsync()
    {
        var release = CreateReleaseRootFact();
        var witnesses = Enumerable.Range(0, 4)
            .Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        var predecessorHeads = new byte[288];
        var dwd = CreateGenesisDwd(
            release.Fact, release.Root, release.Network, witnesses, predecessorHeads);
        var delegation = new ReleaseRootRelativeVerifier().VerifyGenesisWitnessDelegation(
            release.Fact, dwd, predecessorHeads, 101);
        var authorityTuple = GenesisAuthorityTuple(release.Fact, delegation);
        var dcl = CreateFreshDcl(release.Fact, delegation, witnesses, authorityTuple, 100, 105);
        var restored = new ReleaseRootRelativeVerifier().RestoreAncestryRelative(
            new ReleaseRootRestoreInput(
                release.Fact.Pin,
                release.Fact.Manifest.CanonicalBytes,
                [],
                [new WitnessAncestryInput(dwd, predecessorHeads)],
                freshDclCanonical: dcl),
            101);

        var key = Enumerable.Repeat((byte)0xe4, 32).ToArray();
        var provider = new TestHmacProvider(key);
        var source = Enumerable.Repeat((byte)0xe5, 160).ToArray();
        var rfc = EmptyProtectedContainer("RFC1", RecoveryManifestParser.RfcFixedLength, 1,
            source, key);
        var rah = EmptyProtectedContainer("RAH1", RecoveryManifestParser.RahFixedLength, 1,
            source, key);
        var dtc = EmptyProtectedContainer("DTC2", RecoveryManifestParser.DtcFixedLength, 2,
            source, key);
        var dwh = EmptyProtectedContainer("DWH1", RecoveryManifestParser.DwhFixedLength, 1,
            source, key);
        var tag = await provider.ComputeTagAsync(new ProtectedHmacRequest(
            "Deep/ProtectedState/V1/DWH1", ArtifactRegistry.ProtectedHmacSha256,
            key, dwh.AsSpan(0, dwh.Length - 32)), default);
        tag.CopyTo(dwh.AsMemory(dwh.Length - 32));

        var result = await RecoveryVerifier.VerifyWitnessHeadHistoryRelativeAsync(
            restored, new NormalRecoveryStoreInput(rfc, rah, dtc, dwh), provider);
        Assert.Equal(2, provider.Calls); // one fixture tag plus one verifier HMAC
        return result;
    }

    internal static async Task<VerifiedGenesisReleaseHead>
        VerifyGenesisReleaseHeadForEvidenceAsync(
            VerifiedGenesisBaseIdentityContext baseIdentity,
            ReleaseRootRelativeFact releaseRoot,
            KeyPair releaseRootSigner,
            ReadOnlyMemory<byte> protectedKeyId,
            IProtectedHmacProvider hmacProvider,
            ICollection<KeyPair>? witnessSigners = null)
    {
        var witnesses = Enumerable.Range(0, 4)
            .Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        if (witnessSigners is not null)
            foreach (var witness in witnesses) witnessSigners.Add(witness);
        var predecessorHeads = new byte[288];
        var dwd = CreateGenesisDwd(releaseRoot, releaseRootSigner,
            releaseRoot.Manifest.NetworkId.Span, witnesses, predecessorHeads);
        var delegation = new ReleaseRootRelativeVerifier().VerifyGenesisWitnessDelegation(
            releaseRoot, dwd, predecessorHeads, 101);
        var dwdReference = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dwd1, dwd));
        var rrmReference = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Rrm1, releaseRoot.Manifest.CanonicalBytes.Span));
        var checkpointInput = new byte[78];
        rrmReference.CopyTo(checkpointInput, 0);
        dwdReference.CopyTo(checkpointInput, 40);
        var checkpoint = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/release-root-chain", checkpointInput);

        var rrlFields = MinimumFields(RecordDefinitions.Rrl1);
        rrlFields[0] = releaseRoot.Manifest.NetworkId;
        rrlFields[1] = rrmReference;
        rrlFields[2] = U64(0);
        rrlFields[3] = releaseRoot.CurrentEd25519PublicKey;
        rrlFields[4] = rrmReference;
        rrlFields[5] = new byte[38];
        rrlFields[6] = new byte[] { 0 };
        rrlFields[7] = new byte[] { 0 };
        rrlFields[8] = U64(0);
        rrlFields[9] = dwdReference;
        rrlFields[10] = U64(1);
        rrlFields[11] = U16(0);
        rrlFields[12] = checkpoint;
        rrlFields[13] = new byte[38];
        rrlFields[14] = protectedKeyId;
        var rrlUnsigned = CanonicalGrammar.Encode(RecordDefinitions.Rrl1, rrlFields);
        var rrlTranscript = new ReleaseRootRelativeVerifier()
            .CreateLkgHmacTranscript(rrlUnsigned);
        rrlFields[15] = await hmacProvider.ComputeTagAsync(new ProtectedHmacRequest(
            rrlTranscript.Domain, rrlTranscript.Suite,
            protectedKeyId.Span, rrlTranscript.UnsignedCanonical.Span), default);
        var rrl = CanonicalGrammar.Encode(RecordDefinitions.Rrl1, rrlFields);

        var whl = new byte[222];
        "WHL1"u8.CopyTo(whl); whl[4] = 1;
        releaseRoot.Manifest.NetworkId.Span.CopyTo(whl.AsSpan(6));
        baseIdentity.ResetId.CopyTo(whl.AsSpan(22));
        Span<byte> deployment = stackalloc byte[80];
        baseIdentity.Network.CopyTo(deployment[..16]);
        baseIdentity.AccountHash.CopyTo(deployment[16..48]);
        baseIdentity.ResetId.CopyTo(deployment[48..]);
        CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/deployment-subject", deployment).CopyTo(whl, 54);
        dwdReference.CopyTo(whl, 86);
        GenesisReleaseContext.ComputeAuthorityHead(releaseRoot, delegation).CopyTo(whl, 124);
        protectedKeyId.Span.CopyTo(whl.AsSpan(158));
        var whlTag = await hmacProvider.ComputeTagAsync(new ProtectedHmacRequest(
            "Deep/ProtectedState/V1/WHL1", ArtifactRegistry.ProtectedHmacSha256,
            protectedKeyId.Span, whl.AsSpan(0, 190)), default);
        whlTag.Span.CopyTo(whl.AsSpan(190));

        return await new WitnessHeadHistoryLkgVerifier().VerifyGenesisAsync(
            new WitnessHeadHistoryLkgInput(whl), rrl, releaseRoot, [delegation],
            baseIdentity, hmacProvider);
    }

    private static byte[] EmptyProtectedContainer(
        string magic,
        int length,
        byte version,
        ReadOnlySpan<byte> source160,
        ReadOnlySpan<byte> key32)
    {
        var value = new byte[length];
        Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        value[4] = version;
        source160.CopyTo(value.AsSpan(6));
        key32.CopyTo(value.AsSpan(length - 64));
        return value;
    }

    private static (byte[] Proof, byte[] TranscriptHash) ReferenceDxp(
        ReadOnlySpan<byte> transcript,
        ReadOnlySpan<byte> holderPrivate)
    {
        const string saltName = "Deep/IdentityAuth/V1/x25519-pop-salt";
        const string keyName = "Deep/IdentityAuth/V1/x25519-pop-key/device";
        var saltDomain = Encoding.ASCII.GetBytes(saltName);
        var saltInput = new byte[2 + saltDomain.Length + 16 + 1 + 32 + 32 + 32 + 32];
        BinaryPrimitives.WriteUInt16BigEndian(saltInput, checked((ushort)saltDomain.Length));
        saltDomain.CopyTo(saltInput, 2);
        var offset = 2 + saltDomain.Length;
        transcript.Slice(8, 16).CopyTo(saltInput.AsSpan(offset)); offset += 16;
        saltInput[offset++] = transcript[5];
        transcript.Slice(24, 32).CopyTo(saltInput.AsSpan(offset)); offset += 32;
        transcript.Slice(120, 32).CopyTo(saltInput.AsSpan(offset)); offset += 32;
        transcript.Slice(88, 32).CopyTo(saltInput.AsSpan(offset)); offset += 32;
        transcript.Slice(56, 32).CopyTo(saltInput.AsSpan(offset));
        var salt = SHA256.HashData(saltInput);
        var shared = ScalarMult.Mult(holderPrivate.ToArray(), transcript.Slice(88, 32).ToArray());
        var prk = new byte[32];
        Assert.Equal(32, HKDF.Extract(HashAlgorithmName.SHA256, shared, salt, prk));
        var keyDomain = Encoding.ASCII.GetBytes(keyName);
        var info = new byte[2 + keyDomain.Length + 4 + transcript.Length];
        BinaryPrimitives.WriteUInt16BigEndian(info, checked((ushort)keyDomain.Length));
        keyDomain.CopyTo(info, 2);
        BinaryPrimitives.WriteUInt32BigEndian(info.AsSpan(2 + keyDomain.Length), checked((uint)transcript.Length));
        transcript.CopyTo(info.AsSpan(6 + keyDomain.Length));
        var key = new byte[32];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, key, info);
        var proofInput = new byte[4 + transcript.Length];
        BinaryPrimitives.WriteUInt32BigEndian(proofInput, checked((uint)transcript.Length));
        transcript.CopyTo(proofInput.AsSpan(4));
        var proof = HMACSHA256.HashData(key, proofInput);
        var hashPayload = new byte[4 + transcript.Length + 4 + proof.Length];
        BinaryPrimitives.WriteUInt32BigEndian(hashPayload, checked((uint)transcript.Length));
        transcript.CopyTo(hashPayload.AsSpan(4));
        BinaryPrimitives.WriteUInt32BigEndian(hashPayload.AsSpan(4 + transcript.Length), checked((uint)proof.Length));
        proof.CopyTo(hashPayload.AsSpan(8 + transcript.Length));
        return (proof, CanonicalGrammar.Sha256Domain(
            "Deep/IdentityAuth/V1/x25519-pop-transcript-hash",
            hashPayload));
    }

    private static byte[] CreateRrl(
        ReleaseRootRelativeVerifier verifier,
        ReadOnlySpan<byte> hmacKey,
        byte checkpointByte)
    {
        var fields = MinimumFields(RecordDefinitions.Rrl1);
        fields[0] = Enumerable.Repeat((byte)0x61, 16).ToArray();
        fields[1] = DummyReference(ArtifactType.Rrm1, 332, 0x71);
        fields[2] = U64(0);
        fields[3] = Enumerable.Repeat((byte)0x72, 32).ToArray();
        fields[4] = fields[1];
        fields[5] = new byte[38];
        fields[6] = new byte[] { 0 };
        fields[7] = new byte[] { 0 };
        fields[8] = U64(0);
        fields[9] = DummyReference(ArtifactType.Dwd1, 1217, 0x73);
        fields[10] = U64(1);
        fields[11] = U16(0);
        fields[12] = Enumerable.Repeat(checkpointByte, 32).ToArray();
        fields[13] = new byte[38];
        fields[14] = Enumerable.Repeat((byte)0x74, 32).ToArray();
        fields[15] = new byte[32];
        var carrier = CanonicalGrammar.Encode(RecordDefinitions.Rrl1, fields);
        var transcript = verifier.CreateLkgHmacTranscript(carrier);
        fields[15] = ComputeProtectedTag(hmacKey, transcript);
        return CanonicalGrammar.Encode(RecordDefinitions.Rrl1, fields);
    }

    private static byte[] ComputeProtectedTag(
        ReadOnlySpan<byte> key,
        ReleaseRootLkgHmacTranscript transcript)
    {
        var domain = Encoding.ASCII.GetBytes(transcript.Domain);
        var input = new byte[2 + domain.Length + 2 + 4 + transcript.UnsignedCanonical.Length];
        BinaryPrimitives.WriteUInt16BigEndian(input, checked((ushort)domain.Length));
        domain.CopyTo(input, 2);
        var offset = 2 + domain.Length;
        BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset), transcript.Suite);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(offset + 2),
            checked((uint)transcript.UnsignedCanonical.Length));
        transcript.UnsignedCanonical.Span.CopyTo(input.AsSpan(offset + 6));
        return HMACSHA256.HashData(key, input);
    }

    private static byte[] RootKeyHash(ReadOnlySpan<byte> network, ReadOnlySpan<byte> publicKey)
    {
        Span<byte> payload = stackalloc byte[89];
        network.CopyTo(payload);
        payload[16] = (byte)KeyScope.ReleaseRoot;
        payload.Slice(17, 40).Clear();
        publicKey.CopyTo(payload[57..]);
        return CanonicalGrammar.Sha256Domain("Deep/IdentityAuth/V1/key-hash", payload);
    }

    private static byte[] DummyReference(ArtifactType type, uint length, byte fill) =>
        CanonicalGrammar.EncodeReference(new ArtifactReference(
            type,
            length,
            Enumerable.Repeat(fill, 32).ToArray()));

    private static (ReleaseRootRelativeFact Fact, KeyPair Root, byte[] Network,
        ArtifactReference Reference) CreateReleaseRootFact()
    {
        var signer = PublicKeyAuth.GenerateKeyPair();
        var root = PublicKeyAuth.GenerateKeyPair();
        var network = Enumerable.Repeat((byte)0x91, 16).ToArray();
        var fields = MinimumFields(RecordDefinitions.Rrm1);
        fields[0] = network;
        fields[1] = U64(0);
        fields[2] = Enumerable.Repeat((byte)0x92, 32).ToArray();
        fields[3] = U64(0);
        fields[4] = root.PublicKey;
        fields[5] = U64(100);
        fields[6] = U64(15);
        fields[7] = Enumerable.Repeat((byte)0x93, 32).ToArray();
        fields[8] = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/release-manifest-key-id", signer.PublicKey);
        var carrier = CanonicalGrammar.Encode(RecordDefinitions.Rrm1, fields);
        fields[9] = PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(carrier, RecordDefinitions.Rrm1),
            "Deep/Cutover/V1/release-root-manifest"), signer.PrivateKey);
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Rrm1, fields);
        var reference = CanonicalGrammar.ComputeReference(ArtifactType.Rrm1, canonical);
        var pin = new ReleaseRootManifestPin(network, fields[8].Span, signer.PublicKey, 0, reference);
        return (new ReleaseRootRelativeVerifier().VerifyManifest(pin, canonical, 100),
            root, network, reference);
    }

    private static byte[] CreateGenesisDwd(
        ReleaseRootRelativeFact rootFact,
        KeyPair root,
        ReadOnlySpan<byte> network,
        IReadOnlyList<KeyPair> witnesses,
        ReadOnlySpan<byte> predecessorHeads)
    {
        var fields = MinimumFields(RecordDefinitions.Dwd1);
        fields[0] = network.ToArray();
        fields[1] = U64(0);
        fields[2] = new byte[38];
        fields[3] = U64(1);
        fields[4] = U64(100);
        fields[5] = U64(2000);
        fields[6] = U64(10);
        fields[7] = U64(10);
        fields[8] = U64(100);
        fields[9] = U64(15);
        fields[10] = SubjectPolicy(network, 10, 10, 100);
        if (!CanonicalGrammar.IsZero(predecessorHeads))
            throw new InvalidOperationException("Genesis DWD fixture requires exact zero288 predecessor heads.");
        fields[11] = new byte[32];
        fields[12] = new byte[] { 4 };
        var descriptors = new byte[464];
        for (var index = 0; index < 4; index++)
        {
            var row = descriptors.AsSpan(index * 116, 116);
            row[..32].Fill(checked((byte)(index + 1)));
            witnesses[index].PublicKey.CopyTo(row[32..64]);
            row[64] = (byte)WitnessEndpointKind.Ipv4;
            row[66] = 1; row[67] = 2; row[68] = 3; row[69] = checked((byte)(index + 1));
            BinaryPrimitives.WriteUInt16BigEndian(row[82..84], checked((ushort)(8000 + index)));
            row[84..116].Fill(checked((byte)(0xa0 + index)));
        }
        fields[13] = descriptors;
        var setRootPayload = new byte[473];
        U64(1).CopyTo(setRootPayload, 0);
        setRootPayload[8] = 4;
        descriptors.CopyTo(setRootPayload, 9);
        fields[14] = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/witness-set-root", setRootPayload);
        fields[15] = CanonicalGrammar.EncodeReference(rootFact.CurrentTransitionReference);
        var carrier = CanonicalGrammar.Encode(RecordDefinitions.Dwd1, fields);
        var owned = CanonicalGrammar.DecodeOwned(carrier, RecordDefinitions.Dwd1);
        var coreDefinition = RecordDefinitions.Dwd1 with
        {
            Fields = RecordDefinitions.Dwd1.Fields.Take(16).ToArray(),
            MinimumLength = 857,
            MaximumLength = 857,
            OmittedSigningFieldIndexes = new HashSet<int>()
        };
        var core = CanonicalGrammar.Encode(coreDefinition,
            Enumerable.Range(1, 16).Select(tag => (ReadOnlyMemory<byte>)owned.FieldCopy(tag)).ToArray());
        fields[16] = PublicKeyAuth.SignDetached(
            RawSignatureInput("Deep/Cutover/V1/witness-delegation", core), root.PrivateKey);
        for (var index = 0; index < 4; index++)
        {
            var payload = new byte[889];
            core.CopyTo(payload, 0);
            descriptors.AsSpan(index * 116, 32).CopyTo(payload.AsSpan(857));
            fields[17 + index] = PublicKeyAuth.SignDetached(
                RawSignatureInput("Deep/Cutover/V1/witness-set-successor", payload),
                witnesses[index].PrivateKey);
        }
        return CanonicalGrammar.Encode(RecordDefinitions.Dwd1, fields);
    }

    private static byte[] CreateDwt(
        ReleaseRootRelativeFact terminalRoot,
        WitnessDelegationRelativeFact delegation,
        ReadOnlySpan<byte> krf,
        IReadOnlyList<KeyPair> witnesses,
        ulong issuedAt)
    {
        var fields = MinimumFields(RecordDefinitions.Dwt1);
        fields[0] = delegation.Delegation.NetworkId;
        fields[1] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dwd1, delegation.Delegation.CanonicalBytes.Span));
        fields[2] = U64(delegation.Delegation.WitnessEpoch);
        fields[3] = U64(terminalRoot.CurrentGeneration);
        fields[4] = CanonicalGrammar.EncodeReference(terminalRoot.CurrentTransitionReference);
        fields[5] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Krf1, krf));
        fields[6] = U64(100);
        fields[7] = new byte[] { 3 };
        var rows = new byte[435];
        for (var index = 0; index < 3; index++)
        {
            var row = rows.AsSpan(index * 145, 145);
            delegation.Descriptors[index].WitnessId.Span.CopyTo(row);
            BinaryPrimitives.WriteUInt64BigEndian(row[32..40], 0);
            row[40..72].Fill(checked((byte)(0xb0 + index)));
            row[72] = (byte)DurabilityClass.FsyncReplicated;
            BinaryPrimitives.WriteUInt64BigEndian(row[73..81], issuedAt);
            var payload = new byte[235];
            var offset = 0;
            for (var tag = 0; tag < 7; tag++)
            {
                fields[tag].Span.CopyTo(payload.AsSpan(offset));
                offset += fields[tag].Length;
            }
            row[..81].CopyTo(payload.AsSpan(offset));
            PublicKeyAuth.SignDetached(
                RawSignatureInput("Deep/Cutover/V1/witness-terminal-receipt", payload),
                witnesses[index].PrivateKey).CopyTo(row[81..]);
        }
        fields[8] = rows;
        var quorumPayload = new byte[590];
        var quorumOffset = 0;
        for (var tag = 0; tag < 8; tag++)
        {
            fields[tag].Span.CopyTo(quorumPayload.AsSpan(quorumOffset));
            quorumOffset += fields[tag].Length;
        }
        rows.CopyTo(quorumPayload, quorumOffset);
        fields[9] = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/witness-terminal-quorum", quorumPayload);
        return CanonicalGrammar.Encode(RecordDefinitions.Dwt1, fields);
    }

    private static ReleaseRootAuthorityTuple GenesisAuthorityTuple(
        ReleaseRootRelativeFact root,
        WitnessDelegationRelativeFact delegation)
    {
        var genesisReference = CanonicalGrammar.ComputeReference(
            ArtifactType.Rrm1, root.Manifest.CanonicalBytes.Span);
        var dwdReference = CanonicalGrammar.ComputeReference(
            ArtifactType.Dwd1, delegation.Delegation.CanonicalBytes.Span);
        var checkpointPayload = new byte[78];
        CanonicalGrammar.EncodeReference(genesisReference).CopyTo(checkpointPayload, 0);
        CanonicalGrammar.EncodeReference(dwdReference).CopyTo(checkpointPayload, 40);
        var checkpoint = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/release-root-chain", checkpointPayload);
        var tuple = new byte[282];
        var offset = 0;
        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(tuple.AsSpan(offset));
            offset += value.Length;
        }
        Append(CanonicalGrammar.EncodeReference(genesisReference));
        Append(U64(0));
        Append(root.CurrentEd25519PublicKey.Span);
        Append(CanonicalGrammar.EncodeReference(genesisReference));
        Append(new byte[38]);
        tuple[offset++] = 0;
        tuple[offset++] = 0;
        Append(U64(0));
        Append(CanonicalGrammar.EncodeReference(dwdReference));
        Append(U64(1));
        Append(U16(0));
        Append(checkpoint);
        Append(new byte[38]);
        return new ReleaseRootAuthorityTuple(tuple);
    }

    private static byte[] CreateFreshDcl(
        ReleaseRootRelativeFact root,
        WitnessDelegationRelativeFact delegation,
        IReadOnlyList<KeyPair> witnesses,
        ReleaseRootAuthorityTuple tuple,
        ulong issuedAt,
        ulong expiresAt) =>
        CreateFreshDclForEvidence(root, delegation, witnesses,
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/release-root-authority-head", tuple.CanonicalTuple.Span),
            Enumerable.Repeat((byte)0xc1, 32).ToArray(),
            CanonicalGrammar.EncodeReference(new ArtifactReference(
                ArtifactType.Dcs1, 839, Enumerable.Repeat((byte)0xc4, 32).ToArray())),
            issuedAt, expiresAt);

    internal static byte[] CreateFreshDclForEvidence(
        ReleaseRootRelativeFact root,
        WitnessDelegationRelativeFact delegation,
        IReadOnlyList<KeyPair> witnesses,
        ReadOnlySpan<byte> authorityHead32,
        ReadOnlySpan<byte> deploymentSubject32,
        ReadOnlySpan<byte> exactDcsReference38,
        ulong issuedAt,
        ulong expiresAt)
    {
        if (authorityHead32.Length != 32 || deploymentSubject32.Length != 32 ||
            exactDcsReference38.Length != 38)
            throw new RecordException(RecordError.InvalidLength,
                "The DCL1 evidence axes have invalid widths.");
        var dwdReference = CanonicalGrammar.ComputeReference(
            ArtifactType.Dwd1, delegation.Delegation.CanonicalBytes.Span);
        var dcsReference = exactDcsReference38.ToArray();
        var subject = deploymentSubject32.ToArray();
        var nonce = Enumerable.Repeat((byte)0xc2, 32).ToArray();
        var authorityHead = authorityHead32.ToArray();
        var rows = new List<byte[]>();
        for (var index = 0; index < 3; index++)
        {
            var headFields = MinimumFields(RecordDefinitions.Dhl1);
            headFields[0] = root.Manifest.NetworkId;
            headFields[1] = subject;
            headFields[2] = U64(1);
            headFields[3] = dcsReference;
            headFields[4] = delegation.Delegation.Record.FieldCopy(15);
            headFields[5] = U64(delegation.Delegation.WitnessEpoch);
            headFields[6] = CanonicalGrammar.EncodeReference(dwdReference);
            headFields[7] = U64(root.CurrentGeneration);
            headFields[8] = CanonicalGrammar.EncodeReference(root.CurrentTransitionReference);
            headFields[9] = new byte[38];
            headFields[10] = new byte[] { 0 };
            headFields[11] = authorityHead;
            headFields[12] = delegation.Descriptors[index].WitnessId;
            headFields[13] = U64(0);
            headFields[14] = WitnessTreeVerifier.EmptyRoot(
                delegation.Delegation.WitnessEpoch,
                delegation.Descriptors[index].WitnessId.Span,
                delegation.Delegation.MaximumTreeSize);
            headFields[15] = U64(0);
            headFields[16] = headFields[14];
            headFields[17] = new byte[] { 0 };
            headFields[18] = Array.Empty<byte>();
            headFields[19] = nonce;
            headFields[20] = U64(issuedAt);
            headFields[21] = U64(expiresAt);
            var carrier = CanonicalGrammar.Encode(RecordDefinitions.Dhl1, headFields);
            headFields[22] = PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(
                CanonicalGrammar.DecodeOwned(carrier, RecordDefinitions.Dhl1),
                "Deep/Cutover/V1/head-lease"), witnesses[index].PrivateKey);
            rows.Add(CanonicalGrammar.Encode(RecordDefinitions.Dhl1, headFields));
        }
        var blob = new byte[rows.Sum(static row => 4 + row.Length)];
        var cursor = 0;
        foreach (var row in rows)
        {
            BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(cursor), checked((uint)row.Length));
            cursor += 4;
            row.CopyTo(blob, cursor);
            cursor += row.Length;
        }
        var fields = MinimumFields(RecordDefinitions.Dcl1);
        fields[0] = root.Manifest.NetworkId;
        fields[1] = subject;
        fields[2] = U64(1);
        fields[3] = dcsReference;
        fields[4] = CanonicalGrammar.EncodeReference(dwdReference);
        fields[5] = authorityHead;
        fields[6] = delegation.Delegation.Record.FieldCopy(15);
        fields[7] = U64(delegation.Delegation.WitnessEpoch);
        fields[8] = nonce;
        fields[9] = new byte[] { 3 };
        fields[10] = blob;
        fields[11] = U64(issuedAt);
        fields[12] = U64(expiresAt);
        var digestPayload = new byte[224];
        subject.CopyTo(digestPayload, 0);
        U64(1).CopyTo(digestPayload, 32);
        dcsReference.CopyTo(digestPayload, 40);
        nonce.CopyTo(digestPayload, 78);
        for (var index = 0; index < 3; index++)
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dhl1, rows[index])).CopyTo(digestPayload, 110 + index * 38);
        fields[13] = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/lease-digest", digestPayload);
        return CanonicalGrammar.Encode(RecordDefinitions.Dcl1, fields);
    }

    private static byte[] SubjectPolicy(
        ReadOnlySpan<byte> network,
        ulong checkpointTtl,
        ulong leaseTtl,
        ulong maximumTreeSize)
    {
        var payload = new byte[63];
        network.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(16), 1);
        payload[18] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(19), 15);
        payload[27] = 4;
        for (ushort index = 0; index < 4; index++)
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(28 + index * 2), checked((ushort)(index + 1)));
        payload[36] = 4; payload[37] = 4; payload[38] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(39), checkpointTtl);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(47), leaseTtl);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(55), maximumTreeSize);
        return CanonicalGrammar.Sha256Domain("Deep/Cutover/V1/subject-policy", payload);
    }

    private static byte[] RawSignatureInput(string domain, ReadOnlySpan<byte> payload)
    {
        var domainBytes = Encoding.ASCII.GetBytes(domain);
        var output = new byte[2 + domainBytes.Length + 2 + 4 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(output, checked((ushort)domainBytes.Length));
        domainBytes.CopyTo(output, 2);
        var offset = 2 + domainBytes.Length;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), 1);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 2), checked((uint)payload.Length));
        payload.CopyTo(output.AsSpan(offset + 6));
        return output;
    }

    private static byte[] ExtractUnsignedHash(ReadOnlySpan<byte> signingInput)
    {
        var domainLength = BinaryPrimitives.ReadUInt16BigEndian(signingInput);
        var offset = 2 + domainLength + 2;
        var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(signingInput.Slice(offset, 4)));
        return SHA256.HashData(signingInput.Slice(offset + 4, length));
    }

    private static int FieldOffset(ReadOnlySpan<byte> encoded, int tag)
    {
        var offset = 12;
        for (var current = 1; current <= tag; current++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset + 4, 4)));
            offset += 8;
            if (current == tag) return offset;
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(tag));
    }

    private static byte[] CreateTranscript(
        ReadOnlySpan<byte> holderPublic,
        ReadOnlySpan<byte> issuerPublic,
        ulong issuedAt,
        ulong expiresAt,
        X25519PossessionRole role = X25519PossessionRole.Device)
    {
        var transcript = new byte[X25519PossessionVerifier.TranscriptLength];
        "DXP1"u8.CopyTo(transcript);
        transcript[4] = 1;
        transcript[5] = (byte)role;
        Enumerable.Repeat((byte)0x11, 16).ToArray().CopyTo(transcript, 8);
        Enumerable.Repeat((byte)0x22, 32).ToArray().CopyTo(transcript, 24);
        holderPublic.CopyTo(transcript.AsSpan(56));
        issuerPublic.CopyTo(transcript.AsSpan(88));
        Enumerable.Repeat((byte)0x33, 32).ToArray().CopyTo(transcript, 120);
        BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(152), issuedAt);
        BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(160), expiresAt);
        return transcript;
    }

    private static byte[] CreateDrs(
        AccountFixture fixture,
        VerifiedAccount account,
        IReadOnlyList<byte[]> rows,
        ulong revision,
        ulong issuedAt)
    {
        var fields = MinimumFields(RecordDefinitions.Drs1);
        fields[0] = account.Certificate.NetworkId;
        fields[1] = account.DeepAccountIdHash;
        fields[2] = U64(account.Certificate.AccountGeneration);
        fields[3] = U64(revision);
        fields[4] = U64(issuedAt);
        fields[5] = U64(0);
        fields[6] = new byte[38];
        fields[7] = KeyHash(account, KeyScope.AccountRevocation, fixture.Revocation.PublicKey);
        fields[8] = U16(checked((ushort)rows.Count));
        fields[9] = rows.SelectMany(static row => row).ToArray();
        fields[10] = Head(account, rows);
        var unsigned = CanonicalGrammar.Encode(RecordDefinitions.Drs1, fields);
        var record = CanonicalGrammar.DecodeOwned(unsigned, RecordDefinitions.Drs1);
        fields[11] = PublicKeyAuth.SignDetached(
            CanonicalGrammar.GetSigningBytes(record, "Deep/IdentityAuth/V1/revocation-snapshot"),
            fixture.Revocation.PrivateKey);
        return CanonicalGrammar.Encode(RecordDefinitions.Drs1, fields);
    }

    private static (List<byte[]> Rows, List<RevocationCatalogInput> Catalog)
        CreateMaximumRevocationCatalog(AccountFixture fixture, VerifiedAccount account)
    {
        var rows = new List<byte[]>(1024);
        var catalog = new List<RevocationCatalogInput>(1024);
        for (var index = 0; index < 1023; index++)
        {
            var device = CreateRevocationOnlyDevice(fixture, account, index);
            var target = CreateRevocationTarget(
                account,
                RevocationTargetKind.DeviceCertificate,
                device,
                Deterministic32(0x44, index),
                targetGeneration: 1,
                targetNotAfter: 200);
            rows.Add(CreateRevocationRow(
                RevocationTargetKind.DeviceCertificate,
                target,
                targetGeneration: 1,
                revokedAt: 99,
                RevocationReason.DeviceLost));
            catalog.Add(new RevocationCatalogInput(target, device));
        }

        var terminalTarget = CreateRevocationTarget(
            account,
            RevocationTargetKind.AccountTerminal,
            fixture.AccountCanonical,
            account.Certificate.AccountRevocationHandle.Span,
            account.Certificate.AccountGeneration,
            targetNotAfter: 0);
        rows.Add(CreateRevocationRow(
            RevocationTargetKind.AccountTerminal,
            terminalTarget,
            account.Certificate.AccountGeneration,
            revokedAt: 99,
            RevocationReason.AccountShutdown));
        catalog.Add(new RevocationCatalogInput(terminalTarget, fixture.AccountCanonical));
        return (rows, catalog);
    }

    private static byte[] CreateRevocationOnlyDevice(
        AccountFixture fixture,
        VerifiedAccount account,
        int index)
    {
        var fields = MinimumFields(RecordDefinitions.Dpd1);
        fields[0] = account.Certificate.NetworkId;
        fields[1] = account.DeepAccountIdHash;
        fields[2] = U64(account.Certificate.AccountGeneration);
        fields[3] = Deterministic32(0x40, index);
        fields[4] = U64(1);
        fields[5] = Deterministic32(0x41, index);
        fields[6] = Deterministic32(0x42, index);
        fields[7] = Deterministic32(0x44, index);
        fields[8] = U64(0);
        fields[9] = new byte[38];
        fields[10] = KeyHash(account, KeyScope.DeviceCertificateIssuer,
            fixture.DeviceIssuer.PublicKey);
        fields[11] = U64(1);
        fields[12] = new byte[38];
        fields[13] = U64(0);
        fields[14] = new byte[32];
        fields[15] = U64(50);
        fields[16] = U64(200);
        fields[17] = U64((ulong)DeviceCapabilities.MailboxRoleIssuer);
        fields[18] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
        fields[19] = new byte[38];
        fields[20] = Deterministic32(0x45, index);
        return CanonicalGrammar.Encode(RecordDefinitions.Dpd1, fields);
    }

    private static byte[] CreateRevocationTarget(
        VerifiedAccount account,
        RevocationTargetKind targetKind,
        ReadOnlySpan<byte> certificate,
        ReadOnlySpan<byte> revocationHandle,
        ulong targetGeneration,
        ulong targetNotAfter)
    {
        var artifactType = targetKind switch
        {
            RevocationTargetKind.DeviceCertificate => ArtifactType.Dpd1,
            RevocationTargetKind.MailboxRoleCertificate => ArtifactType.Dpm1,
            RevocationTargetKind.AccountTerminal => ArtifactType.Dpa1,
            _ => throw new ArgumentOutOfRangeException(nameof(targetKind))
        };
        var fields = MinimumFields(RecordDefinitions.Drt1);
        fields[0] = account.DeepAccountIdHash;
        fields[1] = new byte[] { (byte)targetKind };
        fields[2] = revocationHandle.ToArray();
        fields[3] = U64(targetGeneration);
        fields[4] = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(artifactType, certificate));
        fields[5] = U64(targetNotAfter);
        return CanonicalGrammar.Encode(RecordDefinitions.Drt1, fields);
    }

    private static byte[] CreateRevocationRow(
        RevocationTargetKind targetKind,
        ReadOnlySpan<byte> target,
        ulong targetGeneration,
        ulong revokedAt,
        RevocationReason reason)
    {
        var row = new byte[62];
        row[0] = (byte)targetKind;
        CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Drt1, target)).CopyTo(row, 1);
        BinaryPrimitives.WriteUInt64BigEndian(row.AsSpan(39), targetGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(row.AsSpan(47), revokedAt);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(55), (ushort)reason);
        return row;
    }

    private static IReadOnlyList<byte[]> PrefixHeads(
        VerifiedAccount account,
        IReadOnlyList<byte[]> rows)
    {
        var heads = new List<byte[]>(rows.Count + 1) { new byte[32] };
        var payload = new byte[158];
        for (var index = 0; index < rows.Count; index++)
        {
            payload.AsSpan().Clear();
            account.Certificate.NetworkId.Span.CopyTo(payload);
            account.DeepAccountIdHash.Span.CopyTo(payload.AsSpan(16));
            BinaryPrimitives.WriteUInt64BigEndian(
                payload.AsSpan(48), account.Certificate.AccountGeneration);
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(56), checked((ulong)index));
            heads[^1].CopyTo(payload, 64);
            rows[index].CopyTo(payload, 96);
            heads.Add(CanonicalGrammar.Sha256Domain(
                "Deep/IdentityAuth/V1/revocation-entry-head", payload));
        }
        return heads;
    }

    private static byte[] Deterministic32(byte domain, int index)
    {
        Span<byte> seed = stackalloc byte[5];
        seed[0] = domain;
        BinaryPrimitives.WriteInt32BigEndian(seed[1..], index);
        return SHA256.HashData(seed);
    }

    private static byte[] Head(VerifiedAccount account, IReadOnlyList<byte[]> rows)
    {
        var previous = new byte[32];
        var payload = new byte[158];
        for (var index = 0; index < rows.Count; index++)
        {
            account.Certificate.NetworkId.Span.CopyTo(payload);
            account.DeepAccountIdHash.Span.CopyTo(payload.AsSpan(16));
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(48), account.Certificate.AccountGeneration);
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(56), checked((ulong)index));
            previous.CopyTo(payload, 64);
            rows[index].CopyTo(payload, 96);
            previous = CanonicalGrammar.Sha256Domain(
                "Deep/IdentityAuth/V1/revocation-entry-head",
                payload);
        }
        return previous;
    }

    private static byte[] KeyHash(
        VerifiedAccount account,
        KeyScope scope,
        ReadOnlySpan<byte> publicKey)
    {
        Span<byte> payload = stackalloc byte[89];
        account.Certificate.NetworkId.Span.CopyTo(payload);
        payload[16] = (byte)scope;
        account.DeepAccountIdHash.Span.CopyTo(payload[17..]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[49..], account.Certificate.AccountGeneration);
        publicKey.CopyTo(payload[57..]);
        return CanonicalGrammar.Sha256Domain("Deep/IdentityAuth/V1/key-hash", payload);
    }

    private static ReadOnlyMemory<byte>[] MinimumFields(RecordDefinition definition) =>
        definition.Fields.Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private sealed class AccountFixture
    {
        private AccountFixture(byte[] accountCanonical, KeyPair deviceIssuer, KeyPair revocation)
        {
            AccountCanonical = accountCanonical;
            DeviceIssuer = deviceIssuer;
            Revocation = revocation;
        }

        internal byte[] AccountCanonical { get; }
        internal KeyPair DeviceIssuer { get; }
        internal KeyPair Revocation { get; }

        internal static AccountFixture Create()
        {
            var keys = Enumerable.Range(0, 4).Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
            var fields = MinimumFields(RecordDefinitions.Dpa1);
            fields[0] = Enumerable.Repeat((byte)0x11, 16).ToArray();
            fields[1] = U64(1);
            fields[2] = U64(1);
            fields[4] = keys[0].PublicKey;
            fields[5] = keys[1].PublicKey;
            fields[6] = keys[2].PublicKey;
            fields[7] = keys[3].PublicKey;
            fields[8] = Enumerable.Repeat((byte)0x44, 32).ToArray();
            fields[9] = U64(50);
            fields[10] = U64(1);
            fields[11] = U16(1);
            var carrier = CanonicalGrammar.Encode(RecordDefinitions.Dpa1, fields);
            var signing = CanonicalGrammar.GetSigningBytes(
                CanonicalGrammar.DecodeOwned(carrier, RecordDefinitions.Dpa1),
                "Deep/IdentityAuth/V1/account-certificate");
            for (var index = 0; index < 4; index++)
                fields[12 + index] = PublicKeyAuth.SignDetached(signing, keys[index].PrivateKey);
            return new AccountFixture(
                CanonicalGrammar.Encode(RecordDefinitions.Dpa1, fields),
                keys[1],
                keys[2]);
        }
    }

    private sealed class TestHmacProvider : IProtectedHmacProvider
    {
        private readonly byte[] _key;

        internal TestHmacProvider(ReadOnlySpan<byte> key)
        {
            _key = key.ToArray();
        }

        internal int Calls { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            var domain = Encoding.ASCII.GetBytes(request.Domain);
            var input = new byte[2 + domain.Length + 2 + 4 + request.UnsignedCanonical.Length];
            BinaryPrimitives.WriteUInt16BigEndian(input, checked((ushort)domain.Length));
            domain.CopyTo(input, 2);
            var offset = 2 + domain.Length;
            BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset), request.Suite);
            BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(offset + 2),
                checked((uint)request.UnsignedCanonical.Length));
            request.UnsignedCanonical.Span.CopyTo(input.AsSpan(offset + 6));
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(HMACSHA256.HashData(_key, input));
        }
    }
}
