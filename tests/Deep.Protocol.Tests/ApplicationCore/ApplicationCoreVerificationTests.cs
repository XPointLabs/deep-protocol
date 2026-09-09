using System.Buffers.Binary;
using System.Reflection;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class ApplicationCoreVerificationTests
{
    [Fact]
    public void PublicDecoders_ReturnExplicitParsedTypes_AndDmc2PayloadIsNotAuthoritative()
    {
        var decoders = typeof(ApplicationCoreCodec).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(method => method.Name.StartsWith("Decode", StringComparison.Ordinal))
            .Where(method => method.Name is "DecodeDid1" or "DecodeDeepIdText" or "DecodeDab1" or
                "DecodeDmd1" or "DecodeDca1" or "DecodeDao1" or "DecodeDmc2")
            .ToArray();

        Assert.NotEmpty(decoders);
        Assert.All(decoders, method => Assert.StartsWith("Parsed", method.ReturnType.Name));
        Assert.Null(typeof(ParsedDmc2).GetProperty("Payload", BindingFlags.Public | BindingFlags.Instance));
        Assert.NotNull(typeof(VerifiedDmc2).GetProperty("Payload", BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(VerifiedDab1).GetConstructors());
        Assert.Empty(typeof(VerifiedDmd1).GetConstructors());
        Assert.Empty(typeof(VerifiedDca1).GetConstructors());
        Assert.Empty(typeof(VerifiedDmc2).GetConstructors());
        Assert.Empty(typeof(VerifiedDpe2Envelope).GetConstructors());
        Assert.Empty(typeof(Dpe2AuthenticationOutput).GetConstructors());
    }

    [Fact]
    public void Verifier_ClosesDpaDrsDpdAndAllApplicationSignatures()
    {
        var fixture = VerifiedFixture.Create();
        var binding = fixture.AuthorAndVerifyDab1(0, new byte[32]);
        var directory = fixture.AuthorAndVerifyDmd1(1, new byte[32]);
        var authorization = fixture.AuthorAndVerifyDca1(binding, directory);

        Assert.Same(fixture.Identity, binding.Identity);
        Assert.Same(fixture.Identity, directory.Identity);
        Assert.Same(binding, authorization.Binding);
        Assert.Same(directory, authorization.Directory);
    }

    [Fact]
    public void Verifier_RejectsSignatureAndExactClosureSubstitutions()
    {
        var fixture = VerifiedFixture.Create();
        var binding = fixture.AuthorAndVerifyDab1(0, new byte[32]);
        var directory = fixture.AuthorAndVerifyDmd1(1, new byte[32]);

        var badBindingBytes = binding.Record.CanonicalBytes.ToArray();
        badBindingBytes[ApplicationCoreFixture.FieldOffset(badBindingBytes, 8)] ^= 0x01;
        var badBinding = ApplicationCoreCodec.DecodeDab1(badBindingBytes);
        AssertVerificationFailure(() => ApplicationCoreVerifier.VerifyDab1(
            badBinding, fixture.DeepId, fixture.Identity, VerifiedFixture.DeploymentProfileId));

        var emptyClosure = ApplicationCoreVerifier.CreateIdentityClosure(
            fixture.Account, fixture.Revocations, []);
        AssertVerificationFailure(() => ApplicationCoreVerifier.VerifyDmd1(directory.Record, emptyClosure));

        var wrongPublisher = ApplicationCoreFixture.Bytes(32, 0xee);
        var badAuthorization = fixture.AuthorDca1(binding, directory, wrongPublisher);
        AssertVerificationFailure(() => ApplicationCoreVerifier.VerifyDca1(
            badAuthorization, binding, directory));
    }

    [Fact]
    public void Dab1Lineage_EnforcesSuccessorReplayAndPermanentForkLatch()
    {
        var fixture = VerifiedFixture.Create();
        var genesis = fixture.AuthorAndVerifyDab1(0, new byte[32]);
        var started = ApplicationCoreVerifier.StartDab1Lineage(genesis);
        var successor = fixture.AuthorAndVerifyDab1(1, genesis.Record.RecordHash.Span);
        var accepted = ApplicationCoreVerifier.PrepareDab1Transition(started.Next, successor);

        Assert.Equal(ApplicationLineageDisposition.AcceptedSuccessor, accepted.Disposition);
        Assert.Equal(ApplicationLineageDisposition.ExactReplay,
            ApplicationCoreVerifier.PrepareDab1Transition(accepted.Next, successor).Disposition);

        var alternate = VerifiedFixture.Create(fixture.AddressKey, accountValue: 0x91, deviceValue: 0x92);
        var conflicting = alternate.AuthorAndVerifyDab1(1, genesis.Record.RecordHash.Span);
        var fork = ApplicationCoreVerifier.PrepareDab1Transition(accepted.Next, conflicting);
        Assert.Equal(ApplicationLineageDisposition.ForkLatched, fork.Disposition);
        Assert.True(fork.Next.ForkLatched);
        Assert.Equal(ApplicationCoreRejection.InvalidLineage,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                ApplicationCoreVerifier.PrepareDab1Transition(fork.Next, successor)).Rejection);
    }

    [Fact]
    public void Dab1Lineage_RejectsCrossDidSuccessorAndSameGenerationFork()
    {
        var owner = VerifiedFixture.Create();
        var genesis = owner.AuthorAndVerifyDab1(0, new byte[32]);
        var ownerSuccessor = owner.AuthorAndVerifyDab1(1, genesis.Record.RecordHash.Span);
        var otherDid = VerifiedFixture.Create(accountValue: 0x91, deviceValue: 0x92);
        var crossDidSuccessor = otherDid.AuthorAndVerifyDab1(1, genesis.Record.RecordHash.Span);

        var started = ApplicationCoreVerifier.StartDab1Lineage(genesis);
        AssertLineageFailure(() =>
            ApplicationCoreVerifier.PrepareDab1Transition(started.Next, crossDidSuccessor));

        var accepted = ApplicationCoreVerifier.PrepareDab1Transition(started.Next, ownerSuccessor);
        var crossDidSameGeneration = otherDid.AuthorAndVerifyDab1(
            ownerSuccessor.Record.BindingGeneration,
            ownerSuccessor.Record.PredecessorDab1Hash.Span);
        AssertLineageFailure(() =>
            ApplicationCoreVerifier.PrepareDab1Transition(accepted.Next, crossDidSameGeneration));
    }

    [Fact]
    public void Dab1Lineage_MaxGenerationRejectsCanonicallyWithoutOverflow()
    {
        var fixture = VerifiedFixture.Create();
        var maxHead = fixture.AuthorAndVerifyDab1(ulong.MaxValue, ApplicationCoreFixture.Bytes(32, 0x71));
        var wrappedCandidate = fixture.AuthorAndVerifyDab1(0, new byte[32]);
        var state = new Dab1LineageState(maxHead, forkLatched: false);

        AssertLineageFailure(() =>
            ApplicationCoreVerifier.PrepareDab1Transition(state, wrappedCandidate));
    }

    [Fact]
    public void Dmd1Lineage_EnforcesSuccessorReplayAndPermanentForkLatch()
    {
        var fixture = VerifiedFixture.Create();
        var genesis = fixture.AuthorAndVerifyDmd1(1, new byte[32]);
        var started = ApplicationCoreVerifier.StartDmd1Lineage(genesis);
        var successor = fixture.AuthorAndVerifyDmd1(2, genesis.Record.RecordHash.Span);
        var accepted = ApplicationCoreVerifier.PrepareDmd1Transition(started.Next, successor);

        Assert.Equal(ApplicationLineageDisposition.AcceptedSuccessor, accepted.Disposition);
        Assert.Equal(ApplicationLineageDisposition.ExactReplay,
            ApplicationCoreVerifier.PrepareDmd1Transition(accepted.Next, successor).Disposition);

        var conflicting = fixture.AuthorAndVerifyDmd1(
            2, genesis.Record.RecordHash.Span, issuedAt: 101);
        var fork = ApplicationCoreVerifier.PrepareDmd1Transition(accepted.Next, conflicting);
        Assert.Equal(ApplicationLineageDisposition.ForkLatched, fork.Disposition);
        Assert.True(fork.Next.ForkLatched);
        Assert.Equal(ApplicationCoreRejection.InvalidLineage,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                ApplicationCoreVerifier.PrepareDmd1Transition(fork.Next, successor)).Rejection);
    }

    [Fact]
    public void VerifiedDmc2_RequiresExactAuthenticatedOuterAndRatchetContext()
    {
        var parsed = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateMessageCreatePayload("authenticated"));
        using var exact = ApplicationCoreFixture.VerifiedEnvelope(parsed);
        var verified = ApplicationCoreVerifier.VerifyDmc2(exact);

        Assert.Equal("authenticated", Assert.IsType<MessageCreateDmc2Payload>(verified.Payload).Text);
        var substitutions = new[]
        {
            ApplicationCoreFixture.VerifiedEnvelope(parsed,
                authenticatedNetwork: ApplicationCoreFixture.Bytes(16, 0xa1),
                envelopeNetwork: ApplicationCoreFixture.Bytes(16, 0xa1)),
            ApplicationCoreFixture.VerifiedEnvelope(parsed,
                authenticatedAccount: ApplicationCoreFixture.Bytes(32, 0xa2)),
            ApplicationCoreFixture.VerifiedEnvelope(parsed,
                authenticatedDevice: ApplicationCoreFixture.Bytes(32, 0xa3),
                envelopeDevice: ApplicationCoreFixture.Bytes(32, 0xa3)),
            ApplicationCoreFixture.VerifiedEnvelope(parsed,
                authenticatedConversation: ApplicationCoreFixture.Bytes(32, 0xa4)),
        };
        foreach (var substitution in substitutions)
        {
            using (substitution)
                AssertVerificationFailure(() => ApplicationCoreVerifier.VerifyDmc2(substitution));
        }
    }

    [Fact]
    public void Dca1_CurrentAuthorityRequiresTrustedTimeInsideHalfOpenWindow()
    {
        var fixture = VerifiedFixture.Create();
        var binding = fixture.AuthorAndVerifyDab1(0, new byte[32]);
        var directory = fixture.AuthorAndVerifyDmd1(1, new byte[32]);
        var verified = fixture.AuthorAndVerifyDca1(binding, directory);

        Assert.Equal(10UL,
            ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(verified, 10).TrustedUnixSeconds);
        Assert.Equal(19UL,
            ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(verified, 19).TrustedUnixSeconds);
        AssertVerificationFailure(() =>
            ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(verified, 9));
        AssertVerificationFailure(() =>
            ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(verified, 20));
    }

    private static void AssertLineageFailure(Action action)
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(action);
        Assert.Equal(ApplicationCoreValidationStage.CryptographicVerification, exception.Stage);
        Assert.Equal(ApplicationCoreRejection.InvalidLineage, exception.Rejection);
    }

    private static void AssertVerificationFailure(Action action)
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(action);
        Assert.Equal(ApplicationCoreValidationStage.CryptographicVerification, exception.Stage);
        Assert.Equal(ApplicationCoreRejection.VerificationFailed, exception.Rejection);
    }

    private sealed class VerifiedFixture
    {
        private VerifiedFixture(
            byte[] network,
            byte[] accountId,
            byte[] deviceId,
            KeyPair addressKey,
            KeyPair accountKey,
            KeyPair deviceIssuerKey,
            VerifiedAccount account,
            VerifiedRevocationState revocations,
            VerifiedApplicationIdentityClosure identity,
            ParsedDid1 deepId)
        {
            Network = network;
            AccountId = accountId;
            DeviceId = deviceId;
            AddressKey = addressKey;
            AccountKey = accountKey;
            DeviceIssuerKey = deviceIssuerKey;
            Account = account;
            Revocations = revocations;
            Identity = identity;
            DeepId = deepId;
        }

        internal const ushort DeploymentProfileId = 7;
        internal byte[] Network { get; }
        internal byte[] AccountId { get; }
        internal byte[] DeviceId { get; }
        internal KeyPair AddressKey { get; }
        internal KeyPair AccountKey { get; }
        internal KeyPair DeviceIssuerKey { get; }
        internal VerifiedAccount Account { get; }
        internal VerifiedRevocationState Revocations { get; }
        internal VerifiedApplicationIdentityClosure Identity { get; }
        internal ParsedDid1 DeepId { get; }

        internal static VerifiedFixture Create(
            KeyPair? existingAddressKey = null,
            byte accountValue = 0x22,
            byte deviceValue = 0x33)
        {
            var network = ApplicationCoreFixture.Bytes(16, 0x11);
            var accountId = ApplicationCoreFixture.Bytes(32, accountValue);
            var deviceId = ApplicationCoreFixture.Bytes(32, deviceValue);
            var addressKey = existingAddressKey ?? PublicKeyAuth.GenerateKeyPair();
            var accountKey = PublicKeyAuth.GenerateKeyPair();
            var deviceIssuerKey = PublicKeyAuth.GenerateKeyPair();
            var revocationKey = PublicKeyAuth.GenerateKeyPair();
            var resetKey = PublicKeyAuth.GenerateKeyPair();

            var dpaFields = MinimumFields(RecordDefinitions.Dpa1);
            dpaFields[0] = network;
            dpaFields[1] = U64(1);
            dpaFields[2] = U64(1);
            dpaFields[4] = accountKey.PublicKey;
            dpaFields[5] = deviceIssuerKey.PublicKey;
            dpaFields[6] = revocationKey.PublicKey;
            dpaFields[7] = resetKey.PublicKey;
            dpaFields[8] = ApplicationCoreFixture.Bytes(32, 0x44);
            dpaFields[9] = U64(100);
            dpaFields[10] = U64(1);
            dpaFields[11] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
            var certificate = IdentityCodec.DecodeAccountCertificate(
                CanonicalGrammar.Encode(RecordDefinitions.Dpa1, dpaFields));
            var account = new VerifiedAccount(certificate, accountId);
            var drs = ApplicationCoreFixture.Revocations(network, accountId);
            var revocations = new VerifiedRevocationState(account, drs, new RevocationCatalog([]));

            var deviceEd = PublicKeyAuth.GenerateKeyPair();
            var dpdFields = MinimumFields(RecordDefinitions.Dpd1);
            dpdFields[0] = network;
            dpdFields[1] = accountId;
            dpdFields[2] = U64(1);
            dpdFields[3] = deviceId;
            dpdFields[4] = U64(1);
            dpdFields[5] = deviceEd.PublicKey;
            dpdFields[6] = ApplicationCoreFixture.Bytes(32, 0x51);
            dpdFields[7] = ApplicationCoreFixture.Bytes(32, 0x52);
            dpdFields[8] = U64(1);
            dpdFields[10] = ApplicationCoreFixture.Bytes(32, 0x53);
            dpdFields[11] = U64(1);
            dpdFields[13] = U64(0);
            dpdFields[14] = ApplicationCoreFixture.Bytes(32, 0x54);
            dpdFields[15] = U64(100);
            dpdFields[16] = U64(1_000);
            dpdFields[17] = U64((ulong)DeviceCapabilities.MailboxRoleIssuer);
            dpdFields[18] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
            dpdFields[20] = ApplicationCoreFixture.Bytes(32, 0x55);
            var certificateDevice = IdentityCodec.DecodeDeviceCertificate(
                CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpdFields));
            var device = new VerifiedDevice(certificateDevice, revocations,
                new X25519Possession(X25519PossessionRole.Device, dpdFields[20].Span));
            var identity = ApplicationCoreVerifier.CreateIdentityClosure(account, revocations, [device]);
            var deepId = ApplicationCoreCodec.AuthorDid1(addressKey.PublicKey,
                ApplicationCoreFixture.Bytes(16, 0x66));
            return new VerifiedFixture(network, accountId, deviceId, addressKey, accountKey,
                deviceIssuerKey, account, revocations, identity, deepId);
        }

        internal VerifiedDab1 AuthorAndVerifyDab1(
            ulong generation,
            ReadOnlySpan<byte> predecessor)
        {
            var realm = ApplicationCoreCodec.DeriveIdentityRealmId(Network, DeploymentProfileId);
            var dpa = Ref(Account.Certificate);
            var unsigned = ApplicationCoreCodec.AuthorDab1(DeepId.RecordHash.Span, realm.Span,
                generation, predecessor, AccountId, 1, dpa, new byte[64], new byte[64]);
            var addressSignature = PublicKeyAuth.SignDetached(
                unsigned.AddressSignatureInput.ToArray(), AddressKey.PrivateKey);
            var accountSignature = PublicKeyAuth.SignDetached(
                unsigned.AccountSignatureInput.ToArray(), AccountKey.PrivateKey);
            var parsed = ApplicationCoreCodec.AuthorDab1(DeepId.RecordHash.Span, realm.Span,
                generation, predecessor, AccountId, 1, dpa, addressSignature, accountSignature);
            return ApplicationCoreVerifier.VerifyDab1(parsed, DeepId, Identity, DeploymentProfileId);
        }

        internal VerifiedDmd1 AuthorAndVerifyDmd1(
            ulong generation,
            ReadOnlySpan<byte> predecessor,
            ulong issuedAt = 100)
        {
            var entry = new DeviceDirectoryEntry(DeviceId, Ref(Identity.ActiveDevices[0].Certificate));
            var unsigned = ApplicationCoreCodec.AuthorDmd1(Network, AccountId, 1,
                Ref(Account.Certificate), Ref(Revocations.Snapshot), generation, predecessor,
                [entry], issuedAt, new byte[64]);
            var signature = PublicKeyAuth.SignDetached(
                unsigned.SignatureInput.ToArray(), DeviceIssuerKey.PrivateKey);
            var parsed = ApplicationCoreCodec.AuthorDmd1(Network, AccountId, 1,
                Ref(Account.Certificate), Ref(Revocations.Snapshot), generation, predecessor,
                [entry], issuedAt, signature);
            return ApplicationCoreVerifier.VerifyDmd1(parsed, Identity);
        }

        internal VerifiedDca1 AuthorAndVerifyDca1(VerifiedDab1 binding, VerifiedDmd1 directory) =>
            ApplicationCoreVerifier.VerifyDca1(
                AuthorDca1(binding, directory, DeviceId), binding, directory);

        internal ParsedDca1 AuthorDca1(
            VerifiedDab1 binding,
            VerifiedDmd1 directory,
            ReadOnlySpan<byte> publisher)
        {
            var dabReference = ApplicationCoreCodec.CreateArtifactReference(
                ApplicationCoreCodec.Dab1ArtifactTypeCode,
                checked((uint)binding.Record.CanonicalBytes.Length),
                binding.Record.RecordHash.Span);
            var unsigned = ApplicationCoreCodec.AuthorDca1(Network, AccountId, Ref(Account.Certificate),
                directory.Record.DirectoryGeneration, directory.Record.RecordHash.Span,
                ApplicationCoreFixture.Bytes(32, 0x77), publisher, 3, 100, 10, 20,
                new byte[64], DeepId.RecordHash.Span, dabReference);
            var signature = PublicKeyAuth.SignDetached(
                unsigned.SignatureInput.ToArray(), AccountKey.PrivateKey);
            return ApplicationCoreCodec.AuthorDca1(Network, AccountId, Ref(Account.Certificate),
                directory.Record.DirectoryGeneration, directory.Record.RecordHash.Span,
                ApplicationCoreFixture.Bytes(32, 0x77), publisher, 3, 100, 10, 20,
                signature, DeepId.RecordHash.Span, dabReference);
        }

        private static ApplicationArtifactReference Ref(CanonicalIdentityArtifact artifact) =>
            ApplicationCoreCodec.CreateArtifactReference((ushort)artifact.ArtifactType,
                checked((uint)artifact.CanonicalBytes.Length), artifact.CanonicalHash.Span);

        private static ReadOnlyMemory<byte>[] MinimumFields(RecordDefinition definition) =>
            definition.Fields.Select(field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

        private static byte[] U64(ulong value)
        {
            var bytes = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
            return bytes;
        }

        private static byte[] U16(ushort value)
        {
            var bytes = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
            return bytes;
        }
    }
}
