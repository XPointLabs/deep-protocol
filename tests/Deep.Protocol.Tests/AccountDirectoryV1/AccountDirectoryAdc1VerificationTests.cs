using System.Buffers.Binary;
using System.Reflection;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Tests.ApplicationCore;
using Sodium;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryAdc1VerificationTests
{
    [Fact]
    public void Capability_IsNonForgeable_AndVerifierHasNoCallerSignatureCallback()
    {
        Assert.Empty(typeof(VerifiedAccountDirectoryCheckpoint).GetConstructors());
        var verify = Assert.Single(typeof(AccountDirectoryAdc1Verifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static), method => method.Name == nameof(AccountDirectoryAdc1Verifier.Verify));
        Assert.DoesNotContain(verify.GetParameters(), parameter =>
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType) ||
            parameter.ParameterType.Name.Contains("Callback", StringComparison.Ordinal) ||
            parameter.ParameterType.Name.Contains("SignatureVerifier", StringComparison.Ordinal));
    }

    [Fact]
    public void Verify_ClosesExactIdentityAndReturnsDefensiveRevocationCapability()
    {
        var fixture = Fixture.Create();
        var revokedA = Bytes(32, 0x10);
        var revokedB = Bytes(32, 0x20);
        ReadOnlyMemory<byte>[] revoked = [revokedA, revokedB];
        var checkpoint = fixture.CreateCheckpoint(revoked);

        var verified = AccountDirectoryAdc1Verifier.Verify(
            checkpoint, fixture.Binding, fixture.Directory, revoked, supportedReader: 1);

        Assert.Same(checkpoint, verified.Checkpoint);
        Assert.Same(fixture.Binding, verified.Binding);
        Assert.Same(fixture.Directory, verified.Directory);
        Assert.Equal(2, verified.RevokedDcaAuthorizationCount);
        Assert.True(verified.IsDcaAuthorizationRevoked(Bytes(32, 0x10)));
        Assert.False(verified.IsDcaAuthorizationRevoked(Bytes(32, 0x30)));
        revokedA[0] ^= 0xff;
        revokedB.AsSpan().Clear();
        Assert.True(verified.IsDcaAuthorizationRevoked(Bytes(32, 0x10)));
        Assert.True(verified.IsDcaAuthorizationRevoked(Bytes(32, 0x20)));
        Assert.Throws<ArgumentException>(() => verified.IsDcaAuthorizationRevoked(new byte[32]));
    }

    [Fact]
    public void Verify_RejectsWrongIdentityDidNetworkAndAccountGeneration()
    {
        var fixture = Fixture.Create();
        var revoked = Revoked();
        var checkpoint = fixture.CreateCheckpoint(revoked);
        var other = Fixture.Create(0x42);
        var otherAddressKey = PublicKeyAuth.GenerateKeyPair();
        var otherDid = fixture.CreateBinding(
            ApplicationCoreCodec.AuthorDid1(otherAddressKey.PublicKey, Bytes(16, 0x68)),
            otherAddressKey);

        Reject(checkpoint, other.Binding, fixture.Directory, revoked, 1);
        Reject(checkpoint, fixture.Binding, other.Directory, revoked, 1);
        Reject(checkpoint, otherDid, fixture.Directory, revoked, 1);
        Reject(fixture.CreateCheckpoint(revoked, network: Bytes(16, 0x44)),
            fixture.Binding, fixture.Directory, revoked, 1);
        Reject(fixture.CreateCheckpoint(revoked, accountGeneration: 2),
            fixture.Binding, fixture.Directory, revoked, 1);
    }

    [Fact]
    public void Verify_RejectsWrongLeafReferencesRecordHashesAndSignature()
    {
        var fixture = Fixture.Create();
        var revoked = Revoked();
        var expectedDpa = fixture.ExactDpaReference();
        var expectedDrs = fixture.ExactDrsReference();
        var wrongDpa = expectedDpa.ToArray(); wrongDpa[^1] ^= 1;
        var wrongDrs = expectedDrs.ToArray(); wrongDrs[^1] ^= 1;

        Reject(fixture.CreateCheckpoint(revoked, leaf: Bytes(32, 0x45)), fixture.Binding, fixture.Directory, revoked, 1);
        Reject(fixture.CreateCheckpoint(revoked, dpaReference: wrongDpa), fixture.Binding, fixture.Directory, revoked, 1);
        Reject(fixture.CreateCheckpoint(revoked, drsReference: wrongDrs), fixture.Binding, fixture.Directory, revoked, 1);
        Reject(fixture.CreateCheckpoint(revoked, dmdHash: Bytes(32, 0x46)), fixture.Binding, fixture.Directory, revoked, 1);
        Reject(fixture.CreateCheckpoint(revoked, dabHash: Bytes(32, 0x47)), fixture.Binding, fixture.Directory, revoked, 1);

        var signed = fixture.CreateCheckpoint(revoked);
        var signature = signed.DeviceIssuerSignature.ToArray(); signature[0] ^= 1;
        var invalidSignature = Clone(signed, signature);
        Reject(invalidSignature, fixture.Binding, fixture.Directory, revoked, 1);
    }

    [Fact]
    public void Verify_RejectsHostileRevocationListsAndUnsupportedReader()
    {
        var fixture = Fixture.Create();
        var revoked = Revoked();
        var checkpoint = fixture.CreateCheckpoint(revoked);

        Reject(checkpoint, fixture.Binding, fixture.Directory, [Bytes(32, 0x11)], 1);
        Reject(checkpoint, fixture.Binding, fixture.Directory, [Bytes(32, 0x20), Bytes(32, 0x10)], 1);
        Reject(checkpoint, fixture.Binding, fixture.Directory, [Bytes(32, 0x10), Bytes(32, 0x10)], 1);
        Reject(checkpoint, fixture.Binding, fixture.Directory, [new byte[32]], 1);
        Reject(checkpoint, fixture.Binding, fixture.Directory, [Bytes(31, 0x10)], 1);
        var tooMany = Enumerable.Range(0, AccountDirectoryAdc1Verifier.MaximumRevokedDcaAuthorizationIds + 1)
            .Select(index => (ReadOnlyMemory<byte>)Id(index + 1)).ToArray();
        Reject(checkpoint, fixture.Binding, fixture.Directory, tooMany, 1);
        Reject(checkpoint, fixture.Binding, fixture.Directory, revoked, 0);
        Reject(fixture.CreateCheckpoint(revoked, minimumReader: 2),
            fixture.Binding, fixture.Directory, revoked, 1);

        ReadOnlyMemory<byte>[] empty = [];
        var emptyCheckpoint = fixture.CreateCheckpoint(empty);
        var verifiedEmpty = AccountDirectoryAdc1Verifier.Verify(
            emptyCheckpoint, fixture.Binding, fixture.Directory, empty, 1);
        Assert.Equal(0, verifiedEmpty.RevokedDcaAuthorizationCount);
        Assert.NotEqual(new byte[32], emptyCheckpoint.RevokedDcaAuthorizationIdsHash.ToArray());
    }

    private static void Reject(
        AccountDirectoryAdc1 checkpoint,
        VerifiedDab1 binding,
        VerifiedDmd1 directory,
        IReadOnlyList<ReadOnlyMemory<byte>> revoked,
        ushort supportedReader) =>
        Assert.Throws<AccountDirectoryAdc1VerificationException>(() =>
            AccountDirectoryAdc1Verifier.Verify(checkpoint, binding, directory, revoked, supportedReader));

    private static ReadOnlyMemory<byte>[] Revoked() => [Bytes(32, 0x10), Bytes(32, 0x20)];

    private static byte[] Id(int value)
    {
        var result = new byte[32];
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(28), value);
        return result;
    }

    private static AccountDirectoryAdc1 Clone(AccountDirectoryAdc1 source, byte[] signature) => new(
        source.NetworkId.Span, source.DirectoryLeafKey.Span, source.AccountGeneration,
        source.CheckpointGeneration, source.PredecessorCheckpointHash.Span,
        source.ExactDpa1Reference.Span, source.ExactDrs1Reference.Span,
        source.ExactDmd1Hash.Span, source.ExactDab1Hash.Span,
        source.RevokedDcaAuthorizationIdsHash.Span, source.IssuedAt,
        source.MinimumReader, signature);

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    internal sealed class Fixture
    {
        private Fixture(
            byte[] network,
            byte[] accountId,
            KeyPair addressKey,
            KeyPair accountKey,
            KeyPair deviceIssuerKey,
            VerifiedAccount account,
            VerifiedRevocationState revocations,
            VerifiedApplicationIdentityClosure identity,
            ParsedDid1 deepId,
            VerifiedDab1 binding,
            VerifiedDmd1 directory)
        {
            Network = network;
            AccountId = accountId;
            AddressKey = addressKey;
            AccountKey = accountKey;
            DeviceIssuerKey = deviceIssuerKey;
            Account = account;
            Revocations = revocations;
            Identity = identity;
            DeepId = deepId;
            Binding = binding;
            Directory = directory;
        }

        internal byte[] Network { get; }
        internal byte[] AccountId { get; }
        internal KeyPair AddressKey { get; }
        internal KeyPair AccountKey { get; }
        internal KeyPair DeviceIssuerKey { get; }
        internal VerifiedAccount Account { get; }
        internal VerifiedRevocationState Revocations { get; }
        internal VerifiedApplicationIdentityClosure Identity { get; }
        internal ParsedDid1 DeepId { get; }
        internal VerifiedDab1 Binding { get; }
        internal VerifiedDmd1 Directory { get; }

        internal static Fixture Create(byte accountValue = 0x22)
        {
            var network = Bytes(16, 0x11);
            var accountId = Bytes(32, accountValue);
            var deviceId = Bytes(32, 0x33);
            var addressKey = PublicKeyAuth.GenerateKeyPair();
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
            dpaFields[8] = Bytes(32, 0x44);
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
            dpdFields[6] = Bytes(32, 0x51);
            dpdFields[7] = Bytes(32, 0x52);
            dpdFields[8] = U64(1);
            dpdFields[10] = Bytes(32, 0x53);
            dpdFields[11] = U64(drs.Revision);
            dpdFields[12] = Ref(drs).CanonicalBytes;
            dpdFields[13] = U64(drs.EntryCount);
            dpdFields[14] = drs.CurrentHead;
            dpdFields[15] = U64(100);
            dpdFields[16] = U64(1_000);
            dpdFields[17] = U64((ulong)DeviceCapabilities.MailboxRoleIssuer);
            dpdFields[18] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
            dpdFields[20] = Bytes(32, 0x55);
            var deviceCertificate = IdentityCodec.DecodeDeviceCertificate(
                CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpdFields));
            var device = new VerifiedDevice(deviceCertificate, revocations,
                new X25519Possession(X25519PossessionRole.Device, dpdFields[20].Span));
            var identity = ApplicationCoreVerifier.CreateIdentityClosure(account, revocations, [device]);
            var deepId = ApplicationCoreCodec.AuthorDid1(addressKey.PublicKey, Bytes(16, 0x66));
            var fixture = new Fixture(network, accountId, addressKey, accountKey, deviceIssuerKey,
                account, revocations, identity, deepId, null!, null!);
            var binding = fixture.CreateBinding(deepId, addressKey);
            var directory = fixture.CreateDirectory(deviceId, deviceCertificate);
            return new Fixture(network, accountId, addressKey, accountKey, deviceIssuerKey,
                account, revocations, identity, deepId, binding, directory);
        }

        internal VerifiedDab1 CreateBinding(ParsedDid1 deepId, KeyPair addressKey)
        {
            var realm = ApplicationCoreCodec.DeriveIdentityRealmId(Network, 7);
            var dpa = Ref(Account.Certificate);
            var unsigned = ApplicationCoreCodec.AuthorDab1(deepId.RecordHash.Span, realm.Span,
                0, new byte[32], AccountId, 1, dpa, new byte[64], new byte[64]);
            var addressSignature = PublicKeyAuth.SignDetached(
                unsigned.AddressSignatureInput.ToArray(), addressKey.PrivateKey);
            var accountSignature = PublicKeyAuth.SignDetached(
                unsigned.AccountSignatureInput.ToArray(), AccountKey.PrivateKey);
            var parsed = ApplicationCoreCodec.AuthorDab1(deepId.RecordHash.Span, realm.Span,
                0, new byte[32], AccountId, 1, dpa, addressSignature, accountSignature);
            return ApplicationCoreVerifier.VerifyDab1(parsed, deepId, Identity, 7);
        }

        private VerifiedDmd1 CreateDirectory(byte[] deviceId, DeviceCertificate device)
        {
            var entry = new DeviceDirectoryEntry(deviceId, Ref(device));
            var unsigned = ApplicationCoreCodec.AuthorDmd1(Network, AccountId, 1,
                Ref(Account.Certificate), Ref(Revocations.Snapshot), 1, new byte[32],
                [entry], 100, new byte[64]);
            var signature = PublicKeyAuth.SignDetached(
                unsigned.SignatureInput.ToArray(), DeviceIssuerKey.PrivateKey);
            return ApplicationCoreVerifier.VerifyDmd1(
                ApplicationCoreCodec.AuthorDmd1(Network, AccountId, 1,
                    Ref(Account.Certificate), Ref(Revocations.Snapshot), 1, new byte[32],
                    [entry], 100, signature), Identity);
        }

        internal AccountDirectoryAdc1 CreateCheckpoint(
            IReadOnlyList<ReadOnlyMemory<byte>> revoked,
            byte[]? network = null,
            ulong accountGeneration = 1,
            byte[]? leaf = null,
            byte[]? dpaReference = null,
            byte[]? drsReference = null,
            byte[]? dmdHash = null,
            byte[]? dabHash = null,
            ushort minimumReader = 1)
        {
            var revokedHash = AccountDirectoryAdc1Verifier.ComputeRevokedDcaAuthorizationIdsHash(revoked);
            var unsigned = new AccountDirectoryAdc1(
                network ?? Network,
                leaf ?? AccountDirectoryAdc1Verifier.ComputeDirectoryLeafKey(Network, DeepId.CanonicalBytes.Span),
                accountGeneration, 0, new byte[32],
                dpaReference ?? ExactDpaReference(), drsReference ?? ExactDrsReference(),
                dmdHash ?? Directory.Record.RecordHash.ToArray(),
                dabHash ?? Binding.Record.RecordHash.ToArray(), revokedHash,
                1_700_000_123, minimumReader, Bytes(64, 1));
            var signature = PublicKeyAuth.SignDetached(
                AccountDirectoryCrypto.ComputeAdc1SigningInput(unsigned), DeviceIssuerKey.PrivateKey);
            return new AccountDirectoryAdc1(
                unsigned.NetworkId.Span, unsigned.DirectoryLeafKey.Span, unsigned.AccountGeneration,
                unsigned.CheckpointGeneration, unsigned.PredecessorCheckpointHash.Span,
                unsigned.ExactDpa1Reference.Span, unsigned.ExactDrs1Reference.Span,
                unsigned.ExactDmd1Hash.Span, unsigned.ExactDab1Hash.Span,
                unsigned.RevokedDcaAuthorizationIdsHash.Span, unsigned.IssuedAt,
                unsigned.MinimumReader, signature);
        }

        internal byte[] ExactDpaReference() =>
            AccountDirectoryCrypto.CreateReference("DPA1"u8, 1,
                Account.Certificate.CanonicalHash.Span);

        internal byte[] ExactDrsReference() =>
            AccountDirectoryCrypto.CreateReference("DRS1"u8, 1,
                Revocations.Snapshot.CanonicalHash.Span);

        private static ApplicationArtifactReference Ref(CanonicalIdentityArtifact artifact) =>
            ApplicationCoreCodec.CreateArtifactReference((ushort)artifact.ArtifactType,
                checked((uint)artifact.CanonicalBytes.Length), artifact.CanonicalHash.Span);

        private static ReadOnlyMemory<byte>[] MinimumFields(RecordDefinition definition) =>
            definition.Fields.Select(field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

        private static byte[] U16(ushort value)
        {
            var result = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(result, value);
            return result;
        }

        private static byte[] U64(ulong value)
        {
            var result = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(result, value);
            return result;
        }
    }
}
