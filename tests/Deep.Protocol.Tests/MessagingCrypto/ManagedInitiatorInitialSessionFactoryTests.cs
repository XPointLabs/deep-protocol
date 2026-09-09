using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Tests.ApplicationCore;
using Sodium;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class ManagedInitiatorInitialSessionFactoryTests
{
    [Theory]
    [InlineData(Dpk2PrekeyKind.OneTime, 0)]
    [InlineData(Dpk2PrekeyKind.LastResort, 7)]
    public void ExactDph2AndInitialTrs1AreProducedAsOneSingleUseCommit(
        Dpk2PrekeyKind kind,
        ushort counter)
    {
        using var fixture = new Fixture(kind, counter);
        using var preparation = fixture.Prepare();
        var claim = fixture.Claim(preparation);
        using var commit = preparation.Complete(
            claim,
            fixture.SessionInit.CanonicalBytes.Span,
            fixture.FirstMessage.CanonicalBytes.Span);

        Assert.Equal(fixture.OperationId, commit.ClaimOperationId.ToArray());
        Assert.Equal(32, commit.SessionId.Length);
        Assert.Equal(32, commit.FullDph2ReplayHash.Length);
        Assert.Equal(32, commit.ClaimBinding.Length);

        using var payload = commit.ConsumeForAtomicStore();
        var exactDph2 = payload.ExactDph2.ToArray();
        var exactTrs1 = payload.ExactTrs1.ToArray();
        try
        {
            var dph2 = Dph2Codec.Decode(exactDph2);
            Assert.Equal(Dph2Codec.SmallTotalBytes, exactDph2.Length);
            Assert.Equal(4112, dph2.InitialCiphertext.Length);
            Assert.Equal(kind, dph2.SelectedPrekey.Kind);
            Assert.Equal(counter, dph2.LastResortUseCounter);
            Assert.Equal(fixture.OperationId, dph2.ClaimOperationId.ToArray());
            Assert.Equal(preparation.SenderEphemeralCommitment.ToArray(),
                MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(dph2));
            Assert.Equal(commit.FullDph2ReplayHash.ToArray(),
                MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(dph2));
            Assert.Equal(commit.ClaimBinding.ToArray(),
                MessagingWireCryptographicInputs.ComputeDph2ClaimBinding(dph2));
            Assert.Contains(dph2.ActualMlKem768Ciphertext.ToArray(), static value => value != 0);

            Assert.Equal("TRS1", System.Text.Encoding.ASCII.GetString(exactTrs1, 0, 4));
            using var state = TripleRatchetDurableStateCodec.Decode(exactTrs1);
            Assert.Equal(dph2.SessionId.ToArray(), state.Binding.SessionId.ToArray());
            Assert.Equal(dph2.InitiatorDeviceId.ToArray(), state.Binding.LocalDeviceId.ToArray());
            Assert.Equal(dph2.ResponderDeviceId.ToArray(), state.Binding.RemoteDeviceId.ToArray());
            Assert.Equal(1UL, state.StorageGeneration);

            Assert.Throws<InvalidOperationException>(() => commit.ConsumeForAtomicStore());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactDph2);
            CryptographicOperations.ZeroMemory(exactTrs1);
        }
    }

    [Theory]
    [InlineData(5_000, 16_400, Dph2Codec.MediumTotalBytes)]
    [InlineData(16_000, 32_784, Dph2Codec.LargeTotalBytes)]
    public void ExactInitialPayloadSelectsTheCanonicalPaddingBucket(
        int textLength,
        int expectedCiphertextLength,
        int expectedDph2Length)
    {
        using var fixture = new Fixture();
        using var preparation = fixture.Prepare();
        var claim = fixture.Claim(preparation);
        var firstMessage = fixture.AuthorFirstMessage(new string('x', textLength));
        using var commit = preparation.Complete(
            claim,
            fixture.SessionInit.CanonicalBytes.Span,
            firstMessage.CanonicalBytes.Span);
        using var payload = commit.ConsumeForAtomicStore();

        var exactDph2 = payload.ExactDph2.ToArray();
        try
        {
            var dph2 = Dph2Codec.Decode(exactDph2);
            Assert.Equal(expectedDph2Length, exactDph2.Length);
            Assert.Equal(expectedCiphertextLength, dph2.InitialCiphertext.Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactDph2);
        }
    }

    [Fact]
    public void ChangedXpc1SenderCommitmentRejectsAndConsumesPreparation()
    {
        using var fixture = new Fixture();
        using var preparation = fixture.Prepare();
        var wrong = preparation.SenderEphemeralCommitment.ToArray();
        wrong[0] ^= 0x80;
        var claim = fixture.Claim(preparation, senderCommitment: wrong);

        Assert.ThrowsAny<CryptographicException>(() => preparation.Complete(
            claim, fixture.SessionInit.CanonicalBytes.Span));
        Assert.Throws<InvalidOperationException>(() => preparation.Complete(
            claim, fixture.SessionInit.CanonicalBytes.Span));
    }

    [Fact]
    public void ClaimForAnotherVerifiedDpk2RejectsBeforeDph2Escapes()
    {
        using var fixture = new Fixture();
        using var other = new Fixture(responderDeviceFill: 0x6a);
        using var preparation = fixture.Prepare();
        var claim = other.ClaimFor(
            other.Offering,
            fixture.OperationId,
            preparation.SenderEphemeralCommitment.Span);

        Assert.Throws<CryptographicException>(() => preparation.Complete(
            claim, fixture.SessionInit.CanonicalBytes.Span));
    }

    [Fact]
    public void SessionInitFromAnotherLocalDirectoryRejectsAndConsumesPreparation()
    {
        using var fixture = new Fixture();
        using var preparation = fixture.Prepare();
        var claim = fixture.Claim(preparation);
        var foreignAccount = Bytes(32, 0xe4);
        var foreignDirectory = ApplicationCoreFixture.Directory(
            fixture.NetworkId, foreignAccount, fixture.DeviceId);
        var foreignPayload = ApplicationCoreCodec.CreateSessionInitPayload(
            Bytes(32, 0xe5), foreignDirectory,
            SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl);
        var foreign = ApplicationCoreFixture.Message(
            foreignPayload, fixture.NetworkId, foreignAccount, fixture.DeviceId);

        Assert.Throws<CryptographicException>(() => preparation.Complete(
            claim, foreign.CanonicalBytes.Span));
        Assert.Throws<InvalidOperationException>(() => preparation.Complete(
            claim, fixture.SessionInit.CanonicalBytes.Span));
    }

    [Fact]
    public void CrossConversationFirstEventRejects()
    {
        using var fixture = new Fixture();
        using var preparation = fixture.Prepare();
        var claim = fixture.Claim(preparation);
        var foreign = ApplicationCoreCodec.AuthorDmc2(
            fixture.NetworkId,
            Bytes(32, 0xe6),
            Bytes(32, 0xe7),
            fixture.AccountId,
            fixture.DeviceId,
            2,
            1_001,
            0,
            Dmc2Flags.None,
            [],
            ApplicationCoreCodec.CreateMessageCreatePayload("foreign"));

        Assert.Throws<CryptographicException>(() => preparation.Complete(
            claim,
            fixture.SessionInit.CanonicalBytes.Span,
            foreign.CanonicalBytes.Span));
    }

    [Fact]
    public void FreshPreparationsNeverReuseTheSenderCommitment()
    {
        using var fixture = new Fixture();
        using var first = fixture.Prepare();
        using var second = fixture.Prepare();

        Assert.NotEqual(
            first.SenderEphemeralCommitment.ToArray(),
            second.SenderEphemeralCommitment.ToArray());
    }

    [Fact]
    public void OwnedRatchetSecretAndAtomicPayloadAreUnavailableAfterDispose()
    {
        using var fixture = new Fixture();
        SecretBuffer? captured = null;
        using var hook = MessagingCryptoFaultInjection.InstallDarkForTests(
            new MessagingCryptoFaultProbe
            {
                OwnedSecret = (name, owner) =>
                {
                    if (name == "initial-session.initiator-ratchet-private") captured = owner;
                },
            });
        var preparation = fixture.Prepare();
        Assert.NotNull(captured);
        preparation.Dispose();
        Assert.Throws<MessagingCryptoException>(() => captured!.Copy());

        using var next = fixture.Prepare();
        var claim = fixture.Claim(next);
        using var commit = next.Complete(claim, fixture.SessionInit.CanonicalBytes.Span);
        var payload = commit.ConsumeForAtomicStore();
        payload.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = payload.ExactTrs1);
        Assert.Throws<ObjectDisposedException>(() => _ = payload.ExactDph2);
    }

    [Fact]
    public void PublicSurfaceHasNoProviderTrustOrRawLongLivedPrivateKeySeam()
    {
        var prepare = Assert.Single(
            typeof(ManagedInitiatorInitialSessionFactory)
                .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly),
            static method => method.Name == nameof(ManagedInitiatorInitialSessionFactory.PrepareClaim));
        Assert.Equal(
            [typeof(VerifiedDpk2Offering), typeof(LocalDeviceX25519AgreementLease)],
            prepare.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.Empty(typeof(InitiatorDph2ClaimPreparation).GetConstructors());
        Assert.Empty(typeof(InitiatorInitialSessionCommitCapability).GetConstructors());
        Assert.Empty(typeof(InitiatorInitialSessionAtomicStorePayload).GetConstructors());

        var publicParameters = typeof(ManagedInitiatorInitialSessionFactory).Assembly
            .GetExportedTypes()
            .Where(static type => type.Namespace == "Deep.Protocol.MessagingCrypto")
            .SelectMany(static type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance |
                                                       BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Where(static method => method.DeclaringType == typeof(ManagedInitiatorInitialSessionFactory) ||
                                    method.DeclaringType == typeof(InitiatorDph2ClaimPreparation))
            .SelectMany(static method => method.GetParameters())
            .ToArray();
        Assert.DoesNotContain(publicParameters, static parameter =>
            parameter.ParameterType == typeof(IMlKem768Provider) ||
            parameter.Name!.Contains("private", StringComparison.OrdinalIgnoreCase) ||
            parameter.Name.Contains("trust", StringComparison.OrdinalIgnoreCase) ||
            parameter.Name.Contains("provider", StringComparison.OrdinalIgnoreCase));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly SyntheticMlKemProvider _mlKem = new();
        private readonly DeterministicEntropy _entropy = new();
        private readonly byte[] _localAgreementPrivate = Sequence(1);
        private readonly byte[] _responderIdentityPrivate = Sequence(65);
        private readonly byte[] _responderSignedPrivate = Sequence(97);
        private readonly byte[] _responderOneTimePrivate = Sequence(129);

        internal Fixture(
            Dpk2PrekeyKind kind = Dpk2PrekeyKind.OneTime,
            ushort lastResortCounter = 0,
            byte responderDeviceFill = 0x22)
        {
            Kind = kind;
            Counter = kind == Dpk2PrekeyKind.OneTime ? (ushort)0 :
                lastResortCounter == 0 ? (ushort)7 : lastResortCounter;
            NetworkId = Bytes(16, 0x11);
            AccountId = Bytes(32, 0x14);
            DeviceId = Bytes(32, 0x15);
            OperationId = Bytes(32, 0x42);
            Directory = ApplicationCoreFixture.Directory(NetworkId, AccountId, DeviceId);
            ExactDpd1Hash = Directory.ActiveDevices[0].Dpd1Reference.CanonicalHash.ToArray();
            OfferingRecord = BuildOffering(kind, responderDeviceFill);
            Offering = new VerifiedDpk2Offering(
                OfferingRecord,
                MessagingWireCryptographicInputs.ComputeExactDpk2Hash(OfferingRecord));
            var sessionPayload = ApplicationCoreCodec.CreateSessionInitPayload(
                Bytes(32, 0x44),
                Directory,
                SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl);
            SessionInit = ApplicationCoreFixture.Message(
                sessionPayload, NetworkId, AccountId, DeviceId);
            FirstMessage = ApplicationCoreCodec.AuthorDmc2(
                NetworkId,
                Bytes(32, 0x16),
                SessionInit.ConversationId.Span,
                AccountId,
                DeviceId,
                2,
                1_001,
                0,
                Dmc2Flags.None,
                [],
                ApplicationCoreCodec.CreateMessageCreatePayload("hello"));
        }

        internal Dpk2PrekeyKind Kind { get; }
        internal ushort Counter { get; }
        internal byte[] NetworkId { get; }
        internal byte[] AccountId { get; }
        internal byte[] DeviceId { get; }
        internal byte[] OperationId { get; }
        internal byte[] ExactDpd1Hash { get; }
        internal ParsedDmd1 Directory { get; }
        internal Dpk2Record OfferingRecord { get; }
        internal VerifiedDpk2Offering Offering { get; }
        internal ParsedDmc2 SessionInit { get; }
        internal ParsedDmc2 FirstMessage { get; }

        internal InitiatorDph2ClaimPreparation Prepare()
        {
            var factory = new ManagedInitiatorInitialSessionFactory(128);
            return factory.PrepareClaimForTests(
                Offering,
                NetworkId,
                AccountId,
                DeviceId,
                3,
                ExactDpd1Hash,
                Directory.DirectoryGeneration,
                Directory.RecordHash.Span,
                _localAgreementPrivate,
                OperationId,
                _mlKem,
                CreateTestState,
                _entropy.Fill);
        }

        internal ParsedDmc2 AuthorFirstMessage(string text) =>
            ApplicationCoreCodec.AuthorDmc2(
                NetworkId,
                Bytes(32, 0x16),
                SessionInit.ConversationId.Span,
                AccountId,
                DeviceId,
                2,
                1_001,
                0,
                Dmc2Flags.None,
                [],
                ApplicationCoreCodec.CreateMessageCreatePayload(text));

        internal VerifiedXpc1PreKeyClaimReceipt Claim(
            InitiatorDph2ClaimPreparation preparation,
            byte[]? senderCommitment = null) =>
            ClaimFor(
                Offering,
                OperationId,
                senderCommitment ?? preparation.SenderEphemeralCommitment.ToArray());

        internal VerifiedXpc1PreKeyClaimReceipt ClaimFor(
            VerifiedDpk2Offering offering,
            ReadOnlySpan<byte> operationId,
            ReadOnlySpan<byte> senderCommitment) =>
            VerifiedXpc1PreKeyClaimReceipt.CreateInitiatorRecoveryTestReceipt(
                offering.Record,
                operationId,
                Bytes(32, 0x52),
                senderCommitment,
                offering.Record.MlKemKind == Dpk2PrekeyKind.OneTime ? (ushort)0 : Counter);

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_localAgreementPrivate);
            CryptographicOperations.ZeroMemory(_responderIdentityPrivate);
            CryptographicOperations.ZeroMemory(_responderSignedPrivate);
            CryptographicOperations.ZeroMemory(_responderOneTimePrivate);
            CryptographicOperations.ZeroMemory(NetworkId);
            CryptographicOperations.ZeroMemory(AccountId);
            CryptographicOperations.ZeroMemory(DeviceId);
            CryptographicOperations.ZeroMemory(OperationId);
            CryptographicOperations.ZeroMemory(ExactDpd1Hash);
        }

        private Dpk2Record BuildOffering(Dpk2PrekeyKind kind, byte responderDeviceFill) =>
            new(
                NetworkId,
                Bytes(32, 0x21),
                Bytes(32, responderDeviceFill),
                5,
                Reference(0x23),
                7,
                Bytes(32, 0x24),
                9,
                11,
                Bytes(32, 0x25),
                13,
                1_700_000_100,
                1_700_000_000,
                1_700_100_000,
                ScalarMult.Base(_responderIdentityPrivate),
                Bytes(32, 0x26),
                ScalarMult.Base(_responderSignedPrivate),
                Bytes(64, 0x27),
                kind == Dpk2PrekeyKind.OneTime ? Bytes(32, 0x28) : [],
                kind == Dpk2PrekeyKind.OneTime ? ScalarMult.Base(_responderOneTimePrivate) : [],
                Bytes(32, 0x29),
                SyntheticMlKemProvider.PublicKey,
                kind,
                kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : (ushort)64,
                Bytes(64, 0x2a),
                Bytes(64, 0x2b));
    }

    private sealed class DeterministicEntropy
    {
        private int _counter;

        internal void Fill(Span<byte> destination)
        {
            var counter = Interlocked.Increment(ref _counter);
            for (var index = 0; index < destination.Length; index++)
                destination[index] = unchecked((byte)(counter + (index * 17) + 1));
        }
    }

    private sealed class SyntheticMlKemProvider : IMlKem768Provider
    {
        internal static byte[] PublicKey => Enumerable.Range(0, 1184)
            .Select(static index => unchecked((byte)(index * 13 + 3))).ToArray();

        public string ProviderIdentifier => "synthetic-initiator-boundary";
        public int DecapsulationKeySize => 1184;

        public bool EncapsulationKeyMatchesDecapsulationKey(
            ReadOnlySpan<byte> encapsulationKey,
            ReadOnlySpan<byte> decapsulationKey) => encapsulationKey.SequenceEqual(decapsulationKey);

        public void Encapsulate(
            ReadOnlySpan<byte> encapsulationKey,
            Span<byte> ciphertext,
            Span<byte> sharedSecret)
        {
            SHA256.HashData(encapsulationKey, sharedSecret);
            for (var index = 0; index < ciphertext.Length; index++)
                ciphertext[index] = unchecked((byte)(encapsulationKey[index % encapsulationKey.Length] ^ 0x5a));
        }

        public void Decapsulate(
            ReadOnlySpan<byte> decapsulationKey,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> sharedSecret)
        {
            _ = ciphertext;
            SHA256.HashData(decapsulationKey, sharedSecret);
        }
    }

    private static TripleRatchetState CreateTestState(
        VerifiedTripleRatchetSeedCapability seed,
        ReadOnlySpan<byte> initialRatchetPrivate,
        ReadOnlySpan<byte> initialRatchetPublic,
        ReadOnlySpan<byte> responderSignedPreKeyPublic,
        int maximumMessagesWithoutPqInjection)
    {
        _ = initialRatchetPrivate;
        using var data = seed.Consume();
        var ec = data.EcRoot.Copy();
        var spqr = data.SpqrRoot.Copy();
        byte[]? component = null;
        byte[]? receive = null;
        byte[]? send = null;
        try
        {
            component = SHA256.HashData(ec.Concat(spqr).ToArray());
            receive = SHA256.HashData(component.Concat(new byte[] { 1 }).ToArray());
            send = SHA256.HashData(component.Concat(new byte[] { 2 }).ToArray());
            return TripleRatchetState.Create(
                data.Binding,
                component,
                responderSignedPreKeyPublic,
                initialRatchetPublic,
                receive,
                send,
                0,
                0,
                1,
                maximumMessagesWithoutPqInjection);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ec);
            CryptographicOperations.ZeroMemory(spqr);
            if (component is not null) CryptographicOperations.ZeroMemory(component);
            if (receive is not null) CryptographicOperations.ZeroMemory(receive);
            if (send is not null) CryptographicOperations.ZeroMemory(send);
        }
    }

    private static byte[] Reference(byte fill)
    {
        var value = new byte[38];
        "DPD1"u8.CopyTo(value);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        value.AsSpan(6).Fill(fill);
        return value;
    }

    private static byte[] Sequence(byte start) =>
        Enumerable.Range(start, 32).Select(static value => (byte)value).ToArray();

    private static byte[] Bytes(int length, byte fill)
    {
        var value = new byte[length];
        value.AsSpan().Fill(fill);
        return value;
    }
}
