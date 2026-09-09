using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class ManagedResponderInitialSessionFactoryTests
{
    [Fact]
    public void VerifiedClaimProducesExactResponderBoundTrs1()
    {
        using var fixture = Fixture.Create();
        using var handoff = fixture.CreateHandoff();
        using var factory = fixture.CreateFactory();

        var exactTrs1 = fixture.CreateExactTrs1(factory, handoff);
        try
        {
            Assert.Equal("TRS1", System.Text.Encoding.ASCII.GetString(exactTrs1, 0, 4));
            Assert.Equal((byte)1, exactTrs1[4]);
            Assert.Equal((ushort)0x0201, BinaryPrimitives.ReadUInt16BigEndian(exactTrs1.AsSpan(5)));
            Assert.Equal(fixture.Initiation.Record.SessionId.ToArray(), exactTrs1.AsSpan(12, 32).ToArray());
            Assert.Equal(fixture.Initiation.TranscriptHash.ToArray(), exactTrs1.AsSpan(44, 64).ToArray());
            Assert.Equal(fixture.Initiation.Record.ResponderDeviceId.ToArray(), exactTrs1.AsSpan(108, 32).ToArray());
            Assert.Equal(fixture.Initiation.Record.ResponderDeviceGeneration,
                BinaryPrimitives.ReadUInt64BigEndian(exactTrs1.AsSpan(140)));
            Assert.Equal(fixture.Offering.DeviceDirectoryHeadHash.ToArray(), exactTrs1.AsSpan(148, 32).ToArray());
            Assert.Equal(fixture.Initiation.Record.InitiatorDeviceId.ToArray(), exactTrs1.AsSpan(180, 32).ToArray());
            Assert.Equal(fixture.Initiation.Record.InitiatorDeviceGeneration,
                BinaryPrimitives.ReadUInt64BigEndian(exactTrs1.AsSpan(212)));
            Assert.Equal(fixture.InitiatorDirectoryHead, exactTrs1.AsSpan(220, 32).ToArray());
            Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(exactTrs1.AsSpan(252)));

            using var decoded = TripleRatchetDurableStateCodec.Decode(exactTrs1);
            Assert.Equal(fixture.Initiation.Record.SessionId.ToArray(), decoded.Binding.SessionId.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactTrs1);
        }
    }

    [Fact]
    public void ProtocolLaneIsSingleUseEvenAfterSuccessfulProduction()
    {
        using var fixture = Fixture.Create();
        using var handoff = fixture.CreateHandoff();
        using var factory = fixture.CreateFactory();
        var exactTrs1 = fixture.CreateExactTrs1(factory, handoff);
        try
        {
            Assert.Throws<InvalidOperationException>(() =>
                fixture.CreateExactTrs1(factory, handoff));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactTrs1);
        }
    }

    [Fact]
    public void LastResortClaimProducesTrs1WithoutOneTimeX25519Secret()
    {
        using var fixture = Fixture.Create(Dpk2PrekeyKind.LastResort);
        using var handoff = fixture.CreateHandoff();
        using var factory = fixture.CreateFactory();

        var exactTrs1 = fixture.CreateExactTrs1(factory, handoff);
        try
        {
            using var decoded = TripleRatchetDurableStateCodec.Decode(exactTrs1);
            Assert.Equal(fixture.Initiation.Record.SessionId.ToArray(), decoded.Binding.SessionId.ToArray());
            Assert.Equal((ushort)37, handoff.LastResortUseCounter);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactTrs1);
        }
    }

    [Fact]
    public void RestoredOpaqueCapabilityProducesExactTrs1AndIsSingleUse()
    {
        using var fixture = Fixture.Create();
        using var restored = fixture.CreateRestoredCapability();
        using var handoff = fixture.CreateHandoff();
        using var factory = fixture.CreateOpaqueFactory();

        var exactTrs1 = fixture.CreateExactTrs1(factory, handoff, restored);
        try
        {
            using var decoded = TripleRatchetDurableStateCodec.Decode(exactTrs1);
            Assert.Equal(fixture.Initiation.Record.SessionId.ToArray(), decoded.Binding.SessionId.ToArray());
            using var secondClaim = fixture.CreateHandoff();
            Assert.Throws<InvalidOperationException>(() =>
                fixture.CreateExactTrs1(factory, secondClaim, restored));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactTrs1);
        }
    }

    [Fact]
    public void RestoredOpaqueCapabilityMismatchBurnsAndZeroizesAllOwnedSecrets()
    {
        using var fixture = Fixture.Create();
        var captured = new List<SecretBuffer>();
        using var hook = MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            OwnedSecret = (name, owner) =>
            {
                if (name.StartsWith("dpk2.persistence.restored-", StringComparison.Ordinal))
                    captured.Add(owner);
            },
        });
        using var restored = fixture.CreateRestoredCapability();
        var changedSession = fixture.Initiation.Record.SessionId.ToArray();
        changedSession[0] ^= 0x80;
        using var mismatched = fixture.CreateHandoff(sessionId: changedSession);
        using var factory = fixture.CreateOpaqueFactory();

        var exception = Assert.Throws<MessagingCryptoException>(() =>
            factory.CreateExactTrs1(mismatched, restored));
        Assert.Equal(MessagingCryptoError.PreKeyConflict, exception.Error);
        Assert.Equal(3, captured.Count);
        Assert.All(captured, owner =>
            Assert.Throws<MessagingCryptoException>(() => owner.Copy()));
        using var retry = fixture.CreateHandoff();
        Assert.Throws<InvalidOperationException>(() =>
            factory.CreateExactTrs1(retry, restored));
    }

    [Fact]
    public void KeyMismatchConsumesLaneAndCannotBeRetried()
    {
        using var fixture = Fixture.Create();
        using var handoff = fixture.CreateHandoff();
        using var factory = fixture.CreateFactory();
        var wrongOneTimeScalar = Sequence(193);
        try
        {
            var mismatch = Assert.Throws<MessagingCryptoException>(() =>
                fixture.CreateExactTrs1(factory, handoff, wrongOneTimeScalar));
            Assert.Equal(MessagingCryptoError.PreKeyConflict, mismatch.Error);
            Assert.Throws<InvalidOperationException>(() =>
                fixture.CreateExactTrs1(factory, handoff));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrongOneTimeScalar);
        }
    }

    [Fact]
    public void HandoffMismatchRejectsBeforeAnyRatchetStateEscapes()
    {
        using var fixture = Fixture.Create();
        var changedSession = fixture.Initiation.Record.SessionId.ToArray();
        changedSession[0] ^= 0x80;
        using var handoff = fixture.CreateHandoff(sessionId: changedSession);
        using var factory = fixture.CreateFactory();

        var mismatch = Assert.Throws<MessagingCryptoException>(() =>
            fixture.CreateExactTrs1(factory, handoff));
        Assert.Equal(MessagingCryptoError.PreKeyConflict, mismatch.Error);
        Assert.Throws<InvalidOperationException>(() =>
            fixture.CreateExactTrs1(factory, handoff));
    }

    [Fact]
    public void FactoryAndTransientPreKeyOwnersAreDisposed()
    {
        using var fixture = Fixture.Create();
        using var handoff = fixture.CreateHandoff();
        var captured = new List<SecretBuffer>();
        using var hook = MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            OwnedSecret = (name, owner) =>
            {
                if (name.StartsWith("initial-session.factory.", StringComparison.Ordinal) ||
                    name.StartsWith("prekey.claimed.", StringComparison.Ordinal))
                    captured.Add(owner);
            },
        });
        var factory = fixture.CreateFactory();
        var exactTrs1 = fixture.CreateExactTrs1(factory, handoff);
        factory.Dispose();
        CryptographicOperations.ZeroMemory(exactTrs1);

        Assert.Equal(4, captured.Count);
        Assert.All(captured, owner =>
            Assert.Throws<MessagingCryptoException>(() => owner.Copy()));
        Assert.Throws<ObjectDisposedException>(() =>
        {
            using var next = fixture.CreateHandoff();
            fixture.CreateExactTrs1(factory, next);
        });
    }

    [Fact]
    public void PublicSurfaceCannotMintVerifiedClaimsOrInjectProviders()
    {
        Assert.Empty(typeof(VerifiedInitialSessionPreKeyClaim).GetConstructors());
        var methods = typeof(ManagedResponderInitialSessionFactory)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(static method => method.Name == nameof(ManagedResponderInitialSessionFactory.CreateExactTrs1))
            .Select(static method => method.GetParameters().Select(static parameter => parameter.ParameterType).ToArray())
            .ToArray();
        Assert.Equal(2, methods.Length);
        Assert.Contains(methods, parameters => parameters.SequenceEqual(
            [typeof(VerifiedInitialSessionPreKeyClaim), typeof(ReadOnlySpan<byte>), typeof(ReadOnlySpan<byte>)]));
        Assert.Contains(methods, parameters => parameters.SequenceEqual(
            [typeof(VerifiedInitialSessionPreKeyClaim), typeof(RestoredDpk2PreKeySecretCapability)]));
        Assert.Empty(typeof(RestoredDpk2PreKeySecretCapability).GetConstructors());
        Assert.Empty(typeof(Dpk2PreKeyPersistenceBlob).GetConstructors());
        Assert.DoesNotContain(
            typeof(RestoredDpk2PreKeySecretCapability)
                .GetProperties(BindingFlags.Public | BindingFlags.Instance),
            static property => property.PropertyType == typeof(byte[]) ||
                               property.PropertyType == typeof(SecretBuffer));
        Assert.DoesNotContain(
            typeof(ManagedResponderInitialSessionFactory).GetMethods(BindingFlags.Public | BindingFlags.Static),
            static candidate => candidate.ReturnType == typeof(VerifiedInitialSessionPreKeyClaim));
        Assert.DoesNotContain(
            typeof(ManagedResponderInitialSessionFactory).GetConstructors()
                .SelectMany(static constructor => constructor.GetParameters()),
            static parameter => parameter.ParameterType == typeof(IMlKem768Provider));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly SyntheticMlKemProvider _mlKem = new();
        private readonly byte[] _mlKemSecret = SyntheticMlKemProvider.CreateKey();
        private readonly byte[] _identityPrivate = Sequence(65);
        private readonly byte[] _signedPreKeyPrivate = Sequence(97);
        private readonly byte[] _oneTimePrivate = Sequence(129);

        private Fixture(
            Dpk2Record offering,
            VerifiedDph2Initiation initiation,
            byte[] initiatorDirectoryHead)
        {
            Offering = offering;
            Initiation = initiation;
            InitiatorDirectoryHead = initiatorDirectoryHead;
            Kind = offering.MlKemKind;
        }

        internal Dpk2Record Offering { get; }
        internal VerifiedDph2Initiation Initiation { get; }
        internal byte[] InitiatorDirectoryHead { get; }
        internal Dpk2PrekeyKind Kind { get; }

        internal static Fixture Create(Dpk2PrekeyKind kind = Dpk2PrekeyKind.OneTime)
        {
            var mlKem = new SyntheticMlKemProvider();
            var mlKemSecret = SyntheticMlKemProvider.CreateKey();
            var identityPrivate = Sequence(65);
            var signedPrivate = Sequence(97);
            var oneTimePrivate = Sequence(129);
            var initiatorIdentityPrivate = Sequence(1);
            var initiatorEphemeralPrivate = Sequence(33);
            var initialRatchetPrivate = Sequence(161);
            var initiatorDirectoryHead = Bytes(32, 0x47);
            try
            {
                var offering = BuildOffering(
                    ScalarMult.Base(identityPrivate),
                    ScalarMult.Base(signedPrivate),
                    kind == Dpk2PrekeyKind.OneTime ? ScalarMult.Base(oneTimePrivate) : [],
                    mlKemSecret,
                    kind);
                using var initiator = HybridInitiatorKeyMaterial.Import(
                    initiatorIdentityPrivate,
                    initiatorEphemeralPrivate);
                using var prepared = HybridPreKeyHandshake.PrepareInitiation(
                    initiator,
                    offering.DeviceAgreementPublicKey.Span,
                    offering.SignedX25519PrekeyPublic.Span,
                    offering.OneTimeX25519PrekeyPublic.Span,
                    offering.MlKem768EncapsulationKey.Span,
                    mlKem);
                var initiation = BuildInitiation(
                    offering,
                    ScalarMult.Base(initiatorIdentityPrivate),
                    ScalarMult.Base(initiatorEphemeralPrivate),
                    ScalarMult.Base(initialRatchetPrivate),
                    prepared.Ciphertext.Span,
                    initiatorDirectoryHead);
                return new Fixture(offering, initiation, initiatorDirectoryHead);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(mlKemSecret);
                CryptographicOperations.ZeroMemory(identityPrivate);
                CryptographicOperations.ZeroMemory(signedPrivate);
                CryptographicOperations.ZeroMemory(oneTimePrivate);
                CryptographicOperations.ZeroMemory(initiatorIdentityPrivate);
                CryptographicOperations.ZeroMemory(initiatorEphemeralPrivate);
                CryptographicOperations.ZeroMemory(initialRatchetPrivate);
            }
        }

        internal ManagedResponderInitialSessionFactory CreateFactory() =>
            new(_identityPrivate, _signedPreKeyPrivate, maximumMessagesWithoutPqInjection: 128);

        internal ManagedResponderInitialSessionFactory CreateOpaqueFactory() =>
            new(_identityPrivate, maximumMessagesWithoutPqInjection: 128);

        internal RestoredDpk2PreKeySecretCapability CreateRestoredCapability()
        {
            var exact = Dpk2Codec.Encode(Offering);
            var hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(Offering);
            var key = Bytes(32, 0xc1);
            try
            {
                using var source = new Dpk2PreKeySecretCapability(
                    Offering,
                    accountGeneration: 2,
                    hash,
                    _signedPreKeyPrivate,
                    Kind == Dpk2PrekeyKind.OneTime ? _oneTimePrivate : [],
                    _mlKemSecret);
                var scope = new Dpk2PreKeyPersistenceScope(
                    Offering.NetworkId.Span,
                    Offering.ResponderAccountId.Span,
                    accountGeneration: 2,
                    Offering.ResponderDeviceId.Span,
                    Offering.ResponderDeviceGeneration,
                    Offering.ResponderDpd1Ref.Span);
                Dpk2PreKeyPersistenceBlob blob;
                using (var writer = new Dpk2PreKeyPersistenceProtector(key))
                    blob = source.SealForPersistence(writer, exact, scope);
                using var reader = new Dpk2PreKeyPersistenceProtector(key);
                return reader.Restore(blob, exact, scope);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(exact);
                CryptographicOperations.ZeroMemory(hash);
                CryptographicOperations.ZeroMemory(key);
            }
        }

        internal VerifiedInitialSessionPreKeyClaim CreateHandoff(byte[]? sessionId = null) =>
            new(
                Kind,
                Initiation.Record.LastResortUseCounter,
                Initiation.Record.ClaimOperationId.Span,
                sessionId ?? Initiation.Record.SessionId.ToArray(),
                MessagingWireCryptographicInputs.ComputeExactDpk2Hash(Offering),
                Bytes(32, 0x55),
                Initiation.FullReplayHash.Span,
                Kind == Dpk2PrekeyKind.OneTime ? Offering.OneTimeX25519PrekeyId.Span : [],
                Offering.MlKemPrekeyId.Span,
                Initiation);

        internal byte[] CreateExactTrs1(
            ManagedResponderInitialSessionFactory factory,
            VerifiedInitialSessionPreKeyClaim handoff,
            byte[]? oneTimePrivate = null)
        {
            return factory.CreateExactTrs1ForTests(
                handoff,
                oneTimePrivate ?? (Kind == Dpk2PrekeyKind.OneTime ? _oneTimePrivate : []),
                _mlKemSecret,
                _mlKem,
                CreateTestState);
        }

        internal byte[] CreateExactTrs1(
            ManagedResponderInitialSessionFactory factory,
            VerifiedInitialSessionPreKeyClaim handoff,
            RestoredDpk2PreKeySecretCapability restored) =>
            factory.CreateExactTrs1ForTests(
                handoff,
                restored,
                _mlKem,
                CreateTestState);

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_mlKemSecret);
            CryptographicOperations.ZeroMemory(_identityPrivate);
            CryptographicOperations.ZeroMemory(_signedPreKeyPrivate);
            CryptographicOperations.ZeroMemory(_oneTimePrivate);
            CryptographicOperations.ZeroMemory(InitiatorDirectoryHead);
        }

        private static TripleRatchetState CreateTestState(
            VerifiedTripleRatchetSeedCapability seed,
            ReadOnlySpan<byte> signedPreKeyPrivate,
            ReadOnlySpan<byte> signedPreKeyPublic,
            ReadOnlySpan<byte> initiatorInitialRatchetPublic,
            int maximumMessagesWithoutPqInjection)
        {
            using var data = seed.Consume();
            byte[]? ec = null;
            byte[]? spqr = null;
            byte[]? component = null;
            byte[]? receiveCommitment = null;
            byte[]? sendCommitment = null;
            try
            {
                ec = data.EcRoot.Copy();
                spqr = data.SpqrRoot.Copy();
                var combined = new byte[64];
                try
                {
                    ec.CopyTo(combined, 0);
                    spqr.CopyTo(combined, 32);
                    component = SHA256.HashData(combined);
                    combined[0] ^= 0x5a;
                    receiveCommitment = SHA256.HashData(combined);
                    combined[0] ^= 0xa5;
                    sendCommitment = SHA256.HashData(combined);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(combined);
                }
                return TripleRatchetState.Create(
                    data.Binding,
                    component,
                    signedPreKeyPublic,
                    initiatorInitialRatchetPublic,
                    receiveCommitment,
                    sendCommitment,
                    nextExpectedReceiveEcN: 0,
                    nextSendEcN: 0,
                    storageGeneration: 1,
                    maximumMessagesWithoutPqInjection);
            }
            finally
            {
                if (ec is not null) CryptographicOperations.ZeroMemory(ec);
                if (spqr is not null) CryptographicOperations.ZeroMemory(spqr);
                if (component is not null) CryptographicOperations.ZeroMemory(component);
                if (receiveCommitment is not null) CryptographicOperations.ZeroMemory(receiveCommitment);
                if (sendCommitment is not null) CryptographicOperations.ZeroMemory(sendCommitment);
            }
        }

        private static Dpk2Record BuildOffering(
            ReadOnlySpan<byte> identityPublic,
            ReadOnlySpan<byte> signedPreKeyPublic,
            ReadOnlySpan<byte> oneTimePublic,
            ReadOnlySpan<byte> mlKemPublic,
            Dpk2PrekeyKind kind) =>
            new(
                Bytes(16, 0x01),
                Bytes(32, 0x11),
                Bytes(32, 0x21),
                3,
                Reference("DPD1", 0x31),
                5,
                Bytes(32, 0x41),
                7,
                11,
                Bytes(32, 0x51),
                13,
                1_700_000_100,
                1_700_000_000,
                1_700_100_000,
                identityPublic,
                Bytes(32, 0x61),
                signedPreKeyPublic,
                Bytes(64, 0x71),
                kind == Dpk2PrekeyKind.OneTime ? Bytes(32, 0x81) : [],
                oneTimePublic,
                Bytes(32, 0x91),
                mlKemPublic,
                kind,
                kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : (ushort)64,
                Bytes(64, 0xa1),
                Bytes(64, 0xb1));

        private static VerifiedDph2Initiation BuildInitiation(
            Dpk2Record offering,
            ReadOnlySpan<byte> initiatorIdentityPublic,
            ReadOnlySpan<byte> initiatorEphemeralPublic,
            ReadOnlySpan<byte> initialRatchetPublic,
            ReadOnlySpan<byte> mlKemCiphertext,
            ReadOnlySpan<byte> initiatorDirectoryHead)
        {
            var dph2 = new Dph2Record(
                offering.NetworkId.Span,
                Bytes(32, 0x12),
                Bytes(32, 0x22),
                17,
                Bytes(38, 0x32),
                offering.ResponderAccountId.Span,
                offering.ResponderDeviceId.Span,
                offering.ResponderDeviceGeneration,
                MessagingWireCryptographicInputs.ComputeExactDpk2Hash(offering),
                Bytes(32, 0x42),
                Bytes(32, 0x52),
                offering.MlKemKind == Dpk2PrekeyKind.OneTime ? (ushort)0 : (ushort)37,
                initiatorIdentityPublic,
                initiatorEphemeralPublic,
                offering.MlKemKind == Dpk2PrekeyKind.OneTime
                    ? Dph2SelectedPrekey.OneTime(
                        offering.SignedX25519PrekeyId.Span,
                        offering.OneTimeX25519PrekeyId.Span,
                        offering.MlKemPrekeyId.Span)
                    : Dph2SelectedPrekey.LastResort(
                        offering.SignedX25519PrekeyId.Span,
                        offering.MlKemPrekeyId.Span),
                mlKemCiphertext,
                initialRatchetPublic,
                Bytes(24, 0xa2),
                Dph2InitialCiphertext.Import(Bytes(4112, 0xb2)));
            var verifiedOffering = new VerifiedDpk2Offering(
                offering,
                MessagingWireCryptographicInputs.ComputeExactDpk2Hash(offering));
            return new VerifiedDph2Initiation(
                dph2,
                verifiedOffering,
                MessagingWireCryptographicInputs.ComputeDph2TranscriptHash(offering, dph2),
                MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(dph2),
                MessagingWireCryptographicInputs.ComputeDph2ClaimBinding(dph2),
                initiatorDirectoryHead);
        }
    }

    private sealed class SyntheticMlKemProvider : IMlKem768Provider
    {
        public string ProviderIdentifier => "synthetic-initial-session-test";
        public int DecapsulationKeySize => 1184;

        internal static byte[] CreateKey() => Enumerable.Range(0, 1184)
            .Select(static index => (byte)((index * 7 + 3) & 0xff)).ToArray();

        public bool EncapsulationKeyMatchesDecapsulationKey(
            ReadOnlySpan<byte> encapsulationKey,
            ReadOnlySpan<byte> decapsulationKey) =>
            encapsulationKey.Length == decapsulationKey.Length &&
            CryptographicOperations.FixedTimeEquals(encapsulationKey, decapsulationKey);

        public void Encapsulate(
            ReadOnlySpan<byte> encapsulationKey,
            Span<byte> ciphertext,
            Span<byte> sharedSecret)
        {
            MessagingCryptoValidation.Exact(encapsulationKey, 1184, nameof(encapsulationKey));
            MessagingCryptoValidation.Exact(ciphertext, 1088, nameof(ciphertext));
            MessagingCryptoValidation.Exact(sharedSecret, 32, nameof(sharedSecret));
            Shake256.HashData(encapsulationKey, ciphertext);
            var input = new byte[encapsulationKey.Length + ciphertext.Length];
            try
            {
                encapsulationKey.CopyTo(input);
                ciphertext.CopyTo(input.AsSpan(encapsulationKey.Length));
                SHA256.HashData(input, sharedSecret);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }

        public void Decapsulate(
            ReadOnlySpan<byte> decapsulationKey,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> sharedSecret)
        {
            Span<byte> expected = stackalloc byte[1088];
            Encapsulate(decapsulationKey, expected, sharedSecret);
            if (!CryptographicOperations.FixedTimeEquals(expected, ciphertext))
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
                throw new CryptographicException("Synthetic ML-KEM ciphertext mismatch.");
            }
        }
    }

    private static byte[] Sequence(int start) =>
        Enumerable.Range(start, 32).Select(static value => unchecked((byte)value)).ToArray();

    private static byte[] Bytes(int length, byte seed)
    {
        var value = new byte[length];
        for (var index = 0; index < value.Length; index++)
            value[index] = unchecked((byte)(seed + index * 17));
        return value;
    }

    private static byte[] Reference(string magic, byte seed)
    {
        var value = Bytes(38, seed);
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        return value;
    }
}
