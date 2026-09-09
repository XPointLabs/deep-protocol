using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.MessagingCrypto;
using Sodium;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class HybridPreKeyHandshakeTests
{
    private static readonly byte[] Dpk2 = "DPK2-DARK-VERIFIED-INPUT-v1"u8.ToArray();

    [Fact]
    public void TwoPhaseSyntheticCombinerVector_BindsActualCiphertextAndMatchesBothSides()
    {
        // This is a synthetic combiner/transcript oracle generated with Python hashlib,
        // hmac and PyNaCl. It is not an ML-KEM interoperability or production-provider vector.
        var mlKemKey = SyntheticMlKemProvider.CreateKey();
        using var initiatorKeys = HybridInitiatorKeyMaterial.Import(Sequence(1), Sequence(33));
        using var prepared = HybridPreKeyHandshake.PrepareInitiation(
            initiatorKeys,
            ScalarMult.Base(Sequence(65)),
            ScalarMult.Base(Sequence(97)),
            ScalarMult.Base(Sequence(129)),
            mlKemKey,
            new SyntheticMlKemProvider());
        var header = BuildHeader(prepared.Ciphertext.Span);
        var fullDph2 = BuildFullDph2(header, Bytes(55));
        var transcriptHash = Convert.FromHexString(
            "DD219A45C1A1DB36CBD2A13C356308FADF647CE228E56A956F4EA7015A6288089A01CF5D488BFF704D82E932D1AE423BE3FDDBEC546AB956B88BEEBCA5CCD510");
        var binding = CreateBinding(transcriptHash);
        var initiatorCapability = VerifiedHybridTranscriptCapability.CreateInitiatorDarkForTests(
            Dpk2, header, prepared.Ciphertext.Span, Bytes(7), Bytes(8), binding);
        using var initiated = HybridPreKeyHandshake.CompleteInitiation(prepared, initiatorCapability);

        using var preKeyState = HybridOneTimePreKeyState.Create(
            Bytes(7), Sequence(129), Bytes(8), mlKemKey);
        using var claimPlan = preKeyState.PrepareConsume(VerifiedPreKeyClaimCapability.CreateDarkForTests(
            Bytes(9), binding.SessionId.Span, FullReplayHash(fullDph2), Bytes(7), Bytes(8)));
        using var claimCommit = claimPlan.Commit(DurableSuccess(claimPlan));
        using var claimedLease = claimCommit.TakeClaimedLease();
        using var nextPreKeyState = claimCommit.TakeNextState();
        using var responderKeys = HybridResponderStaticKeyMaterial.Import(Sequence(65), Sequence(97));
        var responderCapability = VerifiedHybridTranscriptCapability.CreateResponderDarkForTests(
            Dpk2, header, fullDph2, actualMlKemCiphertext: ExtractCiphertext(header),
            x25519PreKeyId: Bytes(7), mlKemPreKeyId: Bytes(8), stateBinding: binding);
        using var accepted = HybridPreKeyHandshake.AcceptInitiation(
            responderKeys,
            claimedLease,
            ScalarMult.Base(Sequence(1)),
            ScalarMult.Base(Sequence(33)),
            responderCapability,
            new SyntheticMlKemProvider());

        Assert.Equal(Convert.ToHexString(transcriptHash), Convert.ToHexString(initiated.TranscriptHash.Span));
        AssertSecret(initiated.UseEcRoot, "ECBB8C54E6B153FA695855BCCDFF205A5B5E1BBDDF132BBBBAC766AB395673C4");
        AssertSecret(initiated.UseSpqrRoot, "CBDEB0F04659C9B2732745964F655720F9F9DCD0410F1052322D1B09CC54355F");
        AssertSecret(initiated.UseInitialAeadKey, "9FB040D2DC39F1FE12A25D47D7086D6C8379762DA9EFADCCDCD88E42841F4D33");
        AssertSameSecret(initiated.UseEcRoot, accepted.UseEcRoot);
        AssertSameSecret(initiated.UseSpqrRoot, accepted.UseSpqrRoot);
        AssertSameSecret(initiated.UseInitialAeadKey, accepted.UseInitialAeadKey);
    }

    [Fact]
    public void VerifiedCapability_RejectsHeaderWithoutActualCiphertext()
    {
        var ciphertext = new byte[1088];
        RandomNumberGenerator.Fill(ciphertext);
        var binding = CreateBinding(Bytes64(3));
        var error = Assert.Throws<MessagingCryptoException>(() =>
            VerifiedHybridTranscriptCapability.CreateInitiatorDarkForTests(
                Dpk2, "header-without-kem"u8, ciphertext,
                ReadOnlySpan<byte>.Empty, Bytes(8), binding));
        Assert.Equal(MessagingCryptoError.InvalidInput, error.Error);
    }

    [Fact]
    public void PhaseTwo_RejectsCiphertextDifferentFromVerifiedTranscript()
    {
        var mlKemKey = SyntheticMlKemProvider.CreateKey();
        using var initiator = HybridInitiatorKeyMaterial.Import(Sequence(1), Sequence(33));
        using var prepared = HybridPreKeyHandshake.PrepareInitiation(
            initiator, ScalarMult.Base(Sequence(65)), ScalarMult.Base(Sequence(97)),
            ReadOnlySpan<byte>.Empty, mlKemKey, new SyntheticMlKemProvider());
        var changed = prepared.Ciphertext.ToArray();
        changed[0] ^= 1;
        var header = BuildHeader(changed);
        var transcript = ComputeTranscript(Dpk2, header);
        var capability = VerifiedHybridTranscriptCapability.CreateInitiatorDarkForTests(
            Dpk2, header, changed, ReadOnlySpan<byte>.Empty, Bytes(8), CreateBinding(transcript));

        var error = Assert.Throws<MessagingCryptoException>(() =>
            HybridPreKeyHandshake.CompleteInitiation(prepared, capability));
        Assert.Equal(MessagingCryptoError.PreKeyConflict, error.Error);
    }

    [Fact]
    public async Task PreparedPhaseAndVerifiedCapability_AreSingleConsumerUnderConcurrency()
    {
        var mlKemKey = SyntheticMlKemProvider.CreateKey();
        using var initiator = HybridInitiatorKeyMaterial.Import(Sequence(1), Sequence(33));
        using var prepared = HybridPreKeyHandshake.PrepareInitiation(
            initiator, ScalarMult.Base(Sequence(65)), ScalarMult.Base(Sequence(97)),
            ReadOnlySpan<byte>.Empty, mlKemKey, new SyntheticMlKemProvider());
        var ciphertext = prepared.Ciphertext.ToArray();
        var header = BuildHeader(ciphertext);
        var binding = CreateBinding(ComputeTranscript(Dpk2, header));
        var capability = VerifiedHybridTranscriptCapability.CreateInitiatorDarkForTests(
            Dpk2, header, ciphertext, ReadOnlySpan<byte>.Empty, Bytes(8), binding);

        var attempts = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            try
            {
                using var result = HybridPreKeyHandshake.CompleteInitiation(prepared, capability);
                return true;
            }
            catch (MessagingCryptoException exception) when (exception.Error == MessagingCryptoError.CapabilityConsumed)
            {
                return false;
            }
        })));
        Assert.Equal(1, attempts.Count(static succeeded => succeeded));
    }

    [Fact]
    public void ChangedEncryptedPayloadConflictsEvenWhenTranscriptHashIsUnchanged()
    {
        var mlKemKey = SyntheticMlKemProvider.CreateKey();
        using var initiator = HybridInitiatorKeyMaterial.Import(Sequence(1), Sequence(33));
        using var prepared = HybridPreKeyHandshake.PrepareInitiation(
            initiator, ScalarMult.Base(Sequence(65)), ScalarMult.Base(Sequence(97)),
            ScalarMult.Base(Sequence(129)), mlKemKey, new SyntheticMlKemProvider());
        var header = BuildHeader(prepared.Ciphertext.Span);
        var firstFull = BuildFullDph2(header, Bytes(70));
        var changedFull = BuildFullDph2(header, Bytes(71));
        var binding = CreateBinding(ComputeTranscript(Dpk2, header));
        using var preKeyState = HybridOneTimePreKeyState.Create(
            Bytes(7), Sequence(129), Bytes(8), mlKemKey);
        using var plan = preKeyState.PrepareConsume(VerifiedPreKeyClaimCapability.CreateDarkForTests(
            Bytes(9), binding.SessionId.Span, FullReplayHash(firstFull), Bytes(7), Bytes(8)));
        using var commit = plan.Commit(DurableSuccess(plan));
        using var claimed = commit.TakeClaimedLease();
        using var committed = commit.TakeNextState();
        using var responder = HybridResponderStaticKeyMaterial.Import(Sequence(65), Sequence(97));
        var changedCapability = VerifiedHybridTranscriptCapability.CreateResponderDarkForTests(
            Dpk2, header, changedFull, prepared.Ciphertext.Span, Bytes(7), Bytes(8), binding);

        var error = Assert.Throws<MessagingCryptoException>(() => HybridPreKeyHandshake.AcceptInitiation(
            responder, claimed, ScalarMult.Base(Sequence(1)), ScalarMult.Base(Sequence(33)),
            changedCapability, new SyntheticMlKemProvider()));
        Assert.Equal(MessagingCryptoError.PreKeyConflict, error.Error);
        Assert.NotEqual(FullReplayHash(firstFull), FullReplayHash(changedFull));
    }

    [Fact]
    public void MissingPqOrClassicalBranch_FailsClosedBeforeSecretsEscape()
    {
        using var initiator = HybridInitiatorKeyMaterial.Import(Sequence(1), Sequence(33));
        var pq = Assert.Throws<MessagingCryptoException>(() => HybridPreKeyHandshake.PrepareInitiation(
            initiator,
            ScalarMult.Base(Sequence(65)),
            ScalarMult.Base(Sequence(97)),
            ReadOnlySpan<byte>.Empty,
            SyntheticMlKemProvider.CreateKey(),
            new ZeroSecretMlKemProvider()));
        Assert.Equal(MessagingCryptoError.InvalidInput, pq.Error);

        var classical = Assert.Throws<MessagingCryptoException>(() => HybridPreKeyHandshake.PrepareInitiation(
            initiator,
            new byte[32],
            ScalarMult.Base(Sequence(97)),
            ReadOnlySpan<byte>.Empty,
            SyntheticMlKemProvider.CreateKey(),
            new SyntheticMlKemProvider()));
        Assert.Equal(MessagingCryptoError.InvalidInput, classical.Error);
    }

    [Fact]
    public void InitiatorPrivateCopiesAreZeroizedWhenInjectedAllocationFaultOccurs()
    {
        var captured = new List<byte[]>();
        using var hook = MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            ManagedSecret = (name, value) =>
            {
                if (!name.StartsWith("initiator.", StringComparison.Ordinal) ||
                    name == "initiator.pq") return;
                captured.Add(value);
                if (name == "initiator.ephemeral-private")
                    throw new InvalidOperationException("injected allocation fault");
            },
        });
        using var initiator = HybridInitiatorKeyMaterial.Import(Sequence(1), Sequence(33));

        var error = Assert.Throws<MessagingCryptoException>(() => HybridPreKeyHandshake.PrepareInitiation(
            initiator, ScalarMult.Base(Sequence(65)), ScalarMult.Base(Sequence(97)),
            ReadOnlySpan<byte>.Empty, SyntheticMlKemProvider.CreateKey(), new SyntheticMlKemProvider()));

        Assert.Equal(MessagingCryptoError.ProviderFailure, error.Error);
        Assert.Equal(2, captured.Count);
        Assert.All(captured, static secret => Assert.True(MessagingCryptoValidation.IsZero(secret)));
    }

    [Fact]
    public void DerivedRootsAreZeroizedWhenInjectedDerivationFaultOccurs()
    {
        using var initiator = HybridInitiatorKeyMaterial.Import(Sequence(1), Sequence(33));
        using var prepared = HybridPreKeyHandshake.PrepareInitiation(
            initiator, ScalarMult.Base(Sequence(65)), ScalarMult.Base(Sequence(97)),
            ReadOnlySpan<byte>.Empty, SyntheticMlKemProvider.CreateKey(), new SyntheticMlKemProvider());
        var header = BuildHeader(prepared.Ciphertext.Span);
        var capability = VerifiedHybridTranscriptCapability.CreateInitiatorDarkForTests(
            Dpk2, header, prepared.Ciphertext.Span, ReadOnlySpan<byte>.Empty, Bytes(8),
            CreateBinding(ComputeTranscript(Dpk2, header)));
        var captured = new List<byte[]>();
        using var hook = MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            ManagedSecret = (name, value) =>
            {
                if (!name.StartsWith("derive.", StringComparison.Ordinal)) return;
                captured.Add(value);
                if (name == "derive.spqr-root")
                    throw new InvalidOperationException("injected derivation fault");
            },
        });

        Assert.Throws<InvalidOperationException>(() =>
            HybridPreKeyHandshake.CompleteInitiation(prepared, capability));

        Assert.Equal(2, captured.Count);
        Assert.All(captured, static secret => Assert.True(MessagingCryptoValidation.IsZero(secret)));
    }

    [Fact]
    public void ExpandOutputAndEarlierRootAreZeroizedWhenInjectedExpandFaultOccurs()
    {
        using var initiator = HybridInitiatorKeyMaterial.Import(Sequence(1), Sequence(33));
        using var prepared = HybridPreKeyHandshake.PrepareInitiation(
            initiator, ScalarMult.Base(Sequence(65)), ScalarMult.Base(Sequence(97)),
            ReadOnlySpan<byte>.Empty, SyntheticMlKemProvider.CreateKey(), new SyntheticMlKemProvider());
        var header = BuildHeader(prepared.Ciphertext.Span);
        var capability = VerifiedHybridTranscriptCapability.CreateInitiatorDarkForTests(
            Dpk2, header, prepared.Ciphertext.Span, ReadOnlySpan<byte>.Empty, Bytes(8),
            CreateBinding(ComputeTranscript(Dpk2, header)));
        var captured = new List<byte[]>();
        using var hook = MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            ManagedSecret = (name, value) =>
            {
                if (!name.StartsWith("expand.", StringComparison.Ordinal)) return;
                captured.Add(value);
                if (name.EndsWith("spqr-root", StringComparison.Ordinal))
                    throw new InvalidOperationException("injected HKDF expand fault");
            },
        });

        Assert.Throws<InvalidOperationException>(() =>
            HybridPreKeyHandshake.CompleteInitiation(prepared, capability));

        Assert.Equal(2, captured.Count);
        Assert.All(captured, static secret => Assert.True(MessagingCryptoValidation.IsZero(secret)));
    }

    [Fact]
    public void PartiallyConstructedHandshakeSecretOwnersAreDisposedOnInjectedFault()
    {
        var captured = new List<SecretBuffer>();
        using var hook = MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            OwnedSecret = (name, owner) =>
            {
                captured.Add(owner);
                if (name == "handshake-secrets.spqr")
                    throw new InvalidOperationException("injected constructor allocation fault");
            },
        });

        Assert.Throws<InvalidOperationException>(() => new HybridHandshakeSecrets(
            Bytes64(3), CreateBinding(Bytes64(3)), Bytes(4), Bytes(5), Bytes(6)));

        Assert.Equal(2, captured.Count);
        Assert.All(captured, owner => Assert.Throws<MessagingCryptoException>(() => owner.Copy()));
    }

    private static RatchetStateBinding CreateBinding(ReadOnlySpan<byte> transcriptHash) => new(
        MessagingCryptoConstants.Suite,
        Bytes(40), transcriptHash,
        Bytes(41), 5, Bytes(42),
        Bytes(43), 9, Bytes(44));

    private static byte[] BuildHeader(ReadOnlySpan<byte> ciphertext)
    {
        var prefix = "DPH2-DARK-PREFIX"u8;
        var suffix = "-NO-PAYLOAD"u8;
        var result = new byte[prefix.Length + ciphertext.Length + suffix.Length];
        prefix.CopyTo(result);
        ciphertext.CopyTo(result.AsSpan(prefix.Length));
        suffix.CopyTo(result.AsSpan(prefix.Length + ciphertext.Length));
        return result;
    }

    private static byte[] ExtractCiphertext(ReadOnlySpan<byte> header) =>
        header.Slice("DPH2-DARK-PREFIX"u8.Length, 1088).ToArray();

    private static byte[] BuildFullDph2(ReadOnlySpan<byte> headerWithoutPayload, ReadOnlySpan<byte> encryptedPayload)
    {
        var result = new byte[headerWithoutPayload.Length + 4 + encryptedPayload.Length];
        headerWithoutPayload.CopyTo(result);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
            result.AsSpan(headerWithoutPayload.Length), checked((uint)encryptedPayload.Length));
        encryptedPayload.CopyTo(result.AsSpan(headerWithoutPayload.Length + 4));
        return result;
    }

    private static byte[] FullReplayHash(ReadOnlySpan<byte> exactFullDph2) =>
        MessagingKdf.Sha256Domain("Deep/Messaging/V2/exact-dph2-replay", exactFullDph2);

    private static DurableDatabaseCasSuccessCapability DurableSuccess(OneTimePreKeyConsumePlan plan) =>
        DurableDatabaseCasSuccessCapability.CreateDarkForTests(
            plan.StateCas,
            plan.ProposedGeneration ?? throw new InvalidOperationException("Fresh plan has no proposed generation."),
            plan.ProposedStateCommitment.Span,
            durableDatabaseCasSucceeded: true);

    private static byte[] ComputeTranscript(ReadOnlySpan<byte> dpk2, ReadOnlySpan<byte> header)
    {
        var payload = new byte[4 + dpk2.Length + 4 + header.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(payload, (uint)dpk2.Length);
        dpk2.CopyTo(payload.AsSpan(4));
        var offset = 4 + dpk2.Length;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(offset), (uint)header.Length);
        header.CopyTo(payload.AsSpan(offset + 4));
        return MessagingKdf.Sha512Domain("Deep/Messaging/V2/handshake-transcript", payload);
    }

    private static void AssertSecret(Action<MessagingSecretAction> use, string expected)
    {
        byte[]? actual = null;
        use(value => actual = value.ToArray());
        try { Assert.Equal(expected, Convert.ToHexString(actual!)); }
        finally { CryptographicOperations.ZeroMemory(actual!); }
    }

    private static void AssertSameSecret(
        Action<MessagingSecretAction> leftUse,
        Action<MessagingSecretAction> rightUse)
    {
        byte[]? left = null, right = null;
        leftUse(value => left = value.ToArray());
        rightUse(value => right = value.ToArray());
        try { Assert.Equal(left, right); }
        finally
        {
            CryptographicOperations.ZeroMemory(left!);
            CryptographicOperations.ZeroMemory(right!);
        }
    }

    private static byte[] Sequence(int start) => Enumerable.Range(start, 32).Select(static value => (byte)value).ToArray();
    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();
    private static byte[] Bytes64(byte value) => Enumerable.Repeat(value, 64).ToArray();

    private sealed class SyntheticMlKemProvider : IMlKem768Provider
    {
        public string ProviderIdentifier => "synthetic-combiner-test-oracle";
        public int DecapsulationKeySize => 1184;

        internal static byte[] CreateKey() => Enumerable.Range(0, 1184)
            .Select(static index => (byte)((index * 7 + 3) & 0xff)).ToArray();

        public bool EncapsulationKeyMatchesDecapsulationKey(
            ReadOnlySpan<byte> encapsulationKey,
            ReadOnlySpan<byte> decapsulationKey) =>
            encapsulationKey.Length == decapsulationKey.Length &&
            CryptographicOperations.FixedTimeEquals(encapsulationKey, decapsulationKey);

        public void Encapsulate(ReadOnlySpan<byte> encapsulationKey, Span<byte> ciphertext, Span<byte> sharedSecret)
        {
            MessagingCryptoValidation.Exact(encapsulationKey, 1184, nameof(encapsulationKey));
            MessagingCryptoValidation.Exact(ciphertext, 1088, nameof(ciphertext));
            MessagingCryptoValidation.Exact(sharedSecret, 32, nameof(sharedSecret));
            var input = new byte[2 + encapsulationKey.Length];
            "ct"u8.CopyTo(input);
            encapsulationKey.CopyTo(input.AsSpan(2));
            Shake256.HashData(input, ciphertext);
            var secretInput = new byte[2 + encapsulationKey.Length + ciphertext.Length];
            "ss"u8.CopyTo(secretInput);
            encapsulationKey.CopyTo(secretInput.AsSpan(2));
            ciphertext.CopyTo(secretInput.AsSpan(2 + encapsulationKey.Length));
            SHA256.HashData(secretInput, sharedSecret);
        }

        public void Decapsulate(ReadOnlySpan<byte> decapsulationKey, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
        {
            Span<byte> expected = stackalloc byte[1088];
            Span<byte> ignored = stackalloc byte[32];
            Encapsulate(decapsulationKey, expected, ignored);
            if (!CryptographicOperations.FixedTimeEquals(expected, ciphertext))
                throw new CryptographicException("Synthetic ciphertext rejected.");
            var input = new byte[2 + decapsulationKey.Length + ciphertext.Length];
            "ss"u8.CopyTo(input);
            decapsulationKey.CopyTo(input.AsSpan(2));
            ciphertext.CopyTo(input.AsSpan(2 + decapsulationKey.Length));
            SHA256.HashData(input, sharedSecret);
        }
    }

    private sealed class ZeroSecretMlKemProvider : IMlKem768Provider
    {
        public string ProviderIdentifier => "negative-zero-secret";
        public int DecapsulationKeySize => 1184;
        public bool EncapsulationKeyMatchesDecapsulationKey(
            ReadOnlySpan<byte> encapsulationKey,
            ReadOnlySpan<byte> decapsulationKey) => false;
        public void Encapsulate(ReadOnlySpan<byte> encapsulationKey, Span<byte> ciphertext, Span<byte> sharedSecret) => sharedSecret.Clear();
        public void Decapsulate(ReadOnlySpan<byte> decapsulationKey, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret) => sharedSecret.Clear();
    }
}
