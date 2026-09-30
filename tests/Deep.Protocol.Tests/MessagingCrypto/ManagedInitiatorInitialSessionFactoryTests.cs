using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Tests.ApplicationCore;
using Sodium;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class ManagedInitiatorInitialSessionFactoryTests
{
    private Func<Dpk2PrekeyKind, Fixture>? createFixture;

    // Called by the signed current V2 identity/claim fixture. Synthetic KEM
    // and ratchet providers below test mechanisms only, never physical/PQ gates.
    internal static async Task AssertV2RecoveryAsync(
        DeepIdV2CurrentContactAuthorization contact, ParsedDcr1V2 closure,
        VerifiedContactServicePlacement placement, ParsedDpk2V2 oneTime,
        ParsedDpk2V2 lastResort, byte[] boot,
        Func<VerifiedDpk2Offering, byte[], byte[], ValueTask<VerifiedXpc1V2PreKeyClaimReceipt>> claim)
    {
        var tests = new ManagedInitiatorInitialSessionFactoryTests
        {
            createFixture = kind => new Fixture(contact, closure, placement,
                kind == Dpk2PrekeyKind.OneTime ? oneTime : lastResort, boot, claim)
        };
        foreach (var kind in new[] { Dpk2PrekeyKind.OneTime, Dpk2PrekeyKind.LastResort })
        {
            await tests.PreClaimPreviewDerivesOnlyTheMatchingInitialAeadKey(kind);
            await tests.ExactDph2AndInitialTrs1AreProducedAsOneSingleUseCommit(kind,
                kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : (ushort)1);
        }
        await tests.ResponderRecoversExactAuthenticatedInitialEvents(false);
        await tests.ResponderRecoversExactAuthenticatedInitialEvents(true);
        await tests.ResponderRejectsTamperedInitialCiphertextBeforeTrs1Escapes();
        await tests.ExactInitialPayloadSelectsTheCanonicalPaddingBucket(5_000, 16_400, Dph2Codec.MediumTotalBytes);
        await tests.ExactInitialPayloadSelectsTheCanonicalPaddingBucket(16_000, 32_784, Dph2Codec.LargeTotalBytes);
        await tests.ChangedXpc1SenderCommitmentRejectsAndConsumesPreparation();
        await tests.ClaimForAnotherVerifiedDpk2RejectsBeforeDph2Escapes();
        await tests.SessionInitFromAnotherLocalDirectoryRejectsAndConsumesPreparation();
        await tests.CrossConversationFirstEventRejects();
        tests.FreshPreparationsNeverReuseTheSenderCommitment();
        await tests.OwnedRatchetSecretAndAtomicPayloadAreUnavailableAfterDispose();
        await tests.CurrentCompletionRejectsExpiryCancellationAndConcurrentDispose();
    }

    private Fixture CreateFixture(Dpk2PrekeyKind kind = Dpk2PrekeyKind.OneTime) =>
        createFixture!(kind);

    private async Task ResponderRecoversExactAuthenticatedInitialEvents(bool includeFirstApplication)
    {
        using var fixture = CreateFixture();
        using var preparation = fixture.Prepare();
        using var commit = await fixture.CompleteAsync(preparation,
            await fixture.Claim(preparation),
            fixture.SessionInit.CanonicalBytes,
            includeFirstApplication ? fixture.FirstMessage.CanonicalBytes : ReadOnlyMemory<byte>.Empty);
        using var outbound = commit.ConsumeForAtomicStore();
        var exactDph2 = outbound.ExactDph2.ToArray();
        try
        {
            var dph2 = Dph2Codec.Decode(exactDph2);
            using var claim = await fixture.ResponderClaim(dph2);
            using var responder = fixture.ResponderFactory();
            using var material = fixture.RecoverInitial(responder, claim);
            Assert.Equal(fixture.SessionInit.CanonicalBytes.ToArray(), material.SessionInitDmc2.ToArray());
            Assert.Equal(
                includeFirstApplication ? fixture.FirstMessage.CanonicalBytes.ToArray() : Array.Empty<byte>(),
                material.FirstApplicationDmc2.ToArray());
            using var state = TripleRatchetDurableStateCodec.Decode(material.ExactTrs1.Span);
            Assert.Equal(dph2.SessionId.ToArray(), state.Binding.SessionId.ToArray());
            Assert.Equal(dph2.ResponderDeviceId.ToArray(), state.Binding.LocalDeviceId.ToArray());
            Assert.Throws<ObjectDisposedException>(() =>
            {
                material.Dispose();
                _ = material.SessionInitDmc2;
            });
        }
        finally { CryptographicOperations.ZeroMemory(exactDph2); }
    }

    private async Task ResponderRejectsTamperedInitialCiphertextBeforeTrs1Escapes()
    {
        using var fixture = CreateFixture();
        using var preparation = fixture.Prepare();
        using var commit = await fixture.CompleteAsync(preparation,
            await fixture.Claim(preparation), fixture.SessionInit.CanonicalBytes);
        using var outbound = commit.ConsumeForAtomicStore();
        var exactDph2 = outbound.ExactDph2.ToArray();
        try
        {
            exactDph2[^1] ^= 0x01;
            var dph2 = Dph2Codec.Decode(exactDph2);
            await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            {
                using var claim = await fixture.ResponderClaim(dph2);
                using var responder = fixture.ResponderFactory();
                using var material = fixture.RecoverInitial(responder, claim);
            });
        }
        finally { CryptographicOperations.ZeroMemory(exactDph2); }
    }

    private async Task PreClaimPreviewDerivesOnlyTheMatchingInitialAeadKey(
        Dpk2PrekeyKind kind)
    {
        using var fixture = CreateFixture(kind);
        using var preparation = fixture.Prepare();
        using var commit = await fixture.CompleteAsync(preparation,
            await fixture.Claim(preparation), fixture.SessionInit.CanonicalBytes);
        using var outbound = commit.ConsumeForAtomicStore();
        var exactDph2 = outbound.ExactDph2.ToArray();
        byte[]? padded = null;
        try
        {
            var dph2 = Dph2Codec.Decode(exactDph2);
            padded = fixture.PreviewPaddedInitialPayload(dph2);
            Assert.Equal(16384, padded.Length);
            var bodyLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(padded.AsSpan()[^4..]));
            var prefix = Dph2InitialClaimTranscriptCodec.DecodePrefix(padded.AsSpan(0, bodyLength), dph2);
            Assert.Equal((byte)1, padded[prefix.Consumed]);
            Assert.Equal(commit.ClaimOperationId.ToArray(), prefix.Request.Field(2).ToArray());
            exactDph2[^1] ^= 1;
            Assert.ThrowsAny<CryptographicException>(() =>
                fixture.PreviewPaddedInitialPayload(Dph2Codec.Decode(exactDph2)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactDph2);
            if (padded is not null) CryptographicOperations.ZeroMemory(padded);
        }
    }

    private async Task ExactDph2AndInitialTrs1AreProducedAsOneSingleUseCommit(
        Dpk2PrekeyKind kind,
        ushort counter)
    {
        using var fixture = CreateFixture(kind);
        using var preparation = fixture.Prepare();
        var claim = await fixture.Claim(preparation);
        using var commit = await fixture.CompleteAsync(preparation,
            claim,
            fixture.SessionInit.CanonicalBytes,
            fixture.FirstMessage.CanonicalBytes);

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
            Assert.Equal(Dph2Codec.MediumTotalBytes, exactDph2.Length);
            Assert.Equal(16400, dph2.InitialCiphertext.Length);
            Assert.Equal(kind, dph2.SelectedPrekey.Kind);
            Assert.Equal(counter, dph2.LastResortUseCounter);
            Assert.Equal(fixture.Directory.ActiveDevices[0].Dpd1Reference.CanonicalBytes.ToArray(),
                dph2.InitiatorDpd1Ref.ToArray());
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
            Assert.Throws<InvalidOperationException>(() => claim.ConsumeForInitiator(dph2));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactDph2);
            CryptographicOperations.ZeroMemory(exactTrs1);
        }
    }

    private async Task ExactInitialPayloadSelectsTheCanonicalPaddingBucket(
        int textLength,
        int expectedCiphertextLength,
        int expectedDph2Length)
    {
        using var fixture = CreateFixture();
        using var preparation = fixture.Prepare();
        var claim = await fixture.Claim(preparation);
        var firstMessage = fixture.AuthorFirstMessage(new string('x', textLength));
        using var commit = await fixture.CompleteAsync(preparation,
            claim,
            fixture.SessionInit.CanonicalBytes,
            firstMessage.CanonicalBytes);
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

    private async Task ChangedXpc1SenderCommitmentRejectsAndConsumesPreparation()
    {
        using var fixture = CreateFixture();
        using var preparation = fixture.Prepare();
        var wrong = preparation.SenderEphemeralCommitment.ToArray();
        wrong[0] ^= 0x80;
        var claim = await fixture.Claim(preparation, senderCommitment: wrong);

        await Assert.ThrowsAnyAsync<CryptographicException>(async () => await fixture.CompleteAsync(preparation,
            claim, fixture.SessionInit.CanonicalBytes));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await fixture.CompleteAsync(preparation,
            claim, fixture.SessionInit.CanonicalBytes));
    }

    private async Task ClaimForAnotherVerifiedDpk2RejectsBeforeDph2Escapes()
    {
        using var fixture = CreateFixture();
        using var other = CreateFixture(Dpk2PrekeyKind.LastResort);
        using var preparation = fixture.Prepare();
        var claim = await other.ClaimFor(
            other.Offering,
            fixture.OperationId,
            preparation.SenderEphemeralCommitment);

        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.CompleteAsync(preparation,
            claim, fixture.SessionInit.CanonicalBytes));
    }

    private async Task SessionInitFromAnotherLocalDirectoryRejectsAndConsumesPreparation()
    {
        using var fixture = CreateFixture();
        using var preparation = fixture.Prepare();
        var claim = await fixture.Claim(preparation);
        var foreignAccount = Bytes(32, 0xe4);
        var foreignDirectory = ApplicationCoreFixture.Directory(
            fixture.NetworkId, foreignAccount, fixture.DeviceId);
        var foreignPayload = ApplicationCoreCodec.CreateSessionInitPayload(
            Bytes(32, 0xe5), foreignDirectory,
            SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl);
        var foreign = ApplicationCoreFixture.Message(
            foreignPayload, fixture.NetworkId, foreignAccount, fixture.DeviceId);

        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.CompleteAsync(preparation,
            claim, foreign.CanonicalBytes));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await fixture.CompleteAsync(preparation,
            claim, fixture.SessionInit.CanonicalBytes));
    }

    private async Task CrossConversationFirstEventRejects()
    {
        using var fixture = CreateFixture();
        using var preparation = fixture.Prepare();
        var claim = await fixture.Claim(preparation);
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

        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.CompleteAsync(preparation,
            claim,
            fixture.SessionInit.CanonicalBytes,
            foreign.CanonicalBytes));
    }

    private void FreshPreparationsNeverReuseTheSenderCommitment()
    {
        using var fixture = CreateFixture();
        using var first = fixture.Prepare();
        using var second = fixture.Prepare();

        Assert.NotEqual(
            first.SenderEphemeralCommitment.ToArray(),
            second.SenderEphemeralCommitment.ToArray());
    }

    private async Task OwnedRatchetSecretAndAtomicPayloadAreUnavailableAfterDispose()
    {
        using var fixture = CreateFixture();
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
        var claim = await fixture.Claim(next);
        using var commit = await fixture.CompleteAsync(next, claim, fixture.SessionInit.CanonicalBytes);
        var payload = commit.ConsumeForAtomicStore();
        payload.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = payload.ExactTrs1);
        Assert.Throws<ObjectDisposedException>(() => _ = payload.ExactDph2);
    }

    private async Task CurrentCompletionRejectsExpiryCancellationAndConcurrentDispose()
    {
        using var fixture = CreateFixture();
        foreach (var samples in new[] { new ulong[] { 7 }, new ulong[] { 3, 7 },
                     new ulong[] { 2 }, new ulong[] { 3, 2 } })
        {
            using var preparation = fixture.Prepare();
            var receipt = await fixture.Claim(preparation);
            var clock = new OperationClock(fixture.Boot, samples);
            await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                await preparation.CompleteAsync(receipt, fixture.Contact.Freshness,
                    new OnionTrustedTimeAuthority(clock), fixture.SessionInit.CanonicalBytes));
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await fixture.CompleteAsync(preparation, receipt, fixture.SessionInit.CanonicalBytes));
        }
        foreach (var cancelAt in new[] { 0, 1, 2 })
        {
            using var cancellation = new CancellationTokenSource();
            using var preparation = fixture.Prepare();
            var receipt = await fixture.Claim(preparation);
            var clock = new OperationClock(fixture.Boot, [3, 3],
                read => { if (read == cancelAt) cancellation.Cancel(); });
            if (cancelAt == 0) cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await preparation.CompleteAsync(receipt, fixture.Contact.Freshness,
                    new OnionTrustedTimeAuthority(clock), fixture.SessionInit.CanonicalBytes,
                    cancellationToken: cancellation.Token));
            Assert.Equal(cancelAt, clock.Reads);
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await fixture.CompleteAsync(preparation, receipt, fixture.SessionInit.CanonicalBytes));
        }
        using (var preparation = fixture.Prepare())
        {
            var receipt = await fixture.Claim(preparation);
            await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                await preparation.CompleteAsync(receipt, fixture.Contact.Freshness,
                    new OnionTrustedTimeAuthority(new OperationClock(Bytes(16, 0xe8), [3])),
                    fixture.SessionInit.CanonicalBytes));
        }
        foreach (var suspendAt in new[] { 1, 2 })
        {
            using var preparation = fixture.Prepare();
            var receipt = await fixture.Claim(preparation);
            var clock = new SuspendedClock(fixture.Boot, suspendAt);
            var completing = preparation.CompleteAsync(receipt, fixture.Contact.Freshness,
                new OnionTrustedTimeAuthority(clock), fixture.SessionInit.CanonicalBytes).AsTask();
            await clock.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            preparation.Dispose();
            clock.Release.TrySetResult();
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await completing);
        }
        // Caller-owned memory can change while a protected-clock read suspends.
        // The authored event must remain the exact pre-suspension owned copy.
        using (var preparation = fixture.Prepare())
        {
            var receipt = await fixture.Claim(preparation);
            var session = fixture.SessionInit.CanonicalBytes.ToArray();
            var clock = new SuspendedClock(fixture.Boot, 1);
            var completing = preparation.CompleteAsync(receipt, fixture.Contact.Freshness,
                new OnionTrustedTimeAuthority(clock), session).AsTask();
            await clock.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            session[0] ^= 1;
            clock.Release.TrySetResult();
            using var commit = await completing;
            using var outbound = commit.ConsumeForAtomicStore();
            var dph2 = Dph2Codec.Decode(outbound.ExactDph2.Span);
            using var responderClaim = await fixture.ResponderClaim(dph2);
            using var responder = fixture.ResponderFactory();
            using var material = fixture.RecoverInitial(responder, responderClaim);
            Assert.Equal(fixture.SessionInit.CanonicalBytes.ToArray(), material.SessionInitDmc2.ToArray());
            CryptographicOperations.ZeroMemory(session);
        }
        using (var preparation = fixture.Prepare())
        {
            var receipt = await fixture.Claim(preparation);
            var clock = new OperationClock(fixture.Boot, [3]);
            await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                await preparation.CompleteAsync(receipt, fixture.Contact.Freshness,
                    new OnionTrustedTimeAuthority(clock), new byte[33083]));
            Assert.Equal(0, clock.Reads);
        }
    }

    [Fact]
    public void PublicSurfaceHasNoProviderTrustOrRawLongLivedPrivateKeySeam()
    {
        var methods = typeof(ManagedInitiatorInitialSessionFactory)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
        Assert.DoesNotContain(methods, static method => method.Name == "PrepareClaim");
        var begin = Assert.Single(methods,
            static method => method.Name == nameof(ManagedInitiatorInitialSessionFactory.BeginClaim));
        var complete = Assert.Single(methods,
            static method => method.Name == nameof(ManagedInitiatorInitialSessionFactory.CompleteClaim));
        Assert.Equal(
            [typeof(LocalDeviceX25519AgreementAuthority), typeof(Dmd1LineageState),
             typeof(VerifiedDeepIdV2DirectoryFreshness),
             typeof(ReadOnlySpan<byte>), typeof(ulong)],
            begin.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.Equal(
            [typeof(InitiatorDph2PreKeyClaim), typeof(VerifiedDpk2Offering),
                typeof(LocalDeviceX25519AgreementLease)],
            complete.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.Empty(typeof(InitiatorDph2ClaimPreparation).GetConstructors());
        Assert.Empty(typeof(InitiatorInitialSessionCommitCapability).GetConstructors());
        Assert.Empty(typeof(InitiatorInitialSessionAtomicStorePayload).GetConstructors());
        var completion = Assert.Single(typeof(InitiatorDph2ClaimPreparation)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly),
            method => !method.IsSpecialName && method.Name != nameof(IDisposable.Dispose));
        Assert.Equal("CompleteAsync", completion.Name);
        Assert.Equal(typeof(ValueTask<InitiatorInitialSessionCommitCapability>), completion.ReturnType);
        Assert.Equal(new[] { typeof(VerifiedXpc1V2PreKeyClaimReceipt),
            typeof(VerifiedDeepIdV2DirectoryFreshness), typeof(OnionTrustedTimeAuthority),
            typeof(ReadOnlyMemory<byte>), typeof(ReadOnlyMemory<byte>), typeof(CancellationToken) },
            completion.GetParameters().Select(parameter => parameter.ParameterType));

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
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType) ||
            parameter.ParameterType == typeof(IDph2VerificationCallbacks) ||
            parameter.Name.Contains("provider", StringComparison.OrdinalIgnoreCase));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly SyntheticMlKemProvider _mlKem = new();
        private readonly DeterministicEntropy _entropy = new();
        private readonly byte[] _localAgreementPrivate = Bytes(32, 0x51);
        private readonly byte[] _responderIdentityPrivate = Bytes(32, 0x51);
        private readonly byte[] _responderSignedPrivate = Bytes(32, 0x81);
        private readonly byte[] _responderOneTimePrivate;
        private readonly ParsedDcr1V2 closure;
        private readonly VerifiedContactServicePlacement placement;
        private readonly byte[] boot;
        private readonly Func<VerifiedDpk2Offering, byte[], byte[],
            ValueTask<VerifiedXpc1V2PreKeyClaimReceipt>> claim;

        internal Fixture(DeepIdV2CurrentContactAuthorization contact,
            ParsedDcr1V2 closure, VerifiedContactServicePlacement placement,
            ParsedDpk2V2 member, byte[] boot,
            Func<VerifiedDpk2Offering, byte[], byte[],
                ValueTask<VerifiedXpc1V2PreKeyClaimReceipt>> claim)
        {
            Contact = contact;
            this.closure = closure;
            this.placement = placement;
            this.boot = boot;
            this.claim = claim;
            Kind = member.Kind;
            Counter = Kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : (ushort)1;
            NetworkId = contact.Freshness.NetworkId.ToArray();
            var checkpoint = contact.Freshness.CurrentCheckpoint!;
            Directory = checkpoint.Directory.Record;
            AccountId = Directory.DeepAccountId.ToArray();
            DeviceId = checkpoint.Binding.Identity.ActiveDevices.Single().Certificate.DeviceId.ToArray();
            OperationId = Bytes(32, 0x42);
            ExactDpd1Hash = Directory.ActiveDevices[0].Dpd1Reference.CanonicalHash.ToArray();
            OfferingRecord = member.Record;
            Offering = DeepIdV2Dpk2PreClaimVerifier.Verify(member.CanonicalBytes.Span,
                contact.Freshness, boot, 3);
            _responderOneTimePrivate = Kind == Dpk2PrekeyKind.OneTime
                ? member.OneTimePrekeyId.ToArray() : Bytes(32, 0x10);
            var sessionPayload = ApplicationCoreCodec.CreateSessionInitPayload(
                Bytes(32, 0x44), Directory,
                SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl);
            SessionInit = ApplicationCoreFixture.Message(
                sessionPayload, NetworkId, AccountId, DeviceId);
            FirstMessage = AuthorFirstMessage("hello");
        }

        internal DeepIdV2CurrentContactAuthorization Contact { get; }
        internal byte[] Boot => boot;
        internal OnionTrustedTimeAuthority Time => new(new Clock(boot));

        internal ValueTask<InitiatorInitialSessionCommitCapability> CompleteAsync(
            InitiatorDph2ClaimPreparation preparation, VerifiedXpc1V2PreKeyClaimReceipt receipt,
            ReadOnlyMemory<byte> session, ReadOnlyMemory<byte> first = default) =>
            preparation.CompleteAsync(receipt, Contact.Freshness, Time, session, first);

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

        internal ManagedResponderInitialSessionFactory ResponderFactory() =>
            new(_responderIdentityPrivate, _responderSignedPrivate, 128);

        internal byte[] PreviewPaddedInitialPayload(Dph2Record dph2)
        {
            var header = Dph2VerificationPlan.Create(dph2, Offering).Prevalidate(
                new Dph2ResolvedInitiator(
                    dph2.InitiatorDeviceAgreementPublicKey.Span,
                    Directory.RecordHash.Span));
            using var responder = HybridResponderStaticKeyMaterial.Import(
                _responderIdentityPrivate, _responderSignedPrivate);
            var previewKeys = new OwnedDpk2PreKeyMaterial(
                _responderSignedPrivate.ToArray(),
                Kind == Dpk2PrekeyKind.OneTime ? _responderOneTimePrivate.ToArray() : null,
                SyntheticMlKemProvider.PublicKey.ToArray());
            using var preview = HybridPreKeyHandshake.PreviewInitialAeadKey(
                responder, previewKeys, header, _mlKem);
            byte[]? key = null;
            byte[]? ciphertext = null;
            byte[]? aad = null;
            byte[]? nonce = null;
            try
            {
                preview.Use(secret => key = secret.ToArray());
                ciphertext = new byte[dph2.InitialCiphertext.Length];
                dph2.InitialCiphertext.CopyCiphertextTo(ciphertext);
                aad = MessagingWireCryptographicInputs.GetDph2InitialAeadAssociatedData(
                    Offering.ExactBytes.Span, dph2);
                nonce = dph2.InitialPayloadNonce.ToArray();
                return SecretAeadXChaCha20Poly1305.Decrypt(
                    ciphertext, nonce, key!, aad);
            }
            finally
            {
                if (key is not null) CryptographicOperations.ZeroMemory(key);
                if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
                if (aad is not null) CryptographicOperations.ZeroMemory(aad);
                if (nonce is not null) CryptographicOperations.ZeroMemory(nonce);
            }
        }

        internal async ValueTask<VerifiedInitialSessionPreKeyClaim> ResponderClaim(Dph2Record dph2)
        {
            var header = Dph2VerificationPlan.Create(dph2, Offering).Prevalidate(
                new Dph2ResolvedInitiator(dph2.InitiatorDeviceAgreementPublicKey.Span,
                    Directory.RecordHash.Span));
            using var responder = HybridResponderStaticKeyMaterial.Import(
                _responderIdentityPrivate, _responderSignedPrivate);
            var keys = new OwnedDpk2PreKeyMaterial(_responderSignedPrivate.ToArray(),
                Kind == Dpk2PrekeyKind.OneTime ? _responderOneTimePrivate.ToArray() : null,
                SyntheticMlKemProvider.PublicKey.ToArray());
            using var previewKey = HybridPreKeyHandshake.PreviewInitialAeadKey(
                responder, keys, header, _mlKem);
            var pair = Dph2InitialPayloadReader.PreviewClaimTranscript(header, previewKey);
            var preview = new Dph2InitialClaimPreview(header, pair.Request, pair.Result);
            var verified = await preview.VerifyCurrentAsync(placement, Contact, closure,
                Contact.Freshness, Time);
            return verified.BindForInitialSession();
        }

        internal ResponderInitialSessionMaterial RecoverInitial(
            ManagedResponderInitialSessionFactory responder,
            VerifiedInitialSessionPreKeyClaim claim) =>
            responder.CreateAuthenticatedInitialSessionForTests(
                claim,
                Kind == Dpk2PrekeyKind.OneTime ? _responderOneTimePrivate : [],
                SyntheticMlKemProvider.PublicKey,
                _mlKem,
                CreateResponderTestState);

        internal InitiatorDph2ClaimPreparation Prepare()
        {
            var factory = new ManagedInitiatorInitialSessionFactory(128);
            return factory.PrepareClaimForTests(
                Offering,
                NetworkId,
                AccountId,
                DeviceId,
                Contact.Freshness.CurrentCheckpoint!.Binding.Identity.ActiveDevices.Single()
                    .Certificate.DeviceGeneration,
                ExactDpd1Hash,
                Directory.DirectoryGeneration,
                Directory.RecordHash.Span,
                Contact.Freshness.CurrentCheckpoint!.Binding.DeepId.CanonicalBytes.Span,
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

        internal ValueTask<VerifiedXpc1V2PreKeyClaimReceipt> Claim(
            InitiatorDph2ClaimPreparation preparation, byte[]? senderCommitment = null) =>
            ClaimFor(Offering, OperationId,
                senderCommitment ?? preparation.SenderEphemeralCommitment.ToArray());

        internal ValueTask<VerifiedXpc1V2PreKeyClaimReceipt> ClaimFor(
            VerifiedDpk2Offering offering, ReadOnlyMemory<byte> operationId,
            ReadOnlyMemory<byte> senderCommitment) =>
            claim(offering, operationId.ToArray(), senderCommitment.ToArray());

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
        internal static byte[] PublicKey => Bytes(1184, 0xc1);

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

    private static TripleRatchetState CreateResponderTestState(
        VerifiedTripleRatchetSeedCapability seed,
        ReadOnlySpan<byte> signedPreKeyPrivate,
        ReadOnlySpan<byte> signedPreKeyPublic,
        ReadOnlySpan<byte> initiatorInitialRatchetPublic,
        int maximumMessagesWithoutPqInjection) =>
        CreateTestState(seed, signedPreKeyPrivate, initiatorInitialRatchetPublic,
            signedPreKeyPublic, maximumMessagesWithoutPqInjection);

    private sealed class Clock(byte[] boot) : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(new OnionMonotonicReading(boot, 3));
    }

    private sealed class OperationClock(byte[] boot, ulong[] samples,
        Action<int>? beforeReturn = null) : IOnionMonotonicClock
    {
        internal int Reads { get; private set; }
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            var index = Reads++;
            beforeReturn?.Invoke(Reads);
            return ValueTask.FromResult(new OnionMonotonicReading(boot,
                samples[Math.Min(index, samples.Length - 1)]));
        }
    }

    private sealed class SuspendedClock(byte[] boot, int suspendAt) : IOnionMonotonicClock
    {
        private int reads;
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            if (++reads == suspendAt)
            {
                Entered.TrySetResult();
                await Release.Task.WaitAsync(cancellationToken);
            }
            return new OnionMonotonicReading(boot, 3);
        }
    }

    private static byte[] Bytes(int length, byte fill)
    {
        var value = new byte[length];
        value.AsSpan().Fill(fill);
        return value;
    }
}
