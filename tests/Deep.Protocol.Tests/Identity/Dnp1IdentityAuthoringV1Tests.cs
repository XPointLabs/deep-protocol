using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Sodium;

namespace Deep.Protocol.Tests.Identity;

public sealed partial class Dnp1IdentityAuthoringV1Tests
{
    private const string Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    private static readonly byte[] Network = Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray();

    [Fact]
    public void AuthorGenesisAccount_IsOfflineExactAndMatchesFrozenVector()
    {
        using var recovery = Recovery(Network);
        var authored = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 7, new FillRandom(0xa1));

        Assert.Equal(644, authored.CanonicalDpa1.Length);
        Assert.Equal(356, authored.CanonicalDrs1.Length);
        Assert.Equal("a5cfd7c919fa53a241335649539918a1c623b3d0b85f3e03b651a036e425c0f9",
            Hex(SHA256.HashData(authored.CanonicalDpa1.Span)));
        Assert.Equal("f60dfb47e4b4a4c585125fd3e8be66ef931fb4a256fc3b907f702d0d39e9bbc1",
            Hex(SHA256.HashData(authored.CanonicalDrs1.Span)));
        Assert.Equal(recovery.AccountIdentity, authored.AccountIdentity);

        var verified = new IdentityRelativeVerifier().VerifyGenesis(
            authored.CanonicalDpa1.Span,
            authored.CanonicalDrs1.Span,
            [],
            1_900_000_000);
        Assert.Equal(1UL, verified.Account.Certificate.AccountGeneration);
        Assert.Equal(1UL, verified.Revocations.Snapshot.Revision);
        Assert.Equal(0UL, verified.Revocations.Snapshot.EntryCount);
        Assert.All(verified.Revocations.Snapshot.CurrentHead.ToArray(), static value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task IssueGenesisDevice_WithoutCurrentDrsReturnsIntentAndTouchesNoPersistence()
    {
        using var recovery = Recovery(Network);
        using var device = Device();

        var result = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, null, device, null, 1_900_000_100, 1_900_086_500, 1_900_172_900);

        Assert.Equal(GenesisDeviceIssuanceStatus.PendingCurrentDrs, result.Status);
        Assert.NotNull(result.PendingIntent);
        Assert.Null(result.IssuedDevice);
        Assert.True(result.PendingIntent!.RequiresCurrentDrs);
        Assert.Equal(device.DeviceId, result.PendingIntent.DeviceId);
    }

    [Fact]
    public async Task IssueGenesisDevice_AuthorsExactCurrentRecordsAndDurableVerifiedCas()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var store = new DurableState();
        var persistence = new DurablePersistence(store);

        var result = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, device, persistence,
            1_900_000_100, 1_900_086_500, 1_900_172_900,
            new FillRandom(0xb1, 0xb2, 0xb3), default);

        Assert.Equal(GenesisDeviceIssuanceStatus.Issued, result.Status);
        Assert.Null(result.PendingIntent);
        var issued = Assert.IsType<IssuedGenesisDevice>(result.IssuedDevice);
        Assert.Equal(776, issued.CanonicalDpd1.Length);
        Assert.Equal(32, issued.X25519PopTranscriptHash.Length);
        Assert.Equal(573, issued.DurableReceipt.CanonicalDxr1.Length);
        Assert.Equal(2UL, issued.DurableReceipt.SourceRevision);
        Assert.Equal("9665d97f57241750c8ced2d1b4d787ac29bd750cd4f61ca08b12ba37c7f9c357",
            Hex(SHA256.HashData(issued.CanonicalDpd1.Span)));
        Assert.Equal("4249bb4dd9381e5f48f728543c9e6f3efe52de42f6d59d987756cc459d5623ea",
            Hex(SHA256.HashData(issued.DurableReceipt.CanonicalDxr1.Span)));

        var dpd = CanonicalGrammar.DecodeOwned(issued.CanonicalDpd1.Span, RecordDefinitions.Dpd1);
        Assert.Equal(1UL, U64(dpd.FieldSpan(5)));
        Assert.Equal(0UL, U64(dpd.FieldSpan(9)));
        Assert.All(dpd.FieldCopy(10), static value => Assert.Equal(0, value));
        Assert.Equal(1UL, U64(dpd.FieldSpan(12)));
        Assert.Equal((ulong)DeviceCapabilities.MailboxRoleIssuer, U64(dpd.FieldSpan(18)));
        Assert.Equal(ArtifactRegistry.IdentityAuthV1Ed25519, U16(dpd.FieldSpan(19)));
        Assert.Equal(device.DeviceId.Bytes.ToArray(), dpd.FieldCopy(4));
        Assert.Equal(device.RevocationHandle.Bytes.ToArray(), dpd.FieldCopy(8));
        Assert.Equal(device.SigningPublicKey.Bytes.ToArray(), dpd.FieldCopy(6));
        Assert.Equal(device.AgreementPublicKey.Bytes.ToArray(), dpd.FieldCopy(7));
        Assert.NotEqual(dpd.FieldCopy(6), dpd.FieldCopy(7));
        Assert.Equal(632, DxpSubjectProjection.EncodeDevice(dpd).Length);

        var substitutedFields = Enumerable.Range(1, 23)
            .Select(tag => (ReadOnlyMemory<byte>)dpd.FieldCopy(tag)).ToArray();
        var substitutedTranscriptHash = substitutedFields[20].ToArray();
        substitutedTranscriptHash[0] ^= 0x80;
        substitutedFields[20] = substitutedTranscriptHash;
        var substitutedDpd = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpd1, substitutedFields),
            RecordDefinitions.Dpd1);
        var substitutedSigning = CanonicalGrammar.GetSigningBytes(
            substitutedDpd, "Deep/IdentityAuth/V1/device-certificate");
        Assert.False(PublicKeyAuth.VerifyDetached(
            dpd.FieldCopy(22), substitutedSigning, dpd.FieldCopy(6)));
        Assert.False(PublicKeyAuth.VerifyDetached(
            dpd.FieldCopy(23), substitutedSigning,
            recovery.DeviceIssuerSigningPublicKey.ToArray()));
        Assert.NotEqual(
            CanonicalGrammar.GetSigningBytes(
                dpd, "Deep/IdentityAuth/V1/device-certificate"),
            substitutedSigning);

        var dxr = CanonicalGrammar.DecodeOwned(
            issued.DurableReceipt.CanonicalDxr1.Span, RecordDefinitions.Dxr1);
        Assert.Equal((byte)X25519PossessionRole.Device, dxr.FieldSpan(2)[0]);
        Assert.True(dxr.FieldSpan(3).SequenceEqual(Network));
        Assert.True(dxr.FieldSpan(6).SequenceEqual(device.AgreementPublicKey.Bytes.Span));
        Assert.True(dxr.FieldSpan(8).SequenceEqual(
            Enumerable.Repeat((byte)0xb3, 32).ToArray()));
        Assert.Equal(1_900_000_100UL, U64(dxr.FieldSpan(10)));
        Assert.Equal(1_900_000_400UL, U64(dxr.FieldSpan(11)));
        Assert.True(dxr.FieldSpan(13).SequenceEqual(issued.X25519PopTranscriptHash.Span));
        Assert.True(issued.SubjectCasReceipt.ExpectedSubjectAbsent);
        Assert.Equal(1UL, issued.SubjectCasReceipt.SubjectRevision);
        Assert.Equal(2, store.ProfileReads);
        Assert.Equal(1, store.PendingWrites);
        Assert.Equal(1, store.VerifiedCasWrites);
    }

    [Fact]
    public async Task DurableVerifiedReplay_ReturnsExactWinnerAcrossAdapterRestart()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        var store = new DurableState();
        byte[] firstDpd;
        using (var firstDevice = Device())
        {
            var first = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery, account, firstDevice, new DurablePersistence(store),
                1_900_000_100, 1_900_086_500, 1_900_172_900,
                new FillRandom(0xb1, 0xb2, 0xb3), default);
            Assert.Equal(GenesisDeviceIssuanceStatus.Issued, first.Status);
            firstDpd = first.IssuedDevice!.CanonicalDpd1.ToArray();
        }

        store.ProfileRevision = 9;
        using var restoredSameDevice = Device();
        var replay = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, restoredSameDevice, new DurablePersistence(store),
            2_000_000_100, 2_000_086_500, 2_000_172_900,
            new FillRandom(0xff), default);
        Assert.Equal(firstDpd, replay.IssuedDevice!.CanonicalDpd1.ToArray());
        Assert.Single(store.NonceLedgerKeys);
        Assert.Equal(1, store.PendingWrites);
        Assert.Equal(1, store.VerifiedCasWrites);
    }

    [Fact]
    public async Task DurableVerifiedReplay_RestoresWithoutRecoveryAuthority()
    {
        byte[] dpa;
        byte[] drs;
        byte[] firstDpd;
        var store = new DurableState();
        using var device = Device();
        using (var recovery = Recovery(Network))
        {
            var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
                recovery, 1_900_000_000, 1, new FillRandom(0xa1));
            dpa = account.CanonicalDpa1.ToArray();
            drs = account.CanonicalDrs1.ToArray();
            var first = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery, account, device, new DurablePersistence(store),
                1_900_000_100, 1_900_086_500, 1_900_172_900,
                new FillRandom(0xb1, 0xb2, 0xb3), default);
            firstDpd = first.IssuedDevice!.CanonicalDpd1.ToArray();
        }

        var restored = await Dnp1IdentityAuthoringV1.RestoreGenesisDeviceAsync(
            dpa,
            drs,
            device,
            new DurablePersistence(store),
            2_000_000_100);

        Assert.Equal(GenesisDeviceIssuanceStatus.Issued, restored.Status);
        Assert.Equal(firstDpd, restored.IssuedDevice!.CanonicalDpd1.ToArray());
        Assert.Equal(1, store.PendingWrites);
        Assert.Equal(1, store.VerifiedCasWrites);
    }

    [Fact]
    public void AuthoredGenesisAccount_RestoresWithoutRecoveryAuthority()
    {
        byte[] dpa;
        byte[] drs;
        DeepAccountIdentityCapability expected;
        using (var recovery = Recovery(Network))
        {
            var authored = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
                recovery, 1_900_000_000, 1, new FillRandom(0xa1));
            dpa = authored.CanonicalDpa1.ToArray();
            drs = authored.CanonicalDrs1.ToArray();
            expected = authored.AccountIdentity;
        }

        var restored = Dnp1IdentityAuthoringV1.RestoreGenesisAccount(
            dpa, drs, 2_000_000_000);

        Assert.Equal(expected, restored.AccountIdentity);
        Assert.Equal(dpa, restored.CanonicalDpa1.ToArray());
        Assert.Equal(drs, restored.CanonicalDrs1.ToArray());
    }

    [Fact]
    public async Task DurableVerifiedReplay_DoesNotDependOnRotatedCurrentProfile()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        var store = new DurableState();
        using var device = Device();
        var first = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, device, new DurablePersistence(store),
            1_900_000_100, 1_900_086_500, 1_900_172_900,
            new FillRandom(0xb1, 0xb2, 0xb3), default);
        var profileReadsAfterCommit = store.ProfileReads;

        // This profile is intentionally invalid for new issuance. Exact replay must
        // resolve the retained key IDs in its authenticated material without reading it.
        store.Fault = PersistenceFault.CollidingKeyRoles;
        var replay = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, device, new DurablePersistence(store),
            2_000_000_100, 2_000_086_500, 2_000_172_900,
            FailIfRandom.Instance, default);

        Assert.Equal(first.IssuedDevice!.CanonicalDpd1.ToArray(),
            replay.IssuedDevice!.CanonicalDpd1.ToArray());
        Assert.Equal(profileReadsAfterCommit, store.ProfileReads);
        Assert.Equal(1, store.PendingWrites);
        Assert.Equal(1, store.VerifiedCasWrites);
    }

    [Fact]
    public async Task ExistingDeviceSubject_RejectsDifferentLocalIntentWithoutNewOperation()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        var store = new DurableState();
        using (var first = Device())
        {
            await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery, account, first, new DurablePersistence(store),
                1_900_000_100, 1_900_086_500, 1_900_172_900,
                new FillRandom(0xb1, 0xb2, 0xb3), default);
        }

        using var substitutedIntent = new OwnedGenesisDeviceSecrets(
            Enumerable.Range(65, 32).Select(static value => (byte)value).ToArray(),
            Enumerable.Range(97, 32).Select(static value => (byte)value).ToArray(),
            Enumerable.Repeat((byte)0xd1, 32).ToArray(),
            Enumerable.Repeat((byte)0xf2, 32).ToArray());
        await Assert.ThrowsAsync<RecordException>(async () =>
            await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery, account, substitutedIntent, new DurablePersistence(store),
                2_000_000_100, 2_000_086_500, 2_000_172_900,
                FailIfRandom.Instance, default));

        Assert.Equal(1, store.PendingWrites);
        Assert.Equal(1, store.VerifiedCasWrites);
        Assert.Single(store.NonceLedgerKeys);
    }

    [Fact]
    public async Task DurableNonceLedger_RejectsSameNonceForDifferentDeviceAcrossRestart()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        var store = new DurableState();
        using var first = Device();
        await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, first, new DurablePersistence(store),
            1_900_000_100, 1_900_086_500, 1_900_172_900,
            new FillRandom(0xb1, 0xb2, 0xb3), default);
        using var second = new OwnedGenesisDeviceSecrets(
            Enumerable.Range(65, 32).Select(static value => (byte)value).ToArray(),
            Enumerable.Range(97, 32).Select(static value => (byte)value).ToArray(),
            Enumerable.Repeat((byte)0xd2, 32).ToArray(),
            Enumerable.Repeat((byte)0xe2, 32).ToArray());

        await Assert.ThrowsAsync<RecordException>(async () =>
            await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery, account, second, new DurablePersistence(store),
                1_900_000_101, 1_900_086_501, 1_900_172_901,
                new FillRandom(0xc1, 0xc2, 0xb3), default));
        Assert.Single(store.NonceLedgerKeys);
        Assert.Equal(1, store.PendingWrites);
    }

    [Fact]
    public async Task CrashAfterPending_ResumesExactPersistedOperationWithoutNewRandomness()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var store = new DurableState { Fault = PersistenceFault.CrashAfterPendingReserve };

        await Assert.ThrowsAsync<SimulatedCrashException>(async () =>
            await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery, account, device, new DurablePersistence(store),
                1_900_000_100, 1_900_086_500, 1_900_172_900,
                new FillRandom(0xb1, 0xb2, 0xb3), default));
        store.Fault = PersistenceFault.None;

        var replay = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, device, new DurablePersistence(store),
            1_900_000_100, 1_900_086_500, 1_900_172_900,
            FailIfRandom.Instance, default);
        Assert.Equal(GenesisDeviceIssuanceStatus.Issued, replay.Status);
        Assert.Equal(1, store.PendingWrites);
        Assert.Equal(1, store.VerifiedCasWrites);
        Assert.Single(store.NonceLedgerKeys);
    }

    [Fact]
    public async Task CrashAfterVerifiedCas_RestartReturnsExactCommittedWinner()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var store = new DurableState { Fault = PersistenceFault.CrashAfterVerifiedCas };

        await Assert.ThrowsAsync<SimulatedCrashException>(async () =>
            await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery, account, device, new DurablePersistence(store),
                1_900_000_100, 1_900_086_500, 1_900_172_900,
                new FillRandom(0xb1, 0xb2, 0xb3), default));
        store.Fault = PersistenceFault.None;
        var replay = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, device, new DurablePersistence(store),
            1_900_000_100, 1_900_086_500, 1_900_172_900,
            FailIfRandom.Instance, default);

        Assert.Equal(GenesisDeviceIssuanceStatus.Issued, replay.Status);
        Assert.Equal(1, store.PendingWrites);
        Assert.Equal(1, store.VerifiedCasWrites);
        Assert.Equal(1UL, replay.IssuedDevice!.SubjectCasReceipt.SubjectRevision);
    }

    [Fact]
    public async Task ConcurrentSameDeviceSubject_HasOneWinnerAndOneExactReplay()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var firstDevice = Device();
        using var secondDevice = Device();
        var store = new DurableState();

        var first = Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, firstDevice, new DurablePersistence(store),
            1_900_000_100, 1_900_086_500, 1_900_172_900,
            new FillRandom(0xb1, 0xb2, 0xb3), default).AsTask();
        var second = Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, secondDevice, new DurablePersistence(store),
            1_900_000_100, 1_900_086_500, 1_900_172_900,
            new FillRandom(0xc1, 0xc2, 0xc3), default).AsTask();
        var results = await Task.WhenAll(first, second);

        Assert.Equal(
            results[0].IssuedDevice!.CanonicalDpd1.ToArray(),
            results[1].IssuedDevice!.CanonicalDpd1.ToArray());
        Assert.Equal(1, store.PendingWrites);
        Assert.Equal(1, store.VerifiedCasWrites);
        Assert.Single(store.NonceLedgerKeys);
    }

    [Fact]
    public async Task StaleProfile_AbortsPendingAndRetryCannotRegenerateOperation()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var store = new DurableState { Fault = PersistenceFault.ProfileMovesBeforeCas };

        await Assert.ThrowsAsync<RecordException>(async () =>
            await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery, account, device, new DurablePersistence(store),
                1_900_000_100, 1_900_086_500, 1_900_172_900,
                new FillRandom(0xb1, 0xb2, 0xb3), default));
        Assert.Equal(1, store.AbortedWrites);
        store.Fault = PersistenceFault.None;
        await Assert.ThrowsAsync<RecordException>(async () =>
            await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery, account, device, new DurablePersistence(store),
                1_900_000_100, 1_900_086_500, 1_900_172_900,
                FailIfRandom.Instance, default));
        Assert.Equal(1, store.PendingWrites);
        Assert.Single(store.NonceLedgerKeys);
    }

    [Fact]
    public void PersistedOwnedSecrets_ZeroEveryInputOnValidationFailure()
    {
        var signing = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var agreement = Enumerable.Repeat((byte)0x22, 32).ToArray();
        var deviceId = new byte[31];
        var revocation = Enumerable.Repeat((byte)0x44, 32).ToArray();

        Assert.Throws<ArgumentException>(() =>
            OwnedPersistedDeviceIdentitySecrets.TakeOwnership(
                signing, agreement, deviceId, revocation));
        Assert.All(signing, static value => Assert.Equal(0, value));
        Assert.All(agreement, static value => Assert.Equal(0, value));
        Assert.All(deviceId, static value => Assert.Equal(0, value));
        Assert.All(revocation, static value => Assert.Equal(0, value));
    }

    [Theory]
    [InlineData(PersistenceFault.CollidingKeyRoles)]
    [InlineData(PersistenceFault.ProfileMovesBeforeCas)]
    [InlineData(PersistenceFault.CorruptPendingEvidence)]
    [InlineData(PersistenceFault.CorruptVerifiedEvidence)]
    public async Task PersistenceFaults_FailClosedBeforeIssuedResult(PersistenceFault fault)
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var store = new DurableState { Fault = fault };

        await Assert.ThrowsAsync<RecordException>(async () =>
            await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery, account, device, new DurablePersistence(store),
                1_900_000_100, 1_900_086_500, 1_900_172_900,
                new FillRandom(0xb1, 0xb2, 0xb3), default));
    }

    [Fact]
    public async Task AccountAndCurrentDrs_CannotBeCrossSourced()
    {
        using var first = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            first, 1_900_000_000, 1, new FillRandom(0xa1));
        var otherNetwork = Network.ToArray();
        otherNetwork[0] ^= 0x40;
        using var second = Recovery(otherNetwork);
        using var device = Device();
        var store = new DurableState();

        await Assert.ThrowsAsync<RecordException>(async () =>
            await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                second, account, device, new DurablePersistence(store),
                1_900_000_100, 1_900_086_500, 1_900_172_900));
        Assert.Equal(0, store.ProfileReads);
    }

    [Fact]
    public void PublicSurface_IsTypedSealedAndHasNoSignerOrSecretEscapeHatches()
    {
        Assert.DoesNotContain(
            typeof(DeepRecoveryV1).Assembly.GetCustomAttributes<
                System.Runtime.CompilerServices.InternalsVisibleToAttribute>(),
            static attribute => string.Equals(
                attribute.AssemblyName,
                "Deep.Protocol.MembershipRoutes",
                StringComparison.Ordinal));
        var authorMethods = typeof(Dnp1IdentityAuthoringV1)
            .GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly);
        Assert.Equal(
            new[]
            {
                "AuthorGenesisAccount",
                "IssueGenesisDeviceAsync",
                "RestoreGenesisAccount",
                "RestoreGenesisDeviceAsync"
            },
            authorMethods.Select(static method => method.Name).Order().ToArray());
        Assert.All(authorMethods.SelectMany(static method => method.GetParameters()),
            static parameter => Assert.False(typeof(Delegate).IsAssignableFrom(parameter.ParameterType)));
        Assert.DoesNotContain(
            typeof(DeepRecoveryAccountCapabilities).GetMethods(BindingFlags.Public | BindingFlags.Instance),
            static method => method.Name.StartsWith("Sign", StringComparison.Ordinal));

        foreach (var type in new[]
        {
            typeof(GenesisAccountAuthoringResult), typeof(PendingGenesisDeviceIntent),
            typeof(IssuedGenesisDevice), typeof(GenesisDeviceIssuanceResult),
            typeof(DurableDxpVerifiedReceipt)
        })
        {
            Assert.True(type.IsSealed);
            Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
            Assert.DoesNotContain(type.GetProperties(BindingFlags.Public | BindingFlags.Instance),
                static property => property.PropertyType == typeof(OwnedRecord) ||
                    property.PropertyType == typeof(VerifiedIdentityRelative) ||
                    property.PropertyType == typeof(DeepRecoveryAccountCapabilities));
        }

        Assert.Equal(typeof(VerifiedDeviceRelative),
            typeof(IssuedGenesisDevice).GetProperty(
                nameof(IssuedGenesisDevice.Verified))!.PropertyType);

        Assert.DoesNotContain(
            typeof(OwnedGenesisDeviceSecrets).GetProperties(BindingFlags.Public | BindingFlags.Instance),
            static property => property.Name.Contains("Private", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Contains("Seed", StringComparison.OrdinalIgnoreCase));
        var friendCallableDeviceSigners = typeof(OwnedGenesisDeviceSecrets)
            .GetMethods(BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(static method => (method.IsAssembly || method.IsFamilyOrAssembly)
                && method.Name.StartsWith("Sign", StringComparison.Ordinal))
            .ToArray();
        var deviceSigner = Assert.Single(friendCallableDeviceSigners);
        Assert.Equal("SignGenesisDeviceCertificate", deviceSigner.Name);
        Assert.Contains(deviceSigner.GetParameters(), static parameter =>
            parameter.ParameterType.Name == "GenesisDeviceCertificateSigningIntent");
        Assert.DoesNotContain(deviceSigner.GetParameters(), static parameter =>
            parameter.ParameterType.Name == "OwnedRecord"
            || parameter.ParameterType == typeof(ReadOnlySpan<byte>)
            || parameter.ParameterType == typeof(byte[]));
        foreach (var intentType in typeof(Dnp1IdentityAuthoringV1).GetNestedTypes(
                     BindingFlags.NonPublic).Where(static type =>
                     type.Name.EndsWith("SigningIntent", StringComparison.Ordinal)))
        {
            Assert.True(intentType.IsSealed);
            Assert.Empty(intentType.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        }
        Assert.True(typeof(LocalDeviceIdentityIntent).IsPublic);
        Assert.True(typeof(LocalDeviceIdentityIntent).IsSealed);
        Assert.Empty(typeof(LocalDeviceIdentityIntent).GetConstructors(
            BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(OwnedPersistedDeviceIdentitySecrets).GetConstructors(
            BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(
            typeof(OwnedPersistedDeviceIdentitySecrets).GetProperties(
                BindingFlags.Public | BindingFlags.Instance),
            static property => property.PropertyType == typeof(byte[]) ||
                property.PropertyType == typeof(ReadOnlyMemory<byte>));
        Assert.DoesNotContain(
            typeof(IssuedGenesisDevice).GetProperties(BindingFlags.Public | BindingFlags.Instance),
            static property => property.Name.Contains("Proof", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Contains("Dxp", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task GenesisResultsExposeVerifierMintedFactsForPublicApplicationComposition()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);

        var identity = issued.Verified.Identity;
        Assert.Equal(account.CanonicalDpa1.ToArray(),
            identity.Account.Certificate.CanonicalBytes.ToArray());
        Assert.Equal(issued.CanonicalDpd1.ToArray(),
            issued.Verified.Certificate.CanonicalBytes.ToArray());
        var closure = ApplicationCoreVerifier.CreateIdentityClosure(
            identity, [issued.Verified]);
        Assert.Same(identity.Account, closure.Account);
        Assert.Single(closure.ActiveDevices);
        var currentDirectory = recovery.AuthorGenesisDmd1(closure, 1_900_000_200);
        Assert.False(currentDirectory.ForkLatched);
        Assert.Equal(1UL, currentDirectory.Head.Record.DirectoryGeneration);
        Assert.Equal(issued.Verified.Certificate.DeviceId.ToArray(),
            Assert.Single(currentDirectory.Head.Record.ActiveDevices).DeviceId.ToArray());
        using var dpk2Authority = device.CreateDpk2AuthoringAuthority(issued.Verified);
        var dpk2Context = new Dpk2AuthoringContext(
            currentDirectory, 1, 1, 1,
            1_900_000_300, 1_900_000_250, 1_900_086_700);
        Assert.Same(currentDirectory, dpk2Context.CurrentDirectory);

        var wrongNetwork = Network.ToArray();
        wrongNetwork[0] ^= 0x80;
        using var wrongRecovery = Recovery(wrongNetwork);
        Assert.Throws<RecordException>(() =>
            wrongRecovery.AuthorGenesisDmd1(closure, 1_900_000_200));
        Assert.Empty(typeof(VerifiedIdentityRelative).GetConstructors());
        Assert.Empty(typeof(VerifiedDeviceRelative).GetConstructors());
    }

    [Fact]
    public void StoreLocalIntent_CreateExportRestore_IsOwnedAndNeverMintsAuthority()
    {
        using var recovery = Recovery(Network);
        using var created = Device();
        var expectedIntent = created.CreateLocalIntent(recovery.AccountIdentity);
        using var persisted = created.ExportOwnedPersistenceCopy();
        var signing = new byte[32];
        var agreement = new byte[32];
        var deviceId = new byte[32];
        var revocation = new byte[32];
        try
        {
            persisted.CopyTo(signing, agreement, deviceId, revocation);
            Assert.Equal(expectedIntent.DeviceId.Bytes.ToArray(), deviceId);
            Assert.Equal(expectedIntent.RevocationHandle.Bytes.ToArray(), revocation);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signing);
            CryptographicOperations.ZeroMemory(agreement);
            CryptographicOperations.ZeroMemory(deviceId);
            CryptographicOperations.ZeroMemory(revocation);
        }

        using var restored = OwnedGenesisDeviceSecrets.RestoreFromPersistedOwnedSecrets(persisted);
        Assert.Equal(expectedIntent, restored.CreateLocalIntent(recovery.AccountIdentity));
        Assert.Throws<ObjectDisposedException>(() =>
            persisted.CopyTo(new byte[32], new byte[32], new byte[32], new byte[32]));
        Assert.DoesNotContain(
            typeof(LocalDeviceIdentityIntent).GetMethods(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static),
            static method => method.ReturnType == typeof(IssuedGenesisDevice));
    }

    [Fact]
    public void PersistedOwnedSecrets_PartialValidationFailureZeroesEverySuppliedArray()
    {
        var signing = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var agreement = Enumerable.Repeat((byte)0x22, 31).ToArray();
        var deviceId = Enumerable.Repeat((byte)0x33, 32).ToArray();
        var revocation = Enumerable.Repeat((byte)0x44, 32).ToArray();

        Assert.Throws<ArgumentException>(() =>
            OwnedPersistedDeviceIdentitySecrets.TakeOwnership(
                signing, agreement, deviceId, revocation));
        Assert.All(signing, static value => Assert.Equal(0, value));
        Assert.All(agreement, static value => Assert.Equal(0, value));
        Assert.All(deviceId, static value => Assert.Equal(0, value));
        Assert.All(revocation, static value => Assert.Equal(0, value));
    }

    [Fact]
    public void PersistedOwnedSecrets_SuccessConsumesAndZeroesCallerArrays()
    {
        var signing = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var agreement = Enumerable.Repeat((byte)0x22, 32).ToArray();
        var deviceId = Enumerable.Repeat((byte)0x33, 32).ToArray();
        var revocation = Enumerable.Repeat((byte)0x44, 32).ToArray();
        using var owned = OwnedPersistedDeviceIdentitySecrets.TakeOwnership(
            signing, agreement, deviceId, revocation);

        Assert.All(signing, static value => Assert.Equal(0, value));
        Assert.All(agreement, static value => Assert.Equal(0, value));
        Assert.All(deviceId, static value => Assert.Equal(0, value));
        Assert.All(revocation, static value => Assert.Equal(0, value));
        var copiedSigning = new byte[32];
        var copiedAgreement = new byte[32];
        var copiedDeviceId = new byte[32];
        var copiedRevocation = new byte[32];
        try
        {
            owned.CopyTo(copiedSigning, copiedAgreement, copiedDeviceId, copiedRevocation);
            Assert.All(copiedSigning, static value => Assert.Equal((byte)0x11, value));
            Assert.All(copiedAgreement, static value => Assert.Equal((byte)0x22, value));
            Assert.All(copiedDeviceId, static value => Assert.Equal((byte)0x33, value));
            Assert.All(copiedRevocation, static value => Assert.Equal((byte)0x44, value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copiedSigning);
            CryptographicOperations.ZeroMemory(copiedAgreement);
            CryptographicOperations.ZeroMemory(copiedDeviceId);
            CryptographicOperations.ZeroMemory(copiedRevocation);
        }
    }

    [Fact]
    public void RecoveryCapability_PartialOwnershipFailureZeroesEverySuppliedSecret()
    {
        var values = new[]
        {
            Enumerable.Repeat((byte)0x11, 32).ToArray(),
            Enumerable.Repeat((byte)0x22, 32).ToArray(),
            Enumerable.Repeat((byte)0x33, 32).ToArray(),
            Enumerable.Repeat((byte)0x44, 32).ToArray(),
            Enumerable.Repeat((byte)0x55, 32).ToArray(),
            Enumerable.Repeat((byte)0x66, 15).ToArray(),
            Enumerable.Repeat((byte)0x77, 32).ToArray()
        };

        Assert.Throws<ArgumentException>(() => new DeepRecoveryAccountCapabilities(
            Network, 1, values[0], values[1], values[2], values[3],
            values[4], values[5], values[6]));
        Assert.All(values, static value =>
            Assert.All(value, static item => Assert.Equal(0, item)));
    }

    [Fact]
    public void OwnedDeviceSecrets_ZeroizeAndRejectEverySecretOperationAfterDispose()
    {
        var device = Device();
        device.Dispose();

        Assert.Throws<ObjectDisposedException>(() => device.ExportOwnedPersistenceCopy());
        Assert.Throws<ObjectDisposedException>(() => device.CreatePossessionProof(new byte[168]));
        foreach (var name in new[] { "signingSeed", "agreementPrivateScalar" })
        {
            var field = typeof(OwnedGenesisDeviceSecrets).GetField(
                name, BindingFlags.NonPublic | BindingFlags.Instance);
            var secret = Assert.IsType<byte[]>(field!.GetValue(device));
            Assert.All(secret, static value => Assert.Equal(0, value));
        }
    }

    [Fact]
    public async Task DeviceAgreementAuthority_BindsExactIssuedDeviceDirectoryOperationAndPeer()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var directory = ExactDirectory(account, issued);
        var operation = SHA256.HashData("DPH2/initiator/test-operation"u8);
        var peerPrivate = Enumerable.Repeat((byte)0x71, 32).ToArray();
        var peerPublic = new byte[32];
        var expected = new byte[32];
        try
        {
            OwnedSodiumX25519.DerivePublicKey(peerPrivate, peerPublic);
            using var authority = device.CreateAgreementAuthority(issued.Verified);
            using var lease = authority.OpenOperation(
                CurrentDirectory(directory),
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                operation,
                peerPublic);

            Assert.Equal(issued.Verified.Certificate.NetworkId.ToArray(), authority.NetworkId.ToArray());
            Assert.Equal(issued.Verified.Certificate.AccountHash.ToArray(), authority.AccountId.ToArray());
            Assert.Equal(issued.Verified.Certificate.DeviceId.ToArray(), authority.DeviceId.ToArray());
            Assert.Equal(issued.Verified.Certificate.CanonicalHash.ToArray(), authority.ExactDpd1Hash.ToArray());
            Assert.Equal(directory.Record.RecordHash.ToArray(), lease.ExactDirectoryHash.ToArray());
            Assert.Equal(operation, lease.OperationBinding.ToArray());
            Assert.Equal(LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1, lease.Purpose);
            Assert.Equal(authority.NetworkId.ToArray(), lease.NetworkId.ToArray());
            Assert.Equal(authority.AccountId.ToArray(), lease.AccountId.ToArray());
            Assert.Equal(authority.AccountGeneration, lease.AccountGeneration);
            Assert.Equal(authority.DeviceId.ToArray(), lease.DeviceId.ToArray());
            Assert.Equal(authority.DeviceGeneration, lease.DeviceGeneration);
            Assert.Equal(authority.ExactDpd1Hash.ToArray(), lease.ExactDpd1Hash.ToArray());

            OwnedSodiumX25519.Agree(peerPrivate, authority.AgreementPublicKey.Span, expected);
            using var shared = lease.AgreeOnce(
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                operation);
            Assert.True(shared.Consume(secret =>
                CryptographicOperations.FixedTimeEquals(secret, expected)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    [Fact]
    public async Task DeviceAgreementLease_HostileBindingDoesNotConsumeButReplayFailsClosed()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var operation = SHA256.HashData("DPH2/responder/test-operation"u8);
        var wrongOperation = operation.ToArray();
        wrongOperation[0] ^= 0x80;
        var peerPrivate = Enumerable.Repeat((byte)0x72, 32).ToArray();
        var peerPublic = new byte[32];
        try
        {
            OwnedSodiumX25519.DerivePublicKey(peerPrivate, peerPublic);
            using var authority = device.CreateAgreementAuthority(issued.Verified);
            Assert.Throws<ArgumentOutOfRangeException>(() => authority.OpenOperation(
                CurrentDirectory(ExactDirectory(account, issued)),
                (LocalDeviceX25519AgreementPurpose)0xff,
                operation,
                peerPublic));
            using var lease = authority.OpenOperation(
                CurrentDirectory(ExactDirectory(account, issued)),
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                operation,
                peerPublic);

            Assert.Throws<RecordException>(() => lease.AgreeOnce(
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                operation));
            Assert.Throws<RecordException>(() => lease.AgreeOnce(
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                wrongOperation));
            Assert.Throws<ArgumentException>(() => lease.AgreeOnce(
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                new byte[32]));
            var wrongPeer = peerPublic.ToArray();
            wrongPeer[0] ^= 0x40;
            Assert.Throws<RecordException>(() => lease.AgreeOnceForExpectedPeer(
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                operation,
                wrongPeer));

            using var shared = lease.AgreeOnceForExpectedPeer(
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                operation,
                peerPublic);
            Assert.Throws<InvalidOperationException>(() => lease.AgreeOnce(
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                operation));

            var disposedOperation = SHA256.HashData("DPH2/disposed-lease/test-operation"u8);
            var disposedLease = authority.OpenOperation(
                CurrentDirectory(ExactDirectory(account, issued)),
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                disposedOperation,
                peerPublic);
            disposedLease.Dispose();
            Assert.Throws<InvalidOperationException>(() => disposedLease.AgreeOnce(
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                disposedOperation));

            authority.Dispose();
            Assert.Throws<ObjectDisposedException>(() => authority.OpenOperation(
                CurrentDirectory(ExactDirectory(account, issued)),
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                SHA256.HashData("DPH2/disposed-authority/test-operation"u8),
                peerPublic));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
        }
    }

    [Fact]
    public async Task DeviceAgreementAuthority_RejectsWrongOwnerTamperedDirectoryAndInvalidPeer()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        using var wrongDevice = new OwnedGenesisDeviceSecrets(
            Enumerable.Repeat((byte)0x11, 32).ToArray(),
            Enumerable.Repeat((byte)0x22, 32).ToArray(),
            Enumerable.Repeat((byte)0xd2, 32).ToArray(),
            Enumerable.Repeat((byte)0xe2, 32).ToArray());
        Assert.Throws<RecordException>(() => wrongDevice.CreateAgreementAuthority(issued.Verified));

        using var authority = device.CreateAgreementAuthority(issued.Verified);
        var operation = SHA256.HashData("DPH2/tamper/test-operation"u8);
        var peerPrivate = Enumerable.Repeat((byte)0x73, 32).ToArray();
        var peerPublic = new byte[32];
        try
        {
            OwnedSodiumX25519.DerivePublicKey(peerPrivate, peerPublic);
            var tamperedHash = issued.Verified.Certificate.CanonicalHash.ToArray();
            tamperedHash[0] ^= 0x40;
            var tamperedDirectory = ExactDirectory(account, issued, dpdHash: tamperedHash);

            Assert.Throws<RecordException>(() => authority.OpenOperation(
                CurrentDirectory(tamperedDirectory),
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                operation,
                peerPublic));
            Assert.Throws<ArgumentException>(() => authority.OpenOperation(
                CurrentDirectory(ExactDirectory(account, issued)),
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                operation,
                new byte[32]));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
        }
    }

    [Fact]
    public async Task DeviceAgreementSecretsAndLeaseBindings_AreZeroizedOnEveryTerminalPath()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var operation = SHA256.HashData("DPH2/zeroization/test-operation"u8);
        var peerPrivate = Enumerable.Repeat((byte)0x74, 32).ToArray();
        var peerPublic = new byte[32];
        try
        {
            OwnedSodiumX25519.DerivePublicKey(peerPrivate, peerPublic);
            var authority = device.CreateAgreementAuthority(issued.Verified);
            var authoritySecret = PrivateArray(authority, "_agreementPrivateScalar");
            var lease = authority.OpenOperation(
                CurrentDirectory(ExactDirectory(account, issued)),
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                operation,
                peerPublic);
            var leaseOperation = PrivateArray(lease, "_operationBinding");
            var leaseDirectory = PrivateArray(lease, "_directoryHash");
            var leasePeer = PrivateArray(lease, "_peerPublicKey");

            using var shared = lease.AgreeOnce(
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                operation);
            Assert.All(leaseOperation, static value => Assert.Equal(0, value));
            Assert.All(leaseDirectory, static value => Assert.Equal(0, value));
            Assert.All(leasePeer, static value => Assert.Equal(0, value));
            Assert.Null(typeof(LocalDeviceX25519AgreementLease)
                .GetField("_agree", BindingFlags.Instance | BindingFlags.NonPublic)!
                .GetValue(lease));
            var sharedBytes = PrivateArray(shared, "_sharedSecret");
            Assert.Throws<SimulatedCrashException>(() => shared.Consume<bool>(static _ =>
                throw new SimulatedCrashException()));
            Assert.All(sharedBytes, static value => Assert.Equal(0, value));
            Assert.Throws<ObjectDisposedException>(() => shared.Consume(static _ => true));

            lease.Dispose();

            authority.Dispose();
            Assert.All(authoritySecret, static value => Assert.Equal(0, value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
        }
    }

    [Fact]
    public void DeviceAgreementPublicSurface_HasNoSecretProviderOrCallerKeyEscapeHatch()
    {
        foreach (var type in new[]
        {
            typeof(LocalDeviceX25519AgreementAuthority),
            typeof(LocalDeviceX25519AgreementLease)
        })
        {
            Assert.True(type.IsPublic);
            Assert.True(type.IsSealed);
            Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
            Assert.DoesNotContain(type.GetProperties(BindingFlags.Public | BindingFlags.Instance),
                static property => property.Name.Contains("Private", StringComparison.OrdinalIgnoreCase) ||
                    property.Name.Contains("Secret", StringComparison.OrdinalIgnoreCase) ||
                    property.PropertyType == typeof(byte[]));
            Assert.DoesNotContain(type.GetMethods(BindingFlags.Public | BindingFlags.Instance |
                BindingFlags.Static | BindingFlags.DeclaredOnly), static method =>
                    method.ReturnType == typeof(byte[]) ||
                    method.ReturnType == typeof(LocalDeviceX25519SharedSecret) ||
                    method.Name != nameof(LocalDeviceX25519AgreementAuthority.OpenOperation) &&
                    method.GetParameters().Any(parameter =>
                        parameter.ParameterType == typeof(ReadOnlySpan<byte>) ||
                        typeof(Delegate).IsAssignableFrom(parameter.ParameterType)));
        }

        Assert.False(typeof(LocalDeviceX25519SharedSecret).IsPublic);
        var factory = Assert.Single(typeof(OwnedGenesisDeviceSecrets).GetMethods(
            BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly),
            static method => method.Name == "CreateAgreementAuthority");
        Assert.Equal(typeof(LocalDeviceX25519AgreementAuthority), factory.ReturnType);
        Assert.Equal(typeof(VerifiedDeviceRelative), Assert.Single(factory.GetParameters()).ParameterType);
        var openOperation = Assert.Single(typeof(LocalDeviceX25519AgreementAuthority).GetMethods(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly),
            static method => method.Name == "OpenOperation");
        Assert.Contains(openOperation.GetParameters(), static parameter =>
            parameter.ParameterType == typeof(Dmd1LineageState));
        Assert.DoesNotContain(openOperation.GetParameters(), static parameter =>
            parameter.ParameterType == typeof(VerifiedDmd1) ||
            parameter.ParameterType == typeof(bool));
        var agreeOnce = Assert.Single(typeof(LocalDeviceX25519AgreementLease).GetMethods(
            BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly),
            static method => method.Name == "AgreeOnce");
        Assert.DoesNotContain(agreeOnce.GetParameters(), static parameter =>
            parameter.Name!.Contains("peer", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            typeof(LocalDeviceX25519AgreementAuthority).GetMethods(
                BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly),
            static method => method.Name == "Agree" && method.IsAssembly);
        var publicLeaseProducers = typeof(DeepIdentityCrypto).Assembly.GetExportedTypes()
            .SelectMany(static type => type.GetMethods(
                BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance))
            .Where(static method => method.ReturnType == typeof(LocalDeviceX25519AgreementLease))
            .ToArray();
        Assert.Same(openOperation, Assert.Single(publicLeaseProducers));
        Assert.DoesNotContain(
            typeof(DeepIdentityCrypto).Assembly.GetExportedTypes().SelectMany(static type =>
                type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance)),
            static method => method.ReturnType == typeof(LocalDeviceX25519AgreementAuthority));
    }

    [Fact]
    public void X25519Agreement_LowOrderPeerFailsClosedAndZeroesOutput()
    {
        var privateScalar = Enumerable.Repeat((byte)0x75, 32).ToArray();
        var lowOrderPeer = new byte[32];
        lowOrderPeer[0] = 1;
        var output = Enumerable.Repeat((byte)0xa5, 32).ToArray();
        try
        {
            Assert.Throws<CryptographicException>(() =>
                OwnedSodiumX25519.Agree(privateScalar, lowOrderPeer, output));
            Assert.All(output, static value => Assert.Equal(0, value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateScalar);
        }
    }

    [Fact]
    public async Task DeviceAgreementAuthority_SecondEnrolledDeviceAndCurrentSuccessorGenerationWork()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        var store = new DurableState();
        using var firstOwner = Device();
        using var secondOwner = OtherDevice();
        var first = await IssueDevice(recovery, account, firstOwner, store);
        var second = await IssueDevice(recovery, account, secondOwner, store, 0x10);
        var enrolledDirectory = ExactDirectory(account, [first.Verified, second.Verified], 1, null);
        var peerPrivate = Enumerable.Repeat((byte)0x76, 32).ToArray();
        var peerPublic = new byte[32];
        try
        {
            OwnedSodiumX25519.DerivePublicKey(peerPrivate, peerPublic);
            using var secondAuthority = secondOwner.CreateAgreementAuthority(second.Verified);
            using var secondLease = secondAuthority.OpenOperation(
                CurrentDirectory(enrolledDirectory),
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                SHA256.HashData("DPH2/second-enrolled-device"u8),
                peerPublic);
            using var secondShared = secondLease.AgreeOnce(
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                SHA256.HashData("DPH2/second-enrolled-device"u8));

            using var successorOwner = SuccessorDevice(first.Verified.Certificate.DeviceId.Span);
            var successor = CreateSuccessorDevice(recovery, account, first.Verified, successorOwner);
            var successorDirectory = ExactDirectory(
                account,
                [successor, second.Verified],
                2,
                enrolledDirectory.Record.RecordHash.ToArray());
            var successorState = ApplicationCoreVerifier.PrepareDmd1Transition(
                CurrentDirectory(enrolledDirectory), successorDirectory).Next;
            using var successorAuthority = successorOwner.CreateAgreementAuthority(successor);
            var successorOperation = SHA256.HashData("DPH2/current-device-generation-2"u8);
            using var successorLease = successorAuthority.OpenOperation(
                successorState,
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                successorOperation,
                peerPublic);
            Assert.Equal(successor.Certificate.CanonicalHash.ToArray(),
                successorLease.ExactDpd1Hash.ToArray());
            using var successorShared = successorLease.AgreeOnce(
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                successorOperation);

            Assert.Equal(2UL, successorAuthority.DeviceGeneration);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
        }
    }

    [Fact]
    public async Task DeviceAgreementAuthority_OldSupersededOmittedAndWrongDpdNeverGetLease()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        var store = new DurableState();
        using var oldOwner = Device();
        using var remainingOwner = OtherDevice();
        var old = await IssueDevice(recovery, account, oldOwner, store);
        var remaining = await IssueDevice(recovery, account, remainingOwner, store, 0x10);
        var priorDirectory = ExactDirectory(account, [old.Verified, remaining.Verified], 1, null);
        using var successorOwner = SuccessorDevice(old.Verified.Certificate.DeviceId.Span);
        var successor = CreateSuccessorDevice(recovery, account, old.Verified, successorOwner);
        var currentDirectory = ExactDirectory(
            account,
            [successor, remaining.Verified],
            2,
            priorDirectory.Record.RecordHash.ToArray());
        var currentState = ApplicationCoreVerifier.PrepareDmd1Transition(
            CurrentDirectory(priorDirectory), currentDirectory).Next;
        var peerPrivate = Enumerable.Repeat((byte)0x77, 32).ToArray();
        var peerPublic = new byte[32];
        try
        {
            OwnedSodiumX25519.DerivePublicKey(peerPrivate, peerPublic);
            using var oldAuthority = oldOwner.CreateAgreementAuthority(old.Verified);
            Assert.Throws<RecordException>(() => oldAuthority.OpenOperation(
                currentState,
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                SHA256.HashData("DPH2/superseded-old-dpd"u8),
                peerPublic));

            var omittedDirectory = ExactDirectory(
                account,
                [remaining.Verified],
                2,
                priorDirectory.Record.RecordHash.ToArray());
            var omittedState = ApplicationCoreVerifier.PrepareDmd1Transition(
                CurrentDirectory(priorDirectory), omittedDirectory).Next;
            Assert.Throws<RecordException>(() => oldAuthority.OpenOperation(
                omittedState,
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                SHA256.HashData("DPH2/revoked-or-omitted-device"u8),
                peerPublic));

            using var successorAuthority = successorOwner.CreateAgreementAuthority(successor);
            var wrongDpdEntry = new DeviceDirectoryEntry(
                successor.Certificate.DeviceId.Span,
                IdentityReference(old.Verified.Certificate));
            var wrongDpdDirectory = ExactDirectory(
                account,
                [successor, remaining.Verified],
                2,
                priorDirectory.Record.RecordHash.ToArray(),
                [wrongDpdEntry, new DeviceDirectoryEntry(
                    remaining.Verified.Certificate.DeviceId.Span,
                    IdentityReference(remaining.Verified.Certificate))]);
            var wrongDpdState = ApplicationCoreVerifier.PrepareDmd1Transition(
                CurrentDirectory(priorDirectory), wrongDpdDirectory).Next;
            Assert.Throws<RecordException>(() => successorAuthority.OpenOperation(
                wrongDpdState,
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                SHA256.HashData("DPH2/wrong-generation-dpd-reference"u8),
                peerPublic));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
        }
    }

    [Fact]
    public async Task DeviceAgreementAuthority_ForkLatchedDirectoryCannotIssueLease()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var genesis = ExactDirectory(account, issued);
        var firstSuccessor = ExactDirectory(
            account, [issued.Verified], 2, genesis.Record.RecordHash.ToArray(), issuedAt: 1_900_000_201);
        var conflictingSuccessor = ExactDirectory(
            account, [issued.Verified], 2, genesis.Record.RecordHash.ToArray(), issuedAt: 1_900_000_202);
        var accepted = ApplicationCoreVerifier.PrepareDmd1Transition(
            CurrentDirectory(genesis), firstSuccessor).Next;
        var forked = ApplicationCoreVerifier.PrepareDmd1Transition(
            accepted, conflictingSuccessor).Next;
        Assert.True(forked.ForkLatched);

        var peerPrivate = Enumerable.Repeat((byte)0x78, 32).ToArray();
        var peerPublic = new byte[32];
        try
        {
            OwnedSodiumX25519.DerivePublicKey(peerPrivate, peerPublic);
            using var authority = device.CreateAgreementAuthority(issued.Verified);
            Assert.Throws<RecordException>(() => authority.OpenOperation(
                forked,
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                SHA256.HashData("DPH2/fork-latched-directory"u8),
                peerPublic));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
        }
    }

    [Fact]
    public async Task DeviceAgreementAuthority_RevocationInLiveIdentityCapabilityFencesExistingAndNewAuthority()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var staleDirectory = CurrentDirectory(ExactDirectory(account, issued));
        using var existingAuthority = device.CreateAgreementAuthority(issued.Verified);

        account.Identity.Authority.Revocations = RevokedState(
            account.Identity.Revocations,
            issued.Verified.Certificate);
        Assert.True(account.Identity.Revocations.Catalog.Contains(
            ArtifactType.Dpd1,
            issued.Verified.Certificate.CanonicalHash.Span));

        var peerPrivate = Enumerable.Repeat((byte)0x7a, 32).ToArray();
        var peerPublic = new byte[32];
        try
        {
            OwnedSodiumX25519.DerivePublicKey(peerPrivate, peerPublic);
            Assert.Throws<RecordException>(() => existingAuthority.OpenOperation(
                staleDirectory,
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                SHA256.HashData("DPH2/revoked-existing-authority"u8),
                peerPublic));
            Assert.Throws<RecordException>(() =>
                device.CreateAgreementAuthority(issued.Verified));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
        }
    }

    [Fact]
    public async Task DeviceAgreementLease_ConcurrentReplayHasExactlyOneWinner()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var operation = SHA256.HashData("DPH2/concurrent-agreement"u8);
        var peerPrivate = Enumerable.Repeat((byte)0x79, 32).ToArray();
        var peerPublic = new byte[32];
        try
        {
            OwnedSodiumX25519.DerivePublicKey(peerPrivate, peerPublic);
            using var authority = device.CreateAgreementAuthority(issued.Verified);
            using var lease = authority.OpenOperation(
                CurrentDirectory(ExactDirectory(account, issued)),
                LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                operation,
                peerPublic);
            LocalDeviceX25519SharedSecret? first = null;
            LocalDeviceX25519SharedSecret? second = null;
            Exception? firstError = null;
            Exception? secondError = null;
            Parallel.Invoke(
                () => Attempt(ref first, ref firstError),
                () => Attempt(ref second, ref secondError));

            var winners = new[] { first, second }.Where(static value => value is not null).ToArray();
            var errors = new[] { firstError, secondError }.Where(static value => value is not null).ToArray();
            Assert.Single(winners);
            Assert.IsType<InvalidOperationException>(Assert.Single(errors));
            winners[0]!.Dispose();

            void Attempt(
                ref LocalDeviceX25519SharedSecret? result,
                ref Exception? error)
            {
                try
                {
                    result = lease.AgreeOnce(
                        LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2,
                        operation);
                }
                catch (Exception exception)
                {
                    error = exception;
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
        }
    }

    private static async Task<IssuedGenesisDevice> IssueDevice(
        DeepRecoveryAccountCapabilities recovery,
        GenesisAccountAuthoringResult account,
        OwnedGenesisDeviceSecrets device,
        DurableState? state = null,
        byte randomOffset = 0)
    {
        var result = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery,
            account,
            device,
            new DurablePersistence(state ?? new DurableState()),
            1_900_000_100,
            1_900_086_500,
            1_900_172_900,
            new FillRandom(
                checked((byte)(0xb1 + randomOffset)),
                checked((byte)(0xb2 + randomOffset)),
                checked((byte)(0xb3 + randomOffset))),
            default);
        return Assert.IsType<IssuedGenesisDevice>(result.IssuedDevice);
    }

    private static VerifiedDmd1 ExactDirectory(
        GenesisAccountAuthoringResult account,
        IssuedGenesisDevice issued,
        byte[]? dpdHash = null)
    {
        if (dpdHash is null)
            return ExactDirectory(account, [issued.Verified], 1, null);
        var certificate = issued.Verified.Certificate;
        return ExactDirectory(
            account,
            [issued.Verified],
            1,
            null,
            [new DeviceDirectoryEntry(
                certificate.DeviceId.Span,
                ApplicationCoreCodec.CreateArtifactReference(
                    (ushort)ArtifactType.Dpd1,
                    checked((uint)certificate.CanonicalBytes.Length),
                    dpdHash))]);
    }

    private static VerifiedDmd1 ExactDirectory(
        GenesisAccountAuthoringResult account,
        IReadOnlyList<VerifiedDeviceRelative> devices,
        ulong generation,
        byte[]? predecessor,
        IReadOnlyList<DeviceDirectoryEntry>? entries = null,
        ulong issuedAt = 1_900_000_200)
    {
        var identity = ApplicationCoreVerifier.CreateIdentityClosure(
            account.Identity,
            devices);
        var directoryEntries = entries ?? devices.Select(static device =>
            new DeviceDirectoryEntry(
                device.Certificate.DeviceId.Span,
                IdentityReference(device.Certificate))).ToArray();
        var record = ApplicationCoreCodec.AuthorDmd1(
            account.Identity.Account.Certificate.NetworkId.Span,
            account.Identity.Account.DeepAccountIdHash.Span,
            account.Identity.Account.Certificate.AccountGeneration,
            IdentityReference(account.Identity.Account.Certificate),
            IdentityReference(account.Identity.Revocations.Snapshot),
            generation,
            predecessor ?? new byte[32],
            directoryEntries,
            issuedAt,
            new byte[64]);
        return new VerifiedDmd1(record, identity);
    }

    private static OwnedGenesisDeviceSecrets OtherDevice() => new(
        Enumerable.Repeat((byte)0x12, 32).ToArray(),
        Enumerable.Repeat((byte)0x23, 32).ToArray(),
        Enumerable.Repeat((byte)0xd2, 32).ToArray(),
        Enumerable.Repeat((byte)0xe2, 32).ToArray());

    private static OwnedGenesisDeviceSecrets SuccessorDevice(ReadOnlySpan<byte> deviceId) => new(
        Enumerable.Repeat((byte)0x13, 32).ToArray(),
        Enumerable.Repeat((byte)0x24, 32).ToArray(),
        deviceId,
        Enumerable.Repeat((byte)0xe3, 32).ToArray());

    private static VerifiedDeviceRelative CreateSuccessorDevice(
        DeepRecoveryAccountCapabilities recovery,
        GenesisAccountAuthoringResult account,
        VerifiedDeviceRelative predecessor,
        OwnedGenesisDeviceSecrets successorOwner)
    {
        var identity = account.Identity;
        var accountRecord = identity.Account;
        var drs = identity.Revocations.Snapshot;
        var fields = RecordDefinitions.Dpd1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength])
            .ToArray();
        fields[0] = accountRecord.Certificate.NetworkId;
        fields[1] = accountRecord.DeepAccountIdHash;
        fields[2] = U64(accountRecord.Certificate.AccountGeneration);
        fields[3] = successorOwner.DeviceId.Bytes;
        fields[4] = U64(predecessor.Certificate.DeviceGeneration + 1);
        fields[5] = successorOwner.SigningPublicKey.Bytes;
        fields[6] = successorOwner.AgreementPublicKey.Bytes;
        fields[7] = successorOwner.RevocationHandle.Bytes;
        fields[8] = U64(0);
        fields[9] = new byte[38];
        fields[10] = IdentityAuthorityVerifier.ComputeKeyHash(
            accountRecord.Certificate.NetworkId.Span,
            KeyScope.DeviceCertificateIssuer,
            accountRecord.DeepAccountIdHash.Span,
            accountRecord.Certificate.AccountGeneration,
            accountRecord.Certificate.DeviceIssuerEd25519PublicKey.Span);
        fields[11] = U64(drs.Revision);
        fields[12] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Drs1, drs.CanonicalBytes.Span));
        fields[13] = U64(drs.EntryCount);
        fields[14] = drs.CurrentHead;
        fields[15] = U64(1_900_000_200);
        fields[16] = U64(1_900_172_900);
        fields[17] = U64((ulong)DeviceCapabilities.MailboxRoleIssuer);
        fields[18] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
        fields[19] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dpd1, predecessor.Certificate.CanonicalBytes.Span));
        fields[20] = SHA256.HashData("DPD1/successor/recovery-possession"u8);
        var unsigned = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpd1, fields),
            RecordDefinitions.Dpd1);
        var signingBytes = CanonicalGrammar.GetSigningBytes(
            unsigned, "Deep/IdentityAuth/V1/device-certificate");
        fields[21] = SignForTest(successorOwner, "signingSeed", signingBytes);
        fields[22] = SignForTest(recovery, "deviceIssuerSigningSeed", signingBytes);
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Dpd1, fields);
        return new IdentityRelativeVerifier().RestoreDeviceFromRecovery(
            identity,
            canonical,
            1_900_000_300,
            predecessor);
    }

    private static VerifiedRevocationState RevokedState(
        VerifiedRevocationState prior,
        DeviceCertificate revokedDevice)
    {
        var targetFields = RecordDefinitions.Drt1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength])
            .ToArray();
        targetFields[0] = prior.Account.DeepAccountIdHash;
        targetFields[1] = new[] { (byte)RevocationTargetKind.DeviceCertificate };
        targetFields[2] = revokedDevice.RevocationHandle;
        targetFields[3] = U64(revokedDevice.DeviceGeneration);
        targetFields[4] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Dpd1, revokedDevice.CanonicalBytes.Span));
        targetFields[5] = U64(revokedDevice.ExpiresAtUnixSeconds);
        var target = new RevocationTarget(CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Drt1, targetFields),
            RecordDefinitions.Drt1));

        var row = new byte[62];
        row[0] = (byte)RevocationTargetKind.DeviceCertificate;
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Drt1, target.CanonicalBytes.Span)).CopyTo(row, 1);
        BinaryPrimitives.WriteUInt64BigEndian(row.AsSpan(39), revokedDevice.DeviceGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(row.AsSpan(47), 1_900_000_400);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(55), (ushort)RevocationReason.DeviceLost);

        var drsFields = RecordDefinitions.Drs1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength])
            .ToArray();
        drsFields[0] = prior.Account.Certificate.NetworkId;
        drsFields[1] = prior.Account.DeepAccountIdHash;
        drsFields[2] = U64(prior.Account.Certificate.AccountGeneration);
        drsFields[3] = U64(prior.Snapshot.Revision + 1);
        drsFields[4] = U64(1_900_000_400);
        drsFields[5] = prior.Snapshot.Record.FieldCopy(6);
        drsFields[6] = prior.Snapshot.Record.FieldCopy(7);
        drsFields[7] = prior.Snapshot.Record.FieldCopy(8);
        drsFields[8] = U16(1);
        drsFields[9] = row;
        drsFields[10] = SHA256.HashData("DRS1/revoked-device/test-head"u8);
        var snapshot = IdentityCodec.DecodeRevocationSnapshot(
            CanonicalGrammar.Encode(RecordDefinitions.Drs1, drsFields));
        var catalog = new RevocationCatalog([
            new RevocationCatalogEntry(
                target,
                1_900_000_400,
                RevocationReason.DeviceLost,
                revokedDevice.CanonicalBytes.Span,
                prior.Snapshot.CanonicalBytes.Span)
        ]);
        return new VerifiedRevocationState(prior.Account, snapshot, catalog);
    }

    private static byte[] SignForTest(object owner, string seedField, ReadOnlySpan<byte> message)
    {
        var seed = PrivateArray(owner, seedField);
        var signature = new byte[OwnedSodiumEd25519.SignatureSize];
        Span<byte> temporaryPublic = stackalloc byte[OwnedSodiumEd25519.PublicKeySize];
        Span<byte> temporarySecret = stackalloc byte[OwnedSodiumEd25519.SecretKeySize];
        OwnedSodiumEd25519.SignDetached(
            seed, message, signature, temporaryPublic, temporarySecret);
        return signature;
    }

    private static ApplicationArtifactReference IdentityReference(CanonicalIdentityArtifact artifact) =>
        ApplicationCoreCodec.CreateArtifactReference(
            (ushort)artifact.ArtifactType,
            checked((uint)artifact.CanonicalBytes.Length),
            artifact.CanonicalHash.Span);

    private static Dmd1LineageState CurrentDirectory(VerifiedDmd1 directory) =>
        ApplicationCoreVerifier.StartDmd1Lineage(directory).Next;

    private static byte[] PrivateArray(object owner, string fieldName)
    {
        var field = owner.GetType().GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance);
        return Assert.IsType<byte[]>(field!.GetValue(owner));
    }

    private static DeepRecoveryAccountCapabilities Recovery(ReadOnlySpan<byte> network)
    {
        var utf8 = Encoding.ASCII.GetBytes(Mnemonic);
        try
        {
            using var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(utf8);
            return DeepRecoveryV1.DeriveAccountCapabilities(phrase, network, 1);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
        }
    }

    private static OwnedGenesisDeviceSecrets Device() => new(
        Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray(),
        Enumerable.Range(33, 32).Select(static value => (byte)value).ToArray(),
        Enumerable.Repeat((byte)0xd1, 32).ToArray(),
        Enumerable.Repeat((byte)0xe1, 32).ToArray());

    private static string Hex(ReadOnlySpan<byte> value) => Convert.ToHexStringLower(value);
    private static byte[] U64(ulong value)
    {
        var encoded = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        return encoded;
    }

    private static byte[] U16(ushort value)
    {
        var encoded = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, value);
        return encoded;
    }

    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static ushort U16(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt16BigEndian(value);

    private sealed class FillRandom(params byte[] fills) : IIdentityAuthoringRandom
    {
        private int index;
        public void Fill(Span<byte> destination)
        {
            var value = fills[Math.Min(index, fills.Length - 1)];
            index++;
            destination.Fill(value);
        }
    }

    private sealed class FailIfRandom : IIdentityAuthoringRandom
    {
        internal static readonly FailIfRandom Instance = new();
        public void Fill(Span<byte> destination) =>
            throw new InvalidOperationException("A durable retry generated new operation material.");
    }

    private sealed class SimulatedCrashException : Exception;

    public enum PersistenceFault
    {
        None,
        CollidingKeyRoles,
        ProfileMovesBeforeCas,
        CorruptPendingEvidence,
        CorruptVerifiedEvidence,
        CrashAfterPendingReserve,
        CrashAfterVerifiedCas
    }

    private sealed class DurableState
    {
        internal readonly object Gate = new();
        internal readonly Dictionary<string, StoredOperation> Rows = [];
        internal readonly Dictionary<string, string> SubjectOperations = [];
        internal readonly HashSet<string> NonceLedgerKeys = [];
        internal int ProfileReads;
        internal int PendingWrites;
        internal int VerifiedCasWrites;
        internal int AbortedWrites;
        internal bool CrashOnNextSubjectRead;
        internal ulong ProfileRevision = 7;
        internal PersistenceFault Fault;
    }

    private sealed class StoredOperation(
        byte[] current,
        ulong revision,
        DxpReplayMaterial? material,
        ulong subjectRevision)
    {
        internal byte[] Current = current;
        internal ulong Revision = revision;
        internal DxpReplayMaterial? Material = material;
        internal ulong SubjectRevision = subjectRevision;
    }

    private sealed class DurablePersistence(DurableState state) : Dnp1IdentityIssuancePersistence
    {
        private static readonly byte[] CatalogKeyId = Enumerable.Repeat((byte)0x31, 32).ToArray();
        private static readonly byte[] DxrKeyId = Enumerable.Repeat((byte)0x32, 32).ToArray();
        private static readonly byte[] DxrHmacKey = Enumerable.Repeat((byte)0x41, 32).ToArray();
        private static readonly byte[] NonceIndexKey = Enumerable.Repeat((byte)0x51, 32).ToArray();

        protected override ValueTask<UntrustedDxpPersistenceProfileReadResult> ReadProfileCoreAsync(
            DxpPersistenceProfileRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            state.ProfileReads++;
            var nonce = new DxpNonceLedgerVerifier().Derive(
                request.Source, Enumerable.Repeat((byte)1, 32).ToArray(), NonceIndexKey);
            var revision = state.Fault == PersistenceFault.ProfileMovesBeforeCas && state.ProfileReads >= 2
                ? state.ProfileRevision + 1 : state.ProfileRevision;
            return ValueTask.FromResult(new UntrustedDxpPersistenceProfileReadResult(
                CatalogKeyId,
                state.Fault == PersistenceFault.CollidingKeyRoles ? CatalogKeyId : DxrKeyId,
                nonce.IndexKeyId.Span,
                revision));
        }

        protected override ValueTask<UntrustedDxpNonceLedgerReadResult> DeriveNonceLedgerCoreAsync(
            DxpNonceLedgerRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var binding = new DxpNonceLedgerVerifier().Derive(
                request.Source, request.Nonce.Span, NonceIndexKey);
            return ValueTask.FromResult(new UntrustedDxpNonceLedgerReadResult(
                binding.LedgerKey.Span, binding.IndexKeyId.Span));
        }

        protected override ValueTask<ReadOnlyMemory<byte>> ComputeDxrTagCoreAsync(
            DxpProtectedTagRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!request.ProtectedStateKeyId.Span.SequenceEqual(DxrKeyId))
                throw new RecordException(RecordError.InvalidField, "Wrong protected key role.");
            var domain = Encoding.ASCII.GetBytes(request.Domain);
            var unsigned = request.UnsignedCanonicalDxr1;
            var input = new byte[2 + domain.Length + 2 + 4 + unsigned.Length];
            BinaryPrimitives.WriteUInt16BigEndian(input, checked((ushort)domain.Length));
            domain.CopyTo(input, 2);
            var offset = 2 + domain.Length;
            BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset), request.Suite);
            BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(offset + 2), checked((uint)unsigned.Length));
            unsigned.Span.CopyTo(input.AsSpan(offset + 6));
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(HMACSHA256.HashData(DxrHmacKey, input));
        }

        protected override ValueTask<UntrustedDxpReplayReadResult?> ReadByDeviceSubjectCoreAsync(
            DxpDeviceSubjectRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (state.Gate)
            {
                if (state.CrashOnNextSubjectRead)
                {
                    state.CrashOnNextSubjectRead = false;
                    throw new SimulatedCrashException();
                }
                var subject = Hex(request.DeviceSubjectKey.Span);
                if (!state.SubjectOperations.TryGetValue(subject, out var operation))
                    return ValueTask.FromResult<UntrustedDxpReplayReadResult?>(null);
                return ValueTask.FromResult<UntrustedDxpReplayReadResult?>(Replay(state.Rows[operation]));
            }
        }

        protected override ValueTask<UntrustedDxpReplayReadResult> ReservePendingCoreAsync(
            DxpPendingWriteRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var record = CanonicalGrammar.DecodeOwned(
                request.CanonicalDxr1.Span, RecordDefinitions.Dxr1);
            var operation = Hex(record.FieldSpan(4));
            var ledger = Hex(record.FieldSpan(9));
            var subject = Hex(request.Material.DeviceSubjectKey.Span);
            lock (state.Gate)
            {
                if (state.SubjectOperations.TryGetValue(subject, out var winner))
                    return ValueTask.FromResult(Replay(state.Rows[winner]));
                if (!request.Scope.OperationId.Span.SequenceEqual(record.FieldSpan(4)) ||
                    state.Rows.ContainsKey(operation) || !state.NonceLedgerKeys.Add(ledger))
                    throw new RecordException(RecordError.InvalidTransition, "Durable nonce replay.");
                var canonical = request.CanonicalDxr1.ToArray();
                var stored = new StoredOperation(canonical, 1, request.Material, 0);
                state.Rows.Add(operation, stored);
                state.SubjectOperations.Add(subject, operation);
                state.PendingWrites++;
                if (state.Fault == PersistenceFault.CrashAfterPendingReserve)
                    throw new SimulatedCrashException();
                return ValueTask.FromResult(Replay(stored,
                    state.Fault == PersistenceFault.CorruptPendingEvidence));
            }
        }

        protected override ValueTask<UntrustedDxpReplayReadResult> CompareExchangeVerifiedCoreAsync(
            DxpVerifiedCasRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var operation = Hex(request.Scope.OperationId.Span);
            lock (state.Gate)
            {
                if (!state.Rows.TryGetValue(operation, out var current))
                    throw new RecordException(RecordError.InvalidTransition, "Exact durable CAS failed.");
                if (current.SubjectRevision != 0)
                    return ValueTask.FromResult(Replay(current));
                var subject = Hex(request.DeviceSubjectKey.Span);
                var expectedHead = CanonicalGrammar.EncodeReference(
                    CanonicalGrammar.ComputeReference(
                        ArtifactType.Dpd1, request.CanonicalDpd1.Span));
                if (current.Revision != request.ExpectedSourceRevision ||
                    !current.Current.AsSpan().SequenceEqual(request.CurrentDxr1.Span) ||
                    !request.ExpectedDeviceSubjectAbsent || current.Material is null ||
                    !state.SubjectOperations.TryGetValue(subject, out var subjectOperation) ||
                    subjectOperation != operation ||
                    !request.NewSubjectHead.Span.SequenceEqual(expectedHead) ||
                    !request.Material.CanonicalDpd1.Span.SequenceEqual(
                        current.Material.CanonicalDpd1.Span) ||
                    !request.Material.CanonicalPendingDxr1.Span.SequenceEqual(
                        current.Material.CanonicalPendingDxr1.Span) ||
                    !request.Material.CanonicalVerifiedDxr1.Span.SequenceEqual(
                        current.Material.CanonicalVerifiedDxr1.Span) ||
                    !request.Material.DeviceSubjectKey.Span.SequenceEqual(
                        current.Material.DeviceSubjectKey.Span) ||
                    !request.Material.ExpectedSubjectPredecessor.Span.SequenceEqual(
                        current.Material.ExpectedSubjectPredecessor.Span) ||
                    !request.Material.NewSubjectHead.Span.SequenceEqual(
                        current.Material.NewSubjectHead.Span))
                    throw new RecordException(RecordError.InvalidTransition, "Exact durable CAS failed.");
                current.Current = request.NextDxr1.ToArray();
                current.Revision++;
                current.SubjectRevision = 1;
                state.VerifiedCasWrites++;
                if (state.Fault == PersistenceFault.CorruptVerifiedEvidence)
                    current.Current[^1] ^= 1;
                if (state.Fault == PersistenceFault.CrashAfterVerifiedCas)
                {
                    state.CrashOnNextSubjectRead = true;
                    throw new SimulatedCrashException();
                }
                return ValueTask.FromResult(Replay(current));
            }
        }

        protected override ValueTask<UntrustedDxpReplayReadResult> CompareExchangeAbortedCoreAsync(
            DxpAbortedCasRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var operation = Hex(request.Scope.OperationId.Span);
            lock (state.Gate)
            {
                if (!state.Rows.TryGetValue(operation, out var current) ||
                    current.SubjectRevision != 0 || current.Revision != request.ExpectedSourceRevision ||
                    !current.Current.AsSpan().SequenceEqual(request.CurrentDxr1.Span) ||
                    !state.SubjectOperations.TryGetValue(
                        Hex(request.DeviceSubjectKey.Span), out var subjectOperation) ||
                    subjectOperation != operation)
                    throw new RecordException(RecordError.InvalidTransition, "Exact durable abort CAS failed.");
                current.Current = request.AbortedDxr1.ToArray();
                current.Revision++;
                current.Material = null;
                state.AbortedWrites++;
                return ValueTask.FromResult(Replay(current));
            }
        }

        private static UntrustedDxpReplayReadResult Replay(
            StoredOperation stored, bool corrupt = false)
        {
            var returned = stored.Current.ToArray();
            if (corrupt) returned[^1] ^= 1;
            return new UntrustedDxpReplayReadResult(
                returned, stored.Revision, stored.Material, stored.SubjectRevision);
        }
    }
}
