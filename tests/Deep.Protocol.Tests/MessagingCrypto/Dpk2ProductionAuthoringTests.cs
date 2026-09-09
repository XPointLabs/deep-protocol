using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.Tests.Identity;

public sealed partial class Dnp1IdentityAuthoringV1Tests
{
    [Fact]
    public async Task Dpk2Persistence_RoundTripsAcrossRestartAndRejectsEveryExactBindingFailure()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var directory = ExactDirectory(account, issued);
        using var authority = device.CreateDpk2AuthoringAuthority(
            issued.Verified, new IncrementingDpk2Random(), new DeterministicDpk2Kem());
        var context = new Dpk2AuthoringContext(
            CurrentDirectory(directory), 7, 3, 11,
            1_900_000_300, 1_900_000_250, 1_900_086_700);
        using var authored = authority.AuthorOneTime(context);
        using var different = authority.AuthorLastResort(context, 9);
        var key = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var wrongKey = key.ToArray();
        wrongKey[0] ^= 0x80;
        var scope = PersistenceScope(authored.Record, issued.Verified.Certificate.AccountGeneration);
        Dpk2PreKeyPersistenceBlob blob;
        try
        {
            using (var protector = new Dpk2PreKeyPersistenceProtector(key))
                blob = authored.SealSecretForPersistence(protector, scope);

            Assert.Throws<InvalidOperationException>(authored.TakeSecretCapability);
            Assert.InRange(blob.CanonicalBytes.Length, 1, Dpk2PreKeyPersistenceBlob.MaximumCanonicalBytes);
            Assert.Equal(blob.CanonicalBytes.ToArray(),
                Dpk2PreKeyPersistenceBlob.Decode(blob.CanonicalBytes).CanonicalBytes.ToArray());

            using var restarted = new Dpk2PreKeyPersistenceProtector(key);
            using var restored = restarted.Restore(blob, authored.ExactDpk2, scope);
            Assert.Equal(authored.ExactDpk2Hash.ToArray(), restored.ExactDpk2Hash.ToArray());
            Assert.Equal(authored.Record.SignedX25519PrekeyId.ToArray(), restored.SignedX25519PreKeyId.ToArray());
            Assert.Equal(authored.Record.OneTimeX25519PrekeyId.ToArray(), restored.OneTimeX25519PreKeyId.ToArray());
            Assert.Equal(authored.Record.MlKemPrekeyId.ToArray(), restored.MlKemPreKeyId.ToArray());

            using var wrongProtector = new Dpk2PreKeyPersistenceProtector(wrongKey);
            Assert.Throws<CryptographicException>(() =>
                wrongProtector.Restore(blob, authored.ExactDpk2, scope));
            Assert.Throws<CryptographicException>(() =>
                restarted.Restore(blob, different.ExactDpk2, scope));

            AssertWrongScope(restarted, blob, authored,
                PersistenceScope(authored.Record, scope.AccountGeneration, network: Changed(scope.NetworkId)));
            AssertWrongScope(restarted, blob, authored,
                PersistenceScope(authored.Record, scope.AccountGeneration, account: Changed(scope.AccountId)));
            AssertWrongScope(restarted, blob, authored,
                PersistenceScope(authored.Record, scope.AccountGeneration + 1));
            AssertWrongScope(restarted, blob, authored,
                PersistenceScope(authored.Record, scope.AccountGeneration, device: Changed(scope.DeviceId)));
            AssertWrongScope(restarted, blob, authored,
                PersistenceScope(authored.Record, scope.AccountGeneration,
                    deviceGeneration: scope.DeviceGeneration + 1));
            AssertWrongScope(restarted, blob, authored,
                PersistenceScope(authored.Record, scope.AccountGeneration,
                    dpd1Reference: Changed(scope.ExactDpd1Reference, 6)));

            var tampered = blob.CanonicalBytes.ToArray();
            tampered[^1] ^= 0x01;
            var tamperedBlob = Dpk2PreKeyPersistenceBlob.Decode(tampered);
            Assert.Throws<CryptographicException>(() =>
                restarted.Restore(tamperedBlob, authored.ExactDpk2, scope));
            Assert.Throws<CryptographicException>(() =>
                Dpk2PreKeyPersistenceBlob.Decode(tampered.AsMemory(0, tampered.Length - 1)));
            Assert.Throws<CryptographicException>(() =>
                Dpk2PreKeyPersistenceBlob.Decode(
                    new byte[Dpk2PreKeyPersistenceBlob.MaximumCanonicalBytes + 1]));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(wrongKey);
        }
    }

    [Fact]
    public async Task Dpk2Persistence_UsesFreshNoncesAndBurnsCapabilityWhenSealingFails()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        using var authority = device.CreateDpk2AuthoringAuthority(
            issued.Verified, new IncrementingDpk2Random(), new DeterministicDpk2Kem());
        using var authored = authority.AuthorOneTime(new Dpk2AuthoringContext(
            CurrentDirectory(ExactDirectory(account, issued)), 7, 3, 11,
            1_900_000_300, 1_900_000_250, 1_900_086_700));
        var key = Enumerable.Repeat((byte)0xd1, 32).ToArray();
        var exactHash = authored.ExactDpk2Hash.ToArray();
        var scope = PersistenceScope(authored.Record, issued.Verified.Certificate.AccountGeneration);
        using var original = authored.TakeSecretCapability();
        using var material = original.ConsumeForProtocolOwner();
        using var first = new Dpk2PreKeySecretCapability(
            authored.Record, scope.AccountGeneration, exactHash,
            material.SignedPrivate, material.OneTimePrivate!, material.MlKemSecret);
        using var second = new Dpk2PreKeySecretCapability(
            authored.Record, scope.AccountGeneration, exactHash,
            material.SignedPrivate, material.OneTimePrivate!, material.MlKemSecret);
        using var rejected = new Dpk2PreKeySecretCapability(
            authored.Record, scope.AccountGeneration, exactHash,
            material.SignedPrivate, material.OneTimePrivate!, material.MlKemSecret);
        try
        {
            using var protector = new Dpk2PreKeyPersistenceProtector(key);
            var firstBlob = first.SealForPersistence(protector, authored.ExactDpk2, scope);
            var secondBlob = second.SealForPersistence(protector, authored.ExactDpk2, scope);
            Assert.NotEqual(firstBlob.CanonicalBytes.ToArray(), secondBlob.CanonicalBytes.ToArray());
            Assert.Throws<InvalidOperationException>(() =>
                first.SealForPersistence(protector, authored.ExactDpk2, scope));

            var wrongScope = PersistenceScope(
                authored.Record, scope.AccountGeneration + 1);
            Assert.Throws<CryptographicException>(() =>
                rejected.SealForPersistence(protector, authored.ExactDpk2, wrongScope));
            Assert.Throws<InvalidOperationException>(() =>
                rejected.SealForPersistence(protector, authored.ExactDpk2, scope));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(exactHash);
        }
    }

    [Fact]
    public async Task Dpk2Authoring_ProducesExactSignedOneTimeAndLastResortOfferings()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var directory = ExactDirectory(account, issued);
        var current = CurrentDirectory(directory);
        var kem = new DeterministicDpk2Kem();
        using var authority = device.CreateDpk2AuthoringAuthority(
            issued.Verified, new IncrementingDpk2Random(), kem);
        var context = new Dpk2AuthoringContext(
            current, 7, 3, 11, 1_900_000_300, 1_900_000_250, 1_900_086_700);

        using var oneTime = authority.AuthorOneTime(context);
        using var lastResort = authority.AuthorLastResort(context, 9);

        AssertOffering(oneTime, Dpk2PrekeyKind.OneTime, 0, directory, issued);
        AssertOffering(lastResort, Dpk2PrekeyKind.LastResort, 9, directory, issued);
        Assert.Equal(Dpk2Codec.OneTimeTotalBytes, oneTime.ExactDpk2.Length);
        Assert.Equal(Dpk2Codec.LastResortTotalBytes, lastResort.ExactDpk2.Length);
        Assert.NotEqual(oneTime.Record.BundleId.ToArray(), lastResort.Record.BundleId.ToArray());
        Assert.Equal(2, kem.GenerateCount);

        using var oneTimeSecret = oneTime.TakeSecretCapability();
        Assert.Throws<InvalidOperationException>(oneTime.TakeSecretCapability);
        Assert.Equal(oneTime.ExactDpk2Hash.ToArray(), oneTimeSecret.ExactDpk2Hash.ToArray());
        Assert.Equal(oneTime.Record.SignedX25519PrekeyId.ToArray(), oneTimeSecret.SignedX25519PreKeyId.ToArray());
        Assert.Equal(oneTime.Record.OneTimeX25519PrekeyId.ToArray(), oneTimeSecret.OneTimeX25519PreKeyId.ToArray());
        Assert.Equal(oneTime.Record.MlKemPrekeyId.ToArray(), oneTimeSecret.MlKemPreKeyId.ToArray());
        byte[] signedOwned;
        byte[] oneTimeOwned;
        byte[] mlKemOwned;
        using (var material = oneTimeSecret.ConsumeForProtocolOwner())
        {
            signedOwned = material.SignedPrivate;
            oneTimeOwned = material.OneTimePrivate!;
            mlKemOwned = material.MlKemSecret;
            Assert.True(DeepIdentityCrypto.X25519PublicKeyMatchesPrivateScalar(
                material.SignedPrivate, oneTime.Record.SignedX25519PrekeyPublic.Span));
            Assert.True(DeepIdentityCrypto.X25519PublicKeyMatchesPrivateScalar(
                material.OneTimePrivate!, oneTime.Record.OneTimeX25519PrekeyPublic.Span));
            Assert.True(kem.EncapsulationKeyMatchesDecapsulationKey(
                oneTime.Record.MlKem768EncapsulationKey.Span, material.MlKemSecret));
        }
        Assert.All(signedOwned, static value => Assert.Equal(0, value));
        Assert.All(oneTimeOwned, static value => Assert.Equal(0, value));
        Assert.All(mlKemOwned, static value => Assert.Equal(0, value));
        Assert.Throws<InvalidOperationException>(oneTimeSecret.ConsumeForProtocolOwner);

        using var lastSecret = lastResort.TakeSecretCapability();
        Assert.Empty(lastSecret.OneTimeX25519PreKeyId.ToArray());
        using var lastMaterial = lastSecret.ConsumeForProtocolOwner();
        Assert.Null(lastMaterial.OneTimePrivate);
    }

    [Fact]
    public async Task Dpk2Authoring_RejectsForkedOrWrongDeviceAuthorityBeforeKeyGeneration()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var directory = ExactDirectory(account, issued);
        var kem = new DeterministicDpk2Kem();
        using var authority = device.CreateDpk2AuthoringAuthority(
            issued.Verified, new IncrementingDpk2Random(), kem);
        var forked = new Dmd1LineageState(directory, forkLatched: true);
        var context = new Dpk2AuthoringContext(
            forked, 1, 1, 1, 1_900_000_300, 1_900_000_300, 1_900_000_400);

        Assert.Throws<RecordException>(() => authority.AuthorOneTime(context));
        Assert.Equal(0, kem.GenerateCount);

        using var wrongDevice = OtherDevice();
        var wrongKem = new DeterministicDpk2Kem();
        Assert.Throws<RecordException>(() => wrongDevice.CreateDpk2AuthoringAuthority(
            issued.Verified, new IncrementingDpk2Random(), wrongKem));
        Assert.True(wrongKem.Disposed);
    }

    [Fact]
    public async Task Dpk2Authoring_PublicFactoryIsLazyAndDisposalZeroizesOwnedDeviceSeed()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var authority = device.CreateDpk2AuthoringAuthority(issued.Verified);
        var owner = Assert.IsType<SecretBuffer>(typeof(Dpk2AuthoringAuthority)
            .GetField("_deviceSigningSeed", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(authority));
        var secret = Assert.IsType<byte[]>(typeof(SecretBuffer)
            .GetField("_value", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(owner));

        authority.Dispose();
        Assert.All(secret, static value => Assert.Equal(0, value));
        Assert.Throws<ObjectDisposedException>(() => authority.AuthorOneTime(
            new Dpk2AuthoringContext(CurrentDirectory(ExactDirectory(account, issued)),
                1, 1, 1, 1_900_000_300, 1_900_000_300, 1_900_000_400)));

    }

    [Fact]
    public async Task Dpk2Authoring_PublicFactoryUsesOnlyTheManifestApprovedMlKemAsset()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
            return;

        StageApprovedMlKemAsset();
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        using var authority = device.CreateDpk2AuthoringAuthority(issued.Verified);
        using var authored = authority.AuthorOneTime(new Dpk2AuthoringContext(
            CurrentDirectory(ExactDirectory(account, issued)),
            1, 1, 1, 1_900_000_300, 1_900_000_300, 1_900_000_400));

        Assert.Equal(Dpk2Codec.OneTimeTotalBytes, authored.ExactDpk2.Length);
        var decoded = Dpk2Codec.Decode(authored.ExactDpk2.Span);
        Assert.Equal(1184, decoded.MlKem768EncapsulationKey.Length);
        Assert.True(PublicKeyAuth.VerifyDetached(
            decoded.BundleSignature.ToArray(),
            MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(decoded),
            issued.Verified.Certificate.DeviceEd25519PublicKey.ToArray()));
    }

    [Fact]
    public async Task Dpk2Authoring_ExactOutputsComposeIntoCanonicalPreKeyInventoryPublication()
    {
        using var recovery = Recovery(Network);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var directory = ExactDirectory(account, issued);
        using var authority = device.CreateDpk2AuthoringAuthority(
            issued.Verified, new IncrementingDpk2Random(), new DeterministicDpk2Kem());
        var context = new Dpk2AuthoringContext(
            CurrentDirectory(directory), 7, 1, 11,
            1_900_000_300, 1_900_000_250, 1_900_086_700);
        var authored = Enumerable.Range(0, 32)
            .Select(_ => authority.AuthorOneTime(context))
            .OrderBy(value => value.Record.OneTimeX25519PrekeyId.ToArray(), ByteArrayOrder.Instance)
            .ToArray();
        using var last = authority.AuthorLastResort(context, 9);
        try
        {
            var exact = authored.Select(value => value.ExactDpk2.ToArray()).ToArray();
            var hashes = exact.Select(value =>
                ContactCodec.Sha256Domain(MessagingWireCryptographicInputs.ExactDpk2Domain, value)).ToArray();
            var root = PreKeyInventoryPublicationVerifier.ComputeMerkleRoot(hashes);
            var fields = new Xpi1UnsignedFields(
                Network,
                Enumerable.Repeat((byte)0x91, 32).ToArray(),
                issued.Verified.Certificate.DeviceId.Span,
                authored[0].Record.ResponderDpd1Ref.Span,
                context.PrekeyServiceGeneration,
                ContactReference("XPS1", 0x92),
                context.InventoryEpoch,
                new byte[32],
                32,
                root,
                last.ExactDpk2Hash.Span,
                directory.Record.RecordHash.Span,
                ContactReference("DRS1", 0x93),
                context.NotBeforeUnixSeconds,
                context.ExpiresAtUnixSeconds);
            var signatureInput = Xpi1Codec.CreateSignatureInput(fields);
            var manifest = Xpi1Codec.Decode(Xpi1Codec.Encode(
                fields, SignForTest(device, "signingSeed", signatureInput)));
            var publication = Xpp1Codec.Decode(Xpp1Codec.Encode(
                Network,
                Enumerable.Repeat((byte)0x94, 32).ToArray(),
                Enumerable.Repeat((byte)0x95, 32).ToArray(),
                manifest,
                exact.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                last.ExactDpk2.Span));

            Assert.Equal(32, publication.OneTimeDpk2Records.Count);
            Assert.Equal(exact[0], publication.OneTimeDpk2Records[0].ToArray());
            Assert.Equal(last.ExactDpk2.ToArray(), publication.LastResortDpk2Record.ToArray());
        }
        finally
        {
            foreach (var value in authored) value.Dispose();
        }
    }

    private static void AssertOffering(
        AuthoredDpk2Offering authored,
        Dpk2PrekeyKind kind,
        ushort reuseLimit,
        VerifiedDmd1 directory,
        IssuedGenesisDevice issued)
    {
        var record = Dpk2Codec.Decode(authored.ExactDpk2.Span);
        Assert.Equal(authored.ExactDpk2.ToArray(), Dpk2Codec.Encode(record));
        Assert.Equal(
            MessagingWireCryptographicInputs.ComputeExactDpk2Hash(record),
            authored.ExactDpk2Hash.ToArray());
        Assert.Equal(kind, record.MlKemKind);
        Assert.Equal(reuseLimit, record.ReuseLimit);
        Assert.Equal(Network, record.NetworkId.ToArray());
        Assert.Equal(issued.Verified.Certificate.AccountHash.ToArray(), record.ResponderAccountId.ToArray());
        Assert.Equal(issued.Verified.Certificate.DeviceId.ToArray(), record.ResponderDeviceId.ToArray());
        Assert.Equal(issued.Verified.Certificate.DeviceGeneration, record.ResponderDeviceGeneration);
        Assert.Equal(directory.Record.DirectoryGeneration, record.DeviceDirectoryGeneration);
        Assert.Equal(directory.Record.RecordHash.ToArray(), record.DeviceDirectoryHeadHash.ToArray());
        Assert.Equal(issued.Verified.Certificate.DeviceX25519PublicKey.ToArray(), record.DeviceAgreementPublicKey.ToArray());
        Assert.Equal(7UL, record.PrekeyServiceGeneration);
        Assert.Equal(3UL, record.InventoryEpoch);
        Assert.Equal(11UL, record.PolicyGeneration);

        var signingKey = issued.Verified.Certificate.DeviceEd25519PublicKey.ToArray();
        Assert.True(PublicKeyAuth.VerifyDetached(
            record.SignedX25519PrekeySignature.ToArray(),
            MessagingWireCryptographicInputs.GetX25519SignedPrekeySignatureInput(record), signingKey));
        Assert.True(PublicKeyAuth.VerifyDetached(
            record.MlKemPrekeySignature.ToArray(),
            MessagingWireCryptographicInputs.GetMlKemPrekeySignatureInput(record), signingKey));
        Assert.True(PublicKeyAuth.VerifyDetached(
            record.BundleSignature.ToArray(),
            MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(record), signingKey));
    }

    private static Dpk2PreKeyPersistenceScope PersistenceScope(
        Dpk2Record record,
        ulong accountGeneration,
        ReadOnlyMemory<byte>? network = null,
        ReadOnlyMemory<byte>? account = null,
        ReadOnlyMemory<byte>? device = null,
        ulong? deviceGeneration = null,
        ReadOnlyMemory<byte>? dpd1Reference = null) =>
        new(
            (network ?? record.NetworkId).Span,
            (account ?? record.ResponderAccountId).Span,
            accountGeneration,
            (device ?? record.ResponderDeviceId).Span,
            deviceGeneration ?? record.ResponderDeviceGeneration,
            (dpd1Reference ?? record.ResponderDpd1Ref).Span);

    private static void AssertWrongScope(
        Dpk2PreKeyPersistenceProtector protector,
        Dpk2PreKeyPersistenceBlob blob,
        AuthoredDpk2Offering authored,
        Dpk2PreKeyPersistenceScope wrongScope) =>
        Assert.Throws<CryptographicException>(() =>
            protector.Restore(blob, authored.ExactDpk2, wrongScope));

    private static ReadOnlyMemory<byte> Changed(ReadOnlyMemory<byte> value, int offset = 0)
    {
        var changed = value.ToArray();
        changed[offset] ^= 0x80;
        return changed;
    }

    private sealed class IncrementingDpk2Random : IIdentityAuthoringRandom
    {
        private byte _next = 0x31;
        public void Fill(Span<byte> destination)
        {
            destination.Fill(_next++);
        }
    }

    private sealed class DeterministicDpk2Kem : IDpk2MlKemKeyGenerator
    {
        private byte _next = 0x71;
        public int GenerateCount { get; private set; }
        public bool Disposed { get; private set; }

        public OwnedMlKem768KeyPair Generate()
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
            GenerateCount++;
            var marker = _next++;
            return new OwnedMlKem768KeyPair(
                Enumerable.Repeat(marker, 1184).ToArray(),
                Enumerable.Repeat(marker, 64).ToArray());
        }

        public bool EncapsulationKeyMatchesDecapsulationKey(
            ReadOnlySpan<byte> encapsulationKey,
            ReadOnlySpan<byte> decapsulationKey) =>
            encapsulationKey.Length == 1184 && decapsulationKey.Length == 64 &&
            encapsulationKey.IndexOfAnyExcept(decapsulationKey[0]) < 0 &&
            decapsulationKey.IndexOfAnyExcept(decapsulationKey[0]) < 0;

        public void Dispose() => Disposed = true;
    }

    private sealed class ByteArrayOrder : IComparer<byte[]>
    {
        internal static readonly ByteArrayOrder Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }

    private static byte[] ContactReference(string magic, byte marker)
    {
        var value = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        value.AsSpan(6).Fill(marker);
        return value;
    }

    private static void StageApprovedMlKemAsset()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        string? source = null;
        while (current is not null)
        {
            var candidate = Path.Combine(current.FullName,
                "native", "Deep.MlKem", "artifacts", "windows-x64", "deep_mlkem.dll");
            if (File.Exists(candidate)) { source = candidate; break; }
            current = current.Parent;
        }
        Assert.False(string.IsNullOrEmpty(source));
        var destination = Path.Combine(AppContext.BaseDirectory,
            DeepMlKemApprovedAssets.WindowsX64.RelativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(source!, destination, overwrite: true);
    }
}
