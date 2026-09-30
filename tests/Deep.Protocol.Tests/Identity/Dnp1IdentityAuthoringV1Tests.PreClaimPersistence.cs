using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Sodium;

namespace Deep.Protocol.Tests.Identity;

public sealed partial class Dnp1IdentityAuthoringV1Tests
{
    [Fact]
    public void PreClaimPersistence_PublicSurfaceIsOpaqueAndBounded()
    {
        Assert.Empty(typeof(InitiatorDph2PreKeyClaimPersistenceBlob).GetConstructors());
        Assert.Equal(2552, InitiatorDph2PreKeyClaimPersistenceBlob.CanonicalByteCount);
        var restore = Assert.Single(typeof(InitiatorDph2PreKeyClaimPersistenceProtector).GetMethods(),
            method => method.Name == "RestoreCurrentAsync");
        Assert.Equal(new[] { typeof(InitiatorDph2PreKeyClaimPersistenceBlob),
            typeof(InitiatorDph2PreKeyClaimPersistenceScope), typeof(LocalDeviceX25519AgreementAuthority),
            typeof(Dmd1LineageState), typeof(VerifiedDeepIdV2DirectoryFreshness),
            typeof(OnionTrustedTimeAuthority), typeof(CancellationToken) },
            restore.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.Equal(typeof(ValueTask<InitiatorDph2PreKeyClaim>), restore.ReturnType);
        Assert.DoesNotContain(typeof(InitiatorDph2PreKeyClaimPersistenceProtector)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly),
            method => method.ReturnType == typeof(byte[]) ||
                method.GetParameters().Any(parameter => typeof(Delegate).IsAssignableFrom(parameter.ParameterType)));
        Assert.ThrowsAny<CryptographicException>(() => new InitiatorDph2PreKeyClaimPersistenceScope(new byte[32], new byte[32]));
        Assert.ThrowsAny<CryptographicException>(() => new InitiatorDph2PreKeyClaimPersistenceProtector(new byte[32]));
        Assert.ThrowsAny<CryptographicException>(() => InitiatorDph2PreKeyClaimPersistenceBlob.Decode(new byte[2552]));
        Assert.ThrowsAny<CryptographicException>(() => InitiatorDph2PreKeyClaimPersistenceBlob.Decode(new byte[2553]));
    }

    // Extends the real authored DID2/device fixture. Directory clock evidence
    // is a bounded fixture; this is secret persistence, not physical delivery.
    private static async Task AssertPreClaimPersistenceAsync(ManagedInitiatorInitialSessionFactory factory,
        LocalDeviceX25519AgreementAuthority authority, LocalDeviceX25519AgreementAuthority otherAuthority,
        Dmd1LineageState directory, VerifiedDeepIdV2DirectoryFreshness current, byte[] boot)
    {
        var key = SHA256.HashData("DID2/preclaim/test/at-rest-key"u8);
        var instance = SHA256.HashData("DID2/preclaim/test/database-instance"u8);
        var intent = SHA256.HashData("DID2/preclaim/test/intent"u8);
        var scope = new InitiatorDph2PreKeyClaimPersistenceScope(instance, intent);
        using var protector = new InitiatorDph2PreKeyClaimPersistenceProtector(key);
        var begun = factory.BeginClaim(authority, directory, current, boot, 3);
        var operation = begun.ClaimOperationId.ToArray();
        var commitment = begun.SenderEphemeralCommitment.ToArray();
        var originalOwners = new List<SecretBuffer>();
        using (var hook = MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            OwnedSecret = (name, owner) => { if (name.StartsWith("initial-session.preclaim-", StringComparison.Ordinal)) originalOwners.Add(owner); }
        }))
        {
            // Capture independently owned material and prove seal consumes it,
            // rather than just disposing the first unrelated claim.
            begun.Dispose();
            begun = factory.BeginClaim(authority, directory, current, boot, 3);
            operation = begun.ClaimOperationId.ToArray(); commitment = begun.SenderEphemeralCommitment.ToArray();
        }
        InitiatorDph2PreKeyClaimPersistenceBlob blob;
        try { blob = protector.SealAndConsume(begun, scope); }
        finally { begun.Dispose(); }
        Assert.Equal(2, originalOwners.Count);
        Assert.All(originalOwners, owner => Assert.Throws<MessagingCryptoException>(() => owner.Copy()));
        Assert.Throws<InvalidOperationException>(() => protector.SealAndConsume(begun, scope));
        var exact = blob.CanonicalBytes.ToArray();
        var decoded = InitiatorDph2PreKeyClaimPersistenceBlob.Decode(exact);
        exact[^1] ^= 1;
        Assert.NotEqual(exact, decoded.CanonicalBytes.ToArray());
        var returned = decoded.CanonicalBytes.ToArray(); returned[12] ^= 1;
        Assert.Equal(blob.CanonicalBytes.ToArray(), decoded.CanonicalBytes.ToArray());
        instance[0] ^= 1; intent[0] ^= 1; key[0] ^= 1; // Scope and protector own their input.

        using (var restored = await protector.RestoreCurrentAsync(decoded, scope, authority, directory,
            current, new OnionTrustedTimeAuthority(new PreClaimClock(boot, [3, 4]))))
        {
            Assert.Equal(operation, restored.ClaimOperationId.ToArray());
            Assert.Equal(commitment, restored.SenderEphemeralCommitment.ToArray());
            restored.RequireCurrentInitiator(authority, directory, current, boot, 4);
            var resealed = protector.SealAndConsume(restored, scope);
            Assert.NotEqual(blob.CanonicalBytes.ToArray(), resealed.CanonicalBytes.ToArray());
            using var again = await protector.RestoreCurrentAsync(resealed, scope, authority, directory,
                current, new OnionTrustedTimeAuthority(new PreClaimClock(boot, [4, 5])));
            Assert.Equal(operation, again.ClaimOperationId.ToArray());
            Assert.Equal(commitment, again.SenderEphemeralCommitment.ToArray());
        }
        using var wrongKey = new InitiatorDph2PreKeyClaimPersistenceProtector(key);
        await Assert.ThrowsAnyAsync<CryptographicException>(async () => await wrongKey.RestoreCurrentAsync(blob,
            scope, authority, directory, current, new OnionTrustedTimeAuthority(new PreClaimClock(boot, [3]))));
        foreach (var wrongScope in new[] { new InitiatorDph2PreKeyClaimPersistenceScope(instance, scope.LogicalIntentId.Span),
            new InitiatorDph2PreKeyClaimPersistenceScope(scope.DatabaseInstanceId.Span, intent) })
        {
            var clock = new PreClaimClock(boot, [3]);
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await protector.RestoreCurrentAsync(blob,
                wrongScope, authority, directory, current, new OnionTrustedTimeAuthority(clock)));
            Assert.Equal(0, clock.Reads);
        }
        foreach (var offset in new[] { 0, 4, 5, 6, 7, 8 })
        {
            var changed = blob.CanonicalBytes.ToArray(); changed[offset] ^= 1;
            Assert.ThrowsAny<CryptographicException>(() => InitiatorDph2PreKeyClaimPersistenceBlob.Decode(changed));
        }
        Assert.ThrowsAny<CryptographicException>(() => InitiatorDph2PreKeyClaimPersistenceBlob.Decode(blob.CanonicalBytes[..^1]));
        foreach (var offset in new[] { 12, 44, 76, 92, 124, 156, 164, 196, 204, 236,
            2288, 2320, 2352, 2384, 2416, 2448, 2472, 2551 })
        {
            var changed = blob.CanonicalBytes.ToArray(); changed[offset] ^= 1;
            // Mutation of DID2 may be structurally rejected before AEAD. Other
            // canonical header/ciphertext substitutions reject during restore.
            try
            {
                var tampered = InitiatorDph2PreKeyClaimPersistenceBlob.Decode(changed);
                await Assert.ThrowsAnyAsync<CryptographicException>(async () => await protector.RestoreCurrentAsync(tampered,
                    scope, authority, directory, current, new OnionTrustedTimeAuthority(new PreClaimClock(boot, [3]))));
            }
            catch (ApplicationCoreFormatException) { Assert.Equal(236, offset); }
        }
        await Assert.ThrowsAnyAsync<CryptographicException>(async () => await protector.RestoreCurrentAsync(blob,
            scope, otherAuthority, directory, current, new OnionTrustedTimeAuthority(new PreClaimClock(boot, [3]))));
        foreach (var samples in new ulong[][] { [60], [3, 60], [5, 4] })
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await protector.RestoreCurrentAsync(blob,
                scope, authority, directory, current, new OnionTrustedTimeAuthority(new PreClaimClock(boot, samples))));
        var changedBoot = boot.ToArray();
        await Assert.ThrowsAnyAsync<CryptographicException>(async () => await protector.RestoreCurrentAsync(blob,
            scope, authority, directory, current, new OnionTrustedTimeAuthority(new PreClaimClock(changedBoot,
                [3], reads => { if (reads == 2) changedBoot[0] ^= 1; }))));
        var wrongBoot = boot.ToArray(); wrongBoot[0] ^= 1;
        await Assert.ThrowsAnyAsync<CryptographicException>(async () => await protector.RestoreCurrentAsync(blob,
            scope, authority, directory, current, new OnionTrustedTimeAuthority(new PreClaimClock(wrongBoot, [3]))));
        for (var cancelAt = 0; cancelAt <= 2; cancelAt++)
        {
            using var cancellation = new CancellationTokenSource();
            if (cancelAt == 0) cancellation.Cancel();
            var clock = new PreClaimClock(boot, [3], reads => { if (reads == cancelAt) cancellation.Cancel(); });
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await protector.RestoreCurrentAsync(blob,
                scope, authority, directory, current, new OnionTrustedTimeAuthority(clock), cancellation.Token));
            Assert.Equal(cancelAt, clock.Reads);
        }
        foreach (var suspendAt in new[] { 1, 2 })
        {
            var originalKey = SHA256.HashData("DID2/preclaim/test/at-rest-key"u8);
            using var disposable = new InitiatorDph2PreKeyClaimPersistenceProtector(originalKey);
            CryptographicOperations.ZeroMemory(originalKey);
            var owners = new List<SecretBuffer>();
            using var hook = MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
            {
                OwnedSecret = (name, owner) => { if (name.StartsWith("initial-session.preclaim-", StringComparison.Ordinal)) owners.Add(owner); }
            });
            var clock = new PreClaimSuspendedClock(boot, suspendAt);
            var restoring = disposable.RestoreCurrentAsync(blob, scope, authority, directory,
                current, new OnionTrustedTimeAuthority(clock)).AsTask();
            await clock.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            disposable.Dispose(); clock.Release.TrySetResult();
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await restoring);
            Assert.Equal(suspendAt == 1 ? 0 : 2, owners.Count);
            Assert.All(owners, owner => Assert.Throws<MessagingCryptoException>(() => owner.Copy()));
        }
        var restoredOwners = new List<SecretBuffer>();
        using (var hook = MessagingCryptoFaultInjection.InstallDarkForTests(new MessagingCryptoFaultProbe
        {
            OwnedSecret = (name, owner) =>
            {
                if (!name.StartsWith("initial-session.preclaim-", StringComparison.Ordinal)) return;
                restoredOwners.Add(owner);
                if (restoredOwners.Count == 2) throw new IOException("Injected stop during preclaim ownership construction.");
            }
        }))
        {
            await Assert.ThrowsAsync<IOException>(async () => await protector.RestoreCurrentAsync(blob,
                scope, authority, directory, current, new OnionTrustedTimeAuthority(new PreClaimClock(boot, [3]))));
        }
        Assert.Equal(2, restoredOwners.Count);
        Assert.All(restoredOwners, owner => Assert.Throws<MessagingCryptoException>(() => owner.Copy()));
        await AssertIndependentPreClaimEnvelopeAsync(blob, scope, protector, authority, directory, current, boot);
        CryptographicOperations.ZeroMemory(key);
    }

    private static async Task AssertIndependentPreClaimEnvelopeAsync(InitiatorDph2PreKeyClaimPersistenceBlob blob,
        InitiatorDph2PreKeyClaimPersistenceScope scope, InitiatorDph2PreKeyClaimPersistenceProtector protector,
        LocalDeviceX25519AgreementAuthority authority, Dmd1LineageState directory,
        VerifiedDeepIdV2DirectoryFreshness current, byte[] boot)
    {
        var sourceKey = SHA256.HashData("DID2/preclaim/test/at-rest-key"u8);
        var header = blob.CanonicalBytes.Span[..2472].ToArray();
        var input = Encoding.ASCII.GetBytes("Deep/Messaging/V2/dph2-preclaim-persistence-key")
            .Concat(new byte[1]).Concat(header).ToArray();
        byte[]? derived = null, plaintext = null;
        try
        {
            derived = HMACSHA256.HashData(sourceKey, input);
            plaintext = SecretAeadXChaCha20Poly1305.Decrypt(blob.CanonicalBytes.Span[2472..].ToArray(),
                header.AsSpan(2448, 24).ToArray(), derived, header);
            Assert.Equal(64, plaintext.Length);
            // Independent interpretation of the frozen envelope/KDF, rather
            // than only a round-trip through one production implementation.
            var ephemeralPublic = new byte[32]; var ratchetPublic = new byte[32];
            OwnedSodiumX25519.DerivePublicKey(plaintext.AsSpan(0, 32), ephemeralPublic);
            OwnedSodiumX25519.DerivePublicKey(plaintext.AsSpan(32, 32), ratchetPublic);
            Assert.True(CryptographicOperations.FixedTimeEquals(ephemeralPublic, header.AsSpan(2384, 32)));
            Assert.True(CryptographicOperations.FixedTimeEquals(ratchetPublic, header.AsSpan(2416, 32)));
            foreach (var zeroScalar in new[] { true, false })
            {
                var malformed = plaintext.ToArray();
                byte[]? ciphertext = null;
                try
                {
                    if (zeroScalar) malformed.AsSpan(0, 32).Clear();
                    else malformed[1] ^= 1; // Not a clamping bit: the public pair must change.
                    ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(malformed,
                        header.AsSpan(2448, 24).ToArray(), derived, header);
                    byte[] exactReauthenticated = [.. header, .. ciphertext];
                    var reauthenticated = InitiatorDph2PreKeyClaimPersistenceBlob.Decode(exactReauthenticated);
                    await Assert.ThrowsAnyAsync<CryptographicException>(async () => await protector.RestoreCurrentAsync(
                        reauthenticated, scope, authority, directory, current,
                        new OnionTrustedTimeAuthority(new PreClaimClock(boot, [3]))));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(malformed);
                    if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sourceKey); CryptographicOperations.ZeroMemory(input);
            if (derived is not null) CryptographicOperations.ZeroMemory(derived);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private sealed class PreClaimClock(byte[] boot, ulong[] samples, Action<int>? afterRead = null) : IOnionMonotonicClock
    {
        internal int Reads { get; private set; }
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            var index = Reads++;
            afterRead?.Invoke(Reads);
            return ValueTask.FromResult(new OnionMonotonicReading(boot, samples[Math.Min(index, samples.Length - 1)]));
        }
    }

    private sealed class PreClaimSuspendedClock(byte[] boot, int suspendAt) : IOnionMonotonicClock
    {
        private int reads;
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            if (++reads == suspendAt) { Entered.TrySetResult(); await Release.Task.WaitAsync(cancellationToken); }
            return new(boot, 3);
        }
    }
}
