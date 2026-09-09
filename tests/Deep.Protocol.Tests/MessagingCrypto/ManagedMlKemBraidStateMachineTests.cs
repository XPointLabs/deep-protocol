using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class ManagedMlKemBraidStateMachineTests
{
    private const int PersistedVectorOffset = 18 + 79 + 32 + 32;
    private static readonly byte[] InitialAuthenticatorSecret = Fill(0x5a, 32);

    [Fact]
    public void ClosedStateTransitionAndWireKindSetsMatchSignalV153()
    {
        var states = Enum.GetValues<ManagedMlKemBraidState>();
        var kinds = Enum.GetValues<Dtr2BraidMessageKind>();
        var transitions = 0;
        foreach (var from in states)
        foreach (var to in states)
            if (ManagedMlKemBraidStateMachine.IsDefinedTransition(from, to))
                transitions++;

        Assert.Equal(ManagedMlKemBraidStateMachine.StateCount, states.Length);
        Assert.Equal(ManagedMlKemBraidStateMachine.TransitionCount, transitions);
        Assert.Equal(7, kinds.Length);
        Assert.True(ManagedMlKemBraidStateMachine.IsDefinedTransition(
            ManagedMlKemBraidState.Ct1Sampled,
            ManagedMlKemBraidState.Ct1Acknowledged));
        Assert.False(ManagedMlKemBraidStateMachine.IsDefinedTransition(
            ManagedMlKemBraidState.Ct1Acknowledged,
            ManagedMlKemBraidState.EkReceivedCt1Sampled));
    }

    [WindowsBraidCandidateFact]
    public void RealCandidateCompletesTwoEpochsWithRoleReversal()
    {
        using var provider = LoadRealCandidateOrSkip();
        using var alice = ManagedMlKemBraidStateMachine.CreateAlice(
            provider, InitialAuthenticatorSecret);
        using var bob = ManagedMlKemBraidStateMachine.CreateBob(
            provider, InitialAuthenticatorSecret);

        var first = CompleteEpoch(alice, bob, 1);
        try
        {
            Assert.Equal(ManagedMlKemBraidState.NoHeaderReceived, alice.State);
            Assert.Equal(2UL, alice.Epoch);
            Assert.Equal(ManagedMlKemBraidState.Ct2Sampled, bob.State);
            Assert.Equal(1UL, bob.Epoch);

            Assert.Null(bob.Receive(2, alice.Send()));
            Assert.Equal(ManagedMlKemBraidState.KeysUnsampled, bob.State);
            Assert.Equal(2UL, bob.Epoch);

            var second = CompleteEpoch(bob, alice, 2);
            try
            {
                Assert.Equal(ManagedMlKemBraidState.NoHeaderReceived, bob.State);
                Assert.Equal(3UL, bob.Epoch);
                Assert.Equal(ManagedMlKemBraidState.Ct2Sampled, alice.State);
                Assert.Equal(2UL, alice.Epoch);
            }
            finally { Zero(second); }
        }
        finally { Zero(first); }
    }

    [WindowsBraidCandidateFact]
    public void ValidOutOfOrderCt1AckPathsPreserveSignalSemantics()
    {
        using var provider = LoadRealCandidateOrSkip();

        using (var alice = ManagedMlKemBraidStateMachine.CreateAlice(
                   provider, InitialAuthenticatorSecret))
        using (var bob = ManagedMlKemBraidStateMachine.CreateBob(
                   provider, InitialAuthenticatorSecret))
        {
            bob.Receive(1, alice.Send());
            var ciphertext1 = bob.Send();
            alice.Receive(1, ciphertext1);

            var beforeEarlyAck = bob.ExportLocalPlaintextState();
            try
            {
                Assert.Null(bob.Receive(1, Dtr2BraidMessage.Ciphertext1Ack()));
                var afterEarlyAck = bob.ExportLocalPlaintextState();
                try { Assert.Equal(beforeEarlyAck, afterEarlyAck); }
                finally { Zero(afterEarlyAck); }
            }
            finally { Zero(beforeEarlyAck); }

            using var bobOutput = bob.Receive(1, alice.Send());
            Assert.NotNull(bobOutput);
            Assert.Equal(ManagedMlKemBraidState.Ct2Sampled, bob.State);
        }

        using (var alice = ManagedMlKemBraidStateMachine.CreateAlice(
                   provider, InitialAuthenticatorSecret))
        using (var bob = ManagedMlKemBraidStateMachine.CreateBob(
                   provider, InitialAuthenticatorSecret))
        {
            bob.Receive(1, alice.Send());
            var ciphertext1 = bob.Send();
            alice.Receive(1, ciphertext1);
            AssertUnchanged(alice, () => Assert.Null(alice.Receive(1, ciphertext1)));
            using var bobOutput = bob.Receive(1, alice.Send());
            Assert.NotNull(bobOutput);
            Assert.Equal(ManagedMlKemBraidState.Ct2Sampled, bob.State);
        }
    }

    [WindowsBraidCandidateFact]
    public void WrongEpochKindAndTamperingAreRejectedWithoutMutation()
    {
        using var provider = LoadRealCandidateOrSkip();
        using var alice = ManagedMlKemBraidStateMachine.CreateAlice(
            provider, InitialAuthenticatorSecret);
        using var bob = ManagedMlKemBraidStateMachine.CreateBob(
            provider, InitialAuthenticatorSecret);

        var header = alice.Send();
        AssertUnchangedAfterFailure(
            bob,
            () => bob.Receive(2, header),
            MessagingCryptoError.TransitionRejected);
        AssertUnchanged(bob, () => Assert.Null(bob.Receive(1, Dtr2BraidMessage.None())));

        var tamperedHeader = TamperHeaderMac(header);
        AssertUnchangedAfterFailure(
            bob,
            () => bob.Receive(1, tamperedHeader),
            MessagingCryptoError.TransitionRejected);

        bob.Receive(1, header);
        var ciphertext1 = bob.Send();
        alice.Receive(1, ciphertext1);
        var encapsulationKey = alice.Send();
        var tamperedKey = TamperEncapsulationKey(encapsulationKey);
        AssertUnchangedAfterFailure(
            bob,
            () => bob.Receive(1, tamperedKey),
            MessagingCryptoError.TransitionRejected);

        using var bobOutput = bob.Receive(1, encapsulationKey);
        Assert.NotNull(bobOutput);
        var ciphertext2 = bob.Send();
        var tamperedCiphertext2 = TamperCiphertext2Mac(ciphertext2);
        AssertUnchangedAfterFailure(
            alice,
            () => alice.Receive(1, tamperedCiphertext2),
            MessagingCryptoError.TransitionRejected);
    }

    [WindowsBraidCandidateFact]
    public void RestartMidEncaps1RecreatesNativeStateAndConverges()
    {
        using var provider = LoadRealCandidateOrSkip();
        using var alice = ManagedMlKemBraidStateMachine.CreateAlice(
            provider, InitialAuthenticatorSecret);
        var bob = ManagedMlKemBraidStateMachine.CreateBob(
            provider, InitialAuthenticatorSecret);
        byte[]? persisted = null;
        try
        {
            bob.Receive(1, alice.Send());
            var ciphertext1 = bob.Send();
            alice.Receive(1, ciphertext1);
            persisted = bob.ExportLocalPlaintextState();
            Assert.Equal(4897, persisted.Length);
            var repeat = bob.ExportLocalPlaintextState();
            try { Assert.Equal(persisted, repeat); }
            finally { Zero(repeat); }

            bob.Dispose();
            bob = ManagedMlKemBraidStateMachine.ImportLocalPlaintextState(provider, persisted);
            Assert.Equal(ManagedMlKemBraidState.Ct1Sampled, bob.State);
            Assert.Equal(1UL, bob.Epoch);

            using var bobOutput = bob.Receive(1, alice.Send());
            Assert.NotNull(bobOutput);
            var ciphertext2 = bob.Send();
            using var aliceOutput = alice.Receive(1, ciphertext2);
            Assert.NotNull(aliceOutput);
            AssertSecretsEqual(bobOutput!, aliceOutput!);
        }
        finally
        {
            bob.Dispose();
            Zero(persisted);
        }
    }

    [WindowsBraidCandidateFact]
    public void CanonicalStateImportRejectsLengthMaskAndSecretSlotTampering()
    {
        using var provider = LoadRealCandidateOrSkip();
        using var bob = ManagedMlKemBraidStateMachine.CreateBob(
            provider, InitialAuthenticatorSecret);
        var exact = bob.ExportLocalPlaintextState();
        try
        {
            Assert.Throws<MessagingCryptoException>(() =>
                ManagedMlKemBraidStateMachine.ImportLocalPlaintextState(provider, exact[..^1]));

            var wrongMask = exact.ToArray();
            wrongMask[17] = 1;
            try
            {
                Assert.Throws<MessagingCryptoException>(() =>
                    ManagedMlKemBraidStateMachine.ImportLocalPlaintextState(provider, wrongMask));
            }
            finally { Zero(wrongMask); }

            var absentSlot = exact.ToArray();
            absentSlot[97] = 1;
            try
            {
                Assert.Throws<MessagingCryptoException>(() =>
                    ManagedMlKemBraidStateMachine.ImportLocalPlaintextState(provider, absentSlot));
            }
            finally { Zero(absentSlot); }

            using var alice = ManagedMlKemBraidStateMachine.CreateAlice(
                provider, InitialAuthenticatorSecret);
            _ = alice.Send();
            var boundKeyState = alice.ExportLocalPlaintextState();
            boundKeyState[PersistedVectorOffset + 257] ^= 0x40;
            try
            {
                Assert.Throws<MessagingCryptoException>(() =>
                    ManagedMlKemBraidStateMachine.ImportLocalPlaintextState(
                        provider, boundKeyState));
            }
            finally { Zero(boundKeyState); }
        }
        finally { Zero(exact); }
    }

    private static byte[] CompleteEpoch(
        ManagedMlKemBraidStateMachine sender,
        ManagedMlKemBraidStateMachine recipient,
        ulong epoch)
    {
        recipient.Receive(epoch, sender.Send());
        sender.Receive(epoch, recipient.Send());
        using var recipientOutput = recipient.Receive(epoch, sender.Send());
        Assert.NotNull(recipientOutput);
        var ciphertext2 = recipient.Send();
        using var senderOutput = sender.Receive(epoch, ciphertext2);
        Assert.NotNull(senderOutput);
        AssertSecretsEqual(recipientOutput!, senderOutput!);
        return senderOutput!.Copy();
    }

    private static void AssertUnchangedAfterFailure(
        ManagedMlKemBraidStateMachine machine,
        Action action,
        MessagingCryptoError expected)
    {
        var before = machine.ExportLocalPlaintextState();
        try
        {
            var exception = Assert.Throws<MessagingCryptoException>(action);
            Assert.Equal(expected, exception.Error);
            var after = machine.ExportLocalPlaintextState();
            try { Assert.Equal(before, after); }
            finally { Zero(after); }
        }
        finally { Zero(before); }
    }

    private static void AssertUnchanged(
        ManagedMlKemBraidStateMachine machine,
        Action action)
    {
        var before = machine.ExportLocalPlaintextState();
        try
        {
            action();
            var after = machine.ExportLocalPlaintextState();
            try { Assert.Equal(before, after); }
            finally { Zero(after); }
        }
        finally { Zero(before); }
    }

    private static Dtr2BraidMessage TamperHeaderMac(Dtr2BraidMessage message)
    {
        var seed = new byte[32];
        var hash = new byte[32];
        var mac = new byte[32];
        try
        {
            message.CopyHeaderTo(seed, hash, mac);
            mac[^1] ^= 0x80;
            return Dtr2BraidMessage.Header(seed, hash, mac);
        }
        finally { Zero(seed, hash, mac); }
    }

    private static Dtr2BraidMessage TamperEncapsulationKey(Dtr2BraidMessage message)
    {
        var vector = new byte[DeepMlKemBraidNativeProvider.EncapsulationKeyVectorSize];
        try
        {
            message.CopyEncapsulationKeyTo(vector);
            vector[257] ^= 0x40;
            return Dtr2BraidMessage.EncapsulationKey(vector);
        }
        finally { Zero(vector); }
    }

    private static Dtr2BraidMessage TamperCiphertext2Mac(Dtr2BraidMessage message)
    {
        var ciphertext2 = new byte[DeepMlKemBraidNativeProvider.Ciphertext2Size];
        var mac = new byte[32];
        try
        {
            message.CopyCiphertext2To(ciphertext2, mac);
            mac[13] ^= 0x20;
            return Dtr2BraidMessage.Ciphertext2(ciphertext2, mac);
        }
        finally { Zero(ciphertext2, mac); }
    }

    private static void AssertSecretsEqual(SecretBuffer expected, SecretBuffer actual)
    {
        var left = expected.Copy();
        var right = actual.Copy();
        try { Assert.True(CryptographicOperations.FixedTimeEquals(left, right)); }
        finally { Zero(left, right); }
    }

    private static DeepMlKemBraidNativeProvider LoadRealCandidateOrSkip()
    {
        var candidate = DeepMlKemBraidApprovedAssets.CandidateForCurrentWindowsProcess();
        var target = RuntimeInformation.ProcessArchitecture == Architecture.X64
            ? "x86_64-pc-windows-msvc"
            : "aarch64-pc-windows-msvc";
        var source = FindAsset(
            "DEEP_MLKEM_BRAID_TEST_ASSET",
            "native", "Deep.MlKemBraid", "target",
            target, "release", "deep_mlkem_braid.dll");
        Stage(source, candidate.RelativePath);
        return DeepMlKemBraidNativeProvider.LoadCandidateForTests(
            candidate);
    }

    private static void Stage(string source, string relativePath)
    {
        var destination = Path.Combine(
            AppContext.BaseDirectory,
            relativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        if (File.Exists(destination))
        {
            var sourceHash = SHA256.HashData(File.ReadAllBytes(source));
            var destinationHash = SHA256.HashData(File.ReadAllBytes(destination));
            try
            {
                if (CryptographicOperations.FixedTimeEquals(sourceHash, destinationHash)) return;
            }
            finally { Zero(sourceHash, destinationHash); }
        }
        File.Copy(source, destination, overwrite: true);
    }

    private static string FindAsset(string environmentName, params string[] relativeParts)
    {
        var explicitPath = Environment.GetEnvironmentVariable(environmentName);
        if (!string.IsNullOrWhiteSpace(explicitPath) && File.Exists(explicitPath))
            return Path.GetFullPath(explicitPath);
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine([current.FullName, .. relativeParts]);
            if (File.Exists(candidate)) return candidate;
            current = current.Parent;
        }
        throw new FileNotFoundException(
            "The reviewed Windows incremental ML-KEM candidate is absent.");
    }

    private static byte[] Fill(byte value, int length)
    {
        var output = new byte[length];
        output.AsSpan().Fill(value);
        return output;
    }

    private static void Zero(params byte[]?[] values)
    {
        foreach (var value in values)
            if (value is not null)
                CryptographicOperations.ZeroMemory(value);
    }
}

internal sealed class WindowsBraidCandidateFactAttribute : FactAttribute
{
    public WindowsBraidCandidateFactAttribute()
    {
        if (!OperatingSystem.IsWindows() ||
            RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
        {
            Skip = "Requires a Windows x64 or ARM64 process for the reviewed Braid candidate.";
            return;
        }

        var explicitPath = Environment.GetEnvironmentVariable("DEEP_MLKEM_BRAID_TEST_ASSET");
        if (!string.IsNullOrWhiteSpace(explicitPath) && File.Exists(explicitPath)) return;

        var target = RuntimeInformation.ProcessArchitecture == Architecture.X64
            ? "x86_64-pc-windows-msvc"
            : "aarch64-pc-windows-msvc";
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(
                current.FullName,
                "native", "Deep.MlKemBraid", "target",
                target, "release", "deep_mlkem_braid.dll");
            if (File.Exists(candidate)) return;
            current = current.Parent;
        }
        Skip = "The reviewed Windows incremental ML-KEM candidate is absent.";
    }
}
