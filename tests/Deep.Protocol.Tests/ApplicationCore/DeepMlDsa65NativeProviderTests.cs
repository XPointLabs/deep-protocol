using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class DeepMlDsa65NativeProviderTests
{
    [Fact]
    public void CurrentDesktopCandidate_ExactAssetSignsVerifiesAndRejectsSubstitution()
    {
        if (!((OperatingSystem.IsWindows() &&
                RuntimeInformation.ProcessArchitecture is (Architecture.X64 or Architecture.Arm64)) ||
              (OperatingSystem.IsLinux() &&
                RuntimeInformation.ProcessArchitecture == Architecture.X64)))
            return;

        using var provider = DeepMlDsa65NativeProvider.LoadCandidateForCurrentProcess();
        using var publicVerifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        var seed = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var publicKey = provider.DerivePublicKey(seed);
        Assert.Equal(
            "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9",
            Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant());

        ReadOnlySpan<byte> context = "Deep/DAB2/V2/root"u8;
        ReadOnlySpan<byte> message = "Deep ID V2 native .NET interop"u8;
        var first = provider.Sign(seed, context, message);
        var second = provider.Sign(seed, context, message);
        Assert.Equal(3309, first.Length);
        Assert.NotEqual(first, second);
        Assert.True(provider.Verify(publicKey, message, context, first));
        Assert.True(publicVerifier.Verify(publicKey, message, context, first));
        Assert.True(provider.Verify(publicKey, message, context, second));
        Assert.False(provider.Verify(publicKey, "tampered"u8, context, first));
        Assert.False(provider.Verify(publicKey, message, "wrong"u8, first));
        publicKey[0] ^= 1;
        Assert.False(provider.Verify(publicKey, message, context, first));

        provider.Dispose();
        Assert.Throws<ObjectDisposedException>(() => provider.DerivePublicKey(seed));
        CryptographicOperations.ZeroMemory(seed);
    }
}
