using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Non-forgeable identity/directory closure recovered from an ADP1
/// CurrentValue proof and the exact DID1 named by the requesting protocol.
/// ADP1 intentionally carries only the DID hash/address projection, so the
/// resolver capability bytes must arrive through an independently
/// authenticated protocol field such as DPH2.
/// </summary>
public sealed class VerifiedAccountDirectoryCurrentValueClosure
{
    internal VerifiedAccountDirectoryCurrentValueClosure(
        VerifiedAccountDirectoryCheckpoint checkpoint,
        Dab1LineageState addressBinding,
        Dmd1LineageState directory)
    {
        Checkpoint = checkpoint;
        AddressBinding = addressBinding;
        Directory = directory;
    }

    public VerifiedAccountDirectoryCheckpoint Checkpoint { get; }
    public Dab1LineageState AddressBinding { get; }
    public Dmd1LineageState Directory { get; }
}

public static class AccountDirectoryCurrentValueClosureVerifier
{
    public static VerifiedAccountDirectoryCurrentValueClosure Verify(
        AccountDirectoryAdp1 proof,
        ReadOnlySpan<byte> exactDid1,
        ulong trustedUnixSeconds,
        ushort deploymentProfileId,
        ushort supportedReader)
    {
        ArgumentNullException.ThrowIfNull(proof);
        if (proof.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue ||
            proof.CurrentValue is null)
            throw new CryptographicException(
                "The account-directory proof has no current identity value.");
        if (trustedUnixSeconds == 0 || deploymentProfileId == 0 || supportedReader == 0)
            throw new ArgumentOutOfRangeException(nameof(trustedUnixSeconds));

        var current = proof.CurrentValue;
        var did = ApplicationCoreCodec.DecodeDid1(exactDid1);
        if (!Fixed(did.RecordHash.Span, current.ExactDid1Hash.Span) ||
            !Fixed(did.AddressPublicKey.Span, current.Did1AddressPublicKey.Span))
            throw new CryptographicException(
                "The exact DID1 differs from the ADP1 current-value projection.");

        var verifier = new IdentityRelativeVerifier();
        var identity = verifier.VerifyGenesis(
            current.Dpa1.CanonicalBytes.Span,
            current.Drs1.CanonicalBytes.Span,
            [],
            trustedUnixSeconds);
        var devices = current.ExactDpd1Records
            .Select(value => verifier.RestoreDeviceFromRecovery(
                identity, value.Span, trustedUnixSeconds))
            .OrderBy(static value => value.Certificate.DeviceId.ToArray(),
                LexicographicByteArrayComparer.Instance)
            .ToArray();
        var applicationIdentity = ApplicationCoreVerifier.CreateIdentityClosure(
            identity, devices);
        var binding = ApplicationCoreVerifier.StartDab1Lineage(
            ApplicationCoreVerifier.VerifyDab1(
                current.Dab1, did, applicationIdentity, deploymentProfileId)).Next;
        var directory = ApplicationCoreVerifier.StartDmd1Lineage(
            ApplicationCoreVerifier.VerifyDmd1(
                current.Dmd1, applicationIdentity)).Next;
        var checkpoint = AccountDirectoryAdc1Verifier.Verify(
            current.Adc1,
            binding.Head,
            directory.Head,
            [],
            supportedReader);
        return new VerifiedAccountDirectoryCurrentValueClosure(
            checkpoint, binding, directory);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private sealed class LexicographicByteArrayComparer : IComparer<byte[]>
    {
        internal static LexicographicByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? x, byte[]? y) => x.AsSpan().SequenceCompareTo(y);
    }
}
