using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;

namespace Deep.Protocol.Tests.Identity;

public sealed partial class Dnp1IdentityAuthoringV1Tests
{
    [Fact]
    public async Task RealDid2AlternateNetworkEpochClosesThroughAdmissionWire()
    {
        if (!((OperatingSystem.IsWindows() &&
                System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is
                    (System.Runtime.InteropServices.Architecture.X64 or
                     System.Runtime.InteropServices.Architecture.Arm64)) ||
              (OperatingSystem.IsLinux() &&
                System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
                    System.Runtime.InteropServices.Architecture.X64)))
            return;
        var (admission, checkpoint, _) = await CreateRealDid2DirectoryGenesisAsync(
            Enumerable.Repeat((byte)0x11, 16).ToArray(), 1_700_000_000);
        var request = new DeepIdV2GenesisAdmissionWireRequest(
            Enumerable.Repeat((byte)0x91, 32).ToArray(), admission);
        var exact = DeepIdV2GenesisAdmissionWireCodec.EncodeRequest(request);
        Assert.Equal(8498, exact.Length);
        var fixtureOutput = Environment.GetEnvironmentVariable(
            "DEEP_DID2_GENESIS_FIXTURE_OUTPUT");
        if (!string.IsNullOrWhiteSpace(fixtureOutput))
            await File.WriteAllBytesAsync(fixtureOutput, exact);
        var decoded = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(exact);
        using var verifier = DeepMlDsa65CandidateVerifierFactory
            .OpenForCurrentProcess();
        var admitted = DeepIdV2GenesisAdmissionVerifier.Verify(
            decoded.Admission, 1_700_000_405, 1, 2, verifier);
        Assert.Equal(checkpoint.Checkpoint.ArtifactHash.ToArray(),
            admitted.Checkpoint.ArtifactHash.ToArray());
        var relative = Assert.Single(admitted.Binding.Identity.ActiveDeviceRelatives);
        Assert.Equal(admission.ExactDpd1.Single().ToArray(),
            relative.Certificate.CanonicalBytes.ToArray());
        var factsOnly = ApplicationCoreVerifier.CreateIdentityClosure(
            admitted.Binding.Identity.Account,
            admitted.Binding.Identity.Revocations,
            admitted.Binding.Identity.ActiveDevices);
        Assert.Empty(factsOnly.ActiveDeviceRelatives);
    }

    internal static async Task<(DeepIdV2GenesisAdmissionRequest Admission,
        VerifiedAdc1V2 Checkpoint, VerifiedDab2 Binding)> CreateRealDid2DirectoryGenesisAsync(
        byte[]? networkOverride = null, ulong epoch = 1_900_000_000,
        string? mnemonicOverride = null)
    {
        var (admission, checkpoint, binding, _) = await
            CreateRealDid2DirectoryGenesisWithDcaAsync(
                networkOverride, epoch, mnemonicOverride);
        return (admission, checkpoint, binding);
    }

    internal static async Task<(DeepIdV2GenesisAdmissionRequest Admission,
        VerifiedAdc1V2 Checkpoint, VerifiedDab2 Binding,
        VerifiedDca1V2 Authorization)> CreateRealDid2DirectoryGenesisWithDcaAsync(
        byte[]? networkOverride = null, ulong epoch = 1_900_000_000,
        string? mnemonicOverride = null)
    {
        var network = networkOverride ?? Network;
        using var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(
            Encoding.ASCII.GetBytes(mnemonicOverride ?? Mnemonic));
        using var recovery = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase, network, 1);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, epoch, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device,
            issuedAtUnixSeconds: checked(epoch + 100));
        var closure = ApplicationCoreVerifier.CreateIdentityClosure(
            issued.Verified.Identity, [issued.Verified]);
        var binding = recovery.AuthorGenesisDab2(phrase, closure, 1);
        var directory = recovery.AuthorGenesisDmd1(closure, checked(epoch + 200));
        var authorization = recovery.AuthorGenesisDca1V2(binding, directory,
            issued.Verified, checked(epoch + 250));
        var checkpoint = recovery.AuthorGenesisAdc1V2(binding, directory,
            checked(epoch + 300));
        var admission = new DeepIdV2GenesisAdmissionRequest(
            account.CanonicalDpa1.Span, account.CanonicalDrs1.Span,
            [issued.CanonicalDpd1], binding.Head.DeepId.CanonicalBytes.Span,
            binding.Head.Record.CanonicalBytes.Span,
            directory.Head.Record.CanonicalBytes.Span,
            checkpoint.Checkpoint.CanonicalBytes.Span, []);
        return (admission, checkpoint, binding.Head, authorization);
    }
}
