using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;

namespace Deep.Protocol.Tests.Identity;

public sealed partial class Dnp1IdentityAuthoringV1Tests
{
    internal static async Task<(DeepIdV2GenesisAdmissionRequest Admission,
        VerifiedAdc1V2 Checkpoint, VerifiedDab2 Binding)> CreateRealDid2DirectoryGenesisAsync()
    {
        using var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(
            Encoding.ASCII.GetBytes(Mnemonic));
        using var recovery = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase, Network, 1);
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1, new FillRandom(0xa1));
        using var device = Device();
        var issued = await IssueDevice(recovery, account, device);
        var closure = ApplicationCoreVerifier.CreateIdentityClosure(
            issued.Verified.Identity, [issued.Verified]);
        var binding = recovery.AuthorGenesisDab2(phrase, closure, 1);
        var directory = recovery.AuthorGenesisDmd1(closure, 1_900_000_200);
        var checkpoint = recovery.AuthorGenesisAdc1V2(binding, directory,
            1_900_000_300);
        var admission = new DeepIdV2GenesisAdmissionRequest(
            account.CanonicalDpa1.Span, account.CanonicalDrs1.Span,
            [issued.CanonicalDpd1], binding.Head.DeepId.CanonicalBytes.Span,
            binding.Head.Record.CanonicalBytes.Span,
            directory.Head.Record.CanonicalBytes.Span,
            checkpoint.Checkpoint.CanonicalBytes.Span, []);
        return (admission, checkpoint, binding.Head);
    }
}
