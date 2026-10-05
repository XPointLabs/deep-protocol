using System.Reflection;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class RetiredMailboxIssuanceSurfaceTests
{
    [Theory]
    [InlineData("ProductionMailboxIssuanceIntent")]
    [InlineData("ProductionMailboxClientPlatform")]
    [InlineData("ProductionMailboxHolderProofError")]
    [InlineData("ProductionMailboxHolderProofException")]
    [InlineData("ProductionMailboxHolderProofInput")]
    [InlineData("IProductionMailboxHolderProofSignatureVerifier")]
    [InlineData("SodiumProductionMailboxHolderProofSignatureVerifier")]
    [InlineData("ProductionMailboxHolderProof")]
    public void ActualAssemblyHasNoRetiredIssuanceProducer(string typeName)
    {
        var assembly = typeof(VerifiedProductionMailboxRevocationSnapshot).Assembly;
        Assert.Null(assembly.GetType("Deep.Protocol.DeepExtension.MailboxAuthority." + typeName));
    }

    [Fact]
    public void RetainedNativeObservationCannotBeUsedAsCurrentGrantRevocationSource()
    {
        var type = typeof(VerifiedProductionMailboxRevocationSnapshot);
        Assert.False(typeof(IMailboxCapabilityRevocationSource).IsAssignableFrom(type));
        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
        Assert.Equal(new[] { "get_CanonicalSnapshotHash", "get_RevokedGrantSerialCount", "get_Snapshot" },
            methods.Select(static method => method.Name).Order(StringComparer.Ordinal));
        Assert.DoesNotContain(type.GetConstructors(), static constructor => constructor.IsPublic);
    }
}
