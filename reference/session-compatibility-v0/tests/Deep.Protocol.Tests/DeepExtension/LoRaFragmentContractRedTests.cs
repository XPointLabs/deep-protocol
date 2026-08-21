using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class LoRaFragmentContractRedTests
{
    private const string Namespace =
        "Deep.Protocol.DeepExtension.LoRaFragments.";

    [Theory]
    [InlineData("LoRaFragmentHeader")]
    [InlineData("LoRaFragmentPolicy")]
    [InlineData("LoRaFragmentAuthenticationHandle")]
    [InlineData("LoRaFragmentReplayScopeHandle")]
    [InlineData("ILoRaFragmentAuthenticator")]
    [InlineData("LoRaFragmentCodec")]
    [InlineData("LoRaFragmentPlanner")]
    [InlineData("LoRaFragmentReassembler")]
    public void RequiredP18APublicSurfaceExists(string typeName)
    {
        var type = typeof(Deep.Protocol.SessionProtocolCodec).Assembly.GetType(
            Namespace + typeName,
            throwOnError: false);

        Assert.NotNull(type);
    }

    [Theory]
    [InlineData("LoRaFragmentCodec", "Encode")]
    [InlineData("LoRaFragmentCodec", "Decode")]
    [InlineData("LoRaFragmentCodec", "BuildAuthenticatedTranscript")]
    [InlineData("LoRaFragmentPlanner", "Plan")]
    [InlineData("LoRaFragmentReassembler", "Process")]
    public void RequiredP18AOperationsExist(string typeName, string methodName)
    {
        var type = typeof(Deep.Protocol.SessionProtocolCodec).Assembly.GetType(
            Namespace + typeName,
            throwOnError: false);

        Assert.NotNull(type);
        Assert.Contains(
            type.GetMethods(),
            method => StringComparer.Ordinal.Equals(method.Name, methodName));
    }

    [Fact]
    public void CanonicalP18AGoldenVectorCatalogExists()
    {
        var vectors = GoldenVectorLoader.Load("lora-fragment-v1.json");

        Assert.Contains(
            vectors.Vectors,
            vector => StringComparer.Ordinal.Equals(
                vector.Id,
                "deep-extension/lora-fragment/v1/none"));
        Assert.Contains(
            vectors.Vectors,
            vector => StringComparer.Ordinal.Equals(
                vector.Id,
                "deep-extension/lora-fragment/v1/xor1"));
    }
}
