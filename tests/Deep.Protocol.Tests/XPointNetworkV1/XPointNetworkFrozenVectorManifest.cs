using System.Security.Cryptography;
using System.Text.Json;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed record XPointPrimitiveVector(
    string Id,
    string Operation,
    string Domain,
    string InputHex,
    string PreimageHex,
    string ExpectedHex);

public sealed record XPointNegativeVector(
    string Id,
    string? InputHex,
    string ExpectedStage,
    string ExpectedError);

internal static class XPointNetworkFrozenVectorManifest
{
    // Deliberately pins the complete frozen fixture corpus.  The per-vector tests
    // below execute the bytes; this catches any unrelated fixture substitution too.
    private const string ExpectedSha256 = "fc682d0bb63a9383b1fe6842d09596cff5555a41c12da9ad38bb6d20de2119eb";

    internal static IReadOnlyList<XPointPrimitiveVector> PrimitiveVectors { get; } = LoadPrimitives();
    internal static IReadOnlyList<XPointNegativeVector> NegativeVectors { get; } = LoadNegatives();

    internal static void AssertUntampered()
    {
        var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path))).ToLowerInvariant();
        Assert.Equal(ExpectedSha256, actual);
    }

    private static IReadOnlyList<XPointPrimitiveVector> LoadPrimitives()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path));
        return document.RootElement.GetProperty("primitiveVectors").EnumerateArray().Select(value => new XPointPrimitiveVector(
            value.GetProperty("id").GetString()!,
            value.GetProperty("operation").GetString()!,
            value.GetProperty("domain").GetString()!,
            value.GetProperty("inputHex").GetString()!,
            value.GetProperty("preimageHex").GetString()!,
            value.GetProperty("expectedHex").GetString()!)).ToArray();
    }

    private static IReadOnlyList<XPointNegativeVector> LoadNegatives()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path));
        return document.RootElement.GetProperty("negativeCases").EnumerateArray().Select(value => new XPointNegativeVector(
            value.GetProperty("id").GetString()!,
            value.TryGetProperty("inputHex", out var input) && input.ValueKind != JsonValueKind.Null ? input.GetString() : null,
            value.GetProperty("expectedStage").GetString()!,
            value.GetProperty("expectedError").GetString()!)).ToArray();
    }

    internal static string Path => FindSpec("xpoint-network-v1.vectors.json");

    internal static string FindSpec(string fileName)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = System.IO.Path.Combine(directory.FullName, "docs", "survival-program", "releases", "v3.0.0", "specs", fileName);
            if (File.Exists(candidate)) return candidate;
            directory = directory.Parent;
        }
        throw new FileNotFoundException("Frozen XPoint vector manifest was not found from the test output tree.");
    }
}
