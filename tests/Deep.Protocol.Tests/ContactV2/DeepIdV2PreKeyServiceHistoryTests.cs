using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2PreKeyServiceHistoryTests
{
    public static IEnumerable<object[]> FrozenCases()
    {
        using var document = ReadVectors();
        foreach (var item in document.RootElement.GetProperty("anchoredCases").EnumerateArray())
            yield return [item.GetProperty("id").GetString()!];
    }

    [Theory]
    [MemberData(nameof(FrozenCases))]
    public void ExactSignedHistoryRequiresActualPriorAnchor(string id)
    {
        using var document = ReadVectors();
        var root = document.RootElement;
        var records = root.GetProperty("records").EnumerateArray().ToDictionary(
            item => item.GetProperty("id").GetString()!, item =>
            {
                var exact = Convert.FromHexString(item.GetProperty("exactHex").GetString()!);
                Assert.Equal(352, exact.Length);
                Assert.Equal(item.GetProperty("sha256").GetString(),
                    Convert.ToHexString(SHA256.HashData(exact)).ToLowerInvariant());
                return DeepIdV2PreKeyServiceCodec.Decode(exact);
            });
        var selected = root.GetProperty("anchoredCases").EnumerateArray()
            .Single(item => item.GetProperty("id").GetString() == id);
        var current = records[selected.GetProperty("current").GetString()!];
        var prior = records[selected.GetProperty("prior").GetString()!];
        var history = selected.GetProperty("history").EnumerateArray()
            .Select(item => records[item.GetString()!]).ToArray();
        var key = Convert.FromHexString(root.GetProperty("publicDeviceSigningKeyHex").GetString()!);
        var error = Record.Exception(() => DeepIdV2PreKeyLineageVerifier.VerifyServiceHistory(
            current, prior, history, key));
        if (selected.GetProperty("accept").GetBoolean()) Assert.Null(error);
        else Assert.True(error is CryptographicException or ApplicationCoreFormatException,
            "An unanchored or nonexact signed history must reject.");
    }

    [Fact]
    public void IntermediateHistoryCannotRelaxTheImmediateHopPredicate()
    {
        using var document = ReadVectors();
        var root = document.RootElement;
        ParsedXps1V2 Service(string id) => DeepIdV2PreKeyServiceCodec.Decode(Convert.FromHexString(
            root.GetProperty("records").EnumerateArray().Single(item => item.GetProperty("id").GetString() == id)
                .GetProperty("exactHex").GetString()!));
        var key = Convert.FromHexString(root.GetProperty("publicDeviceSigningKeyHex").GetString()!);
        DeepIdV2PreKeyLineageVerifier.VerifyServiceTransition(Service("six"), Service("five"), key);
        DeepIdV2PreKeyLineageVerifier.VerifyServiceTransition(Service("seven"), Service("six"), key);
        Assert.Throws<CryptographicException>(() => DeepIdV2PreKeyLineageVerifier.VerifyServiceTransition(
            Service("seven"), Service("five"), key));
        var oversized = Enumerable.Repeat(Service("six"), 46).ToArray();
        Assert.ThrowsAny<Exception>(() => DeepIdV2PreKeyLineageVerifier.VerifyServiceHistory(
            Service("seven"), Service("five"), oversized, key));
    }

    private static JsonDocument ReadVectors()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var path = Path.Combine(directory.FullName, "docs", "survival-program", "releases", "v3.0.0", "specs",
                "contact-prekey-lineage-v2.vectors.json");
            if (File.Exists(path)) return JsonDocument.Parse(File.ReadAllBytes(path));
        }
        throw new FileNotFoundException("The frozen DR-0129 service history corpus is required.");
    }
}
