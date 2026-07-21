using System.IO.Compression;
using System.Security.Cryptography;
using System.Xml.Linq;
using System.Text.Json;

namespace Deep.Protocol.ProfileCarrier.Tests;

public sealed class P14E2SupplyRedTests
{
    [Fact]
    public void CarrierPinsExactDirectSodiumAndLibsodiumDependencies()
    {
        var project = XDocument.Load(Path.Combine(
            RepositoryRoot(),
            "src",
            "Deep.Protocol.ProfileCarrier",
            "Deep.Protocol.ProfileCarrier.csproj"));
        var references = project.Descendants("PackageReference")
            .ToDictionary(
                value => value.Attribute("Include")!.Value,
                value => value.Attribute("Version")!.Value,
                StringComparer.Ordinal);

        Assert.Equal("[1.4.1]", references["Sodium.Core"]);
        Assert.Equal("[1.0.22]", references["libsodium"]);
    }

    [Fact]
    public void ExactVendoredLibsodiumContainsPinnedNativeAssetsForEveryRequiredRid()
    {
        var package = Path.Combine(
            RepositoryRoot(),
            "vendor",
            "p14-profile-carrier",
            "packages",
            "libsodium.1.0.22.nupkg");
        Assert.Equal(
            "f66eac31ea413c1d5d068b46ade11d3295c86ec9d6cd29ff158ba58ef51db51a",
            Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(package))));

        using var archive = ZipFile.OpenRead(package);
        foreach (var expected in NativeAssets)
        {
            var entry = Assert.Single(archive.Entries, value => value.FullName == expected.Path);
            using var stream = entry.Open();
            Assert.Equal(expected.Length, entry.Length);
            Assert.Equal(expected.Sha256, Convert.ToHexStringLower(SHA256.HashData(stream)));
        }
    }

    [Fact]
    public void OfflineGateExecutesRequiredRidNativeAssetProof()
    {
        var gate = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "eng",
            "verify-p14-profile-carrier-offline.ps1"));
        foreach (var rid in new[]
                 {
                     "win-arm64", "win-x64", "linux-arm64", "linux-x64", "android-arm64"
                 })
        {
            Assert.Contains(rid, gate, StringComparison.Ordinal);
        }
        Assert.Contains("native-asset-sha256", gate, StringComparison.Ordinal);
        Assert.Contains("CROSS-RID-EXECUTION-PENDING", gate, StringComparison.Ordinal);
        Assert.Contains(
            "verify-p14e2-win-arm64-build.ps1",
            gate,
            StringComparison.Ordinal);
    }

    [Fact]
    public void OfflineClosureRemainsExactAndAddsNoRuntimePackDownload()
    {
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "eng",
            "p14-profile-carrier.offline-packages.json")));
        var files = manifest.RootElement.GetProperty("files")
            .EnumerateArray()
            .Select(static value => value.GetProperty("name").GetString()!)
            .ToArray();

        Assert.Equal(21, files.Length);
        Assert.DoesNotContain(files, static value =>
            value.StartsWith("Microsoft.NETCore.App.Runtime.", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("Microsoft.AspNetCore.App.Runtime.", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(1, files.Count(static value =>
            value.Equals("libsodium.1.0.22.nupkg", StringComparison.Ordinal)));
        Assert.Equal(1, files.Count(static value =>
            value.Equals("Sodium.Core.1.4.1.nupkg", StringComparison.Ordinal)));
    }

    private static readonly (string Path, long Length, string Sha256)[] NativeAssets =
    [
        ("runtimes/win-arm64/native/libsodium.dll", 328_192, "1616d5625f8721c9914ee7276f3ce63bc873eab530dfcf04e8c4184e2e77052c"),
        ("runtimes/win-x64/native/libsodium.dll", 462_848, "64a1f143868309069f0a0a3c8141c0853c4f17243ddf734e92b11c5411739771"),
        ("runtimes/linux-arm64/native/libsodium.so", 422_688, "54f416a70e0d982a63e7f2402ff6f2a8666bf0a430404a4205ed8eee1868b9db"),
        ("runtimes/linux-x64/native/libsodium.so", 582_600, "963416833246938fd6983e4aa96248dbccb2f95b30095c4a94678d6fb903404b"),
        ("runtimes/android-arm64/native/libsodium.so", 423_648, "f4382f2139f1ddd3a32dce406c98f2d41b472e02351bd18df362f8cb29af1952")
    ];

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Deep.Protocol.slnx")))
        {
            directory = directory.Parent;
        }
        return directory?.FullName ?? throw new InvalidOperationException();
    }
}
