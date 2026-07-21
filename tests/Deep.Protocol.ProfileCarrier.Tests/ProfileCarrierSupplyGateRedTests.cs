using System.Text.Json;
using System.Xml.Linq;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace Deep.Protocol.ProfileCarrier.Tests;

public sealed class ProfileCarrierSupplyGateRedTests
{
    [Fact]
    public void RepositoryPinsExactSdkAndCarriesExecutableOfflineAndProvenanceGates()
    {
        var root = RepositoryRoot();
        using var globalJson = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(root, "global.json")));
        var sdk = globalJson.RootElement.GetProperty("sdk");
        Assert.Equal("10.0.301", sdk.GetProperty("version").GetString());
        Assert.Equal("disable", sdk.GetProperty("rollForward").GetString());

        Assert.True(File.Exists(Path.Combine(
            root, "eng", "verify-p14-profile-carrier-offline.ps1")));
        Assert.True(File.Exists(Path.Combine(
            root, "eng", "verify-p14-profile-carrier-provenance.ps1")));
    }

    [Fact]
    public void EverySolutionProjectUsesACommittedLockedDependencyGraph()
    {
        var root = RepositoryRoot();
        var solution = File.ReadAllText(Path.Combine(root, "Deep.Protocol.slnx"));
        var projectPaths = System.Text.RegularExpressions.Regex
            .Matches(solution, "Project Path=\"([^\"]+)\"")
            .Select(match => match.Groups[1].Value.Replace('/', Path.DirectorySeparatorChar))
            .ToArray();
        Assert.NotEmpty(projectPaths);

        foreach (var relativePath in projectPaths)
        {
            var projectPath = Path.Combine(root, relativePath);
            var project = XDocument.Load(projectPath);
            Assert.Contains(
                project.Descendants("RestorePackagesWithLockFile"),
                static element => element.Value.Equals(
                    "true",
                    StringComparison.OrdinalIgnoreCase));
            Assert.True(
                File.Exists(Path.Combine(
                    Path.GetDirectoryName(projectPath)!,
                    "packages.lock.json")),
                $"Missing lock file for {relativePath}.");
        }
    }

    [Fact]
    public void PackageMetadataIsPreparedForExactCommitDerivedVersion()
    {
        var project = XDocument.Load(Path.Combine(
            RepositoryRoot(),
            "src",
            "Deep.Protocol.ProfileCarrier",
            "Deep.Protocol.ProfileCarrier.csproj"));
        Assert.Contains(
            project.Descendants("IncludeSourceRevisionInInformationalVersion"),
            static element => element.Value.Equals(
                "false",
                StringComparison.OrdinalIgnoreCase));
        Assert.Equal(
            "REVIEW-PENDING / ED25519-VERIFY-ONLY-CANDIDATE / " +
            "CLIENT-ACTIVATION-NO-GO / " +
            "EXTERNAL-CRYPTO-PROFILE-REVIEW-PENDING",
            ProfileCarrierContract.Status);
    }

    [Fact]
    public void GoldenProvenancePinsExactCommitTreeBlobsAndDifferentialHarness()
    {
        var path = Path.Combine(
            AppContext.BaseDirectory,
            "Vectors",
            "xnode-eff4523.provenance.json");
        using var manifest = JsonDocument.Parse(File.ReadAllText(path));
        var root = manifest.RootElement;

        Assert.Equal(
            "deep-p14-profile-carrier-provenance-v1",
            root.GetProperty("schema").GetString());
        Assert.Equal(
            "eff452368fa4cb1324c5b3c8ee06e2f10e96b835",
            root.GetProperty("sourceCommit").GetString());
        Assert.Equal(
            "ee7a54e9eb0bc4c0803b9508627355eec75f0405",
            root.GetProperty("sourceTree").GetString());
        Assert.Equal(
            new[]
            {
                "4394e106d924e9c4b896df2f9caccf25e36989e8",
                "c0f6030b98ac1d1696fd14b7df51b5598d72ae72",
                "dbd173d5d88ddf8da4e8976df91762ff55c6dcbc"
            },
            root.GetProperty("files")
                .EnumerateArray()
                .Select(static file => file.GetProperty("gitBlob").GetString())
                .OrderBy(static value => value, StringComparer.Ordinal));
        Assert.Equal(
            "cc8df0559b033ad7c70aa5d19134c06c58fb2dd6cfc10449525e1fb919679dbe",
            root.GetProperty("goldenSha256").GetString());
        Assert.True(File.Exists(Path.Combine(
            RepositoryRoot(),
            "eng",
            "P14ProfileCarrier.Differential",
            "Program.cs")));
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Deep.Protocol.slnx")))
        {
            directory = directory.Parent;
        }
        return directory?.FullName ??
            throw new InvalidOperationException("Repository root was not found.");
    }
}
