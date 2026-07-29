using System.Xml.Linq;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace Deep.Protocol.ProfileCarrier.Tests;

public sealed class ProfileCarrierDeterminismRedTests
{
    [Fact]
    public void CarrierProjectPinsLogicalSourceRootAndFullRepositoryIdentity()
    {
        var root = RepositoryRoot();
        var project = XDocument.Load(Path.Combine(
            root,
            "src",
            "Deep.Protocol.ProfileCarrier",
            "Deep.Protocol.ProfileCarrier.csproj"));

        AssertProperty(project, "Deterministic", "true");
        AssertProperty(project, "ContinuousIntegrationBuild", "true");
        AssertProperty(
            project,
            "PathMap",
            "$(MSBuildProjectDirectory)=/_/Deep.Protocol.ProfileCarrier");
        AssertProperty(
            project,
            "RepositoryUrl",
            "https://github.com/XPointLabs/deep-protocol.git");
        AssertProperty(project, "RepositoryType", "git");
        AssertProperty(project, "PublishRepositoryUrl", "true");
        AssertProperty(project, "DebugType", "portable");
        AssertProperty(project, "DeepProtocolPackageVersion", "[0.3.0-p04.b887fa0]");
        Assert.Contains(
            project.Descendants("AllowedOutputExtensionsInPackageBuildOutputFolder"),
            element => element.Value.Contains(".pdb", StringComparison.Ordinal));
    }

    [Fact]
    public void TwoCleanPackAndNormalizedSemanticIdentityGatesAreMandatory()
    {
        var root = RepositoryRoot();
        var reproducible = Path.Combine(
            root,
            "eng",
            "verify-p14-profile-carrier-reproducible.ps1");
        var identity = Path.Combine(
            root,
            "eng",
            "Get-P14ProfileCarrierNormalizedIdentity.ps1");
        Assert.True(File.Exists(reproducible));
        Assert.True(File.Exists(identity));
        Assert.True(File.Exists(Path.Combine(
            root,
            "eng",
            "Test-P14ProfileCarrierNormalizedIdentity.ps1")));

        var gate = File.ReadAllText(reproducible);
        Assert.Contains(
            "Test-P14ProfileCarrierNormalizedIdentity.ps1",
            gate,
            StringComparison.Ordinal);
        Assert.Contains("RepositoryCommit=$head", gate, StringComparison.Ordinal);
        Assert.Contains("dll-sha256", gate, StringComparison.Ordinal);
        Assert.Contains("pdb-sha256", gate, StringComparison.Ordinal);
        Assert.Contains("normalized-source-identity-sha256", gate, StringComparison.Ordinal);
        Assert.Contains("exact-carrier-file-only-sha256", gate, StringComparison.Ordinal);
        Assert.Contains("Assert-Equal", gate, StringComparison.Ordinal);

        var offline = File.ReadAllText(Path.Combine(
            root,
            "eng",
            "verify-p14-profile-carrier-offline.ps1"));
        Assert.Contains(
            "verify-p14-profile-carrier-reproducible.ps1",
            offline,
            StringComparison.Ordinal);
        Assert.Contains(
            "exact-carrier-file-only-sha256",
            offline,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "PASS version=$version package=$($nupkg.FullName) sha256=",
            offline,
            StringComparison.Ordinal);

        var p10b3 = Path.Combine(
            root,
            "eng",
            "verify-p10b3-profile-carrier-package.ps1");
        Assert.True(File.Exists(p10b3));
        var p10b3Gate = File.ReadAllText(p10b3);
        Assert.Contains("DeepProtocolPackageVersion", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("0.3.0-p10b3.60ce2e3", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("Normalize-NuGetPackage.ps1", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("--locked-mode", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("CarrierSourceCommit", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("SourceRevisionId=$CarrierSourceCommit", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("RepositoryCommit=$CarrierSourceCommit", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("SourceLink=$sourceLink", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("external-a-b-final-byte-identical", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("--self-test", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("Assert-ExternalDistinctRoots", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("pdbSourceLinkCommit", p10b3Gate, StringComparison.Ordinal);
        Assert.Contains("publishedPackageByteIdentical", p10b3Gate, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "SourceRevisionId=$protocolSourceCommit",
            p10b3Gate,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ProvenanceGateArchivesAcceptedCommitAndSelfTestsDriftRejection()
    {
        var script = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "eng",
            "verify-p14-profile-carrier-provenance.ps1"));
        Assert.Contains("Assert-MaterializedTree", script, StringComparison.Ordinal);
        Assert.Contains("\"archive\", \"--format=zip\"", script, StringComparison.Ordinal);
        Assert.Contains("$commit", script, StringComparison.Ordinal);
        Assert.Contains("source-drift-rejection=PASS", script, StringComparison.Ordinal);
        Assert.DoesNotContain("$workingPath", script, StringComparison.Ordinal);
        Assert.DoesNotContain("-p:XNodeRoot=$XNodeRoot", script, StringComparison.Ordinal);
    }

    [Fact]
    public void P10b3IdentityVerifierRejectsCarrierPackageAndLockDrift()
    {
        var verifier = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "eng",
            "P10B3ProfileCarrier.Identity",
            "Program.cs"));
        Assert.Contains("The PDB SourceLink URLs do not pin", verifier, StringComparison.Ordinal);
        Assert.Contains("PE CodeView identity", verifier, StringComparison.Ordinal);
        Assert.Contains("nuspec repository commit", verifier, StringComparison.Ordinal);
        Assert.Contains("carrier-source-drift", verifier, StringComparison.Ordinal);
        Assert.Contains("package-byte-drift", verifier, StringComparison.Ordinal);
        Assert.Contains("install-lock-drift", verifier, StringComparison.Ordinal);
        Assert.Contains("ValidateProvenance", verifier, StringComparison.Ordinal);
    }

    [Fact]
    public void StaticAssemblySourceAndPackageGraphExcludeRuntimeCapabilities()
    {
        var assembly = typeof(ProfileCarrierComposer).Assembly;
        var forbiddenReferences = new[]
        {
            "Microsoft.Extensions.DependencyInjection",
            "Newtonsoft.Json",
            "System.IO",
            "System.Net",
            "System.Text.Json"
        };
        foreach (var reference in assembly.GetReferencedAssemblies())
        {
            Assert.DoesNotContain(
                forbiddenReferences,
                forbidden => reference.Name!.StartsWith(
                    forbidden,
                    StringComparison.OrdinalIgnoreCase));
        }

        var root = RepositoryRoot();
        var source = string.Join(
            "\n",
            Directory.GetFiles(
                    Path.Combine(root, "src", "Deep.Protocol.ProfileCarrier"),
                    "*.cs")
                .Select(File.ReadAllText));
        foreach (var token in new[]
                 {
                     "System.IO",
                     "System.Net",
                     "HttpClient",
                     "System.Text.Json",
                     "DependencyInjection",
                     "PrivateKey"
                 })
        {
            Assert.DoesNotContain(token, source, StringComparison.OrdinalIgnoreCase);
        }

        var project = XDocument.Load(Path.Combine(
            root,
            "src",
            "Deep.Protocol.ProfileCarrier",
            "Deep.Protocol.ProfileCarrier.csproj"));
        Assert.Equal(
            new[] { "Deep.Protocol", "Sodium.Core", "libsodium" },
            project.Descendants("PackageReference")
                .Select(static reference => reference.Attribute("Include")!.Value)
                .OrderBy(static value => value, StringComparer.Ordinal));
    }

    private static void AssertProperty(
        XDocument project,
        string name,
        string expected) =>
        Assert.Contains(
            project.Descendants(name),
            element => element.Value.Equals(expected, StringComparison.Ordinal));

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
