using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Deep.Protocol.Tests.DevOpsWitness;

public sealed class Dnp1PackageBlockingWitnessTests
{
    private static readonly string Root = FindProtocolRoot();
    private static readonly string NormativeRoot = Path.Combine(
        Directory.GetParent(Root)!.FullName,
        "docs", "survival-program", "releases", "v3.0.0", "specs");

    [Fact]
    public void PackageExactThreeSessionFree_InspectsActualPackageZipsAssembliesResourcesAndPublicApi()
    {
        var result = RunPowerShell(
            Path.Combine(Root, "eng", "Test-Dnp1PackageBlockingWitness.ps1"),
            "-Configuration", BuildConfiguration());

        AssertSucceeded(result);
        Assert.Contains(
            "PASS exact-three actual package/assembly/resource/nuspec/public-API graph",
            result.Output,
            StringComparison.Ordinal);
        Assert.Contains(
            "PASS DevOpsWitness package-exact-three-session-free actual package ZIP and assembly/resource graph",
            result.Output,
            StringComparison.Ordinal);
        Assert.Contains("PASS expected rejection: package ZIP with stripped retained public API", result.Output, StringComparison.Ordinal);
        Assert.Contains("PASS expected rejection: golden-vector assembly with stripped embedded resources", result.Output, StringComparison.Ordinal);
        Assert.Contains("PASS expected rejection: assembly-slot cross-feed", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void GrammarMachineArtifactSetDigest_RealGeneratorAndCheckerRejectEveryBoundDigestMutation()
    {
        var artifactsRoot = Path.Combine(Root, "artifacts", "dnp1-devops-witness-runs");
        Directory.CreateDirectory(artifactsRoot);
        var runRoot = Path.Combine(artifactsRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runRoot);
        try
        {
            var ownership = JsonNode.Parse(File.ReadAllText(
                Path.Combine(NormativeRoot, "dnp1-classical-v1.evidence-ownership.json")))!;
            var packageRows = ownership["rows"]!.AsArray()
                .Where(row => string.Equals(
                    row!["gate"]!.GetValue<string>(),
                    "ProtocolPackageBlocking",
                    StringComparison.Ordinal))
                .ToArray();
            Assert.Equal(219, packageRows.Length);

            const string fixture = "tests/Deep.Protocol.Tests/DevOpsWitness/Dnp1PackageBlockingWitnessTests.cs";
            var mappings = new JsonArray();
            foreach (var row in packageRows)
            {
                var id = row!["id"]!.GetValue<string>();
                mappings.Add(new JsonObject
                {
                    ["id"] = id,
                    ["testFqn"] = $"Deep.Protocol.Tests.DevOpsWitness.Generated.{id.Replace('-', '_')}",
                    ["fixturePath"] = fixture
                });
            }
            var draftPath = Path.Combine(runRoot, "draft.json");
            File.WriteAllText(
                draftPath,
                new JsonObject { ["mappings"] = mappings }.ToJsonString(new() { WriteIndented = true }) + "\n",
                new UTF8Encoding(false));

            var head = Run("git", ["-C", Root, "rev-parse", "HEAD"]);
            AssertSucceeded(head);
            var manifestPath = Path.Combine(runRoot, "executable.json");
            var runnerPath = Path.Combine(runRoot, "generate.ps1");
            var scope = new[]
            {
                "eng/New-Dnp1ExecutableVectorManifest.ps1",
                "eng/Test-Dnp1ExecutableVectors.ps1",
                fixture
            };
            var runner = $"& '{PsQuote(Path.Combine(Root, "eng", "New-Dnp1ExecutableVectorManifest.ps1"))}' " +
                $"-MappingsPath '{PsQuote(draftPath)}' " +
                $"-ProtocolBaseCommit '{head.Output.Trim()}' " +
                "-ImplementationScope @(" + string.Join(",", scope.Select(value => $"'{PsQuote(value)}'")) + ") " +
                $"-NormativeRoot '{PsQuote(NormativeRoot)}' " +
                $"-OutputPath '{PsQuote(manifestPath)}'\n";
            File.WriteAllText(runnerPath, runner, new UTF8Encoding(false));
            AssertSucceeded(RunPowerShell(runnerPath));

            var valid = RunIntegrityChecker(manifestPath);
            AssertSucceeded(valid);
            Assert.Contains("NO executable case discovery or evidence was performed", valid.Output, StringComparison.Ordinal);

            AssertDigestMutationRejected(manifestPath, "registry", manifest =>
                CorruptNormativeDigest(manifest, "dnp1-classical-v1.registry.json"));
            AssertDigestMutationRejected(manifestPath, "schema", manifest =>
                CorruptNormativeDigest(manifest, "dnp1-classical-v1.vectors.schema.json"));
            AssertDigestMutationRejected(manifestPath, "vector", manifest =>
                CorruptNormativeDigest(manifest, "dnp1-classical-v1.vectors.skeleton.json"));
            AssertDigestMutationRejected(manifestPath, "checker", manifest =>
                manifest["implementationScopeSha256"] = new string('0', 64));
        }
        finally
        {
            DeleteRunRoot(artifactsRoot, runRoot);
        }
    }

    [Fact]
    public void GrammarVectorSchemaAdditionalProperty_RealClosedSchemaGateRejectsTopAndCaseProperties()
    {
        var checker = Path.Combine(Directory.GetParent(Root)!.FullName, "scripts", "check-dnp1-classical-spec.ps1");
        var result = RunPowerShell(checker);

        AssertSucceeded(result);
        Assert.Contains(
            "Vector schema: Draft 2020-12 equivalent / additionalProperties and JSON-type negative self-tests passed",
            result.Output,
            StringComparison.Ordinal);
    }

    private static void AssertDigestMutationRejected(
        string manifestPath,
        string label,
        Action<JsonObject> mutate)
    {
        var manifest = JsonNode.Parse(File.ReadAllText(manifestPath))!.AsObject();
        mutate(manifest);
        var changedPath = Path.Combine(Path.GetDirectoryName(manifestPath)!, $"{label}.json");
        File.WriteAllText(
            changedPath,
            manifest.ToJsonString(new() { WriteIndented = true }) + "\n",
            new UTF8Encoding(false));
        var result = RunIntegrityChecker(changedPath);
        Assert.NotEqual(0, result.ExitCode);
    }

    private static void CorruptNormativeDigest(JsonObject manifest, string path)
    {
        var binding = manifest["normativeFiles"]!.AsArray()
            .Select(node => node!.AsObject())
            .Single(node => string.Equals(node["path"]!.GetValue<string>(), path, StringComparison.Ordinal));
        binding["sha256"] = new string('0', 64);
    }

    private static ProcessResult RunIntegrityChecker(string manifestPath) => RunPowerShell(
        Path.Combine(Root, "eng", "Test-Dnp1ExecutableVectors.ps1"),
        "-ManifestPath", manifestPath,
        "-NormativeRoot", NormativeRoot,
        "-Configuration", BuildConfiguration(),
        "-IntegrityOnly");

    private static string BuildConfiguration() =>
        AppContext.BaseDirectory.Contains(
            $"{Path.DirectorySeparatorChar}Debug{Path.DirectorySeparatorChar}",
            StringComparison.OrdinalIgnoreCase)
            ? "Debug"
            : "Release";

    private static string PsQuote(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private static ProcessResult RunPowerShell(string script, params string[] arguments)
    {
        var all = new List<string>
        {
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script
        };
        all.AddRange(arguments);
        return Run("powershell.exe", all);
    }

    private static ProcessResult Run(string fileName, IReadOnlyList<string> arguments)
    {
        var start = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = Root,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {fileName}.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit((int)TimeSpan.FromMinutes(5).TotalMilliseconds))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{fileName} exceeded the five-minute witness bound.");
        }
        Task.WaitAll(stdout, stderr);
        return new(process.ExitCode, stdout.Result + stderr.Result);
    }

    private static void AssertSucceeded(ProcessResult result) =>
        Assert.True(result.ExitCode == 0, result.Output);

    private static void DeleteRunRoot(string artifactsRoot, string runRoot)
    {
        var prefix = Path.GetFullPath(artifactsRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var target = Path.GetFullPath(runRoot);
        if (!target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Unsafe witness cleanup path: {target}");
        if (Directory.Exists(target)) Directory.Delete(target, recursive: true);
    }

    private static string FindProtocolRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "eng", "New-Dnp1ExecutableVectorManifest.ps1")))
                return directory.FullName;
            directory = directory.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate the deep-protocol repository root.");
    }

    private sealed record ProcessResult(int ExitCode, string Output);
}
