using System.Collections.Immutable;
using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

const string sourceLinkKind = "CC110556-A091-4D38-9FEC-25AB9A351A6A";

var options = Parse(args);
var packageRoot = Required(options, "package-root");
var lockPath = Required(options, "lock");
var provenancePath = Required(options, "provenance");
var sourceCommit = Required(options, "source");
var protocolVersion = Required(options, "protocol-version");
var carrierVersion = Required(options, "carrier-version");

ValidateCommit(sourceCommit);
var packageSpecs = new[]
{
    new PackageSpec("Deep.Protocol", protocolVersion),
    new PackageSpec("Deep.Protocol.Abstractions", protocolVersion),
    new PackageSpec("Deep.Protocol.MembershipRoutes", protocolVersion),
    new PackageSpec("Deep.Protocol.ProfileCarrier", carrierVersion),
    new PackageSpec("Deep.Protocol.Protobuf", protocolVersion),
};
ValidatePackageSet(packageRoot, packageSpecs, sourceCommit, protocolVersion);
ValidateLock(lockPath, packageRoot, packageSpecs, protocolVersion);
ValidateProvenance(
    provenancePath,
    packageRoot,
    lockPath,
    packageSpecs,
    sourceCommit,
    protocolVersion,
    carrierVersion);

if (options.ContainsKey("self-test"))
{
    RunMutationTests(
        packageRoot,
        lockPath,
        packageSpecs,
        sourceCommit,
        protocolVersion);
}

Console.WriteLine($"PASS source-commit={sourceCommit}");
foreach (var spec in packageSpecs)
{
    var path = PackagePath(packageRoot, spec);
    Console.WriteLine($"{spec.Id}-sha256={HashHex(path, SHA256.Create())}");
    Console.WriteLine($"{spec.Id}-sha512={HashHex(path, SHA512.Create())}");
}
Console.WriteLine($"lock-sha256={HashHex(lockPath, SHA256.Create())}");
Console.WriteLine($"lock-sha512={HashHex(lockPath, SHA512.Create())}");

static Dictionary<string, string?> Parse(string[] values)
{
    var result = new Dictionary<string, string?>(StringComparer.Ordinal);
    for (var index = 0; index < values.Length; index++)
    {
        var key = values[index];
        if (!key.StartsWith("--", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Unexpected argument: {key}");
        }
        key = key[2..];
        if (key == "self-test")
        {
            result.Add(key, null);
            continue;
        }
        if (++index >= values.Length)
        {
            throw new InvalidOperationException($"Missing value for --{key}.");
        }
        result.Add(key, values[index]);
    }
    return result;
}

static string Required(Dictionary<string, string?> options, string name) =>
    options.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
        ? value
        : throw new InvalidOperationException($"--{name} is required.");

static void ValidateCommit(string value)
{
    if (value.Length != 40 ||
        value.Any(static item => !char.IsAsciiHexDigit(item) || char.IsUpper(item)))
    {
        throw new InvalidOperationException(
            "The source commit must be a full lowercase SHA-1.");
    }
}

static void ValidatePackageSet(
    string packageRoot,
    IEnumerable<PackageSpec> specs,
    string sourceCommit,
    string protocolVersion)
{
    foreach (var spec in specs)
    {
        ValidatePackage(
            PackagePath(packageRoot, spec),
            spec,
            sourceCommit,
            protocolVersion);
    }
}

static void ValidatePackage(
    string packagePath,
    PackageSpec spec,
    string sourceCommit,
    string protocolVersion)
{
    using var archive = ZipFile.OpenRead(packagePath);
    var nuspec = ReadSingle(
        archive,
        static entry => entry.FullName.EndsWith(
            ".nuspec",
            StringComparison.OrdinalIgnoreCase));
    var dll = ReadExact(archive, $"lib/net10.0/{spec.Id}.dll");
    var pdb = ReadExact(archive, $"lib/net10.0/{spec.Id}.pdb");

    using var nuspecStream = new MemoryStream(nuspec);
    var document = XDocument.Load(nuspecStream);
    var metadata = document.Root?.Elements().Single(static value =>
        value.Name.LocalName == "metadata") ??
        throw new InvalidOperationException(
            $"{spec.Id}: package nuspec metadata is missing.");
    if (Child(metadata, "id") != spec.Id ||
        Child(metadata, "version") != spec.Version)
    {
        throw new InvalidOperationException(
            $"{spec.Id}: nuspec id/version differs.");
    }
    var repository = metadata.Elements().Single(static value =>
        value.Name.LocalName == "repository");
    if (repository.Attribute("commit")?.Value != sourceCommit)
    {
        throw new InvalidOperationException(
            $"{spec.Id}: nuspec repository commit differs.");
    }
    ValidateProtocolDependencies(metadata, spec.Id, protocolVersion);

    using var pdbProvider = MetadataReaderProvider.FromPortablePdbImage(
        ImmutableArray.Create(pdb));
    var pdbReader = pdbProvider.GetMetadataReader();
    var sourceLinkEntries = pdbReader.CustomDebugInformation
        .Select(pdbReader.GetCustomDebugInformation)
        .Where(value => pdbReader.GetGuid(value.Kind).ToString().Equals(
            sourceLinkKind,
            StringComparison.OrdinalIgnoreCase))
        .ToArray();
    if (sourceLinkEntries.Length != 1)
    {
        throw new InvalidOperationException(
            $"{spec.Id}: expected one SourceLink record.");
    }
    var sourceLinkJson = Encoding.UTF8.GetString(
        pdbReader.GetBlobBytes(sourceLinkEntries[0].Value))
        .TrimStart('\uFEFF');
    using var sourceLinkDocument = JsonDocument.Parse(sourceLinkJson);
    var sourceUrls = sourceLinkDocument.RootElement
        .GetProperty("documents")
        .EnumerateObject()
        .Select(static value => value.Value.GetString() ??
            throw new InvalidOperationException("A SourceLink URL is null."))
        .ToArray();
    if (sourceUrls.Length == 0 ||
        sourceUrls.Any(value =>
            !value.Contains(sourceCommit, StringComparison.Ordinal)))
    {
        throw new InvalidOperationException(
            $"{spec.Id}: SourceLink does not pin the source commit.");
    }

    using var peReader = new PEReader(new MemoryStream(dll));
    var debugEntries = peReader.ReadDebugDirectory();
    var codeView = peReader.ReadCodeViewDebugDirectoryData(
        debugEntries.Single(static value =>
            value.Type == DebugDirectoryEntryType.CodeView));
    var pdbHeader = pdbReader.DebugMetadataHeader ??
        throw new InvalidOperationException(
            $"{spec.Id}: portable PDB identity is missing.");
    var pdbGuid = new Guid(pdbHeader.Id.AsSpan()[..16]);
    if (codeView.Guid != pdbGuid || codeView.Age != 1)
    {
        throw new InvalidOperationException(
            $"{spec.Id}: PE CodeView does not match the portable PDB.");
    }
    var checksum = peReader.ReadPdbChecksumDebugDirectoryData(
        debugEntries.Single(static value =>
            value.Type == DebugDirectoryEntryType.PdbChecksum));
    if (!checksum.AlgorithmName.Equals(
            "SHA256",
            StringComparison.OrdinalIgnoreCase) ||
        checksum.Checksum.Length != 32 ||
        checksum.Checksum.All(static value => value == 0))
    {
        throw new InvalidOperationException(
            $"{spec.Id}: PE does not carry a valid SHA-256 PDB checksum record.");
    }
}

static void ValidateProtocolDependencies(
    XElement metadata,
    string packageId,
    string protocolVersion)
{
    var dependencies = metadata.Descendants()
        .Where(static value => value.Name.LocalName == "dependency")
        .ToDictionary(
            static value => value.Attribute("id")?.Value ??
                throw new InvalidOperationException(
                    "A dependency id is missing."),
            static value => value.Attribute("version")?.Value ??
                throw new InvalidOperationException(
                    "A dependency version is missing."),
            StringComparer.Ordinal);
    void Equal(string dependencyId, string expected)
    {
        if (!dependencies.TryGetValue(dependencyId, out var actual) ||
            actual != expected)
        {
            throw new InvalidOperationException(
                $"{packageId}: dependency {dependencyId} is {actual}, expected {expected}.");
        }
    }

    if (packageId == "Deep.Protocol")
    {
        Equal("Deep.Protocol.Abstractions", protocolVersion);
        Equal("Deep.Protocol.Protobuf", protocolVersion);
    }
    else if (packageId == "Deep.Protocol.MembershipRoutes")
    {
        Equal("Deep.Protocol", protocolVersion);
    }
    else if (packageId == "Deep.Protocol.ProfileCarrier")
    {
        Equal("Deep.Protocol", $"[{protocolVersion}]");
    }
}

static void ValidateLock(
    string lockPath,
    string packageRoot,
    IEnumerable<PackageSpec> specs,
    string protocolVersion)
{
    using var document = JsonDocument.Parse(File.ReadAllBytes(lockPath));
    var dependencies = document.RootElement
        .GetProperty("dependencies")
        .GetProperty("net10.0");
    foreach (var spec in specs)
    {
        var package = dependencies.GetProperty(spec.Id);
        if (package.GetProperty("resolved").GetString() != spec.Version)
        {
            throw new InvalidOperationException(
                $"The lock does not pin {spec.Id} {spec.Version}.");
        }
        if (package.GetProperty("contentHash").GetString() !=
            HashBase64(PackagePath(packageRoot, spec), SHA512.Create()))
        {
            throw new InvalidOperationException(
                $"The lock contentHash does not identify {spec.Id}.");
        }
    }
    var carrierDependency = dependencies
        .GetProperty("Deep.Protocol.ProfileCarrier")
        .GetProperty("dependencies")
        .GetProperty("Deep.Protocol")
        .GetString();
    if (carrierDependency != $"[{protocolVersion}]")
    {
        throw new InvalidOperationException(
            "The lock does not preserve the carrier's exact protocol dependency.");
    }
}

static void ValidateProvenance(
    string provenancePath,
    string packageRoot,
    string lockPath,
    IEnumerable<PackageSpec> specs,
    string sourceCommit,
    string protocolVersion,
    string carrierVersion)
{
    using var document = JsonDocument.Parse(
        File.ReadAllBytes(provenancePath));
    var root = document.RootElement;
    Equal(root, "schema", "deep-protocol-p10j-package-closure.v1");
    Equal(root, "sourceCommit", sourceCommit);
    Equal(root, "protocolVersion", protocolVersion);
    Equal(root, "profileCarrierVersion", carrierVersion);
    var packageEntries = root.GetProperty("packages")
        .EnumerateArray()
        .ToArray();
    foreach (var spec in specs)
    {
        var entry = packageEntries.Single(value =>
            value.GetProperty("id").GetString() == spec.Id);
        var path = PackagePath(packageRoot, spec);
        Equal(entry, "version", spec.Version);
        Equal(entry, "sha256", HashHex(path, SHA256.Create()));
        Equal(entry, "sha512", HashHex(path, SHA512.Create()));
        Equal(entry, "contentHash", HashBase64(path, SHA512.Create()));
        if (entry.GetProperty("bytes").GetInt64() !=
            new FileInfo(path).Length)
        {
            throw new InvalidOperationException(
                $"{spec.Id}: provenance byte length differs.");
        }
    }
    var lockEntry = root.GetProperty("lockedInstall");
    Equal(lockEntry, "sha256", HashHex(lockPath, SHA256.Create()));
    Equal(lockEntry, "sha512", HashHex(lockPath, SHA512.Create()));
    Equal(lockEntry, "contentHash", HashBase64(lockPath, SHA512.Create()));
    if (lockEntry.GetProperty("bytes").GetInt64() !=
        new FileInfo(lockPath).Length)
    {
        throw new InvalidOperationException(
            "The provenance lock byte length differs.");
    }
}

static void RunMutationTests(
    string packageRoot,
    string lockPath,
    PackageSpec[] specs,
    string sourceCommit,
    string protocolVersion)
{
    var mutatedCommit =
        (sourceCommit[0] == '0' ? "1" : "0") + sourceCommit[1..];
    ExpectRejected(
        () => ValidatePackageSet(
            packageRoot,
            specs,
            mutatedCommit,
            protocolVersion),
        "source-drift");

    var packagePath = PackagePath(packageRoot, specs[0]);
    var expectedPackageHash = HashHex(packagePath, SHA256.Create());
    var mutationRoot = Path.Combine(
        Path.GetTempPath(),
        $"deep-p10j-identity-{Guid.NewGuid():N}");
    Directory.CreateDirectory(mutationRoot);
    try
    {
        var packageMutation = Path.Combine(
            mutationRoot,
            Path.GetFileName(packagePath));
        var packageBytes = File.ReadAllBytes(packagePath);
        packageBytes[^1] ^= 0x01;
        File.WriteAllBytes(packageMutation, packageBytes);
        ExpectRejected(
            () => ValidateHash(
                packageMutation,
                expectedPackageHash,
                "mutated package"),
            "package-byte-drift");

        var lockMutation = Path.Combine(
            mutationRoot,
            "packages.lock.json");
        File.WriteAllBytes(
            lockMutation,
            [.. File.ReadAllBytes(lockPath), (byte)'\n']);
        var expectedLockHash = HashHex(lockPath, SHA256.Create());
        ExpectRejected(
            () => ValidateHash(
                lockMutation,
                expectedLockHash,
                "mutated lock"),
            "lock-byte-drift");
    }
    finally
    {
        Directory.Delete(mutationRoot, recursive: true);
    }
}

static void ValidateHash(string path, string expected, string label)
{
    if (HashHex(path, SHA256.Create()) != expected)
    {
        throw new InvalidOperationException($"{label}: SHA-256 differs.");
    }
}

static void ExpectRejected(Action action, string label)
{
    try
    {
        action();
    }
    catch
    {
        Console.WriteLine($"{label}-rejection=PASS");
        return;
    }
    throw new InvalidOperationException(
        $"The deliberate {label} mutation was accepted.");
}

static string PackagePath(string root, PackageSpec spec) =>
    Path.Combine(root, $"{spec.Id}.{spec.Version}.nupkg");

static byte[] ReadSingle(
    ZipArchive archive,
    Func<ZipArchiveEntry, bool> predicate) =>
    Read(archive.Entries.Single(predicate));

static byte[] ReadExact(ZipArchive archive, string name) =>
    Read(archive.Entries.Single(value =>
        value.FullName.Equals(name, StringComparison.Ordinal)));

static byte[] Read(ZipArchiveEntry entry)
{
    using var stream = entry.Open();
    using var memory = new MemoryStream();
    stream.CopyTo(memory);
    return memory.ToArray();
}

static string Child(XElement parent, string name) =>
    parent.Elements().Single(value => value.Name.LocalName == name).Value;

static void Equal(JsonElement parent, string name, string expected)
{
    if (parent.GetProperty(name).GetString() != expected)
    {
        throw new InvalidOperationException(
            $"The provenance {name} value differs.");
    }
}

static string HashHex(string path, HashAlgorithm algorithm)
{
    using (algorithm)
    using (var stream = File.OpenRead(path))
    {
        return Convert.ToHexStringLower(algorithm.ComputeHash(stream));
    }
}

static string HashBase64(string path, HashAlgorithm algorithm)
{
    using (algorithm)
    using (var stream = File.OpenRead(path))
    {
        return Convert.ToBase64String(algorithm.ComputeHash(stream));
    }
}

internal sealed record PackageSpec(string Id, string Version);
