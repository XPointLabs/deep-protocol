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
var packagePath = Required(options, "package");
var lockPath = Required(options, "lock");
var carrierSourceCommit = Required(options, "carrier-source");
var protocolSourceCommit = Required(options, "protocol-source");
var carrierVersion = Required(options, "carrier-version");
var protocolVersion = Required(options, "protocol-version");
var provenancePath = Optional(options, "provenance");
var expectedPackageSha256 = Optional(options, "package-sha256");
var expectedPackageSha512 = Optional(options, "package-sha512");
var expectedLockSha256 = Optional(options, "lock-sha256");
var expectedLockSha512 = Optional(options, "lock-sha512");

ValidateCommit(carrierSourceCommit, "carrier source");
ValidateCommit(protocolSourceCommit, "protocol source");
ValidatePackage(
    packagePath,
    carrierSourceCommit,
    protocolSourceCommit,
    carrierVersion,
    protocolVersion);
ValidateLock(lockPath, carrierVersion, protocolVersion);
ValidateExpectedHash(packagePath, expectedPackageSha256, expectedPackageSha512, "package");
ValidateExpectedHash(lockPath, expectedLockSha256, expectedLockSha512, "install lock");

if (provenancePath is not null)
{
    ValidateProvenance(
        provenancePath,
        packagePath,
        lockPath,
        carrierSourceCommit,
        protocolSourceCommit,
        carrierVersion,
        protocolVersion);
}

if (options.ContainsKey("self-test"))
{
    RunMutationTests(
        packagePath,
        lockPath,
        carrierSourceCommit,
        protocolSourceCommit,
        carrierVersion,
        protocolVersion);
}

Console.WriteLine(
    $"PASS carrier-source={carrierSourceCommit} protocol-source={protocolSourceCommit}");
Console.WriteLine($"package-sha256={Hash(packagePath, SHA256.Create())}");
Console.WriteLine($"package-sha512={Hash(packagePath, SHA512.Create())}");
Console.WriteLine($"lock-sha256={Hash(lockPath, SHA256.Create())}");
Console.WriteLine($"lock-sha512={Hash(lockPath, SHA512.Create())}");

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

static string? Optional(Dictionary<string, string?> options, string name) =>
    options.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
        ? value
        : null;

static void ValidateCommit(string value, string label)
{
    if (value.Length != 40 || value.Any(static value =>
            !char.IsAsciiHexDigit(value) || char.IsUpper(value)))
    {
        throw new InvalidOperationException($"The {label} commit must be a full lowercase SHA-1.");
    }
}

static void ValidatePackage(
    string packagePath,
    string carrierSourceCommit,
    string protocolSourceCommit,
    string carrierVersion,
    string protocolVersion)
{
    using var archive = ZipFile.OpenRead(packagePath);
    var nuspec = ReadSingle(archive, static entry =>
        entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
    var dll = ReadExact(
        archive,
        "lib/net10.0/Deep.Protocol.ProfileCarrier.dll");
    var pdb = ReadExact(
        archive,
        "lib/net10.0/Deep.Protocol.ProfileCarrier.pdb");

    using var nuspecStream = new MemoryStream(nuspec);
    var document = XDocument.Load(nuspecStream);
    var metadata = document.Root?.Elements().Single(static value =>
        value.Name.LocalName == "metadata") ??
        throw new InvalidOperationException("The package nuspec metadata is missing.");
    var version = Child(metadata, "version");
    if (version != carrierVersion)
    {
        throw new InvalidOperationException(
            $"The nuspec carrier version is {version}, expected {carrierVersion}.");
    }
    var repository = metadata.Elements().Single(static value =>
        value.Name.LocalName == "repository");
    var repositoryCommit = repository.Attribute("commit")?.Value;
    if (repositoryCommit != carrierSourceCommit)
    {
        throw new InvalidOperationException(
            "The nuspec repository commit does not equal the carrier source commit.");
    }
    if (repositoryCommit == protocolSourceCommit)
    {
        throw new InvalidOperationException(
            "The carrier and protocol source identities were conflated.");
    }
    var dependency = metadata.Descendants().Single(value =>
        value.Name.LocalName == "dependency" &&
        value.Attribute("id")?.Value == "Deep.Protocol");
    if (dependency.Attribute("version")?.Value != $"[{protocolVersion}]")
    {
        throw new InvalidOperationException(
            "The Deep.Protocol dependency is not the exact P10B3 version.");
    }

    using var pdbProvider = MetadataReaderProvider.FromPortablePdbImage(
        ImmutableArray.Create(pdb));
    var pdbReader = pdbProvider.GetMetadataReader();
    var customDebugInformation = pdbReader.CustomDebugInformation
        .Select(pdbReader.GetCustomDebugInformation)
        .ToArray();
    var sourceLinkMatches = customDebugInformation
        .Where(value => pdbReader.GetGuid(value.Kind).ToString().Equals(
            sourceLinkKind,
            StringComparison.OrdinalIgnoreCase))
        .ToArray();
    if (sourceLinkMatches.Length != 1)
    {
        var kinds = string.Join(
            ",",
            customDebugInformation.Select(value =>
                pdbReader.GetGuid(value.Kind).ToString()));
        throw new InvalidOperationException(
            $"The portable PDB has {sourceLinkMatches.Length} SourceLink records; kinds={kinds}.");
    }
    var sourceLink = sourceLinkMatches[0];
    var sourceLinkJson = Encoding.UTF8.GetString(
        pdbReader.GetBlobBytes(sourceLink.Value)).TrimStart('\uFEFF');
    using var sourceLinkDocument = JsonDocument.Parse(sourceLinkJson);
    var sourceUrls = sourceLinkDocument.RootElement
        .GetProperty("documents")
        .EnumerateObject()
        .Select(static value => value.Value.GetString() ??
            throw new InvalidOperationException("A SourceLink URL is null."))
        .ToArray();
    if (sourceUrls.Length == 0 ||
        sourceUrls.Any(value => !value.Contains(
            carrierSourceCommit,
            StringComparison.Ordinal)))
    {
        throw new InvalidOperationException(
            "The PDB SourceLink URLs do not pin the carrier source commit.");
    }
    if (sourceUrls.Any(value => value.Contains(
        protocolSourceCommit,
        StringComparison.Ordinal)))
    {
        throw new InvalidOperationException(
            "The PDB SourceLink URLs incorrectly pin the protocol source commit.");
    }

    using var peReader = new PEReader(new MemoryStream(dll));
    var debugEntries = peReader.ReadDebugDirectory();
    var codeViewEntry = debugEntries.Single(static value =>
        value.Type == DebugDirectoryEntryType.CodeView);
    var codeView = peReader.ReadCodeViewDebugDirectoryData(codeViewEntry);
    var pdbHeader = pdbReader.DebugMetadataHeader ??
        throw new InvalidOperationException("The portable PDB identity is missing.");
    var pdbId = pdbHeader.Id;
    var pdbGuid = new Guid(pdbId.AsSpan()[..16]);
    if (codeView.Guid != pdbGuid || codeView.Age != 1)
    {
        throw new InvalidOperationException(
            "The PE CodeView identity does not match the portable PDB identity.");
    }
    var checksumEntry = debugEntries.Single(static value =>
        value.Type == DebugDirectoryEntryType.PdbChecksum);
    var checksum = peReader.ReadPdbChecksumDebugDirectoryData(checksumEntry);
    if (!checksum.AlgorithmName.Equals("SHA256", StringComparison.OrdinalIgnoreCase) ||
        !checksum.Checksum.AsSpan().SequenceEqual(SHA256.HashData(pdb)))
    {
        throw new InvalidOperationException(
            "The PE PDB checksum does not match the packaged portable PDB.");
    }
}

static void ValidateLock(
    string lockPath,
    string carrierVersion,
    string protocolVersion)
{
    using var document = JsonDocument.Parse(File.ReadAllBytes(lockPath));
    var dependencies = document.RootElement
        .GetProperty("dependencies")
        .GetProperty("net10.0");
    var carrier = dependencies.GetProperty("Deep.Protocol.ProfileCarrier");
    var protocol = dependencies.GetProperty("Deep.Protocol");
    if (carrier.GetProperty("type").GetString() != "Direct" ||
        carrier.GetProperty("resolved").GetString() != carrierVersion ||
        carrier.GetProperty("requested").GetString() !=
            $"[{carrierVersion}, {carrierVersion}]" ||
        protocol.GetProperty("type").GetString() != "Direct" ||
        protocol.GetProperty("resolved").GetString() != protocolVersion ||
        protocol.GetProperty("requested").GetString() !=
            $"[{protocolVersion}, {protocolVersion}]")
    {
        throw new InvalidOperationException(
            "The install lock does not pin the exact direct carrier/protocol graph.");
    }
    var dependency = carrier.GetProperty("dependencies")
        .GetProperty("Deep.Protocol")
        .GetString();
    if (dependency != $"[{protocolVersion}]")
    {
        throw new InvalidOperationException(
            "The locked carrier dependency is not the exact protocol version.");
    }
}

static void ValidateProvenance(
    string provenancePath,
    string packagePath,
    string lockPath,
    string carrierSourceCommit,
    string protocolSourceCommit,
    string carrierVersion,
    string protocolVersion)
{
    using var document = JsonDocument.Parse(File.ReadAllBytes(provenancePath));
    var root = document.RootElement;
    Equal(root, "carrierSourceCommit", carrierSourceCommit);
    Equal(root, "protocolContractSourceCommit", protocolSourceCommit);
    Equal(root, "carrierPackageVersion", carrierVersion);
    Equal(root, "protocolDependency", $"[{protocolVersion}]");
    var package = root.GetProperty("package");
    Equal(package, "sha256", Hash(packagePath, SHA256.Create()));
    Equal(package, "sha512", Hash(packagePath, SHA512.Create()));
    if (package.GetProperty("bytes").GetInt64() != new FileInfo(packagePath).Length)
    {
        throw new InvalidOperationException("The provenance package length is stale.");
    }
    var installLock = root.GetProperty("lockedInstallSmoke");
    Equal(installLock, "sha256", Hash(lockPath, SHA256.Create()));
    Equal(installLock, "sha512", Hash(lockPath, SHA512.Create()));
    if (installLock.GetProperty("bytes").GetInt64() != new FileInfo(lockPath).Length)
    {
        throw new InvalidOperationException("The provenance install-lock length is stale.");
    }
}

static void RunMutationTests(
    string packagePath,
    string lockPath,
    string carrierSourceCommit,
    string protocolSourceCommit,
    string carrierVersion,
    string protocolVersion)
{
    var mutatedCommit = (carrierSourceCommit[0] == '0' ? "1" : "0") +
        carrierSourceCommit[1..];
    ExpectRejected(
        () => ValidatePackage(
            packagePath,
            mutatedCommit,
            protocolSourceCommit,
            carrierVersion,
            protocolVersion),
        "carrier-source-drift");

    var mutationRoot = Path.Combine(
        Path.GetTempPath(),
        $"deep-p10b3-carrier-mutation-{Guid.NewGuid():N}");
    Directory.CreateDirectory(mutationRoot);
    try
    {
        var packageMutation = Path.Combine(mutationRoot, "carrier.nupkg");
        var packageBytes = File.ReadAllBytes(packagePath);
        packageBytes[^1] ^= 0x01;
        File.WriteAllBytes(packageMutation, packageBytes);
        var packageSha256 = Hash(packagePath, SHA256.Create());
        ExpectRejected(
            () => ValidateExpectedHash(
                packageMutation,
                packageSha256,
                null,
                "mutated package"),
            "package-byte-drift");

        var lockMutation = Path.Combine(mutationRoot, "packages.lock.json");
        var lockBytes = File.ReadAllBytes(lockPath);
        File.WriteAllBytes(lockMutation, [.. lockBytes, (byte)'\n']);
        var lockSha256 = Hash(lockPath, SHA256.Create());
        ExpectRejected(
            () => ValidateExpectedHash(
                lockMutation,
                lockSha256,
                null,
                "mutated lock"),
            "install-lock-drift");
    }
    finally
    {
        Directory.Delete(mutationRoot, recursive: true);
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

static void ValidateExpectedHash(
    string path,
    string? expectedSha256,
    string? expectedSha512,
    string label)
{
    if (expectedSha256 is not null &&
        !Hash(path, SHA256.Create()).Equals(
            expectedSha256,
            StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"The {label} SHA-256 differs.");
    }
    if (expectedSha512 is not null &&
        !Hash(path, SHA512.Create()).Equals(
            expectedSha512,
            StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"The {label} SHA-512 differs.");
    }
}

static byte[] ReadSingle(
    ZipArchive archive,
    Func<ZipArchiveEntry, bool> predicate)
{
    var entry = archive.Entries.Single(predicate);
    return Read(entry);
}

static byte[] ReadExact(ZipArchive archive, string name)
{
    var entry = archive.Entries.Single(value =>
        value.FullName.Equals(name, StringComparison.Ordinal));
    return Read(entry);
}

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
            $"The provenance {name} value is stale.");
    }
}

static string Hash(string path, HashAlgorithm algorithm)
{
    using (algorithm)
    using (var stream = File.OpenRead(path))
    {
        return Convert.ToHexStringLower(algorithm.ComputeHash(stream));
    }
}
