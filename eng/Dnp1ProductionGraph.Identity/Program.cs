using System.IO.Compression;
using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

var options = Parse(args);
var packageRoot = options.GetValueOrDefault("package-root");
var productionVersion = options.GetValueOrDefault("protocol-version");
var carrierVersion = options.GetValueOrDefault("carrier-version");
var lockPath = options.GetValueOrDefault("lock");
PackageSpec[]? specs = null;
if (!string.IsNullOrWhiteSpace(packageRoot))
{
    if (string.IsNullOrWhiteSpace(productionVersion) || string.IsNullOrWhiteSpace(carrierVersion))
        throw new InvalidOperationException("Package mode requires both versions.");
    specs =
    [
        new("Deep.Protocol", productionVersion, []),
        new("Deep.Protocol.MembershipRoutes", productionVersion,
            [new("Deep.Protocol", $"[{productionVersion}]")]),
        new("Deep.Protocol.ProfileCarrier", carrierVersion,
            [new("Deep.Protocol", $"[{productionVersion}]")])
    ];
    var packages = Directory.GetFiles(packageRoot, "*.nupkg", SearchOption.TopDirectoryOnly);
    if (packages.Length != specs.Length ||
        Directory.EnumerateFiles(packageRoot, "*", SearchOption.AllDirectories)
            .Any(path => !packages.Contains(path, StringComparer.OrdinalIgnoreCase)))
        throw new InvalidOperationException("The production package root is not exact-three and debris-free.");
    foreach (var spec in specs)
        ValidatePackage(Path.Combine(packageRoot, $"{spec.Id}.{spec.Version}.nupkg"), spec);
    if (!string.IsNullOrWhiteSpace(lockPath)) ValidateLock(lockPath, specs);
}

var assemblyOptions = new[] { "protocol-assembly", "routes-assembly", "carrier-assembly" };
var assemblyPaths = assemblyOptions.Select(name => options.GetValueOrDefault(name)).Where(value => !string.IsNullOrWhiteSpace(value)).ToArray();
if (assemblyPaths.Length != 0)
{
    if (assemblyPaths.Length != 3) throw new InvalidOperationException("Assembly mode requires all exact-three assemblies.");
    for (var index = 0; index < assemblyPaths.Length; index++)
        ValidateAssembly(assemblyOptions[index], File.ReadAllBytes(assemblyPaths[index]!));
}
var goldenAssembly = options.GetValueOrDefault("golden-assembly");
if (!string.IsNullOrWhiteSpace(goldenAssembly)) ValidateAssembly("golden-vector-resources", File.ReadAllBytes(goldenAssembly));
if (specs is null && assemblyPaths.Length == 0) throw new InvalidOperationException("A package or assembly validation mode is required.");

Console.WriteLine(specs is null
    ? "PASS exact-three actual assembly/resource/public-API graph"
    : "PASS exact-three actual package/assembly/resource/nuspec/public-API graph");

static void ValidatePackage(string path, PackageSpec spec)
{
    using var archive = ZipFile.OpenRead(path);
    if (archive.Entries.Count is <= 0 or > 4096) throw new InvalidOperationException($"{spec.Id}: ZIP entry bound.");
    var nuspecEntry = archive.Entries.Single(entry => entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
    var nuspecBytes = Read(nuspecEntry, 1_048_576);
    var document = XDocument.Parse(Encoding.UTF8.GetString(nuspecBytes).TrimStart('\uFEFF'));
    var metadata = document.Root!.Elements().Single(element => element.Name.LocalName == "metadata");
    Equal(spec.Id, Child(metadata, "id"), $"{spec.Id} nuspec id");
    Equal(spec.Version, Child(metadata, "version"), $"{spec.Id} nuspec version");
    var dependencies = metadata.Descendants()
        .Where(element => element.Name.LocalName == "dependency")
        .Select(element => new Dependency(
            element.Attribute("id")?.Value ?? throw new InvalidOperationException("Dependency id missing."),
            element.Attribute("version")?.Value ?? throw new InvalidOperationException("Dependency version missing.")))
        .ToArray();
    var internalDependencies = dependencies.Where(dependency => dependency.Id.StartsWith("Deep.Protocol", StringComparison.Ordinal)).ToArray();
    if (!internalDependencies.SequenceEqual(spec.InternalDependencies))
        throw new InvalidOperationException($"{spec.Id}: internal nuspec dependency graph differs.");

    var forbiddenEntry = archive.Entries.FirstOrDefault(entry => ContainsForbidden(entry.FullName));
    if (forbiddenEntry is not null) throw new InvalidOperationException($"{spec.Id}: forbidden ZIP entry {forbiddenEntry.FullName}.");
    var dllEntry = archive.Entries.Single(entry => entry.FullName.Equals($"lib/net10.0/{spec.Id}.dll", StringComparison.Ordinal));
    var dll = Read(dllEntry, 64 * 1024 * 1024);
    ValidateAssembly(spec.Id, dll);
}

static void ValidateAssembly(string packageId, byte[] dll)
{
    using var pe = new PEReader(new MemoryStream(dll, writable: false));
    if (!pe.HasMetadata) throw new InvalidOperationException($"{packageId}: managed metadata missing.");
    var reader = pe.GetMetadataReader();
    foreach (var handle in reader.AssemblyReferences)
    {
        var name = reader.GetString(reader.GetAssemblyReference(handle).Name);
        if (ContainsForbidden(name)) throw new InvalidOperationException($"{packageId}: forbidden AssemblyRef {name}.");
    }
    foreach (var handle in reader.TypeReferences)
    {
        var type = reader.GetTypeReference(handle);
        RejectMetadataName(packageId, reader.GetString(type.Namespace), reader.GetString(type.Name), "TypeRef");
    }
    foreach (var handle in reader.TypeDefinitions)
    {
        var type = reader.GetTypeDefinition(handle);
        var typeName = reader.GetString(type.Name);
        RejectMetadataName(packageId, reader.GetString(type.Namespace), typeName, "TypeDef");
        if (typeName.Contains("RecoveryExternalCheckpointInput", StringComparison.Ordinal) ||
            typeName.Contains("UnverifiedRecovery", StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"{packageId}: raw recovery input/test seam TypeDef leaked into a production assembly.");
        foreach (var methodHandle in type.GetMethods())
        {
            var methodName = reader.GetString(reader.GetMethodDefinition(methodHandle).Name);
            if (methodName.Contains("OpenUnverified", StringComparison.Ordinal) ||
                methodName.Contains("UnverifiedCandidate", StringComparison.Ordinal) ||
                methodName.Contains("RawRecovery", StringComparison.Ordinal))
                throw new InvalidOperationException(
                    $"{packageId}: recovery test seam leaked into a production assembly.");
        }
        if ((type.Attributes & TypeAttributes.VisibilityMask) is TypeAttributes.Public or TypeAttributes.NestedPublic)
        {
            foreach (var methodHandle in type.GetMethods())
            {
                var method = reader.GetMethodDefinition(methodHandle);
                if (ContainsForbidden(reader.GetString(method.Name)))
                    throw new InvalidOperationException($"{packageId}: forbidden public method name.");
            }
            foreach (var propertyHandle in type.GetProperties())
            {
                var property = reader.GetPropertyDefinition(propertyHandle);
                if (ContainsForbidden(reader.GetString(property.Name)))
                    throw new InvalidOperationException($"{packageId}: forbidden public property name.");
            }
        }
    }
    foreach (var handle in reader.ManifestResources)
    {
        var name = reader.GetString(reader.GetManifestResource(handle).Name);
        if (ContainsForbidden(name)) throw new InvalidOperationException($"{packageId}: forbidden resource {name}.");
    }
    foreach (var token in GraphPolicy.Forbidden)
    {
        if (dll.AsSpan().IndexOf(Encoding.UTF8.GetBytes(token)) >= 0 ||
            dll.AsSpan().IndexOf(Encoding.Unicode.GetBytes(token)) >= 0)
            throw new InvalidOperationException($"{packageId}: forbidden legacy token '{token}' in assembly bytes/resources.");
    }
    var snapshot = CreateSnapshot(dll);
    var assemblyName = snapshot.Split('|', 2)[0];
    var requiredAssembly = GraphPolicy.ExpectedAssemblyByInput.GetValueOrDefault(packageId, packageId);
    if (!StringComparer.Ordinal.Equals(assemblyName, requiredAssembly))
        throw new InvalidOperationException($"{packageId}: positive assembly identity differs (actual {assemblyName}).");
    if (!GraphPolicy.ExpectedSnapshots.TryGetValue(assemblyName, out var expectedSnapshots) ||
        !expectedSnapshots.Contains(snapshot, StringComparer.Ordinal))
        throw new InvalidOperationException($"{packageId}: positive public-API/resource/assembly snapshot differs ({snapshot}).");
}

static string CreateSnapshot(byte[] dll)
{
    using var pe = new PEReader(new MemoryStream(dll, writable: false));
    if (!pe.HasMetadata) throw new InvalidOperationException("Snapshot input has no managed metadata.");
    var reader = pe.GetMetadataReader();
    var assembly = reader.GetAssemblyDefinition();
    var assemblyName = reader.GetString(assembly.Name);
    var lines = new List<string> { $"assembly|{assemblyName}" };
    foreach (var handle in reader.AssemblyReferences)
    {
        var reference = reader.GetAssemblyReference(handle);
        lines.Add($"reference|{reader.GetString(reference.Name)}|{reference.Version}|" +
            $"{reader.GetString(reference.Culture)}|{Convert.ToHexString(reader.GetBlobBytes(reference.PublicKeyOrToken))}");
    }
    var resources = pe.PEHeaders.CorHeader?.ResourcesDirectory ?? default;
    var resourceBytes = resources.Size > 0
        ? pe.GetSectionData(resources.RelativeVirtualAddress).GetContent()
        : default;
    foreach (var handle in reader.ManifestResources)
    {
        var resource = reader.GetManifestResource(handle);
        var name = reader.GetString(resource.Name);
        if (!resource.Implementation.IsNil)
        {
            lines.Add($"resource-external|{name}|{resource.Implementation.Kind}|{MetadataTokens.GetToken(resource.Implementation):X8}");
            continue;
        }
        var offset = checked((int)resource.Offset);
        if (resourceBytes.IsDefaultOrEmpty || offset < 0 || offset > resourceBytes.Length - 4)
            throw new InvalidOperationException($"{assemblyName}: embedded resource offset is invalid: {name}.");
        var length = BinaryPrimitives.ReadInt32LittleEndian(resourceBytes.AsSpan(offset, 4));
        if (length < 0 || length > resourceBytes.Length - offset - 4)
            throw new InvalidOperationException($"{assemblyName}: embedded resource length is invalid: {name}.");
        var hash = Convert.ToHexString(SHA256.HashData(resourceBytes.AsSpan(offset + 4, length)));
        lines.Add($"resource|{name}|{length}|{hash}");
    }
    foreach (var handle in reader.TypeDefinitions)
    {
        var type = reader.GetTypeDefinition(handle);
        if (!IsVisibleType(type.Attributes)) continue;
        var typeName = TypeName(reader, handle);
        lines.Add($"type|{typeName}|{(int)type.Attributes:X8}|base={EntityName(reader, type.BaseType)}");
        foreach (var interfaceHandle in type.GetInterfaceImplementations())
        {
            var implementation = reader.GetInterfaceImplementation(interfaceHandle);
            lines.Add($"interface|{typeName}|{EntityName(reader, implementation.Interface)}");
        }
        foreach (var fieldHandle in type.GetFields())
        {
            var field = reader.GetFieldDefinition(fieldHandle);
            if (!IsVisibleField(field.Attributes & FieldAttributes.FieldAccessMask)) continue;
            lines.Add($"field|{typeName}|{reader.GetString(field.Name)}|{(int)field.Attributes:X8}|" +
                Convert.ToHexString(reader.GetBlobBytes(field.Signature)));
        }
        foreach (var methodHandle in type.GetMethods())
        {
            var method = reader.GetMethodDefinition(methodHandle);
            if (!IsVisibleMethod(method.Attributes & MethodAttributes.MemberAccessMask)) continue;
            lines.Add($"method|{typeName}|{reader.GetString(method.Name)}|{(int)method.Attributes:X8}|" +
                Convert.ToHexString(reader.GetBlobBytes(method.Signature)));
        }
        foreach (var propertyHandle in type.GetProperties())
        {
            var property = reader.GetPropertyDefinition(propertyHandle);
            var accessors = property.GetAccessors();
            if (!IsVisibleAccessor(reader, accessors.Getter) && !IsVisibleAccessor(reader, accessors.Setter) &&
                !accessors.Others.Any(handle => IsVisibleAccessor(reader, handle))) continue;
            lines.Add($"property|{typeName}|{reader.GetString(property.Name)}|{(int)property.Attributes:X8}|" +
                Convert.ToHexString(reader.GetBlobBytes(property.Signature)));
        }
        foreach (var eventHandle in type.GetEvents())
        {
            var @event = reader.GetEventDefinition(eventHandle);
            var accessors = @event.GetAccessors();
            if (!IsVisibleAccessor(reader, accessors.Adder) && !IsVisibleAccessor(reader, accessors.Remover) &&
                !IsVisibleAccessor(reader, accessors.Raiser) &&
                !accessors.Others.Any(handle => IsVisibleAccessor(reader, handle))) continue;
            lines.Add($"event|{typeName}|{reader.GetString(@event.Name)}|{(int)@event.Attributes:X8}|" +
                EntityName(reader, @event.Type));
        }
    }
    lines.Sort(StringComparer.Ordinal);
    var canonical = string.Join('\n', lines) + "\n";
    var hashValue = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    return $"{assemblyName}|{lines.Count}|{hashValue}";
}

static bool IsVisibleType(TypeAttributes attributes) =>
    (attributes & TypeAttributes.VisibilityMask) is TypeAttributes.Public or TypeAttributes.NestedPublic or
        TypeAttributes.NestedFamily or TypeAttributes.NestedFamORAssem;

static bool IsVisibleField(FieldAttributes attributes) =>
    attributes is FieldAttributes.Public or FieldAttributes.Family or FieldAttributes.FamORAssem;

static bool IsVisibleMethod(MethodAttributes attributes) =>
    attributes is MethodAttributes.Public or MethodAttributes.Family or MethodAttributes.FamORAssem;

static bool IsVisibleAccessor(MetadataReader reader, MethodDefinitionHandle handle) =>
    !handle.IsNil && IsVisibleMethod(reader.GetMethodDefinition(handle).Attributes & MethodAttributes.MemberAccessMask);

static string TypeName(MetadataReader reader, TypeDefinitionHandle handle)
{
    var type = reader.GetTypeDefinition(handle);
    var name = reader.GetString(type.Name);
    var declaring = type.GetDeclaringType();
    if (!declaring.IsNil) return TypeName(reader, declaring) + "+" + name;
    var ns = reader.GetString(type.Namespace);
    return string.IsNullOrEmpty(ns) ? name : ns + "." + name;
}

static string EntityName(MetadataReader reader, EntityHandle handle) => handle.IsNil
    ? ""
    : handle.Kind switch
{
    HandleKind.TypeDefinition => TypeName(reader, (TypeDefinitionHandle)handle),
    HandleKind.TypeReference => TypeReferenceName(reader, (TypeReferenceHandle)handle),
    HandleKind.TypeSpecification => "typespec:" +
        Convert.ToHexString(reader.GetBlobBytes(reader.GetTypeSpecification((TypeSpecificationHandle)handle).Signature)),
    _ => handle.Kind + ":" + MetadataTokens.GetToken(handle).ToString("X8")
};

static string TypeReferenceName(MetadataReader reader, TypeReferenceHandle handle)
{
    var type = reader.GetTypeReference(handle);
    var ns = reader.GetString(type.Namespace);
    var name = reader.GetString(type.Name);
    return string.IsNullOrEmpty(ns) ? name : ns + "." + name;
}

static void ValidateLock(string path, PackageSpec[] specs)
{
    var bytes = File.ReadAllBytes(path);
    foreach (var token in GraphPolicy.Forbidden)
    {
        if (Encoding.UTF8.GetString(bytes).Contains(token, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Lock contains forbidden legacy dependency '{token}'.");
    }
    using var document = JsonDocument.Parse(bytes);
    var graph = document.RootElement.GetProperty("dependencies").GetProperty("net10.0");
    foreach (var spec in specs)
    {
        if (!graph.TryGetProperty(spec.Id, out var node) || node.GetProperty("resolved").GetString() != spec.Version)
            throw new InvalidOperationException($"Lock does not exact-pin {spec.Id} {spec.Version}.");
    }
}

static bool ContainsForbidden(string value) => GraphPolicy.Forbidden.Any(token => value.Contains(token, StringComparison.OrdinalIgnoreCase));
static void RejectMetadataName(string package, string ns, string name, string kind)
{
    if (ContainsForbidden(ns) || ContainsForbidden(name))
        throw new InvalidOperationException($"{package}: forbidden {kind} {ns}.{name}.");
}
static byte[] Read(ZipArchiveEntry entry, int maximum)
{
    if (entry.Length < 0 || entry.Length > maximum) throw new InvalidOperationException($"Oversized entry {entry.FullName}.");
    using var stream = entry.Open();
    using var memory = new MemoryStream(checked((int)entry.Length));
    stream.CopyTo(memory);
    if (memory.Length != entry.Length) throw new InvalidOperationException($"Truncated entry {entry.FullName}.");
    return memory.ToArray();
}
static string Child(XElement parent, string name) => parent.Elements().Single(element => element.Name.LocalName == name).Value;
static void Equal(string expected, string actual, string label)
{
    if (!StringComparer.Ordinal.Equals(expected, actual)) throw new InvalidOperationException($"{label} differs.");
}
static Dictionary<string, string?> Parse(string[] values)
{
    var result = new Dictionary<string, string?>(StringComparer.Ordinal);
    for (var index = 0; index < values.Length; index++)
    {
        if (!values[index].StartsWith("--", StringComparison.Ordinal)) throw new InvalidOperationException("Unexpected argument.");
        var key = values[index][2..];
        if (++index >= values.Length) throw new InvalidOperationException($"Missing --{key} value.");
        result.Add(key, values[index]);
    }
    return result;
}
internal sealed record Dependency(string Id, string Version);
internal sealed record PackageSpec(string Id, string Version, Dependency[] InternalDependencies);
internal static class GraphPolicy
{
    internal static readonly string[] Forbidden =
    [
        "Deep.Protocol.Abstractions", "Deep.Protocol.Protobuf", "Google.Protobuf",
        "Deep.Protocol.Native", "SessionProtos", "WebSocketProtos",
        "CompatibilityEnvelope", "OpaqueBundle", "NearbyHandshake",
        "NearbySecureChannel", "LoRaFragment", "DPE1", "DPB1"
    ];

    internal static readonly IReadOnlyDictionary<string, string> ExpectedAssemblyByInput =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["protocol-assembly"] = "Deep.Protocol",
            ["routes-assembly"] = "Deep.Protocol.MembershipRoutes",
            ["carrier-assembly"] = "Deep.Protocol.ProfileCarrier",
            ["golden-vector-resources"] = "Deep.Protocol.GoldenVectors"
        };

    internal static readonly IReadOnlyDictionary<string, string[]> ExpectedSnapshots =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["Deep.Protocol"] =
            [
                "Deep.Protocol|5816|DB4955212EC5337165952BA2882B2F50244F442CD7CBA27E1805E82BCC230A60",
                "Deep.Protocol|5816|44CF9525B3F1C8B692031CC2C20FBD0024C21D7B6B3D3D71E1E9639A8D78FCB6"
            ],
            ["Deep.Protocol.MembershipRoutes"] =
            [
                "Deep.Protocol.MembershipRoutes|2553|15560C520E69DC51B83D41DCFD780945D5821039C49D3E0881FD92DCAEC20F62",
                "Deep.Protocol.MembershipRoutes|2553|C018081F6B9AC590E2C17FA8E1AB1B3736FB2F487299EE66902254AE4442E50C"
            ],
            ["Deep.Protocol.ProfileCarrier"] =
            [
                "Deep.Protocol.ProfileCarrier|352|C3C43EF37BECFDF10F4F5133C3CA45C661FEF20BE82C707979E87E60B12FE999",
                "Deep.Protocol.ProfileCarrier|352|68EEC87FA129BA770FAECED63A40F9A1903D503685FF30B1B91B7E2BFD45AB41"
            ],
            ["Deep.Protocol.GoldenVectors"] =
            [
                "Deep.Protocol.GoldenVectors|110|CB8FBE4A262105B188B279AC1119AF9C090ECAF47D24C109FAB65093B8099D4F",
                "Deep.Protocol.GoldenVectors|110|97651F729F3FF5706516979CB0199B582AC45F480FDFDE42F0147822730C37BE"
            ]
        };
}
