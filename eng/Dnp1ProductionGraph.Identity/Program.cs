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
if (GraphPolicy.SnapshotFailures.Count != 0)
    throw new InvalidOperationException(string.Join(Environment.NewLine, GraphPolicy.SnapshotFailures));

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
    foreach (var entry in archive.Entries)
    {
        ValidateNoRetiredTokens(spec.Id, $"package entry name {entry.FullName}", Encoding.UTF8.GetBytes(entry.FullName));
        if (!entry.FullName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            ValidateNoRetiredTokens(spec.Id, $"package entry {entry.FullName}", Read(entry, 64 * 1024 * 1024));
    }
    var dllEntry = archive.Entries.Single(entry => entry.FullName.Equals($"lib/net10.0/{spec.Id}.dll", StringComparison.Ordinal));
    var dll = Read(dllEntry, 64 * 1024 * 1024);
    ValidateAssembly(spec.Id, dll);
}

static void ValidateAssembly(string packageId, byte[] dll)
{
    using var pe = new PEReader(new MemoryStream(dll, writable: false));
    if (!pe.HasMetadata) throw new InvalidOperationException($"{packageId}: managed metadata missing.");
    var reader = pe.GetMetadataReader();
    ValidateProtocolRegistrySurface(packageId, dll, pe, reader);
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
        GraphPolicy.SnapshotFailures.Add(
            $"{packageId}: positive public-API/resource/assembly snapshot differs ({snapshot}).");
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
        if (assemblyName == "Deep.Protocol.GoldenVectors" &&
            name.EndsWith("dnp1-classical-v1.executable.json", StringComparison.Ordinal))
        {
            // This manifest separately binds this verifier in its implementation
            // scope. Hashing its bytes here would create a self-referential digest
            // cycle between the resource snapshot and implementationScopeSha256.
            lines.Add($"resource|{name}|dnp1-executable-integrity-gate");
            continue;
        }
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

static void ValidateProtocolRegistrySurface(
    string packageId, byte[] dll, PEReader pe, MetadataReader reader)
{
    ValidateNoRetiredTokens(packageId, "assembly bytes", dll);

    foreach (var value in ReadUserStrings(pe))
        ValidateRuntimeString(packageId, "#US user string", value);

    foreach (var handle in reader.TypeDefinitions)
    {
        var type = reader.GetTypeDefinition(handle);
        ValidateRuntimeString(packageId, "TypeDef namespace", reader.GetString(type.Namespace));
        ValidateRuntimeString(packageId, "TypeDef name", reader.GetString(type.Name));
        foreach (var fieldHandle in type.GetFields())
        {
            var field = reader.GetFieldDefinition(fieldHandle);
            ValidateRuntimeString(packageId, "field name", reader.GetString(field.Name));
            var constantHandle = field.GetDefaultValue();
            if (constantHandle.IsNil) continue;
            var constant = reader.GetConstant(constantHandle);
            if (constant.TypeCode == ConstantTypeCode.String)
                ValidateRuntimeString(packageId, "field constant", Encoding.Unicode.GetString(reader.GetBlobBytes(constant.Value)));
        }
        foreach (var methodHandle in type.GetMethods())
            ValidateRuntimeString(packageId, "method name", reader.GetString(reader.GetMethodDefinition(methodHandle).Name));
        foreach (var propertyHandle in type.GetProperties())
            ValidateRuntimeString(packageId, "property name", reader.GetString(reader.GetPropertyDefinition(propertyHandle).Name));
        foreach (var eventHandle in type.GetEvents())
            ValidateRuntimeString(packageId, "event name", reader.GetString(reader.GetEventDefinition(eventHandle).Name));
    }

    var resources = pe.PEHeaders.CorHeader?.ResourcesDirectory ?? default;
    var resourceBytes = resources.Size > 0 ? pe.GetSectionData(resources.RelativeVirtualAddress).GetContent() : default;
    foreach (var handle in reader.ManifestResources)
    {
        var resource = reader.GetManifestResource(handle);
        var name = reader.GetString(resource.Name);
        ValidateRuntimeString(packageId, "resource name", name);
        if (!resource.Implementation.IsNil) continue;
        var offset = checked((int)resource.Offset);
        if (resourceBytes.IsDefaultOrEmpty || offset < 0 || offset > resourceBytes.Length - 4)
            throw new InvalidOperationException($"{packageId}: embedded resource offset is invalid: {name}.");
        var length = BinaryPrimitives.ReadInt32LittleEndian(resourceBytes.AsSpan(offset, 4));
        if (length < 0 || length > resourceBytes.Length - offset - 4)
            throw new InvalidOperationException($"{packageId}: embedded resource length is invalid: {name}.");
        ValidateNoRetiredTokens(packageId, $"resource {name}", resourceBytes.AsSpan(offset + 4, length));
    }
}

static void ValidateRuntimeString(string packageId, string surface, string value)
{
    foreach (var retired in DeepProtocolRegistryPolicy.RetiredTokens)
    {
        if (ContainsStandalone(value, retired))
            throw new InvalidOperationException($"{packageId}: retired registry token '{retired}' in {surface}.");
    }
    if (value.Length == 4 && value.All(static character => character is >= 'A' and <= 'Z' or >= '0' and <= '9') &&
        !DeepProtocolRegistryPolicy.AllowedMagic.Contains(value, StringComparer.Ordinal) &&
        !DeepProtocolRegistryPolicy.NonProtocolFourCharacterLiterals.Contains(value, StringComparer.Ordinal))
        throw new InvalidOperationException($"{packageId}: unregistered runtime protocol magic '{value}' in {surface}.");
}

static bool ContainsStandalone(string value, string token)
{
    for (var start = 0; ; start++)
    {
        start = value.IndexOf(token, start, StringComparison.Ordinal);
        if (start < 0) return false;
        var before = start == 0 || !IsRegistryTokenCharacter(value[start - 1]);
        var end = start + token.Length;
        var after = end == value.Length || !IsRegistryTokenCharacter(value[end]);
        if (before && after) return true;
    }
}

static bool IsRegistryTokenCharacter(char value) => char.IsLetterOrDigit(value) || value is '_' or '-';

static void ValidateNoRetiredTokens(string packageId, string surface, ReadOnlySpan<byte> bytes)
{
    foreach (var retired in DeepProtocolRegistryPolicy.RetiredTokens)
    {
        if (ContainsStandaloneBytes(bytes, Encoding.UTF8.GetBytes(retired), utf16: false) ||
            ContainsStandaloneBytes(bytes, Encoding.Unicode.GetBytes(retired), utf16: true))
            throw new InvalidOperationException($"{packageId}: retired registry token '{retired}' in {surface}.");
    }
}

static bool ContainsStandaloneBytes(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> token, bool utf16)
{
    var offset = 0;
    while (offset <= bytes.Length - token.Length)
    {
        var relative = bytes[offset..].IndexOf(token);
        if (relative < 0) return false;
        var start = offset + relative;
        var end = start + token.Length;
        var before = utf16 ? IsUtf16Boundary(bytes, start - 2) : IsAsciiBoundary(bytes, start - 1);
        var after = utf16 ? IsUtf16Boundary(bytes, end) : IsAsciiBoundary(bytes, end);
        if (before && after) return true;
        offset = start + (utf16 ? 2 : 1);
    }
    return false;
}

static bool IsAsciiBoundary(ReadOnlySpan<byte> bytes, int index) =>
    index < 0 || index >= bytes.Length || !IsRegistryTokenCharacter((char)bytes[index]);

static bool IsUtf16Boundary(ReadOnlySpan<byte> bytes, int index)
{
    if (index < 0 || index > bytes.Length - 2) return true;
    return bytes[index + 1] != 0 || !IsRegistryTokenCharacter((char)bytes[index]);
}

static IEnumerable<string> ReadUserStrings(PEReader pe)
{
    var metadata = pe.GetMetadata().GetContent().ToArray();
    var stream = GetMetadataStream(metadata, "#US");
    var offset = stream.Length == 0 ? 0 : 1;
    while (offset < stream.Length)
    {
        var length = ReadCompressedUInt(stream, ref offset);
        if (length == 0)
        {
            if (stream.AsSpan(offset).IndexOfAnyExcept((byte)0) < 0) yield break;
            continue;
        }
        if (length > stream.Length - offset)
            throw new InvalidOperationException("Invalid #US heap entry.");
        var textLength = length - 1;
        if ((textLength & 1) != 0) throw new InvalidOperationException("Invalid UTF-16 #US heap entry.");
        yield return Encoding.Unicode.GetString(stream, offset, textLength);
        offset += length;
    }
}

static byte[] GetMetadataStream(byte[] metadata, string requiredName)
{
    if (metadata.Length < 20 || BinaryPrimitives.ReadUInt32LittleEndian(metadata) != 0x424A5342)
        throw new InvalidOperationException("Invalid CLR metadata root.");
    var versionLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(metadata.AsSpan(12, 4)));
    var offset = checked(16 + ((versionLength + 3) & ~3));
    if (offset > metadata.Length - 4) throw new InvalidOperationException("Invalid CLR metadata header.");
    var streams = BinaryPrimitives.ReadUInt16LittleEndian(metadata.AsSpan(offset + 2, 2));
    offset += 4;
    for (var index = 0; index < streams; index++)
    {
        if (offset > metadata.Length - 8) throw new InvalidOperationException("Invalid CLR stream header.");
        var streamOffset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(metadata.AsSpan(offset, 4)));
        var streamSize = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(metadata.AsSpan(offset + 4, 4)));
        offset += 8;
        var nameStart = offset;
        while (offset < metadata.Length && metadata[offset] != 0) offset++;
        if (offset >= metadata.Length) throw new InvalidOperationException("Invalid CLR stream name.");
        var name = Encoding.ASCII.GetString(metadata, nameStart, offset - nameStart);
        offset = (offset + 4) & ~3;
        if (!StringComparer.Ordinal.Equals(name, requiredName)) continue;
        if (streamOffset < 0 || streamSize < 0 || streamOffset > metadata.Length - streamSize)
            throw new InvalidOperationException("Invalid CLR stream range.");
        return metadata.AsSpan(streamOffset, streamSize).ToArray();
    }
    return [];
}

static int ReadCompressedUInt(byte[] bytes, ref int offset)
{
    if (offset >= bytes.Length) throw new InvalidOperationException("Truncated compressed integer.");
    var first = bytes[offset++];
    if ((first & 0x80) == 0) return first;
    if ((first & 0xC0) == 0x80)
    {
        if (offset >= bytes.Length) throw new InvalidOperationException("Truncated compressed integer.");
        return ((first & 0x3F) << 8) | bytes[offset++];
    }
    if ((first & 0xE0) == 0xC0)
    {
        if (offset > bytes.Length - 3) throw new InvalidOperationException("Truncated compressed integer.");
        return ((first & 0x1F) << 24) | (bytes[offset++] << 16) | (bytes[offset++] << 8) | bytes[offset++];
    }
    throw new InvalidOperationException("Invalid compressed integer.");
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
    internal static readonly List<string> SnapshotFailures = [];

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
                "Deep.Protocol|11290|C29B4D9A8F084EC1010A8FB90914CAD2CB12C3C9EF40E09FC8C875FA2AD9DCDC"
            ],
            ["Deep.Protocol.MembershipRoutes"] =
            [
                "Deep.Protocol.MembershipRoutes|2554|EA00ABECE1D572B507E98B695B77CCB49B3C076F50C507502D67CEC6A6C19855",
                "Deep.Protocol.MembershipRoutes|2554|D01B68E7B3AB092D7E911BA3B227DFFC64B87138CA1D9E699B17AF1738C98B91",
                "Deep.Protocol.MembershipRoutes|2554|BD52697AE36106138FE736514AA0AB91DAFC7745B53EFE8C50D84614C6F84AC0"
            ],
            ["Deep.Protocol.ProfileCarrier"] =
            [
                "Deep.Protocol.ProfileCarrier|352|5AC0D63AF92645344DBDBA0DFFBD4844180B97D956B1E14E26CDB75FBA1F29AA",
                "Deep.Protocol.ProfileCarrier|352|1CCD469CA874FCF66E086E1BBE759302B205635A2D7E0EBB6EEFF186AAB3D2F2",
                "Deep.Protocol.ProfileCarrier|352|8BE8B79C8866FD5CB07A414E7255AD4FF1A530A1AA44D3249D2C4FDB5F5EBBCD"
            ],
            ["Deep.Protocol.GoldenVectors"] =
            [
                "Deep.Protocol.GoldenVectors|111|A10E47D43865462CEBF5236781E3F82D70B1D97F8DCF287F062B7C78791F26D0"
            ]
        };
}
