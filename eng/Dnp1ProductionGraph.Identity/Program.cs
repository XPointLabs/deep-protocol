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
                "Deep.Protocol|11381|10A890B33625A4809F8CF7FAB6DB39357DE2391C909D0B1C5098B04CCA178CCD",
                "Deep.Protocol|11404|4940DB51BD7627A390D36A5BE0EF1002DDF965506A8C87A2BB57B0888256C891",
                "Deep.Protocol|11427|8AB0F3601300D4FE6368DEF248D4799D81A6655DCA27A73AF7F2CBC1B699D1F6",
                "Deep.Protocol|11552|0E8C63C2410E53CC8A4030C33A77831A649FDC2C6B6CB29F526D3724F92E0382",
                "Deep.Protocol|11679|882AF6030E5AF7C8854A6CFD187ED31481C14E28985064398D9426590A5D9895",
                "Deep.Protocol|11724|2EF31A50C7B426079C70D154A248767967763CFE99B32807141C5A609DDA45AF",
                "Deep.Protocol|11724|992EE9647EFB43BB837AD96A3281B55C194CED69AFF13E684499FC536D4D0026",
                "Deep.Protocol|11752|04B7F9C0368C14A3141A2C34392AD0A1F0D96C79F04BD91A9A59A6D0FF29E5C8",
                "Deep.Protocol|11766|1E5E0526F6B4ED99C4DC7915C044D41F70A6283F16A136003BCACF2A4414E746",
                "Deep.Protocol|11843|95B71C797F3D99529608E0056EB75038CFE5FC91AF1558E526C1FAF3F31683F7",
                "Deep.Protocol|11845|31B1AEFD4C4E81573AF53F5A549F0EBB9E91934F8A974AA02209CAA414987E5B",
                "Deep.Protocol|11845|8517D75A56EF05A220A4714501020D3BB7FB364380DC1D2CCBB9B3845586D72B",
                "Deep.Protocol|11855|52AF1FF5A0CE577D2F833AE203665DF1DEE6DB0A5E51E5670682122BD2E5764C",
                "Deep.Protocol|11855|78B02AA8F83717B93C4F9B8144A16943514FF8F775C67AB2B19EBCE91ED2951F",
                "Deep.Protocol|11855|4CA2E72C4A88119E3693FD894A9D5378511152AA0F4F2622B96F61531A66760E",
                "Deep.Protocol|11855|D2775DE944745826F9A39FB5007EA3968755441197429554DF02C98F4FAA2744",
                "Deep.Protocol|11855|454F99DE14BF6B481D56BACF5E6F935706C9DBB42A909A2396F1D5DA15E7AC3F",
                "Deep.Protocol|11855|8D5CB6F34380FD42131AD667D0FE9DAEFCD24DE9FCC4C21D5E2DD8324A2B1940",
                "Deep.Protocol|11862|924D5F9DF3B5CADCEA56FAF39C084FF114D60978709F149E1FE6314DF61C895F",
                "Deep.Protocol|11862|F9AE0BA1177095979DC71285814E0F802B387D1E1537357577A776C79F66ACE3",
                "Deep.Protocol|11867|1710EEF53CE0ACFE6184FD184D043353EBEB7453AB03DDE4B6BCF3E2294E0E71",
                "Deep.Protocol|11867|C85963074805D4638C761EA199BD96E0D3F584701D7E0B402509D258637D969B",
                "Deep.Protocol|11869|9E565F94FD08E96C9467EB421CAF6D93D9F6F082E6FD534896819656A27C1A7B",
                "Deep.Protocol|11869|634F5D398AF1C6959D05C175B923DAE4AE8A04549E3ACDD1DDD1800449046944",
                "Deep.Protocol|11941|8F51892E98BB02D39DFC85CC992574B379857094ECCD88AD6D78418A8BC874A8",
                "Deep.Protocol|11941|CE031104E52B90D39DD3FD592B66EECE1F3DF120781931E96422F445773DC9B0",
                "Deep.Protocol|11996|927EAE195F360C7CF459C6774444DE09A78D54FA238520A2457221046F9F1C3F",
                "Deep.Protocol|11996|758B00A177B9FD45758A10A96A1077EE23DEB99B5FEEBCDC6F6DD50051427AF9",
                // ID-PQ-CB V2 root derivation, before DID2 production activation.
                "Deep.Protocol|11996|2CA6E2B4469D9608C38AC6785230604C6D4E3320EC1B88FF9AF145DFCC1E8254",
                "Deep.Protocol|11996|E8DEDE97019C8E26E52CECEE7ED548BCABF2EC2425885507A468E3F732D7E981",
                // DR-0006 candidate DID2/DAB2/DCA1 V2 API, still not production-active.
                "Deep.Protocol|12143|F57B2CAE817343B7877F63FC73DF2A8DEF6CBB1C13C9930CF67C8CFF5CF7B07F",
                "Deep.Protocol|12144|5BC6710AAD45D372231A66A69D80F85734AEFEAACE2F72E39258E8DEEC8A5DC2",
                // Explicit restore of the existing signed genesis, never re-issuance.
                "Deep.Protocol|12145|899F4F2E692BA657ABC873342AF6A71F89745AB3F9837981AA7CB1345F9A5750",
                // DR-0006 candidate ADC1 V2 exact DID2/DAB2 directory closure.
                "Deep.Protocol|12202|F0EDF73C3E10951FFD00B416FC399497320E92E6C2C575E42097C703E3C34F69",
                // Candidate ADL1 V2 exact DID2-derived lookup capability.
                "Deep.Protocol|12227|EFDE92E81CB3F6E862EF6CBA68CA6A32313BAC8BE6656F96484459172F97DAB2",
                "Deep.Protocol|12227|AE02D088E4DE04DC087926CD39BD908A1912B84185C5DAC91D2DA3F1D92D1721",
                // Candidate V2 witness-private transition and sparse-map primitives.
                "Deep.Protocol|12256|83499EFF68F9C1788B26875CBD5834498CE164E5DB21B43EF4E65D02F31E1790",
                "Deep.Protocol|12256|FD4AB5EE19D61569028022E8E9420299696746C20EF57E6ED116B02D11500EDB",
                // Candidate DID2-only genesis admission verifier; wire cutover remains open.
                "Deep.Protocol|12276|593ED8EB4E1994CBA7711F29CCABCAFC12F9B5B8EF41E86B3A9F8D523E46AB08",
                "Deep.Protocol|12276|D7B698B588C5EB4E449742EDBFD248DAFD42635CF26CF4BDACD0498AD347BA4C",
                // Candidate DGA1/DGR1 V2 bounded wire; service cutover remains open.
                "Deep.Protocol|12300|D05D050E2AAA3558AEF7EC2751950397AFEAB4E5E5678F13C72AC88745AD60E1",
                "Deep.Protocol|12300|2DAFF28F9A5C9EE557B8E61D961EAEF028B1BEB3F2CD4B4F81F7DE814FAA3803",
                // Candidate V2 private transition journal replay, not active ADP1.
                "Deep.Protocol|12300|BFD5AB94D22AAC60E206A7BDD10707142C972A2534A83744C58E9108187DA464",
                "Deep.Protocol|12300|F7D75F036720CC64E85590A2BFA04E6F4CD224EC4B1F99F2C7A6FEEDF13B380B",
                // Candidate DID2-only threshold head mutation over exact V2 journal.
                "Deep.Protocol|12316|ACC99C388264688B6D1172136489ECF53F4C33E5D09155D351554162D9E39D7E",
                "Deep.Protocol|12316|A0A5A6010A5F72F4ABEA349C4D9096C98CF7B871BA0D29916445D83EC3C5286D",
                // Candidate V2 proof material; no public ADP1 envelope yet.
                "Deep.Protocol|12341|DCDCE29546C76D0D18DC0BB87A3F6761E30357755BE7DFF42C56C395F0336617",
                "Deep.Protocol|12341|42C523A1BBA92CF1A93648E7000CFF0A926D222F6605965A5D82221DE23CC1A2",
                // Candidate ADP1 V2 exact DID2/DAB2 wire, not freshness authority.
                "Deep.Protocol|12367|CE3970455808286C8EB88BEECE36F357B03D7C74119DBAD851E057EE81FBBCA8",
                "Deep.Protocol|12367|430F765D9F1AF9528B2BD54267A89B86D04F85553AB701F84DF5C23908C8890D",
                // ADP1 V2 exact revoked-DCA list closure and widened bounded envelope.
                "Deep.Protocol|12369|37E83B7EEE0036C762744A5139777E7F34B3CCE62AE788968723EA7A68212C25",
                "Deep.Protocol|12369|70F02D6CE8CA4AEFA1D224D1B2999A1F59CDED7397F64C5CDAC513DFE40DEFA9",
                // Candidate public DID2 directory genesis/absence freshness verifier.
                "Deep.Protocol|12393|7BA804788DDAEB9DD0B7D8DCE10BC25037AA3BCF466E6E6B90A599529450D8B0",
                "Deep.Protocol|12393|24667DCCFE8EB3684082383C15BB87F41D5C53492B12DBA5F2BEC99E95FD909A",
                // Candidate DID2-only nonce-bound proof issuer; service cutover remains open.
                "Deep.Protocol|12410|F9D24903B5BAC20659A1A5908C0FD8A8A8A7001C004312EDE47CF593CF237935",
                "Deep.Protocol|12410|E03116812CE17F3DA5EAD8036978BDE3F9A790FA6AB415FA03FE79E4352DF6C7",
                // Public DID2 freshness now requires a verified DAB2-bound ADL1 query.
                "Deep.Protocol|12420|A127AC1678FAE99FEA11BFCA780BE8A4A5B062CB46EC30518750425F4AD5E820",
                "Deep.Protocol|12420|3ECB355FD9A6FF124BB5EB31020FE9AC64448E691F2C01269954F3A16446599D",
                // Separately pinned, signed empty V2 bootstrap head before ADA2 state.
                "Deep.Protocol|12422|ABB3C64EF876E2FDFD0944CC4966735C47541B29A147CD9B16EE8480E9FFBC6A",
                "Deep.Protocol|12422|E581420BE0D4ECB12B14693D515B6BE4EDCC981CA29D7E467563FCF4D3EF17F8",
                // Hash-pinned Linux x64 ML-DSA candidate and verifier-only public lease.
                "Deep.Protocol|12427|ED84D97AC96987983690864E89CC26DD898DEB00DF28531D05DBEF6906CFB50D",
                // Candidate DPQ2/DPP2 exact DID2-bound proof wire; public route remains disabled.
                // Both exact Release and Debug metadata snapshots are pinned.
                "Deep.Protocol|12459|FDD2AEA88FE4AFC7F5A31068A2B74A1AC400A5AC55DCDBD1700D43594D206610",
                "Deep.Protocol|12459|2A077D1C807119EA13E41F2445073E60F90F796ECC6617A4092536ADDE8FD45C",
                // Isolated XIR1 V2 issuer/DCA1 candidate; contact publication remains disabled.
                "Deep.Protocol|12473|BE9F0B42C1C81EF5A3F80394136194AE0135BDD6143CC47A5B15A9822C0691D8",
                "Deep.Protocol|12473|BA701AC9862C463931C4669910EA243F8243BBEA986CAF8EA4AA5CB282237982",
                // DID2-bound DCB1 identity/issuer candidate; XPS1, DCR1 and publication remain disabled.
                "Deep.Protocol|12488|7A2A9725A84A7991FF2713A090511C246275B9E506B39C4366A01813B9B250A6",
                "Deep.Protocol|12488|B6BFF8A0A0BD608CA6F8A01A7207307A166E7B8965DDD3E0585BDD95FBC26475",
                // Exact DID2 DCR1 support candidate; freshness and publication remain disabled.
                "Deep.Protocol|12499|93C48D3BEBB1245DA15EDBE06D473C911188C50562B3589AA348FEB63CDB8A4C",
                "Deep.Protocol|12499|3A2D4C8A2B6DC3A7B0ED25DBC8CD4447039413B8DAC34B1AAB23F363ACE9A03A",
                // DID2 bundle now verifies each independent XPS1 descriptor; XPI1/DPK2 remains gated.
                "Deep.Protocol|12500|EA17BF87C7B1F77B23A33D0B08CE65BE1D6619A54CE95D4EE3C97EA0CAD4E7F9",
                "Deep.Protocol|12500|0CF467F43186FF33314AAA92E13BC03A705D0F9FC2CD2F23F42283AEBB0DF0A2",
                // XPI1 manifest binds DID2 DCR1/XPS1; inventory and claim remain separate gates.
                "Deep.Protocol|12504|90230DDECAF65244751DB1C22FC8F5E4778B41CFD46D341FBE238535835A5A49",
                "Deep.Protocol|12504|FC7C44B6859AB51A5BF4AE64C5B6AB1EA0F9A9716008C901111B2E241ACDA8D9",
                // Non-forgeable DID2 directory/DCA1 V2 time-interval authority; runtime stays gated.
                "Deep.Protocol|12519|BD67CA3C49202E0711415C80A311485351ACE232832D386651022867A5BD82FD",
                "Deep.Protocol|12519|773F3F23E1050009C536736C33FEA13779236BDCACF6F788F390C0193E4A6EBD",
                // DR-0007 DID2 capability commitment and separately protected owner capability.
                "Deep.Protocol|12526|A9E62C9FCB295F8195457FC6E120A6810AA9FF1B54E44A5EAD814D75309BD3BC",
                // One-time DID2 empty ADH1 authoring from exact XNA1 witness custody.
                "Deep.Protocol|12527|D0B62D669E50F6CBEEAA07D7F2348E8860E676F97576C75D717944FBDF0F7290",
                "Deep.Protocol|12527|A3FFCF1420A8827419FD2F21C7988C6694BD4CEA3FBF5F8F1076C759C0183F7B",
                // DID2 V2 account can retain the exact verifier-issued device relative for DPH2.
                "Deep.Protocol|12529|F48EBBB1832129AA85B1B1373146474609218832CBC3050D4A2F4FEDBFAAAA21",
                "Deep.Protocol|12529|9184558DD070A4B2ECDB6F045E42EB538AD210FF3EE94AAC30CFB4615FC4DEC4",
                // Internal DID2 anchor-AFP1 successor-tail verifier; no public API expansion.
                "Deep.Protocol|12529|EC9F8A89C0B49C1204C2D07C9C71C4DDF3E46851E242BD0CE4EED6F601CD1C5C",
                // DID2 root-signed forward-tail authoring and exact protected-floor witness API.
                "Deep.Protocol|12556|6F31320F7530592A49B1799F0EA55C3C9F6A46EC3C80F17C13391F3261E170A8",
                // Verifier-issued exact protected floor and root-forward lineage for client LKG CAS.
                "Deep.Protocol|12560|BBCD821526FCBD636863480EC1E309679D9026F5A31D70C4CA8909AB106917D7"
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
                "Deep.Protocol.GoldenVectors|111|A10E47D43865462CEBF5236781E3F82D70B1D97F8DCF287F062B7C78791F26D0",
                "Deep.Protocol.GoldenVectors|111|314594D533F6533B2D8402BC8EA39E1BF29D82D80AC029DD295DD5E307EA2EB0"
            ]
        };
}
