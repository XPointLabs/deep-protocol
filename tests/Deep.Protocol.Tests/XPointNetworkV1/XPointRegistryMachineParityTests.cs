using System.Text.Json;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class XPointRegistryMachineParityTests
{
    [Fact]
    public void GeneratedDefinitionsExactlyMatchEverySecuritySignificantFrozenRegistryField()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(FindSpec("xpoint-network-v1.registry.json")));
        var root = document.RootElement;
        Assert.Equal(XPointNetworkRegistry.RegistryGeneration, root.GetProperty("registryGeneration").GetInt32());
        Assert.False(XPointNetworkRegistry.RuntimeActivation);
        Assert.Equal(XPointNetworkRegistry.RuntimeActivation, root.GetProperty("runtimeActivation").GetBoolean());
        Assert.Equal(XPointNetworkRegistry.HeaderBytes, root.GetProperty("canonicalGrammar").GetProperty("recordHeaderBytes").GetInt32());
        Assert.Equal(XPointNetworkRegistry.FieldHeaderBytes, root.GetProperty("canonicalGrammar").GetProperty("fieldHeaderBytes").GetInt32());
        Assert.Equal(XPointNetworkRegistry.MaximumRecordBytes, root.GetProperty("canonicalGrammar").GetProperty("recordMaximumBytes").GetInt32());

        var records = root.GetProperty("records").EnumerateArray().ToArray();
        Assert.Equal(XPointNetworkRegistry.All.Count, records.Length);
        foreach (var machine in records)
        {
            var definition = XPointNetworkRegistry.Get(machine.GetProperty("magic").GetString()!);
            CompareRecord(machine, definition);
        }

        var domains = root.GetProperty("domains").EnumerateArray().Select(value => value.GetProperty("label").GetString()!).ToArray();
        Assert.Equal(domains, XPointNetworkRegistry.AllDomains);
    }

    [Fact]
    public void GeneratedReplicaPopProjectionExactlyMatchesFrozenRegistry()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(FindSpec("xpoint-network-v1.registry.json")));
        var xcd = document.RootElement.GetProperty("records").EnumerateArray()
            .Single(record => record.GetProperty("magic").GetString() == "XCD1");
        var projection = xcd.GetProperty("projections").EnumerateArray()
            .Single(value => value.GetProperty("name").GetString() == "replicaProofOfPossession");
        Assert.Equal("1..4,8", projection.GetProperty("tags").GetString());
        Assert.Equal(XPointNetworkRegistry.XcdReplicaPopDomain, projection.GetProperty("domain").GetString());
        Assert.Equal("Deep/XPoint/V1/XCD1/replica-pop", XPointNetworkRegistry.XcdReplicaPopDomain);
    }

    private static void CompareRecord(JsonElement machine, XPointRecordDefinition generated)
    {
        Assert.Equal(machine.GetProperty("magic").GetString(), generated.Magic);
        Assert.Equal(machine.GetProperty("version").GetUInt16(), generated.Version);
        Assert.Equal(machine.GetProperty("suite").GetUInt16(), generated.Suite);
        Assert.Equal(machine.GetProperty("fieldCount").GetInt32(), generated.Fields.Count);
        Assert.Equal(machine.GetProperty("minBytes").GetInt32(), generated.MinimumBytes);
        Assert.Equal(machine.GetProperty("maxBytes").GetInt32(), generated.MaximumBytes);
        Assert.Equal("FROZEN_TARGET_NOT_ACTIVE", machine.GetProperty("status").GetString());

        var fields = machine.GetProperty("fields").EnumerateArray().ToArray();
        Assert.Equal(generated.Fields.Count, fields.Length);
        for (var index = 0; index < fields.Length; index++) CompareField(fields[index], generated.Fields[index], generated);

        CompareProjectionAndHashDefinitions(machine, generated);
        CompareGenerationAndPredecessorDefinition(machine, generated);
    }

    private static void CompareProjectionAndHashDefinitions(JsonElement machine, XPointRecordDefinition generated)
    {
        var expectedLast = generated.UnsignedLastTag == 0 ? generated.Fields.Count : generated.UnsignedLastTag;
        var projections = machine.GetProperty("projections").EnumerateArray().ToArray();
        var signed = projections.Where(value => value.TryGetProperty("signatureTag", out _)).ToArray();
        if (generated.SignatureDomain is null)
        {
            Assert.Equal(0, generated.UnsignedLastTag);
            Assert.Empty(signed);
        }
        else
        {
            var projection = Assert.Single(signed);
            Assert.Equal($"1..{generated.UnsignedLastTag}", projection.GetProperty("tags").GetString());
            Assert.Equal(generated.Fields.Count, projection.GetProperty("signatureTag").GetInt32());
            Assert.Equal(generated.SignatureDomain, projection.GetProperty("domain").GetString());
        }

        var derivation = machine.GetProperty("hashDerivations").EnumerateArray()
            .Single(value => value.GetProperty("domain").GetString() == generated.HashDomain);
        Assert.Equal($"1..{expectedLast}", derivation.GetProperty("tags").GetString());
        Assert.EndsWith("Hash32", derivation.GetProperty("name").GetString(), StringComparison.Ordinal);
    }

    private static void CompareGenerationAndPredecessorDefinition(JsonElement machine, XPointRecordDefinition generated)
    {
        var predecessor = machine.GetProperty("fields").EnumerateArray()
            .Where(value => value.TryGetProperty("zeroPolicy", out _)).ToArray();
        if (generated.GenerationTag == 0)
        {
            Assert.Equal(0, generated.PredecessorHashTag);
            Assert.Empty(predecessor);
            return;
        }

        var field = Assert.Single(predecessor);
        Assert.Equal(generated.PredecessorHashTag, field.GetProperty("tag").GetInt32());
        var generationName = generated.Fields[generated.GenerationTag - 1].Name;
        var zeroWidth = generated.Fields[generated.PredecessorHashTag - 1].MinimumLength;
        Assert.Equal($"ZERO{zeroWidth} iff {generationName}=0; otherwise nonzero", field.GetProperty("zeroPolicy").GetString());
        Assert.Equal((ushort)generated.GenerationTag, generated.Fields[generated.PredecessorHashTag - 1].ZeroIffGenerationTag);
    }

    private static void CompareField(JsonElement machine, XPointFieldDefinition generated, XPointRecordDefinition record)
    {
        Assert.Equal(machine.GetProperty("tag").GetUInt16(), generated.Tag);
        Assert.Equal(machine.GetProperty("name").GetString(), generated.Name);
        var type = machine.GetProperty("type").GetString();
        var expectedKind = type switch
        {
            "bytes" => XPointFieldKind.Bytes, "u8" => XPointFieldKind.UInt8, "u16be" => XPointFieldKind.UInt16,
            "u32be" => XPointFieldKind.UInt32, "u64be" => XPointFieldKind.UInt64, "fixed-list" => XPointFieldKind.FixedList,
            "core-ref" => XPointFieldKind.CoreReference, "artifact-ref" => XPointFieldKind.ArtifactReference,
            _ => throw new InvalidOperationException(type),
        };
        Assert.Equal(expectedKind, generated.Kind);
        Assert.Equal(machine.TryGetProperty("nonzero", out var nonzero) && nonzero.GetBoolean(), generated.NonZero);
        if (machine.TryGetProperty("length", out var length))
        {
            Assert.Equal(length.GetInt32(), generated.MinimumLength);
            Assert.Equal(length.GetInt32(), generated.MaximumLength);
        }
        if (type == "fixed-list")
        {
            Assert.Equal(machine.GetProperty("countTag").GetUInt16(), generated.CountTag);
            Assert.Equal(machine.GetProperty("entryBytes").GetInt32(), generated.EntryBytes);
            Assert.Equal(machine.GetProperty("entryBytes").GetInt32() * machine.GetProperty("minItems").GetInt32(), generated.MinimumLength);
            Assert.Equal(machine.GetProperty("entryBytes").GetInt32() * machine.GetProperty("maxItems").GetInt32(), generated.MaximumLength);
        }
        if (machine.TryGetProperty("refType", out var reference)) Assert.Equal(reference.GetString(), generated.ReferenceMagic);
        if (machine.TryGetProperty("minimum", out var minimum)) Assert.Equal(minimum.GetUInt64(), generated.MinimumValue);
        if (machine.TryGetProperty("maximum", out var maximum)) Assert.Equal(maximum.GetUInt64(), generated.MaximumValue);
        if (machine.TryGetProperty("maximumFromTag", out var maximumFromTag))
            Assert.Equal(record.Fields[maximumFromTag.GetInt32() - 1].MaximumValue, generated.MaximumValue);
        if (machine.TryGetProperty("enum", out var values))
        {
            var expected = values.EnumerateObject().Select(value => ulong.Parse(value.Name, System.Globalization.CultureInfo.InvariantCulture)).Order().ToArray();
            Assert.Equal(expected, generated.AllowedValues!.Order());
        }
        Assert.Equal(machine.TryGetProperty("zeroPolicy", out _), generated.ZeroIffGenerationTag != 0);
    }

    private static string FindSpec(string fileName) => XPointNetworkFrozenVectorManifest.FindSpec(fileName);
}
