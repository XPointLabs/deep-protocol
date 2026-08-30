using Deep.Protocol.DeepNative;
using Deep.Protocol.Registry;

namespace Deep.Protocol.Tests.Registry;

public sealed class DeepProtocolRegistryTests
{
    [Fact]
    public void GeneratedIdentifiers_AreCollisionFreeWithinTheirNamespaces()
    {
        foreach (var group in DeepProtocolRegistryGenerated.Identifiers.GroupBy(static value => value.Namespace))
        {
            Assert.Equal(
                group.Count(),
                group.Select(static value => value.CanonicalName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count());

            var numeric = group.Where(static value => value.NumericId.HasValue).ToArray();
            Assert.Equal(numeric.Length, numeric.Select(static value => value.NumericId).Distinct().Count());
        }
    }

    [Fact]
    public void GeneratedRegistry_HasNoAccidentallyActiveIdentifier()
    {
        Assert.DoesNotContain(
            DeepProtocolRegistryGenerated.Identifiers,
            static value => value.Lifecycle == ProtocolIdentifierLifecycle.RELEASE_ACTIVE);
    }

    [Fact]
    public void FrozenArtifactTypes_AreClosedAndUseGeneratedDomains()
    {
        foreach (var type in Enum.GetValues<ArtifactType>())
        {
            var id = (ushort)type;
            Assert.True(DeepProtocolRegistryGenerated.IsKnownDnp1ArtifactType(id));
            Assert.Equal(
                DeepProtocolRegistryGenerated.IsRetainedDnp1ArtifactType(id),
                ArtifactRegistry.IsRetained(type));

            var domain = DeepProtocolRegistryGenerated.GetDnp1ArtifactHashDomain(id);
            if (ArtifactRegistry.IsRetained(type))
            {
                Assert.Null(domain);
            }
            else
            {
                Assert.NotNull(domain);
                Assert.Equal(domain, ArtifactRegistry.GetNewArtifactDomain(type));
            }
        }

        var maximum = Enum.GetValues<ArtifactType>().Max(static value => (ushort)value);
        Assert.False(DeepProtocolRegistryGenerated.IsKnownDnp1ArtifactType(checked((ushort)(maximum + 1))));
    }

    [Fact]
    public void FrozenRecordDefinitions_UseTheImportedGeneratedMagicSet()
    {
        string[] expected =
        [
            "DBG1", "DCL1", "DCM1", "DCN1", "DCP1", "DCQ1", "DCS1", "DCT1", "DHL1",
            "DNR1", "DPA1", "DPC1", "DPD1", "DPJ1", "DPL1", "DPM1", "DPR1", "DPS1",
            "DRA1", "DRC1", "DRS1", "DRT1", "DWD1", "DWL1", "DWT1", "DXR1", "KRF1",
            "KRT1", "MRL2", "MRLC", "RIB1", "RIP2", "RRL1", "RRM1", "XIB1"
        ];
        Assert.Equal(expected, DeepProtocolRegistryGenerated.Dnp1CanonicalRecordMagic);

        foreach (var magic in DeepProtocolRegistryGenerated.Dnp1CanonicalRecordMagic)
            Assert.Equal(magic, RecordDefinitions.Get(magic).Magic);

        Assert.Throws<RecordException>(() => RecordDefinitions.Get("MAX1"));
    }

    [Fact]
    public void FrozenSuiteIdentifiers_AreExact()
    {
        Assert.Equal((ushort)0x0000, DeepProtocolIdentifiers.Suites.DnpUnsignedCommittedV1);
        Assert.Equal((ushort)0x0001, DeepProtocolIdentifiers.Suites.IdentityAuthV1Ed25519);
        Assert.Equal((ushort)0x8001, DeepProtocolIdentifiers.Suites.ProtectedStateHmacSha256V1);
        Assert.Equal((ushort)0x8002, DeepProtocolIdentifiers.Suites.ProtectedStateAeadV1);
    }

    [Fact]
    public void FrozenRegistryProvenanceAndDomains_AreIndependentExpectedValues()
    {
        Assert.Equal("2562b11cdacdcc6e60cf79bdb6265b4f4687fbbe", DeepProtocolRegistryGenerated.Dnp1ApprovedCommit);
        Assert.Equal("abbfdbe76d768ac4b132403d54943dbbf4781bd6865377519e13796b5b5c8b18", DeepProtocolRegistryGenerated.Dnp1RegistrySha256);

        Assert.Equal("Deep/Artifact/V1/DPA1", DeepProtocolRegistryGenerated.GetDnp1ArtifactHashDomain(1));
        Assert.Equal("Deep/Artifact/V1/DRS1", DeepProtocolRegistryGenerated.GetDnp1ArtifactHashDomain(4));
        Assert.Equal("Deep/Artifact/V1/DWT1", DeepProtocolRegistryGenerated.GetDnp1ArtifactHashDomain(44));
        Assert.Null(DeepProtocolRegistryGenerated.GetDnp1ArtifactHashDomain(14));

        Dictionary<string, string> protectedDomains = new(StringComparer.Ordinal)
        {
            ["DBG1"] = "Deep/ProtectedState/V1/DDBG1",
            ["DPJ1"] = "Deep/ProtectedState/V1/DPJ1",
            ["DPL1"] = "Deep/ProtectedState/V1/DPL1",
            ["DWL1"] = "Deep/ProtectedState/V1/DWL1",
            ["DXR1"] = "Deep/ProtectedState/V1/DXP1-verified-receipt",
            ["MRLC"] = "Deep/ProtectedState/V1/MRLC1",
            ["RIB1"] = "Deep/ProtectedState/V1/DRIB1",
            ["RRL1"] = "Deep/ProtectedState/V1/RRL1",
            ["XIB1"] = "Deep/ProtectedState/V1/DXIB1"
        };
        foreach (var pair in protectedDomains)
            Assert.Equal(pair.Value, DeepProtocolRegistryGenerated.GetDnp1ProtectedDomain(pair.Key));
        Assert.Null(DeepProtocolRegistryGenerated.GetDnp1ProtectedDomain("MAX1"));
    }

    [Fact]
    public void CurrentPreCutoverAndRetiredLifecycle_AreNotConflated()
    {
        Assert.Contains(
            DeepProtocolRegistryGenerated.Identifiers,
            static value => value.Namespace == "magic" && value.CanonicalName == "MAU2" &&
                            value.Lifecycle == ProtocolIdentifierLifecycle.CURRENT_PRE_CUTOVER);
        Assert.Contains(
            DeepProtocolRegistryGenerated.Identifiers,
            static value => value.Namespace == "magic" && value.CanonicalName == "PMT1" &&
                            value.Lifecycle == ProtocolIdentifierLifecycle.CURRENT_PRE_CUTOVER);
        Assert.DoesNotContain(
            DeepProtocolRegistryGenerated.Identifiers,
            static value => value.Lifecycle == ProtocolIdentifierLifecycle.RETIRED_REJECT);
    }
}
