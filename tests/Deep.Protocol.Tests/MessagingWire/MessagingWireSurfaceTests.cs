using System.Reflection;
using System.Runtime.InteropServices;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Registry;

namespace Deep.Protocol.Tests.MessagingWire;

public sealed class MessagingWireSurfaceTests
{
    [Fact]
    public void PublicModelsAreSealedImmutableAndExposeNoMutableBuffers()
    {
        var modelTypes = new[]
        {
            typeof(Dpk2Record),
            typeof(Dph2SelectedPrekey),
            typeof(Dph2InitialCiphertext),
            typeof(Dph2Record),
            typeof(Dtr2BraidMessage),
            typeof(Dtr2Record),
            typeof(Dpe2Ciphertext),
            typeof(Dpe2Record),
        };

        foreach (var type in modelTypes)
        {
            Assert.True(type.IsSealed, $"{type.FullName} must be sealed.");
            foreach (var property in type.GetProperties(BindingFlags.Instance | BindingFlags.Public))
            {
                Assert.Null(property.SetMethod);
                Assert.NotEqual(typeof(byte[]), property.PropertyType);
                Assert.False(
                    property.PropertyType.IsGenericType &&
                    property.PropertyType.GetGenericTypeDefinition() == typeof(Memory<>));
            }

            Assert.DoesNotContain(
                type.GetFields(BindingFlags.Instance | BindingFlags.Public),
                field => !field.IsInitOnly);
        }
    }

    [Fact]
    public void ReturnedReadOnlyMemoryCannotMutateOwnedRecord()
    {
        var record = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var original = record.BundleId.ToArray();
        var publicView = record.BundleId;
        Assert.True(MemoryMarshal.TryGetArray(publicView, out var segment));
        segment.Array![segment.Offset] ^= 0xff;

        Assert.Equal(original, record.BundleId.ToArray());
        Assert.Equal(Dpk2Codec.OneTimeTotalBytes, Dpk2Codec.Encode(record).Length);
    }

    [Fact]
    public void TypedCiphertextOwnersCopyInputsAndRequireExactDestinations()
    {
        var source = MessagingWireFixtures.Bytes(4112, 0x31);
        var expected = source.ToArray();
        var dph = Dph2InitialCiphertext.Import(source);
        var dpe = Dpe2Ciphertext.Import(source);
        source.AsSpan().Clear();
        var dphCopy = new byte[4112];
        var dpeCopy = new byte[4112];
        dph.CopyCiphertextTo(dphCopy);
        dpe.CopyCiphertextTo(dpeCopy);

        Assert.Equal(expected, dphCopy);
        Assert.Equal(expected, dpeCopy);
        Assert.Throws<ArgumentException>(() => dph.CopyCiphertextTo(new byte[4111]));
        Assert.Throws<ArgumentException>(() => dpe.CopyCiphertextTo(new byte[4113]));
    }

    [Fact]
    public void MessagingWireHasNoGenericBlobDispatcherProviderOrCallbackSurface()
    {
        var types = typeof(Dpk2Codec).Assembly.GetExportedTypes()
            .Where(type => type.Namespace == typeof(Dpk2Codec).Namespace)
            .ToArray();
        Assert.Equal(
            [
                nameof(IDpe2VerificationCallbacks),
                nameof(IDph2VerificationCallbacks),
                nameof(IDpk2VerificationCallbacks),
                nameof(IDtr2VerificationCallbacks),
            ],
            types.Where(type => type.IsInterface).Select(type => type.Name).Order().ToArray());
        Assert.DoesNotContain(types, type => type.Name.Contains("Provider", StringComparison.Ordinal));
        Assert.DoesNotContain(types, type => type.Name.Contains("Dispatcher", StringComparison.Ordinal));
        Assert.DoesNotContain(types, type => type.Name.Contains("Blob", StringComparison.Ordinal));

        foreach (var method in types.SelectMany(type => type.GetMethods(
                     BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly)))
        {
            Assert.NotEqual(typeof(object), method.ReturnType);
            Assert.DoesNotContain(method.GetParameters(), parameter =>
                parameter.ParameterType == typeof(object) ||
                typeof(Delegate).IsAssignableFrom(parameter.ParameterType) ||
                parameter.ParameterType.Name.Contains("Provider", StringComparison.Ordinal));
        }

        Assert.All(
            typeof(Dtr2Codec).GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly),
            method =>
            {
                if (!method.IsSpecialName)
                    Assert.Contains("Embedded", method.Name, StringComparison.Ordinal);
            });
    }

    [Fact]
    public void VerifiedCapabilitiesAreFacadeMintedAndCannotBeConstructedByConsumers()
    {
        var capabilityTypes = new[]
        {
            typeof(VerifiedDpk2Offering),
            typeof(VerifiedDph2Initiation),
            typeof(VerifiedDtr2Header),
            typeof(VerifiedDpe2Envelope),
        };

        Assert.All(capabilityTypes, type =>
            Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)));
        Assert.True(typeof(MessagingWireVerification).IsAbstract && typeof(MessagingWireVerification).IsSealed);
        Assert.DoesNotContain(
            typeof(MessagingWireVerification).GetMethods(BindingFlags.Public | BindingFlags.Static),
            method => method.ReturnType == typeof(Dpk2Record) ||
                      method.ReturnType == typeof(Dph2Record) ||
                      method.ReturnType == typeof(Dtr2Record) ||
                      method.ReturnType == typeof(Dpe2Record));
    }

    [Fact]
    public void FrozenSizeSurfacesAreExactAndNoRetiredDomainLeaks()
    {
        Assert.Equal("FROZEN_CLEAN_BREAK", MessagingWireActivation.CodecStatus);
        Assert.False(MessagingWireActivation.ProductionActive);
        Assert.Equal([1973, 2037], Dpk2Codec.AllowedTotalSizes.ToArray());
        Assert.Equal([5917, 18205, 34589], Dph2Codec.AllowedTotalSizes.ToArray());
        Assert.Equal([189, 285, 349, 1149, 1341], Dtr2Codec.AllowedTotalSizes.ToArray());
        Assert.Equal(
            [4513, 4609, 4673, 5473, 5665, 16801, 16897, 16961, 17761, 17953,
             33185, 33281, 33345, 34145, 34337, 49553, 49649, 49713, 50513, 50705],
            Dpe2Codec.AllowedTotalSizes.ToArray());

        var domains = typeof(MessagingWireCryptographicInputs)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.FieldType == typeof(string))
            .Select(field => Assert.IsType<string>(field.GetRawConstantValue()))
            .ToArray();
        Assert.All(domains, domain => Assert.StartsWith("Deep/", domain, StringComparison.Ordinal));
        Assert.DoesNotContain(domains, domain => domain.StartsWith("Deep/Handshake/V1/", StringComparison.Ordinal));
    }

    [Fact]
    public void GeneratedRegistryExposesOnlyTheFrozenTargetIdentifiers()
    {
        Assert.Equal("DTR2", DeepProtocolIdentifiers.Magic.DTR2);
        Assert.Equal("DTR2"u8.ToArray(), DeepProtocolIdentifiers.MagicBytes.DTR2.ToArray());
        Assert.Contains(
            DeepProtocolRegistryGenerated.Identifiers,
            identifier => identifier.Namespace == "suite:pairwise-messaging-u16" &&
                          identifier.NumericId == 0x0201 &&
                          identifier.Lifecycle == ProtocolIdentifierLifecycle.FROZEN_TARGET_NOT_ACTIVE);
        foreach (var magic in new[] { "DPK2", "DPH2", "DTR2", "DPE2" })
        {
            Assert.Contains(
                DeepProtocolRegistryGenerated.Identifiers,
                identifier => identifier.Namespace == "magic" &&
                              identifier.CanonicalName == magic &&
                              identifier.Lifecycle == ProtocolIdentifierLifecycle.FROZEN_TARGET_NOT_ACTIVE);
        }
    }

    [Fact]
    public void Did1CannotBeSubstitutedIntoMessagingWireSchemaByApiShape()
    {
        var publicMembers = typeof(Dpk2Record).Assembly.GetExportedTypes()
            .Where(type => type.Namespace == typeof(Dpk2Record).Namespace)
            .SelectMany(type => type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            .Select(member => member.Name)
            .ToArray();

        Assert.DoesNotContain(publicMembers, name => name.Contains("PermanentId", StringComparison.Ordinal));
        Assert.DoesNotContain(publicMembers, name => name.Contains("Did1", StringComparison.OrdinalIgnoreCase));
    }
}
