using System.Reflection;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisAuthoringExact15Tests
{
    [Fact]
    public void BaseIdentityContext_HasNoDtcSourceAnchorRsmDrcOrAuthorityMintSurface()
    {
        var type = typeof(VerifiedGenesisBaseIdentityContext);
        var declared = type.GetMembers(BindingFlags.Public | BindingFlags.NonPublic |
                                       BindingFlags.Instance | BindingFlags.Static |
                                       BindingFlags.DeclaredOnly);
        var publicDeclared = declared.Where(member =>
            member is not ConstructorInfo &&
            IsPublic(member)).ToArray();

        Assert.True(type.IsSealed);
        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(declared, member => ContainsForbiddenCapability(member.Name));
        Assert.DoesNotContain(publicDeclared, member =>
            member.Name.Contains("Create", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Parse", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Convert", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(publicDeclared, member => member.Name is
            "NoAuthorityClaim" or "get_NoAuthorityClaim");
    }

    [Fact]
    public void TransactionAndComponentContexts_HaveNoPublicRawScopeOrIdConstruction()
    {
        foreach (var type in new[]
                 {
                     typeof(GenesisTransactionScopeContext),
                     typeof(GenesisTransactionReservation),
                     typeof(GenesisIdentityContext),
                     typeof(GenesisComponentIntent)
                 })
        {
            Assert.True(type.IsSealed);
            Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
            Assert.DoesNotContain(type.GetMethods(BindingFlags.Public | BindingFlags.Static |
                                                  BindingFlags.DeclaredOnly), method =>
                method.Name.Contains("Parse", StringComparison.OrdinalIgnoreCase) ||
                method.Name.Contains("FromBytes", StringComparison.OrdinalIgnoreCase) ||
                method.GetParameters().Any(parameter =>
                    parameter.ParameterType == typeof(byte[]) ||
                    parameter.ParameterType == typeof(ReadOnlyMemory<byte>)));
            Assert.DoesNotContain(type.GetProperties(BindingFlags.Public | BindingFlags.Instance |
                                                     BindingFlags.DeclaredOnly), property =>
                property.Name.Contains("TransactionId", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Contains("ExactScope", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Contains("KeyId", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Contains("Authority", StringComparison.OrdinalIgnoreCase) &&
                property.Name != "NoAuthorityClaim");
        }
    }

    [Fact]
    public void RecoveryVerifierGenesisFactories_RequireOnlySealedTypedContexts()
    {
        var contextMethods = new HashSet<string>(StringComparer.Ordinal)
        {
            "CreateGenesisBaseIdentityContext",
            "CreateGenesisTransactionScopeContext",
            "RestoreOrReserveGenesisTransactionAsync",
            "AuthorGenesisIdentityContextAsync",
            "CreateGenesisComponentIntent",
            "ReadGenesisRecoveryProtectorAsync",
            "CreateGenesisCutoverSourceContext",
            "AuthorGenesisRecoveryManifestAsync",
            "SealGenesisCandidateAsync"
        };
        var methods = typeof(RecoveryVerifier).GetMethods(
                BindingFlags.Public | BindingFlags.Static)
            .Where(method => contextMethods.Contains(method.Name))
            .ToArray();

        Assert.Equal(contextMethods.Count + 1, methods.Length);
        Assert.Equal(2, methods.Count(method =>
            method.Name == "CreateGenesisBaseIdentityContext"));
        Assert.DoesNotContain(methods, method => method.GetParameters().Any(parameter =>
            IsRawBytes(parameter.ParameterType)));
        Assert.DoesNotContain(methods, method =>
            method.ReturnType.Name.Contains("Authority", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BaseIdentityFactory_RequiresCompletedDistributedManifestAndRejectsRawOrSignedOnlyDcm()
    {
        var methods = typeof(RecoveryVerifier).GetMethods(BindingFlags.Public |
                BindingFlags.Static)
            .Where(method => method.Name == "CreateGenesisBaseIdentityContext")
            .ToArray();

        Assert.Equal(2, methods.Length);
        Assert.Contains(methods, method => method.GetParameters()[4].ParameterType ==
            typeof(GenesisDistributedCutoverManifestPlan));
        Assert.Contains(methods, method => method.GetParameters()[4].ParameterType ==
            typeof(GenesisDistributedAccountResetPlan));
        Assert.DoesNotContain(methods, method => method.GetParameters().Any(parameter =>
            parameter.ParameterType == typeof(CutoverManifest) ||
            parameter.ParameterType == typeof(VerifiedCutoverManifestRelative) ||
            parameter.ParameterType == typeof(GenesisSignedCutoverManifestPlan) ||
            IsRawBytes(parameter.ParameterType)));
        Assert.Empty(typeof(GenesisDistributedCutoverManifestPlan)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(GenesisDistributedAccountResetPlan)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public void IdentityProvenance_RecoveredDrm20CannotEnterGenesisAuthorPath()
    {
        var methods = typeof(RecoveryVerifier).GetMethods(BindingFlags.Public |
            BindingFlags.Static);
        var author = Assert.Single(methods, method =>
            method.Name == "AuthorGenesisIdentityContextAsync");
        var component = Assert.Single(methods, method =>
            method.Name == "CreateGenesisComponentIntent");
        var scope = Assert.Single(methods, method =>
            method.Name == "CreateGenesisTransactionScopeContext");

        Assert.DoesNotContain(author.GetParameters(), parameter =>
            parameter.ParameterType == typeof(VerifiedRecoveredIdentityContext));
        Assert.Equal(typeof(GenesisIdentityContext), component.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(VerifiedGenesisBaseIdentityContext),
            scope.GetParameters()[0].ParameterType);
        Assert.Empty(typeof(GenesisIdentityContext)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(typeof(VerifiedRecoveredIdentityContext)
                .GetMethods(BindingFlags.Public | BindingFlags.Instance |
                            BindingFlags.Static | BindingFlags.DeclaredOnly),
            method => method.ReturnType == typeof(GenesisIdentityContext) ||
                      method.ReturnType == typeof(GenesisComponentIntent));
        Assert.DoesNotContain(methods, method =>
            method.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(VerifiedRecoveredIdentityContext)) &&
            (method.ReturnType == typeof(GenesisIdentityContext) ||
             method.ReturnType == typeof(GenesisComponentIntent) ||
             method.ReturnType == typeof(ValueTask<GenesisIdentityContext>)));
        var release = Assert.Single(methods, method =>
            method.Name == "CreateGenesisReleaseContext");
        Assert.Equal(typeof(VerifiedGenesisBaseIdentityContext),
            release.GetParameters()[0].ParameterType);
        Assert.DoesNotContain(release.GetParameters(), parameter =>
            parameter.ParameterType == typeof(byte[]) ||
            parameter.ParameterType == typeof(ReadOnlyMemory<byte>));
    }

    private static bool ContainsForbiddenCapability(string name) =>
        name.Contains("Dtc", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("Source", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("Anchor", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("Rsm", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("Drc", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("AuthorityClaim", StringComparison.OrdinalIgnoreCase) &&
        name is not ("NoAuthorityClaim" or "get_NoAuthorityClaim");

    private static bool IsPublic(MemberInfo member) => member switch
    {
        MethodBase method => method.IsPublic,
        PropertyInfo property =>
            property.GetMethod?.IsPublic == true || property.SetMethod?.IsPublic == true,
        FieldInfo field => field.IsPublic,
        _ => false
    };

    private static bool IsRawBytes(Type type) =>
        type == typeof(byte[]) ||
        type == typeof(Memory<byte>) ||
        type == typeof(ReadOnlyMemory<byte>) ||
        type == typeof(Span<byte>) ||
        type == typeof(ReadOnlySpan<byte>);
}
