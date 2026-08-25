using System.Reflection;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class PublicApiNamingTests
{
    [Fact]
    public void PackageBlockingCutoverVerifier_UsesFrozenCleanBreakName()
    {
        var methods = typeof(Deep.Protocol.DeepNative.RecoveryVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static);

        Assert.Single(methods, method =>
            method.Name == "VerifyDistributedCutoverManifestAsync");
        Assert.DoesNotContain(methods, method =>
            method.Name == "DistributeCutoverManifestAsync");
    }

    [Fact]
    public void WaveOnePublicSurface_UsesDomainNamesWithoutWorkPackageTokens()
    {
        var assembly = typeof(Deep.Protocol.DeepNative.RecoveryVerifier).Assembly;
        var forbidden = new[] { "Dnp1", "Wave1", "P03", "P04", "4C", "4D", "4E" };
        var offenders = new List<string>();
        foreach (var type in assembly.GetExportedTypes().Where(static value =>
                     value.Namespace == "Deep.Protocol.DeepNative"))
        {
            Check(type.FullName ?? type.Name);
            foreach (var member in type.GetMembers(BindingFlags.Instance | BindingFlags.Static |
                         BindingFlags.Public | BindingFlags.DeclaredOnly))
                Check($"{type.FullName}.{member.Name}");
        }
        Assert.True(offenders.Count == 0,
            "Public Wave 1 API contains work-package names: " + string.Join(", ", offenders));

        void Check(string value)
        {
            if (forbidden.Any(token => value.Contains(token, StringComparison.OrdinalIgnoreCase)))
                offenders.Add(value);
        }
    }
}
