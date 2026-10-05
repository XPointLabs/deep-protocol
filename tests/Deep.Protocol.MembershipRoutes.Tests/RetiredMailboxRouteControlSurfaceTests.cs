using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class RetiredMailboxRouteControlSurfaceTests
{
    [Fact]
    public void ActualRoutesAssemblyContainsNoRetiredTopologyOrRouteControlTypes()
    {
        Assert.DoesNotContain(typeof(MembershipRouteDescriptor).Assembly.GetTypes(),
            type => type.Namespace == "Deep.Protocol.DeepExtension.MailboxTopology");
    }

    [Fact]
    public void ActualProtocolAssemblyContainsNoRetiredRouteVerificationFacade()
    {
        Assert.Null(typeof(MailboxReplicaMembershipProof).Assembly.GetType(
            "Deep.Protocol.DeepExtension.MailboxAuthority.ProductionMailboxRoutesVerificationFacade",
            throwOnError: false));
    }

    [Fact]
    public void RetainedMembershipPublicSurfaceMatchesTheReviewedPreRemovalContract()
    {
        var types = typeof(MembershipRouteDescriptor).Assembly.GetExportedTypes();
        Assert.Equal(9, types.Length);
        Assert.All(types, type => Assert.Equal(
            "Deep.Protocol.DeepExtension.MembershipRoutes", type.Namespace));
        var flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance
            | BindingFlags.Static | BindingFlags.DeclaredOnly;
        var lines = new List<string>();
        foreach (var type in types)
        {
            lines.Add($"type|{type.FullName}|{(int)type.Attributes}|base={type.BaseType!.FullName}");
            foreach (var member in type.GetMembers(flags))
            {
                if (member is MethodBase method &&
                    (method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly))
                    lines.Add($"method|{type.FullName}|{(int)method.Attributes}|{method}");
                else if (member is FieldInfo field &&
                    (field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly))
                    lines.Add($"field|{type.FullName}|{(int)field.Attributes}|{field}");
            }
        }
        lines.Sort(StringComparer.Ordinal);
        Assert.Equal(90, lines.Count);
        var canonical = string.Join('\n', lines) + "\n";
        Assert.Equal("998b290e3e8a41b2fb9017c3b77bd6fd33ad173bd5d8284f780c672d61fd7904",
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant());
    }
}
