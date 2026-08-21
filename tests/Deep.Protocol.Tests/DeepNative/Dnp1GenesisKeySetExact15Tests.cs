using System.Buffers.Binary;
using System.Reflection;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisKeySetExact15Tests
{
    private static readonly byte[] SharedHmac = Bytes(0xd1, 32);
    private static readonly byte[] Latch = Bytes(0xd2, 32);
    private static readonly byte[] Protector = Bytes(0xd3, 32);

    [Fact]
    public async Task Exact296KeySet_AcceptsOnlySixOrderedDistinctHealthyRoles()
    {
        var request = Request();
        var scope = Scope(request);
        var registry = new Registry(scope, 7, Healthy());

        var context = await GenesisProtectedKeySetContext.ReadAsync(
            registry, request, SharedHmac, Latch, Protector, default);

        Assert.Equal(1, registry.Calls);
        Assert.Equal(GenesisProtectedKeySetContext.ExactScopeLength, scope.Length);
        Assert.Equal(7UL, context.SourceRevision);
        Assert.True(context.NoAuthorityClaim);
        Assert.Equal(Bytes(0x41, 32), context.DplKeyId.ToArray());
        Assert.Equal(Bytes(0x42, 32), context.DwlKeyId.ToArray());
        Assert.Equal(Bytes(0x43, 32), context.RrlKeyId.ToArray());
        Assert.Equal(Bytes(0x44, 32), context.RibKeyId.ToArray());
        Assert.Equal(Bytes(0x45, 32), context.MrlcKeyId.ToArray());
        Assert.Equal(Bytes(0x46, 32), context.DxrKeyId.ToArray());
    }

    [Fact]
    public async Task ClosedRowsAndHealth_RejectMissingExtraUnknownReorderedDuplicateOrUnhealthy()
    {
        var request = Request();
        var canonical = Scope(request);
        var cases = new List<(byte[] Scope, ulong Revision, bool[] Health)>
        {
            (canonical[..^1], 7, Healthy()),
            (canonical.Concat(new byte[] { 0 }).ToArray(), 7, Healthy()),
            (MutateU16(canonical, 90, 5), 7, Healthy()),
            (MutateU16(canonical, 92, 7), 7, Healthy()),
            (MutateU16(canonical, 92, 2), 7, Healthy()),
            (MutateU16(canonical, 126, 1), 7, Healthy()),
            (Replace(canonical, 128, canonical.AsSpan(94, 32)), 7, Healthy()),
            (Replace(canonical, 94, new byte[32]), 7, Healthy()),
            (Replace(canonical, 0, Bytes(0xee, 16)), 7, Healthy()),
            (canonical, 0, Healthy()),
            (canonical, 7, Healthy()[..^1]),
            (canonical, 7, Healthy().Concat(new[] { true }).ToArray()),
            (canonical, 7, new[] { true, true, false, true, true, true })
        };

        foreach (var test in cases)
        {
            var registry = new Registry(test.Scope, test.Revision, test.Health);
            await Assert.ThrowsAsync<RecordException>(() =>
                GenesisProtectedKeySetContext.ReadAsync(
                    registry, request, SharedHmac, Latch, Protector, default).AsTask());
            Assert.Equal(1, registry.Calls);
        }
    }

    [Fact]
    public async Task ProviderRoleCrossFeed_RejectsEachSharedLatchOrProtectorSubstitution()
    {
        var request = Request();
        for (var roleIndex = 0; roleIndex < 6; roleIndex++)
        {
            foreach (var forbidden in new[] { SharedHmac, Latch, Protector })
            {
                var scope = Replace(Scope(request), 94 + roleIndex * 34, forbidden);
                var registry = new Registry(scope, 7, Healthy());

                await Assert.ThrowsAsync<RecordException>(() =>
                    GenesisProtectedKeySetContext.ReadAsync(
                        registry, request, SharedHmac, Latch, Protector, default).AsTask());

                Assert.Equal(1, registry.Calls);
            }
        }
    }

    [Fact]
    public async Task Revalidation_RejectsRegistryScopeOrRevisionMovement()
    {
        var request = Request();
        var registry = new Registry(Scope(request), 7, Healthy());
        var context = await GenesisProtectedKeySetContext.ReadAsync(
            registry, request, SharedHmac, Latch, Protector, default);
        registry.Scope = Replace(registry.Scope, 94, Bytes(0x51, 32));
        registry.Revision = 8;

        await Assert.ThrowsAsync<RecordException>(() =>
            context.RevalidateAsync(
                registry, request, SharedHmac, Latch, Protector, default).AsTask());

        Assert.Equal(2, registry.Calls);
    }

    [Fact]
    public async Task RoleSwap_RejectsEveryPairAndDplNeverUsesSharedRecoveryHmac()
    {
        var request = Request();
        for (var first = 0; first < 6; first++)
        {
            for (var second = first + 1; second < 6; second++)
            {
                var registry = new Registry(Scope(request), 7, Healthy());
                var context = await GenesisProtectedKeySetContext.ReadAsync(
                    registry, request, SharedHmac, Latch, Protector, default);
                var swapped = registry.Scope.ToArray();
                var firstOffset = 94 + first * 34;
                var secondOffset = 94 + second * 34;
                var firstKey = swapped.AsSpan(firstOffset, 32).ToArray();
                var secondKey = swapped.AsSpan(secondOffset, 32).ToArray();
                secondKey.CopyTo(swapped, firstOffset);
                firstKey.CopyTo(swapped, secondOffset);
                registry.Scope = swapped;
                var before = registry.Calls;

                await Assert.ThrowsAsync<RecordException>(() =>
                    context.RevalidateAsync(
                        registry, request, SharedHmac, Latch, Protector, default).AsTask());
                Assert.Equal(before + 1, registry.Calls);
            }
        }

        var sharedAsDpl = Replace(Scope(request), 94, SharedHmac);
        var forbiddenRegistry = new Registry(sharedAsDpl, 7, Healthy());
        await Assert.ThrowsAsync<RecordException>(() =>
            GenesisProtectedKeySetContext.ReadAsync(
                forbiddenRegistry, request, SharedHmac, Latch, Protector, default).AsTask());
        Assert.Equal(1, forbiddenRegistry.Calls);
    }

    [Fact]
    public void KeySetCapability_IsSealedNonserializableAndHasNoPublicRawIdSurface()
    {
        foreach (var type in new[]
                 {
                     typeof(GenesisProtectedKeySetContext),
                     typeof(GenesisCutoverSourceContext)
                 })
        {
            var publicMembers = type.GetMembers(BindingFlags.Public | BindingFlags.Instance |
                                                BindingFlags.Static | BindingFlags.DeclaredOnly);

            Assert.True(type.IsSealed);
            Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
            Assert.DoesNotContain(type.GetInterfaces(), candidate =>
                candidate == typeof(System.Runtime.Serialization.ISerializable));
            Assert.DoesNotContain(publicMembers, member =>
                member.Name.Contains("KeyId", StringComparison.OrdinalIgnoreCase) ||
                member.Name.Contains("Parse", StringComparison.OrdinalIgnoreCase) ||
                member.Name.Contains("Authority", StringComparison.OrdinalIgnoreCase) &&
                member.Name is not ("NoAuthorityClaim" or "get_NoAuthorityClaim"));
            Assert.All(publicMembers.OfType<MethodInfo>(), method =>
                Assert.DoesNotContain(method.GetParameters(), parameter =>
                    parameter.ParameterType == typeof(byte[]) ||
                    parameter.ParameterType == typeof(ReadOnlyMemory<byte>)));
        }
    }

    private static GenesisProtectedKeySetRequest Request() => new(
        Bytes(0x11, 16), Bytes(0x12, 32), ComponentKind.Shared,
        Bytes(0x13, 32), 9);

    private static byte[] Scope(GenesisProtectedKeySetRequest request)
    {
        var output = new byte[GenesisProtectedKeySetContext.ExactScopeLength];
        request.ExactScopeAxes.Span.CopyTo(output);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(90, 2), 6);
        for (var index = 0; index < 6; index++)
        {
            var offset = 92 + index * 34;
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2),
                checked((ushort)(index + 1)));
            output.AsSpan(offset + 2, 32).Fill(checked((byte)(0x41 + index)));
        }
        return output;
    }

    private static byte[] MutateU16(byte[] source, int offset, ushort value)
    {
        var output = source.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2), value);
        return output;
    }

    private static byte[] Replace(byte[] source, int offset, ReadOnlySpan<byte> value)
    {
        var output = source.ToArray();
        value.CopyTo(output.AsSpan(offset, value.Length));
        return output;
    }

    private static bool[] Healthy() => Enumerable.Repeat(true, 6).ToArray();

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed class Registry(byte[] scope, ulong revision, bool[] health)
        : GenesisProtectedKeySetRegistry
    {
        public byte[] Scope { get; set; } = scope;
        public ulong Revision { get; set; } = revision;
        public int Calls { get; private set; }

        public override ValueTask<GenesisProtectedKeySetReadResult> ReadAsync(
            GenesisProtectedKeySetRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(new GenesisProtectedKeySetReadResult(
                Scope, Revision, health));
        }
    }
}
