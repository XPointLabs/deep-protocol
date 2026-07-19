using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace Deep.Protocol.ProfileCarrier.Tests;

public sealed class ProfileCarrierMalformedRedTests
{
    [Fact]
    public void RejectsUnknownVersionTrailingReorderingAndNonMinimalLengths()
    {
        var canonical = Compose().FilePayload.ToArray();
        AssertFraming(Mutate(canonical, 4, 2));
        AssertFraming([.. canonical, (byte)0]);

        var bodyOffset = BodyOffset(canonical);
        AssertFraming(Mutate(canonical, bodyOffset, 2));
        var secondTypeOffset = NextComponentOffset(canonical, bodyOffset);
        AssertFraming(Mutate(canonical, secondTypeOffset, 1));

        var nonMinimal = canonical.ToList();
        var lastLengthByte = 6;
        while ((nonMinimal[lastLengthByte] & 0x80) != 0)
        {
            lastLengthByte++;
        }
        nonMinimal[lastLengthByte] |= 0x80;
        nonMinimal.Insert(lastLengthByte + 1, 0);
        AssertFraming(nonMinimal.ToArray());
    }

    [Fact]
    public void TruncationStructuredMutationsAndDeterministicFuzzFailClosed()
    {
        var canonical = Compose().FilePayload.ToArray();
        for (var length = 0; length < canonical.Length; length++)
        {
            AssertRejected(canonical.AsSpan(0, length).ToArray());
        }

        var offsets = ComponentOffsets(canonical)
            .SelectMany(static component => new[]
            {
                component.TypeOffset,
                component.LengthOffset,
                component.PayloadOffset,
                component.PayloadOffset + component.Length - 1
            })
            .Append(0)
            .Append(4)
            .Append(5)
            .Distinct();
        foreach (var offset in offsets)
        {
            foreach (var mask in new byte[] { 0x01, 0x40, 0x80 })
            {
                var mutated = canonical.ToArray();
                mutated[offset] ^= mask;
                AssertRejected(mutated);
            }
        }

        var random = new Random(0x14c1);
        for (var iteration = 0; iteration < 300; iteration++)
        {
            var malformed = new byte[random.Next(0, 1_024)];
            random.NextBytes(malformed);
            AssertRejected(malformed);
        }
    }

    [Fact]
    public void ExactMaximumFileAndComponentCountAreReachableAndFirstOverBoundsFail()
    {
        var exact = FindExactPayload(
            ProfileCarrierLimits.MaximumFilePayloadBytes,
            bridgeCount: ProfileCarrierLimits.MaximumComponents -
                ProfileCarrierLimits.RequiredNonBridgeComponents,
            contactsPerBridge: 8);
        var document = Compose(exact);
        Assert.Equal(ProfileCarrierLimits.MaximumFilePayloadBytes, document.FilePayload.Length);
        Assert.Equal(ProfileCarrierLimits.MaximumComponents, document.ComponentCount);
        _ = ProfileCarrierVerifier.VerifyExact(
            document.FilePayload.Span,
            ProfileCarrierContractRedTests.Options(),
            SyntheticProfileFixture.Verifier());

        AssertFraming(new byte[ProfileCarrierLimits.MaximumFilePayloadBytes + 1]);
        Assert.Throws<ProfileCarrierException>(() =>
            new ProfileCarrierAssemblyInput(
                new byte[ProfileCarrierLimits.MaximumComponentBytes + 1],
                [],
                new byte[] { 1 },
                [(ReadOnlyMemory<byte>)new byte[] { 1 }]));
    }

    private static ProfileCarrierDocument Compose(SyntheticProfileParts? parts = null) =>
        ProfileCarrierComposer.ComposeExact(
            ProfileCarrierContractRedTests.Input(parts ?? SyntheticProfileFixture.Parts()),
            ProfileCarrierContractRedTests.Options(),
            SyntheticProfileFixture.Verifier());

    private static SyntheticProfileParts FindExactPayload(
        int target,
        int bridgeCount,
        int contactsPerBridge)
    {
        const int minimumContactLength = 32;
        const int maximumContactLength = 500;
        var lengths = Enumerable.Repeat(
            minimumContactLength,
            bridgeCount * contactsPerBridge).ToArray();
        for (var attempt = 0; attempt < 256; attempt++)
        {
            var parts = SyntheticProfileFixture.Parts(
                bridgeCount: bridgeCount,
                contactsPerBridge: contactsPerBridge,
                exactContactLengths: lengths);
            var current = Compose(parts).FilePayload.Length;
            if (current == target)
            {
                return parts;
            }

            var delta = target - current;
            if (delta > 0)
            {
                var index = Array.FindIndex(lengths, value => value < maximumContactLength);
                Assert.True(index >= 0);
                lengths[index] += Math.Min(delta, maximumContactLength - lengths[index]);
            }
            else
            {
                var index = Array.FindLastIndex(lengths, value => value > minimumContactLength);
                Assert.True(index >= 0);
                lengths[index] -= Math.Min(-delta, lengths[index] - minimumContactLength);
            }
        }
        throw new Xunit.Sdk.XunitException($"Exact payload {target} was not reached.");
    }

    private static void AssertFraming(byte[] value)
    {
        var exception = Assert.Throws<ProfileCarrierException>(() =>
            ProfileCarrierVerifier.VerifyExact(
                value,
                ProfileCarrierContractRedTests.Options(),
                SyntheticProfileFixture.Verifier()));
        Assert.Equal(ProfileCarrierError.InvalidFraming, exception.Error);
    }

    private static void AssertRejected(byte[] value) =>
        Assert.Throws<ProfileCarrierException>(() =>
            ProfileCarrierVerifier.VerifyExact(
                value,
                ProfileCarrierContractRedTests.Options(),
                SyntheticProfileFixture.Verifier()));

    private static int BodyOffset(byte[] value)
    {
        var offset = 6;
        _ = ReadVarUInt(value, ref offset);
        return offset;
    }

    private static int NextComponentOffset(byte[] value, int componentOffset)
    {
        var offset = componentOffset + 1;
        var length = ReadVarUInt(value, ref offset);
        return offset + length;
    }

    private static IReadOnlyList<ComponentOffset> ComponentOffsets(byte[] value)
    {
        var offset = 6;
        _ = ReadVarUInt(value, ref offset);
        var result = new List<ComponentOffset>(value[5]);
        for (var index = 0; index < value[5]; index++)
        {
            var typeOffset = offset++;
            var lengthOffset = offset;
            var length = ReadVarUInt(value, ref offset);
            result.Add(new(typeOffset, lengthOffset, offset, length));
            offset += length;
        }
        return result;
    }

    private static int ReadVarUInt(byte[] value, ref int offset)
    {
        var result = 0;
        var shift = 0;
        byte current;
        do
        {
            current = value[offset++];
            result |= (current & 0x7f) << shift;
            shift += 7;
        } while ((current & 0x80) != 0);
        return result;
    }

    private static byte[] Mutate(byte[] source, int offset, byte value)
    {
        var result = source.ToArray();
        result[offset] = value;
        return result;
    }

    private sealed record ComponentOffset(
        int TypeOffset,
        int LengthOffset,
        int PayloadOffset,
        int Length);
}
