using System.Buffers;
using System.Collections;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace Deep.Protocol.ProfileCarrier.Tests;

public sealed class ProfileCarrierCorrectiveBoundaryRedTests
{
    [Fact]
    public void ComposerAndVerifierExposeDifferentLeastPrivilegeResultTypes()
    {
        var compositionType = typeof(ProfileCarrierComposer)
            .GetMethod(nameof(ProfileCarrierComposer.ComposeExact))!
            .ReturnType;
        var verificationType = typeof(ProfileCarrierVerifier)
            .GetMethod(nameof(ProfileCarrierVerifier.VerifyExact))!
            .ReturnType;

        Assert.Equal("ProfileCarrierComposition", compositionType.Name);
        Assert.Equal("ProfileCarrierVerificationResult", verificationType.Name);
        Assert.NotEqual(compositionType, verificationType);

        var verifierProperties = verificationType
            .GetProperties()
            .Select(static property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        Assert.Equal(
            new[]
            {
                "BridgeCount",
                "ComponentCount",
                "FilePayloadSha256",
                "Fingerprint",
                "MaximumProtocol",
                "MinimumProtocol"
            },
            verifierProperties.OrderBy(static value => value, StringComparer.Ordinal));
        Assert.DoesNotContain(verifierProperties, static name =>
            name.Contains("Payload", StringComparison.Ordinal) &&
            !name.Equals("FilePayloadSha256", StringComparison.Ordinal));
        Assert.DoesNotContain(verifierProperties, static name =>
            name.Contains("Canonical", StringComparison.Ordinal) ||
            name.Contains("Signature", StringComparison.Ordinal) ||
            name.Contains("Contact", StringComparison.Ordinal) ||
            name.Contains("Endpoint", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("genesis")]
    [InlineData("delegation")]
    [InlineData("bridge")]
    [InlineData("signer")]
    [InlineData("signature")]
    public void OversizeMemoryIsRejectedBeforeAnyCopy(string target)
    {
        using var poison = new PoisonMemoryManager(
            target switch
            {
                "signer" => MembershipLimits.SignerIdLength + 1,
                "signature" => MembershipLimits.MaximumSignatureLength + 1,
                _ => ProfileCarrierLimits.MaximumComponentBytes + 1
            });
        var parts = SyntheticProfileFixture.Parts();
        var approvals = parts.GenesisApprovals.ToArray();
        var bridges = parts.CanonicalSignedBridges
            .Select(static value => (ReadOnlyMemory<byte>)value)
            .ToArray();
        var genesis = (ReadOnlyMemory<byte>)parts.CanonicalGenesis;
        var delegation = (ReadOnlyMemory<byte>)parts.CanonicalSignedDelegation;

        switch (target)
        {
            case "genesis":
                genesis = poison.Value;
                break;
            case "delegation":
                delegation = poison.Value;
                break;
            case "bridge":
                bridges[0] = poison.Value;
                break;
            case "signer":
                approvals[0] = approvals[0] with { SignerId = poison.Value };
                break;
            case "signature":
                approvals[0] = approvals[0] with { Signature = poison.Value };
                break;
        }

        var exception = Assert.Throws<ProfileCarrierException>(() =>
            new ProfileCarrierAssemblyInput(
                genesis,
                approvals,
                delegation,
                bridges));
        Assert.Equal(ProfileCarrierError.BoundsExceeded, exception.Error);
        Assert.False(poison.Accessed);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void KnownOversizeCollectionCountsAreRejectedWithoutEnumeration()
    {
        var parts = SyntheticProfileFixture.Parts();
        var approvals = new CountedThrowingCollection<MembershipSignature>(
            MembershipLimits.MaximumSigners + 1);
        var bridges = new CountedThrowingCollection<ReadOnlyMemory<byte>>(
            ProfileCarrierLimits.MaximumComponents -
            ProfileCarrierLimits.RequiredNonBridgeComponents + 1);

        AssertBounded(() => new ProfileCarrierAssemblyInput(
            parts.CanonicalGenesis,
            approvals,
            parts.CanonicalSignedDelegation,
            []));
        AssertBounded(() => new ProfileCarrierAssemblyInput(
            parts.CanonicalGenesis,
            parts.GenesisApprovals,
            parts.CanonicalSignedDelegation,
            bridges));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ThrowingExternalEnumerablesMapToOneSanitizedContractError(bool onGetEnumerator)
    {
        var parts = SyntheticProfileFixture.Parts();
        var values = new ThrowingEnumerable<MembershipSignature>(onGetEnumerator);

        var exception = Assert.Throws<ProfileCarrierException>(() =>
            new ProfileCarrierAssemblyInput(
                parts.CanonicalGenesis,
                values,
                parts.CanonicalSignedDelegation,
                parts.CanonicalSignedBridges.Select(static value =>
                    (ReadOnlyMemory<byte>)value)));
        Assert.Equal(ProfileCarrierError.InvalidInput, exception.Error);
        Assert.Null(exception.InnerException);

        var rendered = exception.ToString();
        Assert.Equal("[profile-carrier-error:InvalidInput]", rendered);
        Assert.DoesNotContain("sentinel", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(nameof(ThrowingEnumerable<MembershipSignature>), rendered);
        Assert.DoesNotContain(":\\", rendered, StringComparison.Ordinal);
    }

    private static void AssertBounded(Action action)
    {
        var exception = Assert.Throws<ProfileCarrierException>(action);
        Assert.Equal(ProfileCarrierError.BoundsExceeded, exception.Error);
        Assert.Null(exception.InnerException);
    }

    private sealed class PoisonMemoryManager(int length) : MemoryManager<byte>
    {
        public bool Accessed { get; private set; }

        public ReadOnlyMemory<byte> Value => CreateMemory(length);

        public override Span<byte> GetSpan()
        {
            Accessed = true;
            throw new InvalidOperationException("sentinel memory access");
        }

        public override MemoryHandle Pin(int elementIndex = 0) =>
            throw new NotSupportedException();

        public override void Unpin()
        {
        }

        protected override void Dispose(bool disposing)
        {
        }
    }

    private sealed class CountedThrowingCollection<T>(int count) : ICollection<T>
    {
        public int Count => count;

        public bool IsReadOnly => true;

        public IEnumerator<T> GetEnumerator() =>
            throw new InvalidOperationException("sentinel enumerator access");

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public void Add(T item) => throw new NotSupportedException();

        public void Clear() => throw new NotSupportedException();

        public bool Contains(T item) => false;

        public void CopyTo(T[] array, int arrayIndex) => throw new NotSupportedException();

        public bool Remove(T item) => throw new NotSupportedException();
    }

    private sealed class ThrowingEnumerable<T>(bool onGetEnumerator) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator()
        {
            if (onGetEnumerator)
            {
                throw new InvalidOperationException(@"sentinel C:\private\machine-path");
            }
            return new ThrowingEnumerator<T>();
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class ThrowingEnumerator<T> : IEnumerator<T>
    {
        public T Current => default!;

        object IEnumerator.Current => Current!;

        public bool MoveNext() =>
            throw new InvalidOperationException(@"sentinel C:\private\machine-path");

        public void Reset() => throw new NotSupportedException();

        public void Dispose()
        {
        }
    }
}
