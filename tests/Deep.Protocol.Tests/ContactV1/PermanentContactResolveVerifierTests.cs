using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class PermanentContactResolveVerifierTests
{
    [Fact]
    public void ExactPermanentRead_MintsSealedIdentityAndPublisherClosure()
    {
        var fixture = Fixture.Create();

        var closure = fixture.Verify();

        Assert.Equal(fixture.Contact.Binding.DeepId.CanonicalBytes.ToArray(),
            closure.PermanentDeepId.CanonicalBytes.ToArray());
        Assert.Equal(fixture.Contact.Dcr.CanonicalBytes.ToArray(),
            closure.Contact.ResolverResponse.CanonicalBytes.ToArray());
        Assert.Same(closure.Contact.Authorization, closure.Authorization);
        Assert.Equal(closure.Contact.Bundle.Field(10).ToArray(),
            closure.PublisherDevice.Certificate.DeviceId.ToArray());
        Assert.Equal(0UL, closure.PublicationGeneration);
        Assert.Equal(90UL, closure.PublicationExpiresAtUnixSeconds);
        Assert.Equal(30UL, closure.ServerTimeUnixSeconds);
        Assert.Equal(fixture.Wire.Replicas.Select(static replica => replica.Id),
            closure.ReplicaNodeIds.Select(static id => id.ToArray()));
    }

    [Fact]
    public void OutputOwnsProtectedObjectRouteAndReplicaIdentities()
    {
        var fixture = Fixture.Create();
        var closure = fixture.Verify();

        MemoryMarshal.AsMemory(closure.ExactProtectedDcr1).Span.Fill(0);
        MemoryMarshal.AsMemory(closure.ExactRouteClosure).Span.Fill(0);
        MemoryMarshal.AsMemory(closure.ReplicaNodeIds[0]).Span.Fill(0);

        Assert.NotEqual(new byte[fixture.ProtectedDcr1.Length], closure.ExactProtectedDcr1.ToArray());
        Assert.NotEqual(new byte[closure.ExactRouteClosure.Length], closure.ExactRouteClosure.ToArray());
        Assert.Equal(fixture.Wire.Replicas[0].Id, closure.ReplicaNodeIds[0].ToArray());
    }

    [Fact]
    public void WrongPermanentDidLocatorAndNetworkFailClosed()
    {
        var fixture = Fixture.Create();
        var foreignDid = ContactCodecSecurityTests.CryptoDcrFixture.Create(
            1, networkId: fixture.Network).Binding.DeepId;
        AssertCode("PermanentIdentityMismatch", () => fixture.Verify(did: foreignDid));

        var wrongLocator = Bytes(32, 0xd1);
        var wrongPlacement = fixture.Wire.CreatePlacement(wrongLocator);
        var wrongRequest = fixture.Wire.CreateRequest(
            locatorHash: wrongLocator, issuedAt: 20, expiresAt: 60);
        var wrongResult = fixture.Wire.CreatePermanentResult(
            wrongRequest, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30);
        AssertCode("PermanentLocatorMismatch", () => fixture.Verify(
            request: wrongRequest, result: wrongResult, placement: wrongPlacement));

        var wrongPlacementRequest = fixture.Wire.CreateRequest(
            locatorHash: fixture.Locator, placementHash: Bytes(32, 0xd2),
            issuedAt: 20, expiresAt: 60);
        var wrongPlacementResult = fixture.Wire.CreatePermanentResult(
            wrongPlacementRequest, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30);
        AssertCode("PlacementMismatch", () => fixture.Verify(
            request: wrongPlacementRequest, result: wrongPlacementResult));

        var differentRequest = fixture.Wire.CreateRequest(
            locatorHash: fixture.Locator, requestedGeneration: 1,
            issuedAt: 20, expiresAt: 60);
        var differentResult = fixture.Wire.CreatePermanentResult(
            differentRequest, publicationGeneration: 1, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30);
        AssertCode("RequestCorrelationMismatch", () => fixture.Verify(result: differentResult));

        var foreignContact = ContactCodecSecurityTests.CryptoDcrFixture.Create(
            networkId: Bytes(16, 0xe1));
        AssertCode("NetworkMismatch", () => PermanentContactResolveVerifier.Verify(
            fixture.Did, fixture.Request, fixture.Result, fixture.ProtectedDcr1,
            foreignContact.Freshness, fixture.Placement,
            foreignContact.BootId, foreignContact.CurrentMonotonicSample));
    }

    [Fact]
    public void StaleDirectoryPlacementRequestAndPublicationTimesFailClosed()
    {
        var fixture = Fixture.Create();
        AssertCode("DirectoryFreshnessExpired", () => fixture.Verify(
            bootId: Bytes(16, 0xf1)));

        fixture.Wire.Time.Advance(TimeSpan.FromMinutes(2));
        AssertCode("PlacementNotCurrent", () => fixture.Verify());

        fixture = Fixture.Create();
        var staleResult = fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 28);
        AssertCode("PermanentReadTimeInvalid", () => fixture.Verify(result: staleResult));

        var expiredPublication = fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 0, publicationExpiresAt: 30,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 29);
        AssertCode("PermanentReadTimeInvalid", () => fixture.Verify(result: expiredPublication));

        var lateRequest = fixture.Wire.CreateRequest(
            locatorHash: fixture.Locator, issuedAt: 31, expiresAt: 60);
        var lateResult = fixture.Wire.CreatePermanentResult(
            lateRequest, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30);
        AssertCode("PermanentReadTimeInvalid", () => fixture.Verify(
            request: lateRequest, result: lateResult));
    }

    [Fact]
    public void ReplayForkGenerationAndProtectedObjectSubstitutionFailClosed()
    {
        var fixture = Fixture.Create();
        var requested = fixture.Wire.CreateRequest(
            locatorHash: fixture.Locator, requestedGeneration: 2,
            issuedAt: 20, expiresAt: 60);
        var wrongGeneration = fixture.Wire.CreatePermanentResult(
            requested, publicationGeneration: 1, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30);
        AssertCode("PublicationGenerationMismatch", () => fixture.Verify(
            request: requested, result: wrongGeneration));

        var bundleGenerationMismatch = fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 1, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30);
        AssertCode("PublicationGenerationMismatch", () => fixture.Verify(
            result: bundleGenerationMismatch));

        var substituted = fixture.ProtectedDcr1.ToArray();
        substituted[^1] ^= 1;
        AssertCode("ProtectedObjectMismatch", () => fixture.Verify(
            protectedDcr1: substituted));

        var signedSubstitution = fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: substituted, serverTime: 30);
        AssertCode("PermanentResolveRejected", () => fixture.Verify(
            result: signedSubstitution, protectedDcr1: substituted));
    }

    [Fact]
    public void EveryPermanentReceiptTupleFieldIsCryptographicallyBound()
    {
        var fixture = Fixture.Create();
        var signed = fixture.Tuple();

        AssertSignatureRejected(fixture, fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 1, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30, signedTuple: signed));
        AssertSignatureRejected(fixture, fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 0, publicationExpiresAt: 91,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30, signedTuple: signed));
        AssertSignatureRejected(fixture, fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1.Concat(new byte[] { 1 }).ToArray(),
            serverTime: 30, signedTuple: signed));
        AssertSignatureRejected(fixture, fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, routeClosure: RouteClosure(maximum: true),
            serverTime: 30, signedTuple: signed));
        AssertSignatureRejected(fixture, fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30,
            signedTuple: signed with { ServerTime = 29 }));

        var otherOperation = fixture.Wire.CreateRequest(
            locatorHash: fixture.Locator, requestedGeneration: 1,
            issuedAt: 20, expiresAt: 60);
        AssertSignatureRejected(fixture, fixture.Wire.CreatePermanentResult(
            otherOperation, publicationGeneration: 1, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30,
            signedTuple: signed), otherOperation);
    }

    [Fact]
    public void ReplicaSubstitutionDuplicateDomainAndSignatureTamperingFailClosed()
    {
        var fixture = Fixture.Create();
        var outsider = Xis1InviteClaimReceiptVerifierTests.Replica.Create(0x71, 0x72, 0x73);
        var substituted = fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30,
            receiptReplicas: [fixture.Wire.Replicas[0], outsider]);
        AssertCode("ReplicaSetMismatch", () => fixture.Verify(result: substituted));

        var receipts = fixture.Result.Field(22).ToArray();
        receipts[^1] ^= 1;
        var tampered = fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30,
            receiptBytes: receipts);
        AssertCode("InvalidReplicaSignature", () => fixture.Verify(result: tampered));

        var duplicateWire = Xis1InviteClaimReceiptVerifierTests.Fixture.Create(
            fixture.Network, 90, duplicateFailureDomain: true);
        var duplicatePlacement = duplicateWire.CreatePlacement(fixture.Locator);
        var duplicateRequest = duplicateWire.CreateRequest(
            locatorHash: fixture.Locator, issuedAt: 20, expiresAt: 60);
        var duplicateResult = duplicateWire.CreatePermanentResult(
            duplicateRequest, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30);
        AssertCode("ReplicaDiversityInvalid", () => fixture.Verify(
            request: duplicateRequest, result: duplicateResult, placement: duplicatePlacement));

        var wrongKeyWire = Xis1InviteClaimReceiptVerifierTests.Fixture.Create(
            fixture.Network, 90, useWrongXndIdentityKey: true);
        var wrongKeyPlacement = wrongKeyWire.CreatePlacement(fixture.Locator);
        var wrongKeyRequest = wrongKeyWire.CreateRequest(
            locatorHash: fixture.Locator, issuedAt: 20, expiresAt: 60);
        var wrongKeyResult = wrongKeyWire.CreatePermanentResult(
            wrongKeyRequest, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30);
        AssertCode("InvalidReplicaSignature", () => fixture.Verify(
            request: wrongKeyRequest, result: wrongKeyResult, placement: wrongKeyPlacement));
    }

    [Fact]
    public void OneTimeReceiptAndUnverifiedDeviceCannotEnterPermanentPath()
    {
        var fixture = Fixture.Create();
        var oneTime = fixture.Wire.CreateResult(
            fixture.Request, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: fixture.ProtectedDcr1, serverTime: 30);
        AssertCode("NotPermanentRead", () => fixture.Verify(result: oneTime));

        var invalidDcr = fixture.Contact.DcrWithUnverifiedDpd();
        byte[] protectedInvalid;
        using (var resolution = PermanentContactResolutionDerivation.Derive(
            fixture.Network, fixture.Did))
            protectedInvalid = Dcr1ObjectProtectionCodec.SealPermanent(
                invalidDcr, fixture.Network, fixture.Did, resolution);
        var invalidResult = fixture.Wire.CreatePermanentResult(
            fixture.Request, publicationGeneration: 0, publicationExpiresAt: 90,
            objectCiphertext: protectedInvalid, serverTime: 30);
        AssertCode("PermanentResolveRejected", () => fixture.Verify(
            result: invalidResult, protectedDcr1: protectedInvalid));
    }

    [Fact]
    public void PublicSurfaceHasOneNarrowProducerAndNoForgeableCapabilityPath()
    {
        Assert.Empty(typeof(VerifiedPermanentContactResolveClosure).GetConstructors());
        Assert.Empty(typeof(PermanentContactResolveException).GetConstructors());
        var method = Assert.Single(typeof(PermanentContactResolveVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal(nameof(PermanentContactResolveVerifier.Verify), method.Name);
        Assert.Equal(
            [typeof(ParsedDid1), typeof(Xiq1Request), typeof(Xis1Result),
             typeof(ReadOnlyMemory<byte>), typeof(Deep.Protocol.AccountDirectoryV1.VerifiedAccountDirectoryFreshness),
             typeof(VerifiedContactServicePlacement), typeof(ReadOnlySpan<byte>), typeof(ulong)],
            method.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.DoesNotContain(method.GetParameters(), static parameter =>
            parameter.ParameterType == typeof(bool) ||
            parameter.ParameterType == typeof(VerifiedDevice) ||
            parameter.ParameterType == typeof(VerifiedXis1InviteClaimReceipt) ||
            parameter.Name?.Contains("key", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("replica", StringComparison.OrdinalIgnoreCase) == true);
    }

    private static void AssertSignatureRejected(
        Fixture fixture,
        Xis1Result result,
        Xiq1Request? request = null) =>
        AssertCode("InvalidReplicaSignature", () => fixture.Verify(
            request: request, result: result,
            protectedDcr1: result.Field(19).ToArray()));

    private static void AssertCode(string code, Action action) =>
        Assert.Equal(code, Assert.Throws<PermanentContactResolveException>(action).Code);

    private sealed class Fixture
    {
        private Fixture() { }

        internal ContactCodecSecurityTests.CryptoDcrFixture Contact { get; private set; } = null!;
        internal Xis1InviteClaimReceiptVerifierTests.Fixture Wire { get; private set; } = null!;
        internal ParsedDid1 Did => Contact.Binding.DeepId;
        internal byte[] Network => Contact.Dcr.Field(1).ToArray();
        internal byte[] Locator { get; private set; } = null!;
        internal byte[] ProtectedDcr1 { get; private set; } = null!;
        internal VerifiedContactServicePlacement Placement { get; private set; } = null!;
        internal Xiq1Request Request { get; private set; } = null!;
        internal Xis1Result Result { get; private set; } = null!;

        internal static Fixture Create()
        {
            var value = new Fixture
            {
                Contact = ContactCodecSecurityTests.CryptoDcrFixture.Create(
                    networkId: ContactCodecTests.Records.RouteClosure.Xrr.Field(1).ToArray()),
            };
            using (var resolution = PermanentContactResolutionDerivation.Derive(
                value.Network, value.Did))
            {
                value.Locator = resolution.LocatorHash.ToArray();
                value.ProtectedDcr1 = Dcr1ObjectProtectionCodec.SealPermanent(
                    value.Contact.Dcr, value.Network, value.Did, resolution);
            }
            value.Wire = Xis1InviteClaimReceiptVerifierTests.Fixture.Create(
                value.Network, placementValidUntil: 90);
            value.Placement = value.Wire.CreatePlacement(value.Locator);
            value.Request = value.Wire.CreateRequest(
                locatorHash: value.Locator, issuedAt: 20, expiresAt: 60);
            value.Result = value.Wire.CreatePermanentResult(
                value.Request, publicationGeneration: 0, publicationExpiresAt: 90,
                objectCiphertext: value.ProtectedDcr1, serverTime: 30);
            return value;
        }

        internal Xis1InviteClaimReceiptVerifierTests.PermanentReadTuple Tuple() => new(
            Request.RequestHash.ToArray(), Request.LocatorHash.ToArray(), 0, 90,
            SHA256.HashData(ProtectedDcr1), SHA256.HashData(RouteClosure()), 30);

        internal VerifiedPermanentContactResolveClosure Verify(
            ParsedDid1? did = null,
            Xiq1Request? request = null,
            Xis1Result? result = null,
            byte[]? protectedDcr1 = null,
            VerifiedContactServicePlacement? placement = null,
            byte[]? bootId = null) =>
            PermanentContactResolveVerifier.Verify(
                did ?? Did, request ?? Request, result ?? Result,
                protectedDcr1 ?? ProtectedDcr1, Contact.Freshness,
                placement ?? Placement, bootId ?? Contact.BootId,
                Contact.CurrentMonotonicSample);
    }

    private static byte[] RouteClosure(bool maximum = false)
    {
        var fixture = maximum
            ? ContactCodecTests.Records.MaximumRouteClosure
            : ContactCodecTests.Records.RouteClosure;
        var records = new[] { fixture.Xrr, fixture.Xra, fixture.Xrc, fixture.Xss, fixture.Pmt, fixture.Pms };
        var output = new byte[1 + records.Sum(static record => 4 + record.CanonicalBytes.Length)];
        output[0] = 6;
        var offset = 1;
        foreach (var record in records)
        {
            BinaryPrimitives.WriteUInt32BigEndian(
                output.AsSpan(offset), checked((uint)record.CanonicalBytes.Length));
            offset += 4;
            record.CanonicalBytes.Span.CopyTo(output.AsSpan(offset));
            offset += record.CanonicalBytes.Length;
        }
        return output;
    }

    private static byte[] Bytes(int length, byte seed) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index))).ToArray();
}
