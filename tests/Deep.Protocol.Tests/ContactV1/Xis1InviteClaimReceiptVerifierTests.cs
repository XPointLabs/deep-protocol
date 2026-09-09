using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class Xis1InviteClaimReceiptVerifierTests
{
    internal static VerifiedXis1InviteClaimReceipt CreateVerifiedOneTimeClaim(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> objectCiphertext,
        ulong serverTimeUnixSeconds = 30)
    {
        var fixture = Fixture.Create(networkId.ToArray(), placementValidUntil: 90);
        var request = fixture.CreateRequest(issuedAt: 20, expiresAt: 60);
        var result = fixture.CreateResult(
            request, publicationExpiresAt: 90, objectCiphertext: objectCiphertext.ToArray(),
            serverTime: serverTimeUnixSeconds);
        return Xis1InviteClaimReceiptVerifier.Verify(request, result, fixture.Placement);
    }

    [Fact]
    public void ValidClaim_MintsNonForgeableDefensiveCapability()
    {
        var fixture = Fixture.Create();
        var request = fixture.CreateRequest();
        var result = fixture.CreateResult(request);

        var capability = Xis1InviteClaimReceiptVerifier.Verify(request, result, fixture.Placement);

        Assert.Empty(typeof(VerifiedXis1InviteClaimReceipt).GetConstructors());
        var verify = Assert.Single(typeof(Xis1InviteClaimReceiptVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal(
            [typeof(Xiq1Request), typeof(Xis1Result), typeof(VerifiedContactServicePlacement)],
            verify.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.DoesNotContain(verify.GetParameters(), static parameter =>
            parameter.Name?.Contains("key", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("replica", StringComparison.OrdinalIgnoreCase) == true);

        Assert.Equal(request.RequestHash.ToArray(), capability.RequestHash.ToArray());
        Assert.Equal(fixture.LocatorHash, capability.LocatorHash.ToArray());
        Assert.Equal(7UL, capability.PublicationGeneration);
        Assert.Equal(9UL, capability.ClaimCommitGeneration);
        Assert.Equal(220UL, capability.ServerTimeUnixSeconds);
        Assert.Equal(fixture.Replicas.Select(static replica => replica.Id),
            capability.ReplicaNodeIds.Select(static value => value.ToArray()));

        var objectCopy = capability.ObjectCiphertext;
        MemoryMarshal.AsMemory(objectCopy).Span.Fill(0);
        var routeCopy = capability.ExactRouteClosure;
        MemoryMarshal.AsMemory(routeCopy).Span.Fill(0);
        var replicasCopy = capability.ReplicaNodeIds;
        MemoryMarshal.AsMemory(replicasCopy[0]).Span.Fill(0);
        Assert.NotEqual(new byte[capability.ObjectCiphertext.Length], capability.ObjectCiphertext.ToArray());
        Assert.NotEqual(new byte[capability.ExactRouteClosure.Length], capability.ExactRouteClosure.ToArray());
        Assert.Equal(fixture.Replicas[0].Id, capability.ReplicaNodeIds[0].ToArray());
    }

    [Fact]
    public void PermanentNonConsumingSuccess_IsRejected()
    {
        var fixture = Fixture.Create();
        var request = fixture.CreateRequest();
        var result = fixture.CreatePermanentResult(request);

        AssertCode("NotOneTimeClaim", () =>
            Xis1InviteClaimReceiptVerifier.Verify(request, result, fixture.Placement));
    }

    [Fact]
    public void CrossPlacementAndNodeSubstitution_AreRejected()
    {
        var fixture = Fixture.Create();
        var wrongPlacementRequest = fixture.CreateRequest(placementHash: Bytes(32, 0xd1));
        var wrongPlacementResult = fixture.CreateResult(wrongPlacementRequest);
        AssertCode("PlacementMismatch", () =>
            Xis1InviteClaimReceiptVerifier.Verify(wrongPlacementRequest, wrongPlacementResult, fixture.Placement));

        var request = fixture.CreateRequest();
        var outsider = Replica.Create(0x71, 0x72, 0x73);
        var substituted = fixture.CreateResult(request, receiptReplicas: [fixture.Replicas[0], outsider]);
        AssertCode("ReplicaSetMismatch", () =>
            Xis1InviteClaimReceiptVerifier.Verify(request, substituted, fixture.Placement));
    }

    [Fact]
    public void WrongVerifiedXndIdentityKey_IsRejected()
    {
        var fixture = Fixture.Create(useWrongXndIdentityKey: true);
        var request = fixture.CreateRequest();
        var result = fixture.CreateResult(request);

        AssertCode("InvalidReplicaSignature", () =>
            Xis1InviteClaimReceiptVerifier.Verify(request, result, fixture.Placement));
    }

    [Fact]
    public void DuplicateFailureDomain_IsRejected()
    {
        var fixture = Fixture.Create(duplicateFailureDomain: true);
        var request = fixture.CreateRequest();
        var result = fixture.CreateResult(request);

        AssertCode("ReplicaDiversityInvalid", () =>
            Xis1InviteClaimReceiptVerifier.Verify(request, result, fixture.Placement));
    }

    [Fact]
    public void NonCanonicalOrDuplicateReceiptRows_AreRejectedByDecoder()
    {
        var fixture = Fixture.Create();
        var request = fixture.CreateRequest();
        var canonical = fixture.CreateReceiptContainer(fixture.BaseTuple(request), fixture.Replicas);

        var reversed = canonical.ToArray();
        reversed.AsSpan(1, 96).CopyTo(reversed.AsSpan(97, 96));
        canonical.AsSpan(97, 96).CopyTo(reversed.AsSpan(1, 96));
        Assert.Equal("InvalidReplicaReceipts", Assert.Throws<ContactFormatException>(() =>
            fixture.CreateResult(request, receiptBytes: reversed)).Code);

        var duplicate = canonical.ToArray();
        duplicate.AsSpan(1, 96).CopyTo(duplicate.AsSpan(97, 96));
        Assert.Equal("InvalidReplicaReceipts", Assert.Throws<ContactFormatException>(() =>
            fixture.CreateResult(request, receiptBytes: duplicate)).Code);
    }

    [Fact]
    public void EveryReceiptTupleField_IsCryptographicallyBound()
    {
        var fixture = Fixture.Create();
        var request = fixture.CreateRequest();
        var signed = fixture.BaseTuple(request);

        var differentRequest = fixture.CreateRequest(requestedGeneration: 7);
        AssertCode("InvalidReplicaSignature", () => Xis1InviteClaimReceiptVerifier.Verify(
            differentRequest,
            fixture.CreateResult(differentRequest, signedTuple: signed),
            fixture.Placement));

        var otherLocator = Bytes(32, 0xd2);
        var otherPlacement = fixture.CreatePlacement(otherLocator);
        var locatorRequest = fixture.CreateRequest(locatorHash: otherLocator);
        AssertCode("InvalidReplicaSignature", () => Xis1InviteClaimReceiptVerifier.Verify(
            locatorRequest,
            fixture.CreateResult(locatorRequest, signedTuple: signed),
            otherPlacement));

        AssertTupleSignatureRejected(fixture, request, fixture.CreateResult(
            request, publicationGeneration: 8, signedTuple: signed));
        AssertTupleSignatureRejected(fixture, request, fixture.CreateResult(
            request, publicationExpiresAt: 299, signedTuple: signed));
        AssertTupleSignatureRejected(fixture, request, fixture.CreateResult(
            request, objectCiphertext: Bytes(41, 0xd3), signedTuple: signed));
        AssertTupleSignatureRejected(fixture, request, fixture.CreateResult(
            request, routeClosure: RouteClosure(maximum: true), signedTuple: signed));
        AssertTupleSignatureRejected(fixture, request, fixture.CreateResult(
            request, claimCommitGeneration: 10, signedTuple: signed));
        AssertTupleSignatureRejected(fixture, request, fixture.CreateResult(
            request, serverTime: 221, signedTuple: signed));
    }

    [Fact]
    public void StalePlacementAndInvalidSignedTime_AreRejected()
    {
        var fixture = Fixture.Create();
        var request = fixture.CreateRequest();
        var result = fixture.CreateResult(request);
        fixture.Time.Advance(TimeSpan.FromMinutes(2));
        AssertCode("PlacementNotCurrent", () =>
            Xis1InviteClaimReceiptVerifier.Verify(request, result, fixture.Placement));

        fixture = Fixture.Create();
        request = fixture.CreateRequest();
        result = fixture.CreateResult(request, serverTime: request.ExpiresAtUnixSeconds);
        AssertCode("ClaimTimeInvalid", () =>
            Xis1InviteClaimReceiptVerifier.Verify(request, result, fixture.Placement));
    }

    [Fact]
    public void RequestedGenerationAndClaimGeneration_AreClosed()
    {
        var fixture = Fixture.Create();
        var request = fixture.CreateRequest(requestedGeneration: 6);
        var result = fixture.CreateResult(request);
        AssertCode("ClaimGenerationMismatch", () =>
            Xis1InviteClaimReceiptVerifier.Verify(request, result, fixture.Placement));

        request = fixture.CreateRequest();
        result = fixture.CreateResult(request, claimCommitGeneration: 0);
        AssertCode("ClaimGenerationMismatch", () =>
            Xis1InviteClaimReceiptVerifier.Verify(request, result, fixture.Placement));
    }

    [Fact]
    public void PayloadHashMismatch_IsRejectedByDecoder()
    {
        var fixture = Fixture.Create();
        var request = fixture.CreateRequest();
        var cipher = Bytes(40, 0x81);
        var route = RouteClosure();
        var receipts = fixture.CreateReceiptContainer(fixture.BaseTuple(request), fixture.Replicas);

        var objectError = Assert.Throws<ContactFormatException>(() => Xis1Codec.Encode(
            request.CanonicalBytes.Span, Xis1Status.Success, ContactServiceMutationOutcome.DurablyCommitted,
            220, 0, ContactServicePaddingClass.Bytes16384,
            [U64(7), U64(300), Bytes(32, 0xe1), cipher, SHA256.HashData(route), route, U64(9), receipts]));
        Assert.Equal("ObjectCiphertextHashMismatch", objectError.Code);

        var routeError = Assert.Throws<ContactFormatException>(() => Xis1Codec.Encode(
            request.CanonicalBytes.Span, Xis1Status.Success, ContactServiceMutationOutcome.DurablyCommitted,
            220, 0, ContactServicePaddingClass.Bytes16384,
            [U64(7), U64(300), SHA256.HashData(cipher), cipher, Bytes(32, 0xe2), route, U64(9), receipts]));
        Assert.Equal("RouteClosureHashMismatch", routeError.Code);
    }

    private static void AssertTupleSignatureRejected(Fixture fixture, Xiq1Request request, Xis1Result result) =>
        AssertCode("InvalidReplicaSignature", () =>
            Xis1InviteClaimReceiptVerifier.Verify(request, result, fixture.Placement));

    private static void AssertCode(string code, Action action)
    {
        var error = Assert.Throws<Xis1InviteClaimReceiptException>(action);
        Assert.Equal(code, error.Code);
    }

    internal sealed class Fixture
    {
        private Fixture() { }

        internal byte[] NetworkId { get; private set; } =
            ContactCodecTests.Records.RouteClosure.Xrr.Field(1).ToArray();
        internal byte[] OperationId { get; } = Bytes(32, 0x21);
        internal byte[] ViewHash { get; } = Bytes(32, 0x22);
        internal byte[] PlacementHash { get; } = Bytes(32, 0x23);
        internal byte[] LocatorHash { get; } = Bytes(32, 0x24);
        internal MutableTimeProvider Time { get; } = new();
        internal Replica[] Replicas { get; private set; } = null!;
        internal VerifiedOnionNetworkContext Network { get; private set; } = null!;
        internal VerifiedContactServicePlacement Placement { get; private set; } = null!;
        internal ulong PlacementValidUntil { get; private set; } = 300;

        internal static Fixture Create(bool useWrongXndIdentityKey = false, bool duplicateFailureDomain = false) =>
            Create(null, 300, useWrongXndIdentityKey, duplicateFailureDomain);

        internal static Fixture Create(
            byte[]? networkId,
            ulong placementValidUntil,
            bool useWrongXndIdentityKey = false,
            bool duplicateFailureDomain = false)
        {
            var fixture = new Fixture();
            if (networkId is not null) fixture.NetworkId = networkId.ToArray();
            fixture.PlacementValidUntil = placementValidUntil;
            fixture.Replicas =
            [
                Replica.Create(0x31, 0x41, 0x51),
                Replica.Create(0x61, 0x71, duplicateFailureDomain ? (byte)0x51 : (byte)0x81),
            ];
            var nodes = fixture.Replicas.Select((replica, index) =>
            {
                var identity = useWrongXndIdentityKey && index == 0
                    ? PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xf1)).PublicKey
                    : replica.Key.PublicKey;
                return new VerifiedNetworkNode(
                    replica.Id, replica.Id, Bytes(32, checked((byte)(0x91 + index))),
                    replica.FailureDomain, Bytes(32, checked((byte)(0xa1 + index))), 1, 4,
                    [127, 0, 0, checked((byte)(1 + index))], 443,
                    Bytes(32, checked((byte)(0xb1 + index))), 0x0004, 0, 0, 1_000, 1,
                    Bytes(32, checked((byte)(0xc1 + index))), Bytes(32, checked((byte)(0xd1 + index))),
                    identity);
            }).ToArray();
            var lease = new OnionTrustedTimeLease(
                fixture.Time, TimeSpan.FromMinutes(1), Bytes(32, 0xe1));
            fixture.Network = new VerifiedOnionNetworkContext(fixture.NetworkId, lease, nodes);
            fixture.Placement = fixture.CreatePlacement(fixture.LocatorHash);
            return fixture;
        }

        internal VerifiedContactServicePlacement CreatePlacement(byte[] locatorHash) =>
            new(Network, ContactServiceRequestKind.ResolveInvite, ContactServiceClass.InviteResolver,
                ViewHash, PlacementHash, locatorHash, 7, PlacementValidUntil, Replicas.Select(static replica => replica.Id));

        internal Xiq1Request CreateRequest(
            byte[]? locatorHash = null,
            byte[]? placementHash = null,
            ulong requestedGeneration = 0,
            ulong issuedAt = 200,
            ulong expiresAt = 250) =>
            Xiq1Codec.Decode(Xiq1Codec.Encode(
                NetworkId, OperationId, ViewHash, placementHash ?? PlacementHash,
                issuedAt, expiresAt, locatorHash ?? LocatorHash, requestedGeneration,
                Xiq1AntiSpamTokenType.None, [], ContactServicePaddingClass.Bytes16384));

        internal Xis1Result CreatePermanentResult(
            Xiq1Request request,
            ulong publicationGeneration = 7,
            ulong publicationExpiresAt = 300,
            byte[]? objectCiphertext = null,
            byte[]? routeClosure = null,
            ulong serverTime = 220,
            PermanentReadTuple? signedTuple = null,
            IReadOnlyList<Replica>? receiptReplicas = null,
            byte[]? receiptBytes = null)
        {
            var cipher = objectCiphertext ?? Bytes(40, 0x81);
            var route = routeClosure ?? RouteClosure();
            var tuple = new PermanentReadTuple(
                request.RequestHash.ToArray(), request.LocatorHash.ToArray(), publicationGeneration,
                publicationExpiresAt, SHA256.HashData(cipher), SHA256.HashData(route), serverTime);
            return Xis1Codec.Decode(Xis1Codec.Encode(
                request.CanonicalBytes.Span, Xis1Status.Success, ContactServiceMutationOutcome.None,
                serverTime, 0, route.Length > 16_000
                    ? ContactServicePaddingClass.Bytes131072
                    : ContactServicePaddingClass.Bytes16384,
                [U64(publicationGeneration), U64(publicationExpiresAt), SHA256.HashData(cipher), cipher,
                 SHA256.HashData(route), route, receiptBytes ?? CreatePermanentReceiptContainer(
                     signedTuple ?? tuple, receiptReplicas ?? Replicas)]),
                request.CanonicalBytes.Span);
        }

        internal byte[] CreatePermanentReceiptContainer(
            PermanentReadTuple tuple,
            IReadOnlyList<Replica> replicas)
        {
            var transcript = tuple.Encode();
            var signingInput = ContactCodec.SignatureInput(
                "Deep/ContactResolver/V1/permanent-read-result", transcript);
            try
            {
                var rows = replicas
                    .Select(replica => (replica.Id, Signature: PublicKeyAuth.SignDetached(signingInput, replica.Key.PrivateKey)))
                    .OrderBy(static row => row.Id, ByteArrayComparer.Instance)
                    .Select(static row => Join(row.Id, row.Signature))
                    .ToArray();
                return Join([[2], .. rows]);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(transcript);
                CryptographicOperations.ZeroMemory(signingInput);
            }
        }

        internal ClaimTuple BaseTuple(Xiq1Request request)
        {
            var cipher = Bytes(40, 0x81);
            var route = RouteClosure();
            return new ClaimTuple(
                request.RequestHash.ToArray(), request.LocatorHash.ToArray(), 7, 300,
                SHA256.HashData(cipher), SHA256.HashData(route), 9, 220);
        }

        internal Xis1Result CreateResult(
            Xiq1Request request,
            ulong publicationGeneration = 7,
            ulong publicationExpiresAt = 300,
            byte[]? objectCiphertext = null,
            byte[]? routeClosure = null,
            ulong claimCommitGeneration = 9,
            ulong serverTime = 220,
            ClaimTuple? signedTuple = null,
            IReadOnlyList<Replica>? receiptReplicas = null,
            byte[]? receiptBytes = null)
        {
            objectCiphertext ??= Bytes(40, 0x81);
            routeClosure ??= RouteClosure();
            var objectHash = SHA256.HashData(objectCiphertext);
            var routeHash = SHA256.HashData(routeClosure);
            var tuple = new ClaimTuple(
                request.RequestHash.ToArray(), request.LocatorHash.ToArray(), publicationGeneration,
                publicationExpiresAt, objectHash, routeHash, claimCommitGeneration, serverTime);
            var receipts = receiptBytes ?? CreateReceiptContainer(
                signedTuple ?? tuple, receiptReplicas ?? Replicas);
            var padding = routeClosure.Length > 16_000
                ? ContactServicePaddingClass.Bytes131072
                : ContactServicePaddingClass.Bytes16384;
            var exact = Xis1Codec.Encode(
                request.CanonicalBytes.Span, Xis1Status.Success, ContactServiceMutationOutcome.DurablyCommitted,
                serverTime, 0, padding,
                [U64(publicationGeneration), U64(publicationExpiresAt), objectHash, objectCiphertext,
                 routeHash, routeClosure, U64(claimCommitGeneration), receipts]);
            return Xis1Codec.Decode(exact, request.CanonicalBytes.Span);
        }

        internal byte[] CreateReceiptContainer(ClaimTuple tuple, IReadOnlyList<Replica> replicas)
        {
            var transcript = tuple.Encode();
            var signingInput = ContactCodec.SignatureInput(
                "Deep/ContactResolver/V1/invite-claim-commit", transcript);
            try
            {
                var rows = replicas
                    .Select(replica => (replica.Id, Signature: PublicKeyAuth.SignDetached(signingInput, replica.Key.PrivateKey)))
                    .OrderBy(static row => row.Id, ByteArrayComparer.Instance)
                    .Select(static row => Join(row.Id, row.Signature))
                    .ToArray();
                return Join([[2], .. rows]);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(transcript);
                CryptographicOperations.ZeroMemory(signingInput);
            }
        }
    }

    internal sealed record Replica(byte[] Id, KeyPair Key, byte[] FailureDomain)
    {
        internal static Replica Create(byte idSeed, byte keySeed, byte failureSeed) =>
            new(Bytes(32, idSeed), PublicKeyAuth.GenerateKeyPair(Bytes(32, keySeed)), Bytes(32, failureSeed));
    }

    internal sealed record ClaimTuple(
        byte[] RequestHash,
        byte[] LocatorHash,
        ulong PublicationGeneration,
        ulong PublicationExpiresAt,
        byte[] ObjectCiphertextHash,
        byte[] RouteClosureHash,
        ulong ClaimCommitGeneration,
        ulong ServerTime)
    {
        internal byte[] Encode()
        {
            var output = new byte[160];
            RequestHash.CopyTo(output, 0);
            LocatorHash.CopyTo(output, 32);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(64), PublicationGeneration);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(72), PublicationExpiresAt);
            ObjectCiphertextHash.CopyTo(output, 80);
            RouteClosureHash.CopyTo(output, 112);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(144), ClaimCommitGeneration);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(152), ServerTime);
            return output;
        }
    }

    internal sealed record PermanentReadTuple(
        byte[] RequestHash,
        byte[] LocatorHash,
        ulong PublicationGeneration,
        ulong PublicationExpiresAt,
        byte[] ObjectCiphertextHash,
        byte[] RouteClosureHash,
        ulong ServerTime)
    {
        internal byte[] Encode()
        {
            var output = new byte[152];
            RequestHash.CopyTo(output, 0);
            LocatorHash.CopyTo(output, 32);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(64), PublicationGeneration);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(72), PublicationExpiresAt);
            ObjectCiphertextHash.CopyTo(output, 80);
            RouteClosureHash.CopyTo(output, 112);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(144), ServerTime);
            return output;
        }
    }

    internal sealed class MutableTimeProvider : TimeProvider
    {
        private long _timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _timestamp;
        internal void Advance(TimeSpan duration) => _timestamp = checked(_timestamp + duration.Ticks);
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
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

    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private static byte[] Bytes(int length, byte seed)
    {
        var output = new byte[length];
        for (var index = 0; index < length; index++) output[index] = checked((byte)(seed + (index % 13)));
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }
}
