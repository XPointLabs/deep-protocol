using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Tests.ContactV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2ContactRouteRecoveryWireCodecTests
{
    [Theory]
    [InlineData(1, 0)]
    [InlineData(1, 2)]
    [InlineData(2, 1)]
    [InlineData(2, 3)]
    public void FlatModesRoundTripExactPublicCandidates(int mode, int count)
    {
        var (ordinary, response) = Ordinary();
        var pair = new DeepIdV2ContactRouteRecordedPair(ContactRouteAuthorityWireCodec.EncodeRequest(ordinary),
            ContactRouteAuthorityWireCodec.EncodeResponse(ordinary, response));
        var request = Envelope((DeepIdV2ContactRouteRecoveryMode)mode, ordinary, Enumerable.Repeat(pair, count).ToArray());
        var exact = DeepIdV2ContactRouteRecoveryWireCodec.EncodeRequest(request);
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(exact));
        Assert.Equal(mode, exact[2]); Assert.Equal(0, exact[3]);
        Assert.Equal(exact.Length, checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(4))));
        Assert.Equal(request.NetworkId.ToArray(), exact.AsSpan(8, 16).ToArray());
        Assert.Equal(request.RequestNonce.ToArray(), exact.AsSpan(24, 32).ToArray());
        Assert.Equal(request.ViewHash.ToArray(), exact.AsSpan(128, 32).ToArray());
        var baseLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(176)));
        Assert.Equal(request.ExactBaseRequest.Length, baseLength);
        Assert.Equal(count, exact[180 + baseLength]);
        Assert.Equal(new byte[3], exact.AsSpan(181 + baseLength, 3).ToArray());
        var copied = DeepIdV2ContactRouteRecoveryWireCodec.DecodeRequest(exact);
        exact.AsSpan().Clear();
        Assert.Equal(request.CanonicalBytes.ToArray(), copied.CanonicalBytes.ToArray());
        Assert.Equal(count, copied.History.Count);
        var encodedResponse = DeepIdV2ContactRouteRecoveryWireCodec.EncodeResponse(request, response);
        Assert.Equal(SHA256.HashData(request.ExactBaseRequest.Span), encodedResponse.AsSpan(56, 32).ToArray());
        var decodedResponse = DeepIdV2ContactRouteRecoveryWireCodec.DecodeResponse(request, encodedResponse);
        Assert.Equal(response.ExactIssuanceAdh1.ToArray(), decodedResponse.ExactIssuanceAdh1.ToArray());
        Assert.Equal(ContactRouteAuthorityWireCodec.EncodeResponse(ordinary, response),
            ContactRouteAuthorityWireCodec.EncodeResponse(ordinary, decodedResponse));
        // Repeated pairs are untrusted codec candidates. Only the historical
        // verifier can authenticate their order, uniqueness and actual anchor.
        Assert.Empty(typeof(VerifiedDeepIdV2ContactRouteRecordedHistory).GetConstructors());
        Assert.DoesNotContain(typeof(VerifiedDeepIdV2ContactRouteRecordedHistory).GetMethods(),
            value => value.Name is "EnsureCurrentAsync" or "DispatchAsync" or "SignAsync");
    }

    [Fact]
    public void SignatureCommitsFinalTotalAndEveryUnsignedByte()
    {
        var (ordinary, response) = Ordinary();
        var pair = new DeepIdV2ContactRouteRecordedPair(ContactRouteAuthorityWireCodec.EncodeRequest(ordinary),
            ContactRouteAuthorityWireCodec.EncodeResponse(ordinary, response));
        var request = Envelope(DeepIdV2ContactRouteRecoveryMode.IssueAfterRecordedHistory, ordinary, [pair]);
        var exact = request.CanonicalBytes.ToArray();
        var label = Encoding.ASCII.GetBytes("Deep/ContactResolver/V2/route-recovery-request");
        var expected = new byte[label.Length + 7 + exact.Length - 64]; label.CopyTo(expected, 0);
        BinaryPrimitives.WriteUInt16BigEndian(expected.AsSpan(label.Length + 1), 0x0301);
        BinaryPrimitives.WriteUInt32BigEndian(expected.AsSpan(label.Length + 3), checked((uint)(exact.Length - 64)));
        exact.AsSpan(0, exact.Length - 64).CopyTo(expected.AsSpan(label.Length + 7));
        Assert.Equal(expected, DeepIdV2ContactRouteRecoveryWireCodec.SigningInput(request));
        var key = PublicKeyAuth.GenerateKeyPair(B(32, 0x71));
        try
        {
            var signature = PublicKeyAuth.SignDetached(expected, key.PrivateKey);
            Assert.True(PublicKeyAuth.VerifyDetached(signature, expected, key.PublicKey));
            foreach (var offset in new[] { 2, 4, 8, 24, 56, 88, 96, 128, 160, 168, 176, 180, exact.Length - 65 })
            {
                var changed = expected.ToArray(); changed[label.Length + 7 + offset] ^= 1;
                Assert.False(PublicKeyAuth.VerifyDetached(signature, changed, key.PublicKey));
            }
        }
        finally { CryptographicOperations.ZeroMemory(key.PrivateKey); }
    }

    [Theory]
    [InlineData("version")]
    [InlineData("mode")]
    [InlineData("reserved")]
    [InlineData("total")]
    [InlineData("base-length")]
    [InlineData("base-version")]
    [InlineData("history-reserved")]
    [InlineData("four-pairs")]
    [InlineData("zero-issue-pairs")]
    [InlineData("three-read-pairs")]
    [InlineData("pair-request-length")]
    [InlineData("pair-response-length")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("oversize")]
    [InlineData("network")]
    [InlineData("lookup")]
    [InlineData("window")]
    [InlineData("zero-signature")]
    public void HostileFramingRejectsBeforeAnyAuthority(string fault)
    {
        var (ordinary, response) = Ordinary();
        var pair = new DeepIdV2ContactRouteRecordedPair(ContactRouteAuthorityWireCodec.EncodeRequest(ordinary),
            ContactRouteAuthorityWireCodec.EncodeResponse(ordinary, response));
        var request = Envelope(DeepIdV2ContactRouteRecoveryMode.IssueAfterRecordedHistory, ordinary, [pair]);
        var exact = request.CanonicalBytes.ToArray(); var countOffset = 180 + request.ExactBaseRequest.Length;
        switch (fault)
        {
            case "version": exact[1] = 2; break;
            case "mode": exact[2] = 3; break;
            case "reserved": exact[3] = 1; break;
            case "total": BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(4), uint.MaxValue); break;
            case "base-length": BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(176), uint.MaxValue); break;
            case "base-version": exact[181] = 2; break;
            case "history-reserved": exact[countOffset + 1] = 1; break;
            case "four-pairs": exact[countOffset] = 4; break;
            case "zero-issue-pairs": exact[countOffset] = 0; break;
            case "three-read-pairs": exact[2] = 1; exact[countOffset] = 3; break;
            case "pair-request-length": BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(countOffset + 4), uint.MaxValue); break;
            case "pair-response-length": BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(countOffset + 8 + pair.ExactRequest.Length), uint.MaxValue); break;
            case "truncated": exact = exact[..^1]; break;
            case "trailing": exact = [.. exact, 0]; break;
            case "oversize": exact = new byte[146_070]; break;
            case "network": exact[8] ^= 1; break;
            case "lookup": exact[56] ^= 1; break;
            case "window": BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(168), request.IssuedAtUnixSeconds + 121); break;
            case "zero-signature": exact.AsSpan(exact.Length - 64).Clear(); break;
        }
        Assert.ThrowsAny<FormatException>(() => DeepIdV2ContactRouteRecoveryWireCodec.DecodeRequest(exact));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(8)]
    [InlineData(24)]
    [InlineData(56)]
    [InlineData(88)]
    public void ResponseBindsModeNetworkOuterNonceAndExactBaseHash(int offset)
    {
        var (ordinary, response) = Ordinary(); var request = Envelope(DeepIdV2ContactRouteRecoveryMode.ReadRecordedWinner, ordinary, []);
        var encoded = DeepIdV2ContactRouteRecoveryWireCodec.EncodeResponse(request, response); encoded[offset] ^= 1;
        Assert.ThrowsAny<FormatException>(() => DeepIdV2ContactRouteRecoveryWireCodec.DecodeResponse(request, encoded));
    }

    [Fact]
    public void BoundsAndGatewayMatchFrozenAllocationWithoutGrowingOrdinaryCarriers()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(FindSpec("contact-route-recovery-v1.vectors.json")));
        var gateway = document.RootElement.GetProperty("gatewayPrimitive");
        Assert.Equal(Convert.FromHexString(gateway.GetProperty("expectedHex").GetString()!),
            DeepIdV2ContactRouteRecoveryWireCodec.GatewayShard(
                Convert.FromHexString(gateway.GetProperty("networkHex").GetString()!),
                Convert.FromHexString(gateway.GetProperty("outerNonceHex").GetString()!)));
        Assert.Equal(248, DeepIdV2ContactRouteRecoveryWireCodec.RequestFixedOverheadBytes);
        Assert.Equal(40_252, DeepIdV2ContactRouteRecoveryWireCodec.MaximumPairBytes);
        Assert.Equal(146_069, DeepIdV2ContactRouteRecoveryWireCodec.MaximumRequestBytes);
        Assert.Equal(15_271, DeepIdV2ContactRouteRecoveryWireCodec.MaximumResponseBytes);
        Assert.Equal(3, ContactRouteAuthorityWireCodec.RequestVersion);
        Assert.Equal(3, ContactRouteAuthorityWireCodec.ResponseVersion);
        Assert.Equal(25_065, ContactRouteAuthorityWireCodec.MaximumRequestBytes);
        Assert.Equal(171_870, ContactCoordinationOnionCodec.MaximumRequestBytes);
        var (ordinary, _) = Ordinary(); var genesis = new ContactRouteAuthorityWireRequest(ordinary.NetworkId.Span,
            ordinary.RequestNonce.Span, ordinary.DirectoryLookupKey.Span, ordinary.MinimumAdh1Generation,
            ordinary.MinimumAdh1CoreHash.Span, ordinary.ExactDca1.Span,
            DeepIdV2ContactMailboxRouteCodec.Decode(DeepIdV2ContactMailboxRouteTests.Package(false)).Route.Authorization.CanonicalBytes.Span);
        Assert.ThrowsAny<FormatException>(() => Envelope(DeepIdV2ContactRouteRecoveryMode.ReadRecordedWinner, genesis, []));
        var envelope = Envelope(DeepIdV2ContactRouteRecoveryMode.ReadRecordedWinner, ordinary, []);
        var carrier = ContactCoordinationOnionCodec.DecodeRequest(ContactCoordinationOnionCodec.EncodeRequest(
            ContactCoordinationTarget.RouteRecovery, envelope.CanonicalBytes.Span));
        Assert.Equal(envelope.GatewayShard.ToArray(), carrier.GatewayShard.ToArray());
        Assert.Empty(carrier.ProjectionReference.ToArray());
        Assert.Equal(envelope.ExpiresAtUnixSeconds, carrier.ExpiresAtUnixSeconds);
        Assert.NotEqual(ContactCodec.Decode("XRA1", ordinary.ExactXra1.Span).Field(6).ToArray(), carrier.GatewayShard.ToArray());
        Assert.ThrowsAny<FormatException>(() => new DeepIdV2ContactRouteRecordedPair(envelope.CanonicalBytes.Span, B(2_584, 1)));
    }

    // Existing public codec fixtures only: no signed authority or publication
    // claim is made by these deliberately untrusted structural candidates.
    internal static (ContactRouteAuthorityWireRequest Request, ContactRouteAuthorityWireResponse Response) Ordinary()
    {
        var package = DeepIdV2ContactMailboxRouteCodec.Decode(DeepIdV2ContactMailboxRouteTests.Package(false));
        var old = package.Route.Authorization; var fields = Enumerable.Range(1, 16).Select(tag => old.Field(tag)).ToArray();
        fields[2] = U64(1); fields[3] = old.CoreHash;
        var proposal = ContactCodecValidation.AuthorRecord("XRA1", fields);
        var request = new ContactRouteAuthorityWireRequest(package.Authorization.NetworkId.Span, B(32, 0x31), B(32, 0x32),
            0, B(32, 0x33), package.Authorization.CanonicalBytes.Span, proposal.CanonicalBytes.Span,
            package.Invite.CanonicalBytes.Span, package.Route.ExactBytes.Span);
        var authority = new byte[38]; "XNA1"u8.CopyTo(authority); BinaryPrimitives.WriteUInt16BigEndian(authority.AsSpan(4), 1);
        B(32, 0x34).CopyTo(authority, 6);
        var head = new AccountDirectoryAdh1(request.NetworkId.Span, 0, new byte[32], 1, B(32, 0x35), B(32, 0x36),
            authority, B(32, 0x37), 1, 2, 1, [new(B(32, 0x38), B(64, 0x39))]);
        return (request, new(request.NetworkId.Span, request.RequestNonce.Span, package.Route.Selection.CanonicalBytes.Span,
            package.Route.Route.CanonicalBytes.Span, package.Route.Successor.CanonicalBytes.Span, AccountDirectoryAdh1Codec.Encode(head)));
    }

    private static DeepIdV2ContactRouteRecoveryWireRequest Envelope(DeepIdV2ContactRouteRecoveryMode mode,
        ContactRouteAuthorityWireRequest request, IReadOnlyList<DeepIdV2ContactRouteRecordedPair> history) => new(mode,
            request.NetworkId.Span, B(32, 0x41), request.DirectoryLookupKey.Span, 0, B(32, 0x42), B(32, 0x43), 100, 120,
            ContactRouteAuthorityWireCodec.EncodeRequest(request), history, B(64, 0x44));
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] B(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static string FindSpec(string name)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "docs", "survival-program", "releases", "v3.0.0", "specs", name);
            if (File.Exists(candidate)) return candidate;
        }
        throw new FileNotFoundException(name);
    }
}
