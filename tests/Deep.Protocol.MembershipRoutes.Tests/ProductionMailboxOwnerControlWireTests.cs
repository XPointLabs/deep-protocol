using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxOwnerControlWireTests
{
    [Fact]
    public void Ocr1_Exact272_GoldenOffsetsAndCanonicalRoundTrip()
    {
        var value = new ProductionMailboxOwnerControlResponderCertificate
        {
            NetworkId = Bytes(1, 16), MailboxOwnerEd25519PublicKey = Bytes(2, 32),
            RouteDomainHash = Bytes(3, 32), AnchorCanonicalAuthorityHash = Bytes(4, 32),
            ResponderEd25519PublicKey = Bytes(5, 32), IssuedAtUnixSeconds = 100,
            ExpiresAtUnixSeconds = 200, KeyGeneration = 1,
            PreviousCanonicalCertificateHash = new byte[32], AnchorIssuerSignature = Bytes(6, 64)
        };
        var encoded = ProductionMailboxOwnerControlTransportCodec.EncodeResponderCertificate(value);
        Assert.Equal(272, encoded.Length); Assert.Equal("OCR1"u8.ToArray(), encoded[..4]);
        Assert.Equal(1, encoded[4]); Assert.All(encoded[5..8], static b => Assert.Equal(0, b));
        Assert.Equal(value.NetworkId.ToArray(), encoded[8..24]);
        Assert.Equal(value.MailboxOwnerEd25519PublicKey.ToArray(), encoded[24..56]);
        Assert.Equal(value.RouteDomainHash.ToArray(), encoded[56..88]);
        Assert.Equal(value.AnchorCanonicalAuthorityHash.ToArray(), encoded[88..120]);
        Assert.Equal(value.ResponderEd25519PublicKey.ToArray(), encoded[120..152]);
        Assert.Equal(100UL, BinaryPrimitives.ReadUInt64BigEndian(encoded[152..160]));
        Assert.Equal(200UL, BinaryPrimitives.ReadUInt64BigEndian(encoded[160..168]));
        Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(encoded[168..176]));
        Assert.All(encoded[176..208], static b => Assert.Equal(0, b));
        Assert.Equal(value.AnchorIssuerSignature.ToArray(), encoded[208..272]);
        Assert.Equal(encoded, ProductionMailboxOwnerControlTransportCodec.EncodeResponderCertificate(
            ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(encoded)));
    }

    [Fact]
    public void Ocr1_RejectsNonGenesisAndOverflowShapedWindows()
    {
        var encoded = ProductionMailboxOwnerControlTransportCodec.EncodeResponderCertificate(new()
        {
            NetworkId = Bytes(1, 16), MailboxOwnerEd25519PublicKey = Bytes(2, 32),
            RouteDomainHash = Bytes(3, 32), AnchorCanonicalAuthorityHash = Bytes(4, 32),
            ResponderEd25519PublicKey = Bytes(5, 32), IssuedAtUnixSeconds = 100,
            ExpiresAtUnixSeconds = 200, KeyGeneration = 1,
            PreviousCanonicalCertificateHash = new byte[32], AnchorIssuerSignature = Bytes(6, 64)
        });
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(168, 8), 2);
        Assert.Throws<FormatException>(() =>
            ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(encoded));
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(168, 8), 1);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(160, 8), ulong.MaxValue);
        Assert.Throws<FormatException>(() =>
            ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(encoded));
    }

    [Fact]
    public async Task HistoricalAnchor_RestoresOnlyExactCompositeAndProtectedOcr()
    {
        var f = RouteV2TestFixture.Create();
        var enrollment = await ProductionMailboxRouteIssuerAuthoring.AcceptDelegationAsync(
            ProductionMailboxRouteContinuityCodec.EncodeDelegation(f.Delegation),
            ProductionMailboxRouteContinuityCodec.EncodeRouteOriginLkg(f.PreDelegationRouteOriginLkg),
            f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra,
            RouteV2TestFixture.Now, RouteV2TestFixture.Now, 0,
            (request, destination, _) =>
            {
                var signature = PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), f.IssuerPrivateKey);
                signature.CopyTo(destination.Span); return ValueTask.FromResult(64);
            }, static (_, _) => ValueTask.FromResult(true));
        var responder = PublicKeyAuth.GenerateKeyPair(Bytes(33, 32));
        var verifiedOcr = await ProductionMailboxRouteIssuerAuthoring
            .AuthorOwnerControlResponderCertificateAsync(enrollment, f.Authority,
                f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra,
                responder.PublicKey, RouteV2TestFixture.Now + 50,
                (request, destination, _) =>
                {
                    var signature = PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), f.IssuerPrivateKey);
                    signature.CopyTo(destination.Span); return ValueTask.FromResult(64);
                });
        var live = ProductionMailboxRouteIssuerAuthoring.CreateHistoricalAnchor(enrollment,
            f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra, verifiedOcr);
        var protectedState = live.ToProtectedRestoreContext();
        var restored = ProductionMailboxRouteIssuerAuthoring.RestoreHistoricalAnchor(
            enrollment.Enrollment.CanonicalDelegationBytes,
            enrollment.Enrollment.CanonicalAcceptanceBytes,
            enrollment.CanonicalPreDelegationRouteOriginLkg,
            enrollment.CanonicalEnrolledRouteOriginLkg, verifiedOcr.CanonicalBytes,
            f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra,
            protectedState);
        Assert.Equal(verifiedOcr.CanonicalHash.ToArray(),
            restored.CanonicalOwnerControlResponderCertificateHash.ToArray());
        Assert.Equal(f.Delegation.PinnedMrXPublicKeySha256.ToArray(),
            protectedState.PinnedMrXPublicKeySha256.ToArray());
        Assert.Equal(f.Acceptance.AcceptedAtUnixSeconds, protectedState.AcceptedAtUnixSeconds);
        var cursor = ProductionMailboxRouteHistoryAuthoring.CreateInitialCursor(enrollment,
            f.Authority, f.RevocationSnapshot);
        var prcIntent = ProductionMailboxRouteCertificateAuthoring.CreateIntent(restored,
            cursor, f.Authority, f.RevocationSnapshot, RouteV2TestFixture.Now,
            RouteV2TestFixture.Now + 50, RouteV2TestFixture.Now, 0);
        var freshPrc = await ProductionMailboxRouteCertificateAuthoring.AuthorAsync(prcIntent,
            (request, destination, _) =>
            {
                var signature = PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), f.IssuerPrivateKey);
                signature.CopyTo(destination.Span); return ValueTask.FromResult(64);
            }, RouteV2TestFixture.Now, 0);
        Assert.Equal(f.Delegation.MailboxOwnerEd25519PublicKey.ToArray(),
            freshPrc.Certificate.MailboxOwnerEd25519PublicKey.ToArray());
        var request = await ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
            live, cursor, Bytes(44, 32), RouteV2TestFixture.Now, RouteV2TestFixture.Now + 30,
            (signingRequest, destination, _) =>
            {
                var signature = PublicKeyAuth.SignDetached(signingRequest.SigningBytes.ToArray(), f.OwnerPrivateKey);
                signature.CopyTo(destination.Span); return ValueTask.FromResult(64);
            });
        var response = await ProductionMailboxOwnerControlTransportCodec.AuthorNoChangeResponseAsync(
            request, live, RouteV2TestFixture.Now, RouteV2TestFixture.Now + 20,
            (signingRequest, destination, _) =>
            {
                var signature = PublicKeyAuth.SignDetached(signingRequest.SigningBytes.ToArray(), responder.PrivateKey);
                signature.CopyTo(destination.Span); return ValueTask.FromResult(64);
            });
        Assert.Equal(344, request.CanonicalBytes.Length);
        Assert.Equal(384, response.CanonicalHeader.Length);

        var decoded = ProductionMailboxOwnerControlTransportCodec.DecodeResponseHeader(
            response.CanonicalHeader.Span);
        var mixed = SignResponse(decoded with
        {
            NetworkId = Bytes(199, 16), ResponderSignature = new byte[64]
        }, responder.PrivateKey);
        Assert.Throws<FormatException>(() =>
            ProductionMailboxOwnerControlTransportCodec.VerifyResponse(mixed, [], request, live,
                RouteV2TestFixture.Now, 0));

        var payload = Bytes(77, 1024);
        var history = SignResponse(decoded with
        {
            Kind = ProductionMailboxOwnerControlResponseKind.History,
            NextRouteHistoryCheckpointHash = Bytes(78, 32),
            NextRouteHistoryBatchSequence = decoded.CurrentRouteHistoryBatchSequence + 1,
            PayloadSha256 = SHA256.HashData(payload), PayloadLength = (uint)payload.Length,
            ResponderSignature = new byte[64]
        }, responder.PrivateKey);
        var verifiedHeader = ProductionMailboxOwnerControlTransportCodec.VerifyResponseHeader(
            history, request, live, RouteV2TestFixture.Now, 0);
        var stream = new CountingStream(payload);
        await Assert.ThrowsAsync<FormatException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.ReadVerifiedResponsePayloadAsync(
                stream, verifiedHeader));
        Assert.Equal(64, stream.BytesRead);
        history[^1] ^= 1;
        var untouched = new CountingStream(payload);
        Assert.Throws<FormatException>(() =>
            ProductionMailboxOwnerControlTransportCodec.VerifyResponseHeader(
                history, request, live, RouteV2TestFixture.Now, 0));
        Assert.Equal(0, untouched.BytesRead);

        var mutated = verifiedOcr.CanonicalBytes.ToArray(); mutated[120] ^= 1;
        Assert.ThrowsAny<Exception>(() => ProductionMailboxRouteIssuerAuthoring.RestoreHistoricalAnchor(
            enrollment.Enrollment.CanonicalDelegationBytes,
            enrollment.Enrollment.CanonicalAcceptanceBytes,
            enrollment.CanonicalPreDelegationRouteOriginLkg,
            enrollment.CanonicalEnrolledRouteOriginLkg, mutated,
            f.Authority, f.RevocationSnapshot, f.VerifiedCertificate, f.VerifiedPra,
            protectedState));
    }

    private static byte[] SignResponse(ProductionMailboxOwnerControlResponseHeader header,
        byte[] privateKey)
    {
        var signature = PublicKeyAuth.SignDetached(
            ProductionMailboxOwnerControlTransportCodec.GetResponseSigningBytes(header), privateKey);
        return ProductionMailboxOwnerControlTransportCodec.EncodeResponseHeader(header with
        { ResponderSignature = signature });
    }

    private sealed class CountingStream(byte[] bytes) : MemoryStream(bytes, writable: false)
    {
        internal int BytesRead { get; private set; }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var read = base.ReadAsync(buffer, cancellationToken);
            BytesRead += read.IsCompletedSuccessfully ? read.Result : 0;
            return read;
        }
    }

    private static byte[] Bytes(byte value, int count) => Enumerable.Repeat(value, count).ToArray();
}
