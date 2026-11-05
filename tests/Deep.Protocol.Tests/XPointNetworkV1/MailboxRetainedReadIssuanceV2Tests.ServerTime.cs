using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Fixture = Deep.Protocol.Tests.XPointNetworkV1.XPointOnionCapabilityProducerTests.Fixture;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class MailboxRetainedReadIssuanceV2Tests
{
    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task CurrentIssuersProjectTheirFinalTrustedLowerAndKeepFutureWinnerRejection(MailboxCapabilityDomain domain)
    {
        var fixture = Fixture.Create();
        var input = await fixture.VerifyMailboxAsync();
        var route = CurrentWitnessRoute(input.Network);
        var clientLower = input.Network.Closure!.TrustedLowerUnixSeconds;
        var clientUpper = input.Network.Closure.TrustedUpperUnixSeconds;
        var requestExpiry = checked(clientUpper + 20);
        var clock = new Time { Sample = checked(input.Network.Closure.FreshnessMonotonicSample + 1) };
        var holder = PublicKeyAuth.GenerateKeyPair(B(32, 0xa4));
        var capability = domain == MailboxCapabilityDomain.Deposit ? route.Reachability.Field(10) : B(32, 0x67);
        ReadOnlyMemory<byte>[] fields = [input.Network.NetworkId, B(32, 0x65), B(32, 0x66), capability,
            holder.PublicKey, new byte[] { (byte)domain }, ContactCodec.ArtifactReference("PMT2", route.Projection).CanonicalBytes,
            route.Selection.ArtifactHash, U64(clientLower), U64(requestExpiry), route.ExactHash, B(64, 1)];
        var unsignedRequest = ContactCodec.AuthorForOperationalAuthority("XMG2", fields);
        fields[11] = PublicKeyAuth.SignDetached(unsignedRequest.SignatureInput.ToArray(), holder.PrivateKey);
        var request = ContactCodec.AuthorForOperationalAuthority("XMG2", fields);
        var signing = MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(MailboxGrantRouteEvidenceAuthentication.CreateTuple(
            SHA256.HashData(request.CanonicalBytes.Span), request.Field(3).Span,
            MailboxGrantCapabilityDigest.Compute(capability.Span, domain), (byte)domain, 1, route.ExactHash.Span, 250));
        var evidence = ContactServicePlacementFactory.Create(input.Network, ContactServiceRequestKind.ResolveInvite, request.Field(3))
            .RankedReplicaNodeIds.Select(id => new DeepIdV2MailboxGrantReplicaEvidence(id.Span,
                PublicKeyAuth.SignDetached(signing, PublicKeyAuth.GenerateKeyPair(B(32, (byte)(0x90 + (id.Span[0] - 0x10) * 8))).PrivateKey))).ToArray();
        var issuance = await DeepIdV2MailboxGrantIssuanceVerifier.VerifyAsync(input.Network, fixture.Authority,
            input.Pma, request.CanonicalBytes, route.ExactBytes, 250, evidence, new(clock));
        var marker = domain == MailboxCapabilityDomain.Deposit ? (byte)0xe1 : (byte)0xe2;
        var signer = new Issuer { KeyMarker = marker, SignatureMarker = marker };
        var response = await issuance.AuthorSuccessAsync(signer);
        var parsed = ContactCodec.Decode("XMC2", response.Span);
        Assert.Equal(clientLower + 1, BinaryPrimitives.ReadUInt64BigEndian(parsed.Field(4).Span));
        // Client195..205 and issuer196..206 intersect. The previous206
        // projection crosses the unchanged client's strict upper bound.
        Assert.True(BinaryPrimitives.ReadUInt64BigEndian(parsed.Field(4).Span) <= clientUpper);
        await issuance.VerifySuccessAsync(response);
        await issuance.VerifySuccessAsync(response.ToArray());
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(parsed.Field(8).Span);
        var future = MailboxGrantResultAuthor.AuthorSuccess(request, route.ExactBytes.Span, grant, clientUpper + 2, requestExpiry);
        await Assert.ThrowsAsync<CryptographicException>(() => issuance.VerifySuccessAsync(future.CanonicalBytes).AsTask());
        Assert.Equal(1, signer.Calls);
    }

    [Theory]
    [InlineData(1UL)]
    [InlineData(5UL)]
    [InlineData(10UL)]
    public async Task IntersectingIndependentIntervalsAcceptActualIssuerLowerAndRejectPriorUpperProjection(ulong elapsed)
    {
        var state = await State.Create();
        var client = await MailboxHostAuthorityV2Verifier.VerifyAsync(state.Network,
            Fixture.Create().Authority, state.Host.RetainedReadPolicyBytes, new(new Time()));
        var clientRequest = await client.VerifyRetainedReadRequestAsync(state.Request);
        var clientWindow = await clientRequest.ReadCurrentTimeAsync();
        state.Clock.Sample += elapsed;
        var issuerRequest = await state.Host.VerifyRetainedReadRequestAsync(state.Request);
        var issuerWindow = await issuerRequest.ReadCurrentTimeAsync();
        Assert.True(issuerWindow.LowerUnixSeconds <= clientWindow.UpperUnixSeconds);
        Assert.True(clientWindow.LowerUnixSeconds <= issuerWindow.UpperUnixSeconds);
        Assert.True(issuerWindow.UpperUnixSeconds > clientWindow.UpperUnixSeconds);

        var issuer = new Issuer();
        var issuance = await state.Issuance();
        var response = await issuance.AuthorSuccessAsync(issuer);
        var exactWinner = response.ToArray();
        var parsed = ContactCodec.Decode("XMC2", response.Span);
        Assert.Equal(issuerWindow.LowerUnixSeconds,
            BinaryPrimitives.ReadUInt64BigEndian(parsed.Field(4).Span));
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(parsed.Field(8).Span);
        var priorProjection = MailboxGrantResultAuthor.AuthorSuccess(
            ContactCodec.Decode("XMG2", state.Request), state.Route.ExactBytes.Span,
            grant, issuerWindow.UpperUnixSeconds,
            BinaryPrimitives.ReadUInt64BigEndian(parsed.Field(6).Span));
        var rejected = await Assert.ThrowsAsync<CryptographicException>(() =>
            client.VerifyRetainedReadSuccessAsync(state.Route.ExactBytes, state.Request,
                priorProjection.CanonicalBytes).AsTask());
        Assert.Equal("IssuedAfterCurrentUpper", rejected.Data["Deep.MailboxRetainedRead.Check"]);

        await issuance.VerifySuccessAsync(response);
        var accepted = await client.VerifyRetainedReadSuccessAsync(state.Route.ExactBytes,
            state.Request, response);
        await accepted.EnsureCurrentAsync();
        var replay = await client.VerifyRetainedReadSuccessAsync(state.Route.ExactBytes,
            state.Request, exactWinner);
        Assert.Equal(exactWinner, accepted.ExactXmc2.ToArray());
        Assert.Equal(exactWinner, replay.ExactXmc2.ToArray());
        Assert.Equal(1, issuer.Calls);
    }

    // The issuer trust boundary consumes canonical route state attested by
    // two real selected replicas. This fixture signs its complete threshold
    // graph with the actual network witnesses; it makes no native-store claim.
    private static ParsedContactRouteClosure CurrentWitnessRoute(VerifiedOnionNetworkContext network)
    {
        var pmt = network.Closure!.Pmt;
        var original = MakeRoute(pmt, 250);
        ReadOnlyMemory<byte>[] Fields(ContactRecord record, int count) => Enumerable.Range(1, count).Select(record.Field).ToArray();
        ContactRecord Sign(string magic, ReadOnlyMemory<byte>[] fields, int signatureTag)
        {
            var candidate = ContactCodec.AuthorForOperationalAuthority(magic, fields);
            fields[signatureTag - 1] = Enumerable.Range(0, 2).SelectMany(index => B(32, (byte)(0x40 + index))
                .Concat(PublicKeyAuth.SignDetached(candidate.SignatureInput.ToArray(), PublicKeyAuth.GenerateKeyPair(B(32, (byte)(0x50 + index))).PrivateKey))).ToArray();
            return ContactCodec.AuthorForOperationalAuthority(magic, fields);
        }
        var pms = Sign("PMS2", Fields(original.Selection, 11), 11);
        var xrcFields = Fields(original.Route, 21); xrcFields[6] = pms.ArtifactHash;
        xrcFields[8] = XPointNetworkCodec.EncodeCoreReference("XNH1", network.Closure.Head.CoreHash.Span);
        var xrc = Sign("XRC1", xrcFields, 21);
        var xssFields = Fields(original.Successor, 14); xssFields[3] = xrc.CoreHash;
        xssFields[4] = ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes; xssFields[5] = xssFields[4]; xssFields[8] = pms.ArtifactHash;
        var xss = Sign("XSS1", xssFields, 14);
        var xrrFields = Fields(original.Reachability, 20); xrrFields[5] = ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes;
        xrrFields[6] = ContactCodec.ArtifactReference("XSS1", xss).CanonicalBytes; xrrFields[8] = pms.ArtifactHash;
        var xrr = ContactCodec.AuthorForOperationalAuthority("XRR1", xrrFields);
        return ContactRouteClosureCodec.Decode(ContactRouteClosureCodec.EncodeRecords([xrr, original.Authorization, xrc, xss, pmt, pms]));
    }
}
