using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class Xpa1PublicationAuthorizationAuthorTests
{
    [Fact]
    public async Task PermanentPublication_AuthorsExactThresholdAuthorizationAndReverifiesIt()
    {
        var fixture = await Fixture.CreateAsync();

        var authored = await Xpa1PublicationAuthorizationAuthor.AuthorPermanentAsync(
            fixture.Request, fixture.Contact, fixture.Route, fixture.Core.NetworkAuthority, fixture.Placement,
            fixture.Clock, fixture.Signers, default);

        Assert.Equal(authored.ExactXpa1.ToArray(), authored.Request.ExactXpa1.ToArray());
        Assert.Equal(authored.ExactXpu1.ToArray(), authored.Request.CanonicalBytes.ToArray());
        Assert.Equal(fixture.Request.OperationId.ToArray(), authored.Authorization.OperationId.ToArray());
        Assert.Equal(fixture.Locator, authored.Authorization.LocatorHash.ToArray());
        Assert.Equal(fixture.Contact.ResolverResponse.ArtifactHash.ToArray(),
            authored.Authorization.Dcr1Hash.ToArray());
        Assert.Equal(fixture.Contact.Bundle.ArtifactHash.ToArray(),
            authored.Authorization.Dcb1Hash.ToArray());
        var xpa = ServiceWire.ParseValidatedXpa1(authored.Request);
        Assert.Equal(fixture.Core.NetworkAuthority.WitnessThreshold, xpa[20][0]);
    }

    [Fact]
    public async Task PublisherSignatureFromAnotherDevice_IsRejected()
    {
        var fixture = await Fixture.CreateAsync();
        var foreign = PublicKeyAuth.GenerateKeyPair(TestBytes(32, 0xe1));
        var signature = PublicKeyAuth.SignDetached(fixture.PublisherInput, foreign.PrivateKey);
        var request = fixture.WithPublisherSignature(signature);

        var error = await Assert.ThrowsAsync<Xpa1PublicationAuthorizationAuthoringException>(() =>
            Xpa1PublicationAuthorizationAuthor.AuthorPermanentAsync(
                request, fixture.Contact, fixture.Route, fixture.Core.NetworkAuthority, fixture.Placement,
                fixture.Clock, fixture.Signers, default).AsTask());

        Assert.Equal("PublisherSignatureInvalid", error.Code);
    }

    [Fact]
    public async Task BelowCurrentWitnessThreshold_IsRejected()
    {
        var fixture = await Fixture.CreateAsync();

        var error = await Assert.ThrowsAsync<Xpa1PublicationAuthorizationAuthoringException>(() =>
            Xpa1PublicationAuthorizationAuthor.AuthorPermanentAsync(
                fixture.Request, fixture.Contact, fixture.Route, fixture.Core.NetworkAuthority, fixture.Placement,
                fixture.Clock, fixture.Signers.Take(1).ToArray(), default).AsTask());

        Assert.Equal("InsufficientSigners", error.Code);
    }

    [Fact]
    public async Task PublicationAuthorityWire_RoundTripsExactNonceBoundRequestAndResponse()
    {
        var fixture = await Fixture.CreateAsync();
        var authored = await Xpa1PublicationAuthorizationAuthor.AuthorPermanentAsync(
            fixture.Request, fixture.Contact, fixture.Route, fixture.Core.NetworkAuthority,
            fixture.Placement, fixture.Clock, fixture.Signers, default);
        var nonce = TestBytes(32, 0xd1);
        var freshness = fixture.Contact.Freshness;
        var wireRequest = new ContactPublicationAuthorityWireRequest(
            fixture.Core.NetworkAuthority.NetworkId.Span,
            nonce,
            freshness.DirectoryLeafKey.Span,
            freshness.AdhGeneration,
            freshness.ExactAdh1CoreHash.Span,
            fixture.Contact.Authorization.Verified.Record.CanonicalBytes.Span,
            fixture.Contact.ResolverResponse.CanonicalBytes.Span,
            ContactRouteClosureCodec.Encode(fixture.Route),
            fixture.Request.OperationId.Span,
            fixture.Request.Generation,
            fixture.Request.PredecessorObjectHash.Span,
            fixture.Request.ObjectCiphertext.Span,
            fixture.Request.IssuedAtUnixSeconds,
            fixture.Request.ExpiresAtUnixSeconds,
            fixture.Request.EffectiveExpiresAtUnixSeconds,
            fixture.Request.OwnerRetrieveCapability.Span,
            fixture.Request.PublisherSignature.Span);

        var encodedRequest = ContactPublicationAuthorityWireCodec.EncodeRequest(wireRequest);
        var decodedRequest = ContactPublicationAuthorityWireCodec.DecodeRequest(encodedRequest);
        Assert.Equal(encodedRequest,
            ContactPublicationAuthorityWireCodec.EncodeRequest(decodedRequest));
        Assert.Equal(nonce, decodedRequest.RequestNonce.ToArray());

        var response = new ContactPublicationAuthorityWireResponse(
            decodedRequest.NetworkId.Span,
            decodedRequest.RequestNonce.Span,
            authored.ExactXpu1.Span);
        var encodedResponse = ContactPublicationAuthorityWireCodec.EncodeResponse(
            decodedRequest, response);
        var decodedResponse = ContactPublicationAuthorityWireCodec.DecodeResponse(
            decodedRequest, encodedResponse);

        Assert.Equal(authored.ExactXpu1.ToArray(), decodedResponse.ExactXpu1.ToArray());
        Assert.Equal(encodedResponse,
            ContactPublicationAuthorityWireCodec.EncodeResponse(decodedRequest, decodedResponse));
    }

    [Fact]
    public async Task DeviceCustody_AuthorsExactPermanentPublicationRequest()
    {
        var fixture = await Fixture.CreateAsync();
        var publication = new AuthoredPermanentContactPublication(
            fixture.Contact,
            fixture.Request.ObjectCiphertext.Span,
            fixture.Locator);
        var route = new AuthoredPermanentContactRoute(
            fixture.Route,
            fixture.Route.Reachability,
            fixture.Route.Invite);
        var signer = new ContactSigner(
            fixture.Core.Device,
            fixture.Core.VerifiedRecipient);

        var authored = await ContactPublicationAuthorityAuthor.AuthorAsync(
            publication,
            route,
            signer,
            TestBytes(32, 0xd2),
            fixture.Request.OperationId,
            fixture.Request.PredecessorObjectHash,
            fixture.Request.IssuedAtUnixSeconds,
            fixture.Request.ExpiresAtUnixSeconds,
            fixture.Request.EffectiveExpiresAtUnixSeconds,
            fixture.Request.OwnerRetrieveCapability);

        Assert.Equal(fixture.Request.PublisherSignature.ToArray(),
            authored.WireRequest.PublisherSignature.ToArray());
        Assert.Equal(publication.ProtectedDcr1.ToArray(),
            authored.WireRequest.ObjectCiphertext.ToArray());
        Assert.Equal(ContactDeviceSignaturePurpose.PermanentAddressPublication,
            signer.LastPurpose);
    }

    private sealed class Fixture
    {
        private Fixture(
            ContactCodecSecurityTests.CryptoDcrFixture core,
            VerifiedContactBundleClosure contact,
            VerifiedContactRouteClosure route,
            VerifiedContactServicePlacement placement,
            OnionTrustedTimeAuthority clock,
            byte[] locator,
            byte[] publisherInput,
            PermanentAddressPublicationAuthorizationRequest request,
            IXpa1PublicationAuthorizationWitnessSigner[] signers)
        {
            Core = core;
            Contact = contact;
            Route = route;
            Placement = placement;
            Clock = clock;
            Locator = locator;
            PublisherInput = publisherInput;
            Request = request;
            Signers = signers;
        }

        internal ContactCodecSecurityTests.CryptoDcrFixture Core { get; }
        internal VerifiedContactBundleClosure Contact { get; }
        internal VerifiedContactRouteClosure Route { get; }
        internal VerifiedContactServicePlacement Placement { get; }
        internal OnionTrustedTimeAuthority Clock { get; }
        internal byte[] Locator { get; }
        internal byte[] PublisherInput { get; }
        internal PermanentAddressPublicationAuthorizationRequest Request { get; }
        internal IXpa1PublicationAuthorizationWitnessSigner[] Signers { get; }

        internal static async Task<Fixture> CreateAsync()
        {
            var routeFixture = await ContactPublicationAuthorTests.Fixture.CreateAsync();
            var core = routeFixture.Identity;
            var contactSigner = new ContactSigner(core.Device, core.VerifiedRecipient);
            var preKey = await ContactPublicationAuthor.AuthorPreKeyServiceAsync(
                new ContactPreKeyServiceAuthoringRequest(
                    core.VerifiedRecipient, core.Authorization, 32, 8, 20, 80),
                contactSigner);
            var contact = (await ContactPublicationAuthor.AuthorPermanentAsync(
                new ContactBundleAuthoringRequest(
                    core.Authorization, core.Freshness, routeFixture.Route, [preKey],
                    20, 80, core.BootId, core.CurrentMonotonicSample), contactSigner)).Verified;
            using var derived = PermanentContactResolutionDerivation.Derive(
                core.NetworkAuthority.NetworkId.Span, contact.Binding.DeepId);
            var locator = derived.LocatorHash.ToArray();
            var dtt = Deep.Protocol.AccountDirectoryV1.AccountDirectoryDtt1Codec.Decode(
                core.Freshness.ExactDtt1.Span);
            var leaseBoot = PrivacyRoutingWire.Sha256Domain(
                "Deep/XPoint/V1/monotonic-boot-id", core.BootId);
            var network = new VerifiedOnionNetworkContext(
                core.NetworkAuthority.NetworkId.Span,
                new OnionTrustedTimeLease(TimeProvider.System, TimeSpan.FromMinutes(1), leaseBoot),
                []);
            var validUntil = Math.Min(
                core.NetworkAuthority.ExpiresAt, core.Freshness.ExpiresAtUnixSeconds);
            var placement = new VerifiedContactServicePlacement(
                network, ContactServiceRequestKind.PublishInvite, ContactServiceClass.InviteResolver,
                dtt.CurrentXnv1CoreHash.Span, TestBytes(32, 0xc1), locator,
                dtt.CurrentXnv1Generation, validUntil, [TestBytes(32, 0xc2)]);
            var operation = TestBytes(32, 0xc3);
            var ciphertext = TestBytes(64, 0xc4);
            var ciphertextHash = SHA256.HashData(ciphertext);
            var routeHash = SHA256.HashData(ContactRouteClosureCodec.Encode(routeFixture.Route));
            var predecessor = new byte[32];
            var ownerCapability = TestBytes(32, 0xc5);
            var expiresAt = checked(core.Freshness.TrustedUpperUnixSeconds + 10);
            var publisherInput = Xpa1PublicationAuthorizationAuthor.CreatePublisherSigningInput(
                locator, contact.ResolverResponse.ArtifactHash.Span, ciphertextHash,
                routeHash, 0, predecessor, expiresAt, ownerCapability);
            var signature = PublicKeyAuth.SignDetached(publisherInput, core.Device.PrivateKey);
            var request = new PermanentAddressPublicationAuthorizationRequest(
                operation, 0, predecessor, ciphertext,
                core.Freshness.TrustedLowerUnixSeconds, expiresAt, expiresAt,
                ownerCapability, signature);
            var signers = core.NetworkWitnesses
                .Take(core.NetworkAuthority.WitnessThreshold)
                .Select(static witness =>
                    (IXpa1PublicationAuthorizationWitnessSigner)new Signer(witness.Id, witness.Key))
                .ToArray();
            var clock = new OnionTrustedTimeAuthority(new FixedClock(
                new OnionMonotonicReading(core.BootId, core.CurrentMonotonicSample)));
            return new Fixture(core, contact, routeFixture.Route, placement, clock, locator, publisherInput, request, signers);
        }

        internal PermanentAddressPublicationAuthorizationRequest WithPublisherSignature(byte[] signature) =>
            new(Request.OperationId.Span, Request.Generation, Request.PredecessorObjectHash.Span,
                Request.ObjectCiphertext.Span, Request.IssuedAtUnixSeconds, Request.ExpiresAtUnixSeconds,
                Request.EffectiveExpiresAtUnixSeconds, Request.OwnerRetrieveCapability.Span, signature);
    }

    private sealed class ContactSigner(KeyPair key, Deep.Protocol.DeepNative.VerifiedDevice device)
        : IContactDeviceCustodySigner
    {
        public ReadOnlyMemory<byte> DeviceId => device.Certificate.DeviceId;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => TestBytes(32, 0xce);
        internal ContactDeviceSignaturePurpose LastPurpose { get; private set; }

        public ValueTask<int> SignAsync(
            ContactDeviceSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastPurpose = request.Purpose;
            var signature = PublicKeyAuth.SignDetached(
                request.SigningInput.ToArray(), key.PrivateKey);
            signature.CopyTo(signature64);
            return ValueTask.FromResult(signature.Length);
        }
    }

    private sealed class Signer(byte[] id, KeyPair key) : IXpa1PublicationAuthorizationWitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => id.ToArray();

        public ValueTask<ReadOnlyMemory<byte>> SignXpa1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(signingInput.ToArray(), key.PrivateKey));
        }
    }

    private sealed class FixedClock(OnionMonotonicReading reading) : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(
                reading.BootId.Span, reading.SampleSeconds));
        }
    }

    private static byte[] TestBytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();
}
