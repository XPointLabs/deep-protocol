using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class ContactRouteThresholdAuthorTests
{
    [Fact]
    public async Task ExactAdvertisement_AuthorsThresholdSelectionAndRouteClosure()
    {
        var fixture = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var proposal = await fixture.VerifyProposalAsync();
        var deviceSigner = new DeviceSigner(
            fixture.Identity.Device, fixture.Identity.VerifiedRecipient);
        var xra = await ContactRouteAdvertisementAuthor.AuthorGenesisAsync(
            AdvertisementRequest(proposal), deviceSigner);
        var signers = fixture.Witnesses.Take(2)
            .Select(witness => (IContactRouteAuthorityWitnessSigner)
                new WitnessSigner(witness.Id, witness.Key))
            .ToArray();

        var authored = await ContactRouteThresholdAuthor.AuthorAsync(
            new ContactRouteThresholdAuthoringRequest(proposal, xra, 29, 60), signers);
        var completed = await ContactRouteCompletionAuthor.AuthorAsync(
            new ContactRouteCompletionAuthoringRequest(proposal, xra, authored),
            deviceSigner);

        Assert.Equal(fixture.Pmt.Field(7).Span[0], authored.Selection.Field(5).Span[0]);
        Assert.Equal(xra.PlacementInput.ToArray(), authored.Selection.Field(3).ToArray());
        Assert.Equal(authored.Selection.ArtifactHash.ToArray(),
            authored.Authority.Pms2ArtifactHash.ToArray());
        Assert.Equal(ContactCodec.ArtifactReference("XRA1", xra.Record).CanonicalBytes.ToArray(),
            authored.LiveRoute.Field(5).ToArray());
        Assert.Equal(authored.LiveRoute.CoreHash.ToArray(),
            authored.SuccessorCheckpoint.Field(4).ToArray());
        Assert.Equal(completed.Invite.CanonicalBytes.ToArray(),
            completed.Verified.Invite.CanonicalBytes.ToArray());
        Assert.Equal(completed.ExactRouteClosure.ToArray(),
            ContactRouteClosureCodec.Encode(completed.Verified));
        Assert.Equal(
            [ContactDeviceSignaturePurpose.RouteAdvertisement,
             ContactDeviceSignaturePurpose.RouteReachability,
             ContactDeviceSignaturePurpose.InviteRoute],
            deviceSigner.Purposes);
        Assert.All(signers.Cast<WitnessSigner>(), signer => Assert.Equal(
            [ContactRouteAuthoritySignaturePurpose.Selection,
             ContactRouteAuthoritySignaturePurpose.LiveRoute,
             ContactRouteAuthoritySignaturePurpose.SuccessorCheckpoint],
            signer.Purposes));
    }

    [Fact]
    public async Task BelowCurrentWitnessThreshold_FailsBeforeAnySignature()
    {
        var fixture = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var proposal = await fixture.VerifyProposalAsync();
        var xra = await ContactRouteAdvertisementAuthor.AuthorGenesisAsync(
            AdvertisementRequest(proposal),
            new DeviceSigner(fixture.Identity.Device, fixture.Identity.VerifiedRecipient));
        var signer = new WitnessSigner(fixture.Witnesses[0].Id, fixture.Witnesses[0].Key);

        var error = await Assert.ThrowsAsync<ContactPublicationAuthoringException>(() =>
            ContactRouteThresholdAuthor.AuthorAsync(
                new ContactRouteThresholdAuthoringRequest(proposal, xra, 29, 60),
                [signer]).AsTask());

        Assert.Equal("InsufficientRouteWitnesses", error.Code);
        Assert.Empty(signer.Purposes);
    }

    [Fact]
    public async Task AdvertisementFromAnotherProposal_IsRejectedBeforeWitnesses()
    {
        var fixture = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var proposal = await fixture.VerifyProposalAsync();
        var xra = await ContactRouteAdvertisementAuthor.AuthorGenesisAsync(
            AdvertisementRequest(proposal),
            new DeviceSigner(fixture.Identity.Device, fixture.Identity.VerifiedRecipient));
        var fields = Enumerable.Range(1, 16)
            .Select(tag => xra.Record.Field(tag)).ToArray();
        fields[4] = new ContactArtifactReference("PMT2", 1, Bytes(32, 0xe1))
            .CanonicalBytes;
        var provisional = ContactCodec.AuthorForOperationalAuthority("XRA1", fields);
        fields[15] = PublicKeyAuth.SignDetached(
            provisional.SignatureInput.ToArray(), fixture.Identity.Device.PrivateKey);
        var changed = ContactCodec.AuthorForOperationalAuthority("XRA1", fields);
        xra = new AuthoredContactRouteAdvertisement(changed, changed.Field(6).Span);
        var signers = fixture.Witnesses.Take(2)
            .Select(witness => new WitnessSigner(witness.Id, witness.Key)).ToArray();

        var error = await Assert.ThrowsAsync<ContactPublicationAuthoringException>(() =>
            ContactRouteThresholdAuthor.AuthorAsync(
                new ContactRouteThresholdAuthoringRequest(proposal, xra, 29, 60), signers)
                .AsTask());

        Assert.Equal("RouteAdvertisementMismatch", error.Code);
        Assert.All(signers, signer => Assert.Empty(signer.Purposes));
    }

    private static ContactRouteAdvertisementAuthoringRequest AdvertisementRequest(
        VerifiedContactRouteProposalAuthority proposal) =>
        new(proposal, 100, Bytes(32, 0xa1), Bytes(32, 0xa2), Bytes(32, 0xa3),
            29, 60);

    private static byte[] Bytes(int length, byte start) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(start + index))).ToArray();

    private sealed class DeviceSigner(KeyPair key, VerifiedDevice device)
        : IContactDeviceCustodySigner
    {
        private readonly List<ContactDeviceSignaturePurpose> purposes = [];
        public ReadOnlyMemory<byte> DeviceId => device.Certificate.DeviceId;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, 0xb1);
        internal ContactDeviceSignaturePurpose[] Purposes => purposes.ToArray();

        public ValueTask<int> SignAsync(
            ContactDeviceSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            purposes.Add(request.Purpose);
            PublicKeyAuth.SignDetached(request.SigningInput.ToArray(), key.PrivateKey)
                .CopyTo(signature64);
            return ValueTask.FromResult(64);
        }
    }

    private sealed class WitnessSigner(byte[] id, KeyPair key)
        : IContactRouteAuthorityWitnessSigner
    {
        private readonly List<ContactRouteAuthoritySignaturePurpose> purposes = [];
        public ReadOnlyMemory<byte> WitnessId => id.ToArray();
        internal ContactRouteAuthoritySignaturePurpose[] Purposes => purposes.ToArray();

        public ValueTask<int> SignAsync(
            ContactRouteAuthoritySigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            purposes.Add(request.Purpose);
            PublicKeyAuth.SignDetached(request.SigningInput.ToArray(), key.PrivateKey)
                .CopyTo(signature64);
            return ValueTask.FromResult(64);
        }
    }
}
