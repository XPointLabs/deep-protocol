using System.Runtime.InteropServices;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class ContactRouteAdvertisementAuthorTests
{
    [Fact]
    public async Task GenesisAdvertisement_IsDeviceSignedAndProposalBound()
    {
        var fixture = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var proposal = await fixture.VerifyProposalAsync();
        var signer = new Signer(fixture.Identity.Device, fixture.Identity.VerifiedRecipient);
        var request = Request(proposal);

        var authored = await ContactRouteAdvertisementAuthor.AuthorGenesisAsync(
            request, signer);
        var parsed = ContactCodec.Decode("XRA1", authored.ExactXra1.Span);

        Assert.Equal([ContactDeviceSignaturePurpose.RouteAdvertisement], signer.Purposes);
        Assert.Equal(proposal.NetworkId.ToArray(), parsed.Field(1).ToArray());
        Assert.Equal(proposal.Pmt2ArtifactReference.ToArray(), parsed.Field(5).ToArray());
        Assert.Equal(authored.PlacementInput.ToArray(), parsed.Field(6).ToArray());
        Assert.Equal(proposal.RecipientDeviceId.ToArray(), parsed.Field(14).ToArray());
        Assert.Equal(proposal.RecipientDpd1Reference.ToArray(), parsed.Field(15).ToArray());
        ContactCodec.VerifyDeviceSignature(parsed, proposal.RecipientDevicePublicKey.Span);

        var copy = authored.PlacementInput;
        MemoryMarshal.AsMemory(copy).Span.Fill(0);
        Assert.NotEqual(new byte[32], authored.PlacementInput.ToArray());
    }

    [Fact]
    public async Task WrongDeviceSigner_IsRejectedBeforeCustodyCallback()
    {
        var fixture = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var proposal = await fixture.VerifyProposalAsync();
        var wrong = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xd1));
        var signer = new Signer(wrong, fixture.Identity.VerifiedRecipient,
            deviceId: Bytes(32, 0xd2));

        var error = await Assert.ThrowsAsync<ContactPublicationAuthoringException>(() =>
            ContactRouteAdvertisementAuthor.AuthorGenesisAsync(
                Request(proposal), signer).AsTask());

        Assert.Equal("CustodySignerMismatch", error.Code);
        Assert.Empty(signer.Purposes);
    }

    [Fact]
    public async Task InvalidReturnedSignature_IsRejected()
    {
        var fixture = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var proposal = await fixture.VerifyProposalAsync();
        var signer = new InvalidSigner(
            proposal.RecipientDeviceId, proposal.RecipientDevicePublicKey);

        var error = await Assert.ThrowsAsync<ContactPublicationAuthoringException>(() =>
            ContactRouteAdvertisementAuthor.AuthorGenesisAsync(
                Request(proposal), signer).AsTask());

        Assert.Equal("InvalidCustodySignature", error.Code);
    }

    [Fact]
    public async Task ExactAdvertisement_RehydratesOnlyAgainstItsVerifiedProposal()
    {
        var fixture = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var proposal = await fixture.VerifyProposalAsync();
        var authored = await ContactRouteAdvertisementAuthor.AuthorGenesisAsync(
            Request(proposal),
            new Signer(fixture.Identity.Device, fixture.Identity.VerifiedRecipient));

        var rehydrated = ContactRouteAdvertisementVerifier.VerifyExact(
            proposal, authored.ExactXra1);

        Assert.Equal(authored.ExactXra1.ToArray(), rehydrated.ExactXra1.ToArray());
        Assert.Equal(authored.PlacementInput.ToArray(), rehydrated.PlacementInput.ToArray());

        var changed = authored.ExactXra1.ToArray();
        changed[^1] ^= 1;
        var error = Assert.Throws<ContactPublicationAuthoringException>(() =>
            ContactRouteAdvertisementVerifier.VerifyExact(proposal, changed));
        Assert.Equal("InvalidRouteAdvertisementInput", error.Code);
    }

    private static ContactRouteAdvertisementAuthoringRequest Request(
        VerifiedContactRouteProposalAuthority proposal) =>
        new(proposal, 100, Bytes(32, 0xa1), Bytes(32, 0xa2), Bytes(32, 0xa3),
            29, 60);

    private static byte[] Bytes(int length, byte start) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(start + index))).ToArray();

    private sealed class Signer : IContactDeviceCustodySigner
    {
        private readonly KeyPair key;
        private readonly byte[] deviceId;
        private readonly List<ContactDeviceSignaturePurpose> purposes = [];

        internal Signer(KeyPair key, VerifiedDevice device, byte[]? deviceId = null)
        {
            this.key = key;
            this.deviceId = deviceId ?? device.Certificate.DeviceId.ToArray();
        }

        public ReadOnlyMemory<byte> DeviceId => deviceId.ToArray();
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey.ToArray();
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, 0xb1);
        internal ContactDeviceSignaturePurpose[] Purposes => purposes.ToArray();

        public ValueTask<int> SignAsync(
            ContactDeviceSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            purposes.Add(request.Purpose);
            PublicKeyAuth.SignDetached(
                request.SigningInput.ToArray(), key.PrivateKey).CopyTo(signature64);
            return ValueTask.FromResult(64);
        }
    }

    private sealed class InvalidSigner(
        ReadOnlyMemory<byte> deviceId,
        ReadOnlyMemory<byte> publicKey) : IContactDeviceCustodySigner
    {
        public ReadOnlyMemory<byte> DeviceId => deviceId.ToArray();
        public ReadOnlyMemory<byte> Ed25519PublicKey => publicKey.ToArray();
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, 0xc1);

        public ValueTask<int> SignAsync(
            ContactDeviceSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            signature64.Span.Fill(0x5a);
            return ValueTask.FromResult(64);
        }
    }
}
