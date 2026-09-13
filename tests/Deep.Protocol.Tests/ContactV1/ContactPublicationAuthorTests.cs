using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class ContactPublicationAuthorTests
{
    [Fact]
    public async Task AuthorsExactPermanentPublicationFromVerifiedCapabilitiesAndCustody()
    {
        var fixture = await Fixture.CreateAsync();
        var signer = new Signer(fixture.Identity.Device, fixture.Identity.VerifiedRecipient);
        var preKey = await ContactPublicationAuthor.AuthorPreKeyServiceAsync(
            new ContactPreKeyServiceAuthoringRequest(
                fixture.Identity.VerifiedRecipient, fixture.Identity.Authorization,
                32, 8, 20, 80), signer);

        var authored = await ContactPublicationAuthor.AuthorPermanentAsync(
            new ContactBundleAuthoringRequest(
                fixture.Identity.Authorization, fixture.Identity.Freshness, fixture.Route,
                [preKey], 20, 80, fixture.Identity.BootId,
                fixture.Identity.CurrentMonotonicSample), signer);

        Assert.Equal(0UL, preKey.Generation);
        Assert.Equal(0UL, authored.Generation);
        Assert.Equal(authored.Bundle.CanonicalBytes.ToArray(),
            authored.Verified.Bundle.CanonicalBytes.ToArray());
        Assert.Equal(authored.ResolverResponse.CanonicalBytes.ToArray(),
            authored.Verified.ResolverResponse.CanonicalBytes.ToArray());
        using var resolution = PermanentContactResolutionDerivation.Derive(
            fixture.Authority.NetworkId.Span, fixture.Identity.Binding.DeepId);
        Assert.Equal(resolution.LocatorHash.ToArray(), authored.LocatorHash.ToArray());
        var opened = Dcr1ObjectProtectionCodec.OpenPermanent(
            authored.ProtectedDcr1.Span, fixture.Authority.NetworkId.Span,
            fixture.Identity.Binding.DeepId, resolution);
        Assert.Equal(authored.ResolverResponse.CanonicalBytes.ToArray(),
            opened.CanonicalBytes.ToArray());
        Assert.Equal(
            fixture.Identity.VerifiedRecipient.Certificate.DeviceId.ToArray(),
            ContactCodec.DecodeXps1(preKey.ExactXps1.Span).DeviceId);
        Assert.Equal(
            [ContactDeviceSignaturePurpose.PreKeyService,
                ContactDeviceSignaturePurpose.ContactBundle],
            signer.Purposes);
    }

    [Fact]
    public async Task RejectsCustodySignerForAnotherVerifiedKey()
    {
        var fixture = await Fixture.CreateAsync();
        var other = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xef));
        var signer = new MismatchedSigner(
            fixture.Identity.VerifiedRecipient.Certificate.DeviceId.ToArray(), other);

        var error = await Assert.ThrowsAsync<ContactPublicationAuthoringException>(() =>
            ContactPublicationAuthor.AuthorPreKeyServiceAsync(
                new ContactPreKeyServiceAuthoringRequest(
                    fixture.Identity.VerifiedRecipient, fixture.Identity.Authorization,
                    32, 8, 20, 80), signer).AsTask());

        Assert.Equal("CustodySignerMismatch", error.Code);
        Assert.Equal(0, signer.CallCount);
    }

    private sealed class Fixture
    {
        private Fixture(
            ContactNetworkAuthorityVerifierTests.Fixture core,
            VerifiedContactNetworkAuthority authority,
            VerifiedContactRouteClosure route)
        {
            Core = core;
            Authority = authority;
            Route = route;
        }

        internal ContactNetworkAuthorityVerifierTests.Fixture Core { get; }
        internal ContactCodecSecurityTests.CryptoDcrFixture Identity => Core.Identity;
        internal VerifiedContactNetworkAuthority Authority { get; }
        internal VerifiedContactRouteClosure Route { get; }

        internal static async Task<Fixture> CreateAsync()
        {
            var core = ContactNetworkAuthorityVerifierTests.Fixture.Create();
            var authority = await core.VerifyAsync();
            var device = core.Identity.Device;
            var witnesses = core.Witnesses.Take(authority.WitnessThreshold).ToArray();
            var network = core.Network;
            var pmt = core.Pmt;
            var pms = core.Pms;
            var xra = DeviceRecord("XRA1",
            [
                network, Bytes(32, 8), U64(0), new byte[32],
                ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,
                pms.Field(3), U16(1), U32(10), Bytes(32, 10), Bytes(32, 11),
                Bytes(32, 12), U64(20), U64(80), authority.RecipientDeviceId,
                authority.RecipientDpd1Reference, Bytes(64, 14),
            ], 16, device);
            var ranked = pms.Field(6).ToArray();
            var replicaEntries = new byte[ranked.Length * 2];
            for (var index = 0; index < ranked.Length / 32; index++)
            {
                ranked.AsSpan(index * 32, 32)
                    .CopyTo(replicaEntries.AsSpan(index * 64, 32));
                Bytes(32, checked((byte)(0xd0 + index)))
                    .CopyTo(replicaEntries, index * 64 + 32);
            }
            var xrc = WitnessRecord("XRC1",
            [
                network, Bytes(32, 15), U64(0), new byte[32],
                ContactCodec.ArtifactReference("XRA1", xra).CanonicalBytes,
                ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,
                pms.ArtifactHash, authority.Xnv1CoreReference,
                authority.Xnh1CoreReference, Bytes(32, 16), xra.Field(10),
                xra.Field(11), U64(1), new byte[] { 2 }, replicaEntries,
                U64(20), U64(20), U64(80), authority.Adh1CoreReference,
                new byte[] { checked((byte)witnesses.Length) },
                DummyReceipts(witnesses),
            ], 21, witnesses);
            var xss = WitnessRecord("XSS1",
            [
                network, xrc.Field(2), U64(1), xrc.CoreHash,
                ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,
                ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,
                ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,
                authority.Xnv1CoreReference, pms.ArtifactHash, U64(20), U64(80),
                authority.Adh1CoreReference,
                new byte[] { checked((byte)witnesses.Length) },
                DummyReceipts(witnesses),
            ], 14, witnesses);
            var xrr = DeviceRecord("XRR1",
            [
                network, Bytes(32, 17), U64(0), new byte[32],
                ContactCodec.ArtifactReference("XRA1", xra).CanonicalBytes,
                ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,
                ContactCodec.ArtifactReference("XSS1", xss).CanonicalBytes,
                ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,
                pms.ArtifactHash, Bytes(32, 18), xra.Field(9), new byte[] { 3 },
                U32(10), U16(1), U64(20), U64(20), U64(80),
                authority.RecipientDpd1Reference, Bytes(64, 19), new byte[2],
            ], 19, device);
            var xir = DeviceRecord("XIR1",
            [
                network, Bytes(32, 20), U64(0), new byte[32],
                ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,
                xra.Field(6), xra.Field(10), xra.Field(11), new byte[] { 1 },
                U32(0), U16(2), xra.Field(9), U64(20), U64(80),
                authority.RecipientDpd1Reference, authority.Dca1Reference,
                Bytes(64, 21), ContactCodec.ArtifactReference("XRA1", xra).CanonicalBytes,
            ], 17, device);
            var route = ContactCodec.VerifyRouteUpdateClosure(
                xir, xrr, xra, xrc, xss, pmt, pms, authority);
            return new Fixture(core, authority, route);
        }
    }

    private sealed class Signer(KeyPair key, Deep.Protocol.DeepNative.VerifiedDevice device)
        : IContactDeviceCustodySigner
    {
        private readonly List<ContactDeviceSignaturePurpose> purposes = [];
        public ReadOnlyMemory<byte> DeviceId => device.Certificate.DeviceId;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, 0xcc);
        internal ContactDeviceSignaturePurpose[] Purposes => purposes.ToArray();

        public ValueTask<int> SignAsync(
            ContactDeviceSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            purposes.Add(request.Purpose);
            var signature = PublicKeyAuth.SignDetached(
                request.SigningInput.ToArray(), key.PrivateKey);
            signature.CopyTo(signature64);
            return ValueTask.FromResult(signature.Length);
        }
    }

    private sealed class MismatchedSigner(byte[] deviceId, KeyPair key)
        : IContactDeviceCustodySigner
    {
        public ReadOnlyMemory<byte> DeviceId => deviceId;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, 0xcd);
        internal int CallCount { get; private set; }

        public ValueTask<int> SignAsync(
            ContactDeviceSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken)
        {
            CallCount++;
            throw new InvalidOperationException("Must not be called.");
        }
    }

    private static ContactRecord DeviceRecord(
        string magic,
        IReadOnlyList<ReadOnlyMemory<byte>> input,
        int signatureTag,
        KeyPair signer)
    {
        var fields = input.ToArray();
        var provisional = ContactCodecValidation.AuthorRecord(magic, fields);
        fields[signatureTag - 1] = PublicKeyAuth.SignDetached(
            provisional.SignatureInput.ToArray(), signer.PrivateKey);
        return ContactCodecValidation.AuthorRecord(magic, fields);
    }

    private static ContactRecord WitnessRecord(
        string magic,
        IReadOnlyList<ReadOnlyMemory<byte>> input,
        int signatureTag,
        IReadOnlyList<ContactCodecSecurityTests.CryptoDcrFixture.Witness> witnesses)
    {
        var fields = input.ToArray();
        var provisional = ContactCodecValidation.AuthorRecord(magic, fields);
        var receipts = new byte[96 * witnesses.Count];
        for (var index = 0; index < witnesses.Count; index++)
        {
            witnesses[index].Id.CopyTo(receipts, index * 96);
            PublicKeyAuth.SignDetached(
                    provisional.SignatureInput.ToArray(), witnesses[index].Key.PrivateKey)
                .CopyTo(receipts, index * 96 + 32);
        }
        fields[signatureTag - 1] = receipts;
        return ContactCodecValidation.AuthorRecord(magic, fields);
    }

    private static byte[] DummyReceipts(
        IReadOnlyList<ContactCodecSecurityTests.CryptoDcrFixture.Witness> witnesses)
    {
        var receipts = new byte[96 * witnesses.Count];
        for (var index = 0; index < witnesses.Count; index++)
        {
            witnesses[index].Id.CopyTo(receipts, index * 96);
            Bytes(64, checked((byte)(0x90 + index))).CopyTo(receipts, index * 96 + 32);
        }
        return receipts;
    }

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();

    private static byte[] U16(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] U32(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }
}
