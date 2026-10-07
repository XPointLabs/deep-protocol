using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class MailboxGrantAcquisitionCodecTests
{
    [Fact]
    public void Xmg2AndSuccessfulXmc2BindExactRequestAndReachabilityScopedHolder()
    {
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x31));
        var issuer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x51));
        var network = Bytes(16, 0x11);
        var capability = Bytes(32, 0x21);
        var pmsHash = Bytes(32, 0x41);
        var request = SignedRequest(holder, network, capability, pmsHash);
        var crypto = new SodiumMailboxCapabilityCrypto();
        var placement = MailboxPlacementCommitment.Compute(new BlindedPlacementId(capability));
        var current = SignedGrant(crypto, issuer, holder.PublicKey, network, placement, pmsHash, 7, 0x61);
        var result = ContactCodecValidation.AuthorRecord("XMC2",
        [
            network, request.Field(2), U16(1), U64(110), SHA256.HashData(request.CanonicalBytes.Span),
            U64(120), request.Field(11), MailboxAuthenticatedCapabilityCodec.EncodeGrant(current)
        ]);

        Assert.Equal(435, request.CanonicalBytes.Length);
        Assert.Equal(510, result.CanonicalBytes.Length);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        ContactCodec.ValidateMailboxGrantResultBinding(request, result);
    }

    [Fact]
    public void Xmc2FailureCarriesNoRouteOrGrantAuthority()
    {
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x32));
        var request = SignedRequest(holder, Bytes(16, 0x12), Bytes(32, 0x22), Bytes(32, 0x42));
        var failure = ContactCodecValidation.AuthorRecord("XMC2",
        [
            request.Field(1), request.Field(2), U16(2), U64(110),
            SHA256.HashData(request.CanonicalBytes.Span), U64(120), new byte[32],
            ReadOnlyMemory<byte>.Empty
        ]);

        Assert.Equal(206, failure.CanonicalBytes.Length);
        ContactCodec.ValidateMailboxGrantResultBinding(request, failure);
    }

    [Fact]
    public void Xmg2RejectsInvalidProofAndXmc2RejectsChangedRequestBinding()
    {
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x33));
        var request = SignedRequest(holder, Bytes(16, 0x13), Bytes(32, 0x23), Bytes(32, 0x43));
        var fields = Enumerable.Range(1, 12).Select(request.Field).ToArray();
        var changedSignature = fields[11].ToArray();
        changedSignature[0] ^= 1;
        fields[11] = changedSignature;
        var invalidProof = ContactCodecValidation.AuthorRecord("XMG2", fields);
        var proofError = Assert.Throws<ContactFormatException>(
            () => ContactCodec.VerifyMailboxGrantHolderSignature(invalidProof));
        Assert.Equal(ContactValidationStage.Signature, proofError.Stage);

        var changedHash = Bytes(32, 0x91);
        var result = ContactCodecValidation.AuthorRecord("XMC2",
        [
            request.Field(1), request.Field(2), U16(4), U64(110), changedHash,
            U64(120), new byte[32], ReadOnlyMemory<byte>.Empty
        ]);
        var bindingError = Assert.Throws<ContactFormatException>(
            () => ContactCodec.ValidateMailboxGrantResultBinding(request, result));
        Assert.Equal(ContactValidationStage.Closure, bindingError.Stage);
    }

    [Fact]
    public void Xmc2RejectsIssuerSignedSelectionSubstitutionAgainstExactRoute()
    {
        var records = ContactCodecTests.Records.RouteClosure;
        var routeBytes = ContactRouteClosureCodec.EncodeRecords(
            [records.Xrr, records.Xra, records.Xrc, records.Xss, records.Pmt, records.Pms]);
        var route = ContactRouteClosureCodec.Decode(routeBytes);
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x31));
        var issuer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x51));
        var crypto = new SodiumMailboxCapabilityCrypto();
        var request = SignedRequest(holder, route.Reachability.Field(1).ToArray(),
            route.Reachability.Field(10).ToArray(), route.Selection.ArtifactHash.ToArray(), route.ExactHash.ToArray());
        var grant = SignedGrant(crypto, issuer, holder.PublicKey, request.Field(1).ToArray(),
            MailboxPlacementCommitment.Compute(new BlindedPlacementId(route.Reachability.Field(10).Span)),
            route.Projection.ArtifactHash.ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(route.Selection.Field(4).Span), 0x61);
        grant = crypto.SignGrant(grant with { SelectionInput = route.Selection.Field(3).ToArray() }, issuer.PrivateKey);
        _ = MailboxGrantResultAuthor.AuthorSuccess(request, routeBytes, grant, 110, 120);
        var substituted = crypto.SignGrant(grant with { SelectionInput = Bytes(32, 0xb1) }, issuer.PrivateKey);
        var failure = Assert.Throws<ContactFormatException>(() =>
            MailboxGrantResultAuthor.AuthorSuccess(request, routeBytes, substituted, 110, 120));
        Assert.Equal(ContactValidationStage.Closure, failure.Stage);
    }

    [Fact]
    public void Xmg2RejectsRetiredMagicAndCopiedOldPurposeSignature()
    {
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x34));
        var request = SignedRequest(holder, Bytes(16, 0x14), Bytes(32, 0x24), Bytes(32, 0x44));
        var retired = request.CanonicalBytes.ToArray();
        "XMG1"u8.CopyTo(retired);
        Assert.Equal(ContactValidationStage.Header,
            Assert.Throws<ContactFormatException>(() => ContactCodec.Decode(retired)).Stage);

        // Compose hostile old signing bytes only; never decode or authorize XMG1.
        var oldProjection = request.SigningProjection.ToArray();
        "XMG1"u8.CopyTo(oldProjection);
        var oldInput = ContactCodec.SignatureInput("Deep/ContactResolver/V1/XMG1", oldProjection);
        var fields = Enumerable.Range(1, 12).Select(request.Field).ToArray();
        fields[11] = PublicKeyAuth.SignDetached(oldInput, holder.PrivateKey);
        var copied = ContactCodecValidation.AuthorRecord("XMG2", fields);
        Assert.Equal(ContactValidationStage.Signature,
            Assert.Throws<ContactFormatException>(() => ContactCodec.VerifyMailboxGrantHolderSignature(copied)).Stage);
    }

    [Fact]
    public void Xmg2RouteIntentIsSignedNonzeroAndRequiredForBothRoles()
    {
        var records = ContactCodecTests.Records.RouteClosure;
        var route = ContactRouteClosureCodec.Decode(ContactRouteClosureCodec.EncodeRecords(
            [records.Xrr, records.Xra, records.Xrc, records.Xss, records.Pmt, records.Pms]));
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x35));
        var deposit = SignedRequest(holder, route.Reachability.Field(1).ToArray(),
            route.Reachability.Field(10).ToArray(), route.Selection.ArtifactHash.ToArray(), route.ExactHash.ToArray());
        var fields = Enumerable.Range(1, 12).Select(deposit.Field).ToArray();
        fields[6] = ContactCodec.ArtifactReference("PMT2", route.Projection).CanonicalBytes;
        var owner = Bytes(32, 0xb8);
        foreach (var domain in new byte[] { 1, 2 })
        {
            fields[3] = domain == 1 ? route.Reachability.Field(10) : owner;
            fields[5] = new byte[] { domain };
            fields[10] = route.ExactHash;
            var exact = Resign(holder, fields);
            ContactRecord Verify(ContactRecord candidate) => domain == 1
                ? MailboxGrantRequestVerifier.VerifyDeposit(candidate.CanonicalBytes.Span, route, 110)
                : MailboxGrantRequestVerifier.VerifyRetrieve(candidate.CanonicalBytes.Span, route, owner, 110);
            _ = Verify(exact);
            fields[10] = Bytes(32, 0xc8);
            var unsignedSubstitution = ContactCodecValidation.AuthorRecord("XMG2", fields);
            Assert.Equal(ContactValidationStage.Signature,
                Assert.Throws<ContactFormatException>(() => Verify(unsignedSubstitution)).Stage);
            var signedSubstitution = Resign(holder, fields);
            ContactCodec.VerifyMailboxGrantHolderSignature(signedSubstitution);
            Assert.Equal("MailboxGrantRequestRouteBindingMismatch",
                Assert.Throws<ContactFormatException>(() => Verify(signedSubstitution)).Code);
            fields[10] = new byte[32];
            Assert.Equal(ContactValidationStage.Scalar,
                Assert.Throws<ContactFormatException>(() => ContactCodecValidation.AuthorRecord("XMG2", fields)).Stage);
        }
    }

    [Fact]
    public void Xmc2RejectsChangedRouteIntentEvenWithMatchingRequestDigest()
    {
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x36));
        var issuer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x56));
        var request = SignedRequest(holder, Bytes(16, 0x16), Bytes(32, 0x26), Bytes(32, 0x46));
        var grant = SignedGrant(new SodiumMailboxCapabilityCrypto(), issuer, holder.PublicKey,
            request.Field(1).ToArray(), Bytes(32, 0x66), Bytes(32, 0x76), 7, 0x86);
        var result = ContactCodecValidation.AuthorRecord("XMC2",
        [
            request.Field(1), request.Field(2), U16(1), U64(110), SHA256.HashData(request.CanonicalBytes.Span),
            U64(120), Bytes(32, 0xd1), MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)
        ]);
        Assert.Equal("MailboxGrantResultRouteIntentMismatch",
            Assert.Throws<ContactFormatException>(() => ContactCodec.ValidateMailboxGrantResultBinding(request, result)).Code);
    }

    [Fact]
    public void RetiredXmc1HasNoReaderEvenWithCurrentNonSuccessWidth()
    {
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x31));
        var request = SignedRequest(holder, Bytes(16, 0x11), Bytes(32, 0x21), Bytes(32, 0x41));
        var result = MailboxGrantResultAuthor.AuthorFailure(request,
            MailboxGrantAcquisitionResultCode.Unavailable, 110, 120).CanonicalBytes.ToArray();
        "XMC1"u8.CopyTo(result);
        var error = Assert.Throws<ContactFormatException>(() => ContactCodec.Decode(result));
        Assert.Equal(ContactValidationStage.Header, error.Stage);
    }

    private static ContactRecord SignedRequest(
        KeyPair holder,
        byte[] network,
        byte[] capability,
        byte[] pmsHash,
        byte[]? exactRouteHash = null)
    {
        ReadOnlyMemory<byte>[] fields =
        [
            network, Bytes(32, 0x20), Bytes(32, 0x19), capability, holder.PublicKey, new byte[] { 1 },
            Reference("PMT2", 0x30), pmsHash, U64(100), U64(120),
            exactRouteHash ?? Bytes(32, 0x50), Bytes(64, 0x60)
        ];
        return Resign(holder, fields);
    }

    private static ContactRecord Resign(KeyPair holder, ReadOnlyMemory<byte>[] fields)
    {
        var unsigned = ContactCodecValidation.AuthorRecord("XMG2", fields);
        fields[11] = PublicKeyAuth.SignDetached(unsigned.SignatureInput.ToArray(), holder.PrivateKey);
        return ContactCodecValidation.AuthorRecord("XMG2", fields);
    }

    private static MailboxAuthenticatedGrant SignedGrant(
        SodiumMailboxCapabilityCrypto crypto,
        KeyPair issuer,
        byte[] holderPublic,
        byte[] network,
        byte[] placement,
        byte[] membership,
        ulong epoch,
        byte seed) => crypto.SignGrant(new MailboxAuthenticatedGrant
        {
            Domain = MailboxCapabilityDomain.Deposit,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            NetworkId = network,
            Epoch = epoch,
            Generation = 1,
            Serial = Bytes(16, seed),
            NotBeforeUnixSeconds = 100,
            ExpiresAtUnixSeconds = 200,
            OverlapUntilUnixSeconds = 0,
            PlacementCommitment = placement,
            MembershipCommitment = membership,
            IssuerPublicKey = issuer.PublicKey,
            HolderPublicKey = holderPublic,
            SelectionInput = Bytes(32, 0xa1),
            IssuerSignature = ReadOnlyMemory<byte>.Empty
        }, issuer.PrivateKey);

    private static byte[] Reference(string magic, byte seed)
    {
        var result = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        Bytes(32, seed).CopyTo(result, 6);
        return result;
    }

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static byte[] Bytes(int length, byte seed) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index))).ToArray();
}
