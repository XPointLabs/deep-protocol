using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class MailboxGrantAcquisitionCodecTests
{
    [Fact]
    public void Xmg1AndSuccessfulXmc1BindExactRequestAndReachabilityScopedHolder()
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
        var result = ContactCodecValidation.AuthorRecord("XMC1",
        [
            network, request.Field(2), U16(1), U64(110), SHA256.HashData(request.CanonicalBytes.Span),
            U64(120), Bytes(32, 0x81), MailboxAuthenticatedCapabilityCodec.EncodeGrant(current)
        ]);

        Assert.Equal(435, request.CanonicalBytes.Length);
        Assert.Equal(478, result.CanonicalBytes.Length);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        ContactCodec.ValidateMailboxGrantResultBinding(request, result);
    }

    [Fact]
    public void Xmc1FailureCarriesNoRouteOrGrantAuthority()
    {
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x32));
        var request = SignedRequest(holder, Bytes(16, 0x12), Bytes(32, 0x22), Bytes(32, 0x42));
        var failure = ContactCodecValidation.AuthorRecord("XMC1",
        [
            request.Field(1), request.Field(2), U16(2), U64(110),
            SHA256.HashData(request.CanonicalBytes.Span), U64(120), new byte[32],
            ReadOnlyMemory<byte>.Empty
        ]);

        Assert.Equal(206, failure.CanonicalBytes.Length);
        ContactCodec.ValidateMailboxGrantResultBinding(request, failure);
    }

    [Fact]
    public void Xmg1RejectsInvalidProofAndXmc1RejectsChangedRequestBinding()
    {
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x33));
        var request = SignedRequest(holder, Bytes(16, 0x13), Bytes(32, 0x23), Bytes(32, 0x43));
        var fields = Enumerable.Range(1, 12).Select(request.Field).ToArray();
        var changedSignature = fields[11].ToArray();
        changedSignature[0] ^= 1;
        fields[11] = changedSignature;
        var invalidProof = ContactCodecValidation.AuthorRecord("XMG1", fields);
        var proofError = Assert.Throws<ContactFormatException>(
            () => ContactCodec.VerifyMailboxGrantHolderSignature(invalidProof));
        Assert.Equal(ContactValidationStage.Signature, proofError.Stage);

        var changedHash = Bytes(32, 0x91);
        var result = ContactCodecValidation.AuthorRecord("XMC1",
        [
            request.Field(1), request.Field(2), U16(4), U64(110), changedHash,
            U64(120), new byte[32], ReadOnlyMemory<byte>.Empty
        ]);
        var bindingError = Assert.Throws<ContactFormatException>(
            () => ContactCodec.ValidateMailboxGrantResultBinding(request, result));
        Assert.Equal(ContactValidationStage.Closure, bindingError.Stage);
    }

    private static ContactRecord SignedRequest(
        KeyPair holder,
        byte[] network,
        byte[] capability,
        byte[] pmsHash)
    {
        ReadOnlyMemory<byte>[] fields =
        [
            network, Bytes(32, 0x20), Bytes(32, 0x19), capability, holder.PublicKey, new byte[] { 1 },
            Reference("PMT2", 0x30), pmsHash, U64(100), U64(120),
            Bytes(32, 0x50), Bytes(64, 0x60)
        ];
        var unsigned = ContactCodecValidation.AuthorRecord("XMG1", fields);
        fields[11] = PublicKeyAuth.SignDetached(unsigned.SignatureInput.ToArray(), holder.PrivateKey);
        return ContactCodecValidation.AuthorRecord("XMG1", fields);
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
