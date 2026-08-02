using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Sodium;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class ProductionMailboxHolderProofTests
{
    [Fact]
    public void CanonicalTranscript_MatchesIndependentEncoderAndGoldenDigest()
    {
        var input = Input();
        var canonical = ProductionMailboxHolderProof.GetSigningBytes(input);
        var independent = IndependentEncode(input);
        Assert.Equal(independent, canonical);
        Assert.Equal(439, canonical.Length);
        Assert.Equal("3DF4F1CEC1BD161965CA875F751D54EC4C60CBFBF1B4B1DF7E446733F1704510",
            Convert.ToHexString(SHA256.HashData(canonical)));
    }

    [Fact]
    public void HolderAndOwnerVerify_WhileIntentPlatformAuthorityAndRouteTamperFail()
    {
        var input = Input();
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(40, 32));
        var owner = PublicKeyAuth.GenerateKeyPair(Bytes(80, 32));
        input = input with { HolderEd25519PublicKey = holder.PublicKey, MailboxOwnerEd25519PublicKey = owner.PublicKey };
        var canonical = ProductionMailboxHolderProof.GetSigningBytes(input);
        var holderSignature = PublicKeyAuth.SignDetached(canonical, holder.PrivateKey);
        var ownerSignature = PublicKeyAuth.SignDetached(canonical, owner.PrivateKey);
        var verifier = new SodiumProductionMailboxHolderProofSignatureVerifier();
        ProductionMailboxHolderProof.VerifyHolder(input, holderSignature, verifier);
        ProductionMailboxHolderProof.VerifyOwner(input, ownerSignature, verifier);

        foreach (var changed in new[]
        {
            input with { Platform = ProductionMailboxClientPlatform.Windows },
            input with { CanonicalAuthorityHash = Bytes(111, 32) },
            input with { HolderEd25519PublicKey = Bytes(110, 32) },
            input with { MailboxOwnerEd25519PublicKey = Bytes(109, 32) },
            input with { SigningCertificateSha256 = Bytes(108, 32) },
            input with { BuildArtifactSha256 = Bytes(107, 32) },
            input with { IdempotencyKey = Bytes(106, 32) },
            input with { EntitlementCommitment = Bytes(105, 32) },
            input with { ChallengeId = Bytes(104, 16) },
            input with { Challenge = Bytes(113, 32) },
            input with { ProofOfWorkNonce = input.ProofOfWorkNonce + 1 }
        })
            Assert.Equal(ProductionMailboxHolderProofError.InvalidSignature,
                Assert.Throws<ProductionMailboxHolderProofException>(() =>
                    ProductionMailboxHolderProof.VerifyHolder(changed, holderSignature, verifier)).Error);
        Assert.Equal(ProductionMailboxHolderProofError.InvalidIntent,
            Assert.Throws<ProductionMailboxHolderProofException>(() =>
                ProductionMailboxHolderProof.VerifyOwner(
                    input with { Intent = ProductionMailboxIssuanceIntent.PeerDeposit }, ownerSignature, verifier)).Error);
        Assert.Equal(ProductionMailboxHolderProofError.InvalidRoute,
            Assert.Throws<ProductionMailboxHolderProofException>(() =>
                ProductionMailboxHolderProof.VerifyHolder(
                    input with { Intent = ProductionMailboxIssuanceIntent.PeerDeposit }, holderSignature, verifier)).Error);

        var mutableHolder = holder.PublicKey.ToArray();
        var mutableInput = input with { HolderEd25519PublicKey = mutableHolder };
        var mutableSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxHolderProof.GetSigningBytes(mutableInput), holder.PrivateKey);
        ProductionMailboxHolderProof.VerifyHolder(mutableInput, mutableSignature,
            new MutatingVerifier(() => mutableHolder[0] ^= 1));

        var peerInput = input with
        {
            Intent = ProductionMailboxIssuanceIntent.PeerDeposit,
            BlindedMailboxId = Bytes(120, 32), BlindedPlacementId = Bytes(140, 32),
            SelectionInputCommitment = Bytes(160, 32)
        };
        var peerSignature = PublicKeyAuth.SignDetached(
            ProductionMailboxHolderProof.GetSigningBytes(peerInput), holder.PrivateKey);
        foreach (var changed in new[]
        {
            peerInput with { BlindedMailboxId = Bytes(121, 32) },
            peerInput with { BlindedPlacementId = Bytes(141, 32) },
            peerInput with { SelectionInputCommitment = Bytes(161, 32) }
        })
            Assert.Equal(ProductionMailboxHolderProofError.InvalidSignature,
                Assert.Throws<ProductionMailboxHolderProofException>(() =>
                    ProductionMailboxHolderProof.VerifyHolder(changed, peerSignature, verifier)).Error);
    }

    [Fact]
    public void RouteAndFieldValidation_FailClosed()
    {
        var input = Input();
        AssertError(input with { NetworkId = new byte[16] }, ProductionMailboxHolderProofError.InvalidField);
        AssertError(input with { BlindedMailboxId = new byte[31] }, ProductionMailboxHolderProofError.InvalidField);
        AssertError(input with { BlindedMailboxId = Bytes(1, 32) }, ProductionMailboxHolderProofError.InvalidRoute);
        AssertError(input with
        {
            BlindedMailboxId = Bytes(1, 32), BlindedPlacementId = Bytes(2, 32),
            SelectionInputCommitment = Bytes(3, 32)
        }, ProductionMailboxHolderProofError.InvalidRoute);
        AssertError(input with
        {
            Intent = ProductionMailboxIssuanceIntent.PeerDeposit,
            BlindedMailboxId = new byte[32], BlindedPlacementId = new byte[32], SelectionInputCommitment = new byte[32]
        }, ProductionMailboxHolderProofError.InvalidRoute);
    }

    private static void AssertError(ProductionMailboxHolderProofInput input, ProductionMailboxHolderProofError error) =>
        Assert.Equal(error, Assert.Throws<ProductionMailboxHolderProofException>(() =>
            ProductionMailboxHolderProof.GetSigningBytes(input)).Error);

    private static ProductionMailboxHolderProofInput Input() => new()
    {
        Intent = ProductionMailboxIssuanceIntent.LocalOwner,
        Platform = ProductionMailboxClientPlatform.Android,
        NetworkId = Bytes(1, 16), CanonicalAuthorityHash = Bytes(20, 32),
        HolderEd25519PublicKey = Bytes(40, 32), MailboxOwnerEd25519PublicKey = Bytes(80, 32),
        BlindedMailboxId = new byte[32], BlindedPlacementId = new byte[32],
        SelectionInputCommitment = new byte[32], SigningCertificateSha256 = Bytes(180, 32),
        BuildArtifactSha256 = Bytes(200, 32), IdempotencyKey = Bytes(210, 32),
        EntitlementCommitment = Bytes(211, 32), ChallengeId = Bytes(220, 16),
        Challenge = Bytes(230, 32), ProofOfWorkNonce = 0x0102030405060708
    };

    private static byte[] IndependentEncode(ProductionMailboxHolderProofInput input)
    {
        using var stream = new MemoryStream();
        stream.Write(System.Text.Encoding.ASCII.GetBytes("Deep/production-mailbox/holder-proof/v1"));
        stream.Write("PHP1"u8); stream.WriteByte(1); stream.WriteByte((byte)input.Intent);
        stream.WriteByte((byte)input.Platform); stream.WriteByte(0);
        foreach (var value in new[]
        {
            input.NetworkId, input.CanonicalAuthorityHash, input.HolderEd25519PublicKey,
            input.MailboxOwnerEd25519PublicKey, input.BlindedMailboxId, input.BlindedPlacementId,
            input.SelectionInputCommitment, input.SigningCertificateSha256, input.BuildArtifactSha256,
            input.IdempotencyKey, input.EntitlementCommitment, input.ChallengeId, input.Challenge
        }) stream.Write(value.Span);
        Span<byte> nonce = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(nonce, input.ProofOfWorkNonce);
        stream.Write(nonce);
        return stream.ToArray();
    }

    private static byte[] Bytes(byte seed, int length) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index))).ToArray();

    private sealed class MutatingVerifier(Action mutate) : IProductionMailboxHolderProofSignatureVerifier
    {
        private readonly SodiumProductionMailboxHolderProofSignatureVerifier inner = new();
        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature)
        {
            mutate();
            return inner.Verify(publicKey, signingBytes, signature);
        }
    }
}
