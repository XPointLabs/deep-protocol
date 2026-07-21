using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;
using Sodium;

namespace Deep.Protocol.ProfileCarrier.Tests;

public sealed class Ed25519MembershipSignatureVerifierRedTests
{
    // RFC 8032, section 7.1, TEST 1 (empty message).
    private static readonly byte[] RfcPublicKey = Convert.FromHexString(
        "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");
    private static readonly byte[] RfcSignature = Convert.FromHexString(
        "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155" +
        "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");
    private static readonly byte[] TaggedMessage = Convert.FromHexString(
        "444545502D47454E2D56310000000000" +
        "73796E7468657469632D63616E6F6E6963616C2D73746174656D656E742D7631");
    private static readonly byte[] TaggedSignature = Convert.FromHexString(
        "CD1C153F2688C5C846A9063C7C10C951A0707A28E10EBA41FAFC14401192FBBE" +
        "94D4D17811C6BA7B15EAA1D63591EBB8D8B5B2AC77EB3F55D5F14EC720823B0C");

    [Fact]
    public void Rfc8032PositiveAndNegativeVectorsAreVerifiedExactly()
    {
        // The RFC signature is over an empty message, so direct sodium proves the
        // pinned provider primitive independently from DPF1 domain framing.
        Assert.True(PublicKeyAuth.VerifyDetached(RfcSignature, [], RfcPublicKey));
        var corrupted = RfcSignature.ToArray();
        corrupted[0] ^= 0x80;
        Assert.False(PublicKeyAuth.VerifyDetached(corrupted, [], RfcPublicKey));

        var adapter = new SodiumEd25519MembershipSignatureVerifier();
        Assert.True(adapter.Verify(
            new byte[MembershipLimits.SignerIdLength],
            RfcPublicKey,
            MembershipSignatureDomain.Genesis,
            TaggedMessage,
            TaggedSignature));
    }

    [Theory]
    [InlineData("signer")]
    [InlineData("public-key")]
    [InlineData("signature")]
    [InlineData("domain-tag")]
    [InlineData("corrupt")]
    [InlineData("cross-domain")]
    [InlineData("wrong-key")]
    [InlineData("noncanonical-scalar")]
    [InlineData("low-order-key")]
    [InlineData("extended-signature")]
    public void InvalidLengthsFramingAndReplayFailClosed(string mutation)
    {
        var fixture = Ed25519ProfileFixture.Create();
        var signature = fixture.GenesisSignatures[0];
        var signer = fixture.OfflineSigners[0];
        var signerId = signer.SignerId.ToArray();
        var publicKey = signer.PublicKey.ToArray();
        var signingBytes = fixture.GenesisSigningBytes.ToArray();
        var signatureBytes = signature.Signature.ToArray();
        var domain = MembershipSignatureDomain.Genesis;

        switch (mutation)
        {
            case "signer": signerId = signerId[..^1]; break;
            case "public-key": publicKey = publicKey[..^1]; break;
            case "signature": signatureBytes = signatureBytes[..^1]; break;
            case "domain-tag": signingBytes[0] ^= 0x80; break;
            case "corrupt": signatureBytes[0] ^= 0x80; break;
            case "cross-domain": domain = MembershipSignatureDomain.Bridge; break;
            case "wrong-key": publicKey[0] ^= 0x80; break;
            case "noncanonical-scalar": signatureBytes.AsSpan(32).Fill(0xff); break;
            case "low-order-key": publicKey.AsSpan().Clear(); break;
            case "extended-signature": signatureBytes = [.. signatureBytes, (byte)0]; break;
            default: throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        Assert.False(new SodiumEd25519MembershipSignatureVerifier().Verify(
            signerId,
            publicKey,
            domain,
            signingBytes,
            signatureBytes));
    }

    [Fact]
    public void ExistingDeterministicP14SignatureIsRejected()
    {
        var parts = SyntheticProfileFixture.Parts();
        var genesis = MembershipContractCodec.DecodeGenesis(parts.CanonicalGenesis);
        var signature = parts.GenesisApprovals[0];

        Assert.False(new SodiumEd25519MembershipSignatureVerifier().Verify(
            signature.SignerId.Span,
            genesis.OfflineRoots[0].PublicKey.Span,
            MembershipSignatureDomain.Genesis,
            MembershipSigningDomains.Frame(
                MembershipSignatureDomain.Genesis,
                parts.CanonicalGenesis),
            signature.Signature.Span));
    }

    [Fact]
    public void CompleteTestOnlyEd25519SignedDpf1Verifies()
    {
        var fixture = Ed25519ProfileFixture.Create();
        var composed = ProfileCarrierComposer.ComposeExact(
            ProfileCarrierContractRedTests.Input(fixture.Parts),
            ProfileCarrierContractRedTests.Options(),
            new SodiumEd25519MembershipSignatureVerifier());

        var verified = ProfileCarrierVerifier.VerifyExact(
            composed.FilePayload.Span,
            ProfileCarrierContractRedTests.Options(),
            new SodiumEd25519MembershipSignatureVerifier());

        Assert.Equal(composed.FilePayloadSha256.ToArray(), verified.FilePayloadSha256.ToArray());
    }

    [Fact]
    public void ProviderFailuresAreBoundedAndExactOomPropagates()
    {
        var fixture = Ed25519ProfileFixture.Create();
        var signer = fixture.OfflineSigners[0];
        var signature = fixture.GenesisSignatures[0];
        var ordinary = new ThrowingDetachedProvider(
            new InvalidOperationException("raw-provider-secret"));
        var ordinaryAdapter = new SodiumEd25519MembershipSignatureVerifier(ordinary);

        Assert.False(ordinaryAdapter.Verify(
            signer.SignerId.Span,
            signer.PublicKey.Span,
            MembershipSignatureDomain.Genesis,
            fixture.GenesisSigningBytes,
            signature.Signature.Span));
        Assert.Equal(1, ordinary.Calls);

        var nativeLoadFailure = new SodiumEd25519MembershipSignatureVerifier(
            new ThrowingDetachedProvider(new DllNotFoundException("native-provider-path")));
        Assert.False(nativeLoadFailure.Verify(
            signer.SignerId.Span,
            signer.PublicKey.Span,
            MembershipSignatureDomain.Genesis,
            fixture.GenesisSigningBytes,
            signature.Signature.Span));

        var oom = new OutOfMemoryException("exact-oom-instance");
        var oomAdapter = new SodiumEd25519MembershipSignatureVerifier(
            new ThrowingDetachedProvider(oom));
        var thrown = Assert.Throws<OutOfMemoryException>(() => oomAdapter.Verify(
            signer.SignerId.Span,
            signer.PublicKey.Span,
            MembershipSignatureDomain.Genesis,
            fixture.GenesisSigningBytes,
            signature.Signature.Span));
        Assert.Same(oom, thrown);
    }

    [Fact]
    public void ProductSourceHasVerifyOnlyStaticBoundary()
    {
        var root = RepositoryRoot();
        var source = string.Join(
            "\n",
            Directory.GetFiles(
                    Path.Combine(root, "src", "Deep.Protocol.ProfileCarrier"),
                    "*.cs")
                .Select(File.ReadAllText));

        foreach (var forbidden in new[]
                 {
                     "SignDetached", "GenerateKeyPair", "PrivateKey", "SecretKey",
                     "Seed", "System.IO", "System.Net", "DependencyInjection",
                     "HttpClient", "ILogger", "Billing", "Wallet"
                 })
        {
            Assert.DoesNotContain(forbidden, source, StringComparison.OrdinalIgnoreCase);
        }
        Assert.Contains("VerifyDetached", source, StringComparison.Ordinal);
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Deep.Protocol.slnx")))
        {
            directory = directory.Parent;
        }
        return directory?.FullName ?? throw new InvalidOperationException();
    }

    private sealed class ThrowingDetachedProvider(Exception exception)
        : IEd25519DetachedVerificationProvider
    {
        public int Calls { get; private set; }

        public bool VerifyDetached(byte[] signature, byte[] message, byte[] publicKey)
        {
            Calls++;
            throw exception;
        }
    }
}

internal static class ProfileCarrierFramingTestAccess
{
    public static byte[] EncodeWithoutVerification(SyntheticProfileParts parts)
    {
        var components = new List<byte[]>();
        components.Add(parts.CanonicalGenesis);
        // Test-only exact DPF1 assembly access is implemented in GREEN through
        // InternalsVisibleTo; it never becomes a second production parser.
        return ProfileCarrierTestHooks.EncodeUnverified(parts);
    }
}

internal sealed record Ed25519ProfileFixture(
    SyntheticProfileParts Parts,
    IReadOnlyList<MembershipSignerDescriptor> OfflineSigners,
    byte[] GenesisSigningBytes,
    IReadOnlyList<MembershipSignature> GenesisSignatures)
{
    public static Ed25519ProfileFixture Create()
    {
        var offline = CreateSigners(5, 0x10, MembershipSignerRole.OfflineRoot);
        var online = CreateSigners(3, 0x90, MembershipSignerRole.Online);
        var genesis = SyntheticProfileFixture.Genesis() with
        {
            OfflineRoots = offline.Select(static value => value.Descriptor).ToArray(),
            Policy = MembershipPolicy.Beta(
                offline.Select(static value => value.Descriptor.SignerId).ToArray())
        };
        var canonicalGenesis = MembershipContractCodec.EncodeGenesis(genesis);
        var approvals = Sign(
            offline,
            MembershipSignatureDomain.Genesis,
            canonicalGenesis,
            3);
        var unsignedDelegation = new SignerDelegation
        {
            NetworkId = genesis.NetworkId.ToArray(),
            Sequence = genesis.GenesisSequence + 1,
            PreviousHash = MembershipContractHash.Sha256(canonicalGenesis),
            IssuedAtUnixSeconds = 1_000,
            ValidFromUnixSeconds = 1_000,
            ValidUntilUnixSeconds = 2_000,
            MinimumProtocol = genesis.MinimumProtocol,
            MaximumProtocol = genesis.MaximumProtocol,
            PolicyVersion = genesis.PolicyVersion,
            OnlineSigners = online.Select(static value => value.Descriptor).ToArray(),
            Signatures = []
        };
        var delegation = unsignedDelegation with
        {
            Signatures = Sign(
                offline,
                MembershipSignatureDomain.OfflineDelegation,
                MembershipContractCodec.GetDelegationSigningBytes(unsignedDelegation),
                3)
        };
        var preliminaryBridge = new BridgeSnapshot
        {
            NetworkId = genesis.NetworkId.ToArray(),
            Sequence = genesis.GenesisSequence + 1,
            PreviousHash = MembershipContractHash.Sha256(canonicalGenesis),
            IssuedAtUnixSeconds = 1_000,
            ValidFromUnixSeconds = 1_000,
            ValidUntilUnixSeconds = 2_000,
            MinimumProtocol = genesis.MinimumProtocol,
            MaximumProtocol = genesis.MaximumProtocol,
            PolicyVersion = genesis.PolicyVersion,
            EntryContacts =
            [
                new BridgeEntryContact
                {
                    EntryId = Enumerable.Range(0x20, MembershipLimits.SignerIdLength)
                        .Select(static value => (byte)value).ToArray(),
                    Contact = "https://ed25519.invalid/bridge"
                }
            ],
            ForkWitness = new ForkWitnessRecord
            {
                CandidateDomain = MembershipSignatureDomain.Bridge,
                Sequence = genesis.GenesisSequence + 1,
                PreviousHash = MembershipContractHash.Sha256(canonicalGenesis),
                CandidateHash = new byte[MembershipLimits.HashLength]
            }
        };
        var bridge = preliminaryBridge with
        {
            ForkWitness = preliminaryBridge.ForkWitness with
            {
                CandidateHash = MembershipContractHash.Sha256(
                    MembershipContractCodec.GetBridgeCandidateBytes(preliminaryBridge))
            }
        };
        var signedBridge = new SignedBridgeSnapshot
        {
            Statement = bridge,
            Signatures = Sign(
                online,
                MembershipSignatureDomain.Bridge,
                MembershipContractCodec.GetBridgeSigningBytes(bridge),
                2)
        };
        var parts = new SyntheticProfileParts(
            canonicalGenesis,
            approvals,
            MembershipContractCodec.EncodeSignedDelegation(delegation),
            [MembershipContractCodec.EncodeSignedBridge(signedBridge)]);
        return new(
            parts,
            offline.Select(static value => value.Descriptor).ToArray(),
            MembershipSigningDomains.Frame(
                MembershipSignatureDomain.Genesis,
                canonicalGenesis),
            approvals);
    }

    private static SigningDescriptor[] CreateSigners(
        int count,
        int offset,
        MembershipSignerRole role) =>
        Enumerable.Range(0, count)
            .Select(index =>
            {
                var seed = Enumerable.Range(1, 32)
                    .Select(value => unchecked((byte)(value + offset + index)))
                    .ToArray();
                var pair = PublicKeyAuth.GenerateKeyPair(seed);
                return new SigningDescriptor(
                    new MembershipSignerDescriptor
                    {
                        SignerId = Enumerable.Range(offset + index * 16, 16)
                            .Select(static value => unchecked((byte)value)).ToArray(),
                        Role = role,
                        PublicKey = pair.PublicKey
                    },
                    pair.PrivateKey);
            })
            .ToArray();

    private static MembershipSignature[] Sign(
        IReadOnlyList<SigningDescriptor> signers,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> canonical,
        int count)
    {
        var framed = MembershipSigningDomains.Frame(domain, canonical);
        return signers.Take(count)
            .Select(value => new MembershipSignature
            {
                SignerId = value.Descriptor.SignerId.ToArray(),
                Domain = domain,
                Signature = PublicKeyAuth.SignDetached(framed, value.PrivateKey)
            })
            .ToArray();
    }

    private sealed record SigningDescriptor(
        MembershipSignerDescriptor Descriptor,
        byte[] PrivateKey);
}
