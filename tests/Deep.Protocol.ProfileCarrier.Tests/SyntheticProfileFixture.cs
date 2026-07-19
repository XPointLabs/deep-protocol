using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Protocol.ProfileCarrier.Tests;

// Public, deterministic test data only. There are no private keys or seeds.
internal sealed class SyntheticMembershipVerifier : IMembershipSignatureVerifier
{
    public byte[] Sign(
        MembershipSignerDescriptor signer,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> canonicalStatement) =>
        Digest(
            signer.SignerId.Span,
            signer.PublicKey.Span,
            MembershipSigningDomains.Frame(domain, canonicalStatement));

    public bool Verify(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature) =>
        CryptographicOperations.FixedTimeEquals(
            Digest(signerId, publicKey, signingBytes),
            signature);

    private static byte[] Digest(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes)
    {
        var input = new byte[signerId.Length + publicKey.Length + signingBytes.Length];
        signerId.CopyTo(input);
        publicKey.CopyTo(input.AsSpan(signerId.Length));
        signingBytes.CopyTo(input.AsSpan(signerId.Length + publicKey.Length));
        return SHA256.HashData(input);
    }
}

internal sealed record SyntheticProfileParts(
    byte[] CanonicalGenesis,
    IReadOnlyList<MembershipSignature> GenesisApprovals,
    byte[] CanonicalSignedDelegation,
    IReadOnlyList<byte[]> CanonicalSignedBridges);

internal static class SyntheticProfileFixture
{
    public const ulong VerificationTime = 1_100;
    public const ushort Protocol = 2;

    public static SyntheticMembershipVerifier Verifier() => new();

    public static SyntheticProfileParts Parts(
        bool reverseGenesisSignatures = false,
        bool reverseBridges = false,
        int bridgeCount = 1,
        int contactLength = 48,
        int contactsPerBridge = 1,
        IReadOnlyList<int>? exactContactLengths = null)
    {
        var verifier = Verifier();
        var genesis = Genesis();
        var canonicalGenesis = MembershipContractCodec.EncodeGenesis(genesis);
        var genesisApprovals = Signatures(
            genesis.OfflineRoots,
            MembershipSignatureDomain.Genesis,
            canonicalGenesis,
            3,
            verifier).ToArray();
        if (reverseGenesisSignatures)
        {
            Array.Reverse(genesisApprovals);
        }

        var delegation = SignedDelegation(genesis, canonicalGenesis, verifier);
        var bridges = SignedBridges(
                genesis,
                canonicalGenesis,
                delegation,
                bridgeCount,
                contactLength,
                contactsPerBridge,
                exactContactLengths,
                verifier)
            .Select(static value => MembershipContractCodec.EncodeSignedBridge(value))
            .ToArray();
        if (reverseBridges)
        {
            Array.Reverse(bridges);
        }

        return new(
            canonicalGenesis,
            genesisApprovals,
            MembershipContractCodec.EncodeSignedDelegation(delegation),
            bridges);
    }

    public static NetworkGenesis Genesis() =>
        new()
        {
            NetworkId = Range(0x70, MembershipLimits.NetworkIdLength),
            GenesisSequence = 1,
            PolicyVersion = 1,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            IssuedAtUnixSeconds = 1_000,
            OfflineRoots = OfflineRoots(),
            Policy = MembershipPolicy.Beta(
                OfflineRoots().Select(static signer => signer.SignerId).ToArray())
        };

    public static SignerDelegation SignedDelegation(
        NetworkGenesis genesis,
        byte[] canonicalGenesis,
        SyntheticMembershipVerifier verifier)
    {
        var unsigned = new SignerDelegation
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
            OnlineSigners = OnlineSigners(),
            Signatures = []
        };
        var signingBytes = MembershipContractCodec.GetDelegationSigningBytes(unsigned);
        return unsigned with
        {
            Signatures = Signatures(
                genesis.OfflineRoots,
                MembershipSignatureDomain.OfflineDelegation,
                signingBytes,
                3,
                verifier)
        };
    }

    public static IReadOnlyList<SignedBridgeSnapshot> SignedBridges(
        NetworkGenesis genesis,
        byte[] canonicalGenesis,
        SignerDelegation delegation,
        int count,
        int contactLength,
        int contactsPerBridge,
        IReadOnlyList<int>? exactContactLengths,
        SyntheticMembershipVerifier verifier)
    {
        var result = new List<SignedBridgeSnapshot>();
        var previousHash = MembershipContractHash.Sha256(canonicalGenesis);
        var sequence = genesis.GenesisSequence + 1;
        for (var index = 0; index < count; index++)
        {
            var contacts = Enumerable.Range(0, contactsPerBridge)
                .Select(contactIndex =>
                {
                    var exactIndex = index * contactsPerBridge + contactIndex;
                    var length = exactContactLengths?[exactIndex] ?? contactLength;
                    return new BridgeEntryContact
                    {
                        EntryId = Range(
                            0x20 + contactIndex * MembershipLimits.SignerIdLength,
                            MembershipLimits.SignerIdLength),
                        Contact = ExactContact(length, index, contactIndex)
                    };
                })
                .ToArray();
            var preliminary = new BridgeSnapshot
            {
                NetworkId = genesis.NetworkId.ToArray(),
                Sequence = sequence,
                PreviousHash = previousHash,
                IssuedAtUnixSeconds = 1_000,
                ValidFromUnixSeconds = 1_000,
                ValidUntilUnixSeconds = 2_000,
                MinimumProtocol = genesis.MinimumProtocol,
                MaximumProtocol = genesis.MaximumProtocol,
                PolicyVersion = genesis.PolicyVersion,
                EntryContacts = contacts,
                ForkWitness = new ForkWitnessRecord
                {
                    CandidateDomain = MembershipSignatureDomain.Bridge,
                    Sequence = sequence,
                    PreviousHash = previousHash,
                    CandidateHash = new byte[MembershipLimits.HashLength]
                }
            };
            var snapshot = preliminary with
            {
                ForkWitness = preliminary.ForkWitness with
                {
                    CandidateHash = MembershipContractHash.Sha256(
                        MembershipContractCodec.GetBridgeCandidateBytes(preliminary))
                }
            };
            var signingBytes = MembershipContractCodec.GetBridgeSigningBytes(snapshot);
            result.Add(new SignedBridgeSnapshot
            {
                Statement = snapshot,
                Signatures = Signatures(
                    delegation.OnlineSigners,
                    MembershipSignatureDomain.Bridge,
                    signingBytes,
                    2,
                    verifier)
            });
            previousHash = MembershipContractHash.Sha256(signingBytes);
            sequence++;
        }

        return result;
    }

    public static IReadOnlyList<MembershipSignature> Signatures(
        IReadOnlyList<MembershipSignerDescriptor> signers,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> canonicalStatement,
        int count,
        SyntheticMembershipVerifier verifier)
    {
        var canonical = canonicalStatement.ToArray();
        return signers.Take(count)
            .Select(signer => new MembershipSignature
            {
                SignerId = signer.SignerId.ToArray(),
                Domain = domain,
                Signature = verifier.Sign(signer, domain, canonical)
            })
            .ToArray();
    }

    public static IReadOnlyList<MembershipSignerDescriptor> OfflineRoots() =>
        Enumerable.Range(0, 5)
            .Select(index => Descriptor(
                0x10 + index * 16,
                0x40 + index * 32,
                MembershipSignerRole.OfflineRoot))
            .ToArray();

    public static IReadOnlyList<MembershipSignerDescriptor> OnlineSigners() =>
        Enumerable.Range(0, 3)
            .Select(index => Descriptor(
                0xa0 + index * 16,
                0x100 + index * 32,
                MembershipSignerRole.Online))
            .ToArray();

    private static string ExactContact(int length, int bridgeIndex, int contactIndex)
    {
        var prefix = $"https://b.invalid/{bridgeIndex:D2}/{contactIndex:D2}/";
        if (length < prefix.Length || length > MembershipLimits.MaximumContactLength)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }
        return prefix + new string((char)('a' + contactIndex % 20), length - prefix.Length);
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length)
            .Select(static value => unchecked((byte)value))
            .ToArray();

    private static MembershipSignerDescriptor Descriptor(
        int signerStart,
        int keyStart,
        MembershipSignerRole role) =>
        new()
        {
            SignerId = Range(signerStart, MembershipLimits.SignerIdLength),
            Role = role,
            PublicKey = Range(keyStart, MembershipLimits.PublicKeyLength)
        };
}
