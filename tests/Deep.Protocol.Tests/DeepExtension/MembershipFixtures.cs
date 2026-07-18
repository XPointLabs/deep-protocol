using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Protocol.Tests.DeepExtension;

internal sealed class DeterministicMembershipVerifier : IMembershipSignatureVerifier
{
    public bool Verify(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature) =>
        signature.SequenceEqual(SignFramed(signerId, publicKey, signingBytes));

    public byte[] Sign(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> canonicalStatement) =>
        SignFramed(
            signerId,
            publicKey,
            MembershipSigningDomains.Frame(domain, canonicalStatement));

    private static byte[] SignFramed(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes)
    {
        var framed = new byte[signerId.Length + publicKey.Length + signingBytes.Length];
        signerId.CopyTo(framed);
        publicKey.CopyTo(framed.AsSpan(signerId.Length));
        signingBytes.CopyTo(framed.AsSpan(signerId.Length + publicKey.Length));
        return SHA256.HashData(framed);
    }
}

internal static class MembershipFixtures
{
    private static readonly ReadOnlyMemory<byte>[] OfflineSignerIds = Signers(0x10, 5);
    private static readonly ReadOnlyMemory<byte>[] OnlineSignerIds = Signers(0x40, 3);
    private static readonly MembershipSignerDescriptor[] OfflineSigners =
        OfflineSignerIds.Select((id, index) => new MembershipSignerDescriptor
        {
            SignerId = id,
            Role = MembershipSignerRole.OfflineRoot,
            PublicKey = Range(0xe0 + index * 3, MembershipLimits.PublicKeyLength)
        }).ToArray();
    private static readonly MembershipSignerDescriptor[] OnlineSigners =
        OnlineSignerIds.Select((id, index) => new MembershipSignerDescriptor
        {
            SignerId = id,
            Role = MembershipSignerRole.Online,
            PublicKey = Range(0x80 + index * 3, MembershipLimits.PublicKeyLength)
        }).ToArray();

    public static NodeMembershipCommitment Commitment(
        ulong sequence,
        bool wrongPreviousHash = false,
        bool alternateBody = false) =>
        new()
        {
            NetworkId = Range(0x70, MembershipLimits.NetworkIdLength),
            Sequence = sequence,
            PreviousHash = wrongPreviousHash
                ? Range(0xb0, MembershipLimits.HashLength)
                : Range(0xa0, MembershipLimits.HashLength),
            IssuedAtUnixSeconds = 1000,
            ValidFromUnixSeconds = 1000,
            ValidUntilUnixSeconds = 1200,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            PolicyVersion = 1,
            MemberCount = alternateBody ? 12u : 11u,
            MerkleRoot = alternateBody
                ? Range(0xd0, MembershipLimits.HashLength)
                : Range(0xc0, MembershipLimits.HashLength)
        };

    public static SignedMembershipCommitment Sign(
        NodeMembershipCommitment commitment,
        MembershipSignatureDomain domain,
        IReadOnlyList<int> signerIndexes,
        DeterministicMembershipVerifier verifier)
    {
        var bytes = MembershipContractCodec.GetMembershipSigningBytes(commitment);
        return new SignedMembershipCommitment
        {
            Statement = commitment,
            Signatures = signerIndexes.Select(index => Signature(
                OnlineSigners[index], domain, bytes, verifier)).ToArray()
        };
    }

    public static SignedMembershipCommitment SignWithCryptographicDomain(
        NodeMembershipCommitment commitment,
        MembershipSignatureDomain declaredDomain,
        MembershipSignatureDomain cryptographicDomain,
        DeterministicMembershipVerifier verifier)
    {
        var bytes = MembershipContractCodec.GetMembershipSigningBytes(commitment);
        return new SignedMembershipCommitment
        {
            Statement = commitment,
            Signatures = OnlineSigners.Take(2).Select(signer => new MembershipSignature
            {
                SignerId = signer.SignerId.ToArray(),
                Domain = declaredDomain,
                Signature = verifier.Sign(
                    signer.SignerId.Span,
                    signer.PublicKey.Span,
                    cryptographicDomain,
                    bytes)
            }).ToArray()
        };
    }

    public static SignedMembershipCommitment SignedCommitment(
        ulong sequence,
        DeterministicMembershipVerifier verifier,
        bool wrongPreviousHash = false,
        bool expiredDelegation = false,
        bool alternateBody = false)
    {
        var commitment = Commitment(sequence, wrongPreviousHash, alternateBody);
        return Sign(commitment, MembershipSignatureDomain.Membership, [0, 1], verifier);
    }

    public static MembershipVerificationContext Context(
        ulong lastSequence = 6,
        bool expiredDelegation = false,
        ulong verificationTime = 1010,
        uint allowedClockSkew = 30)
    {
        var verifier = new DeterministicMembershipVerifier();
        var genesis = Genesis();
        var delegation = UnsignedDelegation(expiredDelegation);
        var bytes = MembershipContractCodec.GetDelegationSigningBytes(delegation);
        delegation = delegation with
        {
            Signatures = Enumerable.Range(0, 3)
                .Select(index => Signature(
                    OfflineSigners[index],
                    MembershipSignatureDomain.OfflineDelegation,
                    bytes,
                    verifier))
                .ToArray()
        };
        return new MembershipVerificationContext
        {
            Genesis = genesis,
            ActiveDelegation = delegation,
            AuthorityLastKnownGood = new MembershipLastKnownGood
            {
                NetworkId = genesis.NetworkId.ToArray(),
                PolicyVersion = genesis.PolicyVersion,
                Sequence = delegation.Sequence,
                CanonicalHash = MembershipContractHash.Sha256(bytes)
            },
            RevokedDelegationHashes = [],
            LastKnownGood = new MembershipLastKnownGood
            {
                NetworkId = Range(0x70, MembershipLimits.NetworkIdLength),
                PolicyVersion = 1,
                Sequence = lastSequence,
                CanonicalHash = Range(0xa0, MembershipLimits.HashLength)
            },
            VerificationTimeUnixSeconds = verificationTime,
            AllowedClockSkewSeconds = allowedClockSkew,
            ClientProtocol = 2
        };
    }

    public static NetworkGenesis Genesis() =>
        new()
        {
            NetworkId = Range(0x70, MembershipLimits.NetworkIdLength),
            GenesisSequence = 1,
            PolicyVersion = 1,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            IssuedAtUnixSeconds = 800,
            Policy = MembershipPolicy.Beta(OfflineSignerIds, OnlineSignerIds),
            OfflineRoots = OfflineSigners.Select(static value => value with
            {
                SignerId = value.SignerId.ToArray(),
                PublicKey = value.PublicKey.ToArray()
            }).ToArray()
        };

    public static BridgeSnapshot BridgeSnapshot(
        ReadOnlyMemory<byte>? candidateHash = null)
    {
        var snapshot = new BridgeSnapshot
        {
            NetworkId = Range(0x70, MembershipLimits.NetworkIdLength),
            Sequence = 7,
            PreviousHash = Range(0xa0, MembershipLimits.HashLength),
            IssuedAtUnixSeconds = 1000,
            ValidFromUnixSeconds = 1000,
            ValidUntilUnixSeconds = 1200,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            PolicyVersion = 1,
            EntryContacts =
            [
                new BridgeEntryContact
                {
                    EntryId = Range(0x01, MembershipLimits.SignerIdLength),
                    Contact = "https://bridge.example.invalid/v1"
                }
            ],
            ForkWitness = new ForkWitnessRecord
            {
                CandidateDomain = MembershipSignatureDomain.Bridge,
                Sequence = 7,
                PreviousHash = Range(0xa0, MembershipLimits.HashLength),
                CandidateHash = candidateHash ?? Range(0xf0, MembershipLimits.HashLength)
            }
        };
        if (candidateHash.HasValue)
            return snapshot;
        return snapshot with
        {
            ForkWitness = snapshot.ForkWitness with
            {
                CandidateHash = MembershipContractHash.Sha256(
                    MembershipContractCodec.GetBridgeCandidateBytes(snapshot))
            }
        };
    }

    public static SignedBridgeSnapshot SignedBridge(
        DeterministicMembershipVerifier verifier,
        IReadOnlyList<int> signerIndexes,
        bool alternateContact = false)
    {
        var snapshot = BridgeSnapshot();
        if (alternateContact)
        {
            snapshot = snapshot with
            {
                EntryContacts =
                [
                    snapshot.EntryContacts[0] with
                    {
                        Contact = "https://alternate.example.invalid/v1"
                    }
                ]
            };
            snapshot = snapshot with
            {
                ForkWitness = snapshot.ForkWitness with
                {
                    CandidateHash = MembershipContractHash.Sha256(
                        MembershipContractCodec.GetBridgeCandidateBytes(snapshot))
                }
            };
        }
        var bytes = MembershipContractCodec.GetBridgeSigningBytes(snapshot);
        return new SignedBridgeSnapshot
        {
            Statement = snapshot,
            Signatures = signerIndexes.Select(index => Signature(
                OnlineSigners[index],
                MembershipSignatureDomain.Bridge,
                bytes,
                verifier)).ToArray()
        };
    }

    public static MembershipLastKnownGood GenesisAuthorityLastKnownGood()
    {
        var genesis = Genesis();
        return new MembershipLastKnownGood
        {
            NetworkId = genesis.NetworkId.ToArray(),
            PolicyVersion = genesis.PolicyVersion,
            Sequence = genesis.GenesisSequence,
            CanonicalHash = MembershipContractHash.Sha256(
                MembershipContractCodec.EncodeGenesis(genesis))
        };
    }

    public static SignerDelegation SignedDelegation(
        DeterministicMembershipVerifier verifier,
        bool alternateKey = false,
        bool expired = false)
    {
        var delegation = UnsignedDelegation(expired);
        if (alternateKey)
        {
            delegation = delegation with
            {
                OnlineSigners = delegation.OnlineSigners.Select((signer, index) =>
                    index == 0
                        ? signer with { PublicKey = Range(0x22, MembershipLimits.PublicKeyLength) }
                        : signer).ToArray()
            };
        }
        var bytes = MembershipContractCodec.GetDelegationSigningBytes(delegation);
        return delegation with
        {
            Signatures = OfflineSigners.Take(3)
                .Select(signer => Signature(
                    signer, MembershipSignatureDomain.OfflineDelegation, bytes, verifier))
                .ToArray()
        };
    }

    public static SignerRevocation SignedRevocation(
        DeterministicMembershipVerifier verifier,
        bool alternate = false)
    {
        var delegation = SignedDelegation(verifier);
        var delegationHash = MembershipContractHash.Sha256(
            MembershipContractCodec.GetDelegationSigningBytes(delegation));
        var revocation = new SignerRevocation
        {
            NetworkId = delegation.NetworkId.ToArray(),
            Sequence = 3,
            PreviousHash = delegationHash,
            IssuedAtUnixSeconds = 1000,
            ValidFromUnixSeconds = 1000,
            ValidUntilUnixSeconds = 1200,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            PolicyVersion = 1,
            DelegationHash = alternate
                ? Range(0x33, MembershipLimits.HashLength)
                : delegationHash,
            Signatures = []
        };
        var bytes = MembershipContractCodec.GetRevocationSigningBytes(revocation);
        return revocation with
        {
            Signatures = OfflineSigners.Take(3)
                .Select(signer => Signature(
                    signer, MembershipSignatureDomain.OfflineRevocation, bytes, verifier))
                .ToArray()
        };
    }

    public static MembershipInclusionProof InclusionProof() =>
        new()
        {
            NetworkId = Range(0x70, MembershipLimits.NetworkIdLength),
            Sequence = 7,
            MemberCommitment = Range(0x60, MembershipLimits.HashLength),
            LeafIndex = 2,
            SiblingHashes =
            [
                Range(0x20, MembershipLimits.HashLength),
                Range(0x40, MembershipLimits.HashLength)
            ]
        };

    private static SignerDelegation UnsignedDelegation(bool expired) =>
        new()
        {
            NetworkId = Range(0x70, MembershipLimits.NetworkIdLength),
            Sequence = 2,
            PreviousHash = GenesisAuthorityLastKnownGood().CanonicalHash.ToArray(),
            IssuedAtUnixSeconds = 900,
            ValidFromUnixSeconds = 900,
            ValidUntilUnixSeconds = expired ? 950UL : 1300UL,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            PolicyVersion = 1,
            OnlineSigners = OnlineSigners.Select(static value => value with
            {
                SignerId = value.SignerId.ToArray(),
                PublicKey = value.PublicKey.ToArray()
            }).ToArray(),
            Signatures = []
        };

    private static MembershipSignature Signature(
        MembershipSignerDescriptor signer,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> bytes,
        DeterministicMembershipVerifier verifier) =>
        new()
        {
            SignerId = signer.SignerId.ToArray(),
            Domain = domain,
            Signature = verifier.Sign(
                signer.SignerId.Span,
                signer.PublicKey.Span,
                domain,
                bytes)
        };

    private static ReadOnlyMemory<byte>[] Signers(int start, int count) =>
        Enumerable.Range(0, count)
            .Select(index => (ReadOnlyMemory<byte>)Range(start + index * 16, 16))
            .ToArray();

    internal static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();
}
