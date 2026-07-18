using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Protocol.Tests.DeepExtension;

internal sealed class DeterministicMembershipVerifier : IMembershipSignatureVerifier
{
    public byte[] Digest(ReadOnlySpan<byte> canonicalBytes) =>
        SHA256.HashData(canonicalBytes);

    public bool Verify(
        ReadOnlySpan<byte> signerId,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature) =>
        signature.SequenceEqual(Sign(signerId, domain, signingBytes));

    public byte[] Sign(
        ReadOnlySpan<byte> signerId,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> signingBytes)
    {
        var framed = new byte[signerId.Length + 1 + signingBytes.Length];
        signerId.CopyTo(framed);
        framed[signerId.Length] = (byte)domain;
        signingBytes.CopyTo(framed.AsSpan(signerId.Length + 1));
        return SHA256.HashData(framed);
    }
}

internal static class MembershipFixtures
{
    private static readonly ReadOnlyMemory<byte>[] OfflineSignerIds = Signers(0x10, 5);
    private static readonly ReadOnlyMemory<byte>[] OnlineSignerIds = Signers(0x40, 3);

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
                OnlineSignerIds[index], domain, bytes, verifier)).ToArray()
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
                    OfflineSignerIds[index],
                    MembershipSignatureDomain.OfflineDelegation,
                    bytes,
                    verifier))
                .ToArray()
        };
        return new MembershipVerificationContext
        {
            Genesis = genesis,
            ActiveDelegation = delegation,
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
            OfflineRoots = OfflineSignerIds.Select((id, index) => new MembershipSignerDescriptor
            {
                SignerId = id,
                Role = MembershipSignerRole.OfflineRoot,
                PublicKey = Range(0xe0 + index, MembershipLimits.PublicKeyLength)
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
        var verifier = new DeterministicMembershipVerifier();
        return snapshot with
        {
            ForkWitness = snapshot.ForkWitness with
            {
                CandidateHash = verifier.Digest(
                    MembershipContractCodec.GetBridgeCandidateBytes(snapshot))
            }
        };
    }

    public static SignedBridgeSnapshot SignedBridge(
        DeterministicMembershipVerifier verifier,
        IReadOnlyList<int> signerIndexes)
    {
        var snapshot = BridgeSnapshot();
        var bytes = MembershipContractCodec.GetBridgeSigningBytes(snapshot);
        return new SignedBridgeSnapshot
        {
            Statement = snapshot,
            Signatures = signerIndexes.Select(index => Signature(
                OnlineSignerIds[index],
                MembershipSignatureDomain.Bridge,
                bytes,
                verifier)).ToArray()
        };
    }

    private static SignerDelegation UnsignedDelegation(bool expired) =>
        new()
        {
            NetworkId = Range(0x70, MembershipLimits.NetworkIdLength),
            Sequence = 2,
            PreviousHash = Range(0x90, MembershipLimits.HashLength),
            IssuedAtUnixSeconds = 900,
            ValidFromUnixSeconds = 900,
            ValidUntilUnixSeconds = expired ? 950UL : 1300UL,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            PolicyVersion = 1,
            OnlineSignerIds = OnlineSignerIds,
            Signatures = []
        };

    private static MembershipSignature Signature(
        ReadOnlyMemory<byte> signerId,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> bytes,
        DeterministicMembershipVerifier verifier) =>
        new()
        {
            SignerId = signerId.ToArray(),
            Domain = domain,
            Signature = verifier.Sign(signerId.Span, domain, bytes)
        };

    private static ReadOnlyMemory<byte>[] Signers(int start, int count) =>
        Enumerable.Range(0, count)
            .Select(index => (ReadOnlyMemory<byte>)Range(start + index * 16, 16))
            .ToArray();

    internal static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();
}
