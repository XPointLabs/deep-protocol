using System.Buffers.Binary;
using System.Text;

namespace Deep.Protocol.DeepExtension.Membership;

public static class MembershipContractCodec
{
    private const byte Version = 1;
    private static ReadOnlySpan<byte> GenesisMagic => "MNG1"u8;
    private static ReadOnlySpan<byte> DelegationMagic => "MDG1"u8;
    private static ReadOnlySpan<byte> RevocationMagic => "MRV1"u8;
    private static ReadOnlySpan<byte> BridgeMagic => "MBS1"u8;
    private static ReadOnlySpan<byte> MembershipMagic => "MMC1"u8;
    private static ReadOnlySpan<byte> ForkMagic => "MFW1"u8;
    private static ReadOnlySpan<byte> InclusionProofMagic => "MIP1"u8;
    private static ReadOnlySpan<byte> SignedMembershipMagic => "MSM1"u8;
    private static ReadOnlySpan<byte> SignedBridgeMagic => "MSB1"u8;

    public static byte[] EncodeGenesis(NetworkGenesis genesis)
    {
        ArgumentNullException.ThrowIfNull(genesis);
        ValidateGenesis(genesis);
        var writer = new CanonicalWriter(128 + genesis.OfflineRoots.Count * 52);
        writer.Magic(GenesisMagic);
        writer.Byte(Version);
        writer.Zero(3);
        writer.Fixed(genesis.NetworkId, MembershipLimits.NetworkIdLength, "network ID");
        writer.UInt64(genesis.GenesisSequence);
        writer.UInt32(genesis.PolicyVersion);
        writer.UInt16(genesis.MinimumProtocol);
        writer.UInt16(genesis.MaximumProtocol);
        writer.UInt64(genesis.IssuedAtUnixSeconds);
        WritePolicy(writer, genesis.Policy);
        writer.UInt16(checked((ushort)genesis.OfflineRoots.Count));
        foreach (var root in OrderDescriptors(genesis.OfflineRoots))
        {
            writer.Fixed(root.SignerId, MembershipLimits.SignerIdLength, "signer ID");
            writer.Byte((byte)root.Role);
            writer.Zero(3);
            writer.Fixed(root.PublicKey, MembershipLimits.PublicKeyLength, "public key");
        }
        return writer.ToArray();
    }

    public static NetworkGenesis DecodeGenesis(ReadOnlySpan<byte> encoded)
    {
        var reader = new CanonicalReader(encoded, GenesisMagic);
        var networkId = reader.Fixed(MembershipLimits.NetworkIdLength);
        var sequence = reader.UInt64();
        var policyVersion = reader.UInt32();
        var minimumProtocol = reader.UInt16();
        var maximumProtocol = reader.UInt16();
        var issued = reader.UInt64();
        var policy = ReadPolicy(ref reader);
        var count = reader.Count(MembershipLimits.MaximumSigners);
        var roots = new MembershipSignerDescriptor[count];
        for (var index = 0; index < count; index++)
        {
            roots[index] = new MembershipSignerDescriptor
            {
                SignerId = reader.Fixed(MembershipLimits.SignerIdLength),
                Role = reader.Enum<MembershipSignerRole>(),
                PublicKey = ReadDescriptorRemainder(ref reader)
            };
        }
        reader.End();
        var result = new NetworkGenesis
        {
            NetworkId = networkId,
            GenesisSequence = sequence,
            PolicyVersion = policyVersion,
            MinimumProtocol = minimumProtocol,
            MaximumProtocol = maximumProtocol,
            IssuedAtUnixSeconds = issued,
            Policy = policy,
            OfflineRoots = roots
        };
        ValidateGenesis(result);
        RequireCanonical(encoded, EncodeGenesis(result));
        return result;
    }

    private static byte[] ReadDescriptorRemainder(ref CanonicalReader reader)
    {
        reader.Zero(3);
        return reader.Fixed(MembershipLimits.PublicKeyLength);
    }

    public static byte[] GetDelegationSigningBytes(SignerDelegation delegation) =>
        EncodeDelegationStatement(delegation);

    public static byte[] GetRevocationSigningBytes(SignerRevocation revocation) =>
        EncodeAuthorityStatement(
            RevocationMagic,
            revocation.NetworkId,
            revocation.Sequence,
            revocation.PreviousHash,
            revocation.IssuedAtUnixSeconds,
            revocation.ValidFromUnixSeconds,
            revocation.ValidUntilUnixSeconds,
            revocation.MinimumProtocol,
            revocation.MaximumProtocol,
            revocation.PolicyVersion,
            [],
            revocation.DelegationHash);

    public static SignerDelegation DecodeDelegationSigningBytes(ReadOnlySpan<byte> encoded)
    {
        var reader = new CanonicalReader(encoded, DelegationMagic);
        ReadCommon(ref reader, out var networkId, out var sequence, out var previousHash,
            out var issued, out var validFrom, out var validUntil, out var minimumProtocol,
            out var maximumProtocol, out var policyVersion);
        var count = reader.Count(MembershipLimits.MaximumSigners);
        var signers = new MembershipSignerDescriptor[count];
        for (var index = 0; index < count; index++)
        {
            signers[index] = new MembershipSignerDescriptor
            {
                SignerId = reader.Fixed(MembershipLimits.SignerIdLength),
                Role = reader.Enum<MembershipSignerRole>(),
                PublicKey = ReadDescriptorRemainder(ref reader)
            };
        }
        reader.End();
        var result = new SignerDelegation
        {
            NetworkId = networkId,
            Sequence = sequence,
            PreviousHash = previousHash,
            IssuedAtUnixSeconds = issued,
            ValidFromUnixSeconds = validFrom,
            ValidUntilUnixSeconds = validUntil,
            MinimumProtocol = minimumProtocol,
            MaximumProtocol = maximumProtocol,
            PolicyVersion = policyVersion,
            OnlineSigners = signers,
            Signatures = []
        };
        RequireCanonical(encoded, GetDelegationSigningBytes(result));
        return result;
    }

    public static SignerRevocation DecodeRevocationSigningBytes(ReadOnlySpan<byte> encoded)
    {
        var reader = new CanonicalReader(encoded, RevocationMagic);
        ReadCommon(ref reader, out var networkId, out var sequence, out var previousHash,
            out var issued, out var validFrom, out var validUntil, out var minimumProtocol,
            out var maximumProtocol, out var policyVersion);
        var count = reader.UInt16();
        if (count != 0)
            throw Error(MembershipContractError.InvalidLength, "Revocation signer body must be empty.");
        var delegationHash = reader.Fixed(MembershipLimits.HashLength);
        reader.End();
        var result = new SignerRevocation
        {
            NetworkId = networkId,
            Sequence = sequence,
            PreviousHash = previousHash,
            IssuedAtUnixSeconds = issued,
            ValidFromUnixSeconds = validFrom,
            ValidUntilUnixSeconds = validUntil,
            MinimumProtocol = minimumProtocol,
            MaximumProtocol = maximumProtocol,
            PolicyVersion = policyVersion,
            DelegationHash = delegationHash,
            Signatures = []
        };
        RequireCanonical(encoded, GetRevocationSigningBytes(result));
        return result;
    }

    public static byte[] GetBridgeSigningBytes(BridgeSnapshot snapshot)
    {
        var candidate = GetBridgeCandidateBytes(snapshot);
        var witness = EncodeForkWitness(snapshot.ForkWitness);
        return [.. candidate, .. witness];
    }

    public static byte[] GetBridgeCandidateBytes(BridgeSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ValidateCommon(snapshot.NetworkId, snapshot.Sequence, snapshot.PreviousHash,
            snapshot.IssuedAtUnixSeconds, snapshot.ValidFromUnixSeconds, snapshot.ValidUntilUnixSeconds,
            snapshot.MinimumProtocol, snapshot.MaximumProtocol, snapshot.PolicyVersion);
        if (snapshot.EntryContacts.Count is 0 or > MembershipLimits.MaximumBridgeContacts)
            throw Error(MembershipContractError.InvalidField, "Bridge contact count is outside canonical bounds.");
        ValidateDistinctMemories(
            snapshot.EntryContacts.Select(static contact => contact.EntryId).ToArray(),
            MembershipLimits.SignerIdLength,
            "Bridge entry identifiers");
        var writer = WriteCommon(BridgeMagic, snapshot.NetworkId, snapshot.Sequence, snapshot.PreviousHash,
            snapshot.IssuedAtUnixSeconds, snapshot.ValidFromUnixSeconds, snapshot.ValidUntilUnixSeconds,
            snapshot.MinimumProtocol, snapshot.MaximumProtocol, snapshot.PolicyVersion);
        writer.UInt16(checked((ushort)snapshot.EntryContacts.Count));
        foreach (var contact in snapshot.EntryContacts.OrderBy(static value => value.EntryId, MemoryComparer.Instance))
        {
            writer.Fixed(contact.EntryId, MembershipLimits.SignerIdLength, "entry ID");
            writer.String(contact.Contact);
        }
        return writer.ToArray();
    }

    public static BridgeSnapshot DecodeBridgeSigningBytes(ReadOnlySpan<byte> encoded)
    {
        var reader = new CanonicalReader(encoded, BridgeMagic);
        var networkId = reader.Fixed(MembershipLimits.NetworkIdLength);
        var sequence = reader.UInt64();
        var previousHash = reader.Fixed(MembershipLimits.HashLength);
        var issued = reader.UInt64();
        var validFrom = reader.UInt64();
        var validUntil = reader.UInt64();
        var minimumProtocol = reader.UInt16();
        var maximumProtocol = reader.UInt16();
        var policyVersion = reader.UInt32();
        var count = reader.Count(MembershipLimits.MaximumBridgeContacts);
        var contacts = new BridgeEntryContact[count];
        for (var index = 0; index < count; index++)
        {
            contacts[index] = new BridgeEntryContact
            {
                EntryId = reader.Fixed(MembershipLimits.SignerIdLength),
                Contact = reader.String()
            };
        }
        var witness = DecodeForkWitness(reader.Remaining());
        reader.ConsumeRemaining();
        var result = new BridgeSnapshot
        {
            NetworkId = networkId,
            Sequence = sequence,
            PreviousHash = previousHash,
            IssuedAtUnixSeconds = issued,
            ValidFromUnixSeconds = validFrom,
            ValidUntilUnixSeconds = validUntil,
            MinimumProtocol = minimumProtocol,
            MaximumProtocol = maximumProtocol,
            PolicyVersion = policyVersion,
            EntryContacts = contacts,
            ForkWitness = witness
        };
        RequireCanonical(encoded, GetBridgeSigningBytes(result));
        return result;
    }

    public static byte[] GetMembershipSigningBytes(NodeMembershipCommitment commitment)
    {
        ArgumentNullException.ThrowIfNull(commitment);
        ValidateCommon(commitment.NetworkId, commitment.Sequence, commitment.PreviousHash,
            commitment.IssuedAtUnixSeconds, commitment.ValidFromUnixSeconds, commitment.ValidUntilUnixSeconds,
            commitment.MinimumProtocol, commitment.MaximumProtocol, commitment.PolicyVersion);
        if (commitment.MemberCount == 0 || commitment.MerkleRoot.Length != MembershipLimits.HashLength)
            throw Error(MembershipContractError.InvalidField, "Membership commitment body is invalid.");
        var writer = WriteCommon(MembershipMagic, commitment.NetworkId, commitment.Sequence,
            commitment.PreviousHash, commitment.IssuedAtUnixSeconds, commitment.ValidFromUnixSeconds,
            commitment.ValidUntilUnixSeconds, commitment.MinimumProtocol, commitment.MaximumProtocol,
            commitment.PolicyVersion);
        writer.UInt32(commitment.MemberCount);
        writer.Fixed(commitment.MerkleRoot, MembershipLimits.HashLength, "Merkle root");
        return writer.ToArray();
    }

    public static NodeMembershipCommitment DecodeMembershipSigningBytes(ReadOnlySpan<byte> encoded)
    {
        var reader = new CanonicalReader(encoded, MembershipMagic);
        var result = new NodeMembershipCommitment
        {
            NetworkId = reader.Fixed(MembershipLimits.NetworkIdLength),
            Sequence = reader.UInt64(),
            PreviousHash = reader.Fixed(MembershipLimits.HashLength),
            IssuedAtUnixSeconds = reader.UInt64(),
            ValidFromUnixSeconds = reader.UInt64(),
            ValidUntilUnixSeconds = reader.UInt64(),
            MinimumProtocol = reader.UInt16(),
            MaximumProtocol = reader.UInt16(),
            PolicyVersion = reader.UInt32(),
            MemberCount = reader.UInt32(),
            MerkleRoot = reader.Fixed(MembershipLimits.HashLength)
        };
        reader.End();
        RequireCanonical(encoded, GetMembershipSigningBytes(result));
        return result;
    }

    public static byte[] EncodeForkWitness(ForkWitnessRecord witness)
    {
        ArgumentNullException.ThrowIfNull(witness);
        if (witness.CandidateDomain is not (
                MembershipSignatureDomain.Bridge or MembershipSignatureDomain.Membership) ||
            witness.Sequence == 0 ||
            witness.PreviousHash.Length != MembershipLimits.HashLength ||
            witness.CandidateHash.Length != MembershipLimits.HashLength)
            throw Error(MembershipContractError.InvalidField, "Fork witness is invalid.");
        var writer = new CanonicalWriter(80);
        writer.Magic(ForkMagic);
        writer.Byte(Version);
        writer.Zero(3);
        writer.Byte((byte)witness.CandidateDomain);
        writer.Zero(3);
        writer.UInt64(witness.Sequence);
        writer.Fixed(witness.PreviousHash, MembershipLimits.HashLength, "previous hash");
        writer.Fixed(witness.CandidateHash, MembershipLimits.HashLength, "candidate hash");
        return writer.ToArray();
    }

    public static ForkWitnessRecord DecodeForkWitness(ReadOnlySpan<byte> encoded)
    {
        var reader = new CanonicalReader(encoded, ForkMagic);
        var result = new ForkWitnessRecord
        {
            CandidateDomain = reader.Enum<MembershipSignatureDomain>(),
            Sequence = ReadWitnessRemainderSequence(ref reader),
            PreviousHash = reader.Fixed(MembershipLimits.HashLength),
            CandidateHash = reader.Fixed(MembershipLimits.HashLength)
        };
        reader.End();
        RequireCanonical(encoded, EncodeForkWitness(result));
        return result;
    }

    public static byte[] EncodeInclusionProof(MembershipInclusionProof proof)
    {
        ArgumentNullException.ThrowIfNull(proof);
        if (proof.NetworkId.Length != MembershipLimits.NetworkIdLength ||
            proof.Sequence == 0 ||
            proof.MemberCommitment.Length != MembershipLimits.HashLength ||
            proof.SiblingHashes.Count > MembershipLimits.MaximumInclusionProofDepth ||
            proof.SiblingHashes.Any(static hash => hash.Length != MembershipLimits.HashLength))
            throw Error(MembershipContractError.InvalidField, "Membership inclusion proof is invalid.");
        if (proof.SiblingHashes.Count < 32 &&
            proof.LeafIndex >= (1u << proof.SiblingHashes.Count))
            throw Error(MembershipContractError.InvalidField, "Leaf index exceeds the proof depth.");
        var writer = new CanonicalWriter(72 + proof.SiblingHashes.Count * MembershipLimits.HashLength);
        writer.Magic(InclusionProofMagic);
        writer.Byte(Version);
        writer.Zero(3);
        writer.Fixed(proof.NetworkId, MembershipLimits.NetworkIdLength, "network ID");
        writer.UInt64(proof.Sequence);
        writer.Fixed(proof.MemberCommitment, MembershipLimits.HashLength, "member commitment");
        writer.UInt32(proof.LeafIndex);
        writer.UInt16(checked((ushort)proof.SiblingHashes.Count));
        writer.Zero(2);
        foreach (var sibling in proof.SiblingHashes)
            writer.Fixed(sibling, MembershipLimits.HashLength, "sibling hash");
        return writer.ToArray();
    }

    public static MembershipInclusionProof DecodeInclusionProof(ReadOnlySpan<byte> encoded)
    {
        var reader = new CanonicalReader(encoded, InclusionProofMagic);
        var networkId = reader.Fixed(MembershipLimits.NetworkIdLength);
        var sequence = reader.UInt64();
        var commitment = reader.Fixed(MembershipLimits.HashLength);
        var leafIndex = reader.UInt32();
        var depth = reader.UInt16();
        if (depth > MembershipLimits.MaximumInclusionProofDepth)
            throw Error(MembershipContractError.InvalidLength, "Inclusion proof depth exceeds the bound.");
        reader.Zero(2);
        var siblings = new ReadOnlyMemory<byte>[depth];
        for (var index = 0; index < depth; index++)
            siblings[index] = reader.Fixed(MembershipLimits.HashLength);
        reader.End();
        var proof = new MembershipInclusionProof
        {
            NetworkId = networkId,
            Sequence = sequence,
            MemberCommitment = commitment,
            LeafIndex = leafIndex,
            SiblingHashes = siblings
        };
        RequireCanonical(encoded, EncodeInclusionProof(proof));
        return proof;
    }

    private static ulong ReadWitnessRemainderSequence(ref CanonicalReader reader)
    {
        reader.Zero(3);
        return reader.UInt64();
    }

    public static byte[] EncodeSignedMembership(SignedMembershipCommitment signed) =>
        EncodeSignedContainer(
            SignedMembershipMagic,
            GetMembershipSigningBytes(signed.Statement),
            signed.Signatures);

    public static byte[] EncodeSignedBridge(SignedBridgeSnapshot signed) =>
        EncodeSignedContainer(
            SignedBridgeMagic,
            GetBridgeSigningBytes(signed.Statement),
            signed.Signatures);

    public static SignedMembershipCommitment DecodeSignedMembership(ReadOnlySpan<byte> encoded)
    {
        DecodeSignedContainer(encoded, SignedMembershipMagic, out var statement, out var signatures);
        return new SignedMembershipCommitment
        {
            Statement = DecodeMembershipSigningBytes(statement),
            Signatures = signatures
        };
    }

    public static SignedBridgeSnapshot DecodeSignedBridge(ReadOnlySpan<byte> encoded)
    {
        DecodeSignedContainer(encoded, SignedBridgeMagic, out var statement, out var signatures);
        return new SignedBridgeSnapshot
        {
            Statement = DecodeBridgeSigningBytes(statement),
            Signatures = signatures
        };
    }

    private static byte[] EncodeDelegationStatement(SignerDelegation delegation)
    {
        ArgumentNullException.ThrowIfNull(delegation);
        ValidateCommon(delegation.NetworkId, delegation.Sequence, delegation.PreviousHash,
            delegation.IssuedAtUnixSeconds, delegation.ValidFromUnixSeconds,
            delegation.ValidUntilUnixSeconds, delegation.MinimumProtocol,
            delegation.MaximumProtocol, delegation.PolicyVersion);
        ValidateDescriptors(
            delegation.OnlineSigners,
            MembershipSignerRole.Online,
            expectedCount: 3);
        var writer = WriteCommon(DelegationMagic, delegation.NetworkId, delegation.Sequence,
            delegation.PreviousHash, delegation.IssuedAtUnixSeconds,
            delegation.ValidFromUnixSeconds, delegation.ValidUntilUnixSeconds,
            delegation.MinimumProtocol, delegation.MaximumProtocol, delegation.PolicyVersion);
        writer.UInt16(checked((ushort)delegation.OnlineSigners.Count));
        foreach (var signer in OrderDescriptors(delegation.OnlineSigners))
        {
            writer.Fixed(signer.SignerId, MembershipLimits.SignerIdLength, "signer ID");
            writer.Byte((byte)signer.Role);
            writer.Zero(3);
            writer.Fixed(signer.PublicKey, MembershipLimits.PublicKeyLength, "public key");
        }
        return writer.ToArray();
    }

    private static byte[] EncodeAuthorityStatement(
        ReadOnlySpan<byte> magic,
        ReadOnlyMemory<byte> networkId,
        ulong sequence,
        ReadOnlyMemory<byte> previousHash,
        ulong issued,
        ulong validFrom,
        ulong validUntil,
        ushort minimumProtocol,
        ushort maximumProtocol,
        uint policyVersion,
        IReadOnlyList<ReadOnlyMemory<byte>> signerIds,
        ReadOnlyMemory<byte>? extraHash)
    {
        ValidateCommon(networkId, sequence, previousHash, issued, validFrom, validUntil,
            minimumProtocol, maximumProtocol, policyVersion);
        if (signerIds.Count > MembershipLimits.MaximumSigners)
            throw Error(MembershipContractError.InvalidField, "Signer count exceeds canonical bounds.");
        var writer = WriteCommon(magic, networkId, sequence, previousHash, issued, validFrom, validUntil,
            minimumProtocol, maximumProtocol, policyVersion);
        writer.UInt16(checked((ushort)signerIds.Count));
        if (signerIds.Count != 0)
        {
            foreach (var signerId in OrderIds(signerIds))
                writer.Fixed(signerId, MembershipLimits.SignerIdLength, "signer ID");
        }
        if (extraHash.HasValue)
            writer.Fixed(extraHash.Value, MembershipLimits.HashLength, "delegation hash");
        return writer.ToArray();
    }

    private static CanonicalWriter WriteCommon(
        ReadOnlySpan<byte> magic,
        ReadOnlyMemory<byte> networkId,
        ulong sequence,
        ReadOnlyMemory<byte> previousHash,
        ulong issued,
        ulong validFrom,
        ulong validUntil,
        ushort minimumProtocol,
        ushort maximumProtocol,
        uint policyVersion)
    {
        var writer = new CanonicalWriter(128);
        writer.Magic(magic);
        writer.Byte(Version);
        writer.Zero(3);
        writer.Fixed(networkId, MembershipLimits.NetworkIdLength, "network ID");
        writer.UInt64(sequence);
        writer.Fixed(previousHash, MembershipLimits.HashLength, "previous hash");
        writer.UInt64(issued);
        writer.UInt64(validFrom);
        writer.UInt64(validUntil);
        writer.UInt16(minimumProtocol);
        writer.UInt16(maximumProtocol);
        writer.UInt32(policyVersion);
        return writer;
    }

    private static void ValidateCommon(
        ReadOnlyMemory<byte> networkId, ulong sequence, ReadOnlyMemory<byte> previousHash,
        ulong issued, ulong validFrom, ulong validUntil, ushort minimumProtocol,
        ushort maximumProtocol, uint policyVersion)
    {
        if (networkId.Length != MembershipLimits.NetworkIdLength ||
            previousHash.Length != MembershipLimits.HashLength ||
            sequence == 0 || policyVersion == 0 ||
            issued > validFrom || validFrom >= validUntil ||
            minimumProtocol == 0 || minimumProtocol > maximumProtocol)
            throw Error(MembershipContractError.InvalidField, "Common membership statement fields are invalid.");
    }

    private static void ValidateGenesis(NetworkGenesis genesis)
    {
        ValidatePolicy(genesis.Policy);
        if (genesis.NetworkId.Length != MembershipLimits.NetworkIdLength ||
            genesis.GenesisSequence == 0 ||
            genesis.PolicyVersion != genesis.Policy.Version ||
            genesis.MinimumProtocol == 0 ||
            genesis.MinimumProtocol > genesis.MaximumProtocol ||
            genesis.OfflineRoots.Count != genesis.Policy.OfflineRootSignerIds.Count ||
            genesis.OfflineRoots.Count != 5 ||
            !SetEquals(genesis.OfflineRoots.Select(static root => root.SignerId),
                genesis.Policy.OfflineRootSignerIds))
            throw Error(MembershipContractError.InvalidField, "Network genesis is invalid.");
        ValidateDescriptors(genesis.OfflineRoots, MembershipSignerRole.OfflineRoot, expectedCount: 5);
    }

    internal static void ValidatePolicy(MembershipPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ValidateIdSet(policy.OfflineRootSignerIds);
        ValidateIdSet(policy.OnlineSignerIds);
        if (policy.Version != 1 ||
            policy.OfflineThreshold != 3 || policy.OfflineRootSignerIds.Count != 5 ||
            policy.OnlineThreshold != 2 || policy.OnlineSignerIds.Count != 3)
            throw Error(MembershipContractError.InvalidPolicy, "Membership threshold policy is invalid.");
    }

    private static void WritePolicy(CanonicalWriter writer, MembershipPolicy policy)
    {
        ValidatePolicy(policy);
        writer.UInt32(policy.Version);
        writer.UInt16(policy.OfflineThreshold);
        writer.UInt16(policy.OnlineThreshold);
        writer.UInt16(checked((ushort)policy.OfflineRootSignerIds.Count));
        writer.UInt16(checked((ushort)policy.OnlineSignerIds.Count));
        foreach (var value in OrderIds(policy.OfflineRootSignerIds))
            writer.Fixed(value, MembershipLimits.SignerIdLength, "offline signer ID");
        foreach (var value in OrderIds(policy.OnlineSignerIds))
            writer.Fixed(value, MembershipLimits.SignerIdLength, "online signer ID");
    }

    private static MembershipPolicy ReadPolicy(ref CanonicalReader reader)
    {
        var version = reader.UInt32();
        var offlineThreshold = reader.UInt16();
        var onlineThreshold = reader.UInt16();
        var offlineCount = reader.Count(MembershipLimits.MaximumSigners);
        var onlineCount = reader.Count(MembershipLimits.MaximumSigners);
        var offline = new ReadOnlyMemory<byte>[offlineCount];
        for (var index = 0; index < offlineCount; index++)
            offline[index] = reader.Fixed(MembershipLimits.SignerIdLength);
        var online = new ReadOnlyMemory<byte>[onlineCount];
        for (var index = 0; index < onlineCount; index++)
            online[index] = reader.Fixed(MembershipLimits.SignerIdLength);
        return new MembershipPolicy
        {
            Version = version,
            OfflineThreshold = offlineThreshold,
            OnlineThreshold = onlineThreshold,
            OfflineRootSignerIds = offline,
            OnlineSignerIds = online
        };
    }

    private static byte[] EncodeSignedContainer(
        ReadOnlySpan<byte> magic,
        byte[] statement,
        IReadOnlyList<MembershipSignature> signatures)
    {
        if (signatures.Count is 0 or > MembershipLimits.MaximumSigners)
            throw Error(MembershipContractError.InvalidSignature, "Signature count is invalid.");
        if (statement.Length > ushort.MaxValue)
            throw Error(MembershipContractError.InvalidLength, "Signed statement is too large.");
        var writer = new CanonicalWriter(
            12 + statement.Length + signatures.Sum(static value => value.Signature.Length + 20));
        writer.Magic(magic);
        writer.Byte(Version);
        writer.Zero(1);
        writer.UInt16(checked((ushort)statement.Length));
        writer.UInt16(checked((ushort)signatures.Count));
        writer.Zero(2);
        writer.Bytes(statement);
        foreach (var signature in signatures.OrderBy(static value => value.SignerId, MemoryComparer.Instance))
        {
            writer.Fixed(signature.SignerId, MembershipLimits.SignerIdLength, "signer ID");
            writer.Byte((byte)signature.Domain);
            writer.Byte(0);
            if (signature.Signature.Length is < MembershipLimits.MinimumSignatureLength or > MembershipLimits.MaximumSignatureLength)
                throw Error(MembershipContractError.InvalidSignature, "Signature length is invalid.");
            writer.UInt16(checked((ushort)signature.Signature.Length));
            writer.Bytes(signature.Signature.Span);
        }
        return writer.ToArray();
    }

    private static void DecodeSignedContainer(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> magic,
        out byte[] statement,
        out IReadOnlyList<MembershipSignature> signatures)
    {
        var reader = new CanonicalReader(encoded, magic, reservedAfterVersion: 1);
        var statementLength = reader.UInt16();
        var signatureCount = reader.Count(MembershipLimits.MaximumSigners);
        reader.Zero(2);
        statement = reader.Fixed(statementLength);
        var values = new MembershipSignature[signatureCount];
        for (var index = 0; index < signatureCount; index++)
        {
            var signerId = reader.Fixed(MembershipLimits.SignerIdLength);
            var domain = reader.Enum<MembershipSignatureDomain>();
            reader.Zero(1);
            var signatureLength = reader.UInt16();
            if (signatureLength is < MembershipLimits.MinimumSignatureLength or > MembershipLimits.MaximumSignatureLength)
                throw Error(MembershipContractError.InvalidSignature, "Signature length is invalid.");
            values[index] = new MembershipSignature
            {
                SignerId = signerId,
                Domain = domain,
                Signature = reader.Fixed(signatureLength)
            };
        }
        reader.End();
        var canonicalIds = values.Select(static value => value.SignerId).ToArray();
        ValidateDistinctMemories(canonicalIds, MembershipLimits.SignerIdLength, "Signature signer IDs");
        if (!canonicalIds.SequenceEqual(
                canonicalIds.OrderBy(static value => value, MemoryComparer.Instance),
                MemoryEqualityComparer.Instance))
            throw Error(MembershipContractError.NonCanonicalOrder, "Signatures are not canonically ordered.");
        signatures = values;
    }

    private static void ReadCommon(
        ref CanonicalReader reader,
        out byte[] networkId,
        out ulong sequence,
        out byte[] previousHash,
        out ulong issued,
        out ulong validFrom,
        out ulong validUntil,
        out ushort minimumProtocol,
        out ushort maximumProtocol,
        out uint policyVersion)
    {
        networkId = reader.Fixed(MembershipLimits.NetworkIdLength);
        sequence = reader.UInt64();
        previousHash = reader.Fixed(MembershipLimits.HashLength);
        issued = reader.UInt64();
        validFrom = reader.UInt64();
        validUntil = reader.UInt64();
        minimumProtocol = reader.UInt16();
        maximumProtocol = reader.UInt16();
        policyVersion = reader.UInt32();
    }

    private static void ValidateDescriptors(
        IReadOnlyList<MembershipSignerDescriptor> descriptors,
        MembershipSignerRole role,
        int expectedCount)
    {
        if (descriptors.Count != expectedCount ||
            descriptors.Any(value =>
                value.Role != role ||
                value.SignerId.Length != MembershipLimits.SignerIdLength ||
                value.PublicKey.Length != MembershipLimits.PublicKeyLength))
            throw Error(MembershipContractError.InvalidField, "Signer descriptors are invalid.");
        ValidateDistinctMemories(
            descriptors.Select(static value => value.SignerId).ToArray(),
            MembershipLimits.SignerIdLength,
            "Signer identifiers");
        ValidateDistinctMemories(
            descriptors.Select(static value => value.PublicKey).ToArray(),
            MembershipLimits.PublicKeyLength,
            "Signer public keys");
    }

    private static void ValidateDistinctMemories(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        int requiredLength,
        string name)
    {
        if (values.Any(value => value.Length != requiredLength))
            throw Error(MembershipContractError.InvalidLength, $"{name} have invalid lengths.");
        var encoded = values.Select(static value => Convert.ToHexString(value.Span)).ToArray();
        if (encoded.Distinct(StringComparer.Ordinal).Count() != encoded.Length)
            throw Error(MembershipContractError.DuplicateSigner, $"{name} must be distinct.");
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> OrderIds(IEnumerable<ReadOnlyMemory<byte>> values)
    {
        var ordered = values.OrderBy(static value => value, MemoryComparer.Instance).ToArray();
        ValidateIdSet(ordered);
        return ordered;
    }

    private static IReadOnlyList<MembershipSignerDescriptor> OrderDescriptors(
        IEnumerable<MembershipSignerDescriptor> values)
    {
        var ordered = values.OrderBy(static value => value.SignerId, MemoryComparer.Instance).ToArray();
        ValidateIdSet(ordered.Select(static value => value.SignerId).ToArray());
        return ordered;
    }

    private static void ValidateIdSet(IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        if (values.Count is 0 or > MembershipLimits.MaximumSigners ||
            values.Any(static value => value.Length != MembershipLimits.SignerIdLength))
            throw Error(MembershipContractError.InvalidField, "Signer identifiers are invalid.");
        var keys = values.Select(static value => Convert.ToHexString(value.Span)).ToArray();
        if (keys.Distinct(StringComparer.Ordinal).Count() != keys.Length)
            throw Error(MembershipContractError.DuplicateSigner, "Signer identifiers must be distinct.");
    }

    private static bool SetEquals(
        IEnumerable<ReadOnlyMemory<byte>> first,
        IEnumerable<ReadOnlyMemory<byte>> second) =>
        first.Select(static value => Convert.ToHexString(value.Span)).ToHashSet(StringComparer.Ordinal)
            .SetEquals(second.Select(static value => Convert.ToHexString(value.Span)));

    private static void RequireCanonical(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> canonical)
    {
        if (!actual.SequenceEqual(canonical))
            throw Error(MembershipContractError.NonCanonicalOrder, "Encoding is not canonical.");
    }

    private static MembershipContractException Error(MembershipContractError error, string message) =>
        new(error, message);

    private sealed class MemoryComparer : IComparer<ReadOnlyMemory<byte>>
    {
        public static readonly MemoryComparer Instance = new();
        public int Compare(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y) =>
            x.Span.SequenceCompareTo(y.Span);
    }

    private sealed class MemoryEqualityComparer : IEqualityComparer<ReadOnlyMemory<byte>>
    {
        public static readonly MemoryEqualityComparer Instance = new();
        public bool Equals(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y) =>
            x.Span.SequenceEqual(y.Span);
        public int GetHashCode(ReadOnlyMemory<byte> obj) =>
            obj.IsEmpty ? 0 : BinaryPrimitives.ReadInt32BigEndian(obj.Span[..Math.Min(4, obj.Length)]);
    }

    private sealed class CanonicalWriter(int capacity)
    {
        private readonly List<byte> _bytes = new(capacity);
        public void Magic(ReadOnlySpan<byte> value) => Bytes(value);
        public void Byte(byte value) => _bytes.Add(value);
        public void Zero(int count) { for (var i = 0; i < count; i++) _bytes.Add(0); }
        public void UInt16(ushort value) { Span<byte> b = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); Bytes(b); }
        public void UInt32(uint value) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); Bytes(b); }
        public void UInt64(ulong value) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); Bytes(b); }
        public void Fixed(ReadOnlyMemory<byte> value, int length, string name)
        {
            if (value.Length != length) throw Error(MembershipContractError.InvalidLength, $"{name} length is invalid.");
            Bytes(value.Span);
        }
        public void String(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) throw Error(MembershipContractError.InvalidField, "Contact is empty.");
            var encoded = Encoding.UTF8.GetBytes(value);
            if (encoded.Length > MembershipLimits.MaximumContactLength) throw Error(MembershipContractError.InvalidLength, "Contact is too long.");
            UInt16(checked((ushort)encoded.Length));
            Bytes(encoded);
        }
        public void Bytes(ReadOnlySpan<byte> value) { foreach (var item in value) _bytes.Add(item); }
        public byte[] ToArray() => _bytes.ToArray();
    }

    private ref struct CanonicalReader
    {
        private readonly ReadOnlySpan<byte> _bytes;
        private int _offset;
        public CanonicalReader(
            ReadOnlySpan<byte> bytes,
            ReadOnlySpan<byte> magic,
            int reservedAfterVersion = 3)
        {
            _bytes = bytes;
            _offset = 0;
            if (bytes.Length < 8) throw Error(MembershipContractError.InvalidLength, "Statement is truncated.");
            if (!Take(4).SequenceEqual(magic)) throw Error(MembershipContractError.InvalidMagic, "Statement magic is invalid.");
            if (Take(1)[0] != Version) throw Error(MembershipContractError.UnsupportedVersion, "Statement version is unsupported.");
            Zero(reservedAfterVersion);
        }
        public byte[] Fixed(int length) => Take(length).ToArray();
        public ushort UInt16() => BinaryPrimitives.ReadUInt16BigEndian(Take(2));
        public uint UInt32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));
        public ulong UInt64() => BinaryPrimitives.ReadUInt64BigEndian(Take(8));
        public int Count(int maximum) { var count = UInt16(); if (count == 0 || count > maximum) throw Error(MembershipContractError.InvalidLength, "Count is invalid."); return count; }
        public T Enum<T>() where T : struct, Enum
        {
            var value = Take(1)[0];
            if (!System.Enum.IsDefined(typeof(T), value)) throw Error(MembershipContractError.InvalidEnum, "Enum value is invalid.");
            return (T)System.Enum.ToObject(typeof(T), value);
        }
        public string String()
        {
            var length = UInt16();
            if (length == 0 || length > MembershipLimits.MaximumContactLength)
                throw Error(MembershipContractError.InvalidLength, "String length is invalid.");
            try
            {
                return new UTF8Encoding(false, true).GetString(Take(length));
            }
            catch (DecoderFallbackException exception)
            {
                throw new MembershipContractException(
                    MembershipContractError.InvalidField,
                    $"String is not canonical UTF-8: {exception.Message}");
            }
        }
        public ReadOnlySpan<byte> Remaining() => _bytes[_offset..];
        public void ConsumeRemaining() => _offset = _bytes.Length;
        public void Zero(int count)
        {
            if (Take(count).IndexOfAnyExcept((byte)0) >= 0) throw Error(MembershipContractError.ReservedFieldNotZero, "Reserved bytes must be zero.");
        }
        public void End() { if (_offset != _bytes.Length) throw Error(MembershipContractError.InvalidLength, "Statement contains trailing bytes."); }
        private ReadOnlySpan<byte> Take(int length)
        {
            if (length < 0 || _offset > _bytes.Length - length) throw Error(MembershipContractError.InvalidLength, "Statement is truncated.");
            var value = _bytes.Slice(_offset, length);
            _offset += length;
            return value;
        }
    }
}
