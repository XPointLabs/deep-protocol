namespace Deep.Protocol.DeepExtension.Membership;

public static class MembershipContractVerifier
{
    public static VerifiedMembershipCommitment VerifyMembership(
        SignedMembershipCommitment signed,
        MembershipVerificationContext context,
        IMembershipSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(signed);
        var statement = MembershipContractCodec.GetMembershipSigningBytes(signed.Statement);
        VerifyOnlineStatement(
            signed.Statement.NetworkId, signed.Statement.Sequence, signed.Statement.PreviousHash,
            signed.Statement.ValidFromUnixSeconds, signed.Statement.ValidUntilUnixSeconds,
            signed.Statement.MinimumProtocol, signed.Statement.MaximumProtocol,
            signed.Statement.PolicyVersion, MembershipSignatureDomain.Membership,
            statement, signed.Signatures, context, verifier);
        var hash = MembershipContractHash.Sha256(statement);
        return new VerifiedMembershipCommitment
        {
            Statement = signed.Statement,
            CanonicalHash = hash,
            NextLastKnownGood = NextLkg(context.LastKnownGood, signed.Statement.Sequence, hash)
        };
    }

    public static VerifiedBridgeSnapshot VerifyBridge(
        SignedBridgeSnapshot signed,
        MembershipVerificationContext context,
        IMembershipSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(signed);
        var statement = MembershipContractCodec.GetBridgeSigningBytes(signed.Statement);
        VerifyOnlineStatement(
            signed.Statement.NetworkId, signed.Statement.Sequence, signed.Statement.PreviousHash,
            signed.Statement.ValidFromUnixSeconds, signed.Statement.ValidUntilUnixSeconds,
            signed.Statement.MinimumProtocol, signed.Statement.MaximumProtocol,
            signed.Statement.PolicyVersion, MembershipSignatureDomain.Bridge,
            statement, signed.Signatures, context, verifier);
        var hash = MembershipContractHash.Sha256(statement);
        var candidateHash = MembershipContractHash.Sha256(
            MembershipContractCodec.GetBridgeCandidateBytes(signed.Statement));
        var witness = signed.Statement.ForkWitness;
        if (witness.CandidateDomain != MembershipSignatureDomain.Bridge ||
            witness.Sequence != signed.Statement.Sequence ||
            !witness.PreviousHash.Span.SequenceEqual(signed.Statement.PreviousHash.Span) ||
            !witness.CandidateHash.Span.SequenceEqual(candidateHash))
            throw Error(MembershipContractError.InvalidField, "Fork witness does not bind the bridge candidate.");
        return new VerifiedBridgeSnapshot
        {
            Statement = signed.Statement,
            CanonicalHash = hash,
            NextLastKnownGood = NextLkg(context.LastKnownGood, signed.Statement.Sequence, hash)
        };
    }

    public static VerifiedSignerDelegation VerifyDelegation(
        SignerDelegation delegation,
        NetworkGenesis genesis,
        MembershipLastKnownGood authorityLastKnownGood,
        ulong verificationTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocol,
        IMembershipSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(delegation);
        ValidateAuthoritySuccessor(
            delegation.NetworkId,
            delegation.PolicyVersion,
            delegation.Sequence,
            delegation.PreviousHash,
            genesis,
            authorityLastKnownGood);
        VerifyDelegationAuthority(
            delegation, genesis, verificationTimeUnixSeconds,
            allowedClockSkewSeconds, protocol, verifier);
        var canonical = MembershipContractCodec.GetDelegationSigningBytes(delegation);
        var hash = MembershipContractHash.Sha256(canonical);
        return new VerifiedSignerDelegation
        {
            Statement = delegation,
            CanonicalHash = hash,
            NextAuthorityLastKnownGood = NextLkg(
                authorityLastKnownGood, delegation.Sequence, hash)
        };
    }

    public static VerifiedSignerRevocation VerifyRevocation(
        SignerRevocation revocation,
        NetworkGenesis genesis,
        MembershipLastKnownGood authorityLastKnownGood,
        ulong verificationTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocol,
        IMembershipSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(revocation);
        ValidateAuthoritySuccessor(
            revocation.NetworkId,
            revocation.PolicyVersion,
            revocation.Sequence,
            revocation.PreviousHash,
            genesis,
            authorityLastKnownGood);
        ValidateSkew(allowedClockSkewSeconds);
        VerifyTimeAndProtocol(
            revocation.ValidFromUnixSeconds, revocation.ValidUntilUnixSeconds,
            revocation.MinimumProtocol, revocation.MaximumProtocol,
            verificationTimeUnixSeconds, allowedClockSkewSeconds, protocol);
        VerifySignatures(
            MembershipContractCodec.GetRevocationSigningBytes(revocation),
            revocation.Signatures,
            MembershipSignatureDomain.OfflineRevocation,
            genesis.OfflineRoots,
            genesis.Policy.OfflineThreshold,
            verifier);
        var canonical = MembershipContractCodec.GetRevocationSigningBytes(revocation);
        var hash = MembershipContractHash.Sha256(canonical);
        return new VerifiedSignerRevocation
        {
            Statement = revocation,
            CanonicalHash = hash,
            NextAuthorityLastKnownGood = NextLkg(
                authorityLastKnownGood, revocation.Sequence, hash)
        };
    }

    public static MembershipForkEvidence CreateForkEvidence(
        SignedMembershipCommitment first,
        SignedMembershipCommitment second,
        MembershipVerificationContext context,
        IMembershipSignatureVerifier verifier)
    {
        var firstBytes = MembershipContractCodec.GetMembershipSigningBytes(first.Statement);
        var secondBytes = MembershipContractCodec.GetMembershipSigningBytes(second.Statement);
        _ = VerifyMembership(first, context, verifier);
        _ = VerifyMembership(second, context, verifier);
        return CreateEvidence(
            MembershipSignatureDomain.Membership,
            first.Statement.NetworkId,
            first.Statement.Sequence,
            first.Statement.PreviousHash,
            firstBytes,
            second.Statement.NetworkId,
            second.Statement.Sequence,
            second.Statement.PreviousHash,
            secondBytes);
    }

    public static MembershipForkEvidence CreateDelegationForkEvidence(
        SignerDelegation first,
        SignerDelegation second,
        NetworkGenesis genesis,
        MembershipLastKnownGood authorityLastKnownGood,
        ulong verificationTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocol,
        IMembershipSignatureVerifier verifier)
    {
        _ = VerifyDelegation(first, genesis, authorityLastKnownGood,
            verificationTimeUnixSeconds, allowedClockSkewSeconds, protocol, verifier);
        _ = VerifyDelegation(second, genesis, authorityLastKnownGood,
            verificationTimeUnixSeconds, allowedClockSkewSeconds, protocol, verifier);
        return CreateEvidence(
            MembershipSignatureDomain.OfflineDelegation,
            first.NetworkId, first.Sequence, first.PreviousHash,
            MembershipContractCodec.GetDelegationSigningBytes(first),
            second.NetworkId, second.Sequence, second.PreviousHash,
            MembershipContractCodec.GetDelegationSigningBytes(second));
    }

    public static MembershipForkEvidence CreateRevocationForkEvidence(
        SignerRevocation first,
        SignerRevocation second,
        NetworkGenesis genesis,
        MembershipLastKnownGood authorityLastKnownGood,
        ulong verificationTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocol,
        IMembershipSignatureVerifier verifier)
    {
        _ = VerifyRevocation(first, genesis, authorityLastKnownGood,
            verificationTimeUnixSeconds, allowedClockSkewSeconds, protocol, verifier);
        _ = VerifyRevocation(second, genesis, authorityLastKnownGood,
            verificationTimeUnixSeconds, allowedClockSkewSeconds, protocol, verifier);
        return CreateEvidence(
            MembershipSignatureDomain.OfflineRevocation,
            first.NetworkId, first.Sequence, first.PreviousHash,
            MembershipContractCodec.GetRevocationSigningBytes(first),
            second.NetworkId, second.Sequence, second.PreviousHash,
            MembershipContractCodec.GetRevocationSigningBytes(second));
    }

    public static MembershipForkEvidence CreateBridgeForkEvidence(
        SignedBridgeSnapshot first,
        SignedBridgeSnapshot second,
        MembershipVerificationContext context,
        IMembershipSignatureVerifier verifier)
    {
        _ = VerifyBridge(first, context, verifier);
        _ = VerifyBridge(second, context, verifier);
        return CreateEvidence(
            MembershipSignatureDomain.Bridge,
            first.Statement.NetworkId, first.Statement.Sequence, first.Statement.PreviousHash,
            MembershipContractCodec.GetBridgeSigningBytes(first.Statement),
            second.Statement.NetworkId, second.Statement.Sequence, second.Statement.PreviousHash,
            MembershipContractCodec.GetBridgeSigningBytes(second.Statement));
    }

    public static NetworkGenesis ImportSelfHostedGenesis(
        ReadOnlySpan<byte> canonicalGenesis,
        IReadOnlyList<MembershipSignature> signatures,
        IMembershipSignatureVerifier verifier)
    {
        var genesis = MembershipContractCodec.DecodeGenesis(canonicalGenesis);
        VerifySignatures(
            canonicalGenesis.ToArray(),
            signatures,
            MembershipSignatureDomain.Genesis,
            genesis.OfflineRoots,
            genesis.Policy.OfflineThreshold,
            verifier);
        return genesis;
    }

    private static void VerifyOnlineStatement(
        ReadOnlyMemory<byte> networkId,
        ulong sequence,
        ReadOnlyMemory<byte> previousHash,
        ulong validFrom,
        ulong validUntil,
        ushort minimumProtocol,
        ushort maximumProtocol,
        uint policyVersion,
        MembershipSignatureDomain domain,
        byte[] statement,
        IReadOnlyList<MembershipSignature> signatures,
        MembershipVerificationContext context,
        IMembershipSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(verifier);
        MembershipContractCodec.ValidatePolicy(context.Genesis.Policy);
        ValidateSkew(context.AllowedClockSkewSeconds);
        ValidateSuccessor(
            networkId, policyVersion, sequence, previousHash,
            context.Genesis, context.LastKnownGood);
        VerifyTimeAndProtocol(
            validFrom, validUntil, minimumProtocol, maximumProtocol,
            context.VerificationTimeUnixSeconds, context.AllowedClockSkewSeconds,
            context.ClientProtocol);
        VerifyPinnedDelegation(context, verifier);
        VerifySignatures(
            statement,
            signatures,
            domain,
            context.ActiveDelegation.OnlineSigners,
            context.Genesis.Policy.OnlineThreshold,
            verifier);
    }

    private static void VerifyPinnedDelegation(
        MembershipVerificationContext context,
        IMembershipSignatureVerifier verifier)
    {
        var delegation = context.ActiveDelegation;
        var authority = context.AuthorityLastKnownGood;
        if (!authority.NetworkId.Span.SequenceEqual(context.Genesis.NetworkId.Span) ||
            authority.PolicyVersion != context.Genesis.PolicyVersion ||
            delegation.Sequence != authority.Sequence ||
            !delegation.NetworkId.Span.SequenceEqual(authority.NetworkId.Span))
            throw Error(MembershipContractError.AuthorityMismatch, "Active delegation authority LKG is inconsistent.");
        var canonical = MembershipContractCodec.GetDelegationSigningBytes(delegation);
        var hash = MembershipContractHash.Sha256(canonical);
        if (!authority.CanonicalHash.Span.SequenceEqual(hash))
            throw Error(MembershipContractError.AuthorityMismatch, "Active delegation is not the authority LKG.");
        VerifyDelegationAuthority(
            delegation,
            context.Genesis,
            context.VerificationTimeUnixSeconds,
            context.AllowedClockSkewSeconds,
            context.ClientProtocol,
            verifier);
        if (context.RevokedDelegationHashes.Any(value => value.Span.SequenceEqual(hash)))
            throw Error(MembershipContractError.RevokedDelegation, "Online signer delegation is revoked.");
    }

    private static void VerifyDelegationAuthority(
        SignerDelegation delegation,
        NetworkGenesis genesis,
        ulong verificationTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocol,
        IMembershipSignatureVerifier verifier)
    {
        ValidateSkew(allowedClockSkewSeconds);
        MembershipContractCodec.ValidatePolicy(genesis.Policy);
        if (!delegation.NetworkId.Span.SequenceEqual(genesis.NetworkId.Span))
            throw Error(MembershipContractError.NetworkMismatch, "Delegation network does not match genesis.");
        if (delegation.PolicyVersion != genesis.PolicyVersion ||
            !SetEquals(
                delegation.OnlineSigners.Select(static signer => signer.SignerId),
                genesis.Policy.OnlineSignerIds))
            throw Error(MembershipContractError.PolicyMismatch, "Delegation policy does not match genesis.");
        VerifyTimeAndProtocol(
            delegation.ValidFromUnixSeconds, delegation.ValidUntilUnixSeconds,
            delegation.MinimumProtocol, delegation.MaximumProtocol,
            verificationTimeUnixSeconds, allowedClockSkewSeconds, protocol);
        VerifySignatures(
            MembershipContractCodec.GetDelegationSigningBytes(delegation),
            delegation.Signatures,
            MembershipSignatureDomain.OfflineDelegation,
            genesis.OfflineRoots,
            genesis.Policy.OfflineThreshold,
            verifier);
    }

    private static void VerifySignatures(
        byte[] canonicalStatement,
        IReadOnlyList<MembershipSignature> signatures,
        MembershipSignatureDomain expectedDomain,
        IReadOnlyList<MembershipSignerDescriptor> authorizedSigners,
        int threshold,
        IMembershipSignatureVerifier verifier)
    {
        if (signatures.Count == 0)
            throw Error(MembershipContractError.InsufficientQuorum, "No signatures were supplied.");
        var authorized = authorizedSigners.ToDictionary(
            static signer => Convert.ToHexString(signer.SignerId.Span),
            StringComparer.Ordinal);
        var framed = MembershipSigningDomains.Frame(expectedDomain, canonicalStatement);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var accepted = 0;
        foreach (var signature in signatures)
        {
            if (signature.Domain != expectedDomain)
                throw Error(MembershipContractError.WrongSignatureDomain, "Signature domain is not interchangeable.");
            if (signature.SignerId.Length != MembershipLimits.SignerIdLength ||
                signature.Signature.Length is < MembershipLimits.MinimumSignatureLength or > MembershipLimits.MaximumSignatureLength)
                throw Error(MembershipContractError.InvalidSignature, "Signature framing is invalid.");
            var signerId = Convert.ToHexString(signature.SignerId.Span);
            if (!authorized.TryGetValue(signerId, out var signer))
                throw Error(MembershipContractError.UnknownSigner, "Signer is not authorized for this role.");
            if (!seen.Add(signerId))
                throw Error(MembershipContractError.DuplicateSigner, "Duplicate signatures do not count toward quorum.");
            if (!verifier.Verify(
                    signature.SignerId.Span,
                    signer.PublicKey.Span,
                    expectedDomain,
                    framed,
                    signature.Signature.Span))
                throw Error(MembershipContractError.InvalidSignature, "Signature verification failed.");
            accepted++;
        }
        if (accepted < threshold)
            throw Error(MembershipContractError.InsufficientQuorum, "Signature threshold was not met.");
    }

    private static void ValidateAuthoritySuccessor(
        ReadOnlyMemory<byte> networkId,
        uint policyVersion,
        ulong sequence,
        ReadOnlyMemory<byte> previousHash,
        NetworkGenesis genesis,
        MembershipLastKnownGood authorityLastKnownGood)
    {
        ValidateSuccessor(
            networkId, policyVersion, sequence, previousHash, genesis, authorityLastKnownGood);
    }

    private static void ValidateSuccessor(
        ReadOnlyMemory<byte> networkId,
        uint policyVersion,
        ulong sequence,
        ReadOnlyMemory<byte> previousHash,
        NetworkGenesis genesis,
        MembershipLastKnownGood lastKnownGood)
    {
        if (!networkId.Span.SequenceEqual(genesis.NetworkId.Span) ||
            !networkId.Span.SequenceEqual(lastKnownGood.NetworkId.Span))
            throw Error(MembershipContractError.NetworkMismatch, "Statement is for another network.");
        if (policyVersion != genesis.PolicyVersion ||
            policyVersion != lastKnownGood.PolicyVersion)
            throw Error(MembershipContractError.PolicyMismatch, "Statement policy version is not trusted.");
        if (lastKnownGood.Sequence == ulong.MaxValue)
            throw Error(MembershipContractError.SequenceOverflow, "Sequence cannot advance beyond UInt64.");
        if (sequence != lastKnownGood.Sequence + 1)
            throw Error(MembershipContractError.InvalidSequence, "Statement must be the next monotonic sequence.");
        if (!previousHash.Span.SequenceEqual(lastKnownGood.CanonicalHash.Span))
            throw Error(MembershipContractError.PreviousHashMismatch, "Statement previous hash does not match LKG.");
    }

    private static MembershipForkEvidence CreateEvidence(
        MembershipSignatureDomain domain,
        ReadOnlyMemory<byte> firstNetwork,
        ulong firstSequence,
        ReadOnlyMemory<byte> firstPrevious,
        byte[] firstBytes,
        ReadOnlyMemory<byte> secondNetwork,
        ulong secondSequence,
        ReadOnlyMemory<byte> secondPrevious,
        byte[] secondBytes)
    {
        var firstHash = MembershipContractHash.Sha256(firstBytes);
        var secondHash = MembershipContractHash.Sha256(secondBytes);
        if (firstSequence != secondSequence ||
            !firstNetwork.Span.SequenceEqual(secondNetwork.Span) ||
            !firstPrevious.Span.SequenceEqual(secondPrevious.Span) ||
            firstHash.AsSpan().SequenceEqual(secondHash))
            throw Error(MembershipContractError.NotForkEvidence, "Statements do not prove equivocation.");
        return new MembershipForkEvidence
        {
            NetworkId = firstNetwork.ToArray(),
            Domain = domain,
            Sequence = firstSequence,
            PreviousHash = firstPrevious.ToArray(),
            FirstCanonicalStatement = firstBytes,
            SecondCanonicalStatement = secondBytes,
            FirstHash = firstHash,
            SecondHash = secondHash
        };
    }

    private static void VerifyTimeAndProtocol(
        ulong validFrom, ulong validUntil, ushort minimumProtocol, ushort maximumProtocol,
        ulong now, uint skew, ushort protocol)
    {
        if (validFrom >= validUntil)
            throw Error(MembershipContractError.InvalidValidityWindow, "Validity window is invalid.");
        if (protocol < minimumProtocol || protocol > maximumProtocol)
            throw Error(MembershipContractError.ProtocolMismatch, "Protocol is outside the signed range.");
        if (now < validFrom && validFrom - now > skew)
            throw Error(MembershipContractError.NotYetValid, "Statement is not yet valid.");
        if (now > validUntil && now - validUntil > skew)
            throw Error(MembershipContractError.Expired, "Statement has expired.");
    }

    private static void ValidateSkew(uint skew)
    {
        if (skew > MembershipLimits.MaximumClockSkewSeconds)
            throw Error(MembershipContractError.ClockSkewOutOfRange, "Clock skew exceeds the fail-closed bound.");
    }

    private static MembershipLastKnownGood NextLkg(
        MembershipLastKnownGood current, ulong sequence, ReadOnlyMemory<byte> hash) =>
        new()
        {
            NetworkId = current.NetworkId.ToArray(),
            PolicyVersion = current.PolicyVersion,
            Sequence = sequence,
            CanonicalHash = hash.ToArray()
        };

    private static bool SetEquals(
        IEnumerable<ReadOnlyMemory<byte>> first,
        IEnumerable<ReadOnlyMemory<byte>> second) =>
        first.Select(static value => Convert.ToHexString(value.Span)).ToHashSet(StringComparer.Ordinal)
            .SetEquals(second.Select(static value => Convert.ToHexString(value.Span)));

    private static MembershipContractException Error(MembershipContractError error, string message) =>
        new(error, message);
}
