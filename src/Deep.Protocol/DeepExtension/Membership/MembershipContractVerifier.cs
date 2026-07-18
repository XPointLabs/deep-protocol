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
        var hash = Digest(verifier, statement);
        return new VerifiedMembershipCommitment
        {
            Statement = signed.Statement,
            CanonicalHash = hash,
            NextLastKnownGood = NextLkg(context, signed.Statement.Sequence, hash)
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
        var hash = Digest(verifier, statement);
        var candidateHash = Digest(verifier,
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
            NextLastKnownGood = NextLkg(context, signed.Statement.Sequence, hash)
        };
    }

    public static void VerifyDelegation(
        SignerDelegation delegation,
        NetworkGenesis genesis,
        ulong verificationTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocol,
        IMembershipSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(delegation);
        ArgumentNullException.ThrowIfNull(genesis);
        ValidateSkew(allowedClockSkewSeconds);
        MembershipContractCodec.ValidatePolicy(genesis.Policy);
        if (!delegation.NetworkId.Span.SequenceEqual(genesis.NetworkId.Span))
            throw Error(MembershipContractError.NetworkMismatch, "Delegation network does not match genesis.");
        if (delegation.PolicyVersion != genesis.PolicyVersion ||
            !SetEquals(delegation.OnlineSignerIds, genesis.Policy.OnlineSignerIds))
            throw Error(MembershipContractError.PolicyMismatch, "Delegation policy does not match genesis.");
        VerifyTimeAndProtocol(delegation.ValidFromUnixSeconds, delegation.ValidUntilUnixSeconds,
            delegation.MinimumProtocol, delegation.MaximumProtocol, verificationTimeUnixSeconds,
            allowedClockSkewSeconds, protocol);
        VerifySignatures(MembershipContractCodec.GetDelegationSigningBytes(delegation),
            delegation.Signatures, MembershipSignatureDomain.OfflineDelegation,
            genesis.Policy.OfflineRootSignerIds, genesis.Policy.OfflineThreshold, verifier);
    }

    public static void VerifyRevocation(
        SignerRevocation revocation,
        NetworkGenesis genesis,
        ulong verificationTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocol,
        IMembershipSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(revocation);
        if (!revocation.NetworkId.Span.SequenceEqual(genesis.NetworkId.Span) ||
            revocation.PolicyVersion != genesis.PolicyVersion)
            throw Error(MembershipContractError.NetworkMismatch, "Revocation authority does not match genesis.");
        ValidateSkew(allowedClockSkewSeconds);
        VerifyTimeAndProtocol(revocation.ValidFromUnixSeconds, revocation.ValidUntilUnixSeconds,
            revocation.MinimumProtocol, revocation.MaximumProtocol, verificationTimeUnixSeconds,
            allowedClockSkewSeconds, protocol);
        VerifySignatures(MembershipContractCodec.GetRevocationSigningBytes(revocation),
            revocation.Signatures, MembershipSignatureDomain.OfflineRevocation,
            genesis.Policy.OfflineRootSignerIds, genesis.Policy.OfflineThreshold, verifier);
    }

    public static MembershipForkEvidence CreateForkEvidence(
        SignedMembershipCommitment first,
        SignedMembershipCommitment second,
        MembershipVerificationContext context,
        IMembershipSignatureVerifier verifier)
    {
        var firstBytes = MembershipContractCodec.GetMembershipSigningBytes(first.Statement);
        var secondBytes = MembershipContractCodec.GetMembershipSigningBytes(second.Statement);
        VerifyForkCandidate(first, context, verifier, firstBytes);
        VerifyForkCandidate(second, context, verifier, secondBytes);
        var firstHash = Digest(verifier, firstBytes);
        var secondHash = Digest(verifier, secondBytes);
        if (first.Statement.Sequence != second.Statement.Sequence ||
            !first.Statement.NetworkId.Span.SequenceEqual(second.Statement.NetworkId.Span) ||
            !first.Statement.PreviousHash.Span.SequenceEqual(second.Statement.PreviousHash.Span) ||
            firstHash.AsSpan().SequenceEqual(secondHash))
            throw Error(MembershipContractError.NotForkEvidence, "Statements do not prove equivocation.");
        return new MembershipForkEvidence
        {
            NetworkId = first.Statement.NetworkId.ToArray(),
            Domain = MembershipSignatureDomain.Membership,
            Sequence = first.Statement.Sequence,
            PreviousHash = first.Statement.PreviousHash.ToArray(),
            FirstCanonicalStatement = firstBytes,
            SecondCanonicalStatement = secondBytes,
            FirstHash = firstHash,
            SecondHash = secondHash
        };
    }

    public static NetworkGenesis ImportSelfHostedGenesis(
        ReadOnlySpan<byte> canonicalGenesis,
        IReadOnlyList<MembershipSignature> signatures,
        IMembershipSignatureVerifier verifier)
    {
        var genesis = MembershipContractCodec.DecodeGenesis(canonicalGenesis);
        VerifySignatures(canonicalGenesis.ToArray(), signatures, MembershipSignatureDomain.Genesis,
            genesis.Policy.OfflineRootSignerIds, genesis.Policy.OfflineThreshold, verifier);
        return genesis;
    }

    private static void VerifyForkCandidate(
        SignedMembershipCommitment signed,
        MembershipVerificationContext context,
        IMembershipSignatureVerifier verifier,
        byte[] bytes)
    {
        VerifyOnlineStatement(
            signed.Statement.NetworkId, signed.Statement.Sequence, signed.Statement.PreviousHash,
            signed.Statement.ValidFromUnixSeconds, signed.Statement.ValidUntilUnixSeconds,
            signed.Statement.MinimumProtocol, signed.Statement.MaximumProtocol,
            signed.Statement.PolicyVersion, MembershipSignatureDomain.Membership,
            bytes, signed.Signatures, context, verifier, allowSameSuccessorForEvidence: true);
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
        IMembershipSignatureVerifier verifier,
        bool allowSameSuccessorForEvidence = false)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(verifier);
        ValidateSkew(context.AllowedClockSkewSeconds);
        if (!networkId.Span.SequenceEqual(context.Genesis.NetworkId.Span) ||
            !networkId.Span.SequenceEqual(context.LastKnownGood.NetworkId.Span))
            throw Error(MembershipContractError.NetworkMismatch, "Statement is for another network.");
        if (policyVersion != context.Genesis.PolicyVersion ||
            policyVersion != context.LastKnownGood.PolicyVersion)
            throw Error(MembershipContractError.PolicyMismatch, "Statement policy version is not trusted.");
        if (sequence != context.LastKnownGood.Sequence + 1)
            throw Error(MembershipContractError.InvalidSequence, "Statement must be the next monotonic sequence.");
        if (!previousHash.Span.SequenceEqual(context.LastKnownGood.CanonicalHash.Span))
            throw Error(MembershipContractError.PreviousHashMismatch, "Statement previous hash does not match LKG.");
        VerifyTimeAndProtocol(validFrom, validUntil, minimumProtocol, maximumProtocol,
            context.VerificationTimeUnixSeconds, context.AllowedClockSkewSeconds, context.ClientProtocol);
        VerifyDelegation(context.ActiveDelegation, context.Genesis, context.VerificationTimeUnixSeconds,
            context.AllowedClockSkewSeconds, context.ClientProtocol, verifier);
        var delegationHash = Digest(verifier,
            MembershipContractCodec.GetDelegationSigningBytes(context.ActiveDelegation));
        if (context.RevokedDelegationHashes.Any(value => value.Span.SequenceEqual(delegationHash)))
            throw Error(MembershipContractError.RevokedDelegation, "Online signer delegation is revoked.");
        VerifySignatures(statement, signatures, domain, context.ActiveDelegation.OnlineSignerIds,
            context.Genesis.Policy.OnlineThreshold, verifier);
    }

    private static void VerifySignatures(
        byte[] statement,
        IReadOnlyList<MembershipSignature> signatures,
        MembershipSignatureDomain expectedDomain,
        IReadOnlyList<ReadOnlyMemory<byte>> authorizedSignerIds,
        int threshold,
        IMembershipSignatureVerifier verifier)
    {
        if (signatures.Count == 0)
            throw Error(MembershipContractError.InsufficientQuorum, "No signatures were supplied.");
        var authorized = authorizedSignerIds
            .Select(static value => Convert.ToHexString(value.Span))
            .ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var accepted = 0;
        foreach (var signature in signatures)
        {
            if (signature.Domain != expectedDomain)
                throw Error(MembershipContractError.WrongSignatureDomain, "Signature domain is not interchangeable.");
            if (signature.SignerId.Length != MembershipLimits.SignerIdLength ||
                signature.Signature.Length is < MembershipLimits.MinimumSignatureLength or > MembershipLimits.MaximumSignatureLength)
                throw Error(MembershipContractError.InvalidSignature, "Signature framing is invalid.");
            var signer = Convert.ToHexString(signature.SignerId.Span);
            if (!authorized.Contains(signer))
                throw Error(MembershipContractError.UnknownSigner, "Signer is not authorized for this role.");
            if (!seen.Add(signer))
                throw Error(MembershipContractError.DuplicateSigner, "Duplicate signatures do not count toward quorum.");
            if (!verifier.Verify(signature.SignerId.Span, expectedDomain, statement, signature.Signature.Span))
                throw Error(MembershipContractError.InvalidSignature, "Signature verification failed.");
            accepted++;
        }
        if (accepted < threshold)
            throw Error(MembershipContractError.InsufficientQuorum, "Signature threshold was not met.");
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

    private static byte[] Digest(IMembershipSignatureVerifier verifier, ReadOnlySpan<byte> bytes)
    {
        var digest = verifier.Digest(bytes);
        if (digest is null || digest.Length != MembershipLimits.HashLength)
            throw Error(MembershipContractError.InvalidField, "Verifier returned an invalid digest.");
        return digest;
    }

    private static MembershipLastKnownGood NextLkg(
        MembershipVerificationContext context, ulong sequence, ReadOnlyMemory<byte> hash) =>
        new()
        {
            NetworkId = context.LastKnownGood.NetworkId.ToArray(),
            PolicyVersion = context.LastKnownGood.PolicyVersion,
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
