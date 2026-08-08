using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public sealed record ProductionMailboxRouteHistoryAuthoringLink
{
    public required ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; init; }
    public required ReadOnlyMemory<byte> CanonicalAuthority { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRevocations { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRouteCertificate { get; init; }
    public required ReadOnlyMemory<byte> CanonicalRevocationCheckpoint { get; init; }
    public required ReadOnlyMemory<byte> CanonicalTransitionContext { get; init; }
    public required ReadOnlyMemory<byte> CanonicalAuthorization { get; init; }
}

public sealed class VerifiedProductionMailboxRouteHistoryCursor
{
    private readonly VerifiedProductionMailboxRouteHistoryCheckpoint _checkpoint;

    internal VerifiedProductionMailboxRouteHistoryCursor(
        VerifiedProductionMailboxRouteHistoryCheckpoint checkpoint,
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment)
    {
        _checkpoint = checkpoint ?? throw new ArgumentNullException(nameof(checkpoint));
        Enrollment = enrollment ?? throw new ArgumentNullException(nameof(enrollment));
    }

    internal VerifiedProductionMailboxRouteHistoryCheckpoint Checkpoint => _checkpoint;
    internal VerifiedProductionMailboxRouteContinuityEnrollment Enrollment { get; }
    public ReadOnlyMemory<byte> CanonicalCheckpoint => _checkpoint.CanonicalBytes.ToArray();
    public ReadOnlyMemory<byte> CanonicalCheckpointHash => _checkpoint.CanonicalHash.ToArray();
    public ulong LastCommittedBatchSequence => _checkpoint.TrustedCheckpoint.LastCommittedBatchSequence;
    public ulong CumulativeVerifiedRouteLinkCount =>
        _checkpoint.TrustedCheckpoint.CumulativeVerifiedRouteLinkCount;
}

public sealed class ProductionMailboxRouteHistoryBatchCommitPlan
{
    private readonly byte[] _canonicalBatch;
    private readonly byte[] _canonicalBatchHash;

    internal ProductionMailboxRouteHistoryBatchCommitPlan(
        ReadOnlySpan<byte> canonicalBatch,
        VerifiedProductionMailboxRouteHistoryCursor nextCursor)
    {
        _canonicalBatch = canonicalBatch.ToArray();
        _canonicalBatchHash = SHA256.HashData(_canonicalBatch);
        NextCursor = nextCursor ?? throw new ArgumentNullException(nameof(nextCursor));
    }

    public ReadOnlyMemory<byte> CanonicalBatch => _canonicalBatch.ToArray();
    public ReadOnlyMemory<byte> CanonicalBatchHash => _canonicalBatchHash.ToArray();
    public VerifiedProductionMailboxRouteHistoryCursor NextCursor { get; }
}

/// <summary>
/// Exact fields retained by the authenticated durable CAS alongside RHC1. Network-fetched values
/// must never be used to populate this context.
/// </summary>
public sealed record ProductionMailboxRouteHistoryProtectedRestoreContext
{
    public required ReadOnlyMemory<byte> ExpectedCanonicalCheckpointHash { get; init; }
    public required ulong ExpectedLastCommittedBatchSequence { get; init; }
    public required ReadOnlyMemory<byte> ExpectedLastCommittedBatchHash { get; init; }
    public required ReadOnlyMemory<byte> ExpectedCurrentRouteOriginLkgHash { get; init; }
}

/// <summary>
/// Bounded canonical RHB1 authoring backed by the same cryptographic link verifier used for
/// recovery. A batch becomes a commit plan only after every exact artifact and route link advances
/// the sealed RHC1 cursor.
/// </summary>
public static class ProductionMailboxRouteHistoryAuthoring
{
    public static VerifiedProductionMailboxRouteHistoryCursor CreateInitialCursor(
        VerifiedProductionMailboxRouteContinuityEnrollmentState enrollmentState,
        VerifiedProductionMailboxAuthority anchorAuthority,
        VerifiedProductionMailboxRevocationSnapshot anchorRevocations)
    {
        ArgumentNullException.ThrowIfNull(enrollmentState);
        ArgumentNullException.ThrowIfNull(anchorAuthority);
        ArgumentNullException.ThrowIfNull(anchorRevocations);
        var enrollment = enrollmentState.Enrollment;
        var rol = ProductionMailboxRouteContinuityCodec.DecodeRouteOriginLkg(
            enrollmentState.CanonicalEnrolledRouteOriginLkg.Span);
        var authority = anchorAuthority.Authority;
        var delegation = enrollment.Delegation;
        if (!CryptographicOperations.FixedTimeEquals(rol.NetworkId.Span, authority.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(rol.NetworkId.Span, delegation.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(rol.RouteDomainHash.Span,
                delegation.RouteDomainHash.Span) ||
            authority.AuthorityGeneration != delegation.AnchorAuthorityGeneration ||
            !CryptographicOperations.FixedTimeEquals(anchorAuthority.CanonicalAuthorityHash.Span,
                delegation.AnchorCanonicalAuthorityHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span),
                delegation.PinnedMrXPublicKeySha256.Span))
            throw new FormatException("Initial route-history control plane differs from enrollment.");
        if (!CryptographicOperations.FixedTimeEquals(rol.CanonicalDelegationHash.Span,
                enrollment.CanonicalDelegationHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(rol.CanonicalDelegationAcceptanceHash.Span,
                enrollment.CanonicalAcceptanceHash.Span) ||
            rol.AuthorizationKind != delegation.AnchorAuthorizationKind ||
            !CryptographicOperations.FixedTimeEquals(rol.CanonicalAuthorizationHash.Span,
                delegation.AnchorCanonicalRouteAuthorizationHash.Span) ||
            rol.AuthorizationSequence != delegation.AnchorRouteAuthorizationSequence ||
            rol.OwnerRevocationGeneration != 0 ||
            rol.OwnerRevocationHeadHash.Span.IndexOfAnyExcept((byte)0) >= 0 ||
            !CryptographicOperations.FixedTimeEquals(
                ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(rol),
                enrollmentState.EnrolledRouteOriginLkgHash.Span))
            throw new FormatException("Initial route-history ROL1 differs from enrolled continuity state.");
        var revocations = anchorRevocations.Snapshot;
        var checkpoint = new ProductionMailboxRouteHistoryCheckpoint
        {
            NetworkId = rol.NetworkId.ToArray(),
            RouteDomainHash = rol.RouteDomainHash.ToArray(),
            DelegationHistoryBinding = ProductionMailboxRouteContinuityCodec.ComputeDelegationHistoryBinding(
                enrollment.CanonicalDelegationHash.Span, enrollment.CanonicalAcceptanceHash.Span),
            CurrentAuthorizationKind = rol.AuthorizationKind,
            CurrentCanonicalAuthorizationHash = rol.CanonicalAuthorizationHash.ToArray(),
            CurrentAuthorizationSequence = rol.AuthorizationSequence,
            OwnerRevocationGeneration = rol.OwnerRevocationGeneration,
            OwnerRevocationHeadHash = rol.OwnerRevocationHeadHash.ToArray(),
            CurrentRouteOriginLkgHash = enrollmentState.EnrolledRouteOriginLkgHash.ToArray(),
            RouteVerifiedAtUnixSeconds = rol.RouteVerifiedAtUnixSeconds,
            CurrentLocalCommitGeneration = rol.LocalCommitGeneration,
            PinnedMrXPublicKeySha256 = SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span),
            CurrentAuthorityGeneration = authority.AuthorityGeneration,
            CurrentCanonicalAuthorityHash = anchorAuthority.CanonicalAuthorityHash.ToArray(),
            CurrentRevocationGeneration = revocations.RevocationGeneration,
            CurrentRevocationHeadHash = revocations.RevocationHeadHash.ToArray(),
            CurrentRevocationSnapshotHash = anchorRevocations.CanonicalSnapshotHash.ToArray(),
            LastCommittedBatchSequence = 0,
            CumulativeCommittedBatchCount = 0,
            CumulativeVerifiedRouteLinkCount = 0,
            CumulativeCanonicalPayloadBytes = 0,
            HistoryTranscriptHead = new byte[32],
            LastCommittedBatchHash = new byte[32]
        };
        VerifyCheckpointClosure(checkpoint, enrollment, anchorAuthority, anchorRevocations);
        return new(ProductionMailboxRouteHistoryVerifier.CreateInitial(checkpoint), enrollment);
    }

    public static ProductionMailboxRouteHistoryBatchCommitPlan AuthorNextBatch(
        VerifiedProductionMailboxRouteHistoryCursor current,
        IReadOnlyList<ProductionMailboxRouteHistoryAuthoringLink> links)
    {
        ArgumentNullException.ThrowIfNull(current);
        var frozenLinks = Freeze(links);
        var batch = BuildBatch(current, frozenLinks);
        var canonical = ProductionMailboxRouteHistoryCodec.Encode(batch);
        var next = VerifyCore(current, canonical);
        return new(canonical, next);
    }

    public static VerifiedProductionMailboxRouteHistoryCursor VerifyBatch(
        VerifiedProductionMailboxRouteHistoryCursor current,
        ReadOnlySpan<byte> canonicalBatch)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (canonicalBatch.Length < ProductionMailboxRouteHistoryConstants.HeaderLength ||
            canonicalBatch.Length > ProductionMailboxRouteHistoryConstants.MaximumEncodedBytes)
            throw new FormatException("RHB1 length is outside its strict bound.");
        return VerifyCore(current, canonicalBatch);
    }

    public static VerifiedProductionMailboxRouteHistoryCursor RestoreCursor(
        ReadOnlySpan<byte> canonicalCheckpoint,
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment,
        VerifiedProductionMailboxAuthority currentAuthority,
        VerifiedProductionMailboxRevocationSnapshot currentRevocations,
        ProductionMailboxRouteHistoryProtectedRestoreContext protectedState)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        ArgumentNullException.ThrowIfNull(currentAuthority);
        ArgumentNullException.ThrowIfNull(currentRevocations);
        ArgumentNullException.ThrowIfNull(protectedState);
        if (canonicalCheckpoint.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength ||
            protectedState.ExpectedCanonicalCheckpointHash.Length != 32 ||
            protectedState.ExpectedCanonicalCheckpointHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            protectedState.ExpectedLastCommittedBatchHash.Length != 32 ||
            protectedState.ExpectedCurrentRouteOriginLkgHash.Length != 32 ||
            protectedState.ExpectedCurrentRouteOriginLkgHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("Protected RHC1 restore fields have invalid fixed bounds.");
        var frozen = canonicalCheckpoint.ToArray();
        var checkpoint = ProductionMailboxRouteContinuityCodec.DecodeRouteHistoryCheckpoint(frozen);
        var canonicalHash = ProductionMailboxRouteContinuityCodec.ComputeRouteHistoryCheckpointHash(
            checkpoint);
        if (!CryptographicOperations.FixedTimeEquals(canonicalHash,
                protectedState.ExpectedCanonicalCheckpointHash.Span) ||
            checkpoint.LastCommittedBatchSequence !=
                protectedState.ExpectedLastCommittedBatchSequence ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.LastCommittedBatchHash.Span,
                protectedState.ExpectedLastCommittedBatchHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRouteOriginLkgHash.Span,
                protectedState.ExpectedCurrentRouteOriginLkgHash.Span))
            throw new FormatException("RHC1 differs from the protected durable CAS state.");
        VerifyCheckpointClosure(checkpoint, enrollment, currentAuthority, currentRevocations);
        return new(new VerifiedProductionMailboxRouteHistoryCheckpoint(checkpoint, frozen), enrollment);
    }

    private static VerifiedProductionMailboxRouteHistoryCursor VerifyCore(
        VerifiedProductionMailboxRouteHistoryCursor current,
        ReadOnlySpan<byte> canonicalBatch)
    {
        var old = current.Checkpoint.TrustedCheckpoint;
        var verifier = new ProductionMailboxRouteHistoryCryptographicLinkVerifier(
            old.NetworkId, old.RouteDomainHash, old.PinnedMrXPublicKeySha256, current.Enrollment);
        var next = ProductionMailboxRouteHistoryVerifier.Advance(
            canonicalBatch, current.Checkpoint, verifier);
        return ReferenceEquals(next, current.Checkpoint) ? current : new(next, current.Enrollment);
    }

    private static void VerifyCheckpointClosure(
        ProductionMailboxRouteHistoryCheckpoint checkpoint,
        VerifiedProductionMailboxRouteContinuityEnrollment enrollment,
        VerifiedProductionMailboxAuthority currentAuthority,
        VerifiedProductionMailboxRevocationSnapshot currentRevocations)
    {
        var delegation = enrollment.Delegation;
        var authority = currentAuthority.Authority;
        var revocations = currentRevocations.Snapshot;
        var expectedBinding = ProductionMailboxRouteContinuityCodec.ComputeDelegationHistoryBinding(
            enrollment.CanonicalDelegationHash.Span, enrollment.CanonicalAcceptanceHash.Span);
        if (!CryptographicOperations.FixedTimeEquals(checkpoint.NetworkId.Span,
                delegation.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.RouteDomainHash.Span,
                delegation.RouteDomainHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.DelegationHistoryBinding.Span,
                expectedBinding) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.PinnedMrXPublicKeySha256.Span,
                delegation.PinnedMrXPublicKeySha256.Span) ||
            authority.AuthorityGeneration > delegation.MaximumAuthorityGeneration ||
            checkpoint.CurrentAuthorityGeneration != authority.AuthorityGeneration ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentCanonicalAuthorityHash.Span,
                currentAuthority.CanonicalAuthorityHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(authority.NetworkId.Span,
                checkpoint.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span),
                checkpoint.PinnedMrXPublicKeySha256.Span) ||
            revocations.AuthorityGeneration != authority.AuthorityGeneration ||
            !CryptographicOperations.FixedTimeEquals(revocations.NetworkId.Span,
                checkpoint.NetworkId.Span) ||
            checkpoint.CurrentRevocationGeneration != revocations.RevocationGeneration ||
            revocations.RevocationGeneration != authority.Revocation.Generation ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRevocationHeadHash.Span,
                revocations.RevocationHeadHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(revocations.RevocationHeadHash.Span,
                authority.Revocation.HeadHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(checkpoint.CurrentRevocationSnapshotHash.Span,
                currentRevocations.CanonicalSnapshotHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(currentRevocations.CanonicalSnapshotHash.Span,
                authority.Revocation.SnapshotHash.Span))
            throw new FormatException("RHC1 closure differs from enrollment or current control plane.");
    }

    private static ProductionMailboxRouteHistoryBatch BuildBatch(
        VerifiedProductionMailboxRouteHistoryCursor current,
        IReadOnlyList<ProductionMailboxRouteHistoryAuthoringLink> links)
    {
        var artifacts = new List<(ProductionMailboxRouteHistoryArtifactKind Kind, byte[] Bytes, byte[] Hash)>();
        var linkKeys = new List<(ProductionMailboxRouteHistoryAuthoringLink Link,
            (ProductionMailboxRouteHistoryArtifactKind Kind, byte[] Hash)[] Keys)>();
        foreach (var link in links)
        {
            var values = new List<(ProductionMailboxRouteHistoryArtifactKind, ReadOnlyMemory<byte>)>
            {
                (ProductionMailboxRouteHistoryArtifactKind.Authority, link.CanonicalAuthority),
                (ProductionMailboxRouteHistoryArtifactKind.Revocations, link.CanonicalRevocations),
                (ProductionMailboxRouteHistoryArtifactKind.RouteCertificate,
                    link.CanonicalRouteCertificate),
                (link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                    ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                    : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation,
                    link.CanonicalAuthorization)
            };
            if (link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            {
                values.Add((ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint,
                    link.CanonicalRevocationCheckpoint));
                values.Add((ProductionMailboxRouteHistoryArtifactKind.TransitionContext,
                    link.CanonicalTransitionContext));
            }
            var keys = new (ProductionMailboxRouteHistoryArtifactKind, byte[])[values.Count];
            for (var i = 0; i < values.Count; i++)
            {
                var hash = SHA256.HashData(values[i].Item2.Span);
                if (artifacts.Any(item => item.Kind != values[i].Item1 &&
                        CryptographicOperations.FixedTimeEquals(item.Hash, hash)))
                    throw new FormatException("RHB1 cross-type artifact hash aliases are forbidden.");
                keys[i] = (values[i].Item1, hash);
                if (!artifacts.Any(item => item.Kind == values[i].Item1 &&
                        CryptographicOperations.FixedTimeEquals(item.Hash, hash)))
                    artifacts.Add((values[i].Item1, values[i].Item2.ToArray(), hash));
            }
            linkKeys.Add((link, keys));
        }
        var sorted = artifacts.OrderBy(static item => (byte)item.Kind)
            .ThenBy(static item => item.Hash, ByteArrayComparer.Instance).ToArray();
        if (sorted.Length > ProductionMailboxRouteHistoryConstants.MaximumArtifacts)
            throw new FormatException("RHB1 authoring artifact count exceeds its bound.");
        ushort Index(ProductionMailboxRouteHistoryArtifactKind kind, byte[] hash) => checked((ushort)
            Array.FindIndex(sorted, item => item.Kind == kind &&
                CryptographicOperations.FixedTimeEquals(item.Hash, hash)));
        var predecessor = current.Checkpoint.TrustedCheckpoint.CurrentAuthorizationSequence;
        var builtLinks = new ProductionMailboxRouteHistoryLink[linkKeys.Count];
        for (var i = 0; i < linkKeys.Count; i++)
        {
            var item = linkKeys[i];
            var authorization = item.Link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                ? ProductionMailboxRouteAuthorizationCodec.DecodeAdvertisementV2(
                    item.Link.CanonicalAuthorization.Span).Sequence
                : ProductionMailboxRouteAuthorizationCodec.DecodeContinuityActivation(
                    item.Link.CanonicalAuthorization.Span).ActivationSequence;
            var expected = checked(predecessor + 1);
            if (authorization != expected)
                throw new FormatException("RHB1 authoring route sequence is not exact +1.");
            byte[] FindHash(ProductionMailboxRouteHistoryArtifactKind kind) =>
                item.Keys.Single(key => key.Kind == kind).Hash;
            builtLinks[i] = new()
            {
                AuthorizationKind = item.Link.AuthorizationKind,
                AuthorityIndex = Index(ProductionMailboxRouteHistoryArtifactKind.Authority,
                    FindHash(ProductionMailboxRouteHistoryArtifactKind.Authority)),
                RevocationsIndex = Index(ProductionMailboxRouteHistoryArtifactKind.Revocations,
                    FindHash(ProductionMailboxRouteHistoryArtifactKind.Revocations)),
                RouteCertificateIndex = Index(ProductionMailboxRouteHistoryArtifactKind.RouteCertificate,
                    FindHash(ProductionMailboxRouteHistoryArtifactKind.RouteCertificate)),
                RevocationCheckpointIndex = item.Link.AuthorizationKind ==
                    ProductionMailboxRouteAuthorizationKind.OwnerPRA2 ? ushort.MaxValue :
                    Index(ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint,
                        FindHash(ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint)),
                TransitionContextIndex = item.Link.AuthorizationKind ==
                    ProductionMailboxRouteAuthorizationKind.OwnerPRA2 ? ushort.MaxValue :
                    Index(ProductionMailboxRouteHistoryArtifactKind.TransitionContext,
                        FindHash(ProductionMailboxRouteHistoryArtifactKind.TransitionContext)),
                AuthorizationIndex = Index(
                    item.Link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                        ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                        : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation,
                    FindHash(item.Link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                        ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                        : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation)),
                PredecessorSequence = predecessor,
                NewSequence = authorization
            };
            predecessor = authorization;
        }
        return new()
        {
            BatchSequence = checked(current.LastCommittedBatchSequence + 1),
            PreviousCheckpointHash = current.CanonicalCheckpointHash.ToArray(),
            Artifacts = sorted.Select(static item => new ProductionMailboxRouteHistoryArtifact
            {
                Kind = item.Kind,
                CanonicalBytes = item.Bytes
            }).ToArray(),
            Links = builtLinks
        };
    }

    private static ProductionMailboxRouteHistoryAuthoringLink[] Freeze(
        IReadOnlyList<ProductionMailboxRouteHistoryAuthoringLink> links)
    {
        ArgumentNullException.ThrowIfNull(links);
        var count = links.Count;
        if (count is < 1 or > ProductionMailboxRouteHistoryConstants.MaximumLinks)
            throw new FormatException("RHB1 authoring link count is outside its bound.");
        var payloadBytes = 0;
        var uniquePayloads = new List<(ProductionMailboxRouteHistoryArtifactKind Kind, byte[] Hash)>();
        var expectedHashes = new byte[count][][];
        var sourceItems = new ProductionMailboxRouteHistoryAuthoringLink[count];
        for (var i = 0; i < count; i++)
        {
            var item = links[i] ?? throw new FormatException("RHB1 authoring link is null.");
            sourceItems[i] = item;
            Preflight(item);
            expectedHashes[i] = new byte[6][];
            expectedHashes[i][0] = AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind.Authority,
                item.CanonicalAuthority.Span);
            expectedHashes[i][1] = AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind.Revocations,
                item.CanonicalRevocations.Span);
            expectedHashes[i][2] = AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind.RouteCertificate,
                item.CanonicalRouteCertificate.Span);
            if (item.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            {
                expectedHashes[i][3] = AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint,
                    item.CanonicalRevocationCheckpoint.Span);
                expectedHashes[i][4] = AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind.TransitionContext,
                    item.CanonicalTransitionContext.Span);
            }
            else
            {
                expectedHashes[i][3] = [];
                expectedHashes[i][4] = [];
            }
            expectedHashes[i][5] = AddUniquePayload(item.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                    ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                    : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation,
                item.CanonicalAuthorization.Span);
        }
        if (links.Count != count)
            throw new FormatException("RHB1 authoring link collection mutated during preflight.");
        var ownedPayloads = new List<(ProductionMailboxRouteHistoryArtifactKind Kind, byte[] Hash, byte[] Bytes)>();
        var result = new ProductionMailboxRouteHistoryAuthoringLink[count];
        for (var i = 0; i < count; i++)
        {
            var item = sourceItems[i];
            result[i] = item with
            {
                CanonicalAuthority = FreezePayload(ProductionMailboxRouteHistoryArtifactKind.Authority,
                    item.CanonicalAuthority, expectedHashes[i][0]),
                CanonicalRevocations = FreezePayload(ProductionMailboxRouteHistoryArtifactKind.Revocations,
                    item.CanonicalRevocations, expectedHashes[i][1]),
                CanonicalRouteCertificate = FreezePayload(ProductionMailboxRouteHistoryArtifactKind.RouteCertificate,
                    item.CanonicalRouteCertificate, expectedHashes[i][2]),
                CanonicalRevocationCheckpoint = item.AuthorizationKind ==
                    ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
                    ? FreezePayload(ProductionMailboxRouteHistoryArtifactKind.RevocationCheckpoint,
                        item.CanonicalRevocationCheckpoint, expectedHashes[i][3]) : ReadOnlyMemory<byte>.Empty,
                CanonicalTransitionContext = item.AuthorizationKind ==
                    ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
                    ? FreezePayload(ProductionMailboxRouteHistoryArtifactKind.TransitionContext,
                        item.CanonicalTransitionContext, expectedHashes[i][4]) : ReadOnlyMemory<byte>.Empty,
                CanonicalAuthorization = FreezePayload(item.AuthorizationKind ==
                        ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                        ? ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement
                        : ProductionMailboxRouteHistoryArtifactKind.ContinuityActivation,
                    item.CanonicalAuthorization, expectedHashes[i][5])
            };
        }
        if (links.Count != count)
            throw new FormatException("RHB1 authoring link collection mutated.");
        return result;

        byte[] AddUniquePayload(ProductionMailboxRouteHistoryArtifactKind kind, ReadOnlySpan<byte> payload)
        {
            var hash = SHA256.HashData(payload);
            foreach (var existing in uniquePayloads)
            {
                if (!CryptographicOperations.FixedTimeEquals(existing.Hash, hash))
                    continue;
                if (existing.Kind != kind)
                    throw new FormatException("RHB1 cross-type artifact hash aliases are forbidden.");
                return hash;
            }
            payloadBytes = checked(payloadBytes + payload.Length);
            if (payloadBytes > ProductionMailboxRouteHistoryConstants.MaximumPayloadBytes)
                throw new FormatException("RHB1 authoring payload exceeds its aggregate bound.");
            uniquePayloads.Add((kind, hash));
            return hash;
        }

        ReadOnlyMemory<byte> FreezePayload(ProductionMailboxRouteHistoryArtifactKind kind,
            ReadOnlyMemory<byte> payload, byte[] expectedHash)
        {
            var owned = payload.ToArray();
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(owned), expectedHash))
                throw new FormatException("RHB1 authoring input mutated while it was frozen.");
            foreach (var existing in ownedPayloads)
            {
                if (!CryptographicOperations.FixedTimeEquals(existing.Hash, expectedHash))
                    continue;
                if (existing.Kind != kind)
                    throw new FormatException("RHB1 cross-type artifact hash aliases are forbidden.");
                CryptographicOperations.ZeroMemory(owned);
                return existing.Bytes;
            }
            ownedPayloads.Add((kind, expectedHash, owned));
            return owned;
        }
    }

    private static void Preflight(ProductionMailboxRouteHistoryAuthoringLink value)
    {
        static void Bounded(ReadOnlyMemory<byte> bytes, int maximum, string name)
        {
            if (bytes.Length is <= 0 || bytes.Length > maximum)
                throw new FormatException($"RHB1 {name} length is outside its bound.");
        }
        Bounded(value.CanonicalAuthority, ProductionMailboxAuthorityConstants.MaximumArtifactBytes, "PMA1");
        Bounded(value.CanonicalRevocations, ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes, "PMR1");
        if (value.CanonicalRouteCertificate.Length != ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength)
            throw new FormatException("RHB1 PRC1 length is invalid.");
        if (value.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
        {
            if (!value.CanonicalRevocationCheckpoint.IsEmpty || !value.CanonicalTransitionContext.IsEmpty ||
                value.CanonicalAuthorization.Length != ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length)
                throw new FormatException("RHB1 owner link shape is invalid.");
        }
        else if (value.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
        {
            if (value.CanonicalRevocationCheckpoint.Length != ProductionMailboxRouteContinuityConstants.CanonicalRevocationCheckpointLength ||
                value.CanonicalTransitionContext.Length != ProductionMailboxRouteAuthorizationConstants.CanonicalTransitionContextLength ||
                value.CanonicalAuthorization.Length != ProductionMailboxRouteAuthorizationConstants.CanonicalContinuityActivationLength)
                throw new FormatException("RHB1 delegated link shape is invalid.");
        }
        else
            throw new FormatException("RHB1 authorization kind is invalid.");
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? x, byte[]? y) => x is null ? (y is null ? 0 : -1) :
            y is null ? 1 : x.AsSpan().SequenceCompareTo(y);
    }
}
