using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

internal sealed class VerifiedProductionMailboxRouteHistoryCheckpoint
{
    private readonly ProductionMailboxRouteHistoryCheckpoint _checkpoint;
    private readonly byte[] _canonicalBytes;
    private readonly byte[] _canonicalHash;

    internal VerifiedProductionMailboxRouteHistoryCheckpoint(
        ProductionMailboxRouteHistoryCheckpoint checkpoint, ReadOnlySpan<byte> canonicalBytes)
    {
        _checkpoint = ProductionMailboxRouteContinuityCopy.Clone(checkpoint);
        _canonicalBytes = canonicalBytes.ToArray();
        _canonicalHash = ProductionMailboxRouteContinuityCodec.ComputeRouteHistoryCheckpointHash(_checkpoint);
    }

    internal ProductionMailboxRouteHistoryCheckpoint TrustedCheckpoint => _checkpoint;
    internal ReadOnlyMemory<byte> CanonicalBytes => _canonicalBytes.ToArray();
    internal ReadOnlyMemory<byte> CanonicalHash => _canonicalHash.ToArray();
}

internal sealed record ProductionMailboxRouteHistoryLinkVerificationState
{
    internal required ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; init; }
    internal required ReadOnlyMemory<byte> CanonicalAuthorizationHash { get; init; }
    internal required ulong AuthorizationSequence { get; init; }
    internal required ReadOnlyMemory<byte> RouteOriginLkgHash { get; init; }
    internal required ulong RouteVerifiedAtUnixSeconds { get; init; }
    internal required ulong LocalCommitGeneration { get; init; }
    internal required ulong OwnerRevocationGeneration { get; init; }
    internal required ReadOnlyMemory<byte> OwnerRevocationHeadHash { get; init; }
    internal required ulong AuthorityGeneration { get; init; }
    internal required ReadOnlyMemory<byte> CanonicalAuthorityHash { get; init; }
    internal required ulong RevocationGeneration { get; init; }
    internal required ReadOnlyMemory<byte> RevocationHeadHash { get; init; }
    internal required ReadOnlyMemory<byte> RevocationSnapshotHash { get; init; }
}

internal interface IProductionMailboxRouteHistoryLinkVerifier
{
    ProductionMailboxRouteHistoryLinkVerificationState Verify(
        ProductionMailboxRouteHistoryLink link,
        IReadOnlyList<ProductionMailboxRouteHistoryArtifact> artifacts,
        ProductionMailboxRouteHistoryLinkVerificationState predecessor);
}

internal sealed class ProductionMailboxRouteHistoryAdvanceResult
{
    internal ProductionMailboxRouteHistoryAdvanceResult(
        VerifiedProductionMailboxRouteHistoryCheckpoint checkpoint,
        ProductionMailboxRouteHistoryBatch? batch,
        byte[] canonicalBatch,
        bool advanced)
    {
        Checkpoint = checkpoint;
        Batch = batch;
        CanonicalBatch = canonicalBatch;
        Advanced = advanced;
    }

    internal VerifiedProductionMailboxRouteHistoryCheckpoint Checkpoint { get; }
    internal ProductionMailboxRouteHistoryBatch? Batch { get; }
    internal byte[] CanonicalBatch { get; }
    internal bool Advanced { get; }
}

/// <summary>Production internal verifier for one exact historical route link.</summary>
internal sealed class ProductionMailboxRouteHistoryCryptographicLinkVerifier(
    ReadOnlyMemory<byte> expectedNetworkId,
    ReadOnlyMemory<byte> expectedRouteDomainHash,
    ReadOnlyMemory<byte> pinnedMrXPublicKeySha256,
    VerifiedProductionMailboxRouteContinuityEnrollment enrollment)
    : IProductionMailboxRouteHistoryLinkVerifier
{
    private readonly byte[] _network = Fixed(expectedNetworkId, 16, "network");
    private readonly byte[] _route = Fixed(expectedRouteDomainHash, 32, "route domain");
    private readonly byte[] _mrX = Fixed(pinnedMrXPublicKeySha256, 32, "Mr. X pin");
    private readonly VerifiedProductionMailboxRouteContinuityEnrollment _enrollment =
        enrollment ?? throw new ArgumentNullException(nameof(enrollment));
    private readonly IProductionMailboxAuthoritySignatureVerifier _authorityVerifier =
        new SodiumProductionMailboxAuthoritySignatureVerifier();
    private readonly IProductionMailboxRevocationSnapshotSignatureVerifier _revocationVerifier =
        new SodiumProductionMailboxRevocationSnapshotSignatureVerifier();
    private readonly IProductionMailboxRouteSignatureVerifier _routeVerifier =
        new SodiumProductionMailboxRouteSignatureVerifier();

    public ProductionMailboxRouteHistoryLinkVerificationState Verify(
        ProductionMailboxRouteHistoryLink link,
        IReadOnlyList<ProductionMailboxRouteHistoryArtifact> artifacts,
        ProductionMailboxRouteHistoryLinkVerificationState predecessor)
    {
        var authorizationBytes = artifacts[link.AuthorizationIndex].CanonicalBytes.ToArray();
        var linkTime = link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2
            ? ProductionMailboxRouteAuthorizationCodec.DecodeAdvertisementV2(authorizationBytes)
                .PublishedAtUnixSeconds
            : ProductionMailboxRouteAuthorizationCodec.DecodeContinuityActivation(authorizationBytes)
                .IssuedAtUnixSeconds;
        var authorityBytes = artifacts[link.AuthorityIndex].CanonicalBytes.ToArray();
        var authorityArtifact = ProductionMailboxAuthorityCodec.Decode(authorityBytes);
        VerifiedProductionMailboxAuthority authority;
        if (authorityArtifact.AuthorityGeneration == predecessor.AuthorityGeneration)
        {
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(authorityBytes),
                    predecessor.CanonicalAuthorityHash.Span))
                throw new FormatException("RHB1 same-generation PMA1 conflicts with the retained authority.");
            authority = ProductionMailboxAuthorityVerifier.Verify(authorityArtifact,
                new ProductionMailboxAuthorityVerificationContext
                {
                    PinnedMrXPublicKeySha256 = _mrX,
                    ExpectedNetworkId = _network,
                    LastCommittedGeneration = authorityArtifact.AuthorityGeneration - 1,
                    LastCommittedAuthorityHash = authorityArtifact.PreviousAuthorityHash.ToArray(),
                    LastCommittedRevocationGeneration = authorityArtifact.Revocation.Generation,
                    LastCommittedRevocationHeadHash = authorityArtifact.Revocation.HeadHash.ToArray(),
                    LastCommittedRevocationSnapshotHash = authorityArtifact.Revocation.SnapshotHash.ToArray(),
                    NowUnixSeconds = linkTime,
                    ClockSkewSeconds = ProductionMailboxRouteContinuityConstants.MaximumClockSkewSeconds
                }, _authorityVerifier);
        }
        else
        {
            authority = ProductionMailboxRoutesVerificationFacade.VerifyForwardCheckpoint(authorityBytes,
                new ProductionMailboxAuthorityCheckpointVerificationContext
                {
                    PinnedMrXPublicKeySha256 = _mrX,
                    ExpectedNetworkId = _network,
                    LastCommittedGeneration = predecessor.AuthorityGeneration,
                    LastCommittedRevocationGeneration = predecessor.RevocationGeneration,
                    LastCommittedRevocationHeadHash = predecessor.RevocationHeadHash.ToArray(),
                    LastCommittedRevocationSnapshotHash = predecessor.RevocationSnapshotHash.ToArray(),
                    NowUnixSeconds = linkTime,
                    ClockSkewSeconds = ProductionMailboxRouteContinuityConstants.MaximumClockSkewSeconds
                }, _authorityVerifier);
        }
        if (authority.Authority.AuthorityGeneration > _enrollment.Delegation.MaximumAuthorityGeneration)
            throw new FormatException("RHB1 authority exceeds the owner delegation ceiling.");
        var revocationBytes = artifacts[link.RevocationsIndex].CanonicalBytes.ToArray();
        var revocations = ProductionMailboxRevocationSnapshotVerifier.Verify(revocationBytes, authority,
            linkTime, ProductionMailboxRouteContinuityConstants.MaximumClockSkewSeconds,
            _revocationVerifier);
        var certificateBytes = artifacts[link.RouteCertificateIndex].CanonicalBytes.ToArray();
        var certificate = ProductionMailboxRouteCertificateVerifier.Verify(certificateBytes, authority,
            linkTime, ProductionMailboxRouteContinuityConstants.MaximumClockSkewSeconds, _routeVerifier);
        var routeDomain = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(certificate.Certificate);
        if (!CryptographicOperations.FixedTimeEquals(routeDomain, _route))
            throw new FormatException("RHB1 PRC1 route domain mismatch.");

        byte[] authorizationHash;
        if (link.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
        {
            var verified = ProductionMailboxRouteAuthorizationVerifier.VerifyOwnerAuthorization(
                authorizationBytes, authority,
                new ProductionMailboxOwnerRouteAuthorizationVerificationContext
                {
                    ExpectedNetworkId = _network,
                    ExpectedRouteDomainHash = _route,
                    ExpectedPredecessorKind = predecessor.AuthorizationKind,
                    ExpectedPredecessorHash = predecessor.CanonicalAuthorizationHash.ToArray(),
                    ExpectedPredecessorSequence = predecessor.AuthorizationSequence,
                    NowUnixSeconds = linkTime,
                    ClockSkewSeconds = ProductionMailboxRouteContinuityConstants.MaximumClockSkewSeconds
                }, _routeVerifier);
            var embeddedCertificate = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                verified.Advertisement.Certificate);
            if (!certificateBytes.AsSpan().SequenceEqual(embeddedCertificate))
                throw new FormatException(
                    "RHB1 owner PRA2 does not embed the exact indexed PRC1 bytes.");
            authorizationHash = verified.CanonicalHash.ToArray();
        }
        else
        {
            var rtcBytes = artifacts[link.TransitionContextIndex].CanonicalBytes.ToArray();
            var rtcValue = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(rtcBytes);
            if (!CryptographicOperations.FixedTimeEquals(rtcValue.NetworkId.Span, _network) ||
                !CryptographicOperations.FixedTimeEquals(rtcValue.RouteDomainHash.Span, _route) ||
                !CryptographicOperations.FixedTimeEquals(rtcValue.SealedOldRouteOriginLkgHash.Span,
                    predecessor.RouteOriginLkgHash.Span) ||
                rtcValue.OldRouteVerifiedAtUnixSeconds != predecessor.RouteVerifiedAtUnixSeconds ||
                rtcValue.OldLocalRouteCommitGeneration != predecessor.LocalCommitGeneration ||
                rtcValue.PredecessorAuthorizationKind != predecessor.AuthorizationKind ||
                rtcValue.PredecessorRouteAuthorizationSequence != predecessor.AuthorizationSequence ||
                !CryptographicOperations.FixedTimeEquals(
                    rtcValue.PredecessorCanonicalRouteAuthorizationHash.Span,
                    predecessor.CanonicalAuthorizationHash.Span) ||
                !CryptographicOperations.FixedTimeEquals(rtcValue.FreshCanonicalRouteCertificateHash.Span,
                    certificate.CanonicalCertificateHash.Span))
                throw new FormatException("RHB1 delegated RTC1 differs from retained route state.");
            var verifiedRtc = new VerifiedProductionMailboxRouteTransitionContext(rtcValue, rtcBytes,
                ProductionMailboxRouteAuthorizationCodec.ComputeTransitionContextHash(rtcValue));
            var rchBytes = artifacts[link.RevocationCheckpointIndex].CanonicalBytes.ToArray();
            var verifiedRch = ProductionMailboxRouteContinuityVerifier.VerifyRevocationCheckpoint(
                rchBytes, authority, revocations, _enrollment.VerifiedDelegation,
                rtcValue.TransitionSalt.Span, rtcValue.ContinuityTransitionCommitment.Span,
                predecessor.OwnerRevocationGeneration, predecessor.OwnerRevocationHeadHash.Span,
                linkTime,
                ProductionMailboxRouteContinuityConstants.MaximumClockSkewSeconds, _routeVerifier);
            var activation = ProductionMailboxRouteAuthorizationVerifier.VerifyDelegatedActivation(
                authorizationBytes, authority, revocations, certificate, verifiedRch, verifiedRtc,
                _enrollment, linkTime, ProductionMailboxRouteContinuityConstants.MaximumClockSkewSeconds,
                _routeVerifier);
            authorizationHash = activation.CanonicalHash.ToArray();
        }

        var nextRol = new ProductionMailboxRouteOriginLkg
        {
            NetworkId = _network,
            RouteDomainHash = _route,
            AuthorizationKind = link.AuthorizationKind,
            CanonicalAuthorizationHash = authorizationHash,
            AuthorizationSequence = link.NewSequence,
            CanonicalDelegationHash = _enrollment.CanonicalDelegationHash.ToArray(),
            CanonicalDelegationAcceptanceHash = _enrollment.CanonicalAcceptanceHash.ToArray(),
            OwnerRevocationGeneration = predecessor.OwnerRevocationGeneration,
            OwnerRevocationHeadHash = predecessor.OwnerRevocationHeadHash.ToArray(),
            RouteVerifiedAtUnixSeconds = predecessor.RouteVerifiedAtUnixSeconds,
            LocalCommitGeneration = predecessor.LocalCommitGeneration + 1
        };
        return new ProductionMailboxRouteHistoryLinkVerificationState
        {
            AuthorizationKind = link.AuthorizationKind,
            CanonicalAuthorizationHash = authorizationHash,
            AuthorizationSequence = link.NewSequence,
            RouteOriginLkgHash = ProductionMailboxRouteContinuityCodec.ComputeRouteOriginLkgHash(nextRol),
            RouteVerifiedAtUnixSeconds = predecessor.RouteVerifiedAtUnixSeconds,
            LocalCommitGeneration = predecessor.LocalCommitGeneration + 1,
            OwnerRevocationGeneration = predecessor.OwnerRevocationGeneration,
            OwnerRevocationHeadHash = predecessor.OwnerRevocationHeadHash.ToArray(),
            AuthorityGeneration = authority.Authority.AuthorityGeneration,
            CanonicalAuthorityHash = authority.CanonicalAuthorityHash.ToArray(),
            RevocationGeneration = revocations.Snapshot.RevocationGeneration,
            RevocationHeadHash = revocations.Snapshot.RevocationHeadHash.ToArray(),
            RevocationSnapshotHash = revocations.CanonicalSnapshotHash.ToArray()
        };
    }

    private static byte[] Fixed(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"Invalid {name}.");
        return value.ToArray();
    }
}

internal static class ProductionMailboxRouteHistoryVerifier
{
    private static ReadOnlySpan<byte> TranscriptDomain =>
        "Deep/production-mailbox/route-history-transcript/v1"u8;

    internal static VerifiedProductionMailboxRouteHistoryCheckpoint CreateInitial(
        ProductionMailboxRouteHistoryCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        if (checkpoint.LastCommittedBatchSequence != 0 || checkpoint.CumulativeCommittedBatchCount != 0 ||
            checkpoint.CumulativeVerifiedRouteLinkCount != 0 || checkpoint.CumulativeCanonicalPayloadBytes != 0 ||
            checkpoint.HistoryTranscriptHead.Length != 32 || checkpoint.HistoryTranscriptHead.Span.IndexOfAnyExcept((byte)0) >= 0 ||
            checkpoint.LastCommittedBatchHash.Length != 32 || checkpoint.LastCommittedBatchHash.Span.IndexOfAnyExcept((byte)0) >= 0 ||
            checkpoint.OwnerRevocationGeneration != 0 || checkpoint.OwnerRevocationHeadHash.Length != 32 ||
            checkpoint.OwnerRevocationHeadHash.Span.IndexOfAnyExcept((byte)0) >= 0)
            throw new ProductionMailboxRouteContinuityException(
                ProductionMailboxRouteContinuityError.InvalidField,
                "Initial RHC1 counters, transcript or revocation state is invalid.");
        var canonical = ProductionMailboxRouteContinuityCodec.EncodeRouteHistoryCheckpoint(checkpoint);
        return new(checkpoint, canonical);
    }

    internal static VerifiedProductionMailboxRouteHistoryCheckpoint Advance(
        ReadOnlySpan<byte> encodedBatch,
        VerifiedProductionMailboxRouteHistoryCheckpoint current,
        IProductionMailboxRouteHistoryLinkVerifier linkVerifier)
        => AdvanceCore(encodedBatch, current, linkVerifier, allowReplay: true).Checkpoint;

    internal static ProductionMailboxRouteHistoryAdvanceResult AdvanceWithReplay(
        ReadOnlySpan<byte> encodedBatch,
        VerifiedProductionMailboxRouteHistoryCheckpoint current,
        IProductionMailboxRouteHistoryLinkVerifier linkVerifier)
        => AdvanceCore(encodedBatch, current, linkVerifier, allowReplay: true);

    internal static ProductionMailboxRouteHistoryAdvanceResult AdvanceNextForCommit(
        ReadOnlySpan<byte> encodedBatch,
        VerifiedProductionMailboxRouteHistoryCheckpoint current,
        IProductionMailboxRouteHistoryLinkVerifier linkVerifier)
        => AdvanceCore(encodedBatch, current, linkVerifier, allowReplay: false,
            preSnapshotTestHook: null);

    internal static ProductionMailboxRouteHistoryAdvanceResult AdvanceNextForCommit(
        ReadOnlySpan<byte> encodedBatch,
        VerifiedProductionMailboxRouteHistoryCheckpoint current,
        IProductionMailboxRouteHistoryLinkVerifier linkVerifier,
        Action preSnapshotTestHook)
        => AdvanceCore(encodedBatch, current, linkVerifier, allowReplay: false,
            preSnapshotTestHook ?? throw new ArgumentNullException(nameof(preSnapshotTestHook)));

    private static ProductionMailboxRouteHistoryAdvanceResult AdvanceCore(
        ReadOnlySpan<byte> encodedBatch,
        VerifiedProductionMailboxRouteHistoryCheckpoint current,
        IProductionMailboxRouteHistoryLinkVerifier linkVerifier,
        bool allowReplay,
        Action? preSnapshotTestHook = null)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(linkVerifier);
        var preflight = ProductionMailboxRouteHistoryCodec.PreflightHeader(encodedBatch);
        var sequence = preflight.BatchSequence;
        var old = current.TrustedCheckpoint;
        if (sequence == old.LastCommittedBatchSequence)
        {
            if (!allowReplay)
                throw new FormatException(
                    "RHB1 commit-plan verification requires the exact next sequence.");
            var replayHash = SHA256.HashData(encodedBatch);
            if (!CryptographicOperations.FixedTimeEquals(replayHash, old.LastCommittedBatchHash.Span))
                throw new FormatException("RHB1 same-sequence replay conflicts with the durable batch.");
            return new(current, null, [], advanced: false);
        }
        if (old.OwnerRevocationGeneration == 1 &&
            old.OwnerRevocationHeadHash.Length == 32 &&
            old.OwnerRevocationHeadHash.Span.IndexOfAnyExcept((byte)0) >= 0)
            throw new FormatException(
                "RHB1 cannot advance after the protected owner revocation became terminal.");
        if (old.LastCommittedBatchSequence == ulong.MaxValue ||
            sequence != old.LastCommittedBatchSequence + 1)
            throw new FormatException("RHB1 batch sequence is stale or has a gap.");
        var currentHash = current.CanonicalHash.Span;
        if (!CryptographicOperations.FixedTimeEquals(encodedBatch.Slice(16, 32), currentHash))
            throw new FormatException("RHB1 does not bind the exact current RHC1.");
        if (old.CumulativeCommittedBatchCount >= ProductionMailboxRouteHistoryConstants.MaximumBatches ||
            old.CumulativeVerifiedRouteLinkCount >
                (ulong)ProductionMailboxRouteHistoryConstants.MaximumCumulativeLinks -
                preflight.LinkCount ||
            old.CumulativeCanonicalPayloadBytes >
                ProductionMailboxRouteHistoryConstants.MaximumCumulativePayloadBytes -
                checked((ulong)preflight.PayloadBytes) ||
            old.CurrentLocalCommitGeneration > ulong.MaxValue - preflight.LinkCount)
            throw new FormatException("RHB1 cumulative state is terminal or exceeds its bound.");
        ProductionMailboxRouteHistoryCodec.PreflightCanonical(
            encodedBatch, validateNestedFraming: !allowReplay,
            expectedFirstPredecessorSequence: old.CurrentAuthorizationSequence);
        preSnapshotTestHook?.Invoke();
        var frozenBatch = encodedBatch.ToArray();
        var ownedPreflight = ProductionMailboxRouteHistoryCodec
            .PreflightCanonical(frozenBatch, validateNestedFraming: !allowReplay,
                expectedFirstPredecessorSequence: old.CurrentAuthorizationSequence);
        if (ownedPreflight != preflight ||
            !CryptographicOperations.FixedTimeEquals(
                frozenBatch.AsSpan(16, 32), currentHash) ||
            old.LastCommittedBatchSequence == ulong.MaxValue ||
            ownedPreflight.BatchSequence != old.LastCommittedBatchSequence + 1 ||
            old.CumulativeCommittedBatchCount >=
                ProductionMailboxRouteHistoryConstants.MaximumBatches ||
            old.CumulativeVerifiedRouteLinkCount >
                (ulong)ProductionMailboxRouteHistoryConstants.MaximumCumulativeLinks -
                ownedPreflight.LinkCount ||
            old.CumulativeCanonicalPayloadBytes >
                ProductionMailboxRouteHistoryConstants.MaximumCumulativePayloadBytes -
                checked((ulong)ownedPreflight.PayloadBytes) ||
            old.CurrentLocalCommitGeneration > ulong.MaxValue -
                ownedPreflight.LinkCount)
            throw new FormatException(
                "RHB1 owned snapshot differs from its preflight or durable predecessor.");
        var batch = ProductionMailboxRouteHistoryCodec.DecodeOwned(
            frozenBatch, validateNestedFraming: !allowReplay);
        var payloadBytes = checked(
            (ulong)batch.Artifacts.Sum(static item => item.CanonicalBytes.Length));

        var state = new ProductionMailboxRouteHistoryLinkVerificationState
        {
            AuthorizationKind = old.CurrentAuthorizationKind,
            CanonicalAuthorizationHash = old.CurrentCanonicalAuthorizationHash.ToArray(),
            AuthorizationSequence = old.CurrentAuthorizationSequence,
            RouteOriginLkgHash = old.CurrentRouteOriginLkgHash.ToArray(),
            RouteVerifiedAtUnixSeconds = old.RouteVerifiedAtUnixSeconds,
            LocalCommitGeneration = old.CurrentLocalCommitGeneration,
            OwnerRevocationGeneration = old.OwnerRevocationGeneration,
            OwnerRevocationHeadHash = old.OwnerRevocationHeadHash.ToArray(),
            AuthorityGeneration = old.CurrentAuthorityGeneration,
            CanonicalAuthorityHash = old.CurrentCanonicalAuthorityHash.ToArray(),
            RevocationGeneration = old.CurrentRevocationGeneration,
            RevocationHeadHash = old.CurrentRevocationHeadHash.ToArray(),
            RevocationSnapshotHash = old.CurrentRevocationSnapshotHash.ToArray()
        };
        foreach (var link in batch.Links)
        {
            if (link.PredecessorSequence != state.AuthorizationSequence)
                throw new FormatException("RHB1 link predecessor sequence does not match durable state.");
            var next = linkVerifier.Verify(link, batch.Artifacts, FreezeState(state)) ??
                throw new FormatException("RHB1 link verifier returned no state.");
            ValidateNext(state, next, link);
            state = FreezeState(next);
        }

        var nextCheckpoint = new ProductionMailboxRouteHistoryCheckpoint
        {
            NetworkId = old.NetworkId.ToArray(),
            RouteDomainHash = old.RouteDomainHash.ToArray(),
            DelegationHistoryBinding = old.DelegationHistoryBinding.ToArray(),
            CurrentAuthorizationKind = state.AuthorizationKind,
            CurrentCanonicalAuthorizationHash = state.CanonicalAuthorizationHash.ToArray(),
            CurrentAuthorizationSequence = state.AuthorizationSequence,
            OwnerRevocationGeneration = state.OwnerRevocationGeneration,
            OwnerRevocationHeadHash = state.OwnerRevocationHeadHash.ToArray(),
            CurrentRouteOriginLkgHash = state.RouteOriginLkgHash.ToArray(),
            RouteVerifiedAtUnixSeconds = old.RouteVerifiedAtUnixSeconds,
            CurrentLocalCommitGeneration = state.LocalCommitGeneration,
            PinnedMrXPublicKeySha256 = old.PinnedMrXPublicKeySha256.ToArray(),
            CurrentAuthorityGeneration = state.AuthorityGeneration,
            CurrentCanonicalAuthorityHash = state.CanonicalAuthorityHash.ToArray(),
            CurrentRevocationGeneration = state.RevocationGeneration,
            CurrentRevocationHeadHash = state.RevocationHeadHash.ToArray(),
            CurrentRevocationSnapshotHash = state.RevocationSnapshotHash.ToArray(),
            LastCommittedBatchSequence = sequence,
            CumulativeCommittedBatchCount = old.CumulativeCommittedBatchCount + 1,
            CumulativeVerifiedRouteLinkCount = old.CumulativeVerifiedRouteLinkCount + (ulong)batch.Links.Count,
            CumulativeCanonicalPayloadBytes = old.CumulativeCanonicalPayloadBytes + payloadBytes,
            HistoryTranscriptHead = SHA256.HashData([.. TranscriptDomain, .. old.HistoryTranscriptHead.Span,
                .. frozenBatch]),
            LastCommittedBatchHash = SHA256.HashData(frozenBatch)
        };
        var canonical = ProductionMailboxRouteContinuityCodec.EncodeRouteHistoryCheckpoint(nextCheckpoint);
        return new(new VerifiedProductionMailboxRouteHistoryCheckpoint(
            nextCheckpoint, canonical), batch, frozenBatch, advanced: true);
    }

    private static void ValidateNext(ProductionMailboxRouteHistoryLinkVerificationState previous,
        ProductionMailboxRouteHistoryLinkVerificationState next, ProductionMailboxRouteHistoryLink link)
    {
        FixedNonzero(next.CanonicalAuthorizationHash, "authorization hash");
        FixedNonzero(next.RouteOriginLkgHash, "ROL1 hash");
        FixedNonzero(next.CanonicalAuthorityHash, "authority hash");
        FixedNonzero(next.RevocationHeadHash, "PMR1 head hash");
        FixedNonzero(next.RevocationSnapshotHash, "PMR1 snapshot hash");
        if (next.OwnerRevocationHeadHash.Length != 32 ||
            next.OwnerRevocationGeneration != previous.OwnerRevocationGeneration ||
            !CryptographicOperations.FixedTimeEquals(next.OwnerRevocationHeadHash.Span,
                previous.OwnerRevocationHeadHash.Span))
            throw new FormatException("RHB1 owner revocation state changed inside route history.");
        if (next.AuthorizationKind != link.AuthorizationKind || next.AuthorizationSequence != link.NewSequence ||
            next.AuthorizationSequence != previous.AuthorizationSequence + 1 ||
            next.RouteVerifiedAtUnixSeconds != previous.RouteVerifiedAtUnixSeconds ||
            next.LocalCommitGeneration != previous.LocalCommitGeneration + 1 ||
            next.AuthorityGeneration < previous.AuthorityGeneration || next.AuthorityGeneration == ulong.MaxValue ||
            next.RevocationGeneration == 0 || next.RevocationGeneration == ulong.MaxValue)
            throw new FormatException("RHB1 verified link state is inconsistent or terminal.");
        if (next.AuthorityGeneration == previous.AuthorityGeneration)
        {
            if (!CryptographicOperations.FixedTimeEquals(next.CanonicalAuthorityHash.Span,
                    previous.CanonicalAuthorityHash.Span) ||
                next.RevocationGeneration < previous.RevocationGeneration ||
                (next.RevocationGeneration == previous.RevocationGeneration &&
                 (!CryptographicOperations.FixedTimeEquals(next.RevocationHeadHash.Span,
                      previous.RevocationHeadHash.Span) ||
                  !CryptographicOperations.FixedTimeEquals(next.RevocationSnapshotHash.Span,
                      previous.RevocationSnapshotHash.Span))))
                throw new FormatException("RHB1 PMA/PMR lineage rolled back or forked.");
        }
    }

    private static ProductionMailboxRouteHistoryLinkVerificationState FreezeState(
        ProductionMailboxRouteHistoryLinkVerificationState value) => value with
    {
        CanonicalAuthorizationHash = value.CanonicalAuthorizationHash.ToArray(),
        RouteOriginLkgHash = value.RouteOriginLkgHash.ToArray(),
        OwnerRevocationHeadHash = value.OwnerRevocationHeadHash.ToArray(),
        CanonicalAuthorityHash = value.CanonicalAuthorityHash.ToArray(),
        RevocationHeadHash = value.RevocationHeadHash.ToArray(),
        RevocationSnapshotHash = value.RevocationSnapshotHash.ToArray()
    };

    private static void FixedNonzero(ReadOnlyMemory<byte> value, string name)
    {
        if (value.Length != 32 || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException($"RHB1 verified {name} is invalid.");
    }
}
