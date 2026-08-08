using Deep.Protocol.DeepExtension.MailboxTopology;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxRouteHistoryTests
{
    [Fact]
    public void CodecRoundTripsCanonicalOwnerBatch()
    {
        var batch = CreateOwnerBatch();
        var encoded = ProductionMailboxRouteHistoryCodec.Encode(batch);
        var decoded = ProductionMailboxRouteHistoryCodec.Decode(encoded);

        Assert.Equal(1UL, decoded.BatchSequence);
        Assert.Equal(4, decoded.Artifacts.Count);
        Assert.Equal(encoded, ProductionMailboxRouteHistoryCodec.Encode(decoded));
    }

    [Fact]
    public void CodecRejectsUnusedArtifactRows()
    {
        var batch = CreateOwnerBatch();
        var artifacts = batch.Artifacts.Concat([
            new ProductionMailboxRouteHistoryArtifact
            {
                Kind = ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement,
                CanonicalBytes = "unused"u8.ToArray()
            }
        ]).OrderBy(static item => (byte)item.Kind)
          .ThenBy(static item => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(item.CanonicalBytes.Span)),
              StringComparer.Ordinal)
          .ToArray();
        var changed = batch with { Artifacts = artifacts };
        Assert.Throws<FormatException>(() => ProductionMailboxRouteHistoryCodec.Encode(changed));
    }

    [Fact]
    public void CodecRejectsOwnerRtcInjection()
    {
        var batch = CreateOwnerBatch();
        var changed = batch with
        {
            Links = [batch.Links[0] with { TransitionContextIndex = 0 }]
        };
        Assert.Throws<FormatException>(() => ProductionMailboxRouteHistoryCodec.Encode(changed));
    }

    [Fact]
    public void LostResponseRestartReplayReturnsExactCheckpointWithoutLinkCallback()
    {
        var initial = ProductionMailboxRouteHistoryVerifier.CreateInitial(CreateInitialCheckpoint());
        var batch = CreateOwnerBatch() with
        {
            PreviousCheckpointHash = initial.CanonicalHash.ToArray()
        };
        var encoded = ProductionMailboxRouteHistoryCodec.Encode(batch);
        var verifier = new AdvancingLinkVerifier();
        var committed = ProductionMailboxRouteHistoryVerifier.Advance(encoded, initial, verifier);
        Assert.Equal(1, verifier.CallCount);

        verifier.ThrowIfCalled = true;
        var replayed = ProductionMailboxRouteHistoryVerifier.Advance(encoded, committed, verifier);
        Assert.Equal(committed.CanonicalBytes.ToArray(), replayed.CanonicalBytes.ToArray());
        Assert.Equal(1, verifier.CallCount);
    }

    [Fact]
    public void RestartSameSequenceChangedBytesForksBeforeLinkCallback()
    {
        var initial = ProductionMailboxRouteHistoryVerifier.CreateInitial(CreateInitialCheckpoint());
        var encoded = ProductionMailboxRouteHistoryCodec.Encode(CreateOwnerBatch() with
        {
            PreviousCheckpointHash = initial.CanonicalHash.ToArray()
        });
        var verifier = new AdvancingLinkVerifier();
        var committed = ProductionMailboxRouteHistoryVerifier.Advance(encoded, initial, verifier);
        verifier.ThrowIfCalled = true;
        var changed = encoded.ToArray();
        changed[^1] ^= 0x01;
        Assert.Throws<FormatException>(() =>
            ProductionMailboxRouteHistoryVerifier.Advance(changed, committed, verifier));
        Assert.Equal(1, verifier.CallCount);
    }

    private static ProductionMailboxRouteHistoryBatch CreateOwnerBatch()
    {
        var source = new[]
        {
            Artifact(ProductionMailboxRouteHistoryArtifactKind.Authority, "PMA1-a"u8),
            Artifact(ProductionMailboxRouteHistoryArtifactKind.Revocations, "PMR1-a"u8),
            Artifact(ProductionMailboxRouteHistoryArtifactKind.RouteCertificate, "PRC1-a"u8),
            Artifact(ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement, "PRA2-a"u8)
        };
        var artifacts = source.OrderBy(static item => (byte)item.Kind)
            .ThenBy(static item => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(item.CanonicalBytes.Span)),
                StringComparer.Ordinal).ToArray();
        ushort Index(ProductionMailboxRouteHistoryArtifactKind kind) =>
            checked((ushort)Array.FindIndex(artifacts, item => item.Kind == kind));
        return new()
        {
            BatchSequence = 1,
            PreviousCheckpointHash = Enumerable.Repeat((byte)0xA1, 32).ToArray(),
            Artifacts = artifacts,
            Links =
            [
                new ProductionMailboxRouteHistoryLink
                {
                    AuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
                    AuthorityIndex = Index(ProductionMailboxRouteHistoryArtifactKind.Authority),
                    RevocationsIndex = Index(ProductionMailboxRouteHistoryArtifactKind.Revocations),
                    RouteCertificateIndex = Index(ProductionMailboxRouteHistoryArtifactKind.RouteCertificate),
                    RevocationCheckpointIndex = ushort.MaxValue,
                    TransitionContextIndex = ushort.MaxValue,
                    AuthorizationIndex = Index(ProductionMailboxRouteHistoryArtifactKind.OwnerAdvertisement),
                    PredecessorSequence = 1,
                    NewSequence = 2
                }
            ]
        };
    }

    private static ProductionMailboxRouteHistoryArtifact Artifact(
        ProductionMailboxRouteHistoryArtifactKind kind, ReadOnlySpan<byte> bytes) => new()
    {
        Kind = kind,
        CanonicalBytes = bytes.ToArray()
    };

    private static ProductionMailboxRouteHistoryCheckpoint CreateInitialCheckpoint() => new()
    {
        NetworkId = Fill(1, 16),
        RouteDomainHash = Fill(2, 32),
        DelegationHistoryBinding = Fill(3, 32),
        CurrentAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
        CurrentCanonicalAuthorizationHash = Fill(4, 32),
        CurrentAuthorizationSequence = 1,
        OwnerRevocationGeneration = 0,
        OwnerRevocationHeadHash = new byte[32],
        CurrentRouteOriginLkgHash = Fill(5, 32),
        RouteVerifiedAtUnixSeconds = 10,
        CurrentLocalCommitGeneration = 1,
        PinnedMrXPublicKeySha256 = Fill(6, 32),
        CurrentAuthorityGeneration = 1,
        CurrentCanonicalAuthorityHash = Fill(7, 32),
        CurrentRevocationGeneration = 1,
        CurrentRevocationHeadHash = Fill(8, 32),
        CurrentRevocationSnapshotHash = Fill(9, 32),
        LastCommittedBatchSequence = 0,
        CumulativeCommittedBatchCount = 0,
        CumulativeVerifiedRouteLinkCount = 0,
        CumulativeCanonicalPayloadBytes = 0,
        HistoryTranscriptHead = new byte[32],
        LastCommittedBatchHash = new byte[32]
    };

    private static byte[] Fill(byte value, int length) => Enumerable.Repeat(value, length).ToArray();

    private sealed class AdvancingLinkVerifier : IProductionMailboxRouteHistoryLinkVerifier
    {
        public int CallCount { get; private set; }
        public bool ThrowIfCalled { get; set; }

        public ProductionMailboxRouteHistoryLinkVerificationState Verify(
            ProductionMailboxRouteHistoryLink link,
            IReadOnlyList<ProductionMailboxRouteHistoryArtifact> artifacts,
            ProductionMailboxRouteHistoryLinkVerificationState predecessor)
        {
            CallCount++;
            if (ThrowIfCalled)
                throw new InvalidOperationException("Link verifier must not run on replay/fork fast path.");
            return predecessor with
            {
                AuthorizationKind = link.AuthorizationKind,
                CanonicalAuthorizationHash = Fill(10, 32),
                AuthorizationSequence = link.NewSequence,
                RouteOriginLkgHash = Fill(11, 32),
                LocalCommitGeneration = predecessor.LocalCommitGeneration + 1
            };
        }
    }
}
