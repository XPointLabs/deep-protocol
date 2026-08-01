using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Sodium;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxTopologyTests
{
    private const ulong Now = 2_100_000_000;

    [Fact]
    public void Pmt1_AndPms1_VerifyEndToEnd_AndResolveExactlyTwoPinnedReplicas()
    {
        var f = CreateFixture();
        var topologyBytes = ProductionMailboxTopologyCodec.Encode(f.Topology);
        var verifiedTopology = ProductionMailboxTopologyVerifier.Verify(topologyBytes, f.Authority,
            f.Context, new SodiumProductionMailboxTopologySignatureVerifier());
        var selection = SignSelection(f, verifiedTopology);
        var verified = ProductionMailboxSelectionVerifier.Verify(
            ProductionMailboxTopologyCodec.EncodeSelection(selection), f.Authority, verifiedTopology,
            f.PlacementId, Now, 0, new SodiumProductionMailboxTopologySignatureVerifier());

        Assert.Equal(2, verified.Replicas.Count);
        Assert.NotEqual(verified.Replicas[0].ReplicaId.ToArray(), verified.Replicas[1].ReplicaId.ToArray());
        Assert.All(verified.Replicas, replica =>
        {
            Assert.Equal(Uri.UriSchemeHttps, replica.HttpsEndpoint.Scheme);
            Assert.Equal(32, replica.CurrentSpkiSha256.Length);
            Assert.Equal(32, replica.NextSpkiSha256.Length);
            Assert.NotEqual(replica.CurrentSpkiSha256.ToArray(), replica.NextSpkiSha256.ToArray());
        });
        Assert.Equal(SHA256.HashData(topologyBytes), verifiedTopology.CanonicalTopologyHash.ToArray());
    }

    [Fact]
    public void Codecs_AreDeterministicCanonical_AndRejectUnknownOrTrailingBytes()
    {
        var f = CreateFixture();
        var encoded = ProductionMailboxTopologyCodec.Encode(f.Topology);
        Assert.Equal(encoded, ProductionMailboxTopologyCodec.Encode(ProductionMailboxTopologyCodec.Decode(encoded)));
        Assert.Equal(ProductionMailboxTopologyCodec.ComputeCanonicalHash(f.Topology), SHA256.HashData(encoded));

        foreach (var mutation in new Action<byte[]>[]
        {
            bytes => bytes[0] ^= 1, bytes => bytes[4] = 2, bytes => bytes[5] = 1
        })
        {
            var changed = encoded.ToArray(); mutation(changed);
            Assert.Throws<ProductionMailboxTopologyException>(() => ProductionMailboxTopologyCodec.Decode(changed));
        }
        Assert.Throws<ProductionMailboxTopologyException>(() => ProductionMailboxTopologyCodec.Decode([.. encoded, 0]));

        var verifiedTopology = ProductionMailboxTopologyVerifier.Verify(encoded, f.Authority, f.Context, f.SignatureVerifier);
        var selection = SignSelection(f, verifiedTopology);
        var selectionBytes = ProductionMailboxTopologyCodec.EncodeSelection(selection);
        Assert.Equal(selectionBytes, ProductionMailboxTopologyCodec.EncodeSelection(ProductionMailboxTopologyCodec.DecodeSelection(selectionBytes)));
        Assert.Throws<ProductionMailboxTopologyException>(() => ProductionMailboxTopologyCodec.DecodeSelection([.. selectionBytes, 0]));
    }

    [Fact]
    public void TopologyVerifier_RejectsTamperRollbackWrongAuthorityAndStaleTime()
    {
        var f = CreateFixture();
        var encoded = ProductionMailboxTopologyCodec.Encode(f.Topology);
        var tampered = encoded.ToArray(); tampered[^1] ^= 1;
        AssertError(ProductionMailboxTopologyError.InvalidSignature,
            () => ProductionMailboxTopologyVerifier.Verify(tampered, f.Authority, f.Context, f.SignatureVerifier));
        AssertError(ProductionMailboxTopologyError.TopologyRollback,
            () => ProductionMailboxTopologyVerifier.Verify(encoded, f.Authority,
                f.Context with { LastCommittedTopologyGeneration = f.Topology.TopologyGeneration }, f.SignatureVerifier));
        AssertError(ProductionMailboxTopologyError.PreviousHashMismatch,
            () => ProductionMailboxTopologyVerifier.Verify(encoded, f.Authority,
                f.Context with { LastCommittedTopologyHash = Bytes(99, 32) }, f.SignatureVerifier));
        AssertError(ProductionMailboxTopologyError.Expired,
            () => ProductionMailboxTopologyVerifier.Verify(encoded, f.Authority,
                f.Context with { NowUnixSeconds = f.Topology.ExpiresAtUnixSeconds + 1 }, f.SignatureVerifier));
        var wrong = ReSignTopology(f.Topology with { CanonicalAuthorityHash = Bytes(101, 32) }, f.IssuerPrivateKey);
        AssertError(ProductionMailboxTopologyError.AuthorityMismatch,
            () => ProductionMailboxTopologyVerifier.Verify(ProductionMailboxTopologyCodec.Encode(wrong), f.Authority, f.Context, f.SignatureVerifier));
    }

    [Fact]
    public void TopologyCodec_RejectsNodeOrderDuplicateEndpointPinsAndUnsafeUris()
    {
        var f = CreateFixture(); var nodes = f.Topology.CurrentEpoch.Nodes;
        InvalidTopology(f.Topology with { CurrentEpoch = f.Topology.CurrentEpoch with { Nodes = [nodes[1], nodes[0], nodes[2]] } });
        InvalidTopology(f.Topology with
        {
            CurrentEpoch = f.Topology.CurrentEpoch with
            { Nodes = [nodes[0], nodes[1] with { HttpsEndpoint = nodes[0].HttpsEndpoint }, nodes[2]] }
        });
        InvalidTopology(f.Topology with
        {
            CurrentEpoch = f.Topology.CurrentEpoch with
            { Nodes = [nodes[0] with { NextSpkiSha256 = nodes[0].CurrentSpkiSha256 }, nodes[1], nodes[2]] }
        });
        foreach (var endpoint in new[] { "http://node.example.net/", "https://localhost/", "https://node.test/", "https://node.example.net/path", "https://u:p@node.example.net/" })
            InvalidTopology(f.Topology with
            {
                CurrentEpoch = f.Topology.CurrentEpoch with
                { Nodes = [nodes[0] with { HttpsEndpoint = endpoint }, nodes[1], nodes[2]] }
            });
    }

    [Fact]
    public void OfficialTopology_RejectsPrivateIp_ButExplicitUserManagedPolicyAllowsIt()
    {
        var f = CreateFixture(); var nodes = f.Topology.CurrentEpoch.Nodes;
        var privateTopology = ReSignTopology(f.Topology with
        {
            CurrentEpoch = f.Topology.CurrentEpoch with
            { Nodes = [nodes[0] with { HttpsEndpoint = "https://192.168.1.8:8443/" }, nodes[1], nodes[2]] }
        }, f.IssuerPrivateKey);
        AssertError(ProductionMailboxTopologyError.InvalidEndpoint,
            () => ProductionMailboxTopologyVerifier.Verify(ProductionMailboxTopologyCodec.Encode(privateTopology), f.Authority, f.Context, f.SignatureVerifier));

        var user = CreateFixture(userManaged: true); var userNodes = user.Topology.CurrentEpoch.Nodes;
        var allowed = ReSignTopology(user.Topology with
        {
            CurrentEpoch = user.Topology.CurrentEpoch with
            { Nodes = [userNodes[0] with { HttpsEndpoint = "https://192.168.1.8:8443/" }, userNodes[1], userNodes[2]] }
        }, user.IssuerPrivateKey);
        var verified = ProductionMailboxTopologyVerifier.Verify(ProductionMailboxTopologyCodec.Encode(allowed),
            user.Authority, user.Context, user.SignatureVerifier);
        Assert.Equal("192.168.1.8", verified.Snapshot.CurrentEpoch.Nodes[0].HttpsEndpoint.Split('/')[2].Split(':')[0]);
    }

    [Fact]
    public void SelectionVerifier_RejectsWrongInputOrderProofBindingAndSignature()
    {
        var f = CreateFixture();
        var vt = ProductionMailboxTopologyVerifier.Verify(ProductionMailboxTopologyCodec.Encode(f.Topology), f.Authority, f.Context, f.SignatureVerifier);
        var valid = SignSelection(f, vt);
        AssertError(ProductionMailboxTopologyError.SelectionMismatch,
            () => ProductionMailboxSelectionVerifier.Verify(ProductionMailboxTopologyCodec.EncodeSelection(valid), f.Authority, vt,
                new BlindedPlacementId(Bytes(200, 32)), Now, 0, f.SignatureVerifier));

        var reversed = ReSignSelection(valid with { Replicas = valid.Replicas.Reverse().ToArray() }, f.IssuerPrivateKey);
        AssertError(ProductionMailboxTopologyError.SelectionMismatch,
            () => VerifySelection(reversed, f, vt));
        var wrongProof = valid.Replicas[0] with { ReplicaId = valid.Replicas[1].ReplicaId };
        var badProof = valid with { Replicas = [wrongProof, valid.Replicas[1]] };
        Assert.Throws<ProductionMailboxTopologyException>(() => ProductionMailboxTopologyCodec.EncodeSelection(badProof));
        var bytes = ProductionMailboxTopologyCodec.EncodeSelection(valid); bytes[^1] ^= 1;
        AssertError(ProductionMailboxTopologyError.InvalidSignature,
            () => ProductionMailboxSelectionVerifier.Verify(bytes, f.Authority, vt,
                f.PlacementId, Now, 0, f.SignatureVerifier));
    }

    [Fact]
    public void RendezvousV1_IsStableAndMailboxSpecific()
    {
        var f = CreateFixture();
        var a = ProductionMailboxReplicaSelection.Select(f.Topology.NetworkId.Span, f.Topology.AuthorityGeneration,
            f.Topology.CurrentEpoch, ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(new BlindedPlacementId(Bytes(10, 32))));
        var again = ProductionMailboxReplicaSelection.Select(f.Topology.NetworkId.Span, f.Topology.AuthorityGeneration,
            f.Topology.CurrentEpoch, ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(new BlindedPlacementId(Bytes(10, 32))));
        Assert.Equal(a.Select(x => Convert.ToHexString(x.Span)), again.Select(x => Convert.ToHexString(x.Span)));
        Assert.Equal(2, a.Count); Assert.False(a[0].Span.SequenceEqual(a[1].Span));
        Assert.NotEqual(
            Convert.ToHexString(ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(new BlindedPlacementId(Bytes(10, 32)))),
            Convert.ToHexString(ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(new BlindedPlacementId(Bytes(11, 32)))));
    }

    [Fact]
    public void TwoMailboxes_ShareOneTopology_ButBindDistinctPlacementAndExactTwoSelections()
    {
        var f = CreateFixture();
        var topology = ProductionMailboxTopologyVerifier.Verify(
            ProductionMailboxTopologyCodec.Encode(f.Topology), f.Authority, f.Context, f.SignatureVerifier);
        var firstPlacement = new BlindedPlacementId(Bytes(201, 32));
        var secondPlacement = new BlindedPlacementId(Bytes(202, 32));
        var first = SignSelectionFor(f, topology, firstPlacement);
        var second = SignSelectionFor(f, topology, secondPlacement);
        var firstMailboxCommitment = MailboxPlacementCommitment.Compute(firstPlacement);
        var secondMailboxCommitment = MailboxPlacementCommitment.Compute(secondPlacement);
        var firstVerified = ProductionMailboxSelectionVerifier.Verify(
            ProductionMailboxTopologyCodec.EncodeSelection(first), f.Authority, topology,
            firstPlacement, Now, 0, f.SignatureVerifier);
        var secondVerified = ProductionMailboxSelectionVerifier.Verify(
            ProductionMailboxTopologyCodec.EncodeSelection(second), f.Authority, topology,
            secondPlacement, Now, 0, f.SignatureVerifier);
        var firstGrant = SignGrant(f, firstMailboxCommitment, Bytes(211, 32), 1);
        var secondGrant = SignGrant(f, secondMailboxCommitment, Bytes(212, 32), 2);

        Assert.Equal(first.TopologyPlacementCommitment, second.TopologyPlacementCommitment);
        Assert.NotEqual(first.MailboxPlacementCommitment, second.MailboxPlacementCommitment);
        Assert.Equal(firstVerified.Proof.MailboxPlacementCommitment.ToArray(), firstGrant.PlacementCommitment.ToArray());
        Assert.Equal(secondVerified.Proof.MailboxPlacementCommitment.ToArray(), secondGrant.PlacementCommitment.ToArray());
        Assert.NotEqual(firstGrant.PlacementCommitment.ToArray(), secondGrant.PlacementCommitment.ToArray());
        var decodedFirstGrant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(firstGrant));
        Assert.Equal(firstGrant.Epoch, decodedFirstGrant.Epoch);
        Assert.Equal(firstGrant.HolderPublicKey.ToArray(), decodedFirstGrant.HolderPublicKey.ToArray());
        Assert.Equal(firstGrant.PlacementCommitment.ToArray(), decodedFirstGrant.PlacementCommitment.ToArray());
        Assert.Equal(2, firstVerified.Replicas.Count);
        Assert.Equal(2, secondVerified.Replicas.Count);
        AssertError(ProductionMailboxTopologyError.SelectionMismatch, () =>
            ProductionMailboxSelectionVerifier.Verify(
                ProductionMailboxTopologyCodec.EncodeSelection(first), f.Authority, topology,
                secondPlacement, Now, 0, f.SignatureVerifier));
        var substituted = ReSignSelection(first with
        {
            MailboxPlacementCommitment = secondMailboxCommitment
        }, f.IssuerPrivateKey);
        AssertError(ProductionMailboxTopologyError.SelectionMismatch, () =>
            ProductionMailboxSelectionVerifier.Verify(
                ProductionMailboxTopologyCodec.EncodeSelection(substituted), f.Authority, topology,
                firstPlacement, Now, 0, f.SignatureVerifier));
    }

    [Fact]
    public void VerifiedHandles_DefensivelyCopyCallerArrays()
    {
        var f = CreateFixture(); var bytes = ProductionMailboxTopologyCodec.Encode(f.Topology);
        var vt = ProductionMailboxTopologyVerifier.Verify(bytes, f.Authority, f.Context, f.SignatureVerifier);
        var exposed = vt.Snapshot; var original = vt.CanonicalTopologyHash.ToArray();
        Writable(exposed.NetworkId)[0] = 0;
        Writable(vt.CanonicalTopologyHash)[0] = 0;
        Assert.Equal(SHA256.HashData(bytes), original);
        Assert.Equal(original, vt.CanonicalTopologyHash.ToArray());
        Assert.NotEqual(0, vt.Snapshot.NetworkId.Span[0]);
    }

    [Fact]
    public void SelectionVerifier_RejectsCanonicalMip1WithSubstitutedSigningKey()
    {
        var f = CreateFixture();
        var vt = ProductionMailboxTopologyVerifier.Verify(ProductionMailboxTopologyCodec.Encode(f.Topology), f.Authority, f.Context, f.SignatureVerifier);
        var valid = SignSelection(f, vt);
        var mip = MailboxPeerReplicationCodec.DecodeMembershipProof(valid.Replicas[0].CanonicalMIP1Proof.Span);
        var substituted = MailboxPeerReplicationCodec.EncodeMembershipProof(mip with { SigningPublicKey = Bytes(222, 32) });
        var changed = ReSignSelection(valid with
        {
            Replicas =
            [valid.Replicas[0] with { CanonicalMIP1Proof = substituted }, valid.Replicas[1]]
        }, f.IssuerPrivateKey);
        AssertError(ProductionMailboxTopologyError.InvalidMembershipProof, () => VerifySelection(changed, f, vt));
    }

    [Fact]
    public void Verifiers_FreezeCallerBytesBeforeSignatureCallbackMutation()
    {
        var f = CreateFixture(); var topologyBytes = ProductionMailboxTopologyCodec.Encode(f.Topology);
        var topologyVerifier = new MutatingVerifier(() => topologyBytes[20] ^= 1);
        var vt = ProductionMailboxTopologyVerifier.Verify(topologyBytes, f.Authority, f.Context, topologyVerifier);
        var selection = SignSelection(f, vt); var selectionBytes = ProductionMailboxTopologyCodec.EncodeSelection(selection);
        var selectionVerifier = new MutatingVerifier(() => selectionBytes[30] ^= 1);
        var verified = ProductionMailboxSelectionVerifier.Verify(selectionBytes, f.Authority, vt,
            f.PlacementId, Now, 0, selectionVerifier);
        Assert.Equal(2, verified.Replicas.Count);
    }

    [Fact]
    public void TopologyGenesis_IsExplicitAndOversizedArtifactsFailBeforeCopy()
    {
        var f = CreateFixture();
        var genesis = ReSignTopology(f.Topology with { TopologyGeneration = 1, PreviousTopologyHash = new byte[32] }, f.IssuerPrivateKey);
        var verified = ProductionMailboxTopologyVerifier.Verify(ProductionMailboxTopologyCodec.Encode(genesis), f.Authority,
            f.Context with { LastCommittedTopologyGeneration = 0, LastCommittedTopologyHash = new byte[32] }, f.SignatureVerifier);
        Assert.Equal((ulong)1, verified.CommittedTopologyGeneration);
        AssertError(ProductionMailboxTopologyError.InvalidLength, () => ProductionMailboxTopologyCodec.Decode(
            new byte[ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes + 1]));
        AssertError(ProductionMailboxTopologyError.InvalidLength, () => ProductionMailboxTopologyCodec.DecodeSelection(
            new byte[ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes + 1]));
    }

    [Fact]
    public void DeterministicMutationLoops_FailClosedForPmt1AndPms1()
    {
        var f = CreateFixture();
        var topologyBytes = ProductionMailboxTopologyCodec.Encode(f.Topology);
        for (var offset = 0; offset < topologyBytes.Length; offset += Math.Max(1, topologyBytes.Length / 97))
        {
            var changed = topologyBytes.ToArray();
            changed[offset] ^= 1;
            Assert.Throws<ProductionMailboxTopologyException>(() =>
                ProductionMailboxTopologyVerifier.Verify(changed, f.Authority, f.Context, f.SignatureVerifier));
        }

        var topology = ProductionMailboxTopologyVerifier.Verify(topologyBytes, f.Authority, f.Context, f.SignatureVerifier);
        var selectionBytes = ProductionMailboxTopologyCodec.EncodeSelection(SignSelection(f, topology));
        for (var offset = 0; offset < selectionBytes.Length; offset += Math.Max(1, selectionBytes.Length / 97))
        {
            var changed = selectionBytes.ToArray();
            changed[offset] ^= 1;
            Assert.Throws<ProductionMailboxTopologyException>(() => ProductionMailboxSelectionVerifier.Verify(
                changed, f.Authority, topology, f.PlacementId, Now, 0, f.SignatureVerifier));
        }
    }

    private static void VerifySelection(ProductionMailboxSelectionProof proof, Fixture f, VerifiedProductionMailboxTopology topology) =>
        ProductionMailboxSelectionVerifier.Verify(ProductionMailboxTopologyCodec.EncodeSelection(proof), f.Authority,
            topology, f.PlacementId, Now, 0, f.SignatureVerifier);

    private static void InvalidTopology(ProductionMailboxTopologySnapshot topology) =>
        Assert.Throws<ProductionMailboxTopologyException>(() => ProductionMailboxTopologyCodec.GetSigningBytes(topology));

    private static void AssertError(ProductionMailboxTopologyError error, Action action) =>
        Assert.Equal(error, Assert.Throws<ProductionMailboxTopologyException>(action).Error);

    private static Fixture CreateFixture(bool userManaged = false)
    {
        var issuer = PublicKeyAuth.GenerateKeyPair(Bytes(30, 32));
        var mrX = PublicKeyAuth.GenerateKeyPair(Bytes(60, 32));
        var currentDescriptors = Descriptors(9, Now - 100, Now + 1_000);
        var nextDescriptors = Descriptors(10, Now + 100, Now + 2_000);
        var currentRoot = MembershipRouteDescriptorCodec.ComputeRoot(currentDescriptors);
        var nextRoot = MembershipRouteDescriptorCodec.ComputeRoot(nextDescriptors);
        var authority = new ProductionMailboxAuthority
        {
            DevelopmentOnly = false,
            Environment = ProductionMailboxAuthorityEnvironment.Production,
            Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
            Ownership = userManaged ? ProductionMailboxAuthorityOwnership.UserManaged : ProductionMailboxAuthorityOwnership.OfficialManaged,
            EndpointPolicy = userManaged ? ProductionMailboxAuthorityEndpointPolicy.UserManagedPrivateHttps : ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
            NetworkId = Bytes(1, 16),
            AuthorityGeneration = 7,
            PreviousAuthorityHash = Bytes(2, 32),
            MailboxIssuerEd25519PublicKey = issuer.PublicKey,
            MrXApprovalEd25519PublicKey = mrX.PublicKey,
            Coordinator = Endpoint("https://coord.example.net/", 4),
            NodeIngress = Endpoint("https://ingress.example.net/mau2/", 6),
            CurrentEpoch = AuthorityEpoch(9, 70, currentRoot, Bytes(8, 32), Now - 100, Now + 1_000),
            NextEpoch = AuthorityEpoch(10, 71, nextRoot, Bytes(10, 32), Now + 100, Now + 2_000),
            Revocation = new ProductionMailboxAuthorityRevocation
            {
                SnapshotHash = Bytes(12, 32),
                HeadHash = Bytes(13, 32),
                PreviousHeadHash = Bytes(22, 32),
                Generation = 6,
                IssuedAtUnixSeconds = Now - 20,
                ExpiresAtUnixSeconds = Now + 500
            },
            MrXApproval = new ProductionMailboxAuthorityApproval
            {
                AuthorityPayloadHash = Bytes(14, 32),
                AllowedAndroidSigningCertificateSha256 = [Bytes(15, 32)],
                AllowedWindowsSigningCertificateSha256 = [Bytes(16, 32)],
                AndroidReleaseBuildArtifactSha256 = [Bytes(17, 32)],
                WindowsReleaseBuildArtifactSha256 = [Bytes(18, 32)],
                RolloutNotBeforeUnixSeconds = Now - 30,
                RolloutNotAfterUnixSeconds = Now + 500
            },
            Signature = new byte[64]
        };
        authority = SignAuthority(authority, mrX.PrivateKey);
        var authorityContext = new ProductionMailboxAuthorityVerificationContext
        {
            PinnedMrXPublicKeySha256 = SHA256.HashData(mrX.PublicKey),
            ExpectedNetworkId = authority.NetworkId,
            LastCommittedGeneration = 6,
            LastCommittedAuthorityHash = authority.PreviousAuthorityHash,
            LastCommittedRevocationGeneration = 5,
            LastCommittedRevocationHeadHash = authority.Revocation.PreviousHeadHash,
            LastCommittedRevocationSnapshotHash = Bytes(23, 32),
            NowUnixSeconds = Now,
            ClockSkewSeconds = 0
        };
        var verifiedAuthority = ProductionMailboxAuthorityVerifier.Verify(authority, authorityContext, new SodiumProductionMailboxAuthoritySignatureVerifier());
        var topology = new ProductionMailboxTopologySnapshot
        {
            NetworkId = authority.NetworkId,
            AuthorityGeneration = authority.AuthorityGeneration,
            CanonicalAuthorityHash = verifiedAuthority.CanonicalAuthorityHash,
            TopologyGeneration = 3,
            PreviousTopologyHash = Bytes(90, 32),
            IssuedAtUnixSeconds = Now - 10,
            ExpiresAtUnixSeconds = Now + 100,
            CurrentEpoch = TopologyEpoch(authority.CurrentEpoch, currentDescriptors),
            NextEpoch = TopologyEpoch(authority.NextEpoch, nextDescriptors),
            IssuerSignature = new byte[64]
        };
        topology = ReSignTopology(topology, issuer.PrivateKey);
        var blindedPlacement = new BlindedPlacementId(Bytes(201, 32));
        return new Fixture(verifiedAuthority, topology, issuer.PrivateKey, currentDescriptors,
            blindedPlacement,
            ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(blindedPlacement),
            MailboxPlacementCommitment.Compute(blindedPlacement),
            new ProductionMailboxTopologyVerificationContext
            {
                LastCommittedTopologyGeneration = 2,
                LastCommittedTopologyHash = topology.PreviousTopologyHash,
                NowUnixSeconds = Now,
                ClockSkewSeconds = 0
            },
            new SodiumProductionMailboxTopologySignatureVerifier());
    }

    private static ProductionMailboxSelectionProof SignSelection(Fixture f, VerifiedProductionMailboxTopology topology) =>
        SignSelectionFor(f, topology, new BlindedPlacementId(Bytes(201, 32)));

    private static ProductionMailboxSelectionProof SignSelectionFor(
        Fixture f,
        VerifiedProductionMailboxTopology topology,
        BlindedPlacementId blindedPlacement)
    {
        var selectionInputCommitment = ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(blindedPlacement);
        var mailboxPlacementCommitment = MailboxPlacementCommitment.Compute(blindedPlacement);
        var selected = ProductionMailboxReplicaSelection.Select(f.Topology.NetworkId.Span, f.Topology.AuthorityGeneration,
            f.Topology.CurrentEpoch, selectionInputCommitment);
        var proofs = MembershipRouteDescriptorCodec.BuildProofs(f.CurrentDescriptors);
        var replicas = selected.Select(id =>
        {
            var index = Array.FindIndex(f.CurrentDescriptors, d => d.RouterId.Span.SequenceEqual(id.Span));
            var descriptor = f.CurrentDescriptors[index];
            var mip = new MailboxReplicaMembershipProof
            {
                ReplicaId = descriptor.RouterId,
                SigningPublicKey = descriptor.Ed25519PublicKey,
                Epoch = descriptor.Epoch,
                MembershipCommitment = f.Topology.CurrentEpoch.MembershipCommitment,
                CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(descriptor, proofs[index])
            };
            return new ProductionMailboxSelectionReplica
            {
                ReplicaId = descriptor.RouterId,
                CanonicalMIP1Proof = MailboxPeerReplicationCodec.EncodeMembershipProof(mip)
            };
        }).ToArray();
        return ReSignSelection(new ProductionMailboxSelectionProof
        {
            Algorithm = ProductionMailboxSelectionAlgorithm.RendezvousSha256V1,
            NetworkId = f.Topology.NetworkId,
            AuthorityGeneration = f.Topology.AuthorityGeneration,
            CanonicalAuthorityHash = f.Topology.CanonicalAuthorityHash,
            TopologyGeneration = f.Topology.TopologyGeneration,
            CanonicalTopologyHash = topology.CanonicalTopologyHash,
            Epoch = f.Topology.CurrentEpoch.Epoch,
            Generation = f.Topology.CurrentEpoch.Generation,
            MembershipCommitment = f.Topology.CurrentEpoch.MembershipCommitment,
            TopologyPlacementCommitment = f.Topology.CurrentEpoch.TopologyPlacementCommitment,
            MailboxPlacementCommitment = mailboxPlacementCommitment,
            SelectionInputCommitment = selectionInputCommitment,
            IssuedAtUnixSeconds = Now - 5,
            ExpiresAtUnixSeconds = Now + 50,
            Replicas = replicas,
            IssuerSignature = new byte[64]
        }, f.IssuerPrivateKey);
    }

    private static MailboxAuthenticatedGrant SignGrant(
        Fixture f,
        byte[] mailboxPlacementCommitment,
        byte[] holderPublicKey,
        byte serialSeed)
    {
        var epoch = f.Topology.CurrentEpoch;
        return new SodiumMailboxCapabilityCrypto().SignGrant(new MailboxAuthenticatedGrant
        {
            Domain = MailboxCapabilityDomain.Retrieve,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            NetworkId = f.Topology.NetworkId,
            Epoch = epoch.Epoch,
            Generation = epoch.Generation,
            Serial = Bytes(serialSeed, MailboxAuthenticatedCapabilityLimits.SerialLength),
            NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
            ExpiresAtUnixSeconds = epoch.NotAfterUnixSeconds,
            OverlapUntilUnixSeconds = 0,
            PlacementCommitment = mailboxPlacementCommitment,
            MembershipCommitment = epoch.MembershipCommitment,
            IssuerPublicKey = f.Authority.Authority.MailboxIssuerEd25519PublicKey,
            HolderPublicKey = holderPublicKey,
            IssuerSignature = new byte[MailboxAuthenticatedCapabilityLimits.SignatureLength]
        }, f.IssuerPrivateKey);
    }

    private static MembershipRouteDescriptor[] Descriptors(ulong epoch, ulong from, ulong until) => [Descriptor(0x10, epoch, from, until), Descriptor(0x40, epoch, from, until), Descriptor(0x70, epoch, from, until)];
    private static MembershipRouteDescriptor Descriptor(int start, ulong epoch, ulong from, ulong until) => new()
    {
        RouterId = Range(start, 32),
        Ed25519PublicKey = Range(start + 32, 32),
        X25519PublicKey = Range(start + 64, 32),
        RpcEndpoint = $"https://route-{start}.example.net/",
        Roles = MembershipRouteRole.Storage,
        Capabilities = MembershipRouteCapability.Storage,
        Epoch = epoch,
        ValidFromUnixSeconds = from,
        ValidUntilUnixSeconds = until
    };
    private static ProductionMailboxTopologyEpoch TopologyEpoch(ProductionMailboxAuthorityEpoch epoch, MembershipRouteDescriptor[] descriptors) => new()
    {
        Epoch = epoch.Epoch,
        Generation = epoch.Generation,
        MembershipCommitment = epoch.MembershipCommitment,
        TopologyPlacementCommitment = epoch.TopologyPlacementCommitment,
        NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
        NotAfterUnixSeconds = epoch.NotAfterUnixSeconds,
        Nodes = descriptors.Select((d, i) => new ProductionMailboxTopologyNode
        {
            NodeId = d.RouterId,
            HttpsEndpoint = $"https://node-{i + 1}.example.net/",
            CurrentSpkiSha256 = Bytes((byte)(100 + i * 2), 32),
            NextSpkiSha256 = Bytes((byte)(101 + i * 2), 32)
        }).ToArray()
    };
    private static ProductionMailboxAuthorityEpoch AuthorityEpoch(ulong epoch, ulong generation, byte[] membership, byte[] placement, ulong from, ulong until) =>
        new() { Epoch = epoch, Generation = generation, MembershipCommitment = membership, TopologyPlacementCommitment = placement, NotBeforeUnixSeconds = from, NotAfterUnixSeconds = until };
    private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new() { Uri = uri, CurrentSpkiSha256 = Bytes(seed, 32), NextSpkiSha256 = Bytes((byte)(seed + 1), 32) };
    private static ProductionMailboxAuthority SignAuthority(ProductionMailboxAuthority value, byte[] key)
    {
        var bound = value with { MrXApproval = value.MrXApproval with { AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(value) }, Signature = new byte[64] };
        return bound with { Signature = PublicKeyAuth.SignDetached(ProductionMailboxAuthorityCodec.GetSigningBytes(bound), key) };
    }
    private static ProductionMailboxTopologySnapshot ReSignTopology(ProductionMailboxTopologySnapshot value, byte[] key)
    {
        var unsigned = value with { IssuerSignature = new byte[64] };
        return unsigned with { IssuerSignature = PublicKeyAuth.SignDetached(ProductionMailboxTopologyCodec.GetSigningBytes(unsigned), key) };
    }
    private static ProductionMailboxSelectionProof ReSignSelection(ProductionMailboxSelectionProof value, byte[] key)
    {
        var unsigned = value with { IssuerSignature = new byte[64] };
        return unsigned with { IssuerSignature = PublicKeyAuth.SignDetached(ProductionMailboxTopologyCodec.GetSelectionSigningBytes(unsigned), key) };
    }
    private static byte[] Bytes(byte seed, int length) => Enumerable.Range(0, length).Select(i => unchecked((byte)(seed + i))).ToArray();
    private static byte[] Range(int start, int length) => Enumerable.Range(start, length).Select(i => unchecked((byte)i)).ToArray();
    private static byte[] Writable(ReadOnlyMemory<byte> value)
    {
        Assert.True(MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment));
        return segment.Array!;
    }
    private sealed class MutatingVerifier(Action mutate) : IProductionMailboxTopologySignatureVerifier
    {
        private readonly SodiumProductionMailboxTopologySignatureVerifier _inner = new();
        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature)
        { mutate(); return _inner.Verify(publicKey, signingBytes, signature); }
    }
    private sealed record Fixture(VerifiedProductionMailboxAuthority Authority, ProductionMailboxTopologySnapshot Topology,
        byte[] IssuerPrivateKey, MembershipRouteDescriptor[] CurrentDescriptors, BlindedPlacementId PlacementId,
        byte[] SelectionInputCommitment,
        byte[] MailboxPlacementCommitment,
        ProductionMailboxTopologyVerificationContext Context, IProductionMailboxTopologySignatureVerifier SignatureVerifier);
}
