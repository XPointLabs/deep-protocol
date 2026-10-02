using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Tests.Identity;
using Sodium;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed partial class AccountDirectoryFreshnessVerificationTests
{
    [Fact]
    public void Did2RendezvousIssuerSurfaceIsClosedAndDoesNotGrantRouteOrAck()
    {
        Assert.Empty(typeof(VerifiedDeepIdV2ContactUpdateRendezvous).GetConstructors());
        Assert.False(DeepIdV2ContactUpdateRendezvousVerifier.RuntimeActivation);
        Assert.DoesNotContain(typeof(VerifiedDeepIdV2ContactUpdateRendezvous).GetMethods(),
            method => method.Name is "Acknowledge" or "Publish" or "Dispatch" or "BindForInitialSession");
    }

    [Fact]
    public async Task Did2RendezvousIssuer_ExactCurrentProofRejectsScopeTimeAndClockSubstitution()
    {
        // Real PQ DID2/checkpoint and threshold nonce proof, not device E2E.
        var freshness = await RendezvousCurrentProof();
        var checkpoint = freshness.CurrentCheckpoint!;
        var device = Assert.Single(checkpoint.Directory.Identity.ActiveDevices).Certificate;
        var seed = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();
        var key = PublicKeyAuth.GenerateKeyPair(seed);
        try
        {
            Assert.Equal(device.DeviceEd25519PublicKey.ToArray(), key.PublicKey);
            var fields = new ReadOnlyMemory<byte>[]
            {
                freshness.NetworkId, Bytes(32, 0x81), Bytes(32, 0x82), RendezvousU64(0), new byte[32],
                new ContactArtifactReference(ProtocolMagic.PMT2, 1, Bytes(32, 0x83)).CanonicalBytes,
                Bytes(32, 0x84), Bytes(32, 0x85), Bytes(32, 0x86), new byte[] { 0, 7 },
                RendezvousU64(freshness.TrustedLowerUnixSeconds - 1),
                RendezvousU64(freshness.TrustedUpperUnixSeconds + 30), device.DeviceId,
                new ContactArtifactReference(ProtocolMagic.DPD1, 1, device.CanonicalHash.Span).CanonicalBytes,
                Bytes(64, 0x87)
            };
            byte[] Exact(ReadOnlyMemory<byte>[] values, bool damage = false)
            {
                var provisional = ContactCodec.AuthorForValidation(ProtocolMagic.XUR1, values);
                var signed = values.ToArray();
                var signature = PublicKeyAuth.SignDetached(provisional.SignatureInput.ToArray(), key.PrivateKey);
                if (damage) signature[0] ^= 1;
                signed[14] = signature;
                return ContactCodec.AuthorForValidation(ProtocolMagic.XUR1, signed).CanonicalBytes.ToArray();
            }
            ValueTask<VerifiedDeepIdV2ContactUpdateRendezvous> Verify(byte[] exact,
                RendezvousClock? clock = null, CancellationToken ct = default) =>
                DeepIdV2ContactUpdateRendezvousVerifier.VerifyAsync(exact, freshness,
                    new OnionTrustedTimeAuthority(clock ?? new RendezvousClock()), ct);
            var valid = Exact(fields);
            var result = await Verify(valid);
            Assert.Equal(valid, result.ExactXur1.ToArray());
            Assert.Same(freshness, result.Freshness);
            var callerOwned = valid.ToArray();
            var copied = await Verify(callerOwned, new RendezvousClock(onRead: () => callerOwned[^1] ^= 1));
            Assert.Equal(valid, copied.ExactXur1.ToArray());
            foreach (var change in new[] { 0, 5, 9, 10, 11, 12, 13 })
            {
                var altered = fields.ToArray();
                altered[change] = change switch
                {
                    0 => Bytes(16, 0x91),
                    5 => new ContactArtifactReference(ProtocolMagic.PMT2, 1, Bytes(32, 0x92)).CanonicalBytes,
                    9 => new byte[] { 0, 1 },
                    10 => RendezvousU64(freshness.TrustedLowerUnixSeconds + 1),
                    11 => RendezvousU64(freshness.TrustedUpperUnixSeconds),
                    12 => Bytes(32, 0x93),
                    _ => new ContactArtifactReference(ProtocolMagic.DPD1, 1, Bytes(32, 0x94)).CanonicalBytes
                };
                if (change == 5)
                {
                    // Issuer verification deliberately grants no PMT2/route
                    // authority: independently verify it before transport use.
                    Assert.NotNull(await Verify(Exact(altered)));
                }
                else await Assert.ThrowsAnyAsync<CryptographicException>(async () => await Verify(Exact(altered)));
            }
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await Verify(Exact(fields, damage: true)));
            var successor = fields.ToArray(); successor[3] = RendezvousU64(1); successor[4] = Bytes(32, 0x95);
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await Verify(Exact(successor)));
            foreach (var clock in new[]
            {
                new RendezvousClock(first: 1004, final: 1003),
                new RendezvousClock(finalBoot: Bytes(16, 0x96)),
                new RendezvousClock(final: freshness.FreshnessDeadlineMonotonicSeconds),
                new RendezvousClock(first: 999, final: 1003)
            }) await Assert.ThrowsAnyAsync<CryptographicException>(async () => await Verify(valid, clock));
            using var cancellation = new CancellationTokenSource();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await Verify(valid,
                new RendezvousClock(onRead: cancellation.Cancel), cancellation.Token));
            await Assert.ThrowsAsync<ArgumentException>(async () => await Verify(valid[..^1]));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(key.PrivateKey);
        }
    }

    private static async Task<VerifiedDeepIdV2DirectoryFreshness> RendezvousCurrentProof(
        byte[]? network = null, string? mnemonic = null)
    {
        var (_, checkpoint, binding) = await Dnp1IdentityAuthoringV1Tests.CreateRealDid2DirectoryGenesisAsync(
            networkOverride: network, mnemonicOverride: mnemonic);
        var authority = AuthorityFixture.Create(networkOverride: checkpoint.Checkpoint.NetworkId.ToArray(), timeBase: 1_900_000_000);
        var empty = authority.Head(0, new byte[32], 0, AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray(), minimumReader: 2);
        var floor = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(empty));
        var leaf = checkpoint.Checkpoint.DirectoryLeafKey.ToArray();
        var map = new Dictionary<string, byte[]> { [Convert.ToHexString(leaf)] = checkpoint.Checkpoint.ArtifactReference.ToArray() };
        var root = DeepIdV2DirectorySparseMap.ComputeFullMapRoot(map);
        var transition = DeepIdV2DirectoryTransitionCodec.Author(0, leaf, new byte[38],
            checkpoint.Checkpoint.ArtifactReference.Span, DeepIdV2DirectorySparseMap.EmptyMapRoot.Span, root);
        ReadOnlyMemory<byte>[] journal = [transition.CanonicalBytes];
        var head = authority.Head(1, floor.CoreHash.ToArray(), 1, DeepIdV2DirectoryJournal.ComputeAppendRoot(journal), root, minimumReader: 2);
        var exactHead = AccountDirectoryAdh1Codec.Encode(head); var nonce = Bytes(32, 0x31);
        var material = DeepIdV2DirectoryProofMaterialAuthor.Create(new AccountDirectoryProtectedLkg(exactHead), journal, [checkpoint], leaf, floor);
        var request = new AccountDirectoryProofAuthoringRequest(authority.Network, nonce, Bytes(16, 0x44), 1000,
            exactHead, authority.CurrentXnv(), 1_900_000_300, 5, 1_900_000_300, 1_900_000_360,
            AccountDirectoryDtt1IssuanceEpoch.Derive(authority.Verified, 1_900_000_300, 5), 2);
        using var pq = DeepMlDsa65NativeProvider.LoadCandidateForCurrentProcess();
        var proof = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(authority.Verified, request, material,
            authority.Witnesses.Take(2).Select(WitnessSigner.Valid).Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray(), 1, pq);
        var adl = DeepIdV2AccountDirectoryLookupCodec.Author(binding.DeepId, authority.Network, floor.LogGeneration,
            floor.CoreHash.Span, 1, new byte[38], new byte[32]);
        return DeepIdV2DirectoryCurrentProofVerifier.VerifyGenesis(authority.Verified, proof.ExactAdh1, proof.ExactDtt1,
            proof.ExactAdp1V2, nonce, VerifiedDeepIdV2DirectoryQuery.VerifyBinding(adl, binding), Window(), floor, 1, 2, pq);
    }

    private static byte[] RendezvousU64(ulong value)
    {
        var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes;
    }
    private sealed class RendezvousClock(ulong first = 1003, ulong final = 1003,
        byte[]? finalBoot = null, Action? onRead = null) : IOnionMonotonicClock
    {
        private int reads;
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var last = reads++ != 0; onRead?.Invoke();
            return ValueTask.FromResult(new OnionMonotonicReading(last ? finalBoot ?? Bytes(16, 0x44) : Bytes(16, 0x44), last ? final : first));
        }
    }
}
