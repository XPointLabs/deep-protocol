using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Tests.MessagingWire;
using Deep.Protocol.Tests.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed partial class ManagedTripleRatchetNativeOwnershipTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task NativeBraidRecovery_BothSendersExhaustedResumeFreshDataWithoutLosingPending(bool deliverHeaderFirst)
    {
        using var pair = new RecoveryPair();
        var pending = new List<(bool Alice, byte Id, byte[] Cipher)>();
        try
        {
            for (byte id = 1; id <= 32; id++) pending.Add((true, id, await pair.Alice.Send(RecoveryMessage(true, id))));
            if (deliverHeaderFirst) await Verify(pair.Bob, pending[0].Cipher, RecoveryMessage(true, 1));
            for (byte id = 80; id < 112; id++) pending.Add((false, id, await pair.Bob.Send(RecoveryMessage(false, id))));
            await RequirePqBlocked(pair.Alice, true); await RequirePqBlocked(pair.Bob, false);
            var hashes = pending.Select(entry => SHA256.HashData(entry.Cipher)).ToArray();

            var header = pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 200));
            Assert.Equal(Dtr2BraidMessageKind.Header, Dbr2Codec.Decode(header).BraidMessage.Kind);
            Assert.False(pair.Bob.ReceiveControl(pair.BobProvider, header));
            var ct1 = pair.Bob.SendControl(pair.BobProvider, Bytes(32, 201));
            Assert.False(pair.Alice.ReceiveControl(pair.AliceProvider, ct1));
            await RequirePqBlocked(pair.Alice, true); // Ct1 is not fresh KEM output.
            var ek = pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 202));
            Assert.False(pair.Bob.ReceiveControl(pair.BobProvider, ek));
            var ct2 = pair.Bob.SendControl(pair.BobProvider, Bytes(32, 203));
            Assert.False(pair.Alice.ReceiveControl(pair.AliceProvider, ct2));
            Assert.Equal((byte)2, Dbr2Codec.Decode(ek).ControlCounter);
            Assert.Equal((byte)2, Dbr2Codec.Decode(ct2).ControlCounter);
            Assert.Equal(32, pair.Alice.SendMessagesSincePqInjection);
            Assert.Equal(32, pair.Bob.SendMessagesSincePqInjection); // Controls never reset data freshness.

            foreach (var (memory, provider, control) in new[] {
                         (pair.Bob, pair.BobProvider, header), (pair.Alice, pair.AliceProvider, ct1),
                         (pair.Bob, pair.BobProvider, ek), (pair.Alice, pair.AliceProvider, ct2) })
            {
                var before = memory.CommittedDigest();
                Assert.True(memory.ReceiveControl(provider, control));
                Assert.Equal(before, memory.CommittedDigest()); // Old original-link MAC still verifies after fresh root.
            }
            await ResumeBidirectionalFreshData(pair);
            for (var index = 0; index < pending.Count; index++)
            {
                var entry = pending[index];
                Assert.Equal(hashes[index], SHA256.HashData(entry.Cipher));
                if (deliverHeaderFirst && index == 0)
                {
                    using var replay = await pair.Bob.Receive(entry.Cipher);
                    Assert.Equal(ExactDpe2ReceiveSuccessOutcome.ExactReplay, replay.Outcome);
                    Assert.False(replay.HasAuthenticatedDmc2);
                }
                else await Verify(entry.Alice ? pair.Bob : pair.Alice, entry.Cipher, RecoveryMessage(entry.Alice, entry.Id));
            }
        }
        finally { foreach (var entry in pending) CryptographicOperations.ZeroMemory(entry.Cipher); }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task NativeBraidRecovery_DataAlreadyCarriedHeaderAndCt1NeedsOnlySecondSlots()
    {
        using var pair = new RecoveryPair();
        var first = await pair.Alice.Send(RecoveryMessage(true, 1));
        try { await Verify(pair.Bob, first, RecoveryMessage(true, 1)); }
        finally { CryptographicOperations.ZeroMemory(first); }
        for (byte id = 2; id <= 32; id++) CryptographicOperations.ZeroMemory(await pair.Alice.Send(RecoveryMessage(true, id)));
        var reply = await pair.Bob.Send(RecoveryMessage(false, 80));
        try { await Verify(pair.Alice, reply, RecoveryMessage(false, 80)); }
        finally { CryptographicOperations.ZeroMemory(reply); }
        for (byte id = 81; id < 112; id++) CryptographicOperations.ZeroMemory(await pair.Bob.Send(RecoveryMessage(false, id)));
        await RequirePqBlocked(pair.Alice, true); await RequirePqBlocked(pair.Bob, false);
        var ek = pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 202));
        Assert.Equal((byte)2, Dbr2Codec.Decode(ek).ControlCounter);
        Assert.False(pair.Bob.ReceiveControl(pair.BobProvider, ek));
        var ct2 = pair.Bob.SendControl(pair.BobProvider, Bytes(32, 203));
        Assert.Equal((byte)2, Dbr2Codec.Decode(ct2).ControlCounter);
        Assert.False(pair.Alice.ReceiveControl(pair.AliceProvider, ct2));
        await ResumeBidirectionalFreshData(pair);
    }

    [Theory]
    [InlineData("network")]
    [InlineData("session")]
    [InlineData("sender")]
    [InlineData("recipient")]
    [InlineData("slot")]
    [InlineData("mac")]
    [InlineData("header-seed")]
    [InlineData("header-hmac")]
    [InlineData("reflection")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public void NativeBraidRecovery_ChangedScopeOrAuthenticatorsRejectWithoutCommitting(string fault)
    {
        using var pair = new RecoveryPair();
        var original = pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 200));
        var altered = original.ToArray();
        var tag = fault switch { "network" => 1, "session" => 2, "sender" => 3, "recipient" => 4, "slot" => 7,
            "mac" => 11, _ => 9 };
        if (fault == "reflection")
        {
            var sender = altered.AsSpan(FieldOffset(altered, 3), 32).ToArray();
            altered.AsSpan(FieldOffset(altered, 4), 32).CopyTo(altered.AsSpan(FieldOffset(altered, 3), 32));
            sender.CopyTo(altered, FieldOffset(altered, 4));
        }
        else
        {
            var offset = FieldOffset(altered, tag) + (fault == "header-hmac" ? 95 : 0);
            altered[offset] ^= fault == "slot" ? (byte)3 : (byte)0x20;
        }
        if (fault != "mac") pair.Alice.ResignControl(altered); // Valid outer MAC cannot replace scope or native Header proof.
        var before = pair.Bob.CommittedDigest();
        Assert.ThrowsAny<CryptographicException>(() => pair.Bob.ReceiveControl(pair.BobProvider, altered));
        Assert.Equal(before, pair.Bob.CommittedDigest());
        Assert.False(pair.Bob.ReceiveControl(pair.BobProvider, original));
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public void NativeBraidRecovery_ReauthorOccupiedSlotAndChangedValidMacReplayReject()
    {
        using var pair = new RecoveryPair();
        var header = pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 200));
        var senderBefore = pair.Alice.CommittedDigest();
        Assert.ThrowsAny<CryptographicException>(() => pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 210)));
        Assert.Equal(senderBefore, pair.Alice.CommittedDigest());
        Assert.False(pair.Bob.ReceiveControl(pair.BobProvider, header));
        var changed = header.ToArray(); changed[FieldOffset(changed, 5)] ^= 1; pair.Alice.ResignControl(changed);
        var receiverBefore = pair.Bob.CommittedDigest();
        Assert.ThrowsAny<CryptographicException>(() => pair.Bob.ReceiveControl(pair.BobProvider, changed));
        Assert.Equal(receiverBefore, pair.Bob.CommittedDigest());
        Assert.True(pair.Bob.ReceiveControl(pair.BobProvider, header));
        Assert.Equal(receiverBefore, pair.Bob.CommittedDigest());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public void NativeBraidRecovery_DuplicateOperationAcrossDifferentFlightsRejects()
    {
        using var pair = new RecoveryPair();
        var header = pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 200));
        pair.Bob.ReceiveControl(pair.BobProvider, header);
        pair.Alice.ReceiveControl(pair.AliceProvider, pair.Bob.SendControl(pair.BobProvider, Bytes(32, 201)));
        var ek = pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 202));
        var changed = ek.ToArray(); Bytes(32, 200).CopyTo(changed, FieldOffset(changed, 5)); pair.Alice.ResignControl(changed);
        var before = pair.Bob.CommittedDigest();
        Assert.ThrowsAny<CryptographicException>(() => pair.Bob.ReceiveControl(pair.BobProvider, changed));
        Assert.Equal(before, pair.Bob.CommittedDigest());
        Assert.False(pair.Bob.ReceiveControl(pair.BobProvider, ek));
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public void NativeBraidRecovery_ValidOuterMacCannotAuthorizeWrongFlightOrInvalidNativeCt2()
    {
        using var pair = new RecoveryPair();
        var wrong = ManagedBraidControlProfile.CreateUnsigned(Binding(true), Bytes(16, 5), Bytes(32, 220), 1, 1,
            Dtr2BraidMessage.Ciphertext1(Bytes(960, 7)));
        var exactWrong = Dbr2Codec.Encode(wrong); pair.Alice.ResignControl(exactWrong);
        var firstBefore = pair.Bob.CommittedDigest();
        Assert.ThrowsAny<CryptographicException>(() => pair.Bob.ReceiveControl(pair.BobProvider, exactWrong));
        Assert.Equal(firstBefore, pair.Bob.CommittedDigest());
        pair.Bob.ReceiveControl(pair.BobProvider, pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 200)));
        pair.Alice.ReceiveControl(pair.AliceProvider, pair.Bob.SendControl(pair.BobProvider, Bytes(32, 201)));
        pair.Bob.ReceiveControl(pair.BobProvider, pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 202)));
        var ct2 = pair.Bob.SendControl(pair.BobProvider, Bytes(32, 203));
        var altered = ct2.ToArray(); altered[FieldOffset(altered, 9) + 159] ^= 1; pair.Bob.ResignControl(altered);
        var before = pair.Alice.CommittedDigest();
        Assert.ThrowsAny<CryptographicException>(() => pair.Alice.ReceiveControl(pair.AliceProvider, altered));
        Assert.Equal(before, pair.Alice.CommittedDigest());
        Assert.False(pair.Alice.ReceiveControl(pair.AliceProvider, ct2));
    }

    [Theory]
    [InlineData("old-generation")]
    [InlineData("zero-control-root")]
    [InlineData("unknown-mask")]
    [InlineData("reserved")]
    [InlineData("absent-operation")]
    [InlineData("missing-operation")]
    [InlineData("missing-hash")]
    [InlineData("duplicate-operations")]
    [InlineData("unused-link")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public void NativeBraidRecovery_PrivateCleanBreakRejectsMalformedControlCustody(string fault)
    {
        using var pair = new RecoveryPair();
        using var current = pair.Bob.ReadCurrentState();
        var malformed = Component(current);
        try
        {
            switch (fault)
            {
                case "old-generation": malformed[4] = 1; break;
                case "zero-control-root": malformed.AsSpan(496, 32).Clear(); break;
                case "unknown-mask": malformed[528] = 4; break;
                case "reserved": malformed[530] = 1; break;
                case "absent-operation": malformed[536] = 1; break;
                case "missing-operation": malformed[528] = 1; break;
                case "missing-hash": malformed[529] = 1; malformed.AsSpan(600, 32).Fill(1); break;
                case "duplicate-operations": malformed[528] = 3; malformed.AsSpan(536, 64).Fill(1); break;
                case "unused-link": malformed[728] = 1; break;
            }
            var before = pair.Bob.CommittedDigest();
            Assert.ThrowsAny<CryptographicException>(() => pair.BobProvider.PrepareBraidControlSend(
                malformed, Binding(false), Bytes(16, 5), Bytes(32, 230)));
            Assert.Equal(before, pair.Bob.CommittedDigest());
        }
        finally { CryptographicOperations.ZeroMemory(malformed); }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public void NativeBraidRecovery_UncommittedCandidateIsDisposableAndSingleUse()
    {
        using var pair = new RecoveryPair();
        var before = pair.Alice.CommittedDigest();
        using (var current = pair.Alice.ReadCurrentState())
        using (var candidate = current.PrepareBraidRecoverySend(pair.AliceProvider, Bytes(16, 5), Bytes(32, 200)))
        using (var next = candidate.TakeNextState())
        {
            Assert.Throws<MessagingCryptoException>(() => candidate.TakeNextState());
            Assert.Equal(current.StorageGeneration + 1, next.StorageGeneration);
        }
        Assert.Equal(before, pair.Alice.CommittedDigest());
        var original = pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 200));
        var receiverBefore = pair.Bob.CommittedDigest();
        using (var current = pair.Bob.ReadCurrentState())
        using (var candidate = current.PrepareBraidRecoveryReceive(pair.BobProvider, Bytes(16, 5), original))
            Assert.False(candidate.IsExactReplay);
        Assert.Equal(receiverBefore, pair.Bob.CommittedDigest());
        Assert.False(pair.Bob.ReceiveControl(pair.BobProvider, original));
        using var replayState = pair.Bob.ReadCurrentState();
        using var replay = replayState.PrepareBraidRecoveryReceive(pair.BobProvider, Bytes(16, 5), original);
        Assert.True(replay.IsExactReplay);
        Assert.Throws<MessagingCryptoException>(() => replay.TakeNextState());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public void BraidControlNativeRegistryMatchesActualPrivateProducerLayout()
    {
        using var pair = new RecoveryPair();
        using var registry = JsonDocument.Parse(File.ReadAllBytes(XPointNetworkFrozenVectorManifest.FindSpec("braid-recovery-v2.native.registry.json")));
        var root = registry.RootElement; var layout = root.GetProperty("privateState");
        Assert.False(root.GetProperty("productionActive").GetBoolean());
        Assert.Equal(2, layout.GetProperty("linkCountMaximum").GetInt32());
        using var current = pair.Alice.ReadCurrentState(); var component = Component(current);
        byte[]? derived = null;
        try
        {
            Assert.Equal("TRC1"u8.ToArray(), component[..4]);
            Assert.Equal(layout.GetProperty("generation").GetInt32(), component[4]);
            var prefix = layout.GetProperty("prefixBytes").GetInt32();
            var lengthOffset = layout.GetProperty("braidLengthOffset").GetInt32();
            Assert.Equal(component.Length - prefix, checked((int)BinaryPrimitives.ReadUInt32BigEndian(component.AsSpan(lengthOffset, 4))));
            Assert.Equal("MBM1"u8.ToArray(), component.AsSpan(prefix, 4).ToArray());
            var link = layout.GetProperty("linkOffset").GetInt32();
            var linkBytes = layout.GetProperty("linkBytes").GetInt32();
            Assert.Equal(1, component[392]);
            Assert.True(component.AsSpan(link + linkBytes, linkBytes).IndexOfAnyExcept((byte)0) < 0);
            derived = ManagedBraidControlProfile.DeriveRoot(component.AsSpan(328, 32), 0);
            Assert.Equal(derived, component.AsSpan(link + 96, 32).ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(component); if (derived is not null) CryptographicOperations.ZeroMemory(derived); }
    }

    public static IEnumerable<object[]> BraidControlKdfCases()
    {
        using var vectors = JsonDocument.Parse(File.ReadAllBytes(XPointNetworkFrozenVectorManifest.FindSpec("braid-recovery-v2.native.vectors.json")));
        foreach (var row in vectors.RootElement.GetProperty("vectors").EnumerateArray())
            yield return [row.GetProperty("name").GetString()!, row.GetProperty("linkEpoch").GetUInt64(),
                row.GetProperty("spqrRootHex").GetString()!, row.GetProperty("controlRootHex").GetString()!,
                row.GetProperty("authenticatorHex").GetString()!];
    }

    [Theory]
    [MemberData(nameof(BraidControlKdfCases))]
    public void BraidControlKdf_MatchesIndependentNodeWitness(string name, ulong epoch, string spqrHex, string rootHex, string macHex)
    {
        Assert.False(string.IsNullOrWhiteSpace(name));
        var spqr = Convert.FromHexString(spqrHex); var root = ManagedBraidControlProfile.DeriveRoot(spqr, epoch);
        try
        {
            Assert.Equal(Convert.FromHexString(rootHex), root);
            using var structural = JsonDocument.Parse(File.ReadAllBytes(XPointNetworkFrozenVectorManifest.FindSpec("braid-recovery-v2.vectors.json")));
            var frame = Convert.FromHexString(structural.RootElement.GetProperty("positive")[0].GetProperty("encodedHex").GetString()!);
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(FieldOffset(frame, 6), 8), epoch + 1);
            var mac = ManagedBraidControlProfile.ComputeAuthenticator(root, Dbr2Codec.Decode(frame));
            try { Assert.Equal(Convert.FromHexString(macHex), mac); }
            finally { CryptographicOperations.ZeroMemory(mac); }
        }
        finally { CryptographicOperations.ZeroMemory(spqr); CryptographicOperations.ZeroMemory(root); }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task NativeBraidRecovery_SecondOutputPreservesPinnedFrontierAndOldSkippedData()
    {
        using var pair = new RecoveryPair();
        var oldAlice = await pair.Alice.Send(RecoveryMessage(true, 1));
        var oldBob = await pair.Bob.Send(RecoveryMessage(false, 80));
        try
        {
            pair.Bob.ReceiveControl(pair.BobProvider, pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 200)));
            pair.Alice.ReceiveControl(pair.AliceProvider, pair.Bob.SendControl(pair.BobProvider, Bytes(32, 201)));
            pair.Bob.ReceiveControl(pair.BobProvider, pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 202)));
            pair.Alice.ReceiveControl(pair.AliceProvider, pair.Bob.SendControl(pair.BobProvider, Bytes(32, 203)));

            var freshAlice = await pair.Alice.Send(RecoveryMessage(true, 120));
            try { await Verify(pair.Bob, freshAlice, RecoveryMessage(true, 120)); }
            finally { CryptographicOperations.ZeroMemory(freshAlice); }
            // Alice's send frontier is1, but her receive frontier is still0.
            pair.Alice.ReceiveControl(pair.AliceProvider, pair.Bob.SendControl(pair.BobProvider, Bytes(32, 204)));
            pair.Bob.ReceiveControl(pair.BobProvider, pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 205)));
            var ek = pair.Bob.SendControl(pair.BobProvider, Bytes(32, 206));
            var before = pair.Alice.CommittedDigest();
            for (var retry = 0; retry < 2; retry++)
            {
                var error = Assert.Throws<MessagingCryptoException>(() => pair.Alice.ReceiveControl(pair.AliceProvider, ek));
                Assert.Equal(MessagingCryptoError.TransitionRejected, error.Error);
                Assert.Equal("A fresh SPQR link cannot retire a still-current data frontier.", error.Message);
                Assert.Equal(before, pair.Alice.CommittedDigest());
            }

            // Actual data carries the same EK. It must derive epoch0 skipped
            // keys and the epoch1 receive key BEFORE retiring link0 for link2.
            var freshBob = await pair.Bob.Send(RecoveryMessage(false, 121));
            try { await Verify(pair.Alice, freshBob, RecoveryMessage(false, 121)); }
            finally { CryptographicOperations.ZeroMemory(freshBob); }
            pair.Bob.ReceiveControl(pair.BobProvider, pair.Alice.SendControl(pair.AliceProvider, Bytes(32, 207)));
            foreach (var alice in new[] { false, true })
            {
                var message = RecoveryMessage(alice, alice ? (byte)122 : (byte)123);
                var cipher = await (alice ? pair.Alice : pair.Bob).Send(message);
                try
                {
                    Assert.Equal(2UL, Dpe2Codec.Decode(cipher).RatchetHeader.SckaSendingEpoch);
                    await Verify(alice ? pair.Bob : pair.Alice, cipher, message);
                }
                finally { CryptographicOperations.ZeroMemory(cipher); }
            }
            await Verify(pair.Bob, oldAlice, RecoveryMessage(true, 1));
            await Verify(pair.Alice, oldBob, RecoveryMessage(false, 80));
            // Receiving EK as data is not proof that its earlier DBR2 operation
            // was received. Unknown control settlement remains a separate owner.
        }
        finally { CryptographicOperations.ZeroMemory(oldAlice); CryptographicOperations.ZeroMemory(oldBob); }
    }

    private static ParsedDmc2 RecoveryMessage(bool alice, byte id) => ApplicationCoreCodec.AuthorDmc2(Bytes(16, 5),
        Bytes(32, id), Bytes(32, 25), Bytes(32, alice ? (byte)22 : (byte)23), Bytes(32, alice ? (byte)8 : (byte)9),
        id, 1_100_000UL + id, 0, Dmc2Flags.None, [], ApplicationCoreCodec.CreateMessageCreatePayload($"native recovery fixture {id}"));

    private static async Task RequirePqBlocked(IsolatedAtomicMemory memory, bool alice)
    {
        var before = memory.CommittedDigest();
        var error = await Assert.ThrowsAsync<MessagingCryptoException>(() => memory.Send(RecoveryMessage(alice, 120)));
        Assert.Equal(MessagingCryptoError.PqInjectionRequired, error.Error);
        Assert.Equal(before, memory.CommittedDigest());
    }

    private static async Task ResumeBidirectionalFreshData(RecoveryPair pair)
    {
        foreach (var alice in new[] { true, false })
        {
            var message = RecoveryMessage(alice, alice ? (byte)120 : (byte)121);
            var cipher = await (alice ? pair.Alice : pair.Bob).Send(message);
            try
            {
                Assert.Equal(1UL, Dpe2Codec.Decode(cipher).RatchetHeader.SckaSendingEpoch);
                await Verify(alice ? pair.Bob : pair.Alice, cipher, message);
            }
            finally { CryptographicOperations.ZeroMemory(cipher); }
        }
        Assert.Equal(0, pair.Alice.SendMessagesSincePqInjection); Assert.Equal(0, pair.Bob.SendMessagesSincePqInjection);
    }

    private static int FieldOffset(byte[] frame, int target)
    {
        var offset = 12;
        for (var tag = 1; tag < target; tag++) offset += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(offset + 4, 4)));
        return offset + 8;
    }

    private sealed class RecoveryPair : IDisposable
    {
        internal ManagedTripleRatchetComponentProvider AliceProvider { get; }
        internal ManagedTripleRatchetComponentProvider BobProvider { get; private set; } = null!;
        internal IsolatedAtomicMemory Alice { get; private set; } = null!;
        internal IsolatedAtomicMemory Bob { get; private set; } = null!;
        internal RecoveryPair()
        {
            AliceProvider = ManagedTripleRatchetComponentProvider.CreateApproved(DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());
            var alicePrivate = Bytes(32, 3); var bobPrivate = Bytes(32, 4);
            try
            {
                BobProvider = ManagedTripleRatchetComponentProvider.CreateApproved(DeepMlKemBraidNativeProvider.LoadApprovedForCurrentProcess());
                using var ec = SecretBuffer.ImportExact(Bytes(32, 1), 32, "fixture EC root");
                using var pq = SecretBuffer.ImportExact(Bytes(32, 2), 32, "fixture PQ root");
                using var aSeed = VerifiedTripleRatchetSeedCapability.CreateFromVerifiedRoots(Binding(true), ec, pq);
                using var bSeed = VerifiedTripleRatchetSeedCapability.CreateFromVerifiedRoots(Binding(false), ec, pq);
                using var aState = AliceProvider.InitializeAlice(aSeed, alicePrivate, ScalarMult.Base(alicePrivate), ScalarMult.Base(bobPrivate), 1, 32);
                using var bState = BobProvider.InitializeBob(bSeed, bobPrivate, ScalarMult.Base(bobPrivate), ScalarMult.Base(alicePrivate), 1, 32);
                Alice = new(aState); Bob = new(bState);
            }
            catch { Dispose(); throw; }
            finally { CryptographicOperations.ZeroMemory(alicePrivate); CryptographicOperations.ZeroMemory(bobPrivate); }
        }
        public void Dispose() { Alice?.Dispose(); Bob?.Dispose(); AliceProvider.Dispose(); BobProvider?.Dispose(); }
    }

    private sealed partial class IsolatedAtomicMemory
    {
        internal TripleRatchetState ReadCurrentState() => TripleRatchetDurableStateCodec.Decode(state);
        internal int SendMessagesSincePqInjection { get { using var current = ReadCurrentState(); return current.SendMessagesSincePqInjection; } }
        internal byte[] SendControl(ManagedTripleRatchetComponentProvider provider, byte[] operation)
        {
            using var current = ReadCurrentState();
            using var candidate = current.PrepareBraidRecoverySend(provider, Bytes(16, 5), operation);
            var frame = Dbr2Codec.Encode(candidate.Control);
            CommitFixtureControl(current, candidate, frame); return frame;
        }
        internal bool ReceiveControl(ManagedTripleRatchetComponentProvider provider, byte[] frame)
        {
            using var current = ReadCurrentState();
            using var candidate = current.PrepareBraidRecoveryReceive(provider, Bytes(16, 5), frame);
            if (candidate.IsExactReplay) return true;
            CommitFixtureControl(current, candidate, frame); return false;
        }
        private void CommitFixtureControl(TripleRatchetState current, TripleRatchetBraidRecoveryCandidate candidate, byte[] frame)
        {
            // Component evidence only: this trusted in-memory fixture is NOT the production SQL/floor/ACK owner.
            using var next = candidate.TakeNextState();
            Assert.Equal(current.StorageGeneration + 1, next.StorageGeneration);
            Assert.Equal(current.SendEcChain, next.SendEcChain); Assert.Equal(current.NextSendEcN, next.NextSendEcN);
            Assert.Equal(current.ReceiveEcChain, next.ReceiveEcChain); Assert.Equal(current.NextExpectedReceiveEcN, next.NextExpectedReceiveEcN);
            Assert.Equal(current.SendPqFrontier, next.SendPqFrontier); Assert.Equal(current.ReceivePqFrontier, next.ReceivePqFrontier);
            Assert.Equal(current.SendMessagesSincePqInjection, next.SendMessagesSincePqInjection);
            Assert.Equal(current.ReceiveMessagesSincePqInjection, next.ReceiveMessagesSincePqInjection);
            Assert.Equal(current.SkippedKeyCount, next.SkippedKeyCount);
            var encoded = TripleRatchetDurableStateCodec.Encode(next);
            using var cold = TripleRatchetDurableStateCodec.Decode(encoded);
            Assert.Equal(next.StateCommitment.ToArray(), cold.StateCommitment.ToArray());
            CryptographicOperations.ZeroMemory(state); state = encoded;
            CryptographicOperations.ZeroMemory(journal); journal = SHA256.HashData(frame); journalGeneration++;
        }
        internal void ResignControl(byte[] frame)
        {
            using var current = ReadCurrentState(); var component = Component(current);
            try
            {
                // Explicit privileged negative fixture, never a public key export.
                var mac = ManagedBraidControlProfile.ComputeAuthenticator(component.AsSpan(496, 32), Dbr2Codec.Decode(frame));
                try { mac.CopyTo(frame, frame.Length - 32); }
                finally { CryptographicOperations.ZeroMemory(mac); }
            }
            finally { CryptographicOperations.ZeroMemory(component); }
        }
    }
}
