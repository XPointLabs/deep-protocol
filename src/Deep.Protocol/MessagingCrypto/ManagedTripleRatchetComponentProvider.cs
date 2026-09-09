using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.MessagingCrypto;

internal enum TripleRatchetPartyRole : byte
{
    Alice = 1,
    Bob = 2,
}

internal sealed class VerifiedTripleRatchetSeedCapability : IDisposable
{
    private readonly RatchetStateBinding _binding;
    private SecretBuffer? _ecRoot;
    private SecretBuffer? _spqrRoot;
    private int _consumed;

    private VerifiedTripleRatchetSeedCapability(
        RatchetStateBinding binding,
        ReadOnlySpan<byte> ecRoot,
        ReadOnlySpan<byte> spqrRoot)
    {
        _binding = binding;
        _ecRoot = SecretBuffer.ImportExact(ecRoot, 32, nameof(ecRoot));
        try { _spqrRoot = SecretBuffer.ImportExact(spqrRoot, 32, nameof(spqrRoot)); }
        catch { _ecRoot.Dispose(); throw; }
    }

    internal static VerifiedTripleRatchetSeedCapability FromVerifiedHandshake(
        HybridHandshakeSecrets handshake) =>
        (handshake ?? throw new ArgumentNullException(nameof(handshake)))
            .ClaimTripleRatchetSeed();

    internal static VerifiedTripleRatchetSeedCapability CreateFromVerifiedRoots(
        RatchetStateBinding binding,
        SecretBuffer ecRoot,
        SecretBuffer spqrRoot)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(ecRoot);
        ArgumentNullException.ThrowIfNull(spqrRoot);
        byte[]? ec = null;
        byte[]? spqr = null;
        try
        {
            ecRoot.Use(value => ec = value.ToArray());
            spqrRoot.Use(value => spqr = value.ToArray());
            return new VerifiedTripleRatchetSeedCapability(binding, ec, spqr);
        }
        finally
        {
            Zero(ec);
            Zero(spqr);
        }
    }

    internal VerifiedTripleRatchetSeedData Consume()
    {
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.CapabilityConsumed,
                "The verified Triple-Ratchet seed capability is single-use.");
        var ec = Interlocked.Exchange(ref _ecRoot, null) ?? throw Consumed();
        var spqr = Interlocked.Exchange(ref _spqrRoot, null) ?? throw Consumed();
        return new VerifiedTripleRatchetSeedData(_binding, ec, spqr);
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _ecRoot, null)?.Dispose();
        Interlocked.Exchange(ref _spqrRoot, null)?.Dispose();
        Interlocked.Exchange(ref _consumed, 1);
    }

    private static MessagingCryptoException Consumed() => new(
        MessagingCryptoError.CapabilityConsumed,
        "The verified Triple-Ratchet seed capability is unavailable.");

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}

internal sealed class VerifiedTripleRatchetSeedData(
    RatchetStateBinding binding,
    SecretBuffer ecRoot,
    SecretBuffer spqrRoot) : IDisposable
{
    internal RatchetStateBinding Binding { get; } = binding;
    internal SecretBuffer EcRoot { get; } = ecRoot;
    internal SecretBuffer SpqrRoot { get; } = spqrRoot;

    public void Dispose()
    {
        EcRoot.Dispose();
        SpqrRoot.Dispose();
    }
}

/// <summary>
/// Production-internal owner of the exact X25519 Double Ratchet, Deep SPQR
/// chains, and the pinned ML-KEM Braid state machine. Its opaque state is
/// plaintext only inside the caller-sealed TRS1 record.
/// </summary>
internal sealed class ManagedTripleRatchetComponentProvider :
    ITripleRatchetComponentProvider, IDisposable
{
    private readonly DeepMlKemBraidNativeProvider _braidProvider;
    private int _disposed;

    private ManagedTripleRatchetComponentProvider(DeepMlKemBraidNativeProvider braidProvider) =>
        _braidProvider = braidProvider ?? throw new ArgumentNullException(nameof(braidProvider));

    internal static ManagedTripleRatchetComponentProvider CreateApproved(
        DeepMlKemBraidNativeProvider approvedProvider) => new(approvedProvider);

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static ManagedTripleRatchetComponentProvider CreateWithCandidateForTests(
        DeepMlKemBraidNativeProvider braidProvider) => new(braidProvider);
#endif

    internal TripleRatchetState InitializeAlice(
        VerifiedTripleRatchetSeedCapability seedCapability,
        ReadOnlySpan<byte> initialRatchetPrivate,
        ReadOnlySpan<byte> initialRatchetPublic,
        ReadOnlySpan<byte> bobSignedPrekeyPublic,
        ulong storageGeneration,
        int maximumMessagesWithoutPqInjection)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(seedCapability);
        using var seed = seedCapability.Consume();
        using var state = ComponentState.CreateAlice(
            _braidProvider,
            seed,
            initialRatchetPrivate,
            initialRatchetPublic,
            bobSignedPrekeyPublic);
        return CreateOuterState(
            seed.Binding,
            state,
            bobSignedPrekeyPublic,
            state.LocalPublic,
            storageGeneration,
            maximumMessagesWithoutPqInjection);
    }

    internal TripleRatchetState InitializeBob(
        VerifiedTripleRatchetSeedCapability seedCapability,
        ReadOnlySpan<byte> signedPrekeyPrivate,
        ReadOnlySpan<byte> signedPrekeyPublic,
        ReadOnlySpan<byte> aliceInitialRatchetPublic,
        ulong storageGeneration,
        int maximumMessagesWithoutPqInjection)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(seedCapability);
        using var seed = seedCapability.Consume();
        using var state = ComponentState.CreateBob(
            _braidProvider,
            seed,
            signedPrekeyPrivate,
            signedPrekeyPublic,
            aliceInitialRatchetPublic);
        return CreateOuterState(
            seed.Binding,
            state,
            aliceInitialRatchetPublic,
            state.LocalPublic,
            storageGeneration,
            maximumMessagesWithoutPqInjection);
    }

    public RatchetComponentTransition PrepareSend(
        ReadOnlySpan<byte> currentOpaqueState,
        RatchetEcChainCursor sendCursor,
        ReadOnlySpan<byte> networkId,
        PqInjectionSchedule pqSchedule)
    {
        ThrowIfDisposed();
        MessagingCryptoValidation.NonZeroExact(networkId, 16, nameof(networkId));
        ValidateSchedule(pqSchedule);
        using var state = ComponentState.Import(_braidProvider, currentOpaqueState);
        var ec = state.NextSendEc(sendCursor);
        PqDerivedKey? pq = null;
        byte[]? encoded = null;
        byte[]? exactDtr2 = null;
        try
        {
            var braidEpoch = state.Braid.Epoch;
            var braidMessage = state.Braid.Send();
            if (braidEpoch == 0)
                throw Transition("The Braid epoch cannot be zero.");
            var sckaEpoch = braidEpoch - 1;
            pq = state.NextSendPq(sckaEpoch);
            exactDtr2 = Dtr2Codec.EncodeEmbedded(new Dtr2Record(
                networkId,
                ec.Chain.ToArray(),
                state.PreviousEcSendLength,
                ec.N,
                pq.Epoch,
                state.PreviousSckaSendLength,
                pq.N,
                braidEpoch,
                braidMessage));
            encoded = state.Export();
            var material = new RatchetComponentKeyMaterial(
                new RatchetCounterTuple(ec.Chain, ec.N, pq.Epoch, pq.N),
                ec.Key,
                pq.Key,
                pq.Evidence);
            try
            {
                var transition = new RatchetComponentTransition(encoded, [material], exactDtr2);
                encoded = null;
                material = null!;
                return transition;
            }
            finally { material?.Dispose(); }
        }
        finally
        {
            ec.Dispose();
            pq?.Dispose();
            Zero(encoded);
            Zero(exactDtr2);
        }
    }

    public RatchetComponentTransition PrepareReceive(
        ReadOnlySpan<byte> currentOpaqueState,
        RatchetEcChainCursor receiveCursor,
        RatchetCounterTuple target,
        ReadOnlySpan<byte> exactDtr2,
        PqInjectionSchedule pqSchedule)
    {
        ThrowIfDisposed();
        ValidateSchedule(pqSchedule);
        if (exactDtr2.IsEmpty)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The managed production component requires exact canonical DTR2 bytes.");
        var header = Dtr2Codec.DecodeEmbedded(exactDtr2);
        var headerChain = RatchetEcChainId.FromPublicKey(header.EcRatchetPublicKey.Span);
        if (target != new RatchetCounterTuple(
                headerChain,
                header.EcMessageNumber,
                header.SckaSendingEpoch,
                header.SckaMessageNumber))
            throw new MessagingCryptoException(
                MessagingCryptoError.ReplayConflict,
                "The component target differs from exact DTR2.");
        if (header.BraidEpoch == 0 ||
            header.SckaSendingEpoch == ulong.MaxValue ||
            header.SckaSendingEpoch + 1 != header.BraidEpoch)
            throw Transition("DTR2 does not bind the Signal SCKA epoch to braidEpoch - 1.");

        using var state = ComponentState.Import(_braidProvider, currentOpaqueState);
        SecretBuffer? freshOutput = null;
        List<EcDerivedKey>? ec = null;
        List<PqDerivedKey>? pq = null;
        byte[]? encoded = null;
        RatchetComponentKeyMaterial[]? materials = null;
        try
        {
            freshOutput = state.Braid.Receive(header.BraidEpoch, header.BraidMessage);
            var hasFreshContribution = freshOutput is not null;
            if (freshOutput is not null)
                freshOutput.Use(value => state.AddSpqrEpoch(header.BraidEpoch, value));

            ec = state.ReceiveEc(
                receiveCursor,
                target,
                header.EcPreviousSendingChainLength);
            pq = state.ReceivePq(
                target.SckaEpoch,
                target.SckaN,
                header.SckaPreviousSendingChainLength,
                ec.Count,
                hasFreshContribution);
            if (ec.Count != pq.Count)
                throw Transition("The EC and SPQR receive sequences have different lengths.");

            materials = new RatchetComponentKeyMaterial[ec.Count];
            for (var index = 0; index < materials.Length; index++)
                materials[index] = new RatchetComponentKeyMaterial(
                    new RatchetCounterTuple(
                        ec[index].Chain,
                        ec[index].N,
                        pq[index].Epoch,
                        pq[index].N),
                    ec[index].Key,
                    pq[index].Key,
                    pq[index].Evidence);
            encoded = state.Export();
            var result = new RatchetComponentTransition(encoded, materials);
            encoded = null;
            materials = null;
            return result;
        }
        finally
        {
            freshOutput?.Dispose();
            if (ec is not null) foreach (var key in ec) key.Dispose();
            if (pq is not null) foreach (var key in pq) key.Dispose();
            if (materials is not null) foreach (var key in materials) key?.Dispose();
            Zero(encoded);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _braidProvider.Dispose();
    }

    private static TripleRatchetState CreateOuterState(
        RatchetStateBinding binding,
        ComponentState state,
        ReadOnlySpan<byte> receivePublic,
        ReadOnlySpan<byte> sendPublic,
        ulong storageGeneration,
        int maximumMessagesWithoutPqInjection)
    {
        var opaque = state.Export();
        try
        {
            return TripleRatchetState.Create(
                binding,
                opaque,
                receivePublic,
                sendPublic,
                state.ReceiveEvidence,
                state.SendEvidence,
                0,
                0,
                storageGeneration,
                maximumMessagesWithoutPqInjection);
        }
        finally { CryptographicOperations.ZeroMemory(opaque); }
    }

    private static void ValidateSchedule(PqInjectionSchedule schedule)
    {
        if (schedule.MaximumMessagesWithoutFreshContribution is < 1 or > MessagingCryptoConstants.MaximumForwardGap ||
            schedule.MessagesSinceFreshContribution < 0 ||
            schedule.MessagesSinceFreshContribution > schedule.MaximumMessagesWithoutFreshContribution)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The PQ injection schedule is outside the frozen bounds.");
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.ObjectDisposed,
                "The managed Triple-Ratchet component provider is disposed.");
    }

    private static MessagingCryptoException Transition(string message) =>
        new(MessagingCryptoError.TransitionRejected, message);

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }

    private sealed class ComponentState : IDisposable
    {
        private const int PrefixBytes = 596;
        private const int LinkBytes = 96;
        private const byte Version = 1;
        private const byte HasSendEc = 1;
        private const byte HasReceiveEc = 2;
        private const byte PendingSendEc = 4;
        private const byte LinkHasSend = 1;
        private const byte LinkHasReceive = 2;
        private const byte LinkSendFresh = 4;

        private readonly DeepMlKemBraidNativeProvider _provider;
        private readonly List<SpqrLink> _links;
        private byte[] _ecRoot;
        private byte[] _localPrivate;
        private byte[] _localPublic;
        private byte[] _remotePublic;
        private byte[] _advertisedSendPublic;
        private byte[]? _sendEcChain;
        private byte[]? _receiveEcChain;
        private byte[] _sendEvidence;
        private byte[] _receiveEvidence;
        private byte[] _spqrRoot;
        private bool _pendingSendEc;
        private bool _disposed;

        private ComponentState(
            DeepMlKemBraidNativeProvider provider,
            TripleRatchetPartyRole role,
            byte[] ecRoot,
            byte[] localPrivate,
            byte[] localPublic,
            byte[] remotePublic,
            byte[] advertisedSendPublic,
            byte[]? sendEcChain,
            byte[]? receiveEcChain,
            byte[] sendEvidence,
            byte[] receiveEvidence,
            byte[] spqrRoot,
            ulong previousEcSendLength,
            ulong sendEcNext,
            ulong receiveEcNext,
            ulong currentSpqrEpoch,
            ulong sendSpqrEpoch,
            ulong receiveSpqrEpoch,
            ulong previousSckaSendLength,
            bool pendingSendEc,
            List<SpqrLink> links,
            ManagedMlKemBraidStateMachine braid)
        {
            _provider = provider;
            Role = role;
            _ecRoot = ecRoot;
            _localPrivate = localPrivate;
            _localPublic = localPublic;
            _remotePublic = remotePublic;
            _advertisedSendPublic = advertisedSendPublic;
            _sendEcChain = sendEcChain;
            _receiveEcChain = receiveEcChain;
            _sendEvidence = sendEvidence;
            _receiveEvidence = receiveEvidence;
            _spqrRoot = spqrRoot;
            PreviousEcSendLength = previousEcSendLength;
            SendEcNext = sendEcNext;
            ReceiveEcNext = receiveEcNext;
            CurrentSpqrEpoch = currentSpqrEpoch;
            SendSpqrEpoch = sendSpqrEpoch;
            ReceiveSpqrEpoch = receiveSpqrEpoch;
            PreviousSckaSendLength = previousSckaSendLength;
            _pendingSendEc = pendingSendEc;
            _links = links;
            Braid = braid;
            Validate();
        }

        internal TripleRatchetPartyRole Role { get; }
        internal ReadOnlySpan<byte> LocalPublic => _localPublic;
        internal ReadOnlySpan<byte> SendEvidence => _sendEvidence;
        internal ReadOnlySpan<byte> ReceiveEvidence => _receiveEvidence;
        internal ulong PreviousEcSendLength { get; private set; }
        internal ulong SendEcNext { get; private set; }
        internal ulong ReceiveEcNext { get; private set; }
        internal ulong CurrentSpqrEpoch { get; private set; }
        internal ulong SendSpqrEpoch { get; private set; }
        internal ulong ReceiveSpqrEpoch { get; private set; }
        internal ulong PreviousSckaSendLength { get; private set; }
        internal ManagedMlKemBraidStateMachine Braid { get; }

        internal static ComponentState CreateAlice(
            DeepMlKemBraidNativeProvider provider,
            VerifiedTripleRatchetSeedData seed,
            ReadOnlySpan<byte> initialPrivate,
            ReadOnlySpan<byte> initialPublic,
            ReadOnlySpan<byte> remotePublic)
        {
            ValidateKeyPair(initialPrivate, initialPublic);
            MessagingCryptoValidation.NonZeroExact(remotePublic, 32, nameof(remotePublic));
            var root = seed.EcRoot.Copy();
            var agreement = Agree(initialPrivate, remotePublic);
            byte[]? nextRoot = null;
            byte[]? sendChain = null;
            try
            {
                using var step = ManagedTripleRatchetKdfProfile.DeriveEcRoot(root, agreement);
                nextRoot = Copy(step.UseRoot);
                sendChain = Copy(step.UseChain);
                return CreateInitial(
                    provider,
                    TripleRatchetPartyRole.Alice,
                    seed,
                    nextRoot,
                    initialPrivate,
                    initialPublic,
                    remotePublic,
                    sendChain,
                    null,
                    ManagedMlKemBraidStateMachine.CreateAlice(provider, seed.SpqrRoot.Copy()));
            }
            finally
            {
                Zero(root);
                Zero(agreement);
                Zero(nextRoot);
                Zero(sendChain);
            }
        }

        internal static ComponentState CreateBob(
            DeepMlKemBraidNativeProvider provider,
            VerifiedTripleRatchetSeedData seed,
            ReadOnlySpan<byte> signedPrivate,
            ReadOnlySpan<byte> signedPublic,
            ReadOnlySpan<byte> alicePublic)
        {
            ValidateKeyPair(signedPrivate, signedPublic);
            MessagingCryptoValidation.NonZeroExact(alicePublic, 32, nameof(alicePublic));
            var root = seed.EcRoot.Copy();
            var firstAgreement = Agree(signedPrivate, alicePublic);
            byte[]? firstRoot = null;
            byte[]? receiveChain = null;
            byte[]? newPrivate = null;
            byte[]? newPublic = null;
            byte[]? secondAgreement = null;
            byte[]? finalRoot = null;
            byte[]? sendChain = null;
            try
            {
                using (var first = ManagedTripleRatchetKdfProfile.DeriveEcRoot(root, firstAgreement))
                {
                    firstRoot = Copy(first.UseRoot);
                    receiveChain = Copy(first.UseChain);
                }
                (newPrivate, newPublic) = GenerateKeyPair();
                secondAgreement = Agree(newPrivate, alicePublic);
                using (var second = ManagedTripleRatchetKdfProfile.DeriveEcRoot(firstRoot, secondAgreement))
                {
                    finalRoot = Copy(second.UseRoot);
                    sendChain = Copy(second.UseChain);
                }
                return CreateInitial(
                    provider,
                    TripleRatchetPartyRole.Bob,
                    seed,
                    finalRoot,
                    newPrivate,
                    newPublic,
                    alicePublic,
                    sendChain,
                    receiveChain,
                    ManagedMlKemBraidStateMachine.CreateBob(provider, seed.SpqrRoot.Copy()));
            }
            finally
            {
                Zero(root); Zero(firstAgreement); Zero(firstRoot); Zero(receiveChain);
                Zero(newPrivate); Zero(newPublic); Zero(secondAgreement); Zero(finalRoot); Zero(sendChain);
            }
        }

        private static ComponentState CreateInitial(
            DeepMlKemBraidNativeProvider provider,
            TripleRatchetPartyRole role,
            VerifiedTripleRatchetSeedData seed,
            ReadOnlySpan<byte> ecRoot,
            ReadOnlySpan<byte> localPrivate,
            ReadOnlySpan<byte> localPublic,
            ReadOnlySpan<byte> remotePublic,
            ReadOnlySpan<byte> sendEcChain,
            byte[]? receiveEcChain,
            ManagedMlKemBraidStateMachine braid)
        {
            var initial = seed.SpqrRoot.Copy();
            byte[]? spqrRoot = null;
            byte[]? aToB = null;
            byte[]? bToA = null;
            try
            {
                using var derived = ManagedTripleRatchetKdfProfile.InitializeSpqr(initial);
                spqrRoot = Copy(derived.UseRoot);
                aToB = Copy(derived.UseAliceToBob);
                bToA = Copy(derived.UseBobToAlice);
                var send = role == TripleRatchetPartyRole.Alice ? aToB : bToA;
                var receive = role == TripleRatchetPartyRole.Alice ? bToA : aToB;
                var sendEvidence = EvidenceSeed(spqrRoot, role, true);
                var receiveEvidence = EvidenceSeed(spqrRoot, role, false);
                var state = new ComponentState(
                    provider,
                    role,
                    ecRoot.ToArray(),
                    localPrivate.ToArray(),
                    localPublic.ToArray(),
                    remotePublic.ToArray(),
                    localPublic.ToArray(),
                    sendEcChain.ToArray(),
                    receiveEcChain?.ToArray(),
                    sendEvidence,
                    receiveEvidence,
                    spqrRoot.ToArray(),
                    0, 0, 0, 0, 0, 0, 0, false,
                    [new SpqrLink(0, send.ToArray(), 1, receive.ToArray(), 1, false)],
                    braid);
                braid = null!;
                return state;
            }
            finally
            {
                braid?.Dispose();
                Zero(initial); Zero(spqrRoot); Zero(aToB); Zero(bToA);
            }
        }

        internal EcDerivedKey NextSendEc(RatchetEcChainCursor cursor)
        {
            var expectedPublic = _pendingSendEc ? _advertisedSendPublic : _localPublic;
            var expectedN = _pendingSendEc ? PreviousEcSendLength : SendEcNext;
            if (cursor.Chain != RatchetEcChainId.FromPublicKey(expectedPublic) || cursor.NextN != expectedN)
                throw Transition("The provider EC send cursor differs from its durable state.");
            var chain = _sendEcChain ?? throw Transition("The EC sending chain is unavailable.");
            if (SendEcNext == ulong.MaxValue) throw Limit("The EC sending counter is exhausted.");
            using var step = ManagedTripleRatchetKdfProfile.DeriveEcChain(chain);
            var next = Copy(step.UseNextChain);
            var key = Copy(step.UseMessageKey);
            Zero(_sendEcChain);
            _sendEcChain = next;
            SendEcNext++;
            if (_pendingSendEc)
            {
                Zero(_advertisedSendPublic);
                _advertisedSendPublic = _localPublic.ToArray();
                _pendingSendEc = false;
            }
            return new EcDerivedKey(RatchetEcChainId.FromPublicKey(_localPublic), SendEcNext - 1, key);
        }

        internal List<EcDerivedKey> ReceiveEc(
            RatchetEcChainCursor cursor,
            RatchetCounterTuple target,
            ulong previousSendingChainLength)
        {
            if (cursor.Chain != RatchetEcChainId.FromPublicKey(_remotePublic) || cursor.NextN != ReceiveEcNext)
                throw Transition("The provider EC receive cursor differs from its durable state.");
            var keys = new List<EcDerivedKey>();
            try
            {
                if (target.EcChain == cursor.Chain)
                {
                    if (target.EcN < ReceiveEcNext) throw Replay("The EC receive key was already consumed.");
                    DeriveReceiveEcRange(keys, target.EcChain, target.EcN);
                    return keys;
                }
                if (_pendingSendEc)
                    throw Transition("A second remote EC ratchet arrived before the local successor was advertised.");
                if (previousSendingChainLength < ReceiveEcNext)
                    throw new MessagingCryptoException(
                        MessagingCryptoError.ReplayConflict,
                        "The new EC chain PN is behind the durable receive cursor.");
                if (previousSendingChainLength > 0)
                    DeriveReceiveEcRange(keys, cursor.Chain, previousSendingChainLength - 1);
                RotateReceiveEc(target.EcChain.ToArray());
                DeriveReceiveEcRange(keys, target.EcChain, target.EcN);
                return keys;
            }
            catch
            {
                foreach (var key in keys) key.Dispose();
                throw;
            }
        }

        private void DeriveReceiveEcRange(List<EcDerivedKey> keys, RatchetEcChainId chainId, ulong inclusiveTarget)
        {
            var chain = _receiveEcChain ?? throw Transition("The EC receiving chain is unavailable.");
            while (ReceiveEcNext <= inclusiveTarget)
            {
                if (ReceiveEcNext == ulong.MaxValue) throw Limit("The EC receive counter is exhausted.");
                using var step = ManagedTripleRatchetKdfProfile.DeriveEcChain(chain);
                var next = Copy(step.UseNextChain);
                var key = Copy(step.UseMessageKey);
                Zero(_receiveEcChain);
                _receiveEcChain = next;
                chain = next;
                keys.Add(new EcDerivedKey(chainId, ReceiveEcNext, key));
                ReceiveEcNext++;
            }
        }

        private void RotateReceiveEc(ReadOnlySpan<byte> remotePublic)
        {
            byte[]? newRemotePublic = remotePublic.ToArray();
            byte[]? agreement = null;
            byte[]? receiveRoot = null;
            byte[]? receiveChain = null;
            byte[]? newPrivate = null;
            byte[]? newPublic = null;
            byte[]? sendAgreement = null;
            byte[]? finalRoot = null;
            byte[]? sendChain = null;
            try
            {
                agreement = Agree(_localPrivate, newRemotePublic);
                using (var receiveStep = ManagedTripleRatchetKdfProfile.DeriveEcRoot(_ecRoot, agreement))
                {
                    receiveRoot = Copy(receiveStep.UseRoot);
                    receiveChain = Copy(receiveStep.UseChain);
                }
                (newPrivate, newPublic) = GenerateKeyPair();
                sendAgreement = Agree(newPrivate, newRemotePublic);
                using (var sendStep = ManagedTripleRatchetKdfProfile.DeriveEcRoot(receiveRoot, sendAgreement))
                {
                    finalRoot = Copy(sendStep.UseRoot);
                    sendChain = Copy(sendStep.UseChain);
                }
                PreviousEcSendLength = SendEcNext;
                SendEcNext = 0;
                ReceiveEcNext = 0;
                ReplaceRequired(ref _ecRoot, finalRoot!); finalRoot = null;
                ReplaceOptional(ref _receiveEcChain, receiveChain!); receiveChain = null;
                ReplaceOptional(ref _sendEcChain, sendChain!); sendChain = null;
                ReplaceRequired(ref _remotePublic, newRemotePublic!); newRemotePublic = null;
                ReplaceRequired(ref _localPrivate, newPrivate!); newPrivate = null;
                ReplaceRequired(ref _localPublic, newPublic!); newPublic = null;
                _pendingSendEc = true;
            }
            finally
            {
                Zero(newRemotePublic); Zero(agreement); Zero(receiveRoot); Zero(receiveChain);
                Zero(newPrivate); Zero(newPublic); Zero(sendAgreement); Zero(finalRoot); Zero(sendChain);
            }
        }

        internal void AddSpqrEpoch(ulong epoch, ReadOnlySpan<byte> braidOutputKey)
        {
            if (CurrentSpqrEpoch == ulong.MaxValue || epoch != CurrentSpqrEpoch + 1)
                throw Transition("A fresh Braid output must advance SPQR by exactly one epoch.");
            using var step = ManagedTripleRatchetKdfProfile.AdvanceSpqrEpoch(_spqrRoot, braidOutputKey, epoch);
            var root = Copy(step.UseRoot);
            var aToB = Copy(step.UseAliceToBob);
            var bToA = Copy(step.UseBobToAlice);
            try
            {
                var send = Role == TripleRatchetPartyRole.Alice ? aToB : bToA;
                var receive = Role == TripleRatchetPartyRole.Alice ? bToA : aToB;
                _links.Add(new SpqrLink(epoch, send.ToArray(), 1, receive.ToArray(), 1, true));
                ReplaceRequired(ref _spqrRoot, root!); root = null;
                CurrentSpqrEpoch = epoch;
                while (_links.Count > 2)
                {
                    _links[0].Dispose();
                    _links.RemoveAt(0);
                }
            }
            finally { Zero(root); Zero(aToB); Zero(bToA); }
        }

        internal PqDerivedKey NextSendPq(ulong epoch)
        {
            var link = FindLink(epoch);
            if (epoch < SendSpqrEpoch || epoch > CurrentSpqrEpoch)
                throw Transition("The SPQR sending epoch moved backwards or beyond installed state.");
            if (epoch > SendSpqrEpoch)
            {
                if (epoch != SendSpqrEpoch + 1)
                    throw Transition("The SPQR sending epoch skipped a durable epoch.");
                var previous = FindLink(SendSpqrEpoch);
                PreviousSckaSendLength = previous.SendNext - 1;
                SendSpqrEpoch = epoch;
            }
            var direction = Role == TripleRatchetPartyRole.Alice
                ? TripleRatchetDirection.AliceToBob
                : TripleRatchetDirection.BobToAlice;
            var key = link.NextSendKey(direction);
            var fresh = link.TakeSendFresh();
            var prior = _sendEvidence.ToArray();
            var next = AdvanceEvidence(prior, key, epoch, link.SendNext - 1, fresh, true);
            ReplaceRequired(ref _sendEvidence, next);
            try
            {
                return new PqDerivedKey(
                    epoch,
                    link.SendNext - 1,
                    key,
                    new PqStepEvidence(prior, next, fresh));
            }
            finally
            {
                Zero(prior);
                Zero(next);
            }
        }

        internal List<PqDerivedKey> ReceivePq(
            ulong targetEpoch,
            ulong targetN,
            ulong previousSendingChainLength,
            int expectedCount,
            bool hasFreshContribution)
        {
            if (targetN == 0) throw Transition("SPQR message numbers start at one.");
            if (targetEpoch < ReceiveSpqrEpoch || targetEpoch > CurrentSpqrEpoch)
                throw Transition("The SPQR receive epoch is outside retained state.");
            var coordinates = new List<(SpqrLink Link, ulong N)>();
            if (targetEpoch == ReceiveSpqrEpoch)
            {
                var link = FindLink(targetEpoch);
                if (targetN < link.ReceiveNext) throw Replay("The SPQR receive key was already consumed.");
                AddCoordinates(coordinates, link, targetN);
            }
            else
            {
                if (targetEpoch != ReceiveSpqrEpoch + 1)
                    throw Transition("The SPQR receive epoch skipped a durable epoch.");
                var previous = FindLink(ReceiveSpqrEpoch);
                if (previousSendingChainLength < previous.ReceiveNext - 1)
                    throw new MessagingCryptoException(
                        MessagingCryptoError.ReplayConflict,
                        "The SPQR PN is behind the durable receive cursor.");
                if (previousSendingChainLength >= previous.ReceiveNext)
                    AddCoordinates(coordinates, previous, previousSendingChainLength);
                var current = FindLink(targetEpoch);
                AddCoordinates(coordinates, current, targetN);
                ReceiveSpqrEpoch = targetEpoch;
            }
            if (coordinates.Count != expectedCount)
                throw Transition("DTR2 EC and SPQR gaps are not one-to-one.");

            var result = new List<PqDerivedKey>(coordinates.Count);
            try
            {
                for (var index = 0; index < coordinates.Count; index++)
                {
                    var (link, n) = coordinates[index];
                    var direction = Role == TripleRatchetPartyRole.Alice
                        ? TripleRatchetDirection.BobToAlice
                        : TripleRatchetDirection.AliceToBob;
                    var key = link.NextReceiveKey(n, direction);
                    var fresh = hasFreshContribution && index == coordinates.Count - 1;
                    var prior = _receiveEvidence.ToArray();
                    var next = AdvanceEvidence(prior, key, link.Epoch, n, fresh, false);
                    ReplaceRequired(ref _receiveEvidence, next);
                    try
                    {
                        result.Add(new PqDerivedKey(
                            link.Epoch,
                            n,
                            key,
                            new PqStepEvidence(prior, next, fresh)));
                    }
                    finally
                    {
                        Zero(prior);
                        Zero(next);
                    }
                }
                return result;
            }
            catch
            {
                foreach (var item in result) item.Dispose();
                throw;
            }
        }

        private static void AddCoordinates(List<(SpqrLink, ulong)> output, SpqrLink link, ulong target)
        {
            if (target < link.ReceiveNext) return;
            var count = checked(target - link.ReceiveNext + 1);
            if (count > MessagingCryptoConstants.MaximumForwardGap + 1UL)
                throw Limit("The SPQR receive gap exceeds the frozen bound.");
            for (var n = link.ReceiveNext; n <= target; n++) output.Add((link, n));
        }

        internal byte[] Export()
        {
            Validate();
            var braid = Braid.ExportLocalPlaintextState();
            var output = new byte[checked(PrefixBytes + braid.Length)];
            try
            {
                ProtocolMagicBytes.TRC1.CopyTo(output);
                output[4] = Version;
                BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(5), MessagingCryptoConstants.Suite);
                output[7] = (byte)Role;
                output[8] = (byte)((_sendEcChain is null ? 0 : HasSendEc) |
                    (_receiveEcChain is null ? 0 : HasReceiveEc) |
                    (_pendingSendEc ? PendingSendEc : 0));
                _ecRoot.CopyTo(output, 16);
                _localPrivate.CopyTo(output, 48);
                _localPublic.CopyTo(output, 80);
                _remotePublic.CopyTo(output, 112);
                _advertisedSendPublic.CopyTo(output, 144);
                _sendEcChain?.CopyTo(output, 176);
                _receiveEcChain?.CopyTo(output, 208);
                _sendEvidence.CopyTo(output, 240);
                _receiveEvidence.CopyTo(output, 272);
                BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(304), PreviousEcSendLength);
                BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(312), SendEcNext);
                BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(320), ReceiveEcNext);
                _spqrRoot.CopyTo(output, 328);
                BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(360), CurrentSpqrEpoch);
                BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(368), SendSpqrEpoch);
                BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(376), ReceiveSpqrEpoch);
                BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(384), PreviousSckaSendLength);
                output[392] = checked((byte)_links.Count);
                for (var index = 0; index < _links.Count; index++)
                    _links[index].Write(output.AsSpan(400 + index * LinkBytes, LinkBytes));
                BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(592), checked((uint)braid.Length));
                braid.CopyTo(output, PrefixBytes);
                return output;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(output);
                throw;
            }
            finally { CryptographicOperations.ZeroMemory(braid); }
        }

        internal static ComponentState Import(
            DeepMlKemBraidNativeProvider provider,
            ReadOnlySpan<byte> encoded)
        {
            if (encoded.Length < PrefixBytes || encoded.Length > MessagingCryptoConstants.MaximumOpaqueProviderStateBytes ||
                !encoded[..4].SequenceEqual(ProtocolMagicBytes.TRC1) || encoded[4] != Version ||
                BinaryPrimitives.ReadUInt16BigEndian(encoded[5..]) != MessagingCryptoConstants.Suite ||
                !Enum.IsDefined((TripleRatchetPartyRole)encoded[7]) ||
                !MessagingCryptoValidation.IsZero(encoded.Slice(9, 7)) ||
                !MessagingCryptoValidation.IsZero(encoded.Slice(393, 7)))
                throw InvalidStateEncoding();
            var braidLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded[592..]));
            if (braidLength < 1 || encoded.Length != PrefixBytes + braidLength)
                throw InvalidStateEncoding();
            var flags = encoded[8];
            if ((flags & ~(HasSendEc | HasReceiveEc | PendingSendEc)) != 0)
                throw InvalidStateEncoding();
            ValidateOptional((flags & HasSendEc) != 0, encoded.Slice(176, 32));
            ValidateOptional((flags & HasReceiveEc) != 0, encoded.Slice(208, 32));
            var count = encoded[392];
            if (count is < 1 or > 2) throw InvalidStateEncoding();
            var links = new List<SpqrLink>(count);
            ManagedMlKemBraidStateMachine? braid = null;
            try
            {
                for (var index = 0; index < count; index++)
                    links.Add(SpqrLink.Read(encoded.Slice(400 + index * LinkBytes, LinkBytes)));
                if (!MessagingCryptoValidation.IsZero(
                        encoded.Slice(400 + count * LinkBytes, (2 - count) * LinkBytes)))
                    throw InvalidStateEncoding();
                braid = ManagedMlKemBraidStateMachine.ImportLocalPlaintextState(
                    provider,
                    encoded.Slice(PrefixBytes, braidLength));
                var result = new ComponentState(
                    provider,
                    (TripleRatchetPartyRole)encoded[7],
                    ExactNonZero(encoded.Slice(16, 32)),
                    ExactNonZero(encoded.Slice(48, 32)),
                    ExactNonZero(encoded.Slice(80, 32)),
                    ExactNonZero(encoded.Slice(112, 32)),
                    ExactNonZero(encoded.Slice(144, 32)),
                    (flags & HasSendEc) == 0 ? null : encoded.Slice(176, 32).ToArray(),
                    (flags & HasReceiveEc) == 0 ? null : encoded.Slice(208, 32).ToArray(),
                    ExactNonZero(encoded.Slice(240, 32)),
                    ExactNonZero(encoded.Slice(272, 32)),
                    ExactNonZero(encoded.Slice(328, 32)),
                    BinaryPrimitives.ReadUInt64BigEndian(encoded[304..]),
                    BinaryPrimitives.ReadUInt64BigEndian(encoded[312..]),
                    BinaryPrimitives.ReadUInt64BigEndian(encoded[320..]),
                    BinaryPrimitives.ReadUInt64BigEndian(encoded[360..]),
                    BinaryPrimitives.ReadUInt64BigEndian(encoded[368..]),
                    BinaryPrimitives.ReadUInt64BigEndian(encoded[376..]),
                    BinaryPrimitives.ReadUInt64BigEndian(encoded[384..]),
                    (flags & PendingSendEc) != 0,
                    links,
                    braid);
                links = null!;
                braid = null;
                return result;
            }
            finally
            {
                if (links is not null) foreach (var link in links) link.Dispose();
                braid?.Dispose();
            }
        }

        private void Validate()
        {
            if (!Enum.IsDefined(Role) || _links.Count is < 1 or > 2 ||
                CurrentSpqrEpoch != _links[^1].Epoch || SendSpqrEpoch > CurrentSpqrEpoch ||
                ReceiveSpqrEpoch > CurrentSpqrEpoch ||
                _links.All(link => link.Epoch != SendSpqrEpoch) ||
                _links.All(link => link.Epoch != ReceiveSpqrEpoch) ||
                _links.Zip(_links.Skip(1)).Any(pair => pair.Second.Epoch != pair.First.Epoch + 1) ||
                Braid.Epoch != CurrentSpqrEpoch + 1)
                throw InvalidStateEncoding();
            ValidateKeyPair(_localPrivate, _localPublic);
            MessagingCryptoValidation.NonZeroExact(_remotePublic, 32, nameof(_remotePublic));
            MessagingCryptoValidation.NonZeroExact(_advertisedSendPublic, 32, nameof(_advertisedSendPublic));
            MessagingCryptoValidation.NonZeroExact(_ecRoot, 32, nameof(_ecRoot));
            MessagingCryptoValidation.NonZeroExact(_spqrRoot, 32, nameof(_spqrRoot));
            MessagingCryptoValidation.NonZeroExact(_sendEvidence, 32, nameof(_sendEvidence));
            MessagingCryptoValidation.NonZeroExact(_receiveEvidence, 32, nameof(_receiveEvidence));
            if (_pendingSendEc && MessagingCryptoValidation.FixedEquals(_advertisedSendPublic, _localPublic))
                throw InvalidStateEncoding();
        }

        private SpqrLink FindLink(ulong epoch) => _links.FirstOrDefault(link => link.Epoch == epoch) ??
            throw Transition("The requested SPQR epoch is outside the two-epoch retention window.");

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Braid.Dispose();
            foreach (var link in _links) link.Dispose();
            Zero(_ecRoot); Zero(_localPrivate); Zero(_localPublic); Zero(_remotePublic);
            Zero(_advertisedSendPublic); Zero(_sendEcChain); Zero(_receiveEcChain);
            Zero(_sendEvidence); Zero(_receiveEvidence); Zero(_spqrRoot);
        }

        private static byte[] EvidenceSeed(
            ReadOnlySpan<byte> root,
            TripleRatchetPartyRole role,
            bool send)
        {
            Span<byte> input = stackalloc byte[34];
            root.CopyTo(input);
            input[32] = (byte)role;
            input[33] = send ? (byte)1 : (byte)2;
            return MessagingKdf.Sha256Domain("Deep/Messaging/V2/pq-state-evidence", input);
        }

        private static byte[] AdvanceEvidence(
            ReadOnlySpan<byte> prior,
            ReadOnlySpan<byte> key,
            ulong epoch,
            ulong n,
            bool fresh,
            bool send)
        {
            Span<byte> input = stackalloc byte[82];
            prior.CopyTo(input);
            SHA256.HashData(key, input[32..64]);
            BinaryPrimitives.WriteUInt64BigEndian(input[64..], epoch);
            BinaryPrimitives.WriteUInt64BigEndian(input[72..], n);
            input[80] = fresh ? (byte)1 : (byte)0;
            input[81] = send ? (byte)1 : (byte)2;
            return MessagingKdf.Sha256Domain("Deep/Messaging/V2/pq-state-step", input);
        }

        internal static void ValidateOptional(bool present, ReadOnlySpan<byte> value)
        {
            if (present == MessagingCryptoValidation.IsZero(value)) throw InvalidStateEncoding();
        }

        private static byte[] ExactNonZero(ReadOnlySpan<byte> value)
        {
            if (value.Length != 32 || MessagingCryptoValidation.IsZero(value)) throw InvalidStateEncoding();
            return value.ToArray();
        }

        private static MessagingCryptoException InvalidStateEncoding() => new(
            MessagingCryptoError.InvalidInput,
            "The managed Triple-Ratchet component state is not one canonical TRC1 value.");

        private static byte[] Copy(Func<MessagingSecretFunc<byte[]>, byte[]> accessor) =>
            accessor(static value => value.ToArray());

        private static void ReplaceRequired(ref byte[] target, byte[] successor)
        {
            var old = target;
            target = successor;
            Zero(old);
        }

        private static void ReplaceOptional(ref byte[]? target, byte[] successor)
        {
            var old = target;
            target = successor;
            Zero(old);
        }
    }

    private sealed class SpqrLink : IDisposable
    {
        private byte[]? _sendChain;
        private byte[]? _receiveChain;
        private bool _sendFresh;

        internal SpqrLink(
            ulong epoch,
            byte[]? sendChain,
            ulong sendNext,
            byte[]? receiveChain,
            ulong receiveNext,
            bool sendFresh)
        {
            Epoch = epoch;
            _sendChain = sendChain;
            SendNext = sendNext;
            _receiveChain = receiveChain;
            ReceiveNext = receiveNext;
            _sendFresh = sendFresh;
            if (sendNext == 0 || receiveNext == 0 ||
                sendChain is not null && (sendChain.Length != 32 || MessagingCryptoValidation.IsZero(sendChain)) ||
                receiveChain is not null && (receiveChain.Length != 32 || MessagingCryptoValidation.IsZero(receiveChain)))
                throw new MessagingCryptoException(MessagingCryptoError.InvalidInput, "Invalid SPQR link state.");
        }

        internal ulong Epoch { get; }
        internal ulong SendNext { get; private set; }
        internal ulong ReceiveNext { get; private set; }

        internal byte[] NextSendKey(TripleRatchetDirection direction)
        {
            if (_sendChain is null || SendNext == ulong.MaxValue) throw Limit("SPQR send chain unavailable or exhausted.");
            using var step = ManagedTripleRatchetKdfProfile.DeriveSpqrChain(
                _sendChain, Epoch, direction, SendNext);
            var next = Copy(step.UseNextChain);
            var key = Copy(step.UseMessageKey);
            Zero(_sendChain);
            _sendChain = next;
            SendNext++;
            return key;
        }

        internal byte[] NextReceiveKey(ulong expectedN, TripleRatchetDirection direction)
        {
            if (_receiveChain is null || ReceiveNext != expectedN || ReceiveNext == ulong.MaxValue)
                throw Transition("SPQR receive chain is unavailable, non-contiguous, or exhausted.");
            using var step = ManagedTripleRatchetKdfProfile.DeriveSpqrChain(
                _receiveChain, Epoch, direction, ReceiveNext);
            var next = Copy(step.UseNextChain);
            var key = Copy(step.UseMessageKey);
            Zero(_receiveChain);
            _receiveChain = next;
            ReceiveNext++;
            return key;
        }

        internal bool TakeSendFresh()
        {
            var value = _sendFresh;
            _sendFresh = false;
            return value;
        }

        internal void Write(Span<byte> output)
        {
            output.Clear();
            BinaryPrimitives.WriteUInt64BigEndian(output, Epoch);
            output[8] = (byte)((_sendChain is null ? 0 : 1) |
                (_receiveChain is null ? 0 : 2) |
                (_sendFresh ? 4 : 0));
            _sendChain?.CopyTo(output[16..48]);
            BinaryPrimitives.WriteUInt64BigEndian(output[48..], SendNext);
            _receiveChain?.CopyTo(output[56..88]);
            BinaryPrimitives.WriteUInt64BigEndian(output[88..], ReceiveNext);
        }

        internal static SpqrLink Read(ReadOnlySpan<byte> input)
        {
            if (input.Length != 96 || !MessagingCryptoValidation.IsZero(input.Slice(9, 7)) ||
                (input[8] & ~7) != 0)
                throw new MessagingCryptoException(MessagingCryptoError.InvalidInput, "Invalid TRC1 SPQR link.");
            var flags = input[8];
            ComponentState.ValidateOptional((flags & 1) != 0, input.Slice(16, 32));
            ComponentState.ValidateOptional((flags & 2) != 0, input.Slice(56, 32));
            return new SpqrLink(
                BinaryPrimitives.ReadUInt64BigEndian(input),
                (flags & 1) == 0 ? null : input.Slice(16, 32).ToArray(),
                BinaryPrimitives.ReadUInt64BigEndian(input[48..]),
                (flags & 2) == 0 ? null : input.Slice(56, 32).ToArray(),
                BinaryPrimitives.ReadUInt64BigEndian(input[88..]),
                (flags & 4) != 0);
        }

        public void Dispose()
        {
            Zero(_sendChain);
            Zero(_receiveChain);
            _sendChain = null;
            _receiveChain = null;
        }

        private static byte[] Copy(Func<MessagingSecretFunc<byte[]>, byte[]> accessor) =>
            accessor(static value => value.ToArray());
    }

    private sealed class EcDerivedKey(RatchetEcChainId chain, ulong n, byte[] key) : IDisposable
    {
        internal RatchetEcChainId Chain { get; } = chain;
        internal ulong N { get; } = n;
        internal byte[] Key { get; } = key;
        public void Dispose() => CryptographicOperations.ZeroMemory(Key);
    }

    private sealed class PqDerivedKey(
        ulong epoch,
        ulong n,
        byte[] key,
        PqStepEvidence evidence) : IDisposable
    {
        internal ulong Epoch { get; } = epoch;
        internal ulong N { get; } = n;
        internal byte[] Key { get; } = key;
        internal PqStepEvidence Evidence { get; } = evidence;
        public void Dispose() => CryptographicOperations.ZeroMemory(Key);
    }

    private static (byte[] Private, byte[] Public) GenerateKeyPair()
    {
        var privateKey = new byte[32];
        byte[]? publicKey = null;
        try
        {
            RandomNumberGenerator.Fill(privateKey);
            publicKey = ScalarMult.Base(privateKey);
            MessagingCryptoValidation.NonZeroExact(publicKey, 32, nameof(publicKey));
            return (privateKey, publicKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(privateKey);
            Zero(publicKey);
            throw;
        }
    }

    private static void ValidateKeyPair(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        MessagingCryptoValidation.NonZeroExact(privateKey, 32, nameof(privateKey));
        MessagingCryptoValidation.NonZeroExact(publicKey, 32, nameof(publicKey));
        var privateCopy = privateKey.ToArray();
        byte[]? actual = null;
        try
        {
            actual = ScalarMult.Base(privateCopy);
            if (!MessagingCryptoValidation.FixedEquals(actual, publicKey))
                throw new MessagingCryptoException(
                    MessagingCryptoError.InvalidInput,
                    "The X25519 ratchet public key does not match its private scalar.");
        }
        finally { Zero(privateCopy); Zero(actual); }
    }

    private static byte[] Agree(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        MessagingCryptoValidation.NonZeroExact(privateKey, 32, nameof(privateKey));
        MessagingCryptoValidation.NonZeroExact(publicKey, 32, nameof(publicKey));
        var privateCopy = privateKey.ToArray();
        var publicCopy = publicKey.ToArray();
        byte[]? result = null;
        try
        {
            result = ScalarMult.Mult(privateCopy, publicCopy);
            MessagingCryptoValidation.NonZeroExact(result, 32, nameof(result));
            return result;
        }
        catch (MessagingCryptoException) { Zero(result); throw; }
        catch (Exception exception)
        {
            Zero(result);
            throw new MessagingCryptoException(
                MessagingCryptoError.ProviderFailure,
                "libsodium rejected X25519 agreement.",
                exception);
        }
        finally { Zero(privateCopy); Zero(publicCopy); }
    }

    private static byte[] Copy(Func<MessagingSecretFunc<byte[]>, byte[]> accessor) =>
        accessor(static value => value.ToArray());

    private static MessagingCryptoException Replay(string message) =>
        new(MessagingCryptoError.Replay, message);

    private static MessagingCryptoException Limit(string message) =>
        new(MessagingCryptoError.StateLimitExceeded, message);
}
