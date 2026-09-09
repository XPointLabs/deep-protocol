using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// Canonical plaintext codec for one local Triple-Ratchet state. The returned
/// bytes contain secrets and must only be handed to the caller's authenticated,
/// encrypted, atomic state store. This is not a Deep wire record.
/// </summary>
internal static class TripleRatchetDurableStateCodec
{
    internal static byte[] Encode(TripleRatchetState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return state.ExportDurableState();
    }

    internal static TripleRatchetState Decode(ReadOnlySpan<byte> encoded) =>
        TripleRatchetState.ImportDurableState(encoded);
}

internal sealed partial class TripleRatchetState
{
    // Exact TRS1 local plaintext layout, all integers big-endian:
    // magic[4] || version:u8 || suite:u16 || flags:u8 || total:u32 ||
    // directional RatchetStateBinding[240] || storage generation ||
    // receiveEcChain[32] || receiveN:u64 || sendEcChain[32] || sendN:u64 ||
    // PQ schedules/frontiers/commitments || providerLength:u32 || skippedCount:u32 ||
    // providerState || sorted skipped records[185 each] || stateCommitment[32] ||
    // SHA256-D(local checksum domain, every preceding byte)[32].
    // Unknown versions/flags and every non-exact length are rejected; no migration reader exists.
    private static ReadOnlySpan<byte> DurableMagic => ProtocolMagicBytes.TRS1;
    private const byte DurableVersion = 1;
    private const byte TerminalLatchFlag = 0x01;
    private const int DurablePrefixSize = 12;
    private const int DurableScalarSize = 284;
    private const int DurableSkippedKeySize = 185;
    private const int DurableStateCommitmentSize = 32;
    private const int DurableChecksumSize = 32;
    private const int MinimumDurableEncodingSize =
        DurablePrefixSize + RatchetStateBinding.DurableEncodingSize + DurableScalarSize +
        DurableStateCommitmentSize + DurableChecksumSize;
    private const string DurableChecksumDomain = "Deep/LocalState/V1/triple-ratchet-state-checksum";

    internal byte[] ExportDurableState()
    {
        lock (_lifecycleSync)
        {
            ThrowIfDisposed();
            ValidateDurableStateShape();

            var componentLength = _componentState?.Length ?? 0;
            var totalLength = ComputeDurableEncodedLength(componentLength, _skipped.Count);
            var encoded = new byte[totalLength];
            var ownershipTransferred = false;
            byte[]? checksum = null;
            try
            {
                var offset = 0;
                DurableMagic.CopyTo(encoded); offset += 4;
                encoded[offset++] = DurableVersion;
                BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(offset), Binding.Suite); offset += 2;
                encoded[offset++] = IsTerminallyLatched ? TerminalLatchFlag : (byte)0;
                BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(offset), checked((uint)totalLength)); offset += 4;

                Binding.WriteDurableEncoding(encoded.AsSpan(offset, RatchetStateBinding.DurableEncodingSize));
                offset += RatchetStateBinding.DurableEncodingSize;

                BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(offset), StorageGeneration); offset += 8;
                ReceiveEcChain.Write(encoded.AsSpan(offset, 32)); offset += 32;
                BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(offset), NextExpectedReceiveEcN); offset += 8;
                SendEcChain.Write(encoded.AsSpan(offset, 32)); offset += 32;
                BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(offset), NextSendEcN); offset += 8;
                BinaryPrimitives.WriteInt32BigEndian(encoded.AsSpan(offset), ReceiveMessagesSincePqInjection); offset += 4;
                BinaryPrimitives.WriteInt32BigEndian(encoded.AsSpan(offset), SendMessagesSincePqInjection); offset += 4;
                WriteCounter(encoded.AsSpan(offset, 56), ReceivePqFrontier); offset += 56;
                WriteCounter(encoded.AsSpan(offset, 56), SendPqFrontier); offset += 56;
                _receivePqStateCommitment.CopyTo(encoded, offset); offset += 32;
                _sendPqStateCommitment.CopyTo(encoded, offset); offset += 32;
                BinaryPrimitives.WriteInt32BigEndian(encoded.AsSpan(offset), _maximumMessagesWithoutPqInjection); offset += 4;
                BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(offset), checked((uint)componentLength)); offset += 4;
                BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(offset), checked((uint)_skipped.Count)); offset += 4;

                if (_componentState is not null)
                {
                    _componentState.CopyTo(encoded.AsSpan(offset, componentLength));
                    offset += componentLength;
                }

                foreach (var item in _skipped.OrderBy(static item => item.Key.EcN)
                             .ThenBy(static item => item.Key.SckaEpoch)
                             .ThenBy(static item => item.Key.SckaN))
                {
                    WriteSkippedKey(encoded.AsSpan(offset, DurableSkippedKeySize), item.Value);
                    offset += DurableSkippedKeySize;
                }

                _stateCommitment.CopyTo(encoded, offset); offset += DurableStateCommitmentSize;
                checksum = MessagingKdf.Sha256Domain(DurableChecksumDomain, encoded.AsSpan(0, offset));
                checksum.CopyTo(encoded, offset); offset += DurableChecksumSize;
                if (offset != encoded.Length)
                    throw new MessagingCryptoException(
                        MessagingCryptoError.StateLimitExceeded,
                        "The durable ratchet state length accounting diverged.");

                MessagingCryptoFaultInjection.ManagedSecret("ratchet-state-codec.output", encoded);
                ownershipTransferred = true;
                return encoded;
            }
            finally
            {
                if (checksum is not null) CryptographicOperations.ZeroMemory(checksum);
                if (!ownershipTransferred) CryptographicOperations.ZeroMemory(encoded);
            }
        }
    }

    internal static TripleRatchetState ImportDurableState(ReadOnlySpan<byte> encoded)
    {
        ValidateDurableEncodingBeforeAllocation(encoded, out var parsed);

        SecretBuffer? component = null;
        Dictionary<RatchetCounterTuple, SkippedComponentKey>? skipped = null;
        TripleRatchetState? state = null;
        var ownershipTransferred = false;
        try
        {
            var binding = new RatchetStateBinding(
                parsed.Suite,
                encoded.Slice(parsed.BindingOffset, 32),
                encoded.Slice(parsed.BindingOffset + 32, 64),
                encoded.Slice(parsed.BindingOffset + 96, 32),
                parsed.LocalDeviceGeneration,
                encoded.Slice(parsed.BindingOffset + 136, 32),
                encoded.Slice(parsed.BindingOffset + 168, 32),
                parsed.RemoteDeviceGeneration,
                encoded.Slice(parsed.BindingOffset + 208, 32));

            if (parsed.ComponentLength != 0)
            {
                component = SecretBuffer.ImportBounded(
                    encoded.Slice(parsed.ComponentOffset, parsed.ComponentLength),
                    1,
                    MessagingCryptoConstants.MaximumOpaqueProviderStateBytes,
                    "durableComponentState");
                MessagingCryptoFaultInjection.OwnedSecret("ratchet-state-codec.component", component);
            }

            skipped = new Dictionary<RatchetCounterTuple, SkippedComponentKey>(parsed.SkippedCount);
            var skippedOffset = parsed.SkippedOffset;
            for (var index = 0; index < parsed.SkippedCount; index++)
            {
                var entry = encoded.Slice(skippedOffset, DurableSkippedKeySize);
                var counters = ReadCounter(entry);
                SecretBuffer? ec = null;
                SecretBuffer? pq = null;
                try
                {
                    ec = SecretBuffer.ImportExact(entry.Slice(56, 32), 32, "skippedEcKey");
                    pq = SecretBuffer.ImportExact(entry.Slice(88, 32), 32, "skippedPqKey");
                    var evidence = new PqStepEvidence(
                        entry.Slice(120, 32),
                        entry.Slice(152, 32),
                        entry[184] == 1);
                    skipped.Add(counters, new SkippedComponentKey(counters, ec, pq, evidence));
                    ec = null;
                    pq = null;
                }
                finally
                {
                    ec?.Dispose();
                    pq?.Dispose();
                }
                skippedOffset += DurableSkippedKeySize;
            }

            state = new TripleRatchetState(
                binding,
                component,
                parsed.ReceiveEcChain,
                parsed.NextExpectedReceiveEcN,
                parsed.SendEcChain,
                parsed.NextSendEcN,
                parsed.StorageGeneration,
                parsed.ReceiveMessagesSincePqInjection,
                parsed.SendMessagesSincePqInjection,
                parsed.ReceivePqFrontier,
                parsed.SendPqFrontier,
                encoded.Slice(parsed.ReceivePqCommitmentOffset, 32).ToArray(),
                encoded.Slice(parsed.SendPqCommitmentOffset, 32).ToArray(),
                parsed.MaximumMessagesWithoutPqInjection,
                skipped,
                parsed.IsTerminallyLatched);
            component = null;
            skipped = null;

            if (!MessagingCryptoValidation.FixedEquals(
                    state.StateCommitment.Span,
                    encoded.Slice(parsed.StateCommitmentOffset, DurableStateCommitmentSize)))
                throw new MessagingCryptoException(
                    MessagingCryptoError.CasConflict,
                    "The durable ratchet state commitment does not match its canonical contents.");

            MessagingCryptoFaultInjection.OwnedDisposable("ratchet-state-codec.imported-state", state);
            MessagingCryptoFaultInjection.Point("ratchet-state-codec.before-import-release");
            ownershipTransferred = true;
            return state;
        }
        finally
        {
            if (!ownershipTransferred) state?.Dispose();
            component?.Dispose();
            DisposeSkipped(skipped);
        }
    }

    private void ValidateDurableStateShape()
    {
        if (ReceiveEcChain.IsZero || SendEcChain.IsZero)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "Both durable EC chain identities must be nonzero X25519 public keys.");
        MessagingCryptoValidation.NonZeroExact(_receivePqStateCommitment, 32, "receivePqStateCommitment");
        MessagingCryptoValidation.NonZeroExact(_sendPqStateCommitment, 32, "sendPqStateCommitment");
        if (_maximumMessagesWithoutPqInjection is < 1 or > MessagingCryptoConstants.MaximumForwardGap ||
            ReceiveMessagesSincePqInjection < 0 ||
            ReceiveMessagesSincePqInjection > _maximumMessagesWithoutPqInjection ||
            SendMessagesSincePqInjection < 0 ||
            SendMessagesSincePqInjection > _maximumMessagesWithoutPqInjection)
            throw new MessagingCryptoException(
                MessagingCryptoError.StateLimitExceeded,
                "The durable PQ injection counters are outside their closed bounds.");
        if (IsTerminallyLatched != (_componentState is null) || IsTerminallyLatched && _skipped.Count != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.TerminallyLatched,
                "Only a terminal latch may omit all provider and skipped-key secrets.");
        if (_skipped.Count > MessagingCryptoConstants.MaximumSkippedKeys)
            throw new MessagingCryptoException(
                MessagingCryptoError.SkippedKeyLimitExceeded,
                "The durable skipped-key count exceeds 2048.");
        foreach (var item in _skipped)
        {
            if (item.Key != item.Value.Counters || item.Key.EcChain.IsZero ||
                item.Key.EcChain == ReceiveEcChain && item.Key.EcN >= NextExpectedReceiveEcN)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "A durable skipped key is not bound to a prior receive counter.");
        }
        _ = ComputeDurableEncodedLength(_componentState?.Length ?? 0, _skipped.Count);
    }

    private static void ValidateDurableEncodingBeforeAllocation(
        ReadOnlySpan<byte> encoded,
        out ParsedDurableState parsed)
    {
        if (encoded.Length < MinimumDurableEncodingSize ||
            encoded.Length > MessagingCryptoConstants.MaximumDurableRatchetStateBytes)
            throw new MessagingCryptoException(
                MessagingCryptoError.StateLimitExceeded,
                "The durable ratchet state is outside the exact 2 MiB bound.");
        if (!encoded[..4].SequenceEqual(DurableMagic) || encoded[4] != DurableVersion)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The durable ratchet state magic or version is unsupported.");

        var suite = BinaryPrimitives.ReadUInt16BigEndian(encoded[5..]);
        var flags = encoded[7];
        if (suite != MessagingCryptoConstants.Suite || (flags & ~TerminalLatchFlag) != 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The durable ratchet state suite or flags are non-canonical.");
        if (BinaryPrimitives.ReadUInt32BigEndian(encoded[8..]) != (uint)encoded.Length)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The durable ratchet state total length is non-canonical.");

        var bindingOffset = DurablePrefixSize;
        MessagingCryptoValidation.NonZeroExact(encoded.Slice(bindingOffset, 32), 32, "sessionId");
        MessagingCryptoValidation.NonZeroExact(encoded.Slice(bindingOffset + 32, 64), 64, "transcriptHash");
        MessagingCryptoValidation.NonZeroExact(encoded.Slice(bindingOffset + 96, 32), 32, "localDeviceId");
        var localGeneration = BinaryPrimitives.ReadUInt64BigEndian(encoded[(bindingOffset + 128)..]);
        MessagingCryptoValidation.NonZeroExact(encoded.Slice(bindingOffset + 136, 32), 32, "localDirectoryHead");
        MessagingCryptoValidation.NonZeroExact(encoded.Slice(bindingOffset + 168, 32), 32, "remoteDeviceId");
        var remoteGeneration = BinaryPrimitives.ReadUInt64BigEndian(encoded[(bindingOffset + 200)..]);
        MessagingCryptoValidation.NonZeroExact(encoded.Slice(bindingOffset + 208, 32), 32, "remoteDirectoryHead");
        if (localGeneration == 0 || remoteGeneration == 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "Durable device generations must be nonzero.");

        var offset = bindingOffset + RatchetStateBinding.DurableEncodingSize;
        var storageGeneration = BinaryPrimitives.ReadUInt64BigEndian(encoded[offset..]); offset += 8;
        var receiveEcChain = RatchetEcChainId.Read(encoded.Slice(offset, 32)); offset += 32;
        var nextReceive = BinaryPrimitives.ReadUInt64BigEndian(encoded[offset..]); offset += 8;
        var sendEcChain = RatchetEcChainId.Read(encoded.Slice(offset, 32)); offset += 32;
        var nextSend = BinaryPrimitives.ReadUInt64BigEndian(encoded[offset..]); offset += 8;
        var receiveSincePq = BinaryPrimitives.ReadInt32BigEndian(encoded[offset..]); offset += 4;
        var sendSincePq = BinaryPrimitives.ReadInt32BigEndian(encoded[offset..]); offset += 4;
        var receiveFrontier = ReadCounter(encoded.Slice(offset, 56)); offset += 56;
        var sendFrontier = ReadCounter(encoded.Slice(offset, 56)); offset += 56;
        var receivePqOffset = offset;
        MessagingCryptoValidation.NonZeroExact(encoded.Slice(offset, 32), 32, "receivePqStateCommitment"); offset += 32;
        var sendPqOffset = offset;
        MessagingCryptoValidation.NonZeroExact(encoded.Slice(offset, 32), 32, "sendPqStateCommitment"); offset += 32;
        var maximumWithoutPq = BinaryPrimitives.ReadInt32BigEndian(encoded[offset..]); offset += 4;
        var componentLengthValue = BinaryPrimitives.ReadUInt32BigEndian(encoded[offset..]); offset += 4;
        var skippedCountValue = BinaryPrimitives.ReadUInt32BigEndian(encoded[offset..]); offset += 4;

        if (receiveEcChain.IsZero || sendEcChain.IsZero)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "Durable EC chain identities must be nonzero.");
        if (maximumWithoutPq is < 1 or > MessagingCryptoConstants.MaximumForwardGap ||
            receiveSincePq < 0 || receiveSincePq > maximumWithoutPq ||
            sendSincePq < 0 || sendSincePq > maximumWithoutPq ||
            componentLengthValue > MessagingCryptoConstants.MaximumOpaqueProviderStateBytes ||
            skippedCountValue > MessagingCryptoConstants.MaximumSkippedKeys)
            throw new MessagingCryptoException(
                MessagingCryptoError.StateLimitExceeded,
                "A durable ratchet state count or provider length exceeds its closed bound.");

        var terminal = (flags & TerminalLatchFlag) != 0;
        var componentLength = checked((int)componentLengthValue);
        var skippedCount = checked((int)skippedCountValue);
        if (terminal ? componentLength != 0 || skippedCount != 0 : componentLength == 0)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The durable terminal-latch secret shape is non-canonical.");

        var exactLength = ComputeDurableEncodedLength(componentLength, skippedCount);
        if (exactLength != encoded.Length)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The durable ratchet state variable lengths are non-canonical.");

        var componentOffset = offset;
        var skippedOffset = checked(componentOffset + componentLength);
        RatchetCounterTuple? prior = null;
        for (var index = 0; index < skippedCount; index++)
        {
            var entry = encoded.Slice(skippedOffset + index * DurableSkippedKeySize, DurableSkippedKeySize);
            var counters = ReadCounter(entry);
            if (counters.EcChain.IsZero ||
                counters.EcChain == receiveEcChain && counters.EcN >= nextReceive ||
                prior.HasValue && CompareCounter(prior.Value, counters) >= 0)
                throw new MessagingCryptoException(
                    MessagingCryptoError.InvalidInput,
                    "Durable skipped keys must be unique, prior to the receive frontier, and canonically ordered.");
            MessagingCryptoValidation.NonZeroExact(entry.Slice(56, 32), 32, "skippedEcKey");
            MessagingCryptoValidation.NonZeroExact(entry.Slice(88, 32), 32, "skippedPqKey");
            MessagingCryptoValidation.NonZeroExact(entry.Slice(120, 32), 32, "skippedPriorPqCommitment");
            MessagingCryptoValidation.NonZeroExact(entry.Slice(152, 32), 32, "skippedNextPqCommitment");
            if (MessagingCryptoValidation.FixedEquals(entry.Slice(120, 32), entry.Slice(152, 32)) || entry[184] > 1)
                throw new MessagingCryptoException(
                    MessagingCryptoError.InvalidInput,
                    "A durable skipped-key evidence record is non-canonical.");
            prior = counters;
        }

        var stateCommitmentOffset = checked(skippedOffset + skippedCount * DurableSkippedKeySize);
        MessagingCryptoValidation.NonZeroExact(
            encoded.Slice(stateCommitmentOffset, DurableStateCommitmentSize),
            DurableStateCommitmentSize,
            "stateCommitment");

        // No provider or skipped-key owner is allocated before all hostile
        // lengths, counts, flags and canonical ordering have passed.
        var checksumOffset = encoded.Length - DurableChecksumSize;
        var expectedChecksum = MessagingKdf.Sha256Domain(DurableChecksumDomain, encoded[..checksumOffset]);
        try
        {
            if (!MessagingCryptoValidation.FixedEquals(expectedChecksum, encoded[checksumOffset..]))
                throw new MessagingCryptoException(
                    MessagingCryptoError.CasConflict,
                    "The durable ratchet state checksum does not match its exact bytes.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedChecksum);
        }
        MessagingCryptoFaultInjection.Point("ratchet-state-codec.validated-before-allocation");

        parsed = new ParsedDurableState(
            suite, terminal, bindingOffset, localGeneration, remoteGeneration,
            storageGeneration, receiveEcChain, nextReceive, sendEcChain, nextSend,
            receiveSincePq, sendSincePq,
            receiveFrontier, sendFrontier, receivePqOffset, sendPqOffset,
            maximumWithoutPq, componentOffset, componentLength, skippedOffset,
            skippedCount, stateCommitmentOffset);
    }

    private static int ComputeDurableEncodedLength(int componentLength, int skippedCount)
    {
        if (componentLength < 0 ||
            componentLength > MessagingCryptoConstants.MaximumOpaqueProviderStateBytes ||
            skippedCount < 0 || skippedCount > MessagingCryptoConstants.MaximumSkippedKeys)
            throw new MessagingCryptoException(
                MessagingCryptoError.StateLimitExceeded,
                "The durable ratchet state cardinality is outside its closed bounds.");
        var total = checked((long)MinimumDurableEncodingSize + componentLength +
                            (long)skippedCount * DurableSkippedKeySize);
        if (total > MessagingCryptoConstants.MaximumDurableRatchetStateBytes)
            throw new MessagingCryptoException(
                MessagingCryptoError.StateLimitExceeded,
                "The complete durable ratchet state exceeds 2 MiB.");
        return checked((int)total);
    }

    private static void WriteCounter(Span<byte> destination, RatchetCounterTuple counters)
    {
        counters.EcChain.Write(destination[..32]);
        BinaryPrimitives.WriteUInt64BigEndian(destination[32..], counters.EcN);
        BinaryPrimitives.WriteUInt64BigEndian(destination[40..], counters.SckaEpoch);
        BinaryPrimitives.WriteUInt64BigEndian(destination[48..], counters.SckaN);
    }

    private static RatchetCounterTuple ReadCounter(ReadOnlySpan<byte> source) => new(
        RatchetEcChainId.Read(source[..32]),
        BinaryPrimitives.ReadUInt64BigEndian(source[32..]),
        BinaryPrimitives.ReadUInt64BigEndian(source[40..]),
        BinaryPrimitives.ReadUInt64BigEndian(source[48..]));

    private static int CompareCounter(RatchetCounterTuple left, RatchetCounterTuple right)
    {
        var chainA = left.EcChain.A.CompareTo(right.EcChain.A);
        if (chainA != 0) return chainA;
        var chainB = left.EcChain.B.CompareTo(right.EcChain.B);
        if (chainB != 0) return chainB;
        var chainC = left.EcChain.C.CompareTo(right.EcChain.C);
        if (chainC != 0) return chainC;
        var chainD = left.EcChain.D.CompareTo(right.EcChain.D);
        if (chainD != 0) return chainD;
        var ec = left.EcN.CompareTo(right.EcN);
        if (ec != 0) return ec;
        var epoch = left.SckaEpoch.CompareTo(right.SckaEpoch);
        return epoch != 0 ? epoch : left.SckaN.CompareTo(right.SckaN);
    }

    private static void WriteSkippedKey(Span<byte> destination, SkippedComponentKey skipped)
    {
        WriteCounter(destination, skipped.Counters);
        skipped.Ec.CopyTo(destination.Slice(56, 32));
        skipped.Pq.CopyTo(destination.Slice(88, 32));
        skipped.Evidence.PriorStateCommitment.CopyTo(destination.Slice(120, 32));
        skipped.Evidence.NextStateCommitment.CopyTo(destination.Slice(152, 32));
        destination[184] = skipped.Evidence.HasFreshContribution ? (byte)1 : (byte)0;
    }

    private sealed record ParsedDurableState(
        ushort Suite,
        bool IsTerminallyLatched,
        int BindingOffset,
        ulong LocalDeviceGeneration,
        ulong RemoteDeviceGeneration,
        ulong StorageGeneration,
        RatchetEcChainId ReceiveEcChain,
        ulong NextExpectedReceiveEcN,
        RatchetEcChainId SendEcChain,
        ulong NextSendEcN,
        int ReceiveMessagesSincePqInjection,
        int SendMessagesSincePqInjection,
        RatchetCounterTuple ReceivePqFrontier,
        RatchetCounterTuple SendPqFrontier,
        int ReceivePqCommitmentOffset,
        int SendPqCommitmentOffset,
        int MaximumMessagesWithoutPqInjection,
        int ComponentOffset,
        int ComponentLength,
        int SkippedOffset,
        int SkippedCount,
        int StateCommitmentOffset);
}
