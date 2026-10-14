using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.MessagingCrypto;

internal sealed class BraidRecoveryComponentTransition : IDisposable
{
    private SecretBuffer? next;
    internal BraidRecoveryComponentTransition(byte[]? nextOpaque, UnverifiedDbr2Record control, bool replay)
    {
        if (nextOpaque is not null) next = SecretBuffer.ImportBounded(nextOpaque, 1,
            MessagingCryptoConstants.MaximumOpaqueProviderStateBytes, nameof(nextOpaque));
        Control = control; IsExactReplay = replay;
    }
    internal UnverifiedDbr2Record Control { get; }
    internal bool IsExactReplay { get; }
    internal SecretBuffer TakeNextState() => Interlocked.Exchange(ref next, null) ??
        throw new MessagingCryptoException(MessagingCryptoError.CapabilityConsumed, "Control successor is absent or consumed.");
    public void Dispose() => Interlocked.Exchange(ref next, null)?.Dispose();
}

internal sealed partial class ManagedTripleRatchetComponentProvider
{
    internal bool TryVerifyObsoleteBraidControl(ReadOnlySpan<byte> opaque, RatchetStateBinding binding,
        ReadOnlySpan<byte> network, UnverifiedDbr2Record frame)
    {
        ThrowIfDisposed(); MessagingCryptoValidation.NonZeroExact(network, 16, nameof(network));
        if (!MessagingCryptoValidation.FixedEquals(network, frame.NetworkId.Span) ||
            !MessagingCryptoValidation.FixedEquals(binding.SessionId.Span, frame.SessionId.Span) ||
            !MessagingCryptoValidation.FixedEquals(binding.RemoteDeviceId.Span, frame.SenderDeviceId.Span) ||
            !MessagingCryptoValidation.FixedEquals(binding.LocalDeviceId.Span, frame.RecipientDeviceId.Span) ||
            frame.ControlCounter != ManagedBraidControlProfile.Slot(frame.BraidMessage.Kind))
            throw Transition("Obsolete control has a different owned scope/direction/slot.");
        using var state = ComponentState.Import(_braidProvider, opaque);
        return state.TryVerifyObsoleteControl(frame);
    }

    internal BraidRecoveryComponentTransition PrepareBraidControlSend(ReadOnlySpan<byte> opaque,
        RatchetStateBinding binding, ReadOnlySpan<byte> network, ReadOnlySpan<byte> operation)
    {
        ThrowIfDisposed();
        MessagingCryptoValidation.NonZeroExact(network, 16, nameof(network));
        MessagingCryptoValidation.NonZeroExact(operation, 32, nameof(operation));
        using var state = ComponentState.Import(_braidProvider, opaque);
        state.RequireNewControlOperation(operation);
        var epoch = state.Braid.Epoch;
        var braid = state.Braid.Send();
        var slot = ManagedBraidControlProfile.Slot(braid.Kind);
        var link = state.FindLink(epoch - 1);
        link.RequireEmptySendSlot(slot);
        var frame = ManagedBraidControlProfile.CreateUnsigned(binding, network, operation, epoch, slot, braid);
        var mac = link.AuthenticateControl(frame);
        byte[]? next = null;
        try
        {
            var exact = Dbr2Codec.Encode(frame);
            mac.CopyTo(exact, exact.Length - 32);
            frame = Dbr2Codec.Decode(exact);
            link.RecordControlSend(slot, operation);
            next = state.Export();
            return new(next, frame, false);
        }
        finally { Zero(next); Zero(mac); }
    }

    internal BraidRecoveryComponentTransition PrepareBraidControlReceive(ReadOnlySpan<byte> opaque,
        RatchetStateBinding binding, ReadOnlySpan<byte> network, UnverifiedDbr2Record frame)
    {
        ThrowIfDisposed();
        MessagingCryptoValidation.NonZeroExact(network, 16, nameof(network));
        if (!MessagingCryptoValidation.FixedEquals(network, frame.NetworkId.Span) ||
            !MessagingCryptoValidation.FixedEquals(binding.SessionId.Span, frame.SessionId.Span) ||
            !MessagingCryptoValidation.FixedEquals(binding.RemoteDeviceId.Span, frame.SenderDeviceId.Span) ||
            !MessagingCryptoValidation.FixedEquals(binding.LocalDeviceId.Span, frame.RecipientDeviceId.Span) ||
            frame.ControlCounter != ManagedBraidControlProfile.Slot(frame.BraidMessage.Kind))
            throw Transition("Control network/session/device direction or fixed flight slot is not current.");
        using var state = ComponentState.Import(_braidProvider, opaque);
        var link = state.FindLink(frame.BraidEpoch - 1);
        var mac = link.AuthenticateControl(frame);
        try
        {
            if (!MessagingCryptoValidation.FixedEquals(mac, frame.Authenticator.Span))
                throw new CryptographicException("Braid control authentication failed.");
        }
        finally { Zero(mac); }
        var hash = SHA256.HashData(frame.CanonicalBytes.Span);
        var operation = frame.OperationId.ToArray();
        byte[]? next = null;
        try
        {
            if (link.IsExactReceivedControl(frame.ControlCounter, operation, hash))
                return new(null, frame, true);
            state.RequireNewControlOperation(operation);
            using var fresh = state.Braid.ReceiveRecoveryControl(frame.BraidEpoch, frame.BraidMessage);
            if (fresh is not null) fresh.Use(value => state.AddSpqrEpoch(frame.BraidEpoch, value));
            link.RecordControlReceive(frame.ControlCounter, operation, hash);
            next = state.Export();
            return new(next, frame, false);
        }
        finally { Zero(next); Zero(operation); Zero(hash); }
    }

    private sealed partial class ComponentState
    {
        internal bool TryVerifyObsoleteControl(UnverifiedDbr2Record frame)
        {
            if (CurrentSpqrEpoch < frame.BraidEpoch) return false;
            var link = _links.SingleOrDefault(value => value.Epoch == frame.BraidEpoch - 1);
            if (link is null) return false;
            var mac = link.AuthenticateControl(frame);
            try
            {
                if (!MessagingCryptoValidation.FixedEquals(mac, frame.Authenticator.Span))
                    throw new CryptographicException("Obsolete control authentication failed.");
            }
            finally { Zero(mac); }
            var hash = SHA256.HashData(frame.CanonicalBytes.Span);
            try
            {
                if (link.IsExactReceivedControl(frame.ControlCounter, frame.OperationId.Span, hash))
                    throw Replay("Native control replay requires its exact retained durable record.");
                RequireNewControlOperation(frame.OperationId.Span);
                // Read-only disposal proof. Do not call Braid.Receive or record
                // a slot; the obsolete inner flight is NOT a native receive.
                return true;
            }
            finally { Zero(hash); }
        }

        internal void RequireNewControlOperation(ReadOnlySpan<byte> operation)
        {
            foreach (var link in _links)
                if (link.HasControlOperation(operation))
                    throw Replay("Control operation already belongs to a retained slot; retry its exact saved frame.");
        }
        private void ValidateControlOperations()
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var link in _links)
                foreach (var operation in link.ControlOperations())
                    if (!seen.Add(Convert.ToHexString(operation.Span))) throw InvalidStateEncoding();
        }
    }

    private sealed partial class SpqrLink
    {
        private readonly byte[] _controlRoot;
        private readonly byte[] _controlSendOperations = new byte[64];
        private readonly byte[] _controlReceiveOperations = new byte[64];
        private readonly byte[] _controlReceiveHashes = new byte[64];
        private byte _controlSendMask, _controlReceiveMask;

        internal byte[] AuthenticateControl(UnverifiedDbr2Record frame) =>
            ManagedBraidControlProfile.ComputeAuthenticator(_controlRoot, frame);
        internal void RequireEmptySendSlot(byte slot)
        {
            if ((_controlSendMask & Bit(slot)) != 0)
                throw Replay("Braid control slot is already committed; retry the original durable frame.");
        }
        internal void RecordControlSend(byte slot, ReadOnlySpan<byte> operation)
        {
            RequireEmptySendSlot(slot);
            operation.CopyTo(_controlSendOperations.AsSpan((slot - 1) * 32, 32));
            _controlSendMask |= Bit(slot);
        }
        internal bool IsExactReceivedControl(byte slot, ReadOnlySpan<byte> operation, ReadOnlySpan<byte> hash)
        {
            if ((_controlReceiveMask & Bit(slot)) == 0) return false;
            var offset = (slot - 1) * 32;
            if (!MessagingCryptoValidation.FixedEquals(operation, _controlReceiveOperations.AsSpan(offset, 32)) ||
                !MessagingCryptoValidation.FixedEquals(hash, _controlReceiveHashes.AsSpan(offset, 32)))
                throw Replay("Changed Braid control in a retained slot.");
            return true;
        }
        internal void RecordControlReceive(byte slot, ReadOnlySpan<byte> operation, ReadOnlySpan<byte> hash)
        {
            operation.CopyTo(_controlReceiveOperations.AsSpan((slot - 1) * 32, 32));
            hash.CopyTo(_controlReceiveHashes.AsSpan((slot - 1) * 32, 32));
            _controlReceiveMask |= Bit(slot);
        }
        internal bool HasControlOperation(ReadOnlySpan<byte> operation)
        {
            for (byte slot = 1; slot <= 2; slot++)
            {
                var offset = (slot - 1) * 32;
                if ((_controlSendMask & Bit(slot)) != 0 && MessagingCryptoValidation.FixedEquals(operation, _controlSendOperations.AsSpan(offset, 32)) ||
                    (_controlReceiveMask & Bit(slot)) != 0 && MessagingCryptoValidation.FixedEquals(operation, _controlReceiveOperations.AsSpan(offset, 32)))
                    return true;
            }
            return false;
        }
        internal IEnumerable<ReadOnlyMemory<byte>> ControlOperations()
        {
            for (byte slot = 1; slot <= 2; slot++)
            {
                if ((_controlSendMask & Bit(slot)) != 0) yield return _controlSendOperations.AsMemory((slot - 1) * 32, 32);
                if ((_controlReceiveMask & Bit(slot)) != 0) yield return _controlReceiveOperations.AsMemory((slot - 1) * 32, 32);
            }
        }
        private void WriteControl(Span<byte> output)
        {
            _controlRoot.CopyTo(output[96..128]); output[128] = _controlSendMask; output[129] = _controlReceiveMask;
            _controlSendOperations.CopyTo(output[136..200]);
            _controlReceiveOperations.CopyTo(output[200..264]); _controlReceiveHashes.CopyTo(output[264..328]);
        }
        private static void ValidateControlEncoding(ReadOnlySpan<byte> input)
        {
            if (MessagingCryptoValidation.IsZero(input[96..128]) || (input[128] & ~3) != 0 ||
                (input[129] & ~3) != 0 || !MessagingCryptoValidation.IsZero(input[130..136]))
                throw ComponentState.InvalidStateEncoding();
            for (byte slot = 1; slot <= 2; slot++)
            {
                var offset = (slot - 1) * 32;
                ComponentState.ValidateOptional((input[128] & Bit(slot)) != 0, input.Slice(136 + offset, 32));
                ComponentState.ValidateOptional((input[129] & Bit(slot)) != 0, input.Slice(200 + offset, 32));
                ComponentState.ValidateOptional((input[129] & Bit(slot)) != 0, input.Slice(264 + offset, 32));
            }
        }
        private void ReadControl(ReadOnlySpan<byte> input)
        {
            _controlSendMask = input[128]; _controlReceiveMask = input[129];
            input[136..200].CopyTo(_controlSendOperations); input[200..264].CopyTo(_controlReceiveOperations);
            input[264..328].CopyTo(_controlReceiveHashes);
        }
        private void DisposeControl()
        {
            Zero(_controlRoot); Zero(_controlSendOperations); Zero(_controlReceiveOperations); Zero(_controlReceiveHashes);
            _controlSendMask = _controlReceiveMask = 0;
        }
        private static byte Bit(byte slot) => slot is 1 or 2 ? (byte)(1 << (slot - 1)) :
            throw Transition("Control slot is outside the fixed flight bound.");
    }
}
