using System.Security.Cryptography;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>Single-use selection between live state and terminal expired
/// custody. Selection alone is neither durable consumption nor ACK authority.</summary>
public sealed class ResponderInitialMailboxPreparation : IDisposable
{
    private readonly object gate = new();
    private ResponderInitialSessionCommitCapability? live;
    private ResponderExpiredInitialAtomicStorePayload? expired;
    private bool consumed;

    internal ResponderInitialMailboxPreparation(ResponderInitialSessionCommitCapability live) => this.live = live;
    internal ResponderInitialMailboxPreparation(ResponderExpiredInitialAtomicStorePayload expired) => this.expired = expired;

    public bool IsExpired { get { lock (gate) { RequireAvailable(); return expired is not null; } } }
    public ResponderInitialSessionCommitCapability ConsumeLive()
    {
        lock (gate)
        {
            RequireAvailable();
            var result = live ?? throw new InvalidOperationException("Expired custody cannot become a live session.");
            consumed = true; live = null; return result;
        }
    }
    public ResponderExpiredInitialAtomicStorePayload ConsumeExpiredForAtomicStore()
    {
        lock (gate)
        {
            RequireAvailable();
            var result = expired ?? throw new InvalidOperationException("A live session cannot be relabeled expired.");
            consumed = true; expired = null; return result;
        }
    }
    private void RequireAvailable()
    {
        if (consumed || live is null && expired is null)
            throw new InvalidOperationException("Initial mailbox preparation is unavailable or already consumed.");
    }
    public void Dispose()
    {
        lock (gate) { live?.Dispose(); expired?.Dispose(); live = null; expired = null; consumed = true; }
        GC.SuppressFinalize(this);
    }
    ~ResponderInitialMailboxPreparation() => Dispose();
}

/// <summary>Authenticated terminal atomic-store input. Contains no ratchet
/// state or keys. The native owner must commit exact events, reservation and
/// expiry proof together; this object does not authorize an ACK.</summary>
public sealed class ResponderExpiredInitialAtomicStorePayload : IDisposable
{
    private readonly object gate = new();
    private VerifiedDevicePreKeyClaimReservation? reservation;
    private byte[]? init, hello, hash;
    private readonly ulong lower;
    internal ResponderExpiredInitialAtomicStorePayload(VerifiedDevicePreKeyClaimReservation reservation,
        ReadOnlySpan<byte> init, ReadOnlySpan<byte> hello, ReadOnlySpan<byte> discardedStateHash, ulong lower)
    {
        this.reservation = reservation; this.init = init.ToArray(); this.hello = hello.ToArray();
        hash = discardedStateHash.ToArray(); this.lower = lower;
    }
    public VerifiedDevicePreKeyClaimReservation Reservation
    { get { lock (gate) return reservation ?? throw new ObjectDisposedException(GetType().Name); } }
    public ReadOnlyMemory<byte> SessionInitDmc2 { get { lock (gate) return Require(init).ToArray(); } }
    public ReadOnlyMemory<byte> FirstApplicationDmc2 { get { lock (gate) return Require(hello).ToArray(); } }
    public ReadOnlyMemory<byte> DiscardedStateHash { get { lock (gate) return Require(hash).ToArray(); } }
    public ulong ProvenLowerUnixSeconds { get { lock (gate) { _ = Require(hash); return lower; } } }
    private static byte[] Require(byte[]? value) => value ?? throw new ObjectDisposedException(nameof(ResponderExpiredInitialAtomicStorePayload));
    public void Dispose()
    {
        lock (gate)
        {
            reservation?.Dispose(); reservation = null;
            foreach (var value in new[] { init, hello, hash }) if (value is not null) CryptographicOperations.ZeroMemory(value);
            init = null; hello = null; hash = null;
        }
        GC.SuppressFinalize(this);
    }
    ~ResponderExpiredInitialAtomicStorePayload() => Dispose();
}
