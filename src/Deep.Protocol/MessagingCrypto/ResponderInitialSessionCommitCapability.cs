namespace Deep.Protocol.MessagingCrypto;

/// <summary>One transfer of authenticated initial state and its matching
/// device-prekey facts. Preparation alone authorizes neither storage nor ACK.</summary>
public sealed class ResponderInitialSessionCommitCapability : IDisposable
{
    private readonly object gate = new();
    private ResponderInitialSessionMaterial? material;
    private VerifiedDevicePreKeyClaimReservation? reservation;
    private bool consumed;

    internal ResponderInitialSessionCommitCapability(ResponderInitialSessionMaterial material,
        VerifiedDevicePreKeyClaimReservation reservation)
    {
        this.material = material; this.reservation = reservation;
    }

    public ReadOnlyMemory<byte> SessionId { get { lock (gate) return RequireReservation().SessionId; } }
    public ReadOnlyMemory<byte> ClaimOperationId { get { lock (gate) return RequireReservation().OperationId; } }

    public ResponderInitialSessionAtomicStorePayload ConsumeForAtomicStore()
    {
        lock (gate)
        {
            if (consumed) throw new InvalidOperationException("The responder commit capability is single-use.");
            var ownedReservation = RequireReservation();
            var ownedMaterial = material ?? throw new ObjectDisposedException(GetType().Name);
            var payload = new ResponderInitialSessionAtomicStorePayload(ownedMaterial, ownedReservation);
            consumed = true; material = null; reservation = null;
            return payload;
        }
    }

    private VerifiedDevicePreKeyClaimReservation RequireReservation() =>
        reservation ?? throw new ObjectDisposedException(GetType().Name);

    public void Dispose()
    {
        lock (gate)
        {
            material?.Dispose(); material = null;
            reservation?.Dispose(); reservation = null;
        }
        GC.SuppressFinalize(this);
    }

    ~ResponderInitialSessionCommitCapability() => Dispose();
}

/// <summary>Secret-bearing input to the authenticated atomic responder store.
/// Exact state/events and matching reservation must be committed together.</summary>
public sealed class ResponderInitialSessionAtomicStorePayload : IDisposable
{
    private readonly object gate = new();
    private ResponderInitialSessionMaterial? material;
    private VerifiedDevicePreKeyClaimReservation? reservation;

    internal ResponderInitialSessionAtomicStorePayload(ResponderInitialSessionMaterial material,
        VerifiedDevicePreKeyClaimReservation reservation)
    {
        this.material = material; this.reservation = reservation;
    }

    public VerifiedDevicePreKeyClaimReservation Reservation
    {
        get { lock (gate) return reservation ?? throw new ObjectDisposedException(GetType().Name); }
    }
    public ReadOnlyMemory<byte> ExactTrs1 { get { lock (gate) return RequireMaterial().ExactTrs1; } }
    public ReadOnlyMemory<byte> SessionInitDmc2 { get { lock (gate) return RequireMaterial().SessionInitDmc2; } }
    public ReadOnlyMemory<byte> FirstApplicationDmc2 { get { lock (gate) return RequireMaterial().FirstApplicationDmc2; } }
    private ResponderInitialSessionMaterial RequireMaterial() =>
        material ?? throw new ObjectDisposedException(GetType().Name);

    public void Dispose()
    {
        lock (gate)
        {
            material?.Dispose(); material = null;
            reservation?.Dispose(); reservation = null;
        }
        GC.SuppressFinalize(this);
    }

    ~ResponderInitialSessionAtomicStorePayload() => Dispose();
}
