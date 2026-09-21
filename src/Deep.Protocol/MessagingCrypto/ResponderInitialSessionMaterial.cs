using System.Security.Cryptography;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// Authenticated DPH2 events and the matching initial ratchet state. This is
/// not an ACK authority: the caller must durably commit all three together.
/// </summary>
public sealed class ResponderInitialSessionMaterial : IDisposable
{
    private readonly byte[] _exactTrs1;
    private readonly byte[] _sessionInitDmc2;
    private readonly byte[]? _firstApplicationDmc2;
    private int _disposed;

    internal ResponderInitialSessionMaterial(
        ReadOnlySpan<byte> exactTrs1,
        ReadOnlySpan<byte> sessionInitDmc2,
        ReadOnlySpan<byte> firstApplicationDmc2)
    {
        _exactTrs1 = exactTrs1.ToArray();
        _sessionInitDmc2 = sessionInitDmc2.ToArray();
        _firstApplicationDmc2 = firstApplicationDmc2.IsEmpty
            ? null : firstApplicationDmc2.ToArray();
    }

    public ReadOnlyMemory<byte> ExactTrs1 => Copy(_exactTrs1);
    public ReadOnlyMemory<byte> SessionInitDmc2 => Copy(_sessionInitDmc2);
    public ReadOnlyMemory<byte> FirstApplicationDmc2
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return _firstApplicationDmc2 is null
                ? ReadOnlyMemory<byte>.Empty : Copy(_firstApplicationDmc2);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        CryptographicOperations.ZeroMemory(_exactTrs1);
        CryptographicOperations.ZeroMemory(_sessionInitDmc2);
        if (_firstApplicationDmc2 is not null)
            CryptographicOperations.ZeroMemory(_firstApplicationDmc2);
    }

    private ReadOnlyMemory<byte> Copy(byte[] value)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return value.ToArray();
    }
}
