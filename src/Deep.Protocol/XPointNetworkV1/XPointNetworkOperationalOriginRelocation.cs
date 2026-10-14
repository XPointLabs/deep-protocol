using System.Net;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Copied address/port intent for one authenticated predecessor origin.
/// Not a signed record, current authority or permission to translate a client plan.</summary>
public sealed class XPointNetworkOperationalOriginRelocation
{
    private readonly byte[] originId;
    private readonly byte[] address;

    public XPointNetworkOperationalOriginRelocation(ReadOnlySpan<byte> originId, IPAddress address, ushort port)
    {
        if (originId.Length != 32 || originId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An origin ID must be nonzero32.", nameof(originId));
        ArgumentNullException.ThrowIfNull(address);
        AddressFamily = address.AddressFamily switch
        {
            System.Net.Sockets.AddressFamily.InterNetwork => 4,
            System.Net.Sockets.AddressFamily.InterNetworkV6 when address.ScopeId == 0 => 6,
            _ => throw new ArgumentException("An origin address must be unscoped IPv4 or IPv6.", nameof(address))
        };
        this.address = new byte[16];
        address.GetAddressBytes().CopyTo(this.address, 0);
        if (this.address.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An origin address must be nonzero.", nameof(address));
        if (port == 0) throw new ArgumentOutOfRangeException(nameof(port));
        this.originId = originId.ToArray();
        Port = port;
    }

    public ReadOnlyMemory<byte> OriginId => originId.ToArray();
    public byte AddressFamily { get; }
    public ReadOnlyMemory<byte> Address => address.ToArray();
    public ushort Port { get; }
}
