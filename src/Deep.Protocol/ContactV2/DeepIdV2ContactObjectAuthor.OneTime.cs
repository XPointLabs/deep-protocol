using System.Security.Cryptography;
using Deep.Protocol.Identity;

namespace Deep.Protocol.ContactV2;

/// <summary>Secret-bearing local candidate; not publication, consent or redemption authority.</summary>
public sealed class AuthoredDeepIdV2OneTimeContactObject : IDisposable
{
    private readonly object sync = new();
    private readonly byte[] invitation, ciphertext, locator, publicLocator;
    private bool disposed;
    internal AuthoredDeepIdV2OneTimeContactObject(ParsedDcr1V2 closure, byte[] invitation, byte[] ciphertext)
    {
        Closure = closure; this.invitation = invitation.ToArray(); this.ciphertext = ciphertext.ToArray();
        locator = DeepIdV2OneTimeObjectProtection.ComputeLocator(invitation);
        publicLocator = Deep.Protocol.ContactV1.ContactCodec.Decode(ProtocolMagic.DIA1, invitation).Field(5).ToArray();
    }
    public ParsedDcr1V2 Closure { get; }
    /// <summary>Caller-owned secret bytes: retain only in protected account custody, never logs/coordination.</summary>
    public ReadOnlyMemory<byte> ExactInvitation { get { lock (sync) { ThrowIfDisposed(); return invitation.ToArray(); } } }
    public ReadOnlyMemory<byte> ProtectedDcr1 { get { lock (sync) { ThrowIfDisposed(); return ciphertext.ToArray(); } } }
    public ReadOnlyMemory<byte> LocatorHash { get { lock (sync) { ThrowIfDisposed(); return locator.ToArray(); } } }
    internal ReadOnlyMemory<byte> PublicLocator { get { lock (sync) { ThrowIfDisposed(); return publicLocator.ToArray(); } } }
    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return;
            disposed = true;
            CryptographicOperations.ZeroMemory(invitation);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(locator);
            CryptographicOperations.ZeroMemory(publicLocator);
        }
    }
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed, this);
}

public static partial class DeepIdV2ContactObjectAuthor
{
    public static async ValueTask<AuthoredDeepIdV2OneTimeContactObject> AuthorOneTimeGenesisAsync(
        VerifiedDeepIdV2ContactRouteClosure route, OwnedGenesisDeviceSecrets device,
        IReadOnlyList<ParsedXps1V2> preKeyServices, string profileName,
        CancellationToken cancellationToken = default)
    {
        var closure = await AuthorClosureCoreAsync(route, device, preKeyServices, profileName,
            null, null, 2, cancellationToken).ConfigureAwait(false);
        var invitation = DeepIdV2OneTimeObjectProtection.CreateInvitation(closure);
        byte[]? ciphertext = null;
        try
        {
            ciphertext = DeepIdV2OneTimeObjectProtection.Seal(closure, invitation);
            cancellationToken.ThrowIfCancellationRequested();
            return new(closure, invitation, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(invitation);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static async ValueTask<AuthoredDeepIdV2OneTimeContactObject> RestoreOneTimeAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> exactDcr1,
        ReadOnlyMemory<byte> exactInvitation, ReadOnlyMemory<byte> protectedDcr1,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(route); cancellationToken.ThrowIfCancellationRequested();
        // Decode/bound all inputs before allocation or an asynchronous clock read.
        var closure = DeepIdV2ResolverClosureCodec.Decode(exactDcr1.Span);
        if (exactInvitation.Length != 225 || protectedDcr1.Length != closure.CanonicalBytes.Length + 40)
            throw new CryptographicException("One-time retained object lengths are not exact.");
        var invitation = exactInvitation.ToArray(); var ciphertext = protectedDcr1.ToArray();
        try
        {
            var opened = DeepIdV2OneTimeObjectProtection.Open(ciphertext, invitation);
            if (!Fixed(opened.CanonicalBytes.Span, closure.CanonicalBytes.Span))
                throw new CryptographicException("One-time ciphertext differs from exact retained custody.");
            var first = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
            RequireObject(route, closure, first, 2);
            var final = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
            RequireContinuous(first, final); RequireObject(route, closure, final, 2);
            cancellationToken.ThrowIfCancellationRequested();
            return new(closure, invitation, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(invitation); CryptographicOperations.ZeroMemory(ciphertext);
        }
    }
}
