using System.Security.Cryptography;

namespace Deep.Protocol.ContactV2;

/// <summary>An exact authenticated retained threshold starts inside the current
/// uncertainty interval. This permits bounded scheduling only, never use of the
/// threshold before its signed start. Full verification must run again.</summary>
public sealed class DeepIdV2RouteNotBeforeException : CryptographicException
{
    internal DeepIdV2RouteNotBeforeException(uint requiredDelaySeconds)
        : base("The exact retained route threshold requires bounded time convergence.")
    {
        if (requiredDelaySeconds == 0) throw new ArgumentOutOfRangeException(nameof(requiredDelaySeconds));
        RequiredDelaySeconds = requiredDelaySeconds;
    }

    /// <summary>Minimum natural advance of the final trusted lower bound, in
    /// whole seconds. The original deadline, cancellation and actual currentness
    /// checks still bound any wait; this duration grants no authority.</summary>
    public uint RequiredDelaySeconds { get; }
}
