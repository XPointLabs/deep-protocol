using System.Security.Cryptography;

namespace Deep.Protocol.ContactV2;

/// <summary>Closed field names for a current route-context refusal. No record values are disclosed.</summary>
public enum DeepIdV2RouteContextCheck
{
    NetworkAuthority, RecipientNetwork, ViewAuthority, HeadAuthority,
    DirectoryAuthority, TimeAuthority, DirectoryWitnessPolicy, TimeWitnessPolicy,
    DirectoryHead, ViewHash, ViewGeneration, ClockBoot, ClockRegression, ObservationExpiry
}

/// <summary>A Protocol-produced refusal of an exact current route-context binding.</summary>
public sealed class DeepIdV2RouteContextException : CryptographicException
{
    internal DeepIdV2RouteContextException(DeepIdV2RouteContextCheck check)
        : base($"DID2 current route context failed ({check}).")
    {
        Check = check;
        Data["Deep.ContactRoute.Phase"] = "CurrentContext";
        Data["Deep.ContactRoute.Check"] = check.ToString();
    }

    /// <summary>Gets the exact failed field predicate, without its values.</summary>
    public DeepIdV2RouteContextCheck Check { get; }
}
