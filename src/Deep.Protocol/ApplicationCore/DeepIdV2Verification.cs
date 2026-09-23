using System.Buffers.Binary;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.ApplicationCore;

/// <summary>
/// A pure-message ML-DSA-65 verifier. Implementations must authenticate their
/// native implementation and return false on malformed keys or signatures.
/// </summary>
public interface IDeepMlDsa65Verifier
{
    bool Verify(
        ReadOnlySpan<byte> publicKey1952,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> context,
        ReadOnlySpan<byte> signature3309);
}

public sealed class VerifiedDab2
{
    internal VerifiedDab2(
        ParsedDab2 record,
        ParsedDid2 deepId,
        VerifiedApplicationIdentityClosure identity)
    {
        Record = record;
        DeepId = deepId;
        Identity = identity;
    }

    public ParsedDab2 Record { get; }
    public ParsedDid2 DeepId { get; }
    public VerifiedApplicationIdentityClosure Identity { get; }
}

public sealed class Dab2LineageState
{
    internal Dab2LineageState(VerifiedDab2 head, bool forkLatched)
    {
        Head = head;
        ForkLatched = forkLatched;
    }

    public VerifiedDab2 Head { get; }
    public bool ForkLatched { get; }
}

public sealed class Dab2LineageTransitionPlan
{
    internal Dab2LineageTransitionPlan(Dab2LineageState previous,
        Dab2LineageState next, ApplicationLineageDisposition disposition)
    {
        Previous = previous;
        Next = next;
        Disposition = disposition;
    }

    public Dab2LineageState Previous { get; }
    public Dab2LineageState Next { get; }
    public ApplicationLineageDisposition Disposition { get; }
}

/// <summary>
/// Promotes a parsed binding only after exact DPA1 closure and all three
/// independent signatures have been checked. No DID1/DAB1 fallback exists.
/// </summary>
public static class DeepIdV2Verifier
{
    private static ReadOnlySpan<byte> PqContext => "Deep/DAB2/V2/root"u8;

    public static VerifiedDab2 VerifyDab2(
        ParsedDab2 parsed,
        ParsedDid2 deepId,
        VerifiedApplicationIdentityClosure identity,
        ushort deploymentProfileId,
        IDeepMlDsa65Verifier mlDsa65)
    {
        ArgumentNullException.ThrowIfNull(parsed);
        ArgumentNullException.ThrowIfNull(deepId);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(mlDsa65);

        var account = identity.Account;
        var realm = DeepIdV2Codec.DeriveIdentityRealmId(
            account.Certificate.NetworkId.Span, deploymentProfileId);
        var certificate = account.Certificate;
        if (!parsed.ExactDid2Hash.Span.SequenceEqual(deepId.RecordHash.Span) ||
            !parsed.IdentityRealmId.Span.SequenceEqual(realm) ||
            !parsed.DeepAccountId.Span.SequenceEqual(account.DeepAccountIdHash.Span) ||
            parsed.AccountGeneration != certificate.AccountGeneration ||
            parsed.Dpa1Reference.TypeCode != (ushort)certificate.ArtifactType ||
            parsed.Dpa1Reference.CanonicalLength != certificate.CanonicalBytes.Length ||
            !parsed.Dpa1Reference.CanonicalHash.Span.SequenceEqual(certificate.CanonicalHash.Span))
            Reject("DAB2 does not close over the exact DID2/DPA1 identity realm.");

        if (!PublicKeyAuth.VerifyDetached(
                parsed.RootEd25519Signature.ToArray(),
                parsed.RootEd25519SignatureInput.ToArray(),
                deepId.RootEd25519PublicKey.ToArray()))
            Reject("DAB2 Ed25519 root signature is invalid.");

        bool pqVerified;
        try
        {
            pqVerified = mlDsa65.Verify(
                deepId.RootMlDsa65PublicKey.Span,
                parsed.RootMlDsa65SignatureInput.Span,
                PqContext,
                parsed.RootMlDsa65Signature.Span);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            throw ApplicationCoreFormat.Error(
                ApplicationCoreValidationStage.CryptographicVerification,
                ApplicationCoreRejection.VerificationFailed,
                $"DAB2 ML-DSA-65 verification failed closed: {exception.GetType().Name}.");
        }
        if (!pqVerified)
            Reject("DAB2 ML-DSA-65 root signature is invalid.");

        if (!PublicKeyAuth.VerifyDetached(
                parsed.AccountSignature.ToArray(),
                parsed.AccountSignatureInput.ToArray(),
                certificate.AccountEd25519PublicKey.ToArray()))
            Reject("DAB2 account signature is invalid.");

        return new VerifiedDab2(parsed, deepId, identity);
    }

    public static Dab2LineageTransitionPlan StartDab2Lineage(VerifiedDab2 genesis)
    {
        ArgumentNullException.ThrowIfNull(genesis);
        if (genesis.Record.BindingGeneration != 0 ||
            !ApplicationCoreFormat.IsZero(genesis.Record.PredecessorDab2Hash.Span))
            Lineage("A DAB2 lineage starts at generation zero with a zero predecessor.");
        var state = new Dab2LineageState(genesis, forkLatched: false);
        return new Dab2LineageTransitionPlan(state, state,
            ApplicationLineageDisposition.AcceptedGenesis);
    }

    public static Dab2LineageTransitionPlan PrepareDab2Transition(
        Dab2LineageState previous, VerifiedDab2 candidate)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(candidate);
        if (previous.ForkLatched)
            Lineage("The DAB2 lineage is permanently fork-latched.");
        var head = previous.Head.Record;
        var next = candidate.Record;
        if (!head.IdentityRealmId.Span.SequenceEqual(next.IdentityRealmId.Span) ||
            !head.ExactDid2Hash.Span.SequenceEqual(next.ExactDid2Hash.Span))
            Lineage("DAB2 lineages from different realms or permanent IDs cannot be combined.");
        if (next.BindingGeneration == head.BindingGeneration)
        {
            if (head.RecordHash.Span.SequenceEqual(next.RecordHash.Span))
                return new Dab2LineageTransitionPlan(previous, previous,
                    ApplicationLineageDisposition.ExactReplay);
            var latched = new Dab2LineageState(previous.Head, forkLatched: true);
            return new Dab2LineageTransitionPlan(previous, latched,
                ApplicationLineageDisposition.ForkLatched);
        }
        if (head.BindingGeneration == ulong.MaxValue ||
            next.BindingGeneration != head.BindingGeneration + 1 ||
            !next.PredecessorDab2Hash.Span.SequenceEqual(head.RecordHash.Span))
            Lineage("DAB2 must advance exactly one generation and bind its exact predecessor.");
        var accepted = new Dab2LineageState(candidate, forkLatched: false);
        return new Dab2LineageTransitionPlan(previous, accepted,
            ApplicationLineageDisposition.AcceptedSuccessor);
    }

    /// <summary>
    /// The displayed V2 safety number commits to both exact account roots and
    /// both genesis-committed PQ Deep IDs, not to a legacy account-only hash.
    /// </summary>
    public static byte[] ComputeContactSafetyNumber(
        Dab2LineageState first, Dab2LineageState second)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);
        if (first.ForkLatched || second.ForkLatched)
            Lineage("A forked DAB2 binding cannot authorize a contact safety number.");
        var left = first.Head.Identity.Account.Certificate;
        var right = second.Head.Identity.Account.Certificate;
        if (!left.NetworkId.Span.SequenceEqual(right.NetworkId.Span) ||
            left.CanonicalHash.Span.SequenceEqual(right.CanonicalHash.Span))
            Reject("The contact safety number requires two distinct accounts on one network.");
        var firstBeforeSecond = left.CanonicalHash.Span.SequenceCompareTo(right.CanonicalHash.Span) < 0;
        var lower = firstBeforeSecond ? left : right;
        var upper = firstBeforeSecond ? right : left;
        var lowerDid = firstBeforeSecond ? first.Head.DeepId : second.Head.DeepId;
        var upperDid = firstBeforeSecond ? second.Head.DeepId : first.Head.DeepId;
        Span<byte> material = stackalloc byte[160];
        lower.NetworkId.Span.CopyTo(material);
        lower.CanonicalHash.Span.CopyTo(material[16..48]);
        BinaryPrimitives.WriteUInt64BigEndian(material[48..56], lower.AccountGeneration);
        lowerDid.RecordHash.Span.CopyTo(material[56..88]);
        upper.CanonicalHash.Span.CopyTo(material[88..120]);
        BinaryPrimitives.WriteUInt64BigEndian(material[120..128], upper.AccountGeneration);
        upperDid.RecordHash.Span.CopyTo(material[128..160]);
        return ApplicationCoreFormat.Sha256Domain(
            "Deep/Application/V2/contact-safety-number", material);
    }

    private static void Reject(string message) =>
        throw ApplicationCoreFormat.Error(
            ApplicationCoreValidationStage.CryptographicVerification,
            ApplicationCoreRejection.VerificationFailed, message);

    private static void Lineage(string message) =>
        throw ApplicationCoreFormat.Error(
            ApplicationCoreValidationStage.CryptographicVerification,
            ApplicationCoreRejection.InvalidLineage, message);
}
